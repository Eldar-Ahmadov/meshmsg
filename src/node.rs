use crate::{config::State, invite::Invite};
use anyhow::{Context, Result};
use bytes::Bytes;
use futures_util::TryStreamExt;
use iroh::{
    address_lookup::memory::MemoryLookup, endpoint::presets, protocol::Router, Endpoint, PublicKey,
    SecretKey,
};
use iroh_gossip::{
    api::{Event, GossipReceiver, GossipSender},
    net::{Gossip, GOSSIP_ALPN},
    proto::TopicId,
};
use serde::{Deserialize, Serialize};
use serde_byte_array::ByteArray;
use std::{
    io::BufRead,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const SIGNATURE_LENGTH: usize = iroh::Signature::LENGTH;
const MAX_MESSAGE_SIZE: usize = 4096;
type Signature = ByteArray<SIGNATURE_LENGTH>;

#[derive(Debug, Serialize, Deserialize)]
struct Envelope {
    from: PublicKey,
    timestamp_ms: u64,
    body: String,
    signature: Signature,
}

impl Envelope {
    fn encode(secret: &SecretKey, body: String) -> Result<Bytes> {
        let timestamp_ms = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64;
        let mut signed = postcard::to_stdvec(&(secret.public(), timestamp_ms, &body))?;
        let signature = secret.sign(&signed);
        let value = Self {
            from: secret.public(),
            timestamp_ms,
            body,
            signature: ByteArray::new(signature.to_bytes()),
        };
        signed.clear();
        let encoded = postcard::to_stdvec(&value)?;
        anyhow::ensure!(
            encoded.len() <= MAX_MESSAGE_SIZE,
            "encoded message is {} bytes; maximum is {MAX_MESSAGE_SIZE} bytes",
            encoded.len()
        );
        Ok(encoded.into())
    }
    fn decode(data: &[u8]) -> Result<Self> {
        let value: Self = postcard::from_bytes(data).context("decode message")?;
        let signed = postcard::to_stdvec(&(value.from, value.timestamp_ms, &value.body))?;
        value
            .from
            .verify(&signed, &iroh::Signature::from_bytes(&value.signature))
            .context("verify message")?;
        Ok(value)
    }
}

struct RunningNode {
    endpoint: Endpoint,
    router: Router,
    sender: GossipSender,
    receiver: GossipReceiver,
    secret: SecretKey,
}

async fn start(dir: &Path) -> Result<RunningNode> {
    let state = State::load(dir)?;
    let secret = State::load_secret(dir)?;
    let topic: TopicId = state.topic_id()?;
    let lookup = MemoryLookup::new();
    let endpoint = Endpoint::builder(presets::N0)
        .secret_key(secret.clone())
        .address_lookup(lookup.clone())
        .bind()
        .await?;
    let gossip = Gossip::builder().spawn(endpoint.clone());
    let router = Router::builder(endpoint.clone())
        .accept(GOSSIP_ALPN, gossip.clone())
        .spawn();
    let mut bootstrap = Vec::new();
    if let Some(token) = state.invite {
        let invite: Invite = token.parse()?;
        for seed in invite.seeds {
            // A seed's persisted invite also contains itself after its first run.
            if seed.id != endpoint.id() {
                bootstrap.push(seed.id);
                lookup.add_endpoint_info(seed);
            }
        }
    }
    let subscription = if bootstrap.is_empty() {
        // The first seed creates the swarm, so there is no peer to wait for.
        gossip.subscribe(topic, vec![]).await?
    } else {
        gossip.subscribe_and_join(topic, bootstrap).await?
    };
    let (sender, receiver) = subscription.split();
    Ok(RunningNode {
        endpoint,
        router,
        sender,
        receiver,
        secret,
    })
}

pub async fn run_seed(dir: &Path, json: bool) -> Result<()> {
    let mut state = State::load(dir)?;
    let mut node = start(dir).await?;
    node.endpoint.online().await;
    let mut invite = match &state.invite {
        Some(token) => token.parse::<Invite>()?,
        None => Invite {
            topic: state.topic_id()?,
            seeds: Vec::new(),
        },
    };
    let local_addr = node.endpoint.addr();
    invite.seeds.retain(|seed| seed.id != local_addr.id);
    anyhow::ensure!(
        invite.seeds.len() < crate::invite::MAX_SEEDS,
        "seed set already contains the maximum of {} other seeds",
        crate::invite::MAX_SEEDS
    );
    invite.seeds.push(local_addr);
    invite.deduplicate();
    state.invite = Some(invite.to_string());
    state.save(dir)?;
    event(
        json,
        serde_json::json!({"type":"listening", "peer":node.endpoint.id().to_string(), "topic":state.topic, "invite":state.invite}),
    );
    receive_until_signal(&mut node.receiver, json).await?;
    node.router.shutdown().await?;
    Ok(())
}

pub async fn send_once(dir: &Path, body: &str, json: bool) -> Result<()> {
    let node = start(dir).await?;
    node.sender
        .broadcast(Envelope::encode(&node.secret, body.to_owned())?)
        .await?;
    tokio::time::sleep(Duration::from_millis(500)).await;
    event(
        json,
        serde_json::json!({"type":"sent", "from":node.endpoint.id().to_string(), "body":body}),
    );
    node.router.shutdown().await?;
    Ok(())
}

pub async fn listen(dir: &Path, json: bool) -> Result<()> {
    let mut node = start(dir).await?;
    event(
        json,
        serde_json::json!({"type":"connected", "peer":node.endpoint.id().to_string()}),
    );
    receive_until_signal(&mut node.receiver, json).await?;
    node.router.shutdown().await?;
    Ok(())
}

pub async fn chat(dir: &Path, json: bool) -> Result<()> {
    let mut node = start(dir).await?;
    event(
        json,
        serde_json::json!({"type":"connected", "peer":node.endpoint.id().to_string()}),
    );
    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(8);
    std::thread::spawn(move || {
        for line in std::io::stdin().lock().lines().map_while(Result::ok) {
            if tx.blocking_send(line).is_err() {
                break;
            }
        }
    });
    loop {
        tokio::select! {
            line = rx.recv() => match line {
                Some(body) => { node.sender.broadcast(Envelope::encode(&node.secret, body.clone())?).await?; event(json, serde_json::json!({"type":"sent", "body":body})); }
                None => break,
            },
            incoming = node.receiver.try_next() => match incoming? {
                Some(value) => handle_event(value, json), None => break,
            },
            _ = tokio::signal::ctrl_c() => break,
        }
    }
    node.router.shutdown().await?;
    Ok(())
}

async fn receive_until_signal(receiver: &mut GossipReceiver, json: bool) -> Result<()> {
    loop {
        tokio::select! {
            incoming = receiver.try_next() => match incoming? { Some(value) => handle_event(value, json), None => break },
            _ = tokio::signal::ctrl_c() => break,
        }
    }
    Ok(())
}

fn handle_event(value: Event, json: bool) {
    match value {
        Event::Received(message) => match Envelope::decode(&message.content) {
            Ok(msg) => event(
                json,
                serde_json::json!({"type":"message", "from":msg.from.to_string(), "timestamp_ms":msg.timestamp_ms, "body":msg.body}),
            ),
            Err(error) => event(
                json,
                serde_json::json!({"type":"error", "code":"invalid_message", "message":error.to_string()}),
            ),
        },
        Event::NeighborUp(peer) => event(
            json,
            serde_json::json!({"type":"peer_up", "peer":peer.to_string()}),
        ),
        Event::NeighborDown(peer) => event(
            json,
            serde_json::json!({"type":"peer_down", "peer":peer.to_string()}),
        ),
        _ => {}
    }
}

pub async fn status(dir: &Path, json: bool) -> Result<()> {
    let state = State::load(dir)?;
    let secret = State::load_secret(dir)?;
    let value = serde_json::json!({"type":"status", "role":state.role, "peer":secret.public().to_string(), "topic":state.topic, "configured_seed":state.invite.is_some()});
    if json {
        println!("{value}");
    } else {
        println!(
            "role: {:?}\npeer: {}\ntopic: {}\nseed configured: {}",
            state.role,
            secret.public(),
            state.topic,
            state.invite.is_some()
        );
    }
    Ok(())
}

pub async fn doctor(dir: &Path, json: bool) -> Result<()> {
    let state = State::load(dir)?;
    let secret = State::load_secret(dir)?;
    state.topic_id()?;
    if let Some(token) = &state.invite {
        let _: Invite = token.parse()?;
    }
    let value = serde_json::json!({"type":"doctor", "ok":true, "peer":secret.public().to_string()});
    if json {
        println!("{value}");
    } else {
        println!("ok: state, identity, topic, and invite are valid");
    }
    Ok(())
}

fn terminal_safe(value: &str) -> String {
    value
        .chars()
        .flat_map(|character| {
            if character.is_control() {
                character.escape_default().collect::<Vec<_>>()
            } else {
                vec![character]
            }
        })
        .collect()
}

fn event(json: bool, value: serde_json::Value) {
    if json {
        println!("{value}");
    } else {
        match value["type"].as_str().unwrap_or("event") {
            "message" => println!(
                "{}: {}",
                value["from"].as_str().unwrap_or("peer"),
                terminal_safe(value["body"].as_str().unwrap_or(""))
            ),
            "sent" => println!(
                "sent: {}",
                terminal_safe(value["body"].as_str().unwrap_or(""))
            ),
            "peer_up" => println!("peer joined: {}", value["peer"].as_str().unwrap_or("")),
            "peer_down" => println!("peer left: {}", value["peer"].as_str().unwrap_or("")),
            "listening" => println!(
                "seed running\npeer: {}\ninvite: {}",
                value["peer"].as_str().unwrap_or(""),
                value["invite"].as_str().unwrap_or("")
            ),
            "connected" => println!("connected as {}", value["peer"].as_str().unwrap_or("")),
            _ => println!("{value}"),
        }
    }
}
