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
/// Maximum serialized application envelope accepted for broadcast.
const MAX_ENVELOPE_SIZE: usize = 4096;
/// Iroh's limit includes its own framing, so reserve explicit protocol headroom.
const GOSSIP_PROTOCOL_HEADROOM: usize = 512;
const GOSSIP_MAX_MESSAGE_SIZE: usize = MAX_ENVELOPE_SIZE + GOSSIP_PROTOCOL_HEADROOM;
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
        Self::encode_at(secret, body, timestamp_ms)
    }

    fn encode_at(secret: &SecretKey, body: String, timestamp_ms: u64) -> Result<Bytes> {
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
            encoded.len() <= MAX_ENVELOPE_SIZE,
            "encoded message is {} bytes; maximum is {MAX_ENVELOPE_SIZE} bytes",
            encoded.len()
        );
        Ok(encoded.into())
    }
    fn decode(data: &[u8]) -> Result<Self> {
        anyhow::ensure!(
            data.len() <= MAX_ENVELOPE_SIZE,
            "encoded message is {} bytes; maximum is {MAX_ENVELOPE_SIZE} bytes",
            data.len()
        );
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
    let gossip = Gossip::builder()
        .max_message_size(GOSSIP_MAX_MESSAGE_SIZE)
        .spawn(endpoint.clone());
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
    invite.upsert_seed(node.endpoint.addr())?;
    state.invite = Some(invite.to_string());
    state.save(dir)?;
    event(
        json,
        serde_json::json!({"type":"listening", "peer":node.endpoint.id().to_string(), "topic":state.topic, "invite":state.invite}),
    );
    receive_until_signal(&mut node.receiver, json, MessageVisibility::MetadataOnly).await?;
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
    receive_until_signal(&mut node.receiver, json, MessageVisibility::Full).await?;
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
                Some(value) => handle_event(value, json, MessageVisibility::Full), None => break,
            },
            _ = tokio::signal::ctrl_c() => break,
        }
    }
    node.router.shutdown().await?;
    Ok(())
}

#[derive(Clone, Copy)]
enum MessageVisibility {
    Full,
    MetadataOnly,
}

async fn receive_until_signal(
    receiver: &mut GossipReceiver,
    json: bool,
    visibility: MessageVisibility,
) -> Result<()> {
    loop {
        tokio::select! {
            incoming = receiver.try_next() => match incoming? { Some(value) => handle_event(value, json, visibility), None => break },
            _ = tokio::signal::ctrl_c() => break,
        }
    }
    Ok(())
}

fn message_event(msg: Envelope, visibility: MessageVisibility) -> serde_json::Value {
    match visibility {
        MessageVisibility::Full => serde_json::json!({
            "type":"message", "from":msg.from.to_string(),
            "timestamp_ms":msg.timestamp_ms, "body":msg.body
        }),
        MessageVisibility::MetadataOnly => serde_json::json!({
            "type":"message", "from":msg.from.to_string(),
            "timestamp_ms":msg.timestamp_ms, "body_bytes":msg.body.len(), "body_suppressed":true
        }),
    }
}

fn handle_event(value: Event, json: bool, visibility: MessageVisibility) {
    match value {
        Event::Received(message) => match Envelope::decode(&message.content) {
            Ok(msg) => event(json, message_event(msg, visibility)),
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
        Event::Lagged => event(
            json,
            serde_json::json!({"type":"lagged", "message":"receiver fell behind; one or more events were dropped"}),
        ),
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
            "message" if value["body_suppressed"].as_bool() == Some(true) => println!(
                "message from {} ({} bytes; body suppressed)",
                value["from"].as_str().unwrap_or("peer"),
                value["body_bytes"].as_u64().unwrap_or(0)
            ),
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
            "lagged" => println!(
                "warning: {}",
                value["message"].as_str().unwrap_or("receiver lagged")
            ),
            _ => println!("{value}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_boundary_matches_configured_gossip_headroom() {
        assert_eq!(
            GOSSIP_MAX_MESSAGE_SIZE - MAX_ENVELOPE_SIZE,
            GOSSIP_PROTOCOL_HEADROOM
        );

        let secret = SecretKey::generate();
        let timestamp_ms = 1_700_000_000_000;
        let largest_body = (0..=MAX_ENVELOPE_SIZE)
            .rev()
            .find(|length| Envelope::encode_at(&secret, "a".repeat(*length), timestamp_ms).is_ok())
            .expect("an empty message must fit");

        let encoded = Envelope::encode_at(&secret, "a".repeat(largest_body), timestamp_ms)
            .expect("boundary message must fit");
        assert_eq!(encoded.len(), MAX_ENVELOPE_SIZE);
        assert!(Envelope::encode_at(&secret, "a".repeat(largest_body + 1), timestamp_ms).is_err());
    }

    #[test]
    fn decode_rejects_oversized_signed_envelope() {
        let secret = SecretKey::generate();
        let timestamp_ms = 1_700_000_000_000;
        let body = "a".repeat(MAX_ENVELOPE_SIZE);
        let signed = postcard::to_stdvec(&(secret.public(), timestamp_ms, &body)).unwrap();
        let envelope = Envelope {
            from: secret.public(),
            timestamp_ms,
            body,
            signature: ByteArray::new(secret.sign(&signed).to_bytes()),
        };
        let encoded = postcard::to_stdvec(&envelope).unwrap();

        assert!(encoded.len() > MAX_ENVELOPE_SIZE);
        assert!(Envelope::decode(&encoded).is_err());
    }

    #[test]
    fn seed_message_event_suppresses_body_but_keeps_metadata() {
        let secret = SecretKey::generate();
        let value = message_event(
            Envelope {
                from: secret.public(),
                timestamp_ms: 42,
                body: "private text".to_owned(),
                signature: ByteArray::new([0; SIGNATURE_LENGTH]),
            },
            MessageVisibility::MetadataOnly,
        );

        assert_eq!(value["type"], "message");
        assert_eq!(value["timestamp_ms"], 42);
        assert_eq!(value["body_bytes"], 12);
        assert_eq!(value["body_suppressed"], true);
        assert!(value.get("body").is_none());
    }

    #[test]
    fn terminal_output_escapes_control_sequences() {
        let escaped = terminal_safe("hello\n\u{1b}]0;owned\u{7}");

        assert_eq!(escaped, "hello\\n\\u{1b}]0;owned\\u{7}");
        assert!(!escaped.chars().any(char::is_control));
    }
}
