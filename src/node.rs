use crate::{
    config::{prepare_state_dir, Role, State, StateLock},
    invite::Invite,
};
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
    collections::HashSet,
    io::BufRead as _,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    sync::{broadcast, mpsc, oneshot},
};

const SIGNATURE_LENGTH: usize = iroh::Signature::LENGTH;
/// Maximum serialized application envelope accepted for broadcast.
const MAX_ENVELOPE_SIZE: usize = 4096;
/// Iroh's limit includes its own framing, so reserve explicit protocol headroom.
const GOSSIP_PROTOCOL_HEADROOM: usize = 512;
const GOSSIP_MAX_MESSAGE_SIZE: usize = MAX_ENVELOPE_SIZE + GOSSIP_PROTOCOL_HEADROOM;
// JSON can escape each accepted body byte as six ASCII bytes (for example, `\\u0000`).
const MAX_IPC_REQUEST_SIZE: usize = MAX_ENVELOPE_SIZE * 6 + 1024;
const MAX_IPC_EVENT_SIZE: usize = MAX_ENVELOPE_SIZE * 6 + 1024;
const IPC_EVENT_CAPACITY: usize = 256;
const SOCKET_NAME: &str = "daemon.sock";
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
        let signed = postcard::to_stdvec(&(secret.public(), timestamp_ms, &body))?;
        let value = Self {
            from: secret.public(),
            timestamp_ms,
            body,
            signature: ByteArray::new(secret.sign(&signed).to_bytes()),
        };
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
        let (value, remainder): (Self, &[u8]) =
            postcard::take_from_bytes(data).context("decode message")?;
        anyhow::ensure!(
            remainder.is_empty(),
            "encoded message contains trailing bytes"
        );
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
            if seed.id != endpoint.id() {
                bootstrap.push(seed.id);
                lookup.add_endpoint_info(seed);
            }
        }
    }
    let subscription = if bootstrap.is_empty() {
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

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "command", rename_all = "snake_case")]
enum IpcRequest {
    Send { body: String },
    Subscribe,
    Status,
    Stop,
}

enum DaemonCommand {
    Send {
        body: String,
        reply: oneshot::Sender<serde_json::Value>,
    },
    Status {
        reply: oneshot::Sender<serde_json::Value>,
    },
    Stop,
}

struct SocketGuard {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        use std::os::unix::fs::MetadataExt;
        if let Ok(metadata) = std::fs::symlink_metadata(&self.path) {
            if metadata.dev() == self.device && metadata.ino() == self.inode {
                let _ = std::fs::remove_file(&self.path);
            }
        }
    }
}

fn socket_path(dir: &Path) -> PathBuf {
    dir.join(SOCKET_NAME)
}

async fn bind_socket(dir: &Path, _state_lock: &StateLock) -> Result<(UnixListener, SocketGuard)> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    prepare_state_dir(dir)?;
    let path = socket_path(dir);
    if path.exists() {
        if UnixStream::connect(&path).await.is_ok() {
            anyhow::bail!("a meshmsg daemon is already running for {}", dir.display());
        }
        std::fs::remove_file(&path).context("remove stale daemon socket")?;
    }
    let listener = UnixListener::bind(&path).context("bind daemon socket")?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .context("restrict daemon socket permissions")?;
    let metadata = std::fs::symlink_metadata(&path).context("inspect daemon socket")?;
    Ok((
        listener,
        SocketGuard {
            path,
            device: metadata.dev(),
            inode: metadata.ino(),
        },
    ))
}

async fn read_frame(stream: &mut UnixStream, maximum: usize) -> Result<Vec<u8>> {
    let mut frame = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        let read = stream.read(&mut byte).await.context("read daemon socket")?;
        anyhow::ensure!(read != 0, "daemon socket closed before a complete response");
        if byte[0] == b'\n' {
            break;
        }
        anyhow::ensure!(
            frame.len() < maximum,
            "local IPC frame exceeds {maximum} bytes"
        );
        frame.push(byte[0]);
    }
    Ok(frame)
}

async fn write_value(stream: &mut UnixStream, value: &serde_json::Value) -> Result<()> {
    let mut encoded = serde_json::to_vec(value)?;
    anyhow::ensure!(
        encoded.len() <= MAX_IPC_EVENT_SIZE,
        "local IPC event exceeds {MAX_IPC_EVENT_SIZE} bytes"
    );
    encoded.push(b'\n');
    stream
        .write_all(&encoded)
        .await
        .context("write daemon socket")?;
    Ok(())
}

async fn handle_local_client(
    mut stream: UnixStream,
    commands: mpsc::Sender<DaemonCommand>,
    mut events: broadcast::Receiver<serde_json::Value>,
    connected: serde_json::Value,
) -> Result<()> {
    let frame = read_frame(&mut stream, MAX_IPC_REQUEST_SIZE).await?;
    let request: IpcRequest =
        serde_json::from_slice(&frame).context("invalid local IPC request")?;
    match request {
        IpcRequest::Subscribe => {
            write_value(&mut stream, &connected).await?;
            loop {
                match events.recv().await {
                    Ok(value) => write_value(&mut stream, &value).await?,
                    Err(broadcast::error::RecvError::Lagged(count)) => {
                        write_value(
                            &mut stream,
                            &serde_json::json!({"type":"lagged", "message":format!("local listener missed {count} events")}),
                        )
                        .await?;
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        }
        IpcRequest::Send { body } => {
            let (reply, response) = oneshot::channel();
            commands.send(DaemonCommand::Send { body, reply }).await?;
            write_value(&mut stream, &response.await?).await?;
        }
        IpcRequest::Status => {
            let (reply, response) = oneshot::channel();
            commands.send(DaemonCommand::Status { reply }).await?;
            write_value(&mut stream, &response.await?).await?;
        }
        IpcRequest::Stop => {
            write_value(&mut stream, &serde_json::json!({"type":"stopping"})).await?;
            commands.send(DaemonCommand::Stop).await?;
        }
    }
    Ok(())
}

pub async fn run_daemon(dir: &Path, json: bool) -> Result<()> {
    // Install the service-manager signal handler before daemon startup becomes externally visible.
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("install SIGTERM handler")?;
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .context("install SIGINT handler")?;
    // Claim local ownership before reading the identity, starting networking, or mutating state.
    let state_lock = StateLock::acquire(dir)?;
    let mut state = State::load(dir)?;
    let mut node = tokio::select! {
        result = start(dir) => result?,
        _ = terminate.recv() => return Ok(()),
        _ = interrupt.recv() => return Ok(()),
    };
    tokio::select! {
        _ = node.endpoint.online() => {}
        _ = terminate.recv() => {
            node.router.shutdown().await?;
            return Ok(());
        }
        _ = interrupt.recv() => {
            node.router.shutdown().await?;
            return Ok(());
        }
    }

    if state.role == Role::Seed {
        let mut invite = match &state.invite {
            Some(token) => token.parse::<Invite>()?,
            None => Invite {
                topic: state.topic_id()?,
                seeds: Vec::new(),
            },
        };
        invite.upsert_seed(node.endpoint.addr())?;
        state.invite = Some(invite.to_string());
        state.save(dir, &state_lock)?;
    }

    // Expose IPC only after networking is ready, so clients never connect to a
    // socket whose daemon is still blocked during bootstrap.
    let (listener, _socket_guard) = bind_socket(dir, &state_lock).await?;
    let peer = node.endpoint.id().to_string();
    let started = serde_json::json!({
        "type":"daemon_started", "peer":peer, "topic":state.topic,
        "role":state.role, "socket":socket_path(dir), "invite":state.invite
    });
    event(json, started);

    let (command_tx, mut command_rx) = mpsc::channel(32);
    let (event_tx, _) = broadcast::channel(IPC_EVENT_CAPACITY);
    let connected = serde_json::json!({"type":"connected", "peer":peer});
    let mut peers = HashSet::new();

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = accepted.context("accept local daemon client")?;
                let commands = command_tx.clone();
                let events = event_tx.subscribe();
                let connected = connected.clone();
                tokio::spawn(async move {
                    if let Err(error) = handle_local_client(stream, commands, events, connected).await {
                        if !is_local_disconnect(&error) {
                            eprintln!("local client error: {error:#}");
                        }
                    }
                });
            }
            command = command_rx.recv() => match command {
                Some(DaemonCommand::Send { body, reply }) => {
                    let response = match Envelope::encode(&node.secret, body.clone()) {
                        Ok(envelope) => match node.sender.broadcast(envelope).await {
                            Ok(()) => serde_json::json!({"type":"sent", "from":peer, "body":body}),
                            Err(error) => serde_json::json!({"type":"error", "code":"send_failed", "message":error.to_string()}),
                        },
                        Err(error) => serde_json::json!({"type":"error", "code":"invalid_message", "message":error.to_string()}),
                    };
                    if response["type"] == "sent" {
                        let _ = event_tx.send(response.clone());
                    }
                    let _ = reply.send(response);
                }
                Some(DaemonCommand::Status { reply }) => {
                    let _ = reply.send(serde_json::json!({
                        "type":"status", "running":true, "role":state.role, "peer":peer,
                        "topic":state.topic, "configured_seed":state.invite.is_some(),
                        "neighbors":peers.len(), "socket":socket_path(dir)
                    }));
                }
                Some(DaemonCommand::Stop) => break,
                None => break,
            },
            incoming = node.receiver.try_next() => match incoming? {
                Some(value) => {
                    match &value {
                        Event::NeighborUp(peer) => { peers.insert(*peer); }
                        Event::NeighborDown(peer) => { peers.remove(peer); }
                        _ => {}
                    }
                    let values = network_event(value);
                    for full_value in values {
                        let _ = event_tx.send(full_value.clone());
                        let logged = if state.role == Role::Seed { suppress_message_body(full_value) } else { full_value };
                        event(json, logged);
                    }
                }
                None => break,
            },
            _ = interrupt.recv() => break,
            _ = terminate.recv() => break,
        }
    }

    drop(event_tx);
    node.router.shutdown().await?;
    Ok(())
}

fn is_local_disconnect(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause.downcast_ref::<std::io::Error>().is_some_and(|error| {
            matches!(
                error.kind(),
                std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::NotConnected
                    | std::io::ErrorKind::UnexpectedEof
            )
        })
    })
}

fn network_event(value: Event) -> Vec<serde_json::Value> {
    match value {
        Event::Received(message) => vec![match Envelope::decode(&message.content) {
            Ok(msg) => message_event(msg),
            Err(error) => {
                serde_json::json!({"type":"error", "code":"invalid_message", "message":error.to_string()})
            }
        }],
        Event::NeighborUp(peer) => {
            vec![serde_json::json!({"type":"peer_up", "peer":peer.to_string()})]
        }
        Event::NeighborDown(peer) => {
            vec![serde_json::json!({"type":"peer_down", "peer":peer.to_string()})]
        }
        Event::Lagged => vec![
            serde_json::json!({"type":"lagged", "message":"receiver fell behind; one or more events were dropped"}),
        ],
    }
}

fn message_event(msg: Envelope) -> serde_json::Value {
    serde_json::json!({
        "type":"message", "from":msg.from.to_string(),
        "timestamp_ms":msg.timestamp_ms, "body":msg.body
    })
}

fn suppress_message_body(value: serde_json::Value) -> serde_json::Value {
    if value["type"] != "message" {
        return value;
    }
    serde_json::json!({
        "type":"message", "from":value["from"], "timestamp_ms":value["timestamp_ms"],
        "body_bytes":value["body"].as_str().map(str::len).unwrap_or(0), "body_suppressed":true
    })
}

async fn connect_daemon(dir: &Path) -> Result<UnixStream> {
    UnixStream::connect(socket_path(dir))
        .await
        .with_context(|| {
            format!(
                "connect to local daemon at {}; start it with `meshmsg daemon`",
                socket_path(dir).display()
            )
        })
}

async fn send_request(dir: &Path, request: &IpcRequest) -> Result<serde_json::Value> {
    let mut stream = connect_daemon(dir).await?;
    let mut encoded = serde_json::to_vec(request)?;
    anyhow::ensure!(
        encoded.len() <= MAX_IPC_REQUEST_SIZE,
        "local IPC request is too large"
    );
    encoded.push(b'\n');
    stream.write_all(&encoded).await?;
    let frame = read_frame(&mut stream, MAX_IPC_EVENT_SIZE).await?;
    serde_json::from_slice(&frame).context("invalid response from local daemon")
}

fn ensure_success(value: &serde_json::Value) -> Result<()> {
    if value["type"] == "error" {
        anyhow::bail!(
            "daemon rejected request: {}",
            value["message"].as_str().unwrap_or("unknown error")
        );
    }
    Ok(())
}

pub async fn send_once(dir: &Path, body: &str, json: bool) -> Result<()> {
    let value = send_request(
        dir,
        &IpcRequest::Send {
            body: body.to_owned(),
        },
    )
    .await?;
    ensure_success(&value)?;
    event(json, value);
    Ok(())
}

async fn subscribe(dir: &Path) -> Result<BufReader<UnixStream>> {
    let mut stream = connect_daemon(dir).await?;
    let mut request = serde_json::to_vec(&IpcRequest::Subscribe)?;
    request.push(b'\n');
    stream.write_all(&request).await?;
    Ok(BufReader::new(stream))
}

async fn read_subscription(
    reader: &mut BufReader<UnixStream>,
) -> Result<Option<serde_json::Value>> {
    let mut line = Vec::new();
    let read = reader.read_until(b'\n', &mut line).await?;
    if read == 0 {
        return Ok(None);
    }
    anyhow::ensure!(
        line.len() <= MAX_IPC_EVENT_SIZE + 1,
        "daemon event is too large"
    );
    Ok(Some(
        serde_json::from_slice(&line).context("invalid daemon event")?,
    ))
}

pub async fn listen(dir: &Path, json: bool) -> Result<()> {
    let mut reader = subscribe(dir).await?;
    loop {
        tokio::select! {
            value = read_subscription(&mut reader) => match value? {
                Some(value) => event(json, value),
                None => anyhow::bail!("local daemon stopped; restart it with `meshmsg daemon`"),
            },
            _ = tokio::signal::ctrl_c() => break,
        }
    }
    Ok(())
}

pub async fn chat(dir: &Path, json: bool) -> Result<()> {
    let mut reader = subscribe(dir).await?;
    let (tx, mut rx) = mpsc::channel::<String>(8);
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
                Some(body) => {
                    let value = send_request(dir, &IpcRequest::Send { body }).await?;
                    ensure_success(&value)?;
                }
                None => break,
            },
            value = read_subscription(&mut reader) => match value? {
                Some(value) => event(json, value),
                None => anyhow::bail!("local daemon stopped; restart it with `meshmsg daemon`"),
            },
            _ = tokio::signal::ctrl_c() => break,
        }
    }
    Ok(())
}

pub async fn status(dir: &Path, json: bool) -> Result<()> {
    let value = send_request(dir, &IpcRequest::Status).await?;
    if json {
        println!("{value}");
    } else {
        println!(
            "daemon: running\nrole: {}\npeer: {}\ntopic: {}\nneighbors: {}\nseed configured: {}",
            value["role"].as_str().unwrap_or("unknown"),
            value["peer"].as_str().unwrap_or(""),
            value["topic"].as_str().unwrap_or(""),
            value["neighbors"].as_u64().unwrap_or(0),
            value["configured_seed"].as_bool().unwrap_or(false)
        );
    }
    Ok(())
}

pub async fn stop(dir: &Path, json: bool) -> Result<()> {
    let value = send_request(dir, &IpcRequest::Stop).await?;
    event(json, value);
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
            "daemon_started" => {
                println!(
                    "daemon running as {} ({})\nsocket: {}",
                    value["peer"].as_str().unwrap_or(""),
                    value["role"].as_str().unwrap_or("unknown"),
                    value["socket"].as_str().unwrap_or("")
                );
                if let Some(invite) = value["invite"].as_str() {
                    println!("invite: {invite}");
                }
            }
            "connected" => println!("connected as {}", value["peer"].as_str().unwrap_or("")),
            "stopping" => println!("daemon stopping"),
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
    use std::os::unix::fs::PermissionsExt;

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
        let encoded = Envelope::encode_at(&secret, "a".repeat(largest_body), timestamp_ms).unwrap();
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
    fn decode_rejects_trailing_bytes() {
        let secret = SecretKey::generate();
        let mut encoded = Envelope::encode_at(&secret, "hello".to_owned(), 42)
            .unwrap()
            .to_vec();
        encoded.push(0);

        assert!(Envelope::decode(&encoded).is_err());
    }

    #[test]
    fn seed_message_event_suppresses_body_but_keeps_metadata() {
        let secret = SecretKey::generate();
        let value = suppress_message_body(message_event(Envelope {
            from: secret.public(),
            timestamp_ms: 42,
            body: "private text".to_owned(),
            signature: ByteArray::new([0; SIGNATURE_LENGTH]),
        }));
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

    #[test]
    fn worst_case_control_body_fits_ipc_event_limit() {
        let secret = SecretKey::generate();
        let timestamp_ms = 1_700_000_000_000;
        let largest_body = (0..=MAX_ENVELOPE_SIZE)
            .rev()
            .find(|length| Envelope::encode_at(&secret, "\0".repeat(*length), timestamp_ms).is_ok())
            .unwrap();
        let value = message_event(Envelope {
            from: secret.public(),
            timestamp_ms,
            body: "\0".repeat(largest_body),
            signature: ByteArray::new([0; SIGNATURE_LENGTH]),
        });
        assert!(serde_json::to_vec(&value).unwrap().len() <= MAX_IPC_EVENT_SIZE);
    }

    #[tokio::test]
    async fn daemon_socket_is_owner_only_and_replaces_stale_file() {
        let dir = std::env::temp_dir().join(format!("meshmsg-ipc-test-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(socket_path(&dir), b"stale").unwrap();
        let state_lock = StateLock::acquire(&dir).unwrap();
        let (_listener, guard) = bind_socket(&dir, &state_lock).await.unwrap();
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(socket_path(&dir))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        drop(guard);
        assert!(!socket_path(&dir).exists());
        drop(state_lock);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn socket_guard_does_not_remove_a_replacement_path() {
        let dir = std::env::temp_dir().join(format!("meshmsg-ipc-test-{}", rand::random::<u64>()));
        let state_lock = StateLock::acquire(&dir).unwrap();
        let (listener, guard) = bind_socket(&dir, &state_lock).await.unwrap();
        drop(listener);
        std::fs::remove_file(socket_path(&dir)).unwrap();
        std::fs::write(socket_path(&dir), b"replacement").unwrap();

        drop(guard);
        assert_eq!(std::fs::read(socket_path(&dir)).unwrap(), b"replacement");
        drop(state_lock);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn subscriber_exits_when_daemon_event_channel_closes() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let (commands, _command_rx) = mpsc::channel(1);
        let (events, receiver) = broadcast::channel(1);
        let task = tokio::spawn(handle_local_client(
            server,
            commands,
            receiver,
            serde_json::json!({"type":"connected"}),
        ));
        client
            .write_all(b"{\"command\":\"subscribe\"}\n")
            .await
            .unwrap();
        let connected = read_frame(&mut client, MAX_IPC_EVENT_SIZE).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&connected).unwrap()["type"],
            "connected"
        );

        drop(events);
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn slow_subscriber_receives_lag_event() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let (commands, _command_rx) = mpsc::channel(1);
        let (events, receiver) = broadcast::channel(1);
        events.send(serde_json::json!({"type":"first"})).unwrap();
        events.send(serde_json::json!({"type":"second"})).unwrap();
        let task = tokio::spawn(handle_local_client(
            server,
            commands,
            receiver,
            serde_json::json!({"type":"connected"}),
        ));
        client
            .write_all(b"{\"command\":\"subscribe\"}\n")
            .await
            .unwrap();
        let _connected = read_frame(&mut client, MAX_IPC_EVENT_SIZE).await.unwrap();
        let lagged = read_frame(&mut client, MAX_IPC_EVENT_SIZE).await.unwrap();
        let lagged: serde_json::Value = serde_json::from_slice(&lagged).unwrap();
        assert_eq!(lagged["type"], "lagged");

        drop(events);
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn ipc_reader_rejects_oversized_request() {
        let (mut left, mut right) = UnixStream::pair().unwrap();
        let writer = tokio::spawn(async move {
            right
                .write_all(&vec![b'a'; MAX_IPC_REQUEST_SIZE + 1])
                .await
                .unwrap();
        });
        let error = read_frame(&mut left, MAX_IPC_REQUEST_SIZE)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("exceeds"));
        writer.await.unwrap();
    }
}
