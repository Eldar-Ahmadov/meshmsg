use crate::{
    config::{prepare_state_dir, Role, State, StateLock},
    invite::Invite,
};
use anyhow::{Context, Result};
use bytes::Bytes;
use futures_util::TryStreamExt;
use iroh::{
    address_lookup::memory::MemoryLookup, endpoint::presets, protocol::Router, Endpoint, PublicKey,
    SecretKey, Watcher,
};
use iroh_gossip::{
    api::{Event, GossipReceiver, GossipSender},
    net::{Gossip, GOSSIP_ALPN},
    proto::TopicId,
};
use serde::{Deserialize, Serialize};
use serde_byte_array::ByteArray;
#[cfg(unix)]
use std::path::PathBuf;
use std::{
    io::BufRead as _,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
#[cfg(windows)]
use tokio::net::windows::named_pipe::{
    ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
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
const STARTUP_TIMEOUT: Duration = Duration::from_secs(45);
const ENDPOINT_ONLINE_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(unix)]
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

async fn start(state: &State, secret: SecretKey) -> Result<RunningNode> {
    state.validate()?;
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
    if let Some(token) = &state.invite {
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

#[cfg(unix)]
struct LocalEndpointGuard {
    path: PathBuf,
    device: u64,
    inode: u64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

#[cfg(unix)]
impl Drop for LocalEndpointGuard {
    fn drop(&mut self) {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        if let Ok(metadata) = std::fs::symlink_metadata(&self.path) {
            if metadata.dev() == self.device
                && metadata.ino() == self.inode
                && metadata.ctime() == self.changed_seconds
                && metadata.ctime_nsec() == self.changed_nanoseconds
                && metadata.file_type().is_socket()
            {
                let _ = std::fs::remove_file(&self.path);
            }
        }
    }
}

#[cfg(windows)]
struct LocalEndpointGuard;

#[cfg(unix)]
type LocalServerStream = UnixStream;
#[cfg(unix)]
type LocalClientStream = UnixStream;
#[cfg(windows)]
type LocalServerStream = NamedPipeServer;
#[cfg(windows)]
type LocalClientStream = NamedPipeClient;

#[cfg(unix)]
struct LocalListener(UnixListener);

#[cfg(unix)]
impl LocalListener {
    async fn accept(&mut self) -> Result<LocalServerStream> {
        Ok(self
            .0
            .accept()
            .await
            .context("accept local daemon client")?
            .0)
    }
}

#[cfg(windows)]
struct LocalListener {
    pipe_name: String,
    pending: Option<NamedPipeServer>,
}

#[cfg(windows)]
impl LocalListener {
    async fn accept(&mut self) -> Result<LocalServerStream> {
        // This future is polled inside `tokio::select!`, so it must remain
        // cancellation-safe. Keep the pending server in `self` while waiting;
        // taking it before `.await` would leave the listener empty whenever a
        // different select branch wins.
        self.pending
            .as_ref()
            .context("named pipe listener missing")?
            .connect()
            .await
            .context("accept local daemon client")?;
        let next = create_pipe_server(&self.pipe_name, false)?;
        Ok(self
            .pending
            .replace(next)
            .context("named pipe listener missing")?)
    }
}

#[cfg(unix)]
fn local_endpoint(dir: &Path) -> String {
    dir.join(SOCKET_NAME).display().to_string()
}

#[cfg(windows)]
fn local_endpoint(dir: &Path) -> String {
    use sha2::{Digest, Sha256};
    use std::os::windows::ffi::OsStrExt;

    let path = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
    let mut hasher = Sha256::new();
    hasher.update(b"meshmsg-windows-pipe-v1\0");
    for unit in path.as_os_str().encode_wide() {
        hasher.update(unit.to_le_bytes());
    }
    let digest = hasher.finalize();
    let suffix: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    format!(r"\\.\pipe\meshmsg-{suffix}")
}

#[cfg(windows)]
struct WindowsHandle(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl Drop for WindowsHandle {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

#[cfg(windows)]
fn token_user_buffer(token: windows_sys::Win32::Foundation::HANDLE) -> Result<Vec<usize>> {
    use std::ffi::c_void;
    use windows_sys::Win32::Security::{GetTokenInformation, TokenUser};

    let mut required = 0;
    unsafe {
        GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut required);
    }
    anyhow::ensure!(required > 0, "determine Windows token owner size");
    let words = (required as usize).div_ceil(std::mem::size_of::<usize>());
    let mut buffer = vec![0_usize; words];
    let loaded = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast::<c_void>(),
            required,
            &mut required,
        )
    };
    anyhow::ensure!(
        loaded != 0,
        "read Windows token owner: {}",
        std::io::Error::last_os_error()
    );
    Ok(buffer)
}

#[cfg(windows)]
fn sid_belongs_to_current_user(candidate: windows_sys::Win32::Security::PSID) -> Result<bool> {
    use windows_sys::Win32::{
        Foundation::HANDLE,
        Security::{EqualSid, TOKEN_QUERY, TOKEN_USER},
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };

    let mut current_token: HANDLE = std::ptr::null_mut();
    let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut current_token) };
    anyhow::ensure!(
        opened != 0,
        "open current process token: {}",
        std::io::Error::last_os_error()
    );
    let current_token = WindowsHandle(current_token);
    let current_user = token_user_buffer(current_token.0)?;
    let current_sid = unsafe { (*(current_user.as_ptr().cast::<TOKEN_USER>())).User.Sid };
    Ok(unsafe { EqualSid(candidate, current_sid) } != 0)
}

#[cfg(windows)]
fn current_user_sid_string() -> Result<String> {
    use std::ffi::c_void;
    use windows_sys::{
        core::PWSTR,
        Win32::{
            Foundation::{LocalFree, HANDLE},
            Security::{Authorization::ConvertSidToStringSidW, TOKEN_QUERY, TOKEN_USER},
            System::Threading::{GetCurrentProcess, OpenProcessToken},
        },
    };

    let mut token: HANDLE = std::ptr::null_mut();
    let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
    anyhow::ensure!(
        opened != 0,
        "open current process token: {}",
        std::io::Error::last_os_error()
    );
    let token = WindowsHandle(token);
    let user = token_user_buffer(token.0)?;
    let sid = unsafe { (*(user.as_ptr().cast::<TOKEN_USER>())).User.Sid };
    let mut text: PWSTR = std::ptr::null_mut();
    let converted = unsafe { ConvertSidToStringSidW(sid, &mut text) };
    anyhow::ensure!(
        converted != 0,
        "format current user SID: {}",
        std::io::Error::last_os_error()
    );
    let length = unsafe {
        let mut length = 0;
        while *text.add(length) != 0 {
            length += 1;
        }
        length
    };
    let value = String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) })
        .context("current user SID is not valid UTF-16")?;
    unsafe { LocalFree(text.cast::<c_void>()) };
    Ok(value)
}

#[cfg(windows)]
fn process_belongs_to_current_user(process_id: u32) -> Result<bool> {
    use windows_sys::Win32::{
        Foundation::HANDLE,
        Security::{TOKEN_QUERY, TOKEN_USER},
        System::Threading::{OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION},
    };

    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    anyhow::ensure!(
        !process.is_null(),
        "open named pipe server process: {}",
        std::io::Error::last_os_error()
    );
    let process = WindowsHandle(process);

    let mut server_token: HANDLE = std::ptr::null_mut();
    let opened = unsafe { OpenProcessToken(process.0, TOKEN_QUERY, &mut server_token) };
    anyhow::ensure!(
        opened != 0,
        "open named pipe server token: {}",
        std::io::Error::last_os_error()
    );
    let server_token = WindowsHandle(server_token);

    let server_user = token_user_buffer(server_token.0)?;
    let server_sid = unsafe { (*(server_user.as_ptr().cast::<TOKEN_USER>())).User.Sid };
    sid_belongs_to_current_user(server_sid)
}

#[cfg(windows)]
fn verify_named_pipe_server_owner(stream: &NamedPipeClient) -> Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::{Foundation::HANDLE, System::Pipes::GetNamedPipeServerProcessId};

    let mut process_id = 0;
    let found =
        unsafe { GetNamedPipeServerProcessId(stream.as_raw_handle() as HANDLE, &mut process_id) };
    anyhow::ensure!(
        found != 0,
        "identify named pipe server: {}",
        std::io::Error::last_os_error()
    );
    anyhow::ensure!(
        process_belongs_to_current_user(process_id)?,
        "refusing named pipe server owned by another Windows user"
    );
    Ok(())
}

#[cfg(unix)]
async fn bind_local_endpoint(
    dir: &Path,
    _state_lock: &StateLock,
) -> Result<(LocalListener, LocalEndpointGuard)> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    prepare_state_dir(dir)?;
    let path = dir.join(SOCKET_NAME);
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
        LocalListener(listener),
        LocalEndpointGuard {
            path,
            device: metadata.dev(),
            inode: metadata.ino(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        },
    ))
}

#[cfg(windows)]
fn create_pipe_server(name: &str, first: bool) -> Result<NamedPipeServer> {
    use std::{ffi::c_void, ptr};
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::{
            Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW,
            SECURITY_ATTRIBUTES,
        },
    };

    // Make the current user the owner and grant access only to that user,
    // LocalSystem, and administrators. PIPE_REJECT_REMOTE_CLIENTS additionally
    // excludes network clients.
    let user_sid = current_user_sid_string()?;
    let mut sddl: Vec<u16> =
        format!("O:{user_sid}D:P(A;;GA;;;{user_sid})(A;;GA;;;SY)(A;;GA;;;BA)\0")
            .encode_utf16()
            .collect();
    let mut descriptor = ptr::null_mut();
    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_mut_ptr(),
            1,
            &mut descriptor,
            ptr::null_mut(),
        )
    };
    anyhow::ensure!(
        converted != 0,
        "create owner-only named pipe security descriptor: {}",
        std::io::Error::last_os_error()
    );
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let result = unsafe {
        ServerOptions::new()
            .first_pipe_instance(first)
            .reject_remote_clients(true)
            .create_with_security_attributes_raw(
                name,
                (&mut attributes as *mut SECURITY_ATTRIBUTES).cast::<c_void>(),
            )
    };
    unsafe { LocalFree(descriptor as *mut c_void) };
    result.context("create owner-only daemon named pipe")
}

#[cfg(windows)]
async fn bind_local_endpoint(
    dir: &Path,
    _state_lock: &StateLock,
) -> Result<(LocalListener, LocalEndpointGuard)> {
    prepare_state_dir(dir)?;
    let pipe_name = local_endpoint(dir);
    let pending = create_pipe_server(&pipe_name, true)?;
    Ok((
        LocalListener {
            pipe_name,
            pending: Some(pending),
        },
        LocalEndpointGuard,
    ))
}

async fn read_frame<S>(stream: &mut S, maximum: usize) -> Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
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

async fn write_value<S>(stream: &mut S, value: &serde_json::Value) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
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

async fn handle_local_client<S>(
    mut stream: S,
    commands: mpsc::Sender<DaemonCommand>,
    mut events: broadcast::Receiver<serde_json::Value>,
    connected: serde_json::Value,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
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

fn shutdown_signals() -> Result<mpsc::Receiver<()>> {
    let (sender, receiver) = mpsc::channel(1);
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .context("install SIGTERM handler")?;
        let mut interrupt =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                .context("install SIGINT handler")?;
        tokio::spawn(async move {
            tokio::select! {
                _ = terminate.recv() => {}
                _ = interrupt.recv() => {}
            }
            let _ = sender.send(()).await;
        });
    }
    #[cfg(windows)]
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            let _ = sender.send(()).await;
        }
    });
    Ok(receiver)
}

pub async fn run_seed_daemon(dir: &Path, json: bool) -> Result<()> {
    // Fail fast with a role-specific error, then validate again after acquiring
    // daemon ownership to close the concurrent forced-replacement gap.
    State::load(dir)?.ensure_role(Role::Seed)?;
    run_daemon_with_role(dir, json, Some(Role::Seed)).await
}

pub async fn run_daemon(dir: &Path, json: bool) -> Result<()> {
    run_daemon_with_role(dir, json, None).await
}

async fn run_daemon_with_role(dir: &Path, json: bool, expected_role: Option<Role>) -> Result<()> {
    // Install service-manager/console signal handling before startup becomes visible.
    let mut shutdown = shutdown_signals()?;
    // Claim local ownership before reading the identity, starting networking, or mutating state.
    let state_lock = StateLock::acquire(dir)?;
    let (mut state, secret) = State::load_locked(dir, &state_lock)?;
    state.validate()?;
    if let Some(expected_role) = expected_role {
        state.ensure_role(expected_role)?;
    }
    let startup = tokio::select! {
        result = tokio::time::timeout(STARTUP_TIMEOUT, start(&state, secret)) => result,
        _ = shutdown.recv() => return Ok(()),
    };
    let mut node = match startup {
        Ok(Ok(node)) => node,
        Ok(Err(error)) => {
            startup_error(json, "topic_join", &error.to_string());
            return Err(error)
                .context("start gossip topic; verify the invite and seed reachability");
        }
        Err(_) => {
            startup_error(
                json,
                "topic_join",
                "startup timed out while joining the gossip topic",
            );
            anyhow::bail!(
                "startup timed out after {}s while joining the gossip topic; verify that at least one configured seed is reachable",
                STARTUP_TIMEOUT.as_secs()
            );
        }
    };
    let online = tokio::select! {
        result = tokio::time::timeout(ENDPOINT_ONLINE_TIMEOUT, node.endpoint.online()) => result,
        _ = shutdown.recv() => {
            node.router.shutdown().await?;
            return Ok(());
        }
    };
    if online.is_err() {
        startup_error(
            json,
            "endpoint_online",
            "endpoint did not become online before the deadline",
        );
        node.router.shutdown().await?;
        anyhow::bail!(
            "endpoint did not become online within {}s; check internet, DNS, firewall, and relay access",
            ENDPOINT_ONLINE_TIMEOUT.as_secs()
        );
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
    let (mut listener, _endpoint_guard) = bind_local_endpoint(dir, &state_lock).await?;
    let peer = node.endpoint.id().to_string();
    let started = serde_json::json!({
        "type":"daemon_started", "peer":peer, "topic":state.topic,
        "role":state.role, "socket":local_endpoint(dir),
        "local_endpoint":local_endpoint(dir), "endpoint_online":true,
        "topic_joined":node.receiver.is_joined()
    });
    event(json, started);

    let (command_tx, mut command_rx) = mpsc::channel(32);
    let (event_tx, _) = broadcast::channel(IPC_EVENT_CAPACITY);

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let stream = accepted?;
                let commands = command_tx.clone();
                let events = event_tx.subscribe();
                let connected = serde_json::json!({
                    "type":"connected", "peer":peer, "endpoint_online":true,
                    "topic_joined":node.receiver.is_joined()
                });
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
                            Ok(()) => queued_event(&peer, body),
                            Err(error) => serde_json::json!({"type":"error", "code":"send_failed", "message":error.to_string()}),
                        },
                        Err(error) => serde_json::json!({"type":"error", "code":"invalid_message", "message":error.to_string()}),
                    };
                    if response["type"] == "queued" {
                        let _ = event_tx.send(response.clone());
                    }
                    let _ = reply.send(response);
                }
                Some(DaemonCommand::Status { reply }) => {
                    let endpoint_online = node.endpoint.home_relay_status().get()
                        .iter().any(|status| status.is_connected());
                    let neighbors = node.receiver.neighbors().count();
                    let _ = reply.send(serde_json::json!({
                        "type":"status", "running":true, "role":state.role, "peer":peer,
                        "topic":state.topic, "configured_seed":state.invite.is_some(),
                        "neighbors":neighbors, "socket":local_endpoint(dir),
                        "local_endpoint":local_endpoint(dir), "endpoint_online":endpoint_online,
                        "topic_joined":node.receiver.is_joined()
                    }));
                }
                Some(DaemonCommand::Stop) => break,
                None => break,
            },
            incoming = node.receiver.try_next() => match incoming? {
                Some(value) => {
                    let values = network_event(value);
                    for full_value in values {
                        let _ = event_tx.send(full_value.clone());
                        event(json, suppress_message_body(full_value));
                    }
                }
                None => break,
            },
            _ = shutdown.recv() => break,
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

fn queued_event(peer: &str, body: String) -> serde_json::Value {
    serde_json::json!({
        "type":"queued", "from":peer, "body":body,
        "delivery_acknowledged":false
    })
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

#[cfg(unix)]
async fn connect_daemon(dir: &Path) -> Result<LocalClientStream> {
    UnixStream::connect(dir.join(SOCKET_NAME))
        .await
        .with_context(|| {
            format!(
                "connect to local daemon at {}; start it with `meshmsg daemon`",
                local_endpoint(dir)
            )
        })
}

#[cfg(windows)]
async fn connect_daemon(dir: &Path) -> Result<LocalClientStream> {
    let endpoint = local_endpoint(dir);
    for attempt in 0..20 {
        match ClientOptions::new().open(&endpoint) {
            Ok(stream) => {
                verify_named_pipe_server_owner(&stream)
                    .context("authenticate local daemon named pipe")?;
                return Ok(stream);
            }
            Err(error) if attempt < 19 && matches!(error.raw_os_error(), Some(2 | 231)) => {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("connect to local daemon at {endpoint}; start it with `meshmsg daemon`")
                });
            }
        }
    }
    unreachable!("named pipe connection retry loop always returns")
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

async fn subscribe(dir: &Path) -> Result<BufReader<LocalClientStream>> {
    let mut stream = connect_daemon(dir).await?;
    let mut request = serde_json::to_vec(&IpcRequest::Subscribe)?;
    request.push(b'\n');
    stream.write_all(&request).await?;
    Ok(BufReader::new(stream))
}

async fn read_subscription(
    reader: &mut BufReader<LocalClientStream>,
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
            "daemon: running\nrole: {}\npeer: {}\ntopic: {}\nendpoint online: {}\ntopic joined: {}\nneighbors: {}\nseed configured: {}",
            value["role"].as_str().unwrap_or("unknown"),
            value["peer"].as_str().unwrap_or(""),
            value["topic"].as_str().unwrap_or(""),
            value["endpoint_online"].as_bool().unwrap_or(false),
            value["topic_joined"].as_bool().unwrap_or(false),
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
    let (state, secret) = State::load_for_doctor(dir)?;
    state.validate()?;
    let value = serde_json::json!({
        "type":"doctor", "ok":true, "peer":secret.public().to_string(),
        "role":state.role, "topic":state.topic, "configured_seed":state.invite.is_some()
    });
    if json {
        println!("{value}");
    } else {
        println!("ok: state, identity, topic, and invite are valid");
    }
    Ok(())
}

fn startup_error_value(phase: &str, message: &str) -> serde_json::Value {
    serde_json::json!({
        "type":"startup_error", "phase":phase, "message":message,
        "retryable":true
    })
}

fn startup_error(json: bool, phase: &str, message: &str) {
    if json {
        println!("{}", startup_error_value(phase, message));
    }
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
            "queued" => println!(
                "queued locally (delivery not acknowledged): {}",
                terminal_safe(value["body"].as_str().unwrap_or(""))
            ),
            "peer_up" => println!("peer joined: {}", value["peer"].as_str().unwrap_or("")),
            "peer_down" => println!("peer left: {}", value["peer"].as_str().unwrap_or("")),
            "daemon_started" => println!(
                "daemon running as {} ({})\nlocal endpoint: {}",
                value["peer"].as_str().unwrap_or(""),
                value["role"].as_str().unwrap_or("unknown"),
                value["local_endpoint"].as_str().unwrap_or("")
            ),
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
    #[cfg(unix)]
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
    fn daemon_log_message_event_suppresses_body_but_keeps_metadata_for_every_role() {
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
    fn queued_event_does_not_claim_delivery() {
        let value = queued_event("peer", "hello".to_owned());

        assert_eq!(value["type"], "queued");
        assert_eq!(value["delivery_acknowledged"], false);
        assert!(value.get("sent").is_none());
    }

    #[test]
    fn startup_errors_are_structured_and_retryable() {
        let value = startup_error_value("topic_join", "seed unavailable");

        assert_eq!(value["type"], "startup_error");
        assert_eq!(value["phase"], "topic_join");
        assert_eq!(value["retryable"], true);
        assert!(STARTUP_TIMEOUT <= Duration::from_secs(60));
        assert!(ENDPOINT_ONLINE_TIMEOUT <= Duration::from_secs(60));
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

    #[cfg(unix)]
    #[tokio::test]
    async fn daemon_socket_is_owner_only_and_replaces_stale_file() {
        let dir = std::env::temp_dir().join(format!("meshmsg-ipc-test-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(SOCKET_NAME);
        std::fs::write(&path, b"stale").unwrap();
        let state_lock = StateLock::acquire(&dir).unwrap();
        let (_listener, guard) = bind_local_endpoint(&dir, &state_lock).await.unwrap();
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        drop(guard);
        assert!(!path.exists());
        drop(state_lock);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn socket_guard_does_not_remove_a_replacement_path() {
        let dir = std::env::temp_dir().join(format!("meshmsg-ipc-test-{}", rand::random::<u64>()));
        let state_lock = StateLock::acquire(&dir).unwrap();
        let (listener, guard) = bind_local_endpoint(&dir, &state_lock).await.unwrap();
        drop(listener);
        let path = dir.join(SOCKET_NAME);
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"replacement").unwrap();

        drop(guard);
        assert_eq!(std::fs::read(path).unwrap(), b"replacement");
        drop(state_lock);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_pipe_name_stably_hashes_wide_paths() {
        use std::{ffi::OsString, os::windows::ffi::OsStringExt};

        let first = std::path::PathBuf::from(OsString::from_wide(&[0x0061, 0xd800]));
        let second = std::path::PathBuf::from(OsString::from_wide(&[0x0061, 0xd801]));
        assert_eq!(local_endpoint(&first), local_endpoint(&first));
        assert_ne!(local_endpoint(&first), local_endpoint(&second));
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_named_pipe_has_protected_owner_dacl() {
        use std::{ffi::c_void, os::windows::io::AsRawHandle};
        use windows_sys::Win32::{
            Foundation::{LocalFree, HANDLE},
            Security::{
                Authorization::{
                    BuildTrusteeWithSidW, GetEffectiveRightsFromAclW, GetSecurityInfo,
                    SE_KERNEL_OBJECT, TRUSTEE_W,
                },
                CreateWellKnownSid, GetSecurityDescriptorControl, WinWorldSid,
                DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
                SECURITY_MAX_SID_SIZE, SE_DACL_PROTECTED,
            },
        };

        let dir = std::env::temp_dir().join(format!("meshmsg-ipc-test-{}", rand::random::<u64>()));
        let state_lock = StateLock::acquire(&dir).unwrap();
        let (listener, _guard) = bind_local_endpoint(&dir, &state_lock).await.unwrap();
        let server = listener.pending.as_ref().unwrap();
        let mut owner: PSID = std::ptr::null_mut();
        let mut dacl = std::ptr::null_mut();
        let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let status = unsafe {
            GetSecurityInfo(
                server.as_raw_handle() as HANDLE,
                SE_KERNEL_OBJECT,
                DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
                &mut owner,
                std::ptr::null_mut(),
                &mut dacl,
                std::ptr::null_mut(),
                &mut descriptor,
            )
        };
        assert_eq!(status, 0);
        assert!(!owner.is_null());
        assert!(!dacl.is_null());
        assert!(sid_belongs_to_current_user(owner).unwrap());

        let mut control = 0;
        let mut revision = 0;
        let read_control =
            unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) };
        assert_ne!(read_control, 0);
        assert_ne!(control & SE_DACL_PROTECTED, 0);

        let mut world_sid = vec![0_u8; SECURITY_MAX_SID_SIZE as usize];
        let mut world_sid_size = world_sid.len() as u32;
        let made_world = unsafe {
            CreateWellKnownSid(
                WinWorldSid,
                std::ptr::null_mut(),
                world_sid.as_mut_ptr().cast(),
                &mut world_sid_size,
            )
        };
        assert_ne!(made_world, 0);
        let mut trustee = TRUSTEE_W::default();
        unsafe { BuildTrusteeWithSidW(&mut trustee, world_sid.as_mut_ptr().cast()) };
        let mut rights = 0;
        let status = unsafe { GetEffectiveRightsFromAclW(dacl, &trustee, &mut rights) };
        assert_eq!(status, 0);
        assert_eq!(rights, 0, "Everyone must not receive named-pipe access");

        unsafe { LocalFree(descriptor.cast::<c_void>()) };
        drop(state_lock);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_foreign_pipe_owner_sid_is_rejected() {
        use windows_sys::Win32::Security::{
            CreateWellKnownSid, WinLocalSystemSid, SECURITY_MAX_SID_SIZE,
        };

        let mut system_sid = vec![0_u8; SECURITY_MAX_SID_SIZE as usize];
        let mut size = system_sid.len() as u32;
        let created = unsafe {
            CreateWellKnownSid(
                WinLocalSystemSid,
                std::ptr::null_mut(),
                system_sid.as_mut_ptr().cast(),
                &mut size,
            )
        };
        assert_ne!(created, 0, "{}", std::io::Error::last_os_error());
        assert!(!sid_belongs_to_current_user(system_sid.as_mut_ptr().cast()).unwrap());
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_named_pipe_accepts_authenticated_local_ipc() {
        let dir = std::env::temp_dir().join(format!("meshmsg-ipc-test-{}", rand::random::<u64>()));
        let state_lock = StateLock::acquire(&dir).unwrap();
        let endpoint = local_endpoint(&dir);
        let (mut listener, _guard) = bind_local_endpoint(&dir, &state_lock).await.unwrap();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap() });
        let mut client = connect_daemon(&dir).await.unwrap();
        let mut server = accept.await.unwrap();
        assert_eq!(endpoint, local_endpoint(&dir));
        client.write_all(b"ping").await.unwrap();
        let mut received = [0; 4];
        server.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"ping");
        drop(state_lock);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_named_pipe_accept_survives_cancellation() {
        let dir = std::env::temp_dir().join(format!("meshmsg-ipc-test-{}", rand::random::<u64>()));
        let state_lock = StateLock::acquire(&dir).unwrap();
        let (mut listener, _guard) = bind_local_endpoint(&dir, &state_lock).await.unwrap();

        let cancelled = tokio::time::timeout(Duration::from_millis(10), listener.accept()).await;
        assert!(cancelled.is_err());
        assert!(listener.pending.is_some());

        let (server, client) = tokio::join!(listener.accept(), connect_daemon(&dir));
        let mut server = server.unwrap();
        let mut client = client.unwrap();
        client.write_all(b"ping").await.unwrap();
        let mut received = [0; 4];
        server.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"ping");

        drop(state_lock);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn subscriber_exits_when_daemon_event_channel_closes() {
        let (mut client, server) = tokio::io::duplex(MAX_IPC_EVENT_SIZE);
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
        let (mut client, server) = tokio::io::duplex(MAX_IPC_EVENT_SIZE);
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
        let (mut left, mut right) = tokio::io::duplex(MAX_IPC_REQUEST_SIZE + 1);
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
