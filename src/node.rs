use crate::{
    config::{prepare_state_dir, State, StateLock},
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
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant as StdInstant, SystemTime, UNIX_EPOCH},
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
const BENCH_MAGIC: &str = "meshmsg-bench-v1";
const MAX_BENCH_MESSAGES: u64 = 10_000_000;
const MAX_LATENCY_SAMPLES: usize = 1_000_000;
const MAX_MISSING_SEQUENCE_SAMPLE: usize = 100;
const MAX_LATENCY_MS: u64 = 24 * 60 * 60 * 1000;
const STARTUP_TIMEOUT: Duration = Duration::from_secs(45);
const ENDPOINT_ONLINE_TIMEOUT: Duration = Duration::from_secs(30);
/// Re-issue the gossip join after connectivity loss. `join_peers` only queues a
/// connection attempt, so repeating it also covers attempts made while the
/// network interface is still unavailable.
const REJOIN_INTERVAL: Duration = Duration::from_secs(5);
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BenchConfig {
    run_id: String,
    rate: u32,
    duration_secs: u64,
    payload_bytes: usize,
}

#[derive(Debug, PartialEq)]
struct BenchFrame<'a> {
    run_id: &'a str,
    sequence: u64,
    total: u64,
    timestamp_ms: u64,
}

fn unix_timestamp_ms() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64)
}

fn valid_run_id(run_id: &str) -> bool {
    run_id.len() == 32
        && run_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn bench_header(run_id: &str, sequence: u64, total: u64, timestamp_ms: u64) -> String {
    format!("{BENCH_MAGIC}|{run_id}|{sequence:020}|{total:020}|{timestamp_ms:013}|")
}

fn build_bench_body(
    run_id: &str,
    sequence: u64,
    total: u64,
    timestamp_ms: u64,
    payload_bytes: usize,
) -> Result<String> {
    anyhow::ensure!(valid_run_id(run_id), "invalid benchmark run ID");
    anyhow::ensure!(
        total > 0 && total <= MAX_BENCH_MESSAGES,
        "invalid benchmark total"
    );
    anyhow::ensure!(sequence < total, "benchmark sequence is outside the run");
    anyhow::ensure!(
        timestamp_ms <= 9_999_999_999_999,
        "benchmark timestamp is too large"
    );
    let mut body = bench_header(run_id, sequence, total, timestamp_ms);
    anyhow::ensure!(
        payload_bytes >= body.len(),
        "payload size must be at least {} bytes",
        body.len()
    );
    body.extend(std::iter::repeat_n('x', payload_bytes - body.len()));
    Ok(body)
}

fn parse_bench_body(body: &str) -> Result<Option<BenchFrame<'_>>> {
    if !body.starts_with("meshmsg-bench") {
        return Ok(None);
    }
    let mut fields = body.splitn(6, '|');
    anyhow::ensure!(
        fields.next() == Some(BENCH_MAGIC),
        "invalid benchmark framing"
    );
    let run_id = fields.next().context("invalid benchmark framing")?;
    let sequence_text = fields.next().context("invalid benchmark framing")?;
    let total_text = fields.next().context("invalid benchmark framing")?;
    let timestamp_text = fields.next().context("invalid benchmark framing")?;
    let padding = fields.next().context("invalid benchmark framing")?;
    anyhow::ensure!(valid_run_id(run_id), "invalid benchmark run ID");
    for (value, width, name) in [
        (sequence_text, 20, "sequence"),
        (total_text, 20, "total"),
        (timestamp_text, 13, "timestamp"),
    ] {
        anyhow::ensure!(
            value.len() == width && value.bytes().all(|byte| byte.is_ascii_digit()),
            "invalid benchmark {name}"
        );
    }
    anyhow::ensure!(
        padding.bytes().all(|byte| byte == b'x'),
        "invalid benchmark padding"
    );
    let sequence = sequence_text.parse::<u64>()?;
    let total = total_text.parse::<u64>()?;
    let timestamp_ms = timestamp_text.parse::<u64>()?;
    anyhow::ensure!(
        total > 0 && total <= MAX_BENCH_MESSAGES,
        "invalid benchmark total"
    );
    anyhow::ensure!(sequence < total, "benchmark sequence is outside the run");
    Ok(Some(BenchFrame {
        run_id,
        sequence,
        total,
        timestamp_ms,
    }))
}

fn validate_bench_config(config: &BenchConfig) -> Result<u64> {
    anyhow::ensure!(valid_run_id(&config.run_id), "invalid benchmark run ID");
    anyhow::ensure!(
        (1..=10_000).contains(&config.rate),
        "rate must be between 1 and 10000 messages per second"
    );
    anyhow::ensure!(
        (1..=86_400).contains(&config.duration_secs),
        "duration must be between 1 and 86400 seconds"
    );
    let total = u64::from(config.rate)
        .checked_mul(config.duration_secs)
        .context("benchmark message count overflow")?;
    anyhow::ensure!(
        total <= MAX_BENCH_MESSAGES,
        "benchmark plans {total} messages; maximum is {MAX_BENCH_MESSAGES}"
    );
    anyhow::ensure!(
        config.payload_bytes <= MAX_ENVELOPE_SIZE,
        "payload size cannot exceed {MAX_ENVELOPE_SIZE} bytes"
    );
    let body = build_bench_body(
        &config.run_id,
        total - 1,
        total,
        9_999_999_999_999,
        config.payload_bytes,
    )?;
    Envelope::encode_at(&SecretKey::generate(), body, 9_999_999_999_999)
        .context("payload does not fit the signed application envelope")?;
    Ok(total)
}

impl Envelope {
    fn encode(secret: &SecretKey, body: String) -> Result<Bytes> {
        Self::encode_at(secret, body, unix_timestamp_ms()?)
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
    bootstrap_peers: Vec<PublicKey>,
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
        for peer in invite.bootstrap_peers {
            if peer.id != endpoint.id() {
                bootstrap.push(peer.id);
                lookup.add_endpoint_info(peer);
            }
        }
    }
    let subscription = if bootstrap.is_empty() {
        gossip.subscribe(topic, vec![]).await?
    } else {
        gossip.subscribe_and_join(topic, bootstrap.clone()).await?
    };
    let (sender, receiver) = subscription.split();
    Ok(RunningNode {
        endpoint,
        router,
        sender,
        receiver,
        secret,
        bootstrap_peers: bootstrap,
    })
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "command", rename_all = "snake_case")]
enum IpcRequest {
    Send { body: String },
    BenchSend { config: BenchConfig },
    Subscribe,
    Status,
    Stop,
}

enum DaemonCommand {
    Send {
        body: String,
        reply: oneshot::Sender<serde_json::Value>,
    },
    BenchMessage {
        body: String,
        timestamp_ms: u64,
        cancel: oneshot::Receiver<()>,
        reply: oneshot::Sender<std::result::Result<usize, String>>,
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

struct BenchmarkLease(Arc<AtomicBool>);

impl Drop for BenchmarkLease {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

#[derive(Debug, Default)]
struct BenchSendStats {
    attempted: u64,
    queued: u64,
    failed: u64,
    schedule_missed: u64,
    body_bytes: u64,
    envelope_bytes: u64,
    first_error: Option<String>,
}

fn benchmark_due_slots(elapsed: Duration, period: Duration, total: u64) -> u64 {
    ((elapsed.as_nanos() / period.as_nanos()) as u64 + 1).min(total)
}

fn advance_benchmark_slot(due_slots: u64, next_slot: &mut u64, schedule_missed: &mut u64) -> u64 {
    let sequence = due_slots.saturating_sub(1).max(*next_slot);
    *schedule_missed += sequence.saturating_sub(*next_slot);
    *next_slot = sequence + 1;
    sequence
}

fn bench_send_summary(
    config: &BenchConfig,
    total: u64,
    stats: &BenchSendStats,
    reason: &str,
    elapsed: Duration,
) -> serde_json::Value {
    let elapsed_ms = elapsed.as_millis() as u64;
    let elapsed_seconds = elapsed_ms.max(1) as f64 / 1000.0;
    serde_json::json!({
        "type":"bench_send_summary", "schema_version":1,
        "run_id":config.run_id, "rate":config.rate,
        "duration_secs":config.duration_secs, "payload_bytes":config.payload_bytes,
        "planned":total, "attempted":stats.attempted, "queued":stats.queued,
        "failed":stats.failed, "schedule_missed":stats.schedule_missed,
        "queued_body_bytes":stats.body_bytes, "queued_envelope_bytes":stats.envelope_bytes,
        "elapsed_ms":elapsed_ms,
        "achieved_messages_per_second":stats.queued as f64 / elapsed_seconds,
        "achieved_body_bytes_per_second":stats.body_bytes as f64 / elapsed_seconds,
        "completion_reason":reason, "first_error":stats.first_error,
        "delivery_acknowledged":false
    })
}

async fn handle_bench_send<S>(
    stream: &mut S,
    commands: &mpsc::Sender<DaemonCommand>,
    config: BenchConfig,
    benchmark_busy: Arc<AtomicBool>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let total = match validate_bench_config(&config) {
        Ok(total) => total,
        Err(error) => {
            return write_value(
                stream,
                &serde_json::json!({"type":"error", "code":"invalid_benchmark", "message":error.to_string()}),
            )
            .await;
        }
    };
    if benchmark_busy
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return write_value(
            stream,
            &serde_json::json!({"type":"error", "code":"benchmark_busy", "message":"another send benchmark is already active"}),
        )
        .await;
    }
    let _lease = BenchmarkLease(benchmark_busy);
    write_value(
        stream,
        &serde_json::json!({
            "type":"bench_send_started", "schema_version":1,
            "run_id":config.run_id, "rate":config.rate,
            "duration_secs":config.duration_secs, "payload_bytes":config.payload_bytes,
            "planned":total, "delivery_acknowledged":false
        }),
    )
    .await?;

    let started = tokio::time::Instant::now();
    let duration = Duration::from_secs(config.duration_secs);
    let deadline = started + duration;
    let period = Duration::from_nanos(1_000_000_000 / u64::from(config.rate));
    let mut ticks = tokio::time::interval_at(started, period);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut stats = BenchSendStats::default();
    let mut next_slot = 0_u64;
    let mut reason = "deadline";
    let mut interrupt = [0_u8; 1];

    'benchmark: while next_slot < total {
        tokio::select! {
            biased;
            read = stream.read(&mut interrupt) => {
                match read {
                    Ok(0) => return Ok(()),
                    Ok(_) => reason = "interrupted",
                    Err(error) => return Err(error).context("read benchmark cancellation"),
                }
                break;
            }
            _ = tokio::time::sleep_until(deadline) => break,
            _ = ticks.tick() => {}
        }
        let due_slots = benchmark_due_slots(started.elapsed(), period, total);
        let sequence =
            advance_benchmark_slot(due_slots, &mut next_slot, &mut stats.schedule_missed);
        stats.attempted += 1;
        let timestamp_ms = unix_timestamp_ms()?;
        let body = build_bench_body(
            &config.run_id,
            sequence,
            total,
            timestamp_ms,
            config.payload_bytes,
        )?;
        let (reply, response) = oneshot::channel();
        let (cancel, cancellation) = oneshot::channel();
        let command = DaemonCommand::BenchMessage {
            body,
            timestamp_ms,
            cancel: cancellation,
            reply,
        };
        let sent = tokio::select! {
            biased;
            read = stream.read(&mut interrupt) => {
                match read {
                    Ok(0) => return Ok(()),
                    Ok(_) => reason = "interrupted",
                    Err(error) => return Err(error).context("read benchmark cancellation"),
                }
                false
            }
            _ = tokio::time::sleep_until(deadline) => false,
            result = commands.send(command) => {
                if result.is_err() {
                    reason = "daemon_stopped";
                    false
                } else {
                    true
                }
            }
        };
        if !sent {
            break;
        }
        let response = tokio::select! {
            biased;
            read = stream.read(&mut interrupt) => {
                let _ = cancel.send(());
                match read {
                    Ok(0) => return Ok(()),
                    Ok(_) => reason = "interrupted",
                    Err(error) => return Err(error).context("read benchmark cancellation"),
                }
                None
            }
            _ = tokio::time::sleep_until(deadline) => {
                let _ = cancel.send(());
                None
            }
            result = response => Some(result)
        };
        match response {
            Some(Ok(Ok(encoded_bytes))) => {
                stats.queued += 1;
                stats.body_bytes += config.payload_bytes as u64;
                stats.envelope_bytes += encoded_bytes as u64;
            }
            Some(Ok(Err(error))) => {
                stats.failed += 1;
                stats.first_error = Some(error);
                reason = "send_failed";
                break 'benchmark;
            }
            Some(Err(_)) => {
                reason = "daemon_stopped";
                break 'benchmark;
            }
            None => break 'benchmark,
        }
    }

    if next_slot == total && tokio::time::Instant::now() < deadline {
        tokio::select! {
            read = stream.read(&mut interrupt) => match read {
                Ok(0) => return Ok(()),
                Ok(_) => reason = "interrupted",
                Err(error) => return Err(error).context("read benchmark cancellation"),
            },
            _ = tokio::time::sleep_until(deadline) => {}
        }
    }
    let elapsed = started.elapsed();
    let observed = elapsed.min(duration);
    let due_slots = benchmark_due_slots(observed, period, total);
    stats.schedule_missed += due_slots.saturating_sub(next_slot);
    let summary = bench_send_summary(&config, total, &stats, reason, elapsed);
    write_value(stream, &summary).await
}

async fn handle_local_client<S>(
    mut stream: S,
    commands: mpsc::Sender<DaemonCommand>,
    mut events: broadcast::Receiver<serde_json::Value>,
    connected: serde_json::Value,
    benchmark_busy: Arc<AtomicBool>,
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
                            &serde_json::json!({
                                "type":"lagged", "source":"local", "dropped":count,
                                "message":format!("local listener missed {count} events")
                            }),
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
        IpcRequest::BenchSend { config } => {
            handle_bench_send(&mut stream, &commands, config, benchmark_busy).await?;
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

pub async fn run_daemon(dir: &Path, json: bool) -> Result<()> {
    // Install service-manager/console signal handling before startup becomes visible.
    let mut shutdown = shutdown_signals()?;
    // Claim local ownership before reading the identity, starting networking, or mutating state.
    let state_lock = StateLock::acquire(dir)?;
    let (mut state, secret) = State::load_locked(dir, &state_lock)?;
    state.validate_for_identity(secret.public())?;
    let startup = tokio::select! {
        result = tokio::time::timeout(STARTUP_TIMEOUT, start(&state, secret)) => result,
        _ = shutdown.recv() => return Ok(()),
    };
    let mut node = match startup {
        Ok(Ok(node)) => node,
        Ok(Err(error)) => {
            startup_error(json, "topic_join", &error.to_string());
            return Err(error)
                .context("start gossip topic; verify the invite and bootstrap-peer reachability");
        }
        Err(_) => {
            startup_error(
                json,
                "topic_join",
                "startup timed out while joining the gossip topic",
            );
            anyhow::bail!(
                "startup timed out after {}s while joining the gossip topic; verify that at least one configured bootstrap peer is reachable",
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

    if state.advertise_self {
        let mut invite = match &state.invite {
            Some(token) => token.parse::<Invite>()?,
            None => Invite {
                topic: state.topic_id()?,
                bootstrap_peers: Vec::new(),
            },
        };
        invite.upsert_bootstrap_peer(node.endpoint.addr())?;
        state.invite = Some(invite.to_string());
        state.save(dir, &state_lock)?;
    }

    let (has_invite, bootstrap_peer_count, self_advertised) =
        invite_details(&state, node.endpoint.id())?;

    // Expose IPC only after networking is ready, so clients never connect to a
    // socket whose daemon is still blocked during bootstrap.
    let (mut listener, _endpoint_guard) = bind_local_endpoint(dir, &state_lock).await?;
    let peer = node.endpoint.id().to_string();
    let started = serde_json::json!({
        "type":"daemon_started", "peer":peer, "topic":state.topic,
        "advertises_self":state.advertise_self, "has_invite":has_invite,
        "bootstrap_peer_count":bootstrap_peer_count, "self_advertised":self_advertised,
        "socket":local_endpoint(dir), "local_endpoint":local_endpoint(dir),
        "endpoint_online":true, "topic_joined":node.receiver.is_joined()
    });
    event(json, started);

    let (command_tx, mut command_rx) = mpsc::channel(32);
    let (event_tx, _) = broadcast::channel(IPC_EVENT_CAPACITY);
    let benchmark_busy = Arc::new(AtomicBool::new(false));
    let mut rejoin = tokio::time::interval(REJOIN_INTERVAL);
    rejoin.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

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
                let benchmark_busy = benchmark_busy.clone();
                tokio::spawn(async move {
                    if let Err(error) = handle_local_client(stream, commands, events, connected, benchmark_busy).await {
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
                Some(DaemonCommand::BenchMessage { body, timestamp_ms, cancel, reply }) => {
                    match Envelope::encode_at(&node.secret, body, timestamp_ms) {
                        Ok(envelope) => {
                            let encoded_bytes = envelope.len();
                            let sender = node.sender.clone();
                            tokio::spawn(async move {
                                let response = tokio::select! {
                                    result = sender.broadcast(envelope) => result
                                        .map(|()| encoded_bytes)
                                        .map_err(|error| error.to_string()),
                                    _ = cancel => Err("benchmark message cancelled".to_owned()),
                                };
                                let _ = reply.send(response);
                            });
                        }
                        Err(error) => {
                            let _ = reply.send(Err(error.to_string()));
                        }
                    }
                }
                Some(DaemonCommand::Status { reply }) => {
                    let endpoint_online = node.endpoint.home_relay_status().get()
                        .iter().any(|status| status.is_connected());
                    let neighbors = node.receiver.neighbors().count();
                    let _ = reply.send(serde_json::json!({
                        "type":"status", "running":true, "peer":peer, "topic":state.topic,
                        "advertises_self":state.advertise_self, "has_invite":has_invite,
                        "bootstrap_peer_count":bootstrap_peer_count,
                        "self_advertised":self_advertised, "neighbors":neighbors,
                        "socket":local_endpoint(dir), "local_endpoint":local_endpoint(dir),
                        "endpoint_online":endpoint_online, "topic_joined":node.receiver.is_joined()
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
            _ = rejoin.tick(), if !node.bootstrap_peers.is_empty() => {
                if !node.receiver.is_joined() {
                    node.sender
                        .join_peers(node.bootstrap_peers.clone())
                        .await
                        .context("retry gossip bootstrap peers after connectivity loss")?;
                }
            },
            _ = shutdown.recv() => break,
        }
    }

    drop(event_tx);
    node.router.shutdown().await?;
    Ok(())
}

fn invite_details(state: &State, self_id: PublicKey) -> Result<(bool, usize, bool)> {
    let Some(token) = &state.invite else {
        return Ok((false, 0, false));
    };
    let invite: Invite = token.parse()?;
    let self_advertised = invite.bootstrap_peers.iter().any(|peer| peer.id == self_id);
    Ok((true, invite.bootstrap_peers.len(), self_advertised))
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
        Event::Lagged => vec![serde_json::json!({
            "type":"lagged", "source":"gossip", "dropped":serde_json::Value::Null,
            "message":"receiver fell behind; one or more events were dropped"
        })],
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

fn generated_run_id() -> String {
    rand::random::<[u8; 16]>()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

async fn write_request<S: AsyncWrite + Unpin>(stream: &mut S, request: &IpcRequest) -> Result<()> {
    let mut encoded = serde_json::to_vec(request)?;
    anyhow::ensure!(
        encoded.len() <= MAX_IPC_REQUEST_SIZE,
        "local IPC request is too large"
    );
    encoded.push(b'\n');
    stream.write_all(&encoded).await?;
    Ok(())
}

fn print_bench_value(json: bool, value: &serde_json::Value) {
    if json {
        println!("{value}");
        return;
    }
    match value["type"].as_str() {
        Some("bench_send_started") => println!(
            "benchmark send started\nrun id: {}\nplanned messages: {}\ndelivery acknowledged: no",
            value["run_id"].as_str().unwrap_or(""),
            value["planned"].as_u64().unwrap_or(0)
        ),
        Some("bench_send_summary") => println!(
            "benchmark send complete ({})\nattempted: {}\nqueued locally: {}\nfailed: {}\nschedule missed: {}\nachieved: {:.2} messages/s\ndelivery acknowledged: no",
            value["completion_reason"].as_str().unwrap_or("unknown"),
            value["attempted"].as_u64().unwrap_or(0),
            value["queued"].as_u64().unwrap_or(0),
            value["failed"].as_u64().unwrap_or(0),
            value["schedule_missed"].as_u64().unwrap_or(0),
            value["achieved_messages_per_second"].as_f64().unwrap_or(0.0),
        ),
        Some("bench_receive_started") => println!(
            "benchmark receive started\nrun id: {}\nobservation window: {}s",
            value["run_id"].as_str().unwrap_or(""),
            value["duration_secs"].as_u64().unwrap_or(0)
        ),
        Some("bench_receive_summary") => println!(
            "benchmark receive complete ({})\nunique: {}\nmissing: {}\nduplicates: {}\nout of order: {}\nreceived: {:.2} messages/s\nmeasurement incomplete due to lag: {}",
            value["completion_reason"].as_str().unwrap_or("unknown"),
            value["unique"].as_u64().unwrap_or(0),
            value["missing"].as_u64().map(|v| v.to_string()).unwrap_or_else(|| "unknown".into()),
            value["duplicates"].as_u64().unwrap_or(0),
            value["out_of_order"].as_u64().unwrap_or(0),
            value["achieved_messages_per_second"].as_f64().unwrap_or(0.0),
            value["lag"]["incomplete"].as_bool().unwrap_or(false),
        ),
        _ => event(json, value.clone()),
    }
}

pub async fn bench_send(
    dir: &Path,
    run_id: Option<String>,
    rate: u32,
    duration_secs: u64,
    payload_bytes: usize,
    json: bool,
) -> Result<()> {
    let config = BenchConfig {
        run_id: run_id.unwrap_or_else(generated_run_id),
        rate,
        duration_secs,
        payload_bytes,
    };
    validate_bench_config(&config)?;
    let mut stream = connect_daemon(dir).await?;
    write_request(
        &mut stream,
        &IpcRequest::BenchSend {
            config: config.clone(),
        },
    )
    .await?;
    let mut reader = BufReader::new(stream);
    let started = read_subscription(&mut reader)
        .await?
        .context("local daemon stopped before benchmark start")?;
    ensure_success(&started)?;
    anyhow::ensure!(
        started["type"] == "bench_send_started",
        "unexpected benchmark response"
    );
    print_bench_value(json, &started);

    let summary = tokio::select! {
        value = read_subscription(&mut reader) => value?
            .context("local daemon stopped before benchmark summary")?,
        result = tokio::signal::ctrl_c() => {
            result.context("wait for Ctrl-C")?;
            reader.get_mut().write_all(b"\n").await?;
            tokio::time::timeout(Duration::from_secs(5), read_subscription(&mut reader)).await
                .context("timed out waiting for interrupted benchmark summary")??
                .context("local daemon stopped before interrupted benchmark summary")?
        }
    };
    ensure_success(&summary)?;
    anyhow::ensure!(
        summary["type"] == "bench_send_summary",
        "unexpected benchmark response"
    );
    print_bench_value(json, &summary);
    if summary["failed"].as_u64() != Some(0) {
        anyhow::bail!(
            "benchmark send failed: {}",
            summary["first_error"]
                .as_str()
                .unwrap_or("unknown broadcast error")
        );
    }
    anyhow::ensure!(
        summary["completion_reason"].as_str() != Some("daemon_stopped"),
        "local daemon stopped during benchmark send"
    );
    Ok(())
}

#[derive(Debug)]
struct BenchReceiveStats {
    run_id: String,
    expected: Option<u64>,
    seen: Vec<u8>,
    unique: u64,
    duplicates: u64,
    out_of_order: u64,
    highest_sequence: Option<u64>,
    body_bytes: u64,
    latencies: Vec<u64>,
    latency_observations: u64,
    latency_sampled: bool,
    latency_clock_invalid: u64,
    local_lag_events: u64,
    local_dropped: u64,
    gossip_lag_events: u64,
    peer_up: u64,
    peer_down: u64,
    ignored_messages: u64,
    malformed_messages: u64,
}

impl BenchReceiveStats {
    fn new(run_id: String, expected: Option<u64>) -> Result<Self> {
        if let Some(expected) = expected {
            anyhow::ensure!(
                (1..=MAX_BENCH_MESSAGES).contains(&expected),
                "expected count must be between 1 and {MAX_BENCH_MESSAGES}"
            );
        }
        let seen = expected.map_or_else(Vec::new, |count| vec![0; count.div_ceil(8) as usize]);
        Ok(Self {
            run_id,
            expected,
            seen,
            unique: 0,
            duplicates: 0,
            out_of_order: 0,
            highest_sequence: None,
            body_bytes: 0,
            latencies: Vec::new(),
            latency_observations: 0,
            latency_sampled: false,
            latency_clock_invalid: 0,
            local_lag_events: 0,
            local_dropped: 0,
            gossip_lag_events: 0,
            peer_up: 0,
            peer_down: 0,
            ignored_messages: 0,
            malformed_messages: 0,
        })
    }

    fn reservoir_index(observation: u64, sequence: u64) -> u64 {
        // SplitMix64 provides a deterministic pseudorandom draw for Algorithm R.
        let mut value = observation ^ sequence.rotate_left(32);
        value = value.wrapping_add(0x9e3779b97f4a7c15);
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d049bb133111eb);
        value ^ (value >> 31)
    }

    fn record_latency_sample(&mut self, latency: u64, sequence: u64, capacity: usize) {
        self.latency_observations += 1;
        if self.latencies.len() < capacity {
            self.latencies.push(latency);
        } else {
            self.latency_sampled = true;
            let candidate = Self::reservoir_index(self.latency_observations, sequence)
                % self.latency_observations;
            if candidate < capacity as u64 {
                self.latencies[candidate as usize] = latency;
            }
        }
    }

    fn record_message_at(&mut self, value: &serde_json::Value, received_timestamp_ms: u64) {
        let Some(body) = value["body"].as_str() else {
            self.ignored_messages = self.ignored_messages.saturating_add(1);
            return;
        };
        let frame = match parse_bench_body(body) {
            Ok(Some(frame)) => frame,
            Ok(None) => {
                self.ignored_messages = self.ignored_messages.saturating_add(1);
                return;
            }
            Err(_) => {
                if body.contains(&self.run_id) {
                    self.malformed_messages = self.malformed_messages.saturating_add(1);
                } else {
                    self.ignored_messages = self.ignored_messages.saturating_add(1);
                }
                return;
            }
        };
        if frame.run_id != self.run_id {
            self.ignored_messages = self.ignored_messages.saturating_add(1);
            return;
        }
        if self.expected.is_none() {
            self.expected = Some(frame.total);
            self.seen = vec![0; frame.total.div_ceil(8) as usize];
        }
        if self.expected != Some(frame.total) {
            self.malformed_messages = self.malformed_messages.saturating_add(1);
            return;
        }
        let event_timestamp = value["timestamp_ms"].as_u64();
        if event_timestamp != Some(frame.timestamp_ms) {
            self.malformed_messages = self.malformed_messages.saturating_add(1);
            return;
        }
        let byte = (frame.sequence / 8) as usize;
        let mask = 1_u8 << (frame.sequence % 8);
        if self.seen[byte] & mask != 0 {
            self.duplicates = self.duplicates.saturating_add(1);
            return;
        }
        self.seen[byte] |= mask;
        if self
            .highest_sequence
            .is_some_and(|highest| frame.sequence < highest)
        {
            self.out_of_order = self.out_of_order.saturating_add(1);
        }
        self.highest_sequence = Some(
            self.highest_sequence
                .map_or(frame.sequence, |highest| highest.max(frame.sequence)),
        );
        self.unique = self.unique.saturating_add(1);
        self.body_bytes = self.body_bytes.saturating_add(body.len() as u64);

        let Some(latency) = received_timestamp_ms.checked_sub(frame.timestamp_ms) else {
            self.latency_clock_invalid = self.latency_clock_invalid.saturating_add(1);
            return;
        };
        if latency > MAX_LATENCY_MS {
            self.latency_clock_invalid = self.latency_clock_invalid.saturating_add(1);
        } else {
            self.record_latency_sample(latency, frame.sequence, MAX_LATENCY_SAMPLES);
        }
    }

    fn record_event_at(&mut self, value: &serde_json::Value, received_timestamp_ms: u64) {
        match value["type"].as_str() {
            Some("message") => self.record_message_at(value, received_timestamp_ms),
            Some("lagged") if value["source"] == "local" => {
                self.local_lag_events = self.local_lag_events.saturating_add(1);
                self.local_dropped = self
                    .local_dropped
                    .saturating_add(value["dropped"].as_u64().unwrap_or(0));
            }
            Some("lagged") if value["source"] == "gossip" => {
                self.gossip_lag_events = self.gossip_lag_events.saturating_add(1);
            }
            Some("peer_up") => self.peer_up = self.peer_up.saturating_add(1),
            Some("peer_down") => self.peer_down = self.peer_down.saturating_add(1),
            _ => {}
        }
    }

    fn record_event(&mut self, value: &serde_json::Value) {
        self.record_event_at(value, unix_timestamp_ms().unwrap_or(0));
    }

    fn percentile(sorted: &[u64], percentile: usize) -> Option<u64> {
        if sorted.is_empty() {
            return None;
        }
        let rank = (percentile * sorted.len()).div_ceil(100);
        Some(sorted[rank.saturating_sub(1)])
    }

    fn missing_sequence_sample(&self) -> Vec<u64> {
        let Some(expected) = self.expected else {
            return Vec::new();
        };
        (0..expected)
            .filter(|sequence| {
                let byte = (*sequence / 8) as usize;
                let mask = 1_u8 << (*sequence % 8);
                self.seen[byte] & mask == 0
            })
            .take(MAX_MISSING_SEQUENCE_SAMPLE)
            .collect()
    }

    fn summary(&mut self, completion_reason: &str, elapsed: Duration) -> serde_json::Value {
        self.latencies.sort_unstable();
        let elapsed_ms = elapsed.as_millis() as u64;
        let elapsed_seconds = elapsed_ms.max(1) as f64 / 1000.0;
        let missing = self
            .expected
            .map(|expected| expected.saturating_sub(self.unique));
        let incomplete = self.local_lag_events > 0 || self.gossip_lag_events > 0;
        let complete = self
            .expected
            .is_some_and(|expected| expected == self.unique);
        let measurement_valid = complete && !incomplete && self.malformed_messages == 0;
        let missing_sequence_sample = self.missing_sequence_sample();
        serde_json::json!({
            "type":"bench_receive_summary", "schema_version":1,
            "run_id":self.run_id, "completion_reason":completion_reason,
            "elapsed_ms":elapsed_ms, "expected":self.expected,
            "complete":complete, "measurement_valid":measurement_valid,
            "unique":self.unique, "missing":missing,
            "missing_sequence_sample":missing_sequence_sample,
            "duplicates":self.duplicates, "out_of_order":self.out_of_order,
            "highest_sequence":self.highest_sequence,
            "body_bytes":self.body_bytes,
            "achieved_messages_per_second":self.unique as f64 / elapsed_seconds,
            "achieved_body_bytes_per_second":self.body_bytes as f64 / elapsed_seconds,
            "latency":{
                "observations":self.latency_observations,
                "samples":self.latencies.len(), "sampled":self.latency_sampled,
                "clock_invalid":self.latency_clock_invalid,
                "p50_ms":Self::percentile(&self.latencies, 50),
                "p95_ms":Self::percentile(&self.latencies, 95),
                "p99_ms":Self::percentile(&self.latencies, 99)
            },
            "lag":{
                "local_events":self.local_lag_events, "local_dropped":self.local_dropped,
                "gossip_events":self.gossip_lag_events, "incomplete":incomplete
            },
            "peer_up":self.peer_up, "peer_down":self.peer_down,
            "ignored_messages":self.ignored_messages,
            "malformed_messages":self.malformed_messages
        })
    }
}

pub async fn bench_receive(
    dir: &Path,
    run_id: String,
    duration_secs: u64,
    expected: Option<u64>,
    json: bool,
) -> Result<()> {
    anyhow::ensure!(valid_run_id(&run_id), "invalid benchmark run ID");
    anyhow::ensure!(
        (1..=86_400).contains(&duration_secs),
        "duration must be between 1 and 86400 seconds"
    );
    let mut stats = BenchReceiveStats::new(run_id.clone(), expected)?;
    let mut reader = subscribe(dir).await?;
    let connected = read_subscription(&mut reader)
        .await?
        .context("local daemon stopped before benchmark receiver connected")?;
    anyhow::ensure!(
        connected["type"] == "connected",
        "unexpected daemon subscription response"
    );
    let started_value = serde_json::json!({
        "type":"bench_receive_started", "schema_version":1,
        "run_id":run_id, "duration_secs":duration_secs, "expected":expected
    });
    print_bench_value(json, &started_value);
    let started = StdInstant::now();
    let deadline = tokio::time::sleep(Duration::from_secs(duration_secs));
    tokio::pin!(deadline);
    let mut completion_reason = "deadline";
    let mut daemon_stopped = false;
    loop {
        tokio::select! {
            value = read_subscription(&mut reader) => match value? {
                Some(value) => stats.record_event(&value),
                None => {
                    completion_reason = "daemon_stopped";
                    daemon_stopped = true;
                    break;
                }
            },
            _ = &mut deadline => break,
            result = tokio::signal::ctrl_c() => {
                result.context("wait for Ctrl-C")?;
                completion_reason = "interrupted";
                break;
            }
        }
    }
    let summary = stats.summary(completion_reason, started.elapsed());
    print_bench_value(json, &summary);
    anyhow::ensure!(
        !daemon_stopped,
        "local daemon stopped during benchmark receive"
    );
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
            "daemon: running\npeer: {}\ntopic: {}\nadvertises self: {}\nhas invite: {}\nbootstrap peers: {}\nself advertised: {}\nendpoint online: {}\ntopic joined: {}\nneighbors: {}",
            value["peer"].as_str().unwrap_or(""),
            value["topic"].as_str().unwrap_or(""),
            value["advertises_self"].as_bool().unwrap_or(false),
            value["has_invite"].as_bool().unwrap_or(false),
            value["bootstrap_peer_count"].as_u64().unwrap_or(0),
            value["self_advertised"].as_bool().unwrap_or(false),
            value["endpoint_online"].as_bool().unwrap_or(false),
            value["topic_joined"].as_bool().unwrap_or(false),
            value["neighbors"].as_u64().unwrap_or(0)
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
    state.validate_for_identity(secret.public())?;
    let (has_invite, bootstrap_peer_count, self_advertised) =
        invite_details(&state, secret.public())?;
    let value = serde_json::json!({
        "type":"doctor", "ok":true, "peer":secret.public().to_string(), "topic":state.topic,
        "advertises_self":state.advertise_self, "has_invite":has_invite,
        "bootstrap_peer_count":bootstrap_peer_count, "self_advertised":self_advertised
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
                "daemon running as {}\nlocal endpoint: {}",
                value["peer"].as_str().unwrap_or(""),
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

    fn assert_object_keys(value: &serde_json::Value, expected: &[&str]) {
        let actual: std::collections::BTreeSet<_> = value
            .as_object()
            .expect("JSON object")
            .keys()
            .map(String::as_str)
            .collect();
        let expected: std::collections::BTreeSet<_> = expected.iter().copied().collect();
        assert_eq!(actual, expected);
    }

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
    fn benchmark_body_is_fixed_size_and_strictly_parsed() {
        let run_id = "0123456789abcdef0123456789abcdef";
        let body = build_bench_body(run_id, 9, 10, 1_700_000_000_000, 256).unwrap();
        assert_eq!(body.len(), 256);
        assert_eq!(
            parse_bench_body(&body).unwrap(),
            Some(BenchFrame {
                run_id,
                sequence: 9,
                total: 10,
                timestamp_ms: 1_700_000_000_000,
            })
        );
        assert!(build_bench_body(run_id, 0, 1, 1_700_000_000_000, 105).is_err());
        assert!(parse_bench_body("ordinary chat message").unwrap().is_none());
        assert!(parse_bench_body(&body.replace("meshmsg-bench-v1", "meshmsg-bench-v2")).is_err());
        assert!(
            parse_bench_body(&body.replace("00000000000000000009", "00000000000000000010"))
                .is_err()
        );
        assert!(parse_bench_body(&body.replace('x', "|")).is_err());
    }

    #[test]
    fn benchmark_payload_preflight_uses_exact_envelope_limit() {
        let run_id = "0123456789abcdef0123456789abcdef";
        let secret = SecretKey::generate();
        let largest_payload = (106..MAX_ENVELOPE_SIZE)
            .rev()
            .find(|payload_bytes| {
                let body =
                    build_bench_body(run_id, 0, 1, 9_999_999_999_999, *payload_bytes).unwrap();
                Envelope::encode_at(&secret, body, 9_999_999_999_999).is_ok()
            })
            .unwrap();
        let config = BenchConfig {
            run_id: run_id.into(),
            rate: 1,
            duration_secs: 1,
            payload_bytes: largest_payload,
        };
        assert_eq!(validate_bench_config(&config).unwrap(), 1);
        let mut too_small = config.clone();
        too_small.payload_bytes = 105;
        assert!(validate_bench_config(&too_small).is_err());
        let mut too_large = config;
        too_large.payload_bytes = largest_payload + 1;
        assert!(validate_bench_config(&too_large).is_err());
    }

    #[test]
    fn benchmark_config_boundaries_are_authoritatively_validated() {
        let base = BenchConfig {
            run_id: "0123456789abcdef0123456789abcdef".into(),
            rate: 1,
            duration_secs: 1,
            payload_bytes: 106,
        };
        for invalid in [
            BenchConfig {
                rate: 0,
                ..base.clone()
            },
            BenchConfig {
                rate: 10_001,
                ..base.clone()
            },
            BenchConfig {
                duration_secs: 0,
                ..base.clone()
            },
            BenchConfig {
                duration_secs: 86_401,
                ..base.clone()
            },
            BenchConfig {
                rate: 10_000,
                duration_secs: 1_001,
                ..base.clone()
            },
        ] {
            assert!(
                validate_bench_config(&invalid).is_err(),
                "accepted {invalid:?}"
            );
        }
        assert_eq!(
            validate_bench_config(&BenchConfig {
                duration_secs: 86_400,
                ..base.clone()
            })
            .unwrap(),
            86_400
        );
        assert_eq!(
            validate_bench_config(&BenchConfig {
                rate: 10_000,
                duration_secs: 1_000,
                ..base
            })
            .unwrap(),
            MAX_BENCH_MESSAGES
        );
    }

    #[test]
    fn benchmark_schedule_and_sender_summary_are_deterministic() {
        let period = Duration::from_millis(100);
        assert_eq!(benchmark_due_slots(Duration::ZERO, period, 10), 1);
        assert_eq!(
            benchmark_due_slots(Duration::from_millis(99), period, 10),
            1
        );
        assert_eq!(
            benchmark_due_slots(Duration::from_millis(100), period, 10),
            2
        );
        assert_eq!(
            benchmark_due_slots(Duration::from_millis(550), period, 10),
            6
        );
        assert_eq!(benchmark_due_slots(Duration::from_secs(1), period, 10), 10);
        let mut next_slot = 0;
        let mut schedule_missed = 0;
        assert_eq!(
            advance_benchmark_slot(1, &mut next_slot, &mut schedule_missed),
            0
        );
        assert_eq!(
            advance_benchmark_slot(6, &mut next_slot, &mut schedule_missed),
            5
        );
        assert_eq!(schedule_missed, 4);
        assert_eq!(
            advance_benchmark_slot(7, &mut next_slot, &mut schedule_missed),
            6
        );
        assert_eq!(schedule_missed, 4);

        let config = BenchConfig {
            run_id: "0123456789abcdef0123456789abcdef".into(),
            rate: 10,
            duration_secs: 1,
            payload_bytes: 128,
        };
        let stats = BenchSendStats {
            attempted: 7,
            queued: 6,
            failed: 1,
            schedule_missed: 2,
            body_bytes: 768,
            envelope_bytes: 1_200,
            first_error: Some("scripted failure".into()),
        };
        let summary = bench_send_summary(
            &config,
            10,
            &stats,
            "send_failed",
            Duration::from_millis(500),
        );
        assert_object_keys(
            &summary,
            &[
                "type",
                "schema_version",
                "run_id",
                "rate",
                "duration_secs",
                "payload_bytes",
                "planned",
                "attempted",
                "queued",
                "failed",
                "schedule_missed",
                "queued_body_bytes",
                "queued_envelope_bytes",
                "elapsed_ms",
                "achieved_messages_per_second",
                "achieved_body_bytes_per_second",
                "completion_reason",
                "first_error",
                "delivery_acknowledged",
            ],
        );
        assert_eq!(summary["type"], "bench_send_summary");
        assert_eq!(summary["schema_version"], 1);
        assert_eq!(summary["planned"], 10);
        assert_eq!(summary["attempted"], 7);
        assert_eq!(summary["queued"], 6);
        assert_eq!(summary["failed"], 1);
        assert_eq!(summary["schedule_missed"], 2);
        assert_eq!(summary["queued_body_bytes"], 768);
        assert_eq!(summary["completion_reason"], "send_failed");
        assert_eq!(summary["first_error"], "scripted failure");
        assert_eq!(summary["delivery_acknowledged"], false);
        assert_eq!(summary["achieved_messages_per_second"], 12.0);
    }

    #[test]
    fn benchmark_receiver_counts_unique_order_missing_and_lag() {
        let run_id = "0123456789abcdef0123456789abcdef";
        let timestamp_ms = unix_timestamp_ms().unwrap();
        let mut stats = BenchReceiveStats::new(run_id.into(), Some(4)).unwrap();
        for sequence in [2, 0, 2, 1] {
            let body = build_bench_body(run_id, sequence, 4, timestamp_ms, 128).unwrap();
            stats.record_event_at(
                &serde_json::json!({
                    "type":"message", "timestamp_ms":timestamp_ms, "body":body
                }),
                timestamp_ms + 25,
            );
        }
        stats.record_event_at(
            &serde_json::json!({
                "type":"message", "timestamp_ms":timestamp_ms,
                "body":build_bench_body("ffffffffffffffffffffffffffffffff", 0, 1, timestamp_ms, 128).unwrap()
            }),
            timestamp_ms + 25,
        );
        stats.record_event(&serde_json::json!({
            "type":"lagged", "source":"local", "dropped":7
        }));
        stats.record_event(&serde_json::json!({
            "type":"lagged", "source":"gossip", "dropped":null
        }));
        let summary = stats.summary("deadline", Duration::from_secs(1));
        assert_object_keys(
            &summary,
            &[
                "type",
                "schema_version",
                "run_id",
                "completion_reason",
                "elapsed_ms",
                "expected",
                "complete",
                "measurement_valid",
                "unique",
                "missing",
                "missing_sequence_sample",
                "duplicates",
                "out_of_order",
                "highest_sequence",
                "body_bytes",
                "achieved_messages_per_second",
                "achieved_body_bytes_per_second",
                "latency",
                "lag",
                "peer_up",
                "peer_down",
                "ignored_messages",
                "malformed_messages",
            ],
        );
        assert_object_keys(
            &summary["latency"],
            &[
                "observations",
                "samples",
                "sampled",
                "clock_invalid",
                "p50_ms",
                "p95_ms",
                "p99_ms",
            ],
        );
        assert_object_keys(
            &summary["lag"],
            &[
                "local_events",
                "local_dropped",
                "gossip_events",
                "incomplete",
            ],
        );
        assert_eq!(summary["unique"], 3);
        assert_eq!(summary["missing"], 1);
        assert_eq!(summary["missing_sequence_sample"], serde_json::json!([3]));
        assert_eq!(summary["duplicates"], 1);
        assert_eq!(summary["out_of_order"], 2);
        assert_eq!(summary["ignored_messages"], 1);
        assert_eq!(summary["lag"]["local_events"], 1);
        assert_eq!(summary["lag"]["local_dropped"], 7);
        assert_eq!(summary["lag"]["gossip_events"], 1);
        assert_eq!(summary["lag"]["incomplete"], true);
        assert_eq!(summary["measurement_valid"], false);
        assert_eq!(summary["latency"]["observations"], 3);
        assert_eq!(summary["latency"]["p50_ms"], 25);
    }

    #[test]
    fn benchmark_latency_reservoir_is_bounded_and_deterministic() {
        let mut left =
            BenchReceiveStats::new("0123456789abcdef0123456789abcdef".into(), Some(10)).unwrap();
        let mut right =
            BenchReceiveStats::new("0123456789abcdef0123456789abcdef".into(), Some(10)).unwrap();
        for sequence in 0..10 {
            left.record_latency_sample(sequence, sequence, 3);
            right.record_latency_sample(sequence, sequence, 3);
        }
        assert_eq!(left.latency_observations, 10);
        assert_eq!(left.latencies.len(), 3);
        assert!(left.latency_sampled);
        assert_eq!(left.latencies, right.latencies);
        assert_ne!(left.latencies, vec![7, 8, 9]);
    }

    #[test]
    fn benchmark_receiver_handles_clock_skew_learning_and_bounded_missing_sample() {
        let run_id = "0123456789abcdef0123456789abcdef";
        let timestamp_ms = 1_700_000_000_000;
        let mut stats = BenchReceiveStats::new(run_id.into(), None).unwrap();
        for (sequence, received_timestamp_ms) in [
            (0, timestamp_ms - 1),
            (150, timestamp_ms + MAX_LATENCY_MS + 1),
        ] {
            let body = build_bench_body(run_id, sequence, 200, timestamp_ms, 128).unwrap();
            stats.record_event_at(
                &serde_json::json!({
                    "type":"message", "timestamp_ms":timestamp_ms, "body":body
                }),
                received_timestamp_ms,
            );
        }
        let summary = stats.summary("deadline", Duration::from_secs(1));
        assert_eq!(summary["expected"], 200);
        assert_eq!(summary["unique"], 2);
        assert_eq!(summary["missing"], 198);
        assert_eq!(
            summary["missing_sequence_sample"].as_array().unwrap().len(),
            MAX_MISSING_SEQUENCE_SAMPLE
        );
        assert_eq!(summary["latency"]["observations"], 0);
        assert_eq!(summary["latency"]["samples"], 0);
        assert_eq!(summary["latency"]["clock_invalid"], 2);
        assert!(summary["latency"]["p50_ms"].is_null());
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
    fn daemon_log_message_event_suppresses_body_but_keeps_metadata() {
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
        let value = startup_error_value("topic_join", "bootstrap peer unavailable");

        assert_eq!(value["type"], "startup_error");
        assert_eq!(value["phase"], "topic_join");
        assert_eq!(value["retryable"], true);
        assert!(STARTUP_TIMEOUT <= Duration::from_secs(60));
        assert!(ENDPOINT_ONLINE_TIMEOUT <= Duration::from_secs(60));
    }

    #[tokio::test]
    async fn doctor_rejects_unpublishable_advertising_state() {
        let dir = std::env::temp_dir().join(format!(
            "meshmsg-doctor-capacity-test-{}",
            rand::random::<u64>()
        ));
        let invite = Invite {
            topic: TopicId::from_bytes([8; 32]),
            bootstrap_peers: (0..crate::invite::MAX_BOOTSTRAP_PEERS)
                .map(|_| iroh::EndpointAddr::new(SecretKey::generate().public()))
                .collect(),
        };
        State::from_invite(invite.to_string(), &invite, true)
            .save_new(&dir, false)
            .unwrap();

        let error = doctor(&dir, true).await.unwrap_err();

        assert!(error.to_string().contains("cannot advertise self"));
        std::fs::remove_dir_all(dir).unwrap();
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
    async fn benchmark_sender_cancels_while_daemon_reply_is_pending() {
        let (mut client, server) = tokio::io::duplex(MAX_IPC_EVENT_SIZE);
        let (commands, mut command_rx) = mpsc::channel(1);
        let (_events, receiver) = broadcast::channel(1);
        let busy = Arc::new(AtomicBool::new(false));
        let task = tokio::spawn(handle_local_client(
            server,
            commands,
            receiver,
            serde_json::json!({"type":"connected"}),
            busy.clone(),
        ));
        write_request(
            &mut client,
            &IpcRequest::BenchSend {
                config: BenchConfig {
                    run_id: "0123456789abcdef0123456789abcdef".into(),
                    rate: 1,
                    duration_secs: 10,
                    payload_bytes: 128,
                },
            },
        )
        .await
        .unwrap();
        let started = read_frame(&mut client, MAX_IPC_EVENT_SIZE).await.unwrap();
        let started: serde_json::Value = serde_json::from_slice(&started).unwrap();
        assert_eq!(started["type"], "bench_send_started");
        let command = tokio::time::timeout(Duration::from_secs(1), command_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let DaemonCommand::BenchMessage { cancel, reply, .. } = command else {
            panic!("expected benchmark message")
        };
        client.write_all(b"\n").await.unwrap();
        assert!(cancel.await.is_ok());
        drop(reply);
        let summary = tokio::time::timeout(
            Duration::from_secs(1),
            read_frame(&mut client, MAX_IPC_EVENT_SIZE),
        )
        .await
        .unwrap()
        .unwrap();
        let summary: serde_json::Value = serde_json::from_slice(&summary).unwrap();
        assert_eq!(summary["completion_reason"], "interrupted");
        assert_eq!(summary["attempted"], 1);
        assert_eq!(summary["queued"], 0);
        task.await.unwrap().unwrap();
        assert!(!busy.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn benchmark_sender_stops_at_first_send_failure() {
        let (mut client, server) = tokio::io::duplex(MAX_IPC_EVENT_SIZE);
        let (commands, mut command_rx) = mpsc::channel(1);
        let (_events, receiver) = broadcast::channel(1);
        let task = tokio::spawn(handle_local_client(
            server,
            commands,
            receiver,
            serde_json::json!({"type":"connected"}),
            Arc::new(AtomicBool::new(false)),
        ));
        write_request(
            &mut client,
            &IpcRequest::BenchSend {
                config: BenchConfig {
                    run_id: "0123456789abcdef0123456789abcdef".into(),
                    rate: 100,
                    duration_secs: 10,
                    payload_bytes: 128,
                },
            },
        )
        .await
        .unwrap();
        let _started = read_frame(&mut client, MAX_IPC_EVENT_SIZE).await.unwrap();
        let command = command_rx.recv().await.unwrap();
        let DaemonCommand::BenchMessage { reply, .. } = command else {
            panic!("expected benchmark message")
        };
        reply
            .send(Err("scripted broadcast failure".into()))
            .unwrap();
        let summary = read_frame(&mut client, MAX_IPC_EVENT_SIZE).await.unwrap();
        let summary: serde_json::Value = serde_json::from_slice(&summary).unwrap();
        assert_eq!(summary["completion_reason"], "send_failed");
        assert_eq!(summary["attempted"], 1);
        assert_eq!(summary["failed"], 1);
        assert_eq!(summary["first_error"], "scripted broadcast failure");
        task.await.unwrap().unwrap();
        assert!(command_rx.try_recv().is_err());
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
            Arc::new(AtomicBool::new(false)),
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
            Arc::new(AtomicBool::new(false)),
        ));
        client
            .write_all(b"{\"command\":\"subscribe\"}\n")
            .await
            .unwrap();
        let _connected = read_frame(&mut client, MAX_IPC_EVENT_SIZE).await.unwrap();
        let lagged = read_frame(&mut client, MAX_IPC_EVENT_SIZE).await.unwrap();
        let lagged: serde_json::Value = serde_json::from_slice(&lagged).unwrap();
        assert_eq!(lagged["type"], "lagged");
        assert_eq!(lagged["source"], "local");
        assert_eq!(lagged["dropped"], 1);

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
