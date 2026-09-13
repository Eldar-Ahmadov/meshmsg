#[cfg(test)]
use crate::ipc::write_request;
use crate::{
    alias::AliasConfig,
    attachment::{
        self,
        protocol::{offer_event as attachment_offer_event, validate_offer_binding},
        runtime::*,
    },
    config::{prepare_state_dir, State, StateLock},
    contracts::{self},
    direct::{self, DIRECT_ALPN},
    gossip::{self, EventHandler as GossipEventHandler},
    invite::Invite,
    ipc::{
        read_frame, send_request_checked, subscribe, IpcRequest, IpcRequestFrame,
        MAX_IPC_REQUEST_SIZE,
    },
    presence::{self, Directory, PresenceSourceLimiter},
};
use anyhow::{Context, Result};
#[cfg(test)]
use bytes::Bytes;
#[cfg(test)]
use data_encoding::BASE64URL_NOPAD;
use futures_util::TryStreamExt;
use iroh::{
    address_lookup::memory::MemoryLookup, endpoint::presets, protocol::Router, Endpoint, PublicKey,
    SecretKey, Watcher,
};
use iroh_blobs::{
    api::{downloader::Downloader, Store},
    store::{
        fs::{options::Options as FsStoreOptions, FsStore},
        GcConfig,
    },
    BlobsProtocol,
};
use iroh_gossip::{
    api::{Event, GossipReceiver, GossipSender},
    net::Gossip,
    proto::TopicId,
};
#[cfg(test)]
use serde_byte_array::ByteArray;
use std::{
    collections::{HashMap, VecDeque},
    io::BufRead as _,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant as StdInstant, SystemTime, UNIX_EPOCH},
};
#[cfg(windows)]
use tokio::net::windows::named_pipe::{
    ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite},
    sync::{broadcast, mpsc, oneshot, OwnedSemaphorePermit, Semaphore},
};

#[cfg(test)]
use crate::{
    attachment::{
        protocol::{
            attachment_body, parse_attachment_body, parse_signed_offer_token,
            validate_attachment_event, AttachmentWire, ATTACHMENT_OFFER_VERSION, ATTACHMENT_PREFIX,
        },
        AttachmentKind, AttachmentOffer,
    },
    gossip::{
        Envelope, EnvelopeKind, EnvelopeReplayCache, EnvelopeSignaturePayload, TokenBucket,
        TransportSourceLimiter, ENVELOPE_ACCEPTANCE_WINDOW, ENVELOPE_DOMAIN, ENVELOPE_FUTURE_SKEW,
        ENVELOPE_VERSION, GLOBAL_REPLAY_BURST, GLOBAL_TRANSPORT_BURST, MAX_ENVELOPE_REPLAY_ENTRIES,
        MAX_ENVELOPE_SIZE, MAX_MESSAGE_SIZE as GOSSIP_MAX_MESSAGE_SIZE, MAX_REPLAY_IDS_PER_SENDER,
        MAX_REPLAY_SENDERS_PER_SOURCE, MAX_TRANSPORT_SOURCES, PER_SENDER_REPLAY_BURST,
        PROTOCOL_HEADROOM as GOSSIP_PROTOCOL_HEADROOM, REPLAY_BUCKET_RETENTION,
        REPLAY_BUCKET_WIDTH, SIGNATURE_LENGTH, TRANSPORT_SOURCE_BURST,
        TRANSPORT_SOURCE_IDLE_LIFETIME,
    },
    ipc::{
        write_request_with_id, MAX_IPC_EVENT_SIZE, MAX_OFFER_LIST_ENTRIES, MAX_OFFER_LIST_SCANNED,
    },
};
#[cfg(test)]
use iroh_blobs::{ticket::BlobTicket, BlobFormat};
#[cfg(test)]
use std::{collections::BTreeMap, sync::atomic::Ordering};
#[cfg(test)]
use tokio::io::AsyncWriteExt;

const IPC_EVENT_CAPACITY: usize = 256;
/// Bounds all accepted local IPC connections, including long-lived subscriptions
/// and subscriptions. Connections beyond this limit receive a small rejection and
/// are closed without creating a handler task.
const LOCAL_IPC_CONNECTION_CAPACITY: usize = 64;
const LOCAL_IPC_INITIAL_FRAME_TIMEOUT: Duration = Duration::from_secs(8);
const LOCAL_IPC_RESPONSE_WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const LOCAL_IPC_ORDINARY_COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
const LOCAL_IPC_PRIVATE_COMMAND_TIMEOUT: Duration = Duration::from_secs(35);
const LOCAL_IPC_LIST_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const LOCAL_IPC_TRANSFER_COMMAND_TIMEOUT: Duration = Duration::from_secs(60 * 60 + 10);
const LOCAL_IPC_SHUTDOWN_GRACE: Duration = Duration::from_secs(2);
const LOCAL_IPC_REJECTION_WRITE_TIMEOUT: Duration = Duration::from_millis(250);
const STARTUP_TIMEOUT: Duration = Duration::from_secs(45);
const ENDPOINT_ONLINE_TIMEOUT: Duration = Duration::from_secs(30);
/// Re-issue the gossip join after connectivity loss. `join_peers` only queues a
/// connection attempt, so repeating it also covers attempts made while the
/// network interface is still unavailable.
const REJOIN_INTERVAL: Duration = Duration::from_secs(5);
const BLOB_GC_INTERVAL: Duration = Duration::from_secs(60 * 60);
const ATTACHMENT_RETENTION_CHECK_INTERVAL: Duration = Duration::from_secs(60 * 60);
const ATTACHMENT_SPACE_REFRESH_INTERVAL: Duration = Duration::from_secs(30);
pub(crate) const DEFAULT_MAX_ATTACHMENT_STORAGE_BYTES: u64 = 16 * 1024 * 1024 * 1024;
pub(crate) const DEFAULT_MIN_FREE_SPACE_BYTES: u64 = 1024 * 1024 * 1024;
pub(crate) const DEFAULT_ATTACHMENT_RETENTION_SECS: u64 = 0;
#[cfg(unix)]
const SOCKET_NAME: &str = "daemon.sock";
fn unix_timestamp_ms() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64)
}

fn unix_timestamp_ms_saturating(now: SystemTime) -> u64 {
    now.duration_since(UNIX_EPOCH)
        .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

struct RunningNode {
    endpoint: Endpoint,
    router: Router,
    sender: GossipSender,
    receiver: GossipReceiver,
    presence_sender: GossipSender,
    presence_receiver: GossipReceiver,
    secret: SecretKey,
    bootstrap_peers: Vec<PublicKey>,
    bootstrap_addrs: Vec<iroh::EndpointAddr>,
    blob_store: Store,
    downloader: Downloader,
    lookup: MemoryLookup,
    presence_lookup: MemoryLookup,
    direct_replay: direct::ReplayWorker,
    direct_incoming: mpsc::Receiver<meshmsg_protocol::Event>,
}

async fn start(state: &State, secret: SecretKey, state_dir: &Path) -> Result<RunningNode> {
    state.validate()?;
    attachment::cleanup_stale_state_staging(state_dir)
        .context("recover stale attachment share staging")?;
    let topic: TopicId = state.topic_id()?;
    // Keep stable invite/attachment routes isolated from expiring presence.
    // Each MemoryLookup owns one source so presence cleanup cannot erase another.
    let lookup = MemoryLookup::with_provenance("meshmsg_stable");
    let presence_lookup = MemoryLookup::with_provenance("meshmsg_presence");
    let endpoint = Endpoint::builder(presets::N0)
        .secret_key(secret.clone())
        .address_lookup(lookup.clone())
        .address_lookup(presence_lookup.clone())
        .bind()
        .await?;
    let gossip = Gossip::builder()
        .alpn(gossip::ALPN)
        .max_message_size(gossip::MAX_MESSAGE_SIZE)
        .spawn(endpoint.clone());
    // Isolate control-plane membership from the long-standing broadcast Gossip
    // actor. Sharing one actor/connection pool across both topics can perturb
    // broadcast neighbor liveness during failover and rejoin.
    let presence_gossip = Gossip::builder()
        .alpn(presence::ALPN)
        .max_message_size(presence::MAX_GOSSIP_MESSAGE_SIZE)
        .spawn(endpoint.clone());
    let blob_root = state_dir.join("blobs-v1").join(secret.public().to_string());
    let mut blob_options = FsStoreOptions::new(&blob_root);
    blob_options.gc = Some(GcConfig {
        interval: BLOB_GC_INTERVAL,
        add_protected: None,
    });
    let fs_store = FsStore::load_with_opts(blob_root.join("blobs.db"), blob_options)
        .await
        .context("open persistent attachment store")?;
    let blob_store: Store = fs_store.into();
    let downloader = blob_store.downloader(&endpoint);
    let blobs = BlobsProtocol::new(&blob_store, None);
    let (direct, direct_replay, direct_incoming) = direct::setup(secret.clone(), topic, state_dir)
        .context("open persistent direct replay state")?;
    let router = Router::builder(endpoint.clone())
        .accept(gossip::ALPN, gossip.clone())
        .accept(presence::ALPN, presence_gossip.clone())
        .accept(iroh_blobs::ALPN, blobs)
        .accept(DIRECT_ALPN, direct)
        .spawn();
    let mut bootstrap = Vec::new();
    let mut bootstrap_addrs = Vec::new();
    if let Some(token) = &state.invite {
        let invite: Invite = token.parse()?;
        for peer in invite.bootstrap_peers {
            if peer.id != endpoint.id() {
                presence::validate_endpoint_addr(&peer, peer.id)
                    .context("invalid bootstrap endpoint address")?;
                bootstrap.push(peer.id);
                bootstrap_addrs.push(peer.clone());
                lookup.set_endpoint_info(peer);
            }
        }
    }
    let subscription = if bootstrap.is_empty() {
        gossip.subscribe(topic, vec![]).await?
    } else {
        gossip.subscribe_and_join(topic, bootstrap.clone()).await?
    };
    let (sender, receiver) = subscription.split();
    let presence_subscription = if bootstrap.is_empty() {
        presence_gossip
            .subscribe(presence::presence_topic(topic), vec![])
            .await?
    } else {
        presence_gossip
            .subscribe_and_join(presence::presence_topic(topic), bootstrap.clone())
            .await?
    };
    let (presence_sender, presence_receiver) = presence_subscription.split();
    Ok(RunningNode {
        endpoint,
        router,
        sender,
        receiver,
        presence_sender,
        presence_receiver,
        secret,
        bootstrap_peers: bootstrap,
        bootstrap_addrs,
        blob_store,
        downloader,
        lookup,
        presence_lookup,
        direct_replay,
        direct_incoming,
    })
}

const OPERATION_CACHE_CAPACITY: usize = 1_024;
const OPERATION_CACHE_TTL: Duration = Duration::from_secs(10 * 60);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PruneResolution {
    older_than_secs: u64,
    cutoff_ms: u64,
}

struct CompletedOperation {
    fingerprint: [u8; 32],
    response: meshmsg_protocol::Response,
    expires_at: StdInstant,
    prune_resolution: Option<PruneResolution>,
}

struct InFlightOperation {
    fingerprint: [u8; 32],
    waiters: Vec<oneshot::Sender<meshmsg_protocol::Response>>,
    prune_resolution: Option<PruneResolution>,
}

struct OperationCache {
    capacity: usize,
    ttl: Duration,
    completed: HashMap<String, CompletedOperation>,
    order: VecDeque<String>,
    in_flight: HashMap<String, InFlightOperation>,
}

impl OperationCache {
    fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            capacity,
            ttl,
            completed: HashMap::new(),
            order: VecDeque::new(),
            in_flight: HashMap::new(),
        }
    }

    fn prune(&mut self, now: StdInstant) {
        self.completed.retain(|_, entry| entry.expires_at > now);
        self.order.retain(|id| self.completed.contains_key(id));
    }

    fn error(operation_id: &str, code: meshmsg_protocol::ErrorCode) -> meshmsg_protocol::Response {
        contracts::protocol_error_response(
            code,
            meshmsg_protocol::Outcome::NotStarted,
            Some(operation_id.parse().expect("validated operation ID")),
        )
    }

    /// Returns true only for the first caller that must execute the operation.
    fn admit(
        &mut self,
        operation_id: String,
        fingerprint: [u8; 32],
        reply: oneshot::Sender<meshmsg_protocol::Response>,
        now: StdInstant,
    ) -> bool {
        self.prune(now);
        if let Some(entry) = self.completed.get(&operation_id) {
            let response = if entry.fingerprint == fingerprint {
                if let (Some(resolution), meshmsg_protocol::Response::OffersPruned(result)) =
                    (entry.prune_resolution, &entry.response)
                {
                    debug_assert_eq!(result.older_than_secs, Some(resolution.older_than_secs));
                    debug_assert_eq!(result.cutoff_ms, Some(resolution.cutoff_ms));
                }
                entry.response.clone()
            } else {
                Self::error(
                    &operation_id,
                    meshmsg_protocol::ErrorCode::OperationIdConflict,
                )
            };
            let _ = reply.send(response);
            return false;
        }
        if let Some(entry) = self.in_flight.get_mut(&operation_id) {
            if entry.fingerprint == fingerprint {
                entry.waiters.push(reply);
            } else {
                let _ = reply.send(Self::error(
                    &operation_id,
                    meshmsg_protocol::ErrorCode::OperationIdConflict,
                ));
            }
            return false;
        }
        while self.completed.len() + self.in_flight.len() >= self.capacity {
            let Some(oldest) = self.order.pop_front() else {
                let _ = reply.send(Self::error(
                    &operation_id,
                    meshmsg_protocol::ErrorCode::OperationCapacity,
                ));
                return false;
            };
            self.completed.remove(&oldest);
        }
        self.in_flight.insert(
            operation_id,
            InFlightOperation {
                fingerprint,
                waiters: vec![reply],
                prune_resolution: None,
            },
        );
        true
    }

    /// Resolve a prune boundary only for the newly admitted owner and retain it
    /// with the cache entry so execution and terminal replay share one authority.
    fn resolve_prune(
        &mut self,
        operation_id: &str,
        older_than_secs: u64,
        now_ms: u64,
    ) -> PruneResolution {
        let entry = self
            .in_flight
            .get_mut(operation_id)
            .expect("newly admitted prune is in flight");
        let resolution = *entry.prune_resolution.get_or_insert(PruneResolution {
            older_than_secs,
            cutoff_ms: crate::ipc::prune_cutoff_upper_bound(now_ms, older_than_secs),
        });
        debug_assert_eq!(resolution.older_than_secs, older_than_secs);
        resolution
    }

    fn complete(
        &mut self,
        operation_id: &str,
        response: meshmsg_protocol::Response,
        now: StdInstant,
    ) -> meshmsg_protocol::Response {
        let Some(in_flight) = self.in_flight.remove(operation_id) else {
            return response;
        };
        for waiter in in_flight.waiters {
            let _ = waiter.send(response.clone());
        }
        self.completed.insert(
            operation_id.to_owned(),
            CompletedOperation {
                fingerprint: in_flight.fingerprint,
                response,
                expires_at: now + self.ttl,
                prune_resolution: in_flight.prune_resolution,
            },
        );
        self.order.push_back(operation_id.to_owned());
        self.completed
            .get(operation_id)
            .expect("completed operation was inserted")
            .response
            .clone()
    }
}

fn operation_id_bytes(operation_id: &str) -> [u8; 16] {
    data_encoding::HEXLOWER
        .decode(operation_id.as_bytes())
        .expect("validated operation ID")
        .try_into()
        .expect("validated operation ID length")
}

fn operation_fingerprint(kind: &str, fields: &[&[u8]]) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let mut digest = Sha256::new();
    digest.update(b"meshmsg-operation-v1\0");
    digest.update(kind.as_bytes());
    for field in fields {
        digest.update((field.len() as u64).to_le_bytes());
        digest.update(field);
    }
    digest.finalize().into()
}

fn optional_text_fingerprint(value: Option<&str>) -> Vec<u8> {
    match value {
        Some(value) => [b"some\0".as_slice(), value.as_bytes()].concat(),
        None => b"none".to_vec(),
    }
}

enum DaemonCommand {
    Send {
        operation_id: String,
        body: String,
        reply: oneshot::Sender<meshmsg_protocol::Response>,
    },
    PrivateSend {
        operation_id: String,
        to: String,
        body: String,
        reply: oneshot::Sender<meshmsg_protocol::Response>,
    },
    Status {
        reply: oneshot::Sender<meshmsg_protocol::Response>,
    },
    Peers {
        reply: oneshot::Sender<meshmsg_protocol::Response>,
    },
    Offers {
        reply: oneshot::Sender<meshmsg_protocol::Response>,
    },
    OffersRemove {
        operation_id: String,
        offer_id: String,
        direction: Option<String>,
        provider: Option<String>,
        reply: oneshot::Sender<meshmsg_protocol::Response>,
    },
    OffersPrune {
        operation_id: String,
        older_than_secs: u64,
        direction: Option<String>,
        dry_run: bool,
        max_delete: usize,
        reply: oneshot::Sender<meshmsg_protocol::Response>,
    },
    Share {
        operation_id: String,
        source_digest: String,
        path: PathBuf,
        reply: oneshot::Sender<meshmsg_protocol::Response>,
    },
    Download {
        operation_id: String,
        offer: String,
        output: PathBuf,
        mode: meshmsg_protocol::DownloadMode,
        reply: oneshot::Sender<meshmsg_protocol::Response>,
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

#[cfg(test)]
impl LocalEndpointGuard {
    /// Consume the guard before a test removes its state directory. On Unix the
    /// socket cleanup runs through `Drop`; on Windows the zero-sized ownership
    /// marker is simply consumed without pretending it owns a closeable handle.
    fn release_for_test(self) {}
}

#[cfg(unix)]
type LocalServerStream = UnixStream;
#[cfg(unix)]
pub(crate) type LocalClientStream = UnixStream;
#[cfg(windows)]
type LocalServerStream = NamedPipeServer;
#[cfg(windows)]
pub(crate) type LocalClientStream = NamedPipeClient;

// Read EOF alone does not end a Unix subscription: clients may shut down only
// their write half and keep receiving events. Check full closure without writing
// protocol bytes, and only poll after EOF so ordinary subscribers incur no cost.
trait SubscriptionStream: AsyncRead + AsyncWrite + Unpin {
    fn subscription_closed_after_eof(&self) -> Result<bool> {
        Ok(true)
    }
}

#[cfg(unix)]
impl SubscriptionStream for UnixStream {
    fn subscription_closed_after_eof(&self) -> Result<bool> {
        use rustix::event::{poll, PollFd, PollFlags, Timespec};
        let mut fds = [PollFd::new(self, PollFlags::empty())];
        match poll(&mut fds, Some(&Timespec::default())) {
            Ok(_) => {
                let flags = fds[0].revents();
                anyhow::ensure!(
                    !flags.contains(PollFlags::NVAL),
                    "invalid subscription socket"
                );
                Ok(flags.intersects(PollFlags::HUP | PollFlags::ERR))
            }
            Err(rustix::io::Errno::INTR) => Ok(false),
            Err(error) => Err(error).context("poll subscription socket closure"),
        }
    }
}

#[cfg(windows)]
impl SubscriptionStream for NamedPipeServer {}

#[cfg(test)]
impl SubscriptionStream for tokio::io::DuplexStream {}

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
        self.pending
            .replace(next)
            .context("named pipe listener missing")
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
    unsafe { LocalFree(descriptor) };
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

#[derive(Clone, Copy)]
struct LocalIpcTimeouts {
    initial_frame: Duration,
    response_write: Duration,
    ordinary_command: Duration,
    private_command: Duration,
    list_command: Duration,
    transfer_command: Duration,
    rejection_write: Duration,
}

impl Default for LocalIpcTimeouts {
    fn default() -> Self {
        Self {
            initial_frame: LOCAL_IPC_INITIAL_FRAME_TIMEOUT,
            response_write: LOCAL_IPC_RESPONSE_WRITE_TIMEOUT,
            ordinary_command: LOCAL_IPC_ORDINARY_COMMAND_TIMEOUT,
            private_command: LOCAL_IPC_PRIVATE_COMMAND_TIMEOUT,
            list_command: LOCAL_IPC_LIST_COMMAND_TIMEOUT,
            transfer_command: LOCAL_IPC_TRANSFER_COMMAND_TIMEOUT,
            rejection_write: LOCAL_IPC_REJECTION_WRITE_TIMEOUT,
        }
    }
}

async fn write_local_frame<S>(
    stream: &mut S,
    frame: &meshmsg_protocol::DaemonFrame,
    deadline: Duration,
) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    tokio::time::timeout(
        deadline,
        meshmsg_protocol::write_json(stream, frame, meshmsg_protocol::FrameLimit::Event),
    )
    .await
    .context("timed out writing local IPC frame")?
    .map_err(anyhow::Error::from)
}

async fn write_local_response<S>(
    stream: &mut S,
    request_id: Option<meshmsg_protocol::RequestId>,
    response: meshmsg_protocol::Response,
    deadline: Duration,
) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    write_local_frame(
        stream,
        &meshmsg_protocol::DaemonFrame::Response(meshmsg_protocol::ResponseFrame::new(
            request_id, response,
        )),
        deadline,
    )
    .await
}

async fn write_local_event<S>(
    stream: &mut S,
    request_id: meshmsg_protocol::RequestId,
    event: meshmsg_protocol::Event,
    deadline: Duration,
) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    write_local_frame(
        stream,
        &meshmsg_protocol::DaemonFrame::Event(meshmsg_protocol::EventFrame::new(request_id, event)),
        deadline,
    )
    .await
}

async fn command_response<F>(
    operation: F,
    deadline: Duration,
    operation_id: Option<meshmsg_protocol::OperationId>,
) -> meshmsg_protocol::Response
where
    F: std::future::Future<Output = Result<meshmsg_protocol::Response>>,
{
    match tokio::time::timeout(deadline, operation).await {
        Ok(Ok(value)) => value,
        Ok(Err(_)) => meshmsg_protocol::Response::Error(meshmsg_protocol::ProtocolError::new(
            operation_id,
            meshmsg_protocol::ErrorCode::DaemonStopping,
            meshmsg_protocol::Outcome::Unknown,
        )),
        Err(_) => meshmsg_protocol::Response::Error(meshmsg_protocol::ProtocolError::new(
            operation_id,
            meshmsg_protocol::ErrorCode::CommandTimeout,
            meshmsg_protocol::Outcome::Unknown,
        )),
    }
}

async fn lifecycle_command_response<F>(
    operation: F,
    deadline: Duration,
    operation_id: Option<meshmsg_protocol::OperationId>,
    _offer_id: Option<String>,
) -> meshmsg_protocol::Response
where
    F: std::future::Future<Output = Result<meshmsg_protocol::Response>>,
{
    match tokio::time::timeout(deadline, operation).await {
        Ok(Ok(value)) => value,
        Ok(Err(_)) => meshmsg_protocol::Response::Error(meshmsg_protocol::ProtocolError::new(
            operation_id,
            meshmsg_protocol::ErrorCode::AttachmentStorageShutdown,
            meshmsg_protocol::Outcome::Unknown,
        )),
        Err(_) => meshmsg_protocol::Response::Error(meshmsg_protocol::ProtocolError::new(
            operation_id,
            meshmsg_protocol::ErrorCode::AttachmentCommandTimeout,
            meshmsg_protocol::Outcome::Unknown,
        )),
    }
}

async fn send_command(
    commands: &mpsc::Sender<DaemonCommand>,
    command: DaemonCommand,
    response: oneshot::Receiver<meshmsg_protocol::Response>,
) -> Result<meshmsg_protocol::Response> {
    commands.send(command).await?;
    Ok(response.await?)
}

#[cfg(test)]
async fn handle_local_client<S>(
    stream: S,
    commands: mpsc::Sender<DaemonCommand>,
    events: broadcast::Receiver<meshmsg_protocol::Event>,
    connected: meshmsg_protocol::Event,
    startup_peers: Option<meshmsg_protocol::Event>,
) -> Result<()>
where
    S: SubscriptionStream,
{
    handle_local_client_with_timeouts(
        stream,
        commands,
        events,
        connected,
        startup_peers,
        LocalIpcTimeouts::default(),
    )
    .await
}

async fn handle_local_client_with_timeouts<S>(
    stream: S,
    commands: mpsc::Sender<DaemonCommand>,
    events: broadcast::Receiver<meshmsg_protocol::Event>,
    connected: meshmsg_protocol::Event,
    startup_peers: Option<meshmsg_protocol::Event>,
    timeouts: LocalIpcTimeouts,
) -> Result<()>
where
    S: SubscriptionStream,
{
    handle_local_client_inner(stream, commands, events, connected, startup_peers, timeouts).await
}

async fn handle_local_client_inner<S>(
    mut stream: S,
    commands: mpsc::Sender<DaemonCommand>,
    mut events: broadcast::Receiver<meshmsg_protocol::Event>,
    connected: meshmsg_protocol::Event,
    startup_peers: Option<meshmsg_protocol::Event>,
    timeouts: LocalIpcTimeouts,
) -> Result<()>
where
    S: SubscriptionStream,
{
    let frame = match tokio::time::timeout(
        timeouts.initial_frame,
        read_frame(&mut stream, MAX_IPC_REQUEST_SIZE),
    )
    .await
    {
        Ok(result) => result?,
        Err(_) => {
            let _ = write_local_response(
                &mut stream,
                None,
                meshmsg_protocol::Response::Error(meshmsg_protocol::ProtocolError::new(
                    None,
                    meshmsg_protocol::ErrorCode::InitialFrameTimeout,
                    meshmsg_protocol::Outcome::NotStarted,
                )),
                timeouts.response_write,
            )
            .await;
            return Ok(());
        }
    };
    let request_frame: IpcRequestFrame = match serde_json::from_slice(&frame) {
        Ok(frame) => frame,
        Err(_) => {
            let _ = write_local_response(
                &mut stream,
                None,
                meshmsg_protocol::Response::Error(meshmsg_protocol::ProtocolError::new(
                    None,
                    meshmsg_protocol::ErrorCode::InvalidRequest,
                    meshmsg_protocol::Outcome::NotStarted,
                )),
                timeouts.response_write,
            )
            .await;
            return Ok(());
        }
    };
    let request_id = request_frame.request_id;
    let request = request_frame.request;
    match request {
        IpcRequest::Subscribe => {
            write_local_event(
                &mut stream,
                request_id.clone(),
                connected,
                timeouts.response_write,
            )
            .await?;
            if let Some(snapshot) = startup_peers {
                write_local_event(
                    &mut stream,
                    request_id.clone(),
                    snapshot,
                    timeouts.response_write,
                )
                .await?;
            }
            let mut read_closed = false;
            loop {
                let mut disconnect = [0_u8; 1];
                tokio::select! {
                    read = stream.read(&mut disconnect), if !read_closed => {
                        anyhow::ensure!(read? == 0, "unexpected data after subscribe");
                        read_closed = true;
                        if stream.subscription_closed_after_eof()? {
                            break;
                        }
                    }
                    // EOF stays readable forever. Avoid a busy loop while still
                    // reclaiming quiet subscriptions after a full close.
                    _ = tokio::time::sleep(Duration::from_millis(250)), if read_closed => {
                        if stream.subscription_closed_after_eof()? {
                            break;
                        }
                    }
                    value = events.recv() => match value {
                        Ok(value) => write_local_event(
                            &mut stream,
                            request_id.clone(),
                            value,
                            timeouts.response_write,
                        ).await?,
                        Err(broadcast::error::RecvError::Lagged(count)) => {
                            write_local_event(
                                &mut stream,
                                request_id.clone(),
                                meshmsg_protocol::Event::Lagged {
                                    source: meshmsg_protocol::EventSource::Local,
                                    dropped: count,
                                    message: format!("local listener missed {count} events"),
                                },
                                timeouts.response_write,
                            )
                            .await?;
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
            }
        }
        IpcRequest::Send { operation_id, body } => {
            let response_operation_id = operation_id.clone();
            let (reply, response) = oneshot::channel();
            let value = command_response(
                send_command(
                    &commands,
                    DaemonCommand::Send {
                        operation_id: operation_id.into_string(),
                        body: body.into_string(),
                        reply,
                    },
                    response,
                ),
                timeouts.ordinary_command,
                Some(response_operation_id),
            )
            .await;
            write_local_response(
                &mut stream,
                Some(request_id),
                value,
                timeouts.response_write,
            )
            .await?;
        }
        IpcRequest::PrivateSend {
            operation_id,
            to,
            body,
        } => {
            let response_operation_id = operation_id.clone();
            let (reply, response) = oneshot::channel();
            let value = command_response(
                send_command(
                    &commands,
                    DaemonCommand::PrivateSend {
                        operation_id: operation_id.into_string(),
                        to: to.into_string(),
                        body: body.into_string(),
                        reply,
                    },
                    response,
                ),
                timeouts.private_command,
                Some(response_operation_id),
            )
            .await;
            write_local_response(
                &mut stream,
                Some(request_id),
                value,
                timeouts.response_write,
            )
            .await?;
        }
        IpcRequest::Status => {
            let (reply, response) = oneshot::channel();
            let value = command_response(
                send_command(&commands, DaemonCommand::Status { reply }, response),
                timeouts.ordinary_command,
                None,
            )
            .await;
            write_local_response(
                &mut stream,
                Some(request_id),
                value,
                timeouts.response_write,
            )
            .await?;
        }
        IpcRequest::Peers => {
            let (reply, response) = oneshot::channel();
            let value = command_response(
                send_command(&commands, DaemonCommand::Peers { reply }, response),
                timeouts.ordinary_command,
                None,
            )
            .await;
            write_local_response(
                &mut stream,
                Some(request_id),
                value,
                timeouts.response_write,
            )
            .await?;
        }
        IpcRequest::Offers => {
            let (reply, response) = oneshot::channel();
            let value = command_response(
                send_command(&commands, DaemonCommand::Offers { reply }, response),
                timeouts.list_command,
                None,
            )
            .await;
            write_local_response(
                &mut stream,
                Some(request_id),
                value,
                timeouts.response_write,
            )
            .await?;
        }
        IpcRequest::OffersRemove {
            operation_id,
            offer_id,
            direction,
            provider,
        } => {
            let (reply, response) = oneshot::channel();
            let value = lifecycle_command_response(
                send_command(
                    &commands,
                    DaemonCommand::OffersRemove {
                        operation_id: operation_id.to_string(),
                        offer_id: offer_id.into_string(),
                        direction: direction.map(|value| value.to_string()),
                        provider: provider.map(meshmsg_protocol::PeerId::into_string),
                        reply,
                    },
                    response,
                ),
                timeouts.list_command,
                Some(operation_id),
                None,
            )
            .await;
            write_local_response(
                &mut stream,
                Some(request_id),
                value,
                timeouts.response_write,
            )
            .await?;
        }
        IpcRequest::OffersPrune {
            operation_id,
            older_than_secs,
            direction,
            dry_run,
            max_delete,
        } => {
            let (reply, response) = oneshot::channel();
            let value = lifecycle_command_response(
                send_command(
                    &commands,
                    DaemonCommand::OffersPrune {
                        operation_id: operation_id.to_string(),
                        older_than_secs,
                        direction: direction.map(|value| value.to_string()),
                        dry_run,
                        max_delete,
                        reply,
                    },
                    response,
                ),
                timeouts.list_command,
                Some(operation_id),
                None,
            )
            .await;
            write_local_response(
                &mut stream,
                Some(request_id),
                value,
                timeouts.response_write,
            )
            .await?;
        }
        IpcRequest::Share {
            operation_id,
            source_digest,
            path,
        } => {
            let response_operation_id = operation_id.clone();
            let (reply, response) = oneshot::channel();
            let value = lifecycle_command_response(
                send_command(
                    &commands,
                    DaemonCommand::Share {
                        operation_id: operation_id.into_string(),
                        source_digest: source_digest.into_string(),
                        path,
                        reply,
                    },
                    response,
                ),
                timeouts.transfer_command,
                Some(response_operation_id),
                None,
            )
            .await;
            write_local_response(
                &mut stream,
                Some(request_id),
                value,
                timeouts.response_write,
            )
            .await?;
        }
        IpcRequest::Download {
            operation_id,
            offer,
            output,
            mode,
        } => {
            let (reply, response) = oneshot::channel();
            let value = lifecycle_command_response(
                send_command(
                    &commands,
                    DaemonCommand::Download {
                        operation_id: operation_id.to_string(),
                        offer,
                        output,
                        mode,
                        reply,
                    },
                    response,
                ),
                timeouts.transfer_command,
                Some(operation_id),
                None,
            )
            .await;
            write_local_response(
                &mut stream,
                Some(request_id),
                value,
                timeouts.response_write,
            )
            .await?;
        }
        IpcRequest::Stop => {
            // Reserve bounded queue capacity before acknowledging. Once `send`
            // succeeds the daemon will stop even if the client disappears before
            // reading the acknowledgement; before it succeeds, report not_started.
            let response = match tokio::time::timeout(timeouts.ordinary_command, commands.reserve())
                .await
            {
                Ok(Ok(permit)) => {
                    permit.send(DaemonCommand::Stop);
                    meshmsg_protocol::Response::Stopping {
                        outcome: "accepted".into(),
                    }
                }
                Ok(Err(_)) => {
                    meshmsg_protocol::Response::Error(meshmsg_protocol::ProtocolError::new(
                        None,
                        meshmsg_protocol::ErrorCode::DaemonStopping,
                        meshmsg_protocol::Outcome::NotStarted,
                    ))
                }
                Err(_) => meshmsg_protocol::Response::Error(meshmsg_protocol::ProtocolError::new(
                    None,
                    meshmsg_protocol::ErrorCode::CommandTimeout,
                    meshmsg_protocol::Outcome::NotStarted,
                )),
            };
            write_local_response(
                &mut stream,
                Some(request_id),
                response,
                timeouts.response_write,
            )
            .await?;
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

async fn reject_local_client_at_capacity<S>(mut stream: S, write_timeout: Duration)
where
    S: AsyncWrite + Unpin,
{
    let _ = write_local_response(
        &mut stream,
        None,
        meshmsg_protocol::Response::Error(meshmsg_protocol::ProtocolError::new(
            None,
            meshmsg_protocol::ErrorCode::IpcCapacity,
            meshmsg_protocol::Outcome::NotStarted,
        )),
        write_timeout,
    )
    .await;
}

struct LocalClientSession {
    commands: mpsc::Sender<DaemonCommand>,
    events: broadcast::Receiver<meshmsg_protocol::Event>,
    connected: meshmsg_protocol::Event,
    startup_peers: Option<meshmsg_protocol::Event>,
}

async fn handle_admitted_local_client<S>(
    stream: S,
    session: LocalClientSession,
    timeouts: LocalIpcTimeouts,
    permit: OwnedSemaphorePermit,
) -> Result<()>
where
    S: SubscriptionStream,
{
    let _permit = permit;
    handle_local_client_with_timeouts(
        stream,
        session.commands,
        session.events,
        session.connected,
        session.startup_peers,
        timeouts,
    )
    .await
}

/// Admit immediately after the platform listener has accepted/authenticated the
/// stream. The preparation closure is deliberately invoked only after a permit
/// is owned, so saturated clients cannot trigger snapshots, subscriptions, or
/// other per-client state work.
async fn admit_local_client<S, F>(
    stream: S,
    connection_limit: &Arc<Semaphore>,
    tasks: &mut tokio::task::JoinSet<()>,
    timeouts: LocalIpcTimeouts,
    prepare: F,
) -> Result<bool>
where
    S: SubscriptionStream + Send + 'static,
    F: FnOnce() -> Result<LocalClientSession>,
{
    let permit = match connection_limit.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            // Accept before rejecting so cooperative clients receive an
            // explicit retryable result instead of an opaque connect error.
            reject_local_client_at_capacity(stream, timeouts.rejection_write).await;
            return Ok(false);
        }
    };
    let session = prepare()?;
    tasks.spawn(async move {
        let _ = handle_admitted_local_client(stream, session, timeouts, permit).await;
    });
    Ok(true)
}

async fn drain_local_client_tasks(tasks: &mut tokio::task::JoinSet<()>, grace: Duration) {
    let deadline = tokio::time::Instant::now() + grace;
    while !tasks.is_empty() {
        match tokio::time::timeout_at(deadline, tasks.join_next()).await {
            Ok(Some(_)) => {}
            Ok(None) => return,
            Err(_) => break,
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
}

pub async fn run_daemon(
    dir: &Path,
    max_attachment_bytes: u64,
    max_attachment_storage_bytes: u64,
    min_attachment_free_bytes: u64,
    attachment_retention_secs: u64,
) -> Result<()> {
    anyhow::ensure!(
        max_attachment_bytes > 0,
        "maximum attachment size must be greater than zero"
    );
    anyhow::ensure!(
        max_attachment_storage_bytes > 0,
        "maximum attachment storage must be greater than zero"
    );
    // Install service-manager/console signal handling before startup becomes visible.
    let mut shutdown = shutdown_signals()?;
    // Claim local ownership before reading the identity, starting networking, or mutating state.
    let state_lock = StateLock::acquire(dir)?;
    let (mut state, secret) = State::load_locked(dir, &state_lock)?;
    state.validate_for_identity(secret.public())?;
    let alias_config = AliasConfig::load_for_identity(dir, secret.public())?;
    let startup = tokio::select! {
        result = tokio::time::timeout(STARTUP_TIMEOUT, start(&state, secret, dir)) => result,
        _ = shutdown.recv() => return Ok(()),
    };
    let mut node = match startup {
        Ok(Ok(node)) => node,
        Ok(Err(error)) => {
            return Err(error)
                .context("start gossip topic; verify the invite and bootstrap-peer reachability");
        }
        Err(_) => {
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
            node.direct_replay.shutdown().await?;
            return Ok(());
        }
    };
    if online.is_err() {
        node.router.shutdown().await?;
        node.direct_replay.shutdown().await?;
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
    let blob_root = dir.join("blobs-v1").join(node.secret.public().to_string());
    let attachment_storage = AttachmentStorage::open(
        node.blob_store.clone(),
        blob_root,
        dir,
        max_attachment_storage_bytes,
        min_attachment_free_bytes,
        attachment_retention_secs,
    )
    .await
    .context("initialize attachment lifecycle state")?;
    // Expose IPC only after networking is ready, so clients never connect to a
    // socket whose daemon is still blocked during bootstrap.
    let (mut listener, _endpoint_guard) = bind_local_endpoint(dir, &state_lock).await?;
    let peer = node.endpoint.id().to_string();
    eprintln!("daemon running as {peer}");

    let (command_tx, mut command_rx) = mpsc::channel(32);
    let (event_tx, _) = broadcast::channel(IPC_EVENT_CAPACITY);
    let transfer_limit = Arc::new(Semaphore::new(2));
    let offer_list_limit = Arc::new(Semaphore::new(1));
    let direct_sender = direct::DirectSender::new(
        node.endpoint.clone(),
        node.secret.clone(),
        state.topic_id()?,
    );
    // Deliberately daemon-lifetime scoped: status advertises the bounded TTL and
    // restart semantics so callers never infer durable command history.
    let operation_cache = Arc::new(Mutex::new(OperationCache::new(
        OPERATION_CACHE_CAPACITY,
        OPERATION_CACHE_TTL,
    )));
    let topic = state.topic_id()?;
    let mut directory = Directory::new(node.presence_lookup.clone());
    let directory_epoch = data_encoding::HEXLOWER.encode(&rand::random::<[u8; 16]>());
    let mut directory_revision = 0_u64;
    for address in &node.bootstrap_addrs {
        if directory.pin(address.clone()).is_ok() {
            // Invite validation already bounds bootstrap addresses; invalid direct
            // addresses simply remain unavailable for private messaging.
        }
    }
    if presence::validate_endpoint_addr(&node.endpoint.addr(), node.endpoint.id()).is_ok() {
        directory.pin(node.endpoint.addr())?;
    }
    let mut presence = tokio::time::interval(presence::ANNOUNCE_INTERVAL);
    presence.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut presence_cleanup = tokio::time::interval(presence::CLEANUP_INTERVAL);
    presence_cleanup.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut presence_sources = PresenceSourceLimiter::default();
    let mut gossip_events = GossipEventHandler::default();
    let connection_limit = Arc::new(Semaphore::new(LOCAL_IPC_CONNECTION_CAPACITY));
    let mut local_client_tasks = tokio::task::JoinSet::new();
    let mut transfer_tasks = tokio::task::JoinSet::new();
    let mut offer_list_tasks = tokio::task::JoinSet::new();
    let mut rejoin = tokio::time::interval(REJOIN_INTERVAL);
    rejoin.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut retention_check = tokio::time::interval(ATTACHMENT_RETENTION_CHECK_INTERVAL);
    retention_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Do not run a retention pass immediately at startup.
    retention_check.tick().await;
    let mut attachment_space_refresh = tokio::time::interval(ATTACHMENT_SPACE_REFRESH_INTERVAL);
    attachment_space_refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    attachment_space_refresh.tick().await;

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let stream = accepted?;
                // Admission is the first operation after the platform listener's
                // accept/authentication. Everything in this closure—including
                // cleanup, time lookup, snapshot construction, and subscription—
                // runs only while this client owns a connection permit.
                let _admitted = admit_local_client(
                    stream,
                    &connection_limit,
                    &mut local_client_tasks,
                    LocalIpcTimeouts::default(),
                    || {
                        // Expiration is authoritative in the daemon. Emit it before
                        // capturing the new subscriber's snapshot so queued events
                        // are strictly later than that snapshot.
                        presence::emit_transitions(directory.cleanup(), &event_tx, &directory_epoch, &mut directory_revision);
                        let generated_at_ms = unix_timestamp_ms()?;
                        let startup_peers = presence::snapshot(
                            (&node.endpoint, &node.receiver),
                            &directory,
                            &peer,
                            alias_config.effective(),
                            generated_at_ms,
                            &directory_epoch,
                            directory_revision,
                        );
                        let connected = meshmsg_protocol::Event::Connected(
                            meshmsg_protocol::Connected {
                                peer: peer.parse().expect("public key is canonical"),
                                endpoint_online: true,
                                topic_joined: node.receiver.is_joined(),
                                alias: alias_config.effective().map(str::parse).transpose()?,
                            },
                        );
                        Ok(LocalClientSession {
                            commands: command_tx.clone(),
                            events: event_tx.subscribe(),
                            connected,
                            startup_peers: Some(meshmsg_protocol::Event::PeersSnapshot(startup_peers)),
                        })
                    },
                ).await?;
            }
            command = command_rx.recv() => match command {
                Some(DaemonCommand::Send { operation_id, body, reply }) => {
                    let fingerprint = operation_fingerprint("send", &[body.as_bytes()]);
                    if !operation_cache.lock().expect("operation cache poisoned").admit(
                        operation_id.clone(), fingerprint, reply, StdInstant::now()
                    ) {
                        continue;
                    }
                    let response = match unix_timestamp_ms() {
                        Ok(timestamp_ms) => match gossip::Envelope::encode_message_with_id_at(
                            &node.secret, topic, body.clone(),
                            operation_id_bytes(&operation_id), timestamp_ms,
                        ) {
                            Ok(envelope) => match node.sender.broadcast(envelope).await {
                                Ok(()) => meshmsg_protocol::Response::Queued(gossip::queued_event(
                                    &peer, operation_id_bytes(&operation_id), body, timestamp_ms,
                                )),
                                Err(_error) => contracts::protocol_error_response(
                                    meshmsg_protocol::ErrorCode::SendFailed,
                                    meshmsg_protocol::Outcome::Unknown,
                                    Some(operation_id.parse().expect("validated operation ID")),
                                ),
                            },
                            Err(_error) => contracts::protocol_error_response(
                                meshmsg_protocol::ErrorCode::InvalidMessage,
                                meshmsg_protocol::Outcome::NotStarted,
                                Some(operation_id.parse().expect("validated operation ID")),
                            ),
                        },
                        Err(_error) => contracts::protocol_error_response(
                            meshmsg_protocol::ErrorCode::InvalidMessage,
                            meshmsg_protocol::Outcome::NotStarted,
                            Some(operation_id.parse().expect("validated operation ID")),
                        ),
                    };
                    let response = operation_cache.lock().expect("operation cache poisoned")
                        .complete(&operation_id, response, StdInstant::now());
                    if let meshmsg_protocol::Response::Queued(queued) = response {
                        let _ = event_tx.send(meshmsg_protocol::Event::Queued(queued));
                    }
                }
                Some(DaemonCommand::PrivateSend { operation_id, to, body, reply }) => {
                    let fingerprint = operation_fingerprint(
                        "private_send", &[to.as_bytes(), body.as_bytes()]
                    );
                    if !operation_cache.lock().expect("operation cache poisoned").admit(
                        operation_id.clone(), fingerprint, reply, StdInstant::now()
                    ) {
                        continue;
                    }
                    presence::emit_transitions(directory.cleanup(), &event_tx, &directory_epoch, &mut directory_revision);
                    let address = match directory.resolve(&to) {
                        Ok(address) => address,
                        Err(_error) => {
                            operation_cache.lock().expect("operation cache poisoned").complete(
                                &operation_id,
                                contracts::protocol_error_response(
                                    meshmsg_protocol::ErrorCode::RecipientUnresolved,
                                    meshmsg_protocol::Outcome::NotStarted,
                                    Some(operation_id.parse().expect("validated operation ID")),
                                ),
                                StdInstant::now(),
                            );
                            continue;
                        }
                    };
                    let permit = match direct_sender.try_reserve() {
                        Ok(permit) => permit,
                        Err(error) => {
                            operation_cache.lock().expect("operation cache poisoned").complete(
                                &operation_id,
                                meshmsg_protocol::Response::Error(error),
                                StdInstant::now(),
                            );
                            continue;
                        }
                    };
                    let operation_cache = operation_cache.clone();
                    transfer_tasks.spawn(async move {
                        let response = permit
                            .send(address, body, operation_id_bytes(&operation_id))
                            .await;
                        operation_cache.lock().expect("operation cache poisoned")
                            .complete(&operation_id, response, StdInstant::now());
                    });
                }
                Some(DaemonCommand::Status { reply }) => {
                    let endpoint_online = node.endpoint.home_relay_status().get()
                        .iter().any(|status| status.is_connected());
                    let neighbors = node.receiver.neighbors().count();
                    let replay_status = direct::replay_status(&node.direct_replay);
                    let status = meshmsg_protocol::Status {
                        running: true,
                        peer: peer.parse()?,
                        topic: state.topic.parse()?,
                        advertises_self: state.advertise_self,
                        has_invite,
                        bootstrap_peer_count,
                        self_advertised,
                        neighbors,
                        endpoint_online,
                        topic_joined: node.receiver.is_joined(),
                        alias: alias_config.effective().map(str::parse).transpose()?,
                        alias_enabled: alias_config.enabled(),
                        captured_hostname: alias_config.hostname().map(str::to_owned),
                        custom_alias: alias_config.custom().map(str::to_owned),
                        advertised_aliases: directory.advertised_aliases(),
                        operation_cache_capacity: OPERATION_CACHE_CAPACITY,
                        operation_cache_ttl_ms: OPERATION_CACHE_TTL.as_millis() as u64,
                        operation_cache_persistent: false,
                        direct_replay_available: replay_status.available,
                        direct_replay_error: replay_status.error,
                        direct_replay_capacity: replay_status.capacity,
                        direct_replay_per_sender_capacity: replay_status.per_sender_capacity,
                        direct_replay_queue_capacity: replay_status.queue_capacity,
                        direct_replay_global_rate_per_second: replay_status.global_rate_per_second,
                        direct_replay_global_rate_burst: replay_status.global_rate_burst,
                        direct_replay_sender_rate_per_second: replay_status.sender_rate_per_second,
                        direct_replay_sender_rate_burst: replay_status.sender_rate_burst,
                        max_attachment_bytes,
                        attachment_storage: attachment_storage.status(),
                        attachment_retention_secs,
                    };
                    status.validate().map_err(anyhow::Error::msg)?;
                    let _ = reply.send(meshmsg_protocol::Response::Status(status));
                }
                Some(DaemonCommand::Peers { reply }) => {
                    presence::emit_transitions(directory.cleanup(), &event_tx, &directory_epoch, &mut directory_revision);
                    let generated_at_ms = unix_timestamp_ms()?;
                    let _ = reply.send(meshmsg_protocol::Response::PeersSnapshot(
                        presence::snapshot(
                            (&node.endpoint, &node.receiver),
                            &directory,
                            &peer,
                            alias_config.effective(),
                            generated_at_ms,
                            &directory_epoch,
                            directory_revision,
                        ),
                    ));
                }
                Some(DaemonCommand::Offers { reply }) => {
                    let permit = match try_admit_offer_listing(&offer_list_limit) {
                        Ok(permit) => permit,
                        Err(error) => {
                            let _ = reply.send(meshmsg_protocol::Response::Error(error));
                            continue;
                        }
                    };
                    let store = node.blob_store.clone();
                    offer_list_tasks.spawn(async move {
                        let _permit = permit;
                        let response = list_offers_request(store).await;
                        let _ = reply.send(response);
                    });
                }
                Some(DaemonCommand::OffersRemove { operation_id, offer_id, direction, provider, reply }) => {
                    let direction_fingerprint = optional_text_fingerprint(direction.as_deref());
                    let provider_fingerprint = optional_text_fingerprint(provider.as_deref());
                    let fingerprint = operation_fingerprint(
                        "offers_remove",
                        &[offer_id.as_bytes(), &direction_fingerprint, &provider_fingerprint],
                    );
                    if !operation_cache.lock().expect("operation cache poisoned").admit(
                        operation_id.clone(), fingerprint, reply, StdInstant::now()
                    ) {
                        continue;
                    }
                    let valid_direction = direction.as_deref().is_none_or(|value| matches!(value, "incoming" | "outgoing"));
                    let provider = match provider {
                        Some(value) => match value.parse::<PublicKey>() {
                            Ok(key) if key.to_string() == value => Some(value),
                            _ => {
                                let error = meshmsg_protocol::ProtocolError::new(
                                    Some(operation_id.parse().expect("validated operation ID")),
                                    meshmsg_protocol::ErrorCode::InvalidOfferSelector,
                                    meshmsg_protocol::Outcome::NotStarted,
                                );
                                operation_cache.lock().expect("operation cache poisoned").complete(
                                    &operation_id, meshmsg_protocol::Response::Error(error), StdInstant::now());
                                continue;
                            }
                        },
                        None => None,
                    };
                    if !contracts::valid_operation_id(&offer_id) || !valid_direction {
                        let error = meshmsg_protocol::ProtocolError::new(
                            Some(operation_id.parse().expect("validated operation ID")),
                            meshmsg_protocol::ErrorCode::InvalidOfferSelector,
                            meshmsg_protocol::Outcome::NotStarted,
                        );
                        operation_cache.lock().expect("operation cache poisoned").complete(
                            &operation_id, meshmsg_protocol::Response::Error(error), StdInstant::now());
                        continue;
                    }
                    let storage = attachment_storage.clone();
                    let operation_cache = operation_cache.clone();
                    offer_list_tasks.spawn(async move {
                        let response = remove_offer_request(
                            storage, &operation_id, &offer_id,
                            direction.as_deref(), provider.as_deref(),
                        ).await;
                        operation_cache.lock().expect("operation cache poisoned").complete(
                            &operation_id, response, StdInstant::now());
                    });
                }
                Some(DaemonCommand::OffersPrune { operation_id, older_than_secs, direction, dry_run, max_delete, reply }) => {
                    let age_fingerprint = older_than_secs.to_le_bytes();
                    let direction_fingerprint = optional_text_fingerprint(direction.as_deref());
                    let dry_run_fingerprint = [u8::from(dry_run)];
                    let maximum_fingerprint = max_delete.to_le_bytes();
                    let fingerprint = operation_fingerprint(
                        "offers_prune",
                        &[&age_fingerprint, &direction_fingerprint, &dry_run_fingerprint, &maximum_fingerprint],
                    );
                    if !operation_cache.lock().expect("operation cache poisoned").admit(
                        operation_id.clone(), fingerprint, reply, StdInstant::now()
                    ) {
                        continue;
                    }
                    if !direction.as_deref().is_none_or(|value| matches!(value, "incoming" | "outgoing"))
                        || !(1..=MAX_PRUNE_TAGS).contains(&max_delete)
                    {
                        let error = meshmsg_protocol::ProtocolError::new(
                            Some(operation_id.parse().expect("validated operation ID")),
                            meshmsg_protocol::ErrorCode::InvalidPruneRequest,
                            meshmsg_protocol::Outcome::NotStarted,
                        );
                        operation_cache.lock().expect("operation cache poisoned").complete(
                            &operation_id, meshmsg_protocol::Response::Error(error), StdInstant::now());
                        continue;
                    }
                    let resolution = operation_cache
                        .lock()
                        .expect("operation cache poisoned")
                        .resolve_prune(
                            &operation_id,
                            older_than_secs,
                            unix_timestamp_ms_saturating(SystemTime::now()),
                        );
                    let age = resolution.older_than_secs;
                    let cutoff = resolution.cutoff_ms;
                    let storage = attachment_storage.clone();
                    let operation_cache = operation_cache.clone();
                    offer_list_tasks.spawn(async move {
                        let response = prune_offers_request(
                            storage, &operation_id, age, cutoff,
                            direction.as_deref(), dry_run, max_delete,
                        ).await;
                        operation_cache.lock().expect("operation cache poisoned").complete(
                            &operation_id, response, StdInstant::now());
                    });
                }
                Some(DaemonCommand::Share { operation_id, source_digest, path, reply }) => {
                    let fingerprint = operation_fingerprint(
                        "share", &[path.as_os_str().as_encoded_bytes(), source_digest.as_bytes()]
                    );
                    if !operation_cache.lock().expect("operation cache poisoned").admit(
                        operation_id.clone(), fingerprint, reply, StdInstant::now()
                    ) {
                        continue;
                    }
                    let permit = match try_admit_transfer(
                        &transfer_limit, "share_busy", "attachment transfer capacity reached"
                    ) {
                        Ok(permit) => permit,
                        Err(_) => {
                            let error = meshmsg_protocol::ProtocolError::new(
                                Some(operation_id.parse().expect("validated operation ID")),
                                meshmsg_protocol::ErrorCode::AttachmentStorageBusy,
                                meshmsg_protocol::Outcome::NotStarted,
                            );
                            operation_cache.lock().expect("operation cache poisoned")
                                .complete(&operation_id, meshmsg_protocol::Response::Error(error), StdInstant::now());
                            continue;
                        }
                    };
                    let store = node.blob_store.clone();
                    let storage = attachment_storage.clone();
                    let endpoint = node.endpoint.clone();
                    let secret = node.secret.clone();
                    let sender = node.sender.clone();
                    let state_dir = dir.to_path_buf();
                    let events = event_tx.clone();
                    let operation_cache = operation_cache.clone();
                    transfer_tasks.spawn(async move {
                        let _permit = permit;
                        let response = share_request(
                            ShareResources {
                                store,
                                storage,
                                endpoint,
                                secret,
                                topic,
                                sender,
                                state_dir,
                            },
                            operation_id.clone(),
                            source_digest,
                            path,
                            max_attachment_bytes,
                        ).await;
                        let response = operation_cache.lock().expect("operation cache poisoned")
                            .complete(&operation_id, response, StdInstant::now());
                        if let meshmsg_protocol::Response::AttachmentShared(shared) = response {
                            let _ = events.send(meshmsg_protocol::Event::AttachmentShared(shared));
                        }
                    });
                }
                Some(DaemonCommand::Download { operation_id, offer, output, mode, reply }) => {
                    let mode_name = match mode {
                        meshmsg_protocol::DownloadMode::Install => "install",
                    };
                    let fingerprint = operation_fingerprint(
                        "download",
                        &[offer.as_bytes(), output.as_os_str().as_encoded_bytes(), mode_name.as_bytes()],
                    );
                    if !operation_cache.lock().expect("operation cache poisoned").admit(
                        operation_id.clone(), fingerprint, reply, StdInstant::now()
                    ) {
                        continue;
                    }
                    let permit = match try_admit_transfer(
                        &transfer_limit, "download_busy", "attachment transfer capacity reached"
                    ) {
                        Ok(permit) => permit,
                        Err(_) => {
                            let error = meshmsg_protocol::ProtocolError::new(
                                Some(operation_id.parse().expect("validated operation ID")),
                                meshmsg_protocol::ErrorCode::AttachmentStorageBusy,
                                meshmsg_protocol::Outcome::NotStarted,
                            );
                            operation_cache.lock().expect("operation cache poisoned").complete(
                                &operation_id, meshmsg_protocol::Response::Error(error), StdInstant::now());
                            continue;
                        }
                    };
                    let store = node.blob_store.clone();
                    let storage = attachment_storage.clone();
                    let downloader = node.downloader.clone();
                    let endpoint = node.endpoint.clone();
                    let lookup = node.lookup.clone();
                    let events = event_tx.clone();
                    let operation_cache = operation_cache.clone();
                    transfer_tasks.spawn(async move {
                        let _permit = permit;
                        let response = download_request(
                            DownloadResources {
                                store,
                                storage,
                                topic,
                                downloader,
                                endpoint,
                                lookup,
                            },
                            events.clone(),
                            operation_id.clone(),
                            offer,
                            output,
                            max_attachment_bytes,
                            mode,
                        ).await;
                        let response = operation_cache.lock().expect("operation cache poisoned")
                            .complete(&operation_id, response, StdInstant::now());
                        if let meshmsg_protocol::Response::DownloadComplete(complete) = response {
                            let _ = events.send(meshmsg_protocol::Event::DownloadComplete(complete));
                        }
                    });
                }
                Some(DaemonCommand::Stop) => break,
                None => break,
            },
            incoming = node.receiver.try_next() => match incoming? {
                Some(value) => {
                    if let Event::NeighborUp(remote) = &value {
                        // A new client may have bootstrapped through an older node that does
                        // not know the derived presence topic. Join it directly as well.
                        let _ = node.presence_sender.join_peers(vec![*remote]).await;
                        presence::announce(
                            &node.presence_sender,
                            &node.secret,
                            topic,
                            alias_config.effective(),
                            node.endpoint.addr(),
                        ).await;
                    }
                    let now_ms = unix_timestamp_ms()?;
                    let values = gossip_events.handle(value, topic, now_ms, |envelope| {
                        let offer = validate_offer_binding(
                            envelope.from,
                            envelope.message_id,
                            envelope.timestamp_ms,
                            envelope.body,
                        )?;
                        Ok(attachment_offer_event(
                            envelope.from,
                            envelope.message_id,
                            envelope.timestamp_ms,
                            envelope.encoded,
                            offer,
                        ))
                    });
                    for event in values {
                        let _ = event_tx.send(event);
                    }
                }
                None => break,
            },
            incoming = node.presence_receiver.try_next() => match incoming? {
                Some(Event::Received(message)) => {
                    // Rate-limit the authenticated transport hop, not the signed
                    // presence identity, which an invite holder can rotate cheaply.
                    if presence_sources.allow(message.delivered_from) {
                        // Never let receive-time cleanup swallow an expiry. The
                        // explicit cleanup transition is emitted first.
                        presence::emit_transitions(directory.cleanup(), &event_tx, &directory_epoch, &mut directory_revision);
                        if let Ok(Some(transition)) = directory.receive(&message.content, topic) {
                            presence::emit_transitions([transition], &event_tx, &directory_epoch, &mut directory_revision);
                        }
                    }
                }
                Some(Event::NeighborDown(source)) => presence_sources.remove(source),
                Some(Event::NeighborUp(_) | Event::Lagged) => {}
                None => break,
            },
            incoming = node.direct_incoming.recv() => {
                if let Some(event) = incoming {
                    let _ = event_tx.send(event);
                }
            },
            _ = presence.tick() => {
                presence::announce(
                    &node.presence_sender,
                    &node.secret,
                    topic,
                    alias_config.effective(),
                    node.endpoint.addr(),
                ).await;
            },
            _ = presence_cleanup.tick() => {
                presence::emit_transitions(directory.cleanup(), &event_tx, &directory_epoch, &mut directory_revision);
                presence_sources.cleanup();
            },
            _ = attachment_space_refresh.tick() => {
                let storage = attachment_storage.clone();
                offer_list_tasks.spawn(async move {
                    let _ = storage.refresh_free_space().await;
                });
            }
            _ = retention_check.tick(), if attachment_retention_secs != 0 => {
                let storage = attachment_storage.clone();
                offer_list_tasks.spawn(async move {
                    let _ = storage.automatic_retention_pass().await;
                });
            }
            _ = rejoin.tick(), if !node.bootstrap_peers.is_empty() => {
                if !node.receiver.is_joined() {
                    node.sender
                        .join_peers(node.bootstrap_peers.clone())
                        .await
                        .context("retry gossip bootstrap peers after connectivity loss")?;
                }
                if !node.presence_receiver.is_joined() {
                    node.presence_sender
                        .join_peers(node.bootstrap_peers.clone())
                        .await
                        .context("retry presence bootstrap peers after connectivity loss")?;
                }
            },
            completed = local_client_tasks.join_next(), if !local_client_tasks.is_empty() => {
                let _ = completed;
            },
            completed = transfer_tasks.join_next(), if !transfer_tasks.is_empty() => {
                let _ = completed;
            },
            completed = offer_list_tasks.join_next(), if !offer_list_tasks.is_empty() => {
                let _ = completed;
            },
            _ = shutdown.recv() => break,
        }
    }

    // Stop admission and command submission first. Closing the event channel
    // lets subscriptions finish naturally; cancelling work releases any pending
    // command replies. Give handlers a short drain window before force-aborting.
    connection_limit.close();
    command_rx.close();
    transfer_limit.close();
    attachment_storage.gate.close();
    offer_list_limit.close();
    direct_sender.close();
    drop(event_tx);
    transfer_tasks.abort_all();
    offer_list_tasks.abort_all();
    while transfer_tasks.join_next().await.is_some() {}
    while offer_list_tasks.join_next().await.is_some() {}
    drain_local_client_tasks(&mut local_client_tasks, LOCAL_IPC_SHUTDOWN_GRACE).await;
    node.router.shutdown().await?;
    node.direct_replay.shutdown().await?;
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

#[cfg(test)]
fn received_envelope_event(envelope: Envelope, encoded: &[u8]) -> serde_json::Value {
    let event = if envelope.kind == EnvelopeKind::Message {
        gossip::message_event(&envelope)
    } else {
        match validate_offer_binding(
            envelope.from,
            envelope.message_id,
            envelope.timestamp_ms,
            &envelope.body,
        ) {
            Ok(offer) => attachment_offer_event(
                envelope.from,
                envelope.message_id,
                envelope.timestamp_ms,
                encoded,
                offer,
            ),
            Err(_error) => meshmsg_protocol::Event::Error(meshmsg_protocol::ProtocolError::new(
                None,
                meshmsg_protocol::ErrorCode::InvalidAttachmentOffer,
                meshmsg_protocol::Outcome::NotStarted,
            )),
        }
    };
    serde_json::to_value(event).expect("test event serialization")
}

#[cfg(test)]
fn network_event(
    value: Event,
    topic: TopicId,
    replay: &mut EnvelopeReplayCache,
    sources: &mut TransportSourceLimiter,
    now_ms: u64,
) -> Vec<serde_json::Value> {
    gossip::network_event(value, topic, replay, sources, now_ms, |envelope| {
        let offer = validate_offer_binding(
            envelope.from,
            envelope.message_id,
            envelope.timestamp_ms,
            envelope.body,
        )?;
        Ok(attachment_offer_event(
            envelope.from,
            envelope.message_id,
            envelope.timestamp_ms,
            envelope.encoded,
            offer,
        ))
    })
    .into_iter()
    .map(|event| serde_json::to_value(event).expect("test event serialization"))
    .collect()
}

#[cfg(test)]
fn queued_event(
    peer: &str,
    message_id: [u8; 16],
    body: String,
    timestamp_ms: u64,
) -> serde_json::Value {
    serde_json::to_value(meshmsg_protocol::DaemonFrame::Response(
        meshmsg_protocol::ResponseFrame::new(
            Some(meshmsg_protocol::RequestId::new_random()),
            meshmsg_protocol::Response::Queued(gossip::queued_event(
                peer,
                message_id,
                body,
                timestamp_ms,
            )),
        ),
    ))
    .expect("test queued serialization")
}

#[cfg(test)]
fn message_event(envelope: Envelope) -> serde_json::Value {
    serde_json::to_value(gossip::message_event(&envelope)).expect("test message serialization")
}

#[cfg(unix)]
pub(crate) async fn connect_daemon(dir: &Path) -> Result<LocalClientStream> {
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
pub(crate) async fn connect_daemon(dir: &Path) -> Result<LocalClientStream> {
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

pub async fn send_once(
    dir: &Path,
    operation_id: Option<String>,
    to: Option<&str>,
    body: &str,
    json: bool,
) -> Result<()> {
    let operation_id = operation_id.unwrap_or_else(crate::ipc::new_operation_id);
    let value = if let Some(to) = to {
        let value = send_request_checked(
            dir,
            &IpcRequest::PrivateSend {
                operation_id: operation_id.parse()?,
                to: to.parse()?,
                body: meshmsg_protocol::PrivateBody::new(body)?,
            },
            "private_accepted",
        )
        .await
        .with_context(|| format!("operation {operation_id}"))?;
        match &value.response {
            meshmsg_protocol::Response::PrivateAccepted(accepted) => anyhow::ensure!(
                accepted.operation_id.to_string() == operation_id
                    && accepted.message_id.to_string() == operation_id
                    && accepted.body_bytes == body.len(),
                "private-send acceptance metadata does not match the request"
            ),
            _ => unreachable!("checked response family"),
        }
        value
    } else {
        let value = send_request_checked(
            dir,
            &IpcRequest::Send {
                operation_id: operation_id.parse()?,
                body: meshmsg_protocol::BroadcastBody::new(body)?,
            },
            "queued",
        )
        .await
        .with_context(|| format!("operation {operation_id}"))?;
        match &value.response {
            meshmsg_protocol::Response::Queued(queued) => anyhow::ensure!(
                queued.operation_id.to_string() == operation_id
                    && queued.message_id.to_string() == operation_id,
                "daemon returned mismatched broadcast operation metadata"
            ),
            _ => unreachable!("checked response family"),
        }
        value
    };
    output_response(json, &value)?;
    Ok(())
}

fn caller_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()
            .context("read current directory")?
            .join(path))
    }
}

pub async fn share(
    dir: &Path,
    operation_id: Option<String>,
    path: &Path,
    json: bool,
) -> Result<()> {
    let operation_id = operation_id.unwrap_or_else(crate::ipc::new_operation_id);
    let status = send_request_checked(dir, &IpcRequest::Status, "status").await?;
    let maximum = match &status.response {
        meshmsg_protocol::Response::Status(status) => status.max_attachment_bytes,
        _ => unreachable!("checked response family"),
    };
    let path = caller_path(path)?;
    let digest_path = path.clone();
    let source_digest =
        tokio::task::spawn_blocking(move || attachment::share_source_digest(&digest_path, maximum))
            .await
            .context("attachment digest task failed")??;
    let frame = send_lifecycle_request(
        dir,
        &IpcRequest::Share {
            operation_id: operation_id.parse()?,
            source_digest: source_digest.parse()?,
            path,
        },
        "attachment_shared",
        &operation_id,
    )
    .await
    .with_context(|| format!("operation {operation_id}"))?;
    let meshmsg_protocol::Response::AttachmentShared(shared) = &frame.response else {
        unreachable!("checked attachment-shared family")
    };
    anyhow::ensure!(
        shared.operation_id.to_string() == operation_id
            && shared.source_digest.to_string() == source_digest,
        "daemon returned mismatched share operation metadata"
    );
    output_response(json, &frame)?;
    Ok(())
}

pub async fn peers(dir: &Path, json: bool) -> Result<()> {
    let value = send_request_checked(dir, &IpcRequest::Peers, "peers_snapshot")
        .await
        .context("request peer directory; the daemon may need to be upgraded and restarted")?;
    output_response(json, &value)?;
    Ok(())
}

pub async fn offers(dir: &Path, json: bool) -> Result<()> {
    let value = send_request_checked(dir, &IpcRequest::Offers, "offers").await?;
    output_response(json, &value)?;
    Ok(())
}

async fn send_lifecycle_request(
    dir: &Path,
    request: &IpcRequest,
    expected_type: &str,
    expected_operation_id: &str,
) -> Result<meshmsg_protocol::ResponseFrame> {
    let frame = crate::ipc::send_request_checked(dir, request, expected_type).await?;
    let actual_operation_id = match &frame.response {
        meshmsg_protocol::Response::AttachmentShared(value) => &value.operation_id,
        meshmsg_protocol::Response::OfferRemoved(value)
        | meshmsg_protocol::Response::OffersPruned(value) => &value.operation_id,
        meshmsg_protocol::Response::DownloadComplete(value) => &value.operation_id,
        _ => unreachable!("checked mutation response family"),
    };
    anyhow::ensure!(
        actual_operation_id.to_string() == expected_operation_id,
        "daemon response operation ID does not match the request"
    );
    Ok(frame)
}

pub async fn offers_remove(
    dir: &Path,
    operation_id: Option<String>,
    offer_id: &str,
    direction: Option<&str>,
    provider: Option<&str>,
    json: bool,
) -> Result<()> {
    let operation_id = operation_id.unwrap_or_else(crate::ipc::new_operation_id);
    let frame = send_lifecycle_request(
        dir,
        &IpcRequest::OffersRemove {
            operation_id: operation_id.parse()?,
            offer_id: offer_id.parse()?,
            direction: direction.map(str::parse).transpose()?,
            provider: provider.map(str::parse).transpose()?,
        },
        "offer_removed",
        &operation_id,
    )
    .await?;
    let meshmsg_protocol::Response::OfferRemoved(result) = &frame.response else {
        unreachable!("checked lifecycle family")
    };
    anyhow::ensure!(
        result.offer_id.as_ref().map(ToString::to_string).as_deref() == Some(offer_id)
            && result
                .direction
                .as_ref()
                .map(ToString::to_string)
                .as_deref()
                == direction
            && result.provider.as_ref().map(ToString::to_string).as_deref() == provider
            && result.maximum == MAX_PRUNE_TAGS,
        "lifecycle response does not match its request"
    );
    output_response(json, &frame)?;
    Ok(())
}

pub async fn offers_prune(
    dir: &Path,
    operation_id: Option<String>,
    older_than_secs: Option<u64>,
    direction: Option<&str>,
    dry_run: bool,
    max_delete: usize,
    json: bool,
) -> Result<()> {
    let operation_id = operation_id.unwrap_or_else(crate::ipc::new_operation_id);
    let status = send_request_checked(dir, &IpcRequest::Status, "status").await?;
    let retention = match &status.response {
        meshmsg_protocol::Response::Status(status) => status.attachment_retention_secs,
        _ => unreachable!("checked response family"),
    };
    let effective_age = older_than_secs.unwrap_or(retention);
    let frame = send_lifecycle_request(
        dir,
        &IpcRequest::OffersPrune {
            operation_id: operation_id.parse()?,
            older_than_secs: effective_age,
            direction: direction.map(str::parse).transpose()?,
            dry_run,
            max_delete,
        },
        "offers_pruned",
        &operation_id,
    )
    .await?;
    let meshmsg_protocol::Response::OffersPruned(result) = &frame.response else {
        unreachable!("checked lifecycle family")
    };
    anyhow::ensure!(
        result.older_than_secs == Some(effective_age)
            && result
                .direction
                .as_ref()
                .map(ToString::to_string)
                .as_deref()
                == direction
            && result.dry_run == dry_run
            && result.maximum == max_delete,
        "lifecycle response does not match its request"
    );
    output_response(json, &frame)?;
    Ok(())
}

pub async fn download(
    dir: &Path,
    operation_id: Option<String>,
    offer: &str,
    output: &Path,
    json: bool,
) -> Result<()> {
    let operation_id = operation_id.unwrap_or_else(crate::ipc::new_operation_id);
    let status = send_request_checked(dir, &IpcRequest::Status, "status").await?;
    let status = match &status.response {
        meshmsg_protocol::Response::Status(status) => status,
        _ => unreachable!("checked response family"),
    };
    // Retain the exact absolute representation submitted to the daemon. Do not
    // canonicalize through symlinks or require the not-yet-created destination.
    let requested_output = caller_path(output)?;
    let topic_bytes: [u8; 32] = data_encoding::HEXLOWER
        .decode(status.topic.to_string().as_bytes())
        .context("daemon status topic is invalid")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("daemon status topic has the wrong length"))?;
    let expected = download_request_context(
        &operation_id,
        offer,
        &requested_output,
        TopicId::from_bytes(topic_bytes),
    )
    .context("validate submitted attachment offer")?;
    let frame = send_lifecycle_request(
        dir,
        &IpcRequest::Download {
            operation_id: operation_id.parse()?,
            offer: offer.to_owned(),
            output: requested_output.clone(),
            mode: meshmsg_protocol::DownloadMode::Install,
        },
        "download_complete",
        &operation_id,
    )
    .await?;
    let meshmsg_protocol::Response::DownloadComplete(result) = &frame.response else {
        unreachable!("checked download family")
    };
    result
        .validate_for_request(&expected)
        .map_err(anyhow::Error::msg)?;
    output_response(json, &frame)?;
    Ok(())
}

pub async fn listen(dir: &Path, json: bool) -> Result<()> {
    let mut reader = subscribe(dir).await?;
    loop {
        tokio::select! {
            value = reader.read() => match value? {
                Some(frame) => output_event(json, &frame)?,
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
                    // `lines()` removes the terminator, so an empty value is a
                    // blank input line. Ignore it without allocating an operation
                    // ID or contacting the daemon.
                    if body.is_empty() {
                        continue;
                    }
                    crate::message::validate_broadcast_body(&body)?;
                    send_request_checked(
                        dir,
                        &IpcRequest::Send {
                            operation_id: crate::ipc::new_operation_id().parse()?,
                            body: meshmsg_protocol::BroadcastBody::new(body)?,
                        },
                        "queued",
                    )
                    .await?;
                }
                None => break,
            },
            value = reader.read() => match value? {
                Some(frame) => output_event(json, &frame)?,
                None => anyhow::bail!("local daemon stopped; restart it with `meshmsg daemon`"),
            },
            _ = tokio::signal::ctrl_c() => break,
        }
    }
    Ok(())
}

pub async fn status(dir: &Path, json: bool) -> Result<()> {
    let frame = send_request_checked(dir, &IpcRequest::Status, "status").await?;
    let value = match &frame.response {
        meshmsg_protocol::Response::Status(value) => value,
        _ => unreachable!("checked response family"),
    };
    if json {
        println!("{}", serde_json::to_string(&frame)?);
    } else {
        println!(
            "daemon: running\npeer: {}\ntopic: {}\nalias: {}\nalias enabled: {}\nadvertised aliases: {}\nadvertises self: {}\nhas invite: {}\nbootstrap peers: {}\nself advertised: {}\nendpoint online: {}\ntopic joined: {}\nneighbors: {}\nattachment storage: {} / {} bytes ({} unique blobs, {} / {} pins)\nattachment filesystem available: {} bytes (minimum {})\nattachment storage pressure: {}\nattachment retention: {} seconds",
            value.peer,
            value.topic,
            value.alias.as_ref().map(|alias| alias.as_str()).unwrap_or("(disabled)"),
            value.alias_enabled,
            value.advertised_aliases,
            value.advertises_self,
            value.has_invite,
            value.bootstrap_peer_count,
            value.self_advertised,
            value.endpoint_online,
            value.topic_joined,
            value.neighbors,
            value.attachment_storage.tagged_bytes,
            value.attachment_storage.quota_bytes,
            value.attachment_storage.tagged_blobs,
            value.attachment_storage.tags,
            value.attachment_storage.tag_capacity,
            value.attachment_storage.available_bytes,
            value.attachment_storage.min_free_bytes,
            value.attachment_storage.pressure,
            value.attachment_retention_secs
        );
    }
    Ok(())
}

pub async fn stop(dir: &Path, json: bool) -> Result<()> {
    let value = send_request_checked(dir, &IpcRequest::Stop, "stopping").await?;
    output_response(json, &value)?;
    Ok(())
}

pub async fn doctor(dir: &Path, json: bool) -> Result<()> {
    let (state, secret) = State::load_for_doctor(dir)?;
    state.validate_for_identity(secret.public())?;
    let alias_config = AliasConfig::load_for_identity(dir, secret.public())?;
    let (has_invite, bootstrap_peer_count, self_advertised) =
        invite_details(&state, secret.public())?;
    let value = serde_json::json!({
        "type":"doctor", "request_id":contracts::new_request_id(),
        "ok":true, "peer":secret.public().to_string(), "topic":state.topic,
        "advertises_self":state.advertise_self, "has_invite":has_invite,
        "bootstrap_peer_count":bootstrap_peer_count, "self_advertised":self_advertised,
        "alias":alias_config.effective(), "alias_enabled":alias_config.enabled(),
        "captured_hostname":alias_config.hostname(), "custom_alias":alias_config.custom()
    });
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

fn attachment_kind_name(kind: meshmsg_protocol::AttachmentKind) -> &'static str {
    match kind {
        meshmsg_protocol::AttachmentKind::File => "file",
        meshmsg_protocol::AttachmentKind::DirectoryTarV1 => "directory_tar_v1",
    }
}

fn print_peer_snapshot(value: &meshmsg_protocol::PeerSnapshot) {
    println!(
        "self: {}{} ({})",
        value.self_peer.public_key,
        value
            .self_peer
            .alias
            .as_ref()
            .map(|alias| format!(" ({})", alias.as_str()))
            .unwrap_or_default(),
        if value.self_peer.online {
            "online"
        } else {
            "offline"
        }
    );
    for peer in &value.peers {
        println!(
            "peer: {}{} ({})",
            peer.public_key,
            peer.alias
                .as_ref()
                .map(|alias| format!(" ({})", alias.as_str()))
                .unwrap_or_default(),
            if peer.online { "online" } else { "offline" }
        );
    }
}

fn print_peer_transition(action: &str, value: &meshmsg_protocol::PeerTransition) {
    println!(
        "{action}: {}{}",
        value.peer.public_key,
        value
            .peer
            .alias
            .as_ref()
            .map(|alias| format!(" ({})", alias.as_str()))
            .unwrap_or_default()
    );
}

fn offer_listing_warnings(truncated: bool, item_errors: usize) -> Vec<String> {
    let mut warnings = Vec::new();
    if truncated {
        warnings
            .push("WARNING: attachment listing truncated; more pinned blobs may exist".to_owned());
    }
    if item_errors != 0 {
        warnings.push(format!(
            "WARNING: {item_errors} attachment tag(s) could not be read"
        ));
    }
    warnings
}

fn print_offers(value: &meshmsg_protocol::OffersList) {
    if value.blobs.is_empty() {
        println!("no pinned attachment blobs");
    } else {
        for blob in &value.blobs {
            println!(
                "{}  {}  {}  {}  {}  {}  {}  {} bytes  {}",
                blob.direction,
                terminal_safe(blob.name.as_str()),
                attachment_kind_name(blob.kind),
                blob.offer_id,
                blob.provider
                    .as_ref()
                    .map(ToString::to_string)
                    .as_deref()
                    .unwrap_or("-"),
                terminal_safe(&blob.format),
                terminal_safe(&blob.status),
                blob.size
                    .map(|size| size.to_string())
                    .as_deref()
                    .unwrap_or("?"),
                blob.hash
            );
        }
    }
    for warning in offer_listing_warnings(value.truncated, value.item_errors) {
        println!("{warning}");
    }
}

fn print_lifecycle(value: &meshmsg_protocol::LifecycleResult, prune: bool) {
    if prune {
        println!(
            "{} {} attachment pin(s); {} quota bytes released{}",
            if value.dry_run {
                "would remove"
            } else {
                "removed"
            },
            if value.dry_run {
                value.selected_tags
            } else {
                value.removed_tags
            },
            value.released_bytes,
            if value.limited {
                " (more eligible pins remain)"
            } else {
                ""
            }
        );
    } else {
        println!(
            "removed {} attachment pin(s); {} quota bytes released",
            value.removed_tags, value.released_bytes
        );
    }
}

fn print_protocol_error(error: &meshmsg_protocol::ProtocolError) {
    println!("error: {}", error.message());
}

fn output_response(json: bool, frame: &meshmsg_protocol::ResponseFrame) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string(frame)?);
        return Ok(());
    }
    match &frame.response {
        meshmsg_protocol::Response::Status(_) => println!("daemon running"),
        meshmsg_protocol::Response::Queued(value) => println!(
            "queued locally (delivery not acknowledged): {}",
            terminal_safe(value.body.as_ref())
        ),
        meshmsg_protocol::Response::PrivateAccepted(value) if value.duplicate_accepted => println!(
            "private message was previously accepted by {} (not redelivered; not durable or read)",
            value.to
        ),
        meshmsg_protocol::Response::PrivateAccepted(value) => println!(
            "private message accepted by {} (acceptance only; not durable or read)",
            value.to
        ),
        meshmsg_protocol::Response::PeersSnapshot(value) => print_peer_snapshot(value),
        meshmsg_protocol::Response::Offers(value) => print_offers(value),
        meshmsg_protocol::Response::AttachmentShared(value) => println!(
            "shared {} ({} bytes)\noffer: {}\ndelivery acknowledged: no",
            terminal_safe(value.name.as_str()),
            value.size,
            value.offer.as_str()
        ),
        meshmsg_protocol::Response::OfferRemoved(value) => print_lifecycle(value, false),
        meshmsg_protocol::Response::OffersPruned(value) => print_lifecycle(value, true),
        meshmsg_protocol::Response::DownloadComplete(value) => println!(
            "downloaded {} bytes to {}",
            value.size,
            value.output.display()
        ),
        meshmsg_protocol::Response::Stopping { .. } => println!("daemon stopping"),
        meshmsg_protocol::Response::Error(error) => print_protocol_error(error),
    }
    Ok(())
}

fn output_event(json: bool, frame: &meshmsg_protocol::EventFrame) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string(frame)?);
        return Ok(());
    }
    match &frame.event {
        meshmsg_protocol::Event::Connected(value) => println!("connected as {}", value.peer),
        meshmsg_protocol::Event::Message(value) => {
            println!("{}: {}", value.from, terminal_safe(value.body.as_ref()))
        }
        meshmsg_protocol::Event::PrivateMessage(value) => println!(
            "private from {}: {}",
            value.from,
            terminal_safe(value.body.as_ref())
        ),
        meshmsg_protocol::Event::Queued(value) => println!(
            "queued locally (delivery not acknowledged): {}",
            terminal_safe(value.body.as_ref())
        ),
        meshmsg_protocol::Event::AttachmentOffer(value) => println!(
            "{} shared {} ({} bytes)\ndownload with: meshmsg download '{}' --output PATH",
            value.from,
            terminal_safe(value.name.as_str()),
            value.size,
            value.offer.as_str()
        ),
        meshmsg_protocol::Event::AttachmentShared(value) => println!(
            "shared {} ({} bytes)\noffer: {}\ndelivery acknowledged: no",
            terminal_safe(value.name.as_str()),
            value.size,
            value.offer.as_str()
        ),
        meshmsg_protocol::Event::PeersSnapshot(value) => print_peer_snapshot(value),
        meshmsg_protocol::Event::PeerDiscovered(value) => {
            print_peer_transition("peer discovered", value)
        }
        meshmsg_protocol::Event::PeerUpdated(value) => print_peer_transition("peer updated", value),
        meshmsg_protocol::Event::PeerExpired(value) => print_peer_transition("peer expired", value),
        meshmsg_protocol::Event::DownloadStarted { .. } => {
            println!("attachment download started")
        }
        meshmsg_protocol::Event::DownloadProgress {
            received_bytes,
            total_bytes,
            ..
        } => println!("attachment download: {received_bytes} / {total_bytes} bytes"),
        meshmsg_protocol::Event::DownloadComplete(value) => println!(
            "downloaded {} bytes to {}",
            value.size,
            value.output.display()
        ),
        meshmsg_protocol::Event::Lagged { message, .. } => {
            println!("warning: {}", terminal_safe(message))
        }
        meshmsg_protocol::Event::Stopping {} => println!("daemon stopping"),
        meshmsg_protocol::Event::Error(error) => print_protocol_error(error),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    const TEST_OPERATION_ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    use crate::attachment::DEFAULT_MAX_ATTACHMENT_BYTES;
    use iroh_blobs::protocol::ChunkRangesExt;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn caller_share_path_preserves_the_exact_absolute_representation() {
        let current = std::env::current_dir().unwrap();
        let relative = Path::new("./directory/../file.txt");
        assert_eq!(caller_path(relative).unwrap(), current.join(relative));
        let absolute = current.join("./directory/../file.txt");
        assert_eq!(caller_path(&absolute).unwrap(), absolute);
    }

    fn connected_fixture() -> meshmsg_protocol::Event {
        meshmsg_protocol::Event::Connected(meshmsg_protocol::Connected {
            peer: "2".repeat(64).parse().unwrap(),
            endpoint_online: true,
            topic_joined: true,
            alias: None,
        })
    }

    fn peer_discovered_fixture(revision: u64) -> meshmsg_protocol::Event {
        meshmsg_protocol::Event::PeerDiscovered(meshmsg_protocol::PeerTransition {
            directory_epoch: "4".repeat(32).parse().unwrap(),
            directory_revision: revision,
            peer: meshmsg_protocol::RemotePeer {
                public_key: "3".repeat(64).parse().unwrap(),
                alias: None,
                online: true,
                last_seen_ms: 1,
                expires_at_ms: 2,
            },
        })
    }

    fn response_value(response: &meshmsg_protocol::Response) -> serde_json::Value {
        serde_json::to_value(response).unwrap()
    }

    fn response_error(response: &meshmsg_protocol::Response) -> &meshmsg_protocol::ProtocolError {
        match response {
            meshmsg_protocol::Response::Error(error) => error,
            _ => panic!("expected protocol error"),
        }
    }

    fn lifecycle_result(
        response: &meshmsg_protocol::Response,
    ) -> &meshmsg_protocol::LifecycleResult {
        match response {
            meshmsg_protocol::Response::OfferRemoved(value)
            | meshmsg_protocol::Response::OffersPruned(value) => value,
            _ => panic!("expected lifecycle response"),
        }
    }

    fn test_topic() -> TopicId {
        TopicId::from_bytes([7; 32])
    }

    fn unsigned_test_envelope(from: PublicKey, body: String, timestamp_ms: u64) -> Envelope {
        Envelope {
            domain: ENVELOPE_DOMAIN.to_owned(),
            version: ENVELOPE_VERSION,
            topic: test_topic(),
            from,
            message_id: [3; 16],
            timestamp_ms,
            kind: EnvelopeKind::Message,
            body,
            signature: ByteArray::new([0; SIGNATURE_LENGTH]),
        }
    }

    fn encode_unchecked_signed_envelope(
        secret: &SecretKey,
        kind: EnvelopeKind,
        body: String,
        message_id: [u8; 16],
        timestamp_ms: u64,
    ) -> Bytes {
        let topic = test_topic();
        let signed = postcard::to_stdvec(&EnvelopeSignaturePayload {
            domain: ENVELOPE_DOMAIN,
            version: ENVELOPE_VERSION,
            topic,
            from: secret.public(),
            message_id,
            timestamp_ms,
            kind,
            body: &body,
        })
        .unwrap();
        postcard::to_stdvec(&Envelope {
            domain: ENVELOPE_DOMAIN.to_owned(),
            version: ENVELOPE_VERSION,
            topic,
            from: secret.public(),
            message_id,
            timestamp_ms,
            kind,
            body,
            signature: ByteArray::new(secret.sign(&signed).to_bytes()),
        })
        .unwrap()
        .into()
    }

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

    #[tokio::test]
    async fn operation_cache_joins_conflicts_caches_terminal_outcomes_and_bounds_retention() {
        let now = StdInstant::now();
        let mut cache = OperationCache::new(2, Duration::from_secs(10));
        let id1 = "11111111111111111111111111111111";
        let id2 = "22222222222222222222222222222222";
        let id3 = "33333333333333333333333333333333";
        let fp1 = operation_fingerprint("send", &[b"one"]);
        let different = operation_fingerprint("send", &[b"different"]);

        // IDs are global across kinds and every lifecycle/download selector is
        // represented without Option ambiguity or path/token normalization.
        assert_ne!(fp1, operation_fingerprint("download", &[b"one"]));
        assert_ne!(
            operation_fingerprint(
                "offers_remove",
                &[
                    b"offer",
                    &optional_text_fingerprint(None),
                    &optional_text_fingerprint(None)
                ],
            ),
            operation_fingerprint(
                "offers_remove",
                &[
                    b"offer",
                    &optional_text_fingerprint(Some("incoming")),
                    &optional_text_fingerprint(None),
                ],
            )
        );
        assert_ne!(
            operation_fingerprint(
                "offers_prune",
                &[
                    &0_u64.to_le_bytes(),
                    &optional_text_fingerprint(None),
                    &[0],
                    &1_usize.to_le_bytes(),
                ],
            ),
            operation_fingerprint(
                "offers_prune",
                &[
                    &1_u64.to_le_bytes(),
                    &optional_text_fingerprint(None),
                    &[0],
                    &1_usize.to_le_bytes(),
                ],
            ),
            "changed prune age must conflict"
        );
        assert_ne!(
            operation_fingerprint("download", &[b"token", b"/tmp/one"]),
            operation_fingerprint("download", &[b"token", b"/tmp/two"]),
        );
        assert_ne!(
            operation_fingerprint("download", &[b"token", b"/tmp/one"]),
            operation_fingerprint("download", &[b"changed-token", b"/tmp/one"]),
        );
        assert_ne!(
            operation_fingerprint("download", &[b"token", b"/tmp/one", b"install"]),
            operation_fingerprint("download", &[b"token", b"/tmp/one", b"raw"]),
        );

        let (reply1, response1) = oneshot::channel();
        assert!(cache.admit(id1.into(), fp1, reply1, now));
        let (duplicate, duplicate_response) = oneshot::channel();
        assert!(!cache.admit(id1.into(), fp1, duplicate, now));
        let (conflict, conflict_response) = oneshot::channel();
        assert!(!cache.admit(id1.into(), different, conflict, now));
        assert_eq!(
            response_error(&conflict_response.await.unwrap()).code,
            meshmsg_protocol::ErrorCode::OperationIdConflict,
        );

        let terminal = contracts::protocol_error_response(
            meshmsg_protocol::ErrorCode::SendFailed,
            meshmsg_protocol::Outcome::Unknown,
            Some(id1.parse().unwrap()),
        );
        let stored = cache.complete(id1, terminal, now);
        assert_eq!(
            response_error(&stored)
                .operation_id
                .as_ref()
                .unwrap()
                .as_str(),
            id1
        );
        assert_eq!(response1.await.unwrap(), stored);
        assert_eq!(duplicate_response.await.unwrap(), stored);
        let (cached, cached_response) = oneshot::channel();
        assert!(!cache.admit(id1.into(), fp1, cached, now));
        assert_eq!(cached_response.await.unwrap(), stored);

        let partial = contracts::protocol_error_response(
            meshmsg_protocol::ErrorCode::DownloadFailed,
            meshmsg_protocol::Outcome::Partial,
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".parse().unwrap()),
        );
        let partial_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let partial_fp = operation_fingerprint("download", &[b"token", b"output"]);
        let mut partial_cache = OperationCache::new(2, Duration::from_secs(10));
        let (partial_reply, partial_response) = oneshot::channel();
        assert!(partial_cache.admit(partial_id.into(), partial_fp, partial_reply, now));
        let partial = partial_cache.complete(partial_id, partial, now);
        assert_eq!(partial_response.await.unwrap(), partial);
        let (partial_retry, partial_retry_response) = oneshot::channel();
        assert!(!partial_cache.admit(partial_id.into(), partial_fp, partial_retry, now));
        assert_eq!(partial_retry_response.await.unwrap(), partial);

        let removal_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let removal_fp = operation_fingerprint("offers_remove", &[b"selector"]);
        let (removal_reply, removal_response) = oneshot::channel();
        assert!(partial_cache.admit(removal_id.into(), removal_fp, removal_reply, now));
        let removal_error = contracts::ProtocolErrorAdapter::new(
            "attachment_removal_partial",
            "private",
            "partial",
            true,
        );
        let removal = partial_cache.complete(
            removal_id,
            meshmsg_protocol::Response::Error(removal_error.typed().unwrap()),
            now,
        );
        assert_eq!(removal_response.await.unwrap(), removal);
        let (removal_retry, removal_retry_response) = oneshot::channel();
        assert!(!partial_cache.admit(removal_id.into(), removal_fp, removal_retry, now));
        assert_eq!(removal_retry_response.await.unwrap(), removal);

        let fp2 = operation_fingerprint("send", &[b"two"]);
        let (reply2, _response2) = oneshot::channel();
        assert!(cache.admit(id2.into(), fp2, reply2, now));
        cache.complete(
            id2,
            contracts::protocol_error_response(
                meshmsg_protocol::ErrorCode::SendFailed,
                meshmsg_protocol::Outcome::Unknown,
                Some(id2.parse().unwrap()),
            ),
            now,
        );
        let fp3 = operation_fingerprint("send", &[b"three"]);
        let (reply3, _response3) = oneshot::channel();
        assert!(cache.admit(id3.into(), fp3, reply3, now));
        assert!(
            !cache.completed.contains_key(id1),
            "oldest terminal entry was not evicted"
        );

        let mut expired = OperationCache::new(2, Duration::from_millis(1));
        let (reply, _response) = oneshot::channel();
        assert!(expired.admit(id1.into(), fp1, reply, now));
        expired.complete(
            id1,
            contracts::protocol_error_response(
                meshmsg_protocol::ErrorCode::SendFailed,
                meshmsg_protocol::Outcome::Unknown,
                Some(id1.parse().unwrap()),
            ),
            now,
        );
        let (retry, _retry_response) = oneshot::channel();
        assert!(expired.admit(id1.into(), fp1, retry, now + Duration::from_millis(2)));

        // The cache is intentionally daemon-lifetime scoped. A fresh daemon
        // admits the same ID again; status/docs tell clients not to infer
        // restart-persistent idempotency.
        let mut restarted = OperationCache::new(2, Duration::from_secs(10));
        let (retry, _retry_response) = oneshot::channel();
        assert!(restarted.admit(id1.into(), fp1, retry, now));
    }

    #[test]
    fn lifecycle_partial_errors_are_compact_across_operation_cache() {
        let operation = "11111111111111111111111111111111";
        let mut producer = contracts::ProtocolErrorAdapter::new(
            "attachment_removal_partial",
            "private store failure",
            "partial",
            true,
        );
        producer.operation_id = Some(operation.into());
        let mut cache = OperationCache::new(2, Duration::from_secs(60));
        let now = StdInstant::now();
        let (reply, _receiver) = oneshot::channel();
        assert!(cache.admit(operation.into(), [7; 32], reply, now));
        let value = cache.complete(
            operation,
            meshmsg_protocol::Response::Error(producer.typed().unwrap()),
            now,
        );
        let error = response_error(&value);
        assert_eq!(error.operation_id.as_ref().unwrap().as_str(), operation);
        assert_eq!(error.outcome, meshmsg_protocol::Outcome::Partial);
        let value = response_value(&value);
        assert!(value.get("selected_tags").is_none());
        assert!(value.get("retryable").is_none());
    }

    #[test]
    fn daemon_resolved_prune_cutoff_is_authoritative_near_ttl() {
        assert_eq!(
            unix_timestamp_ms_saturating(UNIX_EPOCH - Duration::from_millis(1)),
            0,
            "a backwards wall clock saturates instead of creating a future cutoff"
        );
        let operation = "44444444444444444444444444444444";
        let now = StdInstant::now();
        let ttl = Duration::from_secs(600);
        let fingerprint = |age: u64| {
            operation_fingerprint(
                "offers_prune",
                &[
                    &age.to_le_bytes(),
                    &optional_text_fingerprint(Some("outgoing")),
                    &[0],
                    &1_usize.to_le_bytes(),
                ],
            )
        };
        let mut cache = OperationCache::new(4, ttl);
        let (first_reply, _first_receiver) = oneshot::channel();
        assert!(cache.admit(operation.into(), fingerprint(60), first_reply, now));
        let resolution = cache.resolve_prune(operation, 60, 100_000);
        assert_eq!(resolution.cutoff_ms, 40_000);
        let terminal =
            meshmsg_protocol::Response::OffersPruned(meshmsg_protocol::LifecycleResult {
                operation_id: operation.parse().unwrap(),
                offer_id: None,
                direction: Some(meshmsg_protocol::OfferDirection::Outgoing),
                provider: None,
                older_than_secs: Some(60),
                maximum: 1,
                dry_run: false,
                selected_tags: 0,
                removed_tags: 0,
                released_bytes: 0,
                limited: false,
                cutoff_ms: Some(40_000),
            });
        cache.complete(operation, terminal.clone(), now);
        assert_eq!(
            cache.completed.get(operation).unwrap().prune_resolution,
            Some(resolution)
        );

        // A retry can arrive with a much later or backwards wall clock. Its
        // stable caller-intent fingerprint does not derive another cutoff.
        let (replay_reply, replay_receiver) = oneshot::channel();
        assert!(!cache.admit(
            operation.into(),
            fingerprint(60),
            replay_reply,
            now + ttl - Duration::from_millis(1),
        ));
        let replayed = replay_receiver.blocking_recv().unwrap();
        assert_eq!(replayed, terminal);

        let (conflict_reply, conflict_receiver) = oneshot::channel();
        assert!(!cache.admit(
            operation.into(),
            fingerprint(61),
            conflict_reply,
            now + Duration::from_secs(1),
        ));
        let conflict = conflict_receiver.blocking_recv().unwrap();
        assert_eq!(
            response_error(&conflict).code,
            meshmsg_protocol::ErrorCode::OperationIdConflict
        );
        assert_eq!(
            response_error(&conflict)
                .operation_id
                .as_ref()
                .unwrap()
                .as_str(),
            operation
        );
    }

    #[test]
    fn concurrent_offer_listing_returns_the_stable_retryable_busy_contract() {
        let limit = Arc::new(Semaphore::new(1));
        let active_listing = try_admit_offer_listing(&limit).unwrap();
        let busy = try_admit_offer_listing(&limit).unwrap_err();
        assert_eq!(busy.code, meshmsg_protocol::ErrorCode::OffersBusy);
        assert_eq!(busy.message(), "Attachment listing is currently busy.");
        assert_eq!(busy.outcome, meshmsg_protocol::Outcome::NotStarted);
        assert!(busy.retryable());
        drop(active_listing);
        assert!(try_admit_offer_listing(&limit).is_ok());
    }

    #[test]
    fn pinned_blob_tags_preserve_names_and_kinds() {
        let id = "0123456789abcdef0123456789abcdef";
        let provider = SecretKey::generate().public();
        let name = "résumé 2026.pdf";
        assert_eq!(
            parse_pinned_blob_tag(outbound_blob_tag(id, AttachmentKind::File, name).as_bytes()),
            Some(PinnedBlobTag {
                direction: "outgoing",
                offer_id: id.to_owned(),
                provider: None,
                name: name.to_owned(),
                kind: AttachmentKind::File,
            })
        );
        assert_eq!(
            parse_pinned_blob_tag(
                inbound_blob_tag(provider, id, AttachmentKind::DirectoryTarV1, "results.tar")
                    .as_bytes()
            ),
            Some(PinnedBlobTag {
                direction: "incoming",
                offer_id: id.to_owned(),
                provider: Some(provider.to_string()),
                name: "results.tar".to_owned(),
                kind: AttachmentKind::DirectoryTarV1,
            })
        );
    }

    #[test]
    fn malformed_pinned_blob_tags_are_ignored() {
        for invalid in [
            "meshmsg/out/v1/",
            "meshmsg/out/v1/0123456789ABCDEF0123456789ABCDEF/file/bmFtZQ",
            "meshmsg/out/v1/0123456789abcdef0123456789abcdef/unknown/bmFtZQ",
            "meshmsg/out/v1/0123456789abcdef0123456789abcdef/file/not+base64",
            "meshmsg/in/v1//0123456789abcdef0123456789abcdef/file/bmFtZQ",
            "meshmsg/in/v1/provider/0123456789abcdef0123456789abcdef/file/bmFtZQ/extra",
            "meshmsg/out/v2/0123456789abcdef0123456789abcdef/file/bmFtZQ",
            "other/out/v1/0123456789abcdef0123456789abcdef",
        ] {
            assert_eq!(parse_pinned_blob_tag(invalid.as_bytes()), None, "{invalid}");
        }
        assert_eq!(parse_pinned_blob_tag(&[0xff]), None);
        let provider = SecretKey::generate().public().to_string();
        let canonical = format!(
            "{INBOUND_BLOB_TAG_PREFIX}{provider}/0123456789abcdef0123456789abcdef/file/bmFtZQ"
        );
        let uppercase_provider = canonical.replacen(&provider, &provider.to_ascii_uppercase(), 1);
        let padded_provider = canonical.replacen(&provider, &format!("{provider}="), 1);
        assert!(parse_pinned_blob_tag(canonical.as_bytes()).is_some());
        assert_eq!(parse_pinned_blob_tag(uppercase_provider.as_bytes()), None);
        assert_eq!(parse_pinned_blob_tag(padded_provider.as_bytes()), None);
        assert_eq!(
            [canonical, uppercase_provider, padded_provider]
                .iter()
                .filter(|tag| parse_pinned_blob_tag(tag.as_bytes()).is_some())
                .count(),
            1,
            "noncanonical provider encodings consumed duplicate logical slots"
        );

        let oversized_name = format!(
            "meshmsg/out/v1/0123456789abcdef0123456789abcdef/file/{}",
            "A".repeat(MAX_ATTACHMENT_INDEX_TAG_BYTES + 1)
        );
        assert_eq!(parse_pinned_blob_tag(oversized_name.as_bytes()), None);
        let oversized_provider = format!(
            "meshmsg/in/v1/{}/0123456789abcdef0123456789abcdef/file/bmFtZQ",
            "a".repeat(MAX_ENCODED_PUBLIC_KEY_BYTES + 1)
        );
        assert_eq!(parse_pinned_blob_tag(oversized_provider.as_bytes()), None);
    }

    fn sample_offer(provider: PublicKey) -> AttachmentOffer {
        AttachmentOffer {
            offer_id: "0123456789abcdef0123456789abcdef".to_owned(),
            kind: AttachmentKind::File,
            name: "report.txt".to_owned(),
            size: 6,
            ticket: BlobTicket::new(
                iroh::EndpointAddr::new(provider),
                iroh_blobs::Hash::new(b"report"),
                BlobFormat::Raw,
            )
            .to_string(),
        }
    }

    #[test]
    fn signed_attachment_offer_round_trips_and_rejects_tampering() {
        let secret = SecretKey::generate();
        let offer = sample_offer(secret.public());
        let encoded = Envelope::encode_with_id_at(
            &secret,
            test_topic(),
            EnvelopeKind::AttachmentOffer,
            attachment_body(&offer).unwrap(),
            operation_id_bytes(&offer.offer_id),
            42,
        )
        .unwrap();
        let token = BASE64URL_NOPAD.encode(&encoded);

        let (decoded, ticket) = parse_signed_offer_token(&token, test_topic()).unwrap();
        assert_eq!(decoded, offer);
        assert_eq!(ticket.addr().id, secret.public());
        let context = download_request_context(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &token,
            Path::new("/tmp/report.txt"),
            test_topic(),
        )
        .unwrap();
        assert_eq!(context.offer_id.to_string(), offer.offer_id);
        assert_eq!(context.provider.to_string(), secret.public().to_string());
        assert_eq!(context.kind, meshmsg_protocol::AttachmentKind::File);
        assert_eq!(context.name.as_str(), "report.txt");
        assert_eq!(context.declared_size, Some(6));
        assert_eq!(
            context.token_digest.to_string(),
            crate::ipc::download_token_digest(&token)
        );
        validate_attachment_event(
            Some(test_topic()),
            Some(42),
            &secret.public().to_string(),
            &decoded.offer_id,
            42,
            &decoded,
            &token,
        )
        .unwrap();
        assert!(validate_attachment_event(
            Some(TopicId::from_bytes([8; 32])),
            Some(42),
            &secret.public().to_string(),
            &decoded.offer_id,
            42,
            &decoded,
            &token,
        )
        .is_err());
        assert!(validate_attachment_event(
            Some(test_topic()),
            Some(42 + ENVELOPE_ACCEPTANCE_WINDOW.as_millis() as u64 + 1),
            &secret.public().to_string(),
            &decoded.offer_id,
            42,
            &decoded,
            &token,
        )
        .is_err());
        // Saved signed tokens are portable capabilities: their nonzero signed
        // timestamp remains authenticated but does not expire at download time.
        assert!(parse_signed_offer_token(&token, test_topic()).is_ok());
        let zero_time = encode_unchecked_signed_envelope(
            &secret,
            EnvelopeKind::AttachmentOffer,
            attachment_body(&offer).unwrap(),
            operation_id_bytes(&offer.offer_id),
            0,
        );
        let zero_time_envelope = Envelope::decode(&zero_time, test_topic()).unwrap();
        assert!(validate_offer_binding(
            zero_time_envelope.from,
            zero_time_envelope.message_id,
            zero_time_envelope.timestamp_ms,
            &zero_time_envelope.body,
        )
        .is_err());
        assert!(
            parse_signed_offer_token(&BASE64URL_NOPAD.encode(&zero_time), test_topic()).is_err()
        );

        let mut tampered = encoded.to_vec();
        let last = tampered.last_mut().unwrap();
        *last ^= 1;
        assert!(
            parse_signed_offer_token(&BASE64URL_NOPAD.encode(&tampered), test_topic()).is_err()
        );
    }

    #[test]
    fn envelope_v2_is_topic_bound_and_replay_and_time_bounded() {
        let secret = SecretKey::generate();
        let topic = test_topic();
        let other_topic = TopicId::from_bytes([8; 32]);
        let now_ms = 1_700_000_000_000;
        let encoded = Envelope::encode_at(
            &secret,
            topic,
            EnvelopeKind::Message,
            "hello".to_owned(),
            now_ms,
        )
        .unwrap();

        assert!(Envelope::decode(&encoded, other_topic).is_err());
        let envelope = Envelope::decode(&encoded, topic).unwrap();
        assert_eq!(envelope.domain, ENVELOPE_DOMAIN);
        assert_eq!(envelope.version, ENVELOPE_VERSION);
        assert_eq!(envelope.topic, topic);
        assert_eq!(envelope.kind, EnvelopeKind::Message);

        let mut altered = envelope.clone();
        altered.topic = other_topic;
        assert!(Envelope::decode(&postcard::to_stdvec(&altered).unwrap(), other_topic).is_err());
        let mut altered = envelope.clone();
        altered.message_id[0] ^= 1;
        assert!(Envelope::decode(&postcard::to_stdvec(&altered).unwrap(), topic).is_err());
        let mut altered = envelope.clone();
        altered.kind = EnvelopeKind::AttachmentOffer;
        assert!(Envelope::decode(&postcard::to_stdvec(&altered).unwrap(), topic).is_err());

        let mut replay = EnvelopeReplayCache::default();
        replay.accept(&envelope, envelope.from, now_ms).unwrap();
        assert!(replay.accept(&envelope, envelope.from, now_ms).is_err());

        let stale = Envelope::decode(
            &Envelope::encode_at(
                &secret,
                topic,
                EnvelopeKind::Message,
                "stale".to_owned(),
                now_ms - ENVELOPE_ACCEPTANCE_WINDOW.as_millis() as u64 - 1,
            )
            .unwrap(),
            topic,
        )
        .unwrap();
        assert!(EnvelopeReplayCache::default()
            .accept(&stale, stale.from, now_ms)
            .is_err());

        let future = Envelope::decode(
            &Envelope::encode_at(
                &secret,
                topic,
                EnvelopeKind::Message,
                "future".to_owned(),
                now_ms + ENVELOPE_FUTURE_SKEW.as_millis() as u64 + 1,
            )
            .unwrap(),
            topic,
        )
        .unwrap();
        assert!(EnvelopeReplayCache::default()
            .accept(&future, future.from, now_ms)
            .is_err());
    }

    #[test]
    fn crafted_signed_empty_message_is_rejected_before_replay_and_next_message_survives() {
        let secret = SecretKey::generate();
        let topic = test_topic();
        let now_ms = 1_700_000_000_000;
        let message_id = [9; 16];
        let signed_envelope = |body: String| {
            let signed = postcard::to_stdvec(&EnvelopeSignaturePayload {
                domain: ENVELOPE_DOMAIN,
                version: ENVELOPE_VERSION,
                topic,
                from: secret.public(),
                message_id,
                timestamp_ms: now_ms,
                kind: EnvelopeKind::Message,
                body: &body,
            })
            .unwrap();
            postcard::to_stdvec(&Envelope {
                domain: ENVELOPE_DOMAIN.to_owned(),
                version: ENVELOPE_VERSION,
                topic,
                from: secret.public(),
                message_id,
                timestamp_ms: now_ms,
                kind: EnvelopeKind::Message,
                body,
                signature: ByteArray::new(secret.sign(&signed).to_bytes()),
            })
            .unwrap()
        };
        let source = SecretKey::generate().public();
        let mut replay = EnvelopeReplayCache::default();
        let mut sources = TransportSourceLimiter::default();

        let rejected = network_event(
            Event::Received(iroh_gossip::api::Message {
                content: signed_envelope(String::new()).into(),
                scope: iroh_gossip::proto::DeliveryScope::Neighbors,
                delivered_from: source,
            }),
            topic,
            &mut replay,
            &mut sources,
            now_ms,
        );
        assert!(rejected.is_empty());
        assert_eq!(
            replay.live_ids, 0,
            "invalid semantics consumed replay state"
        );

        let accepted = network_event(
            Event::Received(iroh_gossip::api::Message {
                content: signed_envelope("still connected".to_owned()).into(),
                scope: iroh_gossip::proto::DeliveryScope::Neighbors,
                delivered_from: source,
            }),
            topic,
            &mut replay,
            &mut sources,
            now_ms,
        );
        assert_eq!(accepted.len(), 1);
        assert_eq!(accepted[0]["type"], "message");
        assert_eq!(accepted[0]["body"], "still connected");
        assert_eq!(replay.live_ids, 1);
    }

    #[tokio::test]
    async fn local_daemon_interoperates_with_v2_and_rejects_other_protocol_versions() {
        let exercise = |request: Vec<u8>| async move {
            let (mut client, server) = tokio::io::duplex(4096);
            let (commands, mut command_rx) = mpsc::channel(1);
            let (events, _) = broadcast::channel(1);
            let task = tokio::spawn(handle_local_client(
                server,
                commands,
                events.subscribe(),
                connected_fixture(),
                None,
            ));
            client.write_all(&request).await.unwrap();
            let frame = read_frame(&mut client, MAX_IPC_EVENT_SIZE).await.unwrap();
            let value: serde_json::Value = serde_json::from_slice(&frame).unwrap();
            let typed: meshmsg_protocol::DaemonFrame = serde_json::from_slice(&frame).unwrap();
            assert_eq!(typed.protocol_version(), meshmsg_protocol::PROTOCOL_VERSION);
            drop(client);
            let _ = command_rx.recv().await;
            task.await.unwrap().unwrap();
            value
        };

        let mut request = Vec::new();
        write_request_with_id(
            &mut request,
            &IpcRequest::Stop,
            "11111111111111111111111111111111",
        )
        .await
        .unwrap();
        let response = exercise(request).await;
        assert_eq!(response["type"], "stopping");
        assert_eq!(response["request_id"], "11111111111111111111111111111111");
        let response_dto: meshmsg_protocol::ResponseFrame =
            serde_json::from_value(response.clone()).unwrap();
        assert!(matches!(
            response_dto.response,
            meshmsg_protocol::Response::Stopping { .. }
        ));
        let mut unsupported_response = response.clone();
        unsupported_response["protocol_version"] = 3.into();
        assert!(
            serde_json::from_value::<meshmsg_protocol::ResponseFrame>(unsupported_response)
                .is_err()
        );

        // Decode a frame produced by the real subscription path directly through
        // the public typed event frame.
        let (mut client, server) = tokio::io::duplex(4096);
        let (commands, _command_rx) = mpsc::channel(1);
        let (events, _) = broadcast::channel(1);
        let subscriber = tokio::spawn(handle_local_client(
            server,
            commands,
            events.subscribe(),
            connected_fixture(),
            None,
        ));
        write_request_with_id(
            &mut client,
            &IpcRequest::Subscribe,
            "33333333333333333333333333333333",
        )
        .await
        .unwrap();
        let connected = read_frame(&mut client, MAX_IPC_EVENT_SIZE).await.unwrap();
        let event_dto: meshmsg_protocol::EventFrame = serde_json::from_slice(&connected).unwrap();
        assert!(matches!(
            event_dto.event,
            meshmsg_protocol::Event::Connected(_)
        ));
        let mut unsupported_event: serde_json::Value = serde_json::from_slice(&connected).unwrap();
        unsupported_event["protocol_version"] = 3.into();
        assert!(serde_json::from_value::<meshmsg_protocol::EventFrame>(unsupported_event).is_err());
        drop(client);
        subscriber.await.unwrap().unwrap();

        for version in [1, 3] {
            let request = format!(
                "{{\"protocol_version\":{version},\"request_id\":\"22222222222222222222222222222222\",\"request\":{{\"command\":\"stop\"}}}}\n"
            )
            .into_bytes();
            let response = exercise(request).await;
            assert_eq!(response["type"], "error");
            assert_eq!(response["code"], "invalid_request");
            assert!(response.get("request_id").is_none());
            let response_dto: meshmsg_protocol::ResponseFrame =
                serde_json::from_value(response).unwrap();
            assert!(matches!(
                response_dto.response,
                meshmsg_protocol::Response::Error(_)
            ));
        }

        // A failed typed decode is terminal. Even recognizable envelope fields
        // are not reparsed to recover correlation or classify the rejection.
        let oversized_send = serde_json::json!({
            "protocol_version": meshmsg_protocol::PROTOCOL_VERSION,
            "request_id": "44444444444444444444444444444444",
            "request": {
                "command": "send",
                "operation_id": "55555555555555555555555555555555",
                "body": "x".repeat(crate::message::MAX_BROADCAST_BODY_BYTES + 1),
            }
        });
        let mut request = serde_json::to_vec(&oversized_send).unwrap();
        request.push(b'\n');
        let response = exercise(request).await;
        assert_eq!(response["code"], "invalid_request");
        assert!(response.get("request_id").is_none());
        assert!(response.get("operation_id").is_none());
    }

    #[test]
    fn malformed_signed_attachment_semantics_do_not_consume_replay_admission() {
        let signer = SecretKey::generate();
        let other = SecretKey::generate();
        let now_ms = 1_700_000_000_000;
        let message_id = operation_id_bytes("0123456789abcdef0123456789abcdef");
        let mut uppercase = sample_offer(signer.public());
        uppercase.offer_id = uppercase.offer_id.to_ascii_uppercase();
        let mut mixed_case = sample_offer(signer.public());
        mixed_case.offer_id.replace_range(7..8, "A");
        let mut mismatched_id = sample_offer(signer.public());
        mismatched_id.offer_id = "fedcba9876543210fedcba9876543210".into();
        let wrong_provider = sample_offer(other.public());
        let mut unsafe_name = sample_offer(signer.public());
        unsafe_name.name = "../report.txt".into();
        let mut wrong_format = sample_offer(signer.public());
        wrong_format.ticket = BlobTicket::new(
            iroh::EndpointAddr::new(signer.public()),
            iroh_blobs::Hash::new(b"hash sequence"),
            BlobFormat::HashSeq,
        )
        .to_string();
        let malformed_bodies = [
            String::new(),
            format!("{ATTACHMENT_PREFIX}malformed"),
            attachment_body(&uppercase).unwrap(),
            attachment_body(&mixed_case).unwrap(),
            attachment_body(&mismatched_id).unwrap(),
            attachment_body(&wrong_provider).unwrap(),
            attachment_body(&unsafe_name).unwrap(),
            attachment_body(&wrong_format).unwrap(),
        ];

        for body in malformed_bodies {
            let source = SecretKey::generate().public();
            let mut replay = EnvelopeReplayCache::default();
            let mut sources = TransportSourceLimiter::default();
            let rejected = network_event(
                Event::Received(iroh_gossip::api::Message {
                    content: encode_unchecked_signed_envelope(
                        &signer,
                        EnvelopeKind::AttachmentOffer,
                        body,
                        message_id,
                        now_ms,
                    ),
                    scope: iroh_gossip::proto::DeliveryScope::Neighbors,
                    delivered_from: source,
                }),
                test_topic(),
                &mut replay,
                &mut sources,
                now_ms,
            );
            assert!(rejected.is_empty());
            assert_eq!(replay.live_ids, 0);
            assert_eq!(sources.sources.len(), 1);
            assert_eq!(
                sources.admission_global.milli_tokens,
                GLOBAL_TRANSPORT_BURST * 1_000
            );

            let valid = Envelope::encode_with_id_at(
                &signer,
                test_topic(),
                EnvelopeKind::Message,
                "valid reuse after malformed attachment".into(),
                message_id,
                now_ms,
            )
            .unwrap();
            let accepted = network_event(
                Event::Received(iroh_gossip::api::Message {
                    content: valid,
                    scope: iroh_gossip::proto::DeliveryScope::Neighbors,
                    delivered_from: source,
                }),
                test_topic(),
                &mut replay,
                &mut sources,
                now_ms,
            );
            assert_eq!(accepted.len(), 1);
            assert_eq!(accepted[0]["type"], "message");
            assert_eq!(replay.live_ids, 1);
        }
    }

    #[test]
    fn attachment_offer_identity_cannot_be_replayed_under_an_alternate_envelope_id() {
        let signer = SecretKey::generate();
        let source = SecretKey::generate().public();
        let now_ms = 1_700_000_000_000;
        let offer = sample_offer(signer.public());
        let canonical_id = operation_id_bytes(&offer.offer_id);
        let body = attachment_body(&offer).unwrap();
        let canonical = Envelope::encode_with_id_at(
            &signer,
            test_topic(),
            EnvelopeKind::AttachmentOffer,
            body.clone(),
            canonical_id,
            now_ms,
        )
        .unwrap();
        let mut replay = EnvelopeReplayCache::default();
        let mut sources = TransportSourceLimiter::default();
        let received = |content| {
            Event::Received(iroh_gossip::api::Message {
                content,
                scope: iroh_gossip::proto::DeliveryScope::Neighbors,
                delivered_from: source,
            })
        };
        let accepted = network_event(
            received(canonical.clone()),
            test_topic(),
            &mut replay,
            &mut sources,
            now_ms,
        );
        assert_eq!(accepted[0]["type"], "attachment_offer");
        assert_eq!(replay.live_ids, 1);

        let duplicate = network_event(
            received(canonical),
            test_topic(),
            &mut replay,
            &mut sources,
            now_ms,
        );
        assert!(duplicate.is_empty());
        assert_eq!(replay.live_ids, 1);

        let alternate = encode_unchecked_signed_envelope(
            &signer,
            EnvelopeKind::AttachmentOffer,
            body,
            operation_id_bytes("fedcba9876543210fedcba9876543210"),
            now_ms,
        );
        let source_tokens = sources.admission_global.milli_tokens;
        let bypass = network_event(
            received(alternate),
            test_topic(),
            &mut replay,
            &mut sources,
            now_ms,
        );
        assert!(bypass.is_empty(), "malformed offer reached subscribers");
        assert_eq!(replay.live_ids, 1);
        assert_eq!(sources.admission_global.milli_tokens, source_tokens);
    }

    #[test]
    fn stale_future_and_replay_frames_do_not_consume_admission_tokens() {
        let signer = SecretKey::generate();
        let source = SecretKey::generate().public();
        let now_ms = 1_700_000_040_000;
        let mut replay = EnvelopeReplayCache::default();
        let mut sources = TransportSourceLimiter::default();
        let received = |content| {
            Event::Received(iroh_gossip::api::Message {
                content,
                scope: iroh_gossip::proto::DeliveryScope::Neighbors,
                delivered_from: source,
            })
        };
        let stale = encode_unchecked_signed_envelope(
            &signer,
            EnvelopeKind::Message,
            "stale".into(),
            [1; 16],
            now_ms - ENVELOPE_ACCEPTANCE_WINDOW.as_millis() as u64 - 1,
        );
        let future = encode_unchecked_signed_envelope(
            &signer,
            EnvelopeKind::Message,
            "future".into(),
            [2; 16],
            now_ms + ENVELOPE_FUTURE_SKEW.as_millis() as u64 + 1,
        );
        let initial_admission = GLOBAL_TRANSPORT_BURST * 1_000;
        for rejected in [stale, future] {
            let _ = network_event(
                received(rejected),
                test_topic(),
                &mut replay,
                &mut sources,
                now_ms,
            );
            assert_eq!(sources.admission_global.milli_tokens, initial_admission);
            assert_eq!(
                sources.sources[&source].admission_limiter.milli_tokens,
                TRANSPORT_SOURCE_BURST * 1_000
            );
        }

        let valid = Envelope::encode_with_id_at(
            &signer,
            test_topic(),
            EnvelopeKind::Message,
            "valid".into(),
            [3; 16],
            now_ms,
        )
        .unwrap();
        assert_eq!(
            network_event(
                received(valid.clone()),
                test_topic(),
                &mut replay,
                &mut sources,
                now_ms,
            )[0]["type"],
            "message"
        );
        let after_valid = sources.admission_global.milli_tokens;
        let source_after_valid = sources.sources[&source].admission_limiter.milli_tokens;
        let _ = network_event(
            received(valid),
            test_topic(),
            &mut replay,
            &mut sources,
            now_ms,
        );
        assert_eq!(sources.admission_global.milli_tokens, after_valid);
        assert_eq!(
            sources.sources[&source].admission_limiter.milli_tokens,
            source_after_valid
        );

        let unrelated = Envelope::encode_with_id_at(
            &signer,
            test_topic(),
            EnvelopeKind::Message,
            "unrelated".into(),
            [4; 16],
            now_ms,
        )
        .unwrap();
        assert_eq!(
            network_event(
                received(unrelated),
                test_topic(),
                &mut replay,
                &mut sources,
                now_ms,
            )[0]["body"],
            "unrelated"
        );
        assert_eq!(sources.admission_global.milli_tokens, after_valid - 1_000);
        assert_eq!(
            sources.sources[&source].admission_limiter.milli_tokens,
            source_after_valid - 1_000
        );
        assert_eq!(
            sources.verification_global.milli_tokens,
            GLOBAL_TRANSPORT_BURST * 1_000 - 5_000
        );
    }

    #[test]
    fn replay_is_rejected_through_the_exact_bucket_and_freshness_boundary() {
        let secret = SecretKey::generate();
        let bucket_start_ms = 1_700_000_040_000;
        let inserted_at_ms = bucket_start_ms + REPLAY_BUCKET_WIDTH.as_millis() as u64 - 1;
        let envelope = unsigned_test_envelope(
            secret.public(),
            "message".to_owned(),
            inserted_at_ms + ENVELOPE_FUTURE_SKEW.as_millis() as u64,
        );
        let final_fresh_ms = envelope.timestamp_ms + ENVELOPE_ACCEPTANCE_WINDOW.as_millis() as u64;
        assert_eq!(
            final_fresh_ms,
            bucket_start_ms + REPLAY_BUCKET_RETENTION.as_millis() as u64 - 1
        );
        let mut replay = EnvelopeReplayCache::default();
        replay
            .accept(&envelope, envelope.from, inserted_at_ms)
            .unwrap();

        for minutes in 1..=5 {
            let now_ms = inserted_at_ms + minutes * REPLAY_BUCKET_WIDTH.as_millis() as u64;
            assert_eq!(
                replay
                    .accept(&envelope, envelope.from, now_ms)
                    .unwrap_err()
                    .to_string(),
                "replayed message"
            );
        }
        assert_eq!(
            replay
                .accept(&envelope, envelope.from, final_fresh_ms)
                .unwrap_err()
                .to_string(),
            "replayed message"
        );
        assert_eq!(
            replay
                .accept(&envelope, envelope.from, final_fresh_ms + 1)
                .unwrap_err()
                .to_string(),
            "message timestamp is outside the acceptance window"
        );
        assert_eq!(replay.live_ids, 0);
    }

    #[test]
    fn replay_buckets_expire_only_after_the_complete_retention_period() {
        let secret = SecretKey::generate();
        let base_ms = 1_700_000_040_000;
        let mut envelope = unsigned_test_envelope(secret.public(), "message".to_owned(), base_ms);
        let mut replay = EnvelopeReplayCache::default();
        replay.accept(&envelope, envelope.from, base_ms).unwrap();
        let just_before_expiry = base_ms + REPLAY_BUCKET_RETENTION.as_millis() as u64 - 1;
        replay.rotate(just_before_expiry);
        assert_eq!(replay.live_ids, 1);

        let expiry = base_ms + REPLAY_BUCKET_RETENTION.as_millis() as u64;
        replay.rotate(expiry);
        assert_eq!(replay.live_ids, 0);
        assert!(replay.buckets.is_empty());
        envelope.timestamp_ms = expiry;
        replay.accept(&envelope, envelope.from, expiry).unwrap();
    }

    #[test]
    fn per_sender_rate_limit_and_quota_isolate_other_senders() {
        let abusive = SecretKey::generate();
        let other = SecretKey::generate();
        let now_ms = 1_700_000_040_000;
        let mut replay = EnvelopeReplayCache::default();
        let mut envelope = unsigned_test_envelope(abusive.public(), "message".to_owned(), now_ms);
        for index in 0..PER_SENDER_REPLAY_BURST {
            envelope.message_id = u128::from(index).to_le_bytes();
            replay.accept(&envelope, envelope.from, now_ms).unwrap();
        }
        envelope.message_id = u128::from(PER_SENDER_REPLAY_BURST).to_le_bytes();
        assert_eq!(
            replay
                .accept(&envelope, envelope.from, now_ms)
                .unwrap_err()
                .to_string(),
            "sender message rate limit exceeded"
        );

        let mut other_envelope = unsigned_test_envelope(other.public(), "other".to_owned(), now_ms);
        replay
            .accept(&other_envelope, other_envelope.from, now_ms)
            .unwrap();

        replay.senders.get_mut(&abusive.public()).unwrap().live_ids = MAX_REPLAY_IDS_PER_SENDER;
        envelope.timestamp_ms += 10;
        envelope.message_id = u128::from(PER_SENDER_REPLAY_BURST + 1).to_le_bytes();
        assert_eq!(
            replay
                .accept(&envelope, envelope.from, now_ms + 10)
                .unwrap_err()
                .to_string(),
            "sender replay quota reached"
        );
        other_envelope.timestamp_ms += 10;
        other_envelope.message_id[0] ^= 1;
        replay
            .accept(&other_envelope, other_envelope.from, now_ms + 10)
            .unwrap();
    }

    #[test]
    fn authenticated_transport_source_bounds_sender_key_rotation() {
        let source = SecretKey::generate().public();
        let other_source = SecretKey::generate().public();
        let now_ms = 1_700_000_040_000;
        let mut replay = EnvelopeReplayCache::default();
        for index in 0..MAX_REPLAY_SENDERS_PER_SOURCE {
            let mut envelope = unsigned_test_envelope(
                SecretKey::generate().public(),
                "rotated".to_owned(),
                now_ms,
            );
            envelope.message_id = (index as u128).to_le_bytes();
            replay.accept(&envelope, source, now_ms).unwrap();
        }
        let rotated = unsigned_test_envelope(
            SecretKey::generate().public(),
            "one too many".to_owned(),
            now_ms,
        );
        assert_eq!(
            replay
                .accept(&rotated, source, now_ms)
                .unwrap_err()
                .to_string(),
            "transport source sender quota reached"
        );
        replay.accept(&rotated, other_source, now_ms).unwrap();
    }

    #[test]
    fn malformed_and_overloaded_remote_traffic_is_silent_before_admission() {
        let source = SecretKey::generate().public();
        let now_ms = 1_700_000_040_000;
        let mut sources = TransportSourceLimiter::default();
        for _ in 0..TRANSPORT_SOURCE_BURST {
            assert!(sources.allow_verification(source, now_ms));
        }
        let global_tokens_before_malformed = sources.admission_global.milli_tokens;
        let mut replay = EnvelopeReplayCache::default();
        let values = network_event(
            Event::Received(iroh_gossip::api::Message {
                content: Bytes::from_static(b"not an envelope"),
                scope: iroh_gossip::proto::DeliveryScope::Neighbors,
                delivered_from: source,
            }),
            test_topic(),
            &mut replay,
            &mut sources,
            now_ms,
        );
        assert!(values.is_empty());
        assert_eq!(replay.live_ids, 0);
        assert_eq!(sources.sources.len(), 1);
        assert_eq!(
            sources.admission_global.milli_tokens,
            global_tokens_before_malformed
        );
    }

    #[test]
    fn transport_source_limiter_isolates_sources_and_bounds_source_rotation() {
        let now_ms = 1_700_000_040_000;
        let abusive = SecretKey::generate().public();
        let other = SecretKey::generate().public();
        let mut limiter = TransportSourceLimiter::default();
        for _ in 0..TRANSPORT_SOURCE_BURST {
            assert!(limiter.allow_verification(abusive, now_ms));
        }
        assert!(!limiter.allow_verification(abusive, now_ms));
        assert!(limiter.allow_verification(other, now_ms));

        let mut source_limited = TransportSourceLimiter::default();
        for _ in 0..MAX_TRANSPORT_SOURCES {
            assert!(source_limited.allow_verification(SecretKey::generate().public(), now_ms));
        }
        assert!(!source_limited.allow_verification(SecretKey::generate().public(), now_ms));
        assert!(source_limited.allow_verification(
            SecretKey::generate().public(),
            now_ms + TRANSPORT_SOURCE_IDLE_LIFETIME.as_millis() as u64
        ));
    }

    #[test]
    fn global_pressure_rejects_without_evicting_live_replay_ids() {
        let now_ms = 1_700_000_040_000;
        let secrets: Vec<_> = (0..10).map(|_| SecretKey::generate()).collect();
        let mut replay = EnvelopeReplayCache::default();
        let mut first = None;
        for index in 0..GLOBAL_REPLAY_BURST {
            let secret = &secrets[index as usize % secrets.len()];
            let mut envelope =
                unsigned_test_envelope(secret.public(), "message".to_owned(), now_ms);
            envelope.message_id = u128::from(index).to_le_bytes();
            replay.accept(&envelope, envelope.from, now_ms).unwrap();
            first.get_or_insert(envelope);
        }
        let mut next =
            unsigned_test_envelope(SecretKey::generate().public(), "next".to_owned(), now_ms);
        assert_eq!(
            replay
                .accept(&next, next.from, now_ms)
                .unwrap_err()
                .to_string(),
            "global message rate limit exceeded"
        );
        assert_eq!(
            replay
                .accept(
                    first.as_ref().unwrap(),
                    first.as_ref().unwrap().from,
                    now_ms,
                )
                .unwrap_err()
                .to_string(),
            "replayed message"
        );

        next.timestamp_ms += 1;
        replay.accept(&next, next.from, now_ms + 1).unwrap();

        let mut capacity_limited = EnvelopeReplayCache::with_capacity(3);
        let source = SecretKey::generate().public();
        let mut retained = unsigned_test_envelope(
            SecretKey::generate().public(),
            "retained".to_owned(),
            now_ms,
        );
        for id in 0..3_u128 {
            retained.message_id = id.to_le_bytes();
            capacity_limited.accept(&retained, source, now_ms).unwrap();
        }
        let first_retained = {
            let mut value = retained.clone();
            value.message_id = 0_u128.to_le_bytes();
            value
        };
        retained.message_id = 3_u128.to_le_bytes();
        assert_eq!(
            capacity_limited
                .accept(&retained, source, now_ms)
                .unwrap_err()
                .to_string(),
            "global replay capacity reached"
        );
        assert_eq!(capacity_limited.live_ids, 3);
        assert_eq!(
            capacity_limited
                .accept(&first_retained, source, now_ms)
                .unwrap_err()
                .to_string(),
            "replayed message"
        );
    }

    #[test]
    fn token_bucket_and_timestamp_boundaries_are_inclusive_and_exact() {
        assert_eq!(MAX_REPLAY_IDS_PER_SENDER, 42_200);
        assert_eq!(MAX_ENVELOPE_REPLAY_ENTRIES, 422_000);
        let secret = SecretKey::generate();
        let now_ms = 1_700_000_040_000;
        let mut replay = EnvelopeReplayCache::default();
        let mut envelope = unsigned_test_envelope(
            secret.public(),
            "oldest".to_owned(),
            now_ms - ENVELOPE_ACCEPTANCE_WINDOW.as_millis() as u64,
        );
        replay.accept(&envelope, envelope.from, now_ms).unwrap();
        envelope.message_id[0] ^= 1;
        envelope.timestamp_ms = now_ms + ENVELOPE_FUTURE_SKEW.as_millis() as u64;
        replay.accept(&envelope, envelope.from, now_ms).unwrap();

        let mut limiter = TokenBucket::new(100, 1, now_ms);
        assert!(limiter.available());
        limiter.consume();
        limiter.refill(now_ms + 9);
        assert!(!limiter.available());
        limiter.refill(now_ms + 10);
        assert!(limiter.available());
    }

    #[test]
    fn attachment_wire_rejects_provider_mismatch_version_and_trailing_bytes() {
        let signer = SecretKey::generate();
        let other = SecretKey::generate();
        let mismatched = sample_offer(other.public());
        assert!(crate::attachment::protocol::encode_signed_offer(
            &signer,
            test_topic(),
            mismatched,
            42,
        )
        .is_err());

        let version = postcard::to_stdvec(&AttachmentWire {
            version: ATTACHMENT_OFFER_VERSION + 1,
            offer: sample_offer(signer.public()),
        })
        .unwrap();
        let body = format!("{ATTACHMENT_PREFIX}{}", BASE64URL_NOPAD.encode(&version));
        assert!(parse_attachment_body(&body).is_err());

        let mut trailing = postcard::to_stdvec(&AttachmentWire {
            version: ATTACHMENT_OFFER_VERSION,
            offer: sample_offer(signer.public()),
        })
        .unwrap();
        trailing.push(0);
        let body = format!("{ATTACHMENT_PREFIX}{}", BASE64URL_NOPAD.encode(&trailing));
        assert!(parse_attachment_body(&body).is_err());
    }

    #[test]
    fn ordinary_and_malformed_prefixed_signed_text_remain_messages() {
        let secret = SecretKey::generate();
        for body in ["legacy text", "meshmsg-attachment-v1:not-an-offer"] {
            let encoded = Envelope::encode_at(
                &secret,
                test_topic(),
                EnvelopeKind::Message,
                body.to_owned(),
                42,
            )
            .unwrap();
            let envelope = Envelope::decode(&encoded, test_topic()).unwrap();
            let event = received_envelope_event(envelope, &encoded);
            assert_eq!(event["type"], "message");
            assert_eq!(event["body"], body);
        }
    }

    #[test]
    fn signed_zero_size_is_validated_but_raw_ticket_size_is_unspecified() {
        validate_declared_attachment_size(Some(0), 0).unwrap();
        assert!(validate_declared_attachment_size(Some(0), 1).is_err());
        validate_declared_attachment_size(None, 1).unwrap();
    }

    #[test]
    fn envelope_boundary_matches_configured_gossip_headroom() {
        assert_eq!(
            GOSSIP_MAX_MESSAGE_SIZE - MAX_ENVELOPE_SIZE,
            GOSSIP_PROTOCOL_HEADROOM
        );
        let secret = SecretKey::generate();
        let timestamp_ms = 1_700_000_000_000;
        let body = "a".repeat(crate::message::MAX_BROADCAST_BODY_BYTES);
        for timestamp in [timestamp_ms, u64::MAX] {
            let encoded = Envelope::encode_at(
                &secret,
                test_topic(),
                EnvelopeKind::Message,
                body.clone(),
                timestamp,
            )
            .unwrap();
            assert!(encoded.len() <= MAX_ENVELOPE_SIZE);
        }
        assert!(Envelope::encode_at(
            &secret,
            test_topic(),
            EnvelopeKind::Message,
            "a".repeat(crate::message::MAX_BROADCAST_BODY_BYTES + 1),
            timestamp_ms,
        )
        .is_err());
    }

    #[test]
    fn released_v2_body_range_remains_decodable_and_publishable() {
        let secret = SecretKey::generate();
        for length in [
            crate::message::MAX_BROADCAST_BODY_BYTES + 1,
            3923,
            crate::message::MAX_V2_MESSAGE_BODY_BYTES,
        ] {
            let encoded = encode_unchecked_signed_envelope(
                &secret,
                EnvelopeKind::Message,
                "a".repeat(length),
                [5; 16],
                1,
            );
            assert!(encoded.len() <= MAX_ENVELOPE_SIZE);
            let envelope = Envelope::decode(&encoded, test_topic()).unwrap();
            assert_eq!(envelope.body.len(), length);
            let value = message_event(envelope);
            assert!(serde_json::from_value::<meshmsg_protocol::Event>(value).is_ok());
        }
    }

    #[test]
    fn released_v2_capacity_uses_exact_postcard_metadata_boundaries() {
        let secret = SecretKey::generate();
        // Postcard varints add one metadata byte at each 7-bit timestamp
        // boundary. These capacities are measured on the complete released V2
        // structure, including its string-length prefix and fixed signature.
        for (timestamp_ms, capacity) in [
            (0, 3928),
            (127, 3928),
            (1_u64 << 7, 3927),
            ((1_u64 << 14) - 1, 3927),
            (1_u64 << 14, 3926),
            (1_u64 << 21, 3925),
            (1_u64 << 28, 3924),
            (1_u64 << 35, 3923),
            (1_u64 << 42, 3922),
            (1_u64 << 49, 3921),
            (1_u64 << 56, 3920),
            (1_u64 << 63, 3919),
            (u64::MAX, 3919),
        ] {
            let at_limit = encode_unchecked_signed_envelope(
                &secret,
                EnvelopeKind::Message,
                "a".repeat(capacity),
                [6; 16],
                timestamp_ms,
            );
            let over_limit = encode_unchecked_signed_envelope(
                &secret,
                EnvelopeKind::Message,
                "a".repeat(capacity + 1),
                [6; 16],
                timestamp_ms,
            );
            assert_eq!(
                at_limit.len(),
                MAX_ENVELOPE_SIZE,
                "timestamp {timestamp_ms}"
            );
            assert!(
                Envelope::decode(&at_limit, test_topic()).is_ok(),
                "exact frame rejected at timestamp {timestamp_ms}"
            );
            assert_eq!(
                over_limit.len(),
                MAX_ENVELOPE_SIZE + 1,
                "timestamp {timestamp_ms}"
            );
            assert!(
                Envelope::decode(&over_limit, test_topic()).is_err(),
                "oversized frame accepted at timestamp {timestamp_ms}"
            );
        }

        let body_127 = encode_unchecked_signed_envelope(
            &secret,
            EnvelopeKind::Message,
            "a".repeat(127),
            [7; 16],
            0,
        );
        let body_128 = encode_unchecked_signed_envelope(
            &secret,
            EnvelopeKind::Message,
            "a".repeat(128),
            [7; 16],
            0,
        );
        assert_eq!(body_128.len() - body_127.len(), 2);
        assert_eq!(crate::message::MAX_V2_MESSAGE_BODY_BYTES, 3928);
    }

    #[test]
    fn decode_rejects_oversized_signed_envelope() {
        let secret = SecretKey::generate();
        let timestamp_ms = 1_700_000_000_000;
        let body = "a".repeat(MAX_ENVELOPE_SIZE);
        let envelope = unsigned_test_envelope(secret.public(), body, timestamp_ms);
        let encoded = postcard::to_stdvec(&envelope).unwrap();
        assert!(encoded.len() > MAX_ENVELOPE_SIZE);
        assert!(Envelope::decode(&encoded, test_topic()).is_err());
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let secret = SecretKey::generate();
        let mut encoded = Envelope::encode_at(
            &secret,
            test_topic(),
            EnvelopeKind::Message,
            "hello".to_owned(),
            42,
        )
        .unwrap()
        .to_vec();
        encoded.push(0);

        assert!(Envelope::decode(&encoded, test_topic()).is_err());
    }

    #[test]
    fn queued_event_has_canonical_send_metadata_and_does_not_claim_delivery() {
        let value = queued_event(
            &"1".repeat(64),
            [4; 16],
            "hello".to_owned(),
            1_700_000_000_000,
        );

        assert_eq!(value["type"], "queued");
        assert_eq!(value["protocol_version"], 2);
        assert!(contracts::valid_request_id(
            value["request_id"].as_str().unwrap()
        ));
        assert_eq!(value["operation_id"], "04040404040404040404040404040404");
        assert_eq!(value["message_id"], "04040404040404040404040404040404");
        assert_eq!(value["from"], "1".repeat(64));
        assert_eq!(value["body"], "hello");
        assert_eq!(value["timestamp_ms"], 1_700_000_000_000_u64);
        assert_eq!(value["delivery_acknowledged"], false);
        assert_object_keys(
            &value,
            &[
                "protocol_version",
                "request_id",
                "type",
                "from",
                "operation_id",
                "message_id",
                "timestamp_ms",
                "body",
                "delivery_acknowledged",
            ],
        );
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

    #[tokio::test]
    async fn download_commit_process_exit_child() {
        let Ok(root) = std::env::var("MESHMSG_COMMIT_CRASH_ROOT") else {
            return;
        };
        let phase = std::env::var("MESHMSG_COMMIT_CRASH_PHASE").unwrap();
        let root = PathBuf::from(root);
        std::fs::create_dir_all(&root).unwrap();
        let options = FsStoreOptions::new(&root.join("store"));
        let store: Store = FsStore::load_with_opts(root.join("blobs.db"), options)
            .await
            .unwrap()
            .into();
        let provider = SecretKey::from_bytes(&[9; 32]).public();
        let ticket = BlobTicket::new(
            iroh::EndpointAddr::new(provider),
            iroh_blobs::Hash::new(b"crash payload"),
            BlobFormat::Raw,
        );
        let tag = raw_ticket_blob_tag(&ticket);
        let staging = root.join(".meshmsg-part-1111111111111111.download");
        std::fs::write(&staging, b"crash payload").unwrap();
        let output = root.join("output");
        let _ = commit_download(
            DownloadCommit {
                store: &store,
                tag_name: tag.as_bytes(),
                hash_and_format: ticket.hash_and_format(),
                staging: attachment::StagedFile::new(staging),
                output: &output,
                kind: AttachmentKind::File,
                max_attachment_bytes: DEFAULT_MAX_ATTACHMENT_BYTES,
                pin_already_committed: false,
            },
            &|boundary| {
                if boundary == phase {
                    std::process::exit(86);
                }
                Ok(())
            },
        )
        .await;
        panic!("child did not exit at {phase}");
    }

    #[tokio::test]
    async fn process_exit_recovery_reopens_raw_pin_retries_without_duplicates_and_tracks_leftovers()
    {
        for phase in ["after_blob_tag_sync", "after_destination_install"] {
            let root = std::env::temp_dir().join(format!(
                "meshmsg-commit-process-exit-{phase}-{}",
                rand::random::<u64>()
            ));
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg("node::tests::download_commit_process_exit_child")
                .arg("--nocapture")
                .env("MESHMSG_COMMIT_CRASH_ROOT", &root)
                .env("MESHMSG_COMMIT_CRASH_PHASE", phase)
                .status()
                .unwrap();
            assert_eq!(status.code(), Some(86));

            let provider = SecretKey::from_bytes(&[9; 32]).public();
            let ticket = BlobTicket::new(
                iroh::EndpointAddr::new(provider),
                iroh_blobs::Hash::new(b"crash payload"),
                BlobFormat::Raw,
            );
            let offer_id = raw_ticket_offer_id(&ticket);
            assert!(contracts::valid_operation_id(&offer_id));
            assert_eq!(offer_id, raw_ticket_offer_id(&ticket));
            let tag = raw_ticket_blob_tag(&ticket);
            let options = FsStoreOptions::new(&root.join("store"));
            let store: Store = FsStore::load_with_opts(root.join("blobs.db"), options)
                .await
                .unwrap()
                .into();
            let (pins, _, item_errors) = list_pinned_blobs(&store).await.unwrap();
            assert!(
                pins.is_empty(),
                "missing blob content must not be advertised"
            );
            assert_eq!(item_errors, 1);
            assert_eq!(
                store
                    .tags()
                    .get(tag.as_bytes())
                    .await
                    .unwrap()
                    .unwrap()
                    .hash_and_format(),
                ticket.hash_and_format()
            );
            let output = root.join("output");
            let staging = root.join(".meshmsg-part-1111111111111111.download");
            assert_eq!(output.exists(), phase == "after_destination_install");
            assert!(staging.exists(), "abrupt exit should bypass cleanup guards");
            // Arbitrary output scopes are not scanned by state startup cleanup.
            assert_eq!(attachment::cleanup_stale_state_staging(&root).unwrap(), 0);
            assert!(staging.exists());

            if phase == "after_blob_tag_sync" {
                let outcome = commit_download(
                    DownloadCommit {
                        store: &store,
                        tag_name: tag.as_bytes(),
                        hash_and_format: ticket.hash_and_format(),
                        staging: attachment::StagedFile::new(staging.clone()),
                        output: &output,
                        kind: AttachmentKind::File,
                        max_attachment_bytes: DEFAULT_MAX_ATTACHMENT_BYTES,
                        pin_already_committed: false,
                    },
                    &|_| Ok(()),
                )
                .await
                .unwrap();
                assert!(outcome.destination_synced);
                assert!(outcome.cleanup_complete);
                assert_eq!(
                    store
                        .tags()
                        .get(tag.as_bytes())
                        .await
                        .unwrap()
                        .unwrap()
                        .hash_and_format(),
                    ticket.hash_and_format(),
                    "raw retry changed the permanent pin"
                );
                assert_eq!(std::fs::read(&output).unwrap(), b"crash payload");
                assert!(!staging.exists());
            }
            drop(store);
            let _ = std::fs::remove_dir_all(root);
        }
    }

    #[tokio::test]
    async fn download_commit_fault_boundaries_preserve_retry_and_partial_success_semantics() {
        for boundary in [
            "blob_tag_persist",
            "after_blob_tag_persist",
            "blob_tag_sync",
            "after_blob_tag_sync",
            "destination_install",
        ] {
            let root = std::env::temp_dir().join(format!(
                "meshmsg-download-commit-{boundary}-{}",
                rand::random::<u64>()
            ));
            std::fs::create_dir_all(&root).unwrap();
            let options = FsStoreOptions::new(&root.join("store"));
            let store: Store = FsStore::load_with_opts(root.join("blobs.db"), options)
                .await
                .unwrap()
                .into();
            let hash_and_format = iroh_blobs::HashAndFormat::raw(iroh_blobs::Hash::new(b"blob"));
            let provider = SecretKey::generate().public();
            let provider_text = provider.to_string();
            let tag = inbound_blob_tag(
                provider,
                "0123456789abcdef0123456789abcdef",
                AttachmentKind::File,
                "retry.txt",
            );
            let output = root.join("output");
            let staging = root.join("first.download");
            std::fs::write(&staging, b"blob").unwrap();
            let injected = |current| {
                if current == boundary {
                    anyhow::bail!("injected {boundary} failure")
                }
                Ok(())
            };

            let error = commit_download(
                DownloadCommit {
                    store: &store,
                    tag_name: tag.as_bytes(),
                    hash_and_format,
                    staging: attachment::StagedFile::new(staging.clone()),
                    output: &output,
                    kind: AttachmentKind::File,
                    max_attachment_bytes: DEFAULT_MAX_ATTACHMENT_BYTES,
                    pin_already_committed: false,
                },
                &injected,
            )
            .await
            .unwrap_err();
            assert!(error.to_string().contains("injected"));
            assert!(
                !output.exists(),
                "{boundary} installed an output on failure"
            );
            assert!(
                !staging.exists(),
                "{boundary} leaked its failed staging file"
            );
            assert_eq!(
                store.tags().get(tag.as_bytes()).await.unwrap().is_some(),
                boundary != "blob_tag_persist",
                "unexpected pin state at {boundary}"
            );

            // Retrying repeats the idempotent tag set/sync and then installs to
            // the still-unused destination. This also recovers an uncertain
            // tag sync and a durable pin left by an install failure.
            let retry_staging = root.join("retry.download");
            std::fs::write(&retry_staging, b"blob").unwrap();
            let outcome = commit_download(
                DownloadCommit {
                    store: &store,
                    tag_name: tag.as_bytes(),
                    hash_and_format,
                    staging: attachment::StagedFile::new(retry_staging),
                    output: &output,
                    kind: AttachmentKind::File,
                    max_attachment_bytes: DEFAULT_MAX_ATTACHMENT_BYTES,
                    pin_already_committed: false,
                },
                &|_| Ok(()),
            )
            .await
            .unwrap();
            assert!(outcome.destination_synced);
            assert!(outcome.cleanup_complete);
            assert!(outcome.warnings.is_empty());
            assert_eq!(std::fs::read(&output).unwrap(), b"blob");
            store.sync_db().await.unwrap();
            let parsed = parse_pinned_blob_tag(tag.as_bytes()).unwrap();
            assert_eq!(parsed.direction, "incoming");
            assert_eq!(parsed.provider.as_deref(), Some(provider_text.as_str()));
            assert_eq!(
                store
                    .tags()
                    .get(tag.as_bytes())
                    .await
                    .unwrap()
                    .unwrap()
                    .hash_and_format(),
                hash_and_format
            );
            drop(store);
            let _ = std::fs::remove_dir_all(root);
        }

        for boundary in [
            "after_destination_install",
            "destination_sync",
            "parent_sync",
            "after_destination_sync",
            "staging_cleanup",
            "after_staging_cleanup",
        ] {
            let root = std::env::temp_dir().join(format!(
                "meshmsg-download-partial-{boundary}-{}",
                rand::random::<u64>()
            ));
            std::fs::create_dir_all(&root).unwrap();
            let options = FsStoreOptions::new(&root.join("store"));
            let store: Store = FsStore::load_with_opts(root.join("blobs.db"), options)
                .await
                .unwrap()
                .into();
            let hash_and_format = iroh_blobs::HashAndFormat::raw(iroh_blobs::Hash::new(b"blob"));
            let provider = SecretKey::generate().public();
            let provider_text = provider.to_string();
            let tag = inbound_blob_tag(
                provider,
                "fedcba9876543210fedcba9876543210",
                AttachmentKind::File,
                "partial.txt",
            );
            let output = root.join("output");
            let staging = root.join("part.download");
            std::fs::write(&staging, b"blob").unwrap();
            let injected = |current| {
                if current == boundary {
                    anyhow::bail!("injected {boundary} failure")
                }
                Ok(())
            };

            let outcome = commit_download(
                DownloadCommit {
                    store: &store,
                    tag_name: tag.as_bytes(),
                    hash_and_format,
                    staging: attachment::StagedFile::new(staging.clone()),
                    output: &output,
                    kind: AttachmentKind::File,
                    max_attachment_bytes: DEFAULT_MAX_ATTACHMENT_BYTES,
                    pin_already_committed: false,
                },
                &injected,
            )
            .await
            .unwrap();
            assert_eq!(std::fs::read(&output).unwrap(), b"blob");
            assert_eq!(
                outcome.destination_synced,
                !matches!(boundary, "destination_sync" | "parent_sync")
            );
            assert_eq!(outcome.cleanup_complete, boundary != "staging_cleanup");
            assert_eq!(outcome.warnings.len(), 1);
            assert!(!staging.exists(), "drop recovery did not remove staging");
            let parsed = parse_pinned_blob_tag(tag.as_bytes()).unwrap();
            assert_eq!(parsed.direction, "incoming");
            assert_eq!(parsed.provider.as_deref(), Some(provider_text.as_str()));
            assert_eq!(
                store
                    .tags()
                    .get(tag.as_bytes())
                    .await
                    .unwrap()
                    .unwrap()
                    .hash_and_format(),
                hash_and_format
            );
            drop(store);
            let _ = std::fs::remove_dir_all(root);
        }
    }

    #[tokio::test]
    async fn signed_directory_commit_reports_after_install_fault_without_false_failure() {
        let root = std::env::temp_dir().join(format!(
            "meshmsg-signed-directory-commit-{}",
            rand::random::<u64>()
        ));
        let source = root.join("source");
        std::fs::create_dir_all(source.join("nested")).unwrap();
        std::fs::write(source.join("nested/file.txt"), b"directory payload").unwrap();
        let archive = root.join("directory.download");
        attachment::create_deterministic_tar(&source, &archive, DEFAULT_MAX_ATTACHMENT_BYTES)
            .unwrap();
        let bytes = std::fs::read(&archive).unwrap();
        let hash_and_format = iroh_blobs::HashAndFormat::raw(iroh_blobs::Hash::new(&bytes));
        let provider = SecretKey::generate().public();
        let offer_id = "abcdefabcdefabcdefabcdefabcdefab";
        let tag = inbound_blob_tag(
            provider,
            offer_id,
            AttachmentKind::DirectoryTarV1,
            "source.tar",
        );
        let options = FsStoreOptions::new(&root.join("store"));
        let store: Store = FsStore::load_with_opts(root.join("blobs.db"), options)
            .await
            .unwrap()
            .into();
        let output = root.join("installed");
        let outcome = commit_download(
            DownloadCommit {
                store: &store,
                tag_name: tag.as_bytes(),
                hash_and_format,
                staging: attachment::StagedFile::new(archive),
                output: &output,
                kind: AttachmentKind::DirectoryTarV1,
                max_attachment_bytes: DEFAULT_MAX_ATTACHMENT_BYTES,
                pin_already_committed: false,
            },
            &|boundary| {
                if boundary == "after_destination_install" {
                    anyhow::bail!("simulated interruption")
                }
                Ok(())
            },
        )
        .await
        .unwrap();
        assert!(outcome.destination_synced);
        assert!(outcome.cleanup_complete);
        assert_eq!(outcome.warnings.len(), 1);
        assert_eq!(
            std::fs::read(output.join("nested/file.txt")).unwrap(),
            b"directory payload"
        );
        let parsed = parse_pinned_blob_tag(tag.as_bytes()).unwrap();
        assert_eq!(parsed.direction, "incoming");
        assert_eq!(parsed.offer_id, offer_id);
        assert_eq!(
            store
                .tags()
                .get(tag.as_bytes())
                .await
                .unwrap()
                .unwrap()
                .hash_and_format(),
            hash_and_format
        );
        drop(store);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn actual_blob_store_listing_caps_valid_ordered_tags() {
        let dir =
            std::env::temp_dir().join(format!("meshmsg-offers-test-{}", rand::random::<u64>()));
        let options = FsStoreOptions::new(&dir);
        let store: Store = FsStore::load_with_opts(dir.join("blobs.db"), options)
            .await
            .unwrap()
            .into();
        let source = dir.join("listing-source");
        std::fs::write(&source, b"listing test").unwrap();
        let imported = store.blobs().add_path(&source).temp_tag().await.unwrap();
        let hash = imported.hash();
        for index in (0..=MAX_OFFER_LIST_ENTRIES).rev() {
            let tag = outbound_blob_tag(
                &format!("{index:032x}"),
                AttachmentKind::File,
                &format!("file-{index}"),
            );
            store
                .tags()
                .set(tag.as_bytes(), iroh_blobs::HashAndFormat::raw(hash))
                .await
                .unwrap();
        }
        // A malformed tag is ignored by the real parser and does not consume the valid cap.
        store
            .tags()
            .set(
                b"meshmsg/out/v1/not-an-offer/file/bmFtZQ",
                iroh_blobs::HashAndFormat::raw(hash),
            )
            .await
            .unwrap();

        let (blobs, truncated, item_errors) = list_pinned_blobs(&store).await.unwrap();
        assert_eq!(blobs.len(), MAX_OFFER_LIST_ENTRIES);
        assert!(truncated);
        assert_eq!(item_errors, 1);
        assert_eq!(blobs[0].offer_id.to_string(), format!("{:032x}", 0));
        assert_eq!(
            blobs.last().unwrap().offer_id.to_string(),
            format!("{:032x}", MAX_OFFER_LIST_ENTRIES - 1)
        );
        let frame = meshmsg_protocol::ResponseFrame::new(
            Some(meshmsg_protocol::RequestId::new_random()),
            meshmsg_protocol::Response::Offers(meshmsg_protocol::OffersList {
                blobs,
                truncated,
                item_errors,
            }),
        );
        let encoded = serde_json::to_vec(&frame).unwrap();
        assert!(
            encoded.len() <= MAX_IPC_EVENT_SIZE,
            "maximum canonical offer-list response exceeds IPC frame"
        );
        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }

    fn encoded_bao(data: &[u8], ranges: &bao_tree::ChunkRanges) -> (iroh_blobs::Hash, Vec<u8>) {
        use bao_tree::io::outboard::PreOrderMemOutboard;
        let outboard = PreOrderMemOutboard::create(data, iroh_blobs::store::IROH_BLOCK_SIZE);
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&(data.len() as u64).to_le_bytes());
        bao_tree::io::sync::encode_ranges_validated(data, &outboard, ranges, &mut encoded).unwrap();
        (outboard.root.into(), encoded)
    }

    async fn lifecycle_test_store(label: &str) -> (PathBuf, PathBuf, Store) {
        let root =
            std::env::temp_dir().join(format!("meshmsg-storage-{label}-{}", rand::random::<u64>()));
        let state = root.join("state");
        let blob_root = root.join("blobs");
        std::fs::create_dir_all(&state).unwrap();
        let store: Store =
            FsStore::load_with_opts(blob_root.join("blobs.db"), FsStoreOptions::new(&blob_root))
                .await
                .unwrap()
                .into();
        persist_attachment_index(&state, &AttachmentRetentionIndex::default()).unwrap();
        (root, state, store)
    }

    #[tokio::test]
    async fn missing_attachment_index_initializes_only_an_empty_fresh_store() {
        let (root, state, store) = lifecycle_test_store("missing-index-empty").await;
        std::fs::remove_file(state.join(ATTACHMENT_INDEX_NAME)).unwrap();

        let storage = AttachmentStorage::open(store.clone(), root.join("blobs"), &state, 100, 0, 0)
            .await
            .unwrap();
        assert_eq!(storage.status().tags, 0);
        assert!(state.join(ATTACHMENT_INDEX_NAME).is_file());

        drop(storage);
        drop(store);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn managed_pins_without_attachment_index_fail_closed() {
        let (root, state, store) = lifecycle_test_store("missing-index-pins").await;
        std::fs::remove_file(state.join(ATTACHMENT_INDEX_NAME)).unwrap();
        let tag = outbound_blob_tag(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            AttachmentKind::File,
            "existing.bin",
        );
        pin_test_blob(&store, &root, b"existing", &[tag]).await;

        let error = AttachmentStorage::open(store.clone(), root.join("blobs"), &state, 100, 0, 0)
            .await
            .err()
            .expect("managed pins without a current index must fail closed");
        let message = format!("{error:#}");
        assert!(message.contains("attachment retention index is missing"));
        assert!(message.contains("restore attachment-retention-v1.json"));
        assert!(!state.join(ATTACHMENT_INDEX_NAME).exists());

        drop(store);
        let _ = std::fs::remove_dir_all(root);
    }

    async fn pin_test_blob(store: &Store, root: &Path, bytes: &[u8], tags: &[String]) {
        let path = root.join(format!("source-{}", rand::random::<u64>()));
        std::fs::write(&path, bytes).unwrap();
        let imported = store.blobs().add_path(&path).temp_tag().await.unwrap();
        for tag in tags {
            store
                .tags()
                .set(tag.as_bytes(), imported.hash_and_format())
                .await
                .unwrap();
        }
        store.sync_db().await.unwrap();
    }

    #[tokio::test]
    async fn real_store_offer_scan_bounds_4095_4096_4097_and_caps_item_errors() {
        for count in [4095_usize, 4096, 4097] {
            let dir = std::env::temp_dir().join(format!(
                "meshmsg-offer-scan-{count}-{}",
                rand::random::<u64>()
            ));
            let options = FsStoreOptions::new(&dir);
            let store: Store = FsStore::load_with_opts(dir.join("blobs.db"), options)
                .await
                .unwrap()
                .into();
            for index in 0..count {
                let malformed = format!("meshmsg/out/v1/A{index:031x}/file/eA");
                store
                    .tags()
                    .set(
                        malformed.as_bytes(),
                        iroh_blobs::HashAndFormat::raw(iroh_blobs::Hash::new(b"missing")),
                    )
                    .await
                    .unwrap();
            }
            store.sync_db().await.unwrap();
            let (listed, truncated, item_errors) = list_pinned_blobs(&store).await.unwrap();
            assert!(listed.is_empty());
            assert!(truncated);
            assert_eq!(item_errors, count.min(MAX_OFFER_LIST_SCANNED));
            drop(store);
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    #[tokio::test]
    async fn incomplete_and_missing_pins_fail_closed_then_restart_accounts_completion() {
        let (root, state, store) = lifecycle_test_store("incomplete-reconcile").await;
        let data = vec![9_u8; 64 * 1024];
        let partial_ranges = bao_tree::ChunkRanges::chunks(0..1);
        let (hash, partial) = encoded_bao(&data, &partial_ranges);
        store
            .blobs()
            .import_bao_bytes(hash, partial_ranges, partial)
            .await
            .unwrap();
        assert!(matches!(
            store.blobs().status(hash).await.unwrap(),
            iroh_blobs::api::proto::BlobStatus::Partial { .. }
        ));
        let partial_tag = outbound_blob_tag(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1",
            AttachmentKind::File,
            "partial",
        );
        store
            .tags()
            .set(partial_tag.as_bytes(), iroh_blobs::HashAndFormat::raw(hash))
            .await
            .unwrap();
        store.sync_db().await.unwrap();
        let (listed, truncated, item_errors) = list_pinned_blobs(&store).await.unwrap();
        assert!(listed.is_empty());
        assert!(truncated);
        assert_eq!(item_errors, 1, "partial blob must be an item error");
        let error = AttachmentStorage::open(
            store.clone(),
            root.join("blobs"),
            &state,
            data.len() as u64,
            0,
            0,
        )
        .await
        .err()
        .expect("partial tagged blob must fail closed");
        assert!(format!("{error:#}").contains("incomplete"));

        let all = bao_tree::ChunkRanges::all();
        let (_, complete) = encoded_bao(&data, &all);
        store
            .blobs()
            .import_bao_bytes(hash, all, complete)
            .await
            .unwrap();
        let storage = AttachmentStorage::open(
            store.clone(),
            root.join("blobs"),
            &state,
            data.len() as u64,
            0,
            0,
        )
        .await
        .unwrap();
        assert_eq!(storage.status().tagged_bytes, data.len() as u64);
        assert!(storage
            .admit_pin(
                "meshmsg/out/v1/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb1/file/eA",
                iroh_blobs::HashAndFormat::raw(iroh_blobs::Hash::new(b"x")),
                1,
            )
            .is_err());
        drop(storage);
        let restarted = AttachmentStorage::open(
            store.clone(),
            root.join("blobs"),
            &state,
            data.len() as u64,
            0,
            0,
        )
        .await
        .unwrap();
        assert_eq!(restarted.status().tagged_bytes, data.len() as u64);
        drop(restarted);

        store.tags().delete(partial_tag.as_bytes()).await.unwrap();
        let missing_hash = iroh_blobs::Hash::new(b"not stored");
        let missing_tag = outbound_blob_tag(
            "ccccccccccccccccccccccccccccccc1",
            AttachmentKind::File,
            "missing",
        );
        store
            .tags()
            .set(
                missing_tag.as_bytes(),
                iroh_blobs::HashAndFormat::raw(missing_hash),
            )
            .await
            .unwrap();
        store.sync_db().await.unwrap();
        let error = AttachmentStorage::open(store.clone(), root.join("blobs"), &state, 100, 0, 0)
            .await
            .err()
            .expect("missing tagged blob must fail closed");
        assert!(format!("{error:#}").contains("missing"));
        drop(store);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn concurrent_partial_completion_is_atomically_charged_without_restart() {
        let (root, state, store) = lifecycle_test_store("concurrent-completion").await;
        let data = vec![7_u8; 96 * 1024];
        let partial_ranges = bao_tree::ChunkRanges::chunks(0..1);
        let (hash, partial) = encoded_bao(&data, &partial_ranges);
        store
            .blobs()
            .import_bao_bytes(hash, partial_ranges, partial)
            .await
            .unwrap();
        let storage = AttachmentStorage::open(
            store.clone(),
            root.join("blobs"),
            &state,
            data.len() as u64,
            0,
            0,
        )
        .await
        .unwrap();
        let tag = outbound_blob_tag(
            "ddddddddddddddddddddddddddddddd1",
            AttachmentKind::File,
            "concurrent",
        );
        let parsed = parse_pinned_blob_tag(tag.as_bytes()).unwrap();
        let hash_and_format = iroh_blobs::HashAndFormat::raw(hash);
        let error = storage
            .commit_pin(
                &tag,
                parsed.clone(),
                hash_and_format,
                data.len() as u64,
                &|_| Ok(()),
            )
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("incomplete"));
        assert_eq!(storage.status().tagged_bytes, 0);
        assert!(storage.state.lock().unwrap().reservations.is_empty());

        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let complete_store = store.clone();
        let complete_data = data.clone();
        let complete_barrier = barrier.clone();
        let completion = tokio::spawn(async move {
            complete_barrier.wait().await;
            let all = bao_tree::ChunkRanges::all();
            let (_, encoded) = encoded_bao(&complete_data, &all);
            complete_store
                .blobs()
                .import_bao_bytes(hash, all, encoded)
                .await
                .unwrap();
        });
        barrier.wait().await;
        completion.await.unwrap();
        let observed_during_commit = std::sync::atomic::AtomicU64::new(0);
        assert!(storage
            .commit_pin(
                &tag,
                parsed,
                hash_and_format,
                data.len() as u64,
                &|boundary| {
                    if boundary == "before_attachment_index_persist" {
                        observed_during_commit
                            .store(storage.status().tagged_bytes, Ordering::SeqCst);
                    }
                    Ok(())
                }
            )
            .await
            .unwrap());
        assert_eq!(
            observed_during_commit.load(Ordering::SeqCst),
            data.len() as u64,
            "cached quota must update atomically before index persistence"
        );
        assert_eq!(storage.status().tagged_bytes, data.len() as u64);
        assert_eq!(storage.status().tagged_blobs, 1);
        assert!(storage
            .admit_pin(
                "meshmsg/out/v1/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeee1/file/eA",
                iroh_blobs::HashAndFormat::raw(iroh_blobs::Hash::new(b"boundary")),
                1,
            )
            .is_err());
        drop(store);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn removal_gc_guard_is_inflight_through_delete_sync_and_gets_full_post_commit_grace() {
        let (root, state, store) = lifecycle_test_store("gc-guard-stalls").await;
        let tag = outbound_blob_tag(
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            AttachmentKind::File,
            "stall",
        );
        pin_test_blob(&store, &root, b"guarded", std::slice::from_ref(&tag)).await;
        let hash_and_format = iroh_blobs::HashAndFormat::raw(iroh_blobs::Hash::new(b"guarded"));
        let storage = AttachmentStorage::open(store.clone(), root.join("blobs"), &state, 100, 0, 0)
            .await
            .unwrap();
        // Force an expiry-boundary replacement. Refresh may remove this expired
        // entry before begin, but begin must atomically install InFlight either way.
        let expired = store.tags().temp_tag(hash_and_format).await.unwrap();
        storage.state.lock().unwrap().gc_protections.insert(
            hash_and_format,
            GcProtection {
                _tag: expired,
                deadline: GcProtectionDeadline::Until(StdInstant::now()),
            },
        );

        let delete_entered = Arc::new(std::sync::Barrier::new(2));
        let delete_release = Arc::new(std::sync::Barrier::new(2));
        let sync_entered = Arc::new(std::sync::Barrier::new(2));
        let sync_release = Arc::new(std::sync::Barrier::new(2));
        let task_storage = storage.clone();
        let task_delete_entered = delete_entered.clone();
        let task_delete_release = delete_release.clone();
        let task_sync_entered = sync_entered.clone();
        let task_sync_release = sync_release.clone();
        let removal = tokio::spawn(async move {
            let fault = move |boundary| {
                if boundary == "attachment_tag_delete" {
                    task_delete_entered.wait();
                    task_delete_release.wait();
                } else if boundary == "attachment_removal_sync" {
                    task_sync_entered.wait();
                    task_sync_release.wait();
                }
                Ok(())
            };
            task_storage
                .remove_with_fault(
                    RemovalSpec {
                        operation_id: TEST_OPERATION_ID,
                        offer_id: Some("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"),
                        direction: None,
                        provider: None,
                        older_than_secs: None,
                        maximum: 1,
                        dry_run: false,
                    },
                    &fault,
                )
                .await
        });

        tokio::task::spawn_blocking(move || delete_entered.wait())
            .await
            .unwrap();
        storage.refresh_free_space().await.unwrap();
        assert!(matches!(
            storage
                .state
                .lock()
                .unwrap()
                .gc_protections
                .get(&hash_and_format)
                .map(|entry| entry.deadline),
            Some(GcProtectionDeadline::InFlight)
        ));
        tokio::task::spawn_blocking(move || delete_release.wait())
            .await
            .unwrap();

        tokio::task::spawn_blocking(move || sync_entered.wait())
            .await
            .unwrap();
        storage.refresh_free_space().await.unwrap();
        assert!(matches!(
            storage
                .state
                .lock()
                .unwrap()
                .gc_protections
                .get(&hash_and_format)
                .map(|entry| entry.deadline),
            Some(GcProtectionDeadline::InFlight)
        ));
        let sync_finished_at = StdInstant::now();
        tokio::task::spawn_blocking(move || sync_release.wait())
            .await
            .unwrap();
        removal.await.unwrap().unwrap();
        let deadline = match storage
            .state
            .lock()
            .unwrap()
            .gc_protections
            .get(&hash_and_format)
            .map(|entry| entry.deadline)
        {
            Some(GcProtectionDeadline::Until(deadline)) => deadline,
            _ => panic!("successful removal did not finalize its GC guard"),
        };
        assert!(deadline >= sync_finished_at + TRANSFER_TIMEOUT);
        drop(store);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn removal_gc_guard_restores_prior_state_when_deletion_never_starts() {
        let (root, state, store) = lifecycle_test_store("gc-guard-rollback").await;
        let tags = [
            outbound_blob_tag(
                "11111111111111111111111111111112",
                AttachmentKind::File,
                "prior",
            ),
            outbound_blob_tag(
                "22222222222222222222222222222223",
                AttachmentKind::File,
                "new",
            ),
        ];
        pin_test_blob(&store, &root, b"prior", std::slice::from_ref(&tags[0])).await;
        pin_test_blob(&store, &root, b"new", std::slice::from_ref(&tags[1])).await;
        let prior_hash = iroh_blobs::HashAndFormat::raw(iroh_blobs::Hash::new(b"prior"));
        let new_hash = iroh_blobs::HashAndFormat::raw(iroh_blobs::Hash::new(b"new"));
        let storage = AttachmentStorage::open(store.clone(), root.join("blobs"), &state, 100, 0, 0)
            .await
            .unwrap();
        let prior_deadline = StdInstant::now() + Duration::from_secs(300);
        let prior_temp = store.tags().temp_tag(prior_hash).await.unwrap();
        storage.state.lock().unwrap().gc_protections.insert(
            prior_hash,
            GcProtection {
                _tag: prior_temp,
                deadline: GcProtectionDeadline::Until(prior_deadline),
            },
        );
        let result = storage
            .remove_with_fault(
                RemovalSpec {
                    operation_id: TEST_OPERATION_ID,
                    offer_id: None,
                    direction: None,
                    provider: None,
                    older_than_secs: None,
                    maximum: 2,
                    dry_run: false,
                },
                &|boundary| {
                    if boundary == "attachment_tag_delete" {
                        anyhow::bail!("stopped before deletion")
                    }
                    Ok(())
                },
            )
            .await
            .unwrap();
        assert!(matches!(result, meshmsg_protocol::Response::Error(_)));
        {
            let state = storage.state.lock().unwrap();
            assert!(matches!(
                state
                    .gc_protections
                    .get(&prior_hash)
                    .map(|entry| entry.deadline),
                Some(GcProtectionDeadline::Until(deadline)) if deadline == prior_deadline
            ));
            assert!(!state.gc_protections.contains_key(&new_hash));
        }
        assert_eq!(storage.status().tags, 2);

        let failed_sync_started = StdInstant::now();
        let result = storage
            .remove_with_fault(
                RemovalSpec {
                    operation_id: TEST_OPERATION_ID,
                    offer_id: None,
                    direction: None,
                    provider: None,
                    older_than_secs: None,
                    maximum: 2,
                    dry_run: false,
                },
                &|boundary| {
                    if boundary == "attachment_removal_sync" {
                        anyhow::bail!("injected sync failure")
                    }
                    Ok(())
                },
            )
            .await
            .unwrap();
        let error = response_error(&result);
        assert_eq!(
            error.code,
            meshmsg_protocol::ErrorCode::AttachmentRemovalPartial
        );
        let state = storage.state.lock().unwrap();
        for value in [prior_hash, new_hash] {
            assert!(matches!(
                state
                    .gc_protections
                    .get(&value)
                    .map(|entry| entry.deadline),
                Some(GcProtectionDeadline::Until(deadline))
                    if deadline >= failed_sync_started + TRANSFER_TIMEOUT
            ));
        }
        drop(state);
        drop(store);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn active_provider_read_survives_concurrent_pin_removal_and_observed_gc() {
        let root =
            std::env::temp_dir().join(format!("meshmsg-active-read-gc-{}", rand::random::<u64>()));
        let state = root.join("state");
        let blob_root = root.join("blobs");
        std::fs::create_dir_all(&state).unwrap();
        let gc_rounds = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let gc_armed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let gc_barrier = Arc::new(tokio::sync::Barrier::new(2));
        let callback_rounds = gc_rounds.clone();
        let callback_armed = gc_armed.clone();
        let callback_barrier = gc_barrier.clone();
        let mut options = FsStoreOptions::new(&blob_root);
        options.gc = Some(GcConfig {
            interval: Duration::from_millis(20),
            add_protected: Some(Arc::new(move |_| {
                let rounds = callback_rounds.clone();
                let armed = callback_armed.clone();
                let barrier = callback_barrier.clone();
                Box::pin(async move {
                    rounds.fetch_add(1, Ordering::SeqCst);
                    if armed.load(Ordering::SeqCst) {
                        barrier.wait().await;
                    }
                    iroh_blobs::store::ProtectOutcome::Continue
                })
            })),
        });
        let store: Store = FsStore::load_with_opts(blob_root.join("blobs.db"), options)
            .await
            .unwrap()
            .into();
        persist_attachment_index(&state, &AttachmentRetentionIndex::default()).unwrap();
        let data = vec![5_u8; 2 * 1024 * 1024];
        let tag = outbound_blob_tag(
            "fffffffffffffffffffffffffffffff1",
            AttachmentKind::File,
            "active",
        );
        pin_test_blob(&store, &root, &data, std::slice::from_ref(&tag)).await;
        let hash = iroh_blobs::Hash::new(&data);
        let storage = AttachmentStorage::open(
            store.clone(),
            blob_root.clone(),
            &state,
            data.len() as u64,
            0,
            0,
        )
        .await
        .unwrap();

        let mut reader = store.blobs().reader(hash);
        let mut prefix = vec![0_u8; 16 * 1024];
        reader.read_exact(&mut prefix).await.unwrap();
        assert_eq!(prefix, data[..prefix.len()]);
        storage
            .remove(
                TEST_OPERATION_ID,
                Some("fffffffffffffffffffffffffffffff1"),
                None,
                None,
                None,
                1,
                false,
            )
            .await
            .unwrap();
        assert_eq!(storage.status().tags, 0);
        assert!(storage
            .state
            .lock()
            .unwrap()
            .gc_protections
            .contains_key(&iroh_blobs::HashAndFormat::raw(hash)));

        gc_armed.store(true, Ordering::SeqCst);
        tokio::time::timeout(Duration::from_secs(5), gc_barrier.wait())
            .await
            .expect("GC did not reach its post-removal protection barrier");
        gc_armed.store(false, Ordering::SeqCst);
        let completed_round = gc_rounds.load(Ordering::SeqCst);
        tokio::time::timeout(Duration::from_secs(5), async {
            while gc_rounds.load(Ordering::SeqCst) <= completed_round {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("GC did not complete the post-removal cycle");
        assert!(matches!(
            store.blobs().status(hash).await.unwrap(),
            iroh_blobs::api::proto::BlobStatus::Complete { .. }
        ));
        let mut suffix = Vec::new();
        reader.read_to_end(&mut suffix).await.unwrap();
        assert_eq!(suffix, data[prefix.len()..]);
        drop(store);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn attachment_storage_deduplicates_quota_and_releases_only_last_reference() {
        let (root, state, store) = lifecycle_test_store("dedup").await;
        let first = outbound_blob_tag(
            "00000000000000000000000000000001",
            AttachmentKind::File,
            "same.bin",
        );
        let second = outbound_blob_tag(
            "00000000000000000000000000000002",
            AttachmentKind::File,
            "same.bin",
        );
        pin_test_blob(&store, &root, b"same bytes", &[first, second]).await;
        let storage = AttachmentStorage::open(store.clone(), root.join("blobs"), &state, 10, 0, 60)
            .await
            .unwrap();
        let status = storage.status();
        assert_eq!(status.tagged_bytes, 10);
        assert_eq!(status.tagged_blobs, 1);
        assert_eq!(status.tags, 2);
        storage
            .admit_pin(
                "meshmsg/out/v1/new/file/bmV3",
                iroh_blobs::HashAndFormat::raw(iroh_blobs::Hash::new(b"same bytes")),
                u64::MAX,
            )
            .unwrap();
        assert!(storage
            .admit_pin(
                "meshmsg/out/v1/other/file/b3RoZXI",
                iroh_blobs::HashAndFormat::raw(iroh_blobs::Hash::new(b"other")),
                1,
            )
            .unwrap_err()
            .to_string()
            .starts_with("attachment_quota_exceeded:"));

        let removed = storage
            .remove(
                TEST_OPERATION_ID,
                Some("00000000000000000000000000000001"),
                None,
                None,
                None,
                512,
                false,
            )
            .await
            .unwrap();
        assert_eq!(lifecycle_result(&removed).removed_tags, 1);
        assert_eq!(lifecycle_result(&removed).released_bytes, 0);
        let removed = storage
            .remove(
                TEST_OPERATION_ID,
                Some("00000000000000000000000000000002"),
                None,
                None,
                None,
                512,
                false,
            )
            .await
            .unwrap();
        assert_eq!(lifecycle_result(&removed).released_bytes, 10);
        assert_eq!(storage.status().tagged_bytes, 0);
        storage
            .admit_pin(
                "meshmsg/out/v1/x/file/eA",
                iroh_blobs::HashAndFormat::raw(iroh_blobs::Hash::new(b"x")),
                10,
            )
            .unwrap();
        drop(store);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn attachment_index_read_is_bounded_versioned_and_permission_safe() {
        let state = std::env::temp_dir().join(format!(
            "meshmsg-attachment-index-test-{}",
            rand::random::<u64>()
        ));
        crate::config::prepare_state_dir(&state).unwrap();
        let path = state.join(ATTACHMENT_INDEX_NAME);
        let missing = load_attachment_index(&state).unwrap_err();
        assert_eq!(
            missing
                .downcast_ref::<crate::persistent::PersistentError>()
                .unwrap()
                .kind(),
            crate::persistent::PersistentErrorKind::Missing
        );

        persist_attachment_index(&state, &AttachmentRetentionIndex::default()).unwrap();
        let mut exact = std::fs::read(&path).unwrap();
        exact.resize(MAX_ATTACHMENT_INDEX_BYTES, b' ');
        std::fs::write(&path, &exact).unwrap();
        assert!(load_attachment_index(&state)
            .unwrap()
            .created_at_ms
            .is_empty());

        std::fs::write(&path, vec![b' '; MAX_ATTACHMENT_INDEX_BYTES + 1]).unwrap();
        assert!(load_attachment_index(&state)
            .unwrap_err()
            .to_string()
            .contains("exceeds its size limit"));
        std::fs::write(&path, b"{\"schema_version\":1").unwrap();
        assert!(load_attachment_index(&state)
            .unwrap_err()
            .to_string()
            .contains("could not parse attachment retention index"));
        std::fs::write(&path, br#"{"schema_version":256,"created_at_ms":{}}"#).unwrap();
        assert!(load_attachment_index(&state)
            .unwrap_err()
            .to_string()
            .contains("unsupported attachment retention index schema version 256"));
        std::fs::write(
            &path,
            format!(
                "{{\"schema_version\":1,\"created_at_ms\":{{\"{}\":1}}}}",
                "x".repeat(MAX_ATTACHMENT_INDEX_TAG_BYTES + 1)
            ),
        )
        .unwrap();
        assert!(load_attachment_index(&state).is_err());

        for (exact, oversized) in [
            (
                r"\u0078".repeat(MAX_ATTACHMENT_INDEX_TAG_BYTES),
                r"\u0078".repeat(MAX_ATTACHMENT_INDEX_TAG_BYTES + 1),
            ),
            (
                r"\\".repeat(MAX_ATTACHMENT_INDEX_TAG_BYTES),
                r"\\".repeat(MAX_ATTACHMENT_INDEX_TAG_BYTES + 1),
            ),
        ] {
            std::fs::write(
                &path,
                format!("{{\"schema_version\":1,\"created_at_ms\":{{\"{exact}\":1}}}}"),
            )
            .unwrap();
            let loaded = load_attachment_index(&state).unwrap();
            assert_eq!(
                loaded.created_at_ms.keys().next().unwrap().len(),
                MAX_ATTACHMENT_INDEX_TAG_BYTES
            );
            std::fs::write(
                &path,
                format!("{{\"schema_version\":1,\"created_at_ms\":{{\"{oversized}\":1}}}}"),
            )
            .unwrap();
            assert!(load_attachment_index(&state).is_err());
        }

        let mut compact = BTreeMap::new();
        for index in 0..MAX_ATTACHMENT_TAGS {
            compact.insert(format!("k{index:04x}"), index as u64);
        }
        let boundary = serde_json::to_vec(&serde_json::json!({
            "schema_version":1,
            "created_at_ms":compact,
        }))
        .unwrap();
        assert!(boundary.len() < MAX_ATTACHMENT_INDEX_BYTES);
        std::fs::write(&path, &boundary).unwrap();
        assert_eq!(
            load_attachment_index(&state).unwrap().created_at_ms.len(),
            MAX_ATTACHMENT_TAGS
        );
        let insertion = boundary.len() - 2;
        let mut amplified = boundary;
        amplified.splice(insertion..insertion, b",\"overflow\":1".iter().copied());
        std::fs::write(&path, amplified).unwrap();
        assert!(load_attachment_index(&state).is_err());

        persist_attachment_index(&state, &AttachmentRetentionIndex::default()).unwrap();
        #[cfg(unix)]
        {
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            std::fs::remove_file(&path).unwrap();
            std::os::unix::fs::symlink(state.join("missing"), &path).unwrap();
            assert!(load_attachment_index(&state).is_err());
        }
        std::fs::remove_dir_all(state).unwrap();
    }

    #[tokio::test]
    async fn attachment_prune_is_oldest_first_bounded_dry_run_and_persistent() {
        let (root, state, store) = lifecycle_test_store("prune").await;
        let tags = (1..=3)
            .map(|id| {
                outbound_blob_tag(
                    &format!("{id:032x}"),
                    AttachmentKind::File,
                    &format!("{id}.bin"),
                )
            })
            .collect::<Vec<_>>();
        for (id, tag) in tags.iter().enumerate() {
            pin_test_blob(&store, &root, &[id as u8], std::slice::from_ref(tag)).await;
        }
        let storage =
            AttachmentStorage::open(store.clone(), root.join("blobs"), &state, 100, 0, 60)
                .await
                .unwrap();
        let now = unix_timestamp_ms().unwrap();
        {
            let mut lifecycle = storage.state.lock().unwrap();
            lifecycle
                .index
                .created_at_ms
                .insert(tags[0].clone(), now - 20_000);
            lifecycle
                .index
                .created_at_ms
                .insert(tags[1].clone(), now - 10_000);
            lifecycle.index.created_at_ms.insert(tags[2].clone(), now);
            persist_attachment_index(&state, &lifecycle.index).unwrap();
        }
        let dry = storage
            .remove(TEST_OPERATION_ID, None, None, None, Some(10), 1, true)
            .await
            .unwrap();
        assert_eq!(lifecycle_result(&dry).selected_tags, 1);
        assert_eq!(lifecycle_result(&dry).removed_tags, 0);
        assert!(lifecycle_result(&dry).limited);
        assert_eq!(storage.status().tags, 3);
        let pruned = storage
            .remove(TEST_OPERATION_ID, None, None, None, Some(10), 2, false)
            .await
            .unwrap();
        assert_eq!(
            lifecycle_result(&pruned).removed_tags,
            2,
            "the exact cutoff is inclusive"
        );
        assert_eq!(storage.status().tags, 1);
        let held = storage.gate.clone().acquire_owned().await.unwrap();
        let busy = storage
            .remove(TEST_OPERATION_ID, None, None, None, Some(0), 1, false)
            .await
            .unwrap_err();
        assert!(busy.to_string().starts_with("attachment_storage_busy:"));
        drop(held);

        drop(storage);
        // Crash recovery reconciles stale metadata against authoritative pins.
        let mut persisted: AttachmentRetentionIndex =
            serde_json::from_slice(&std::fs::read(state.join(ATTACHMENT_INDEX_NAME)).unwrap())
                .unwrap();
        persisted
            .created_at_ms
            .insert("meshmsg/out/v1/stale/file/c3RhbGU".into(), 1);
        persist_attachment_index(&state, &persisted).unwrap();
        let reopened =
            AttachmentStorage::open(store.clone(), root.join("blobs"), &state, 100, 0, 60)
                .await
                .unwrap();
        assert_eq!(reopened.state.lock().unwrap().index.created_at_ms.len(), 1);
        drop(store);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn startup_reconciliation_bounds_reserved_prefix_and_ignores_foreign_tags() {
        let (root, state, store) = lifecycle_test_store("startup-bound").await;
        let imported = store.blobs().add_slice(b"present").await.unwrap();
        let hash = imported.hash;
        for id in 0..=MAX_ATTACHMENT_TAGS {
            let tag = outbound_blob_tag(&format!("{id:032x}"), AttachmentKind::File, "x");
            store
                .tags()
                .set(tag.as_bytes(), iroh_blobs::HashAndFormat::raw(hash))
                .await
                .unwrap();
        }
        for id in 0..100 {
            store
                .tags()
                .set(
                    format!("foreign/{id:04}").as_bytes(),
                    iroh_blobs::HashAndFormat::hash_seq(hash),
                )
                .await
                .unwrap();
        }
        store.sync_db().await.unwrap();
        let error =
            AttachmentStorage::open(store.clone(), root.join("blobs"), &state, u64::MAX, 0, 0)
                .await
                .err()
                .unwrap();
        assert!(error.to_string().contains("tag capacity exceeded"));
        drop(store);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn foreign_tags_are_preserved_and_hash_seq_meshmsg_tags_fail_closed() {
        let (root, state, store) = lifecycle_test_store("foreign-format").await;
        let imported = store.blobs().add_slice(b"foreign").await.unwrap();
        let hash = imported.hash;
        store
            .tags()
            .set(b"foreign/keep", iroh_blobs::HashAndFormat::hash_seq(hash))
            .await
            .unwrap();
        let valid = outbound_blob_tag(
            "11111111111111111111111111111111",
            AttachmentKind::File,
            "x",
        );
        store
            .tags()
            .set(valid.as_bytes(), iroh_blobs::HashAndFormat::raw(hash))
            .await
            .unwrap();
        store.sync_db().await.unwrap();
        let storage = AttachmentStorage::open(store.clone(), root.join("blobs"), &state, 100, 0, 0)
            .await
            .unwrap();
        assert!(storage
            .admit_pin(
                "meshmsg/out/v1/new/file/eA",
                iroh_blobs::HashAndFormat::hash_seq(hash),
                0,
            )
            .unwrap_err()
            .to_string()
            .contains("hash_seq"));
        storage
            .remove(
                TEST_OPERATION_ID,
                Some("11111111111111111111111111111111"),
                None,
                None,
                None,
                1,
                false,
            )
            .await
            .unwrap();
        assert!(store.tags().get(b"foreign/keep").await.unwrap().is_some());
        let unsupported = outbound_blob_tag(
            "22222222222222222222222222222222",
            AttachmentKind::File,
            "x",
        );
        store
            .tags()
            .set(
                unsupported.as_bytes(),
                iroh_blobs::HashAndFormat::hash_seq(hash),
            )
            .await
            .unwrap();
        store.sync_db().await.unwrap();
        let (listed, truncated, item_errors) = list_pinned_blobs(&store).await.unwrap();
        assert!(listed.is_empty());
        assert!(truncated);
        assert_eq!(item_errors, 1);
        drop(storage);
        let error = AttachmentStorage::open(store.clone(), root.join("blobs"), &state, 100, 0, 0)
            .await
            .err()
            .unwrap();
        assert!(error.to_string().contains("unsupported hash_seq"));
        drop(store);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn pin_transaction_faults_rollback_reservations_and_restart_without_phantoms() {
        for boundary in [
            "before_attachment_tag_set",
            "after_attachment_tag_set",
            "after_attachment_tag_sync",
            "before_attachment_index_persist",
            "after_attachment_index_persist",
        ] {
            let (root, state, store) = lifecycle_test_store(boundary).await;
            let storage =
                AttachmentStorage::open(store.clone(), root.join("blobs"), &state, 100, 0, 0)
                    .await
                    .unwrap();
            let imported = store.blobs().add_slice(b"x").await.unwrap();
            let tag_name = outbound_blob_tag(
                "33333333333333333333333333333333",
                AttachmentKind::File,
                "x",
            );
            let parsed = parse_pinned_blob_tag(tag_name.as_bytes()).unwrap();
            let error = storage
                .commit_pin(
                    &tag_name,
                    parsed,
                    imported.hash_and_format(),
                    1,
                    &|current| {
                        if current == boundary {
                            anyhow::bail!("injected {boundary}")
                        } else {
                            Ok(())
                        }
                    },
                )
                .await
                .unwrap_err();
            assert!(error.to_string().contains("injected"));
            assert_eq!(storage.status().tags, 0, "cache phantom at {boundary}");
            assert!(storage.state.lock().unwrap().reservations.is_empty());
            assert!(store
                .tags()
                .get(tag_name.as_bytes())
                .await
                .unwrap()
                .is_none());
            drop(storage);
            let reopened =
                AttachmentStorage::open(store.clone(), root.join("blobs"), &state, 100, 0, 0)
                    .await
                    .unwrap();
            assert_eq!(reopened.status().tags, 0, "restart phantom at {boundary}");
            drop(store);
            let _ = std::fs::remove_dir_all(root);
        }
    }

    #[tokio::test]
    async fn attachment_pin_process_exit_child() {
        let Ok(root) = std::env::var("MESHMSG_ATTACHMENT_PIN_CRASH_ROOT") else {
            return;
        };
        let phase = std::env::var("MESHMSG_ATTACHMENT_PIN_CRASH_PHASE").unwrap();
        let root = PathBuf::from(root);
        let state = root.join("state");
        let blob_root = root.join("blobs");
        std::fs::create_dir_all(&state).unwrap();
        let store: Store =
            FsStore::load_with_opts(blob_root.join("blobs.db"), FsStoreOptions::new(&blob_root))
                .await
                .unwrap()
                .into();
        let storage = AttachmentStorage::open(store.clone(), blob_root, &state, 100, 0, 0)
            .await
            .unwrap();
        let imported = store.blobs().add_slice(b"x").await.unwrap();
        let tag_name = outbound_blob_tag(
            "dddddddddddddddddddddddddddddddd",
            AttachmentKind::File,
            "x",
        );
        let _ = storage
            .commit_pin(
                &tag_name,
                parse_pinned_blob_tag(tag_name.as_bytes()).unwrap(),
                imported.hash_and_format(),
                1,
                &|current| {
                    if current == phase {
                        std::process::exit(87);
                    }
                    Ok(())
                },
            )
            .await;
        panic!("child did not exit at {phase}");
    }

    #[tokio::test]
    async fn crash_boundaries_reconcile_tag_and_index_without_phantom_reservations() {
        for phase in [
            "after_attachment_tag_sync",
            "after_attachment_index_persist",
        ] {
            let root = std::env::temp_dir().join(format!(
                "meshmsg-pin-crash-{phase}-{}",
                rand::random::<u64>()
            ));
            let result = std::process::Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg("node::tests::attachment_pin_process_exit_child")
                .arg("--nocapture")
                .env("MESHMSG_ATTACHMENT_PIN_CRASH_ROOT", &root)
                .env("MESHMSG_ATTACHMENT_PIN_CRASH_PHASE", phase)
                .status()
                .unwrap();
            assert_eq!(result.code(), Some(87));
            let state = root.join("state");
            let blob_root = root.join("blobs");
            let store: Store = FsStore::load_with_opts(
                blob_root.join("blobs.db"),
                FsStoreOptions::new(&blob_root),
            )
            .await
            .unwrap()
            .into();
            let storage = AttachmentStorage::open(store.clone(), blob_root, &state, 100, 0, 0)
                .await
                .unwrap();
            assert_eq!(storage.status().tags, 1);
            {
                let lifecycle = storage.state.lock().unwrap();
                assert_eq!(lifecycle.index.created_at_ms.len(), 1);
                assert!(lifecycle.reservations.is_empty());
            }
            storage
                .remove(
                    TEST_OPERATION_ID,
                    Some("dddddddddddddddddddddddddddddddd"),
                    None,
                    None,
                    None,
                    1,
                    false,
                )
                .await
                .unwrap();
            assert_eq!(storage.status().tags, 0);
            drop(store);
            let _ = std::fs::remove_dir_all(root);
        }
    }

    #[tokio::test]
    async fn rollback_failure_reconciles_authoritative_tag_and_remove_recovers_capacity() {
        let (root, state, store) = lifecycle_test_store("rollback-reconcile").await;
        let storage = AttachmentStorage::open(store.clone(), root.join("blobs"), &state, 1, 0, 0)
            .await
            .unwrap();
        let tag_name = outbound_blob_tag(
            "44444444444444444444444444444444",
            AttachmentKind::File,
            "x",
        );
        let parsed = parse_pinned_blob_tag(tag_name.as_bytes()).unwrap();
        let imported = store.blobs().add_slice(b"x").await.unwrap();
        let error = storage
            .commit_pin(
                &tag_name,
                parsed,
                imported.hash_and_format(),
                1,
                &|current| match current {
                    "after_attachment_tag_set" | "before_attachment_tag_rollback" => {
                        anyhow::bail!("injected rollback fault")
                    }
                    _ => Ok(()),
                },
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("rollback failed"));
        assert_eq!(storage.status().tags, 1, "authoritative tag was hidden");
        assert!(storage.state.lock().unwrap().reservations.is_empty());
        storage
            .remove(
                TEST_OPERATION_ID,
                Some("44444444444444444444444444444444"),
                None,
                None,
                None,
                1,
                false,
            )
            .await
            .unwrap();
        assert_eq!(storage.status().tags, 0);
        drop(store);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn removal_sync_index_and_partial_delete_faults_reconcile_and_restart() {
        for boundary in [
            "attachment_removal_sync",
            "attachment_removal_index_persist",
        ] {
            let (root, state, store) = lifecycle_test_store(boundary).await;
            let tag = outbound_blob_tag(
                "66666666666666666666666666666666",
                AttachmentKind::File,
                "x",
            );
            pin_test_blob(&store, &root, b"x", std::slice::from_ref(&tag)).await;
            let storage =
                AttachmentStorage::open(store.clone(), root.join("blobs"), &state, 100, 0, 0)
                    .await
                    .unwrap();
            let value = storage
                .remove_with_fault(
                    RemovalSpec {
                        operation_id: TEST_OPERATION_ID,
                        offer_id: Some("66666666666666666666666666666666"),
                        direction: None,
                        provider: None,
                        older_than_secs: None,
                        maximum: 1,
                        dry_run: false,
                    },
                    &|current| {
                        if current == boundary {
                            anyhow::bail!("injected {boundary}")
                        } else {
                            Ok(())
                        }
                    },
                )
                .await
                .unwrap();
            let error = response_error(&value);
            assert_eq!(
                error.code,
                meshmsg_protocol::ErrorCode::AttachmentRemovalPartial
            );
            assert_eq!(storage.status().tags, 0);
            drop(storage);
            let reopened =
                AttachmentStorage::open(store.clone(), root.join("blobs"), &state, 100, 0, 0)
                    .await
                    .unwrap();
            assert_eq!(reopened.status().tags, 0);
            drop(store);
            let _ = std::fs::remove_dir_all(root);
        }

        let (root, state, store) = lifecycle_test_store("partial-delete").await;
        let tags = [
            outbound_blob_tag(
                "77777777777777777777777777777777",
                AttachmentKind::File,
                "a",
            ),
            outbound_blob_tag(
                "88888888888888888888888888888888",
                AttachmentKind::File,
                "b",
            ),
        ];
        for tag in &tags {
            pin_test_blob(&store, &root, tag.as_bytes(), std::slice::from_ref(tag)).await;
        }
        let storage =
            AttachmentStorage::open(store.clone(), root.join("blobs"), &state, 1000, 0, 0)
                .await
                .unwrap();
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let value = storage
            .remove_with_fault(
                RemovalSpec {
                    operation_id: TEST_OPERATION_ID,
                    offer_id: None,
                    direction: None,
                    provider: None,
                    older_than_secs: None,
                    maximum: 2,
                    dry_run: false,
                },
                &|current| {
                    if current == "attachment_tag_delete"
                        && calls.fetch_add(1, Ordering::SeqCst) == 0
                    {
                        anyhow::bail!("first delete failed")
                    }
                    Ok(())
                },
            )
            .await
            .unwrap();
        let error = response_error(&value);
        assert_eq!(error.outcome, meshmsg_protocol::Outcome::Partial);
        assert_eq!(storage.status().tags, 1);
        drop(store);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn download_install_failure_rolls_back_new_pin_and_index_reservation() {
        let (root, state, store) = lifecycle_test_store("install-rollback").await;
        let storage = AttachmentStorage::open(store.clone(), root.join("blobs"), &state, 100, 0, 0)
            .await
            .unwrap();
        let tag_name = outbound_blob_tag(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            AttachmentKind::File,
            "x",
        );
        let imported = store.blobs().add_slice(b"x").await.unwrap();
        let hash_and_format = imported.hash_and_format();
        let created = storage
            .commit_pin(
                &tag_name,
                parse_pinned_blob_tag(tag_name.as_bytes()).unwrap(),
                hash_and_format,
                1,
                &|_| Ok(()),
            )
            .await
            .unwrap();
        assert!(created);
        let staging = root.join("staging");
        let output = root.join("existing");
        std::fs::write(&staging, b"x").unwrap();
        std::fs::write(&output, b"keep").unwrap();
        let error = commit_download(
            DownloadCommit {
                store: &store,
                tag_name: tag_name.as_bytes(),
                hash_and_format,
                staging: attachment::StagedFile::new(staging),
                output: &output,
                kind: AttachmentKind::File,
                max_attachment_bytes: DEFAULT_MAX_ATTACHMENT_BYTES,
                pin_already_committed: true,
            },
            &|_| Ok(()),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("already exists"));
        storage
            .rollback_committed_pin(&tag_name, created)
            .await
            .unwrap();
        assert_eq!(storage.status().tags, 0);
        assert!(storage.state.lock().unwrap().reservations.is_empty());
        assert!(store
            .tags()
            .get(tag_name.as_bytes())
            .await
            .unwrap()
            .is_none());
        drop(store);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn lifecycle_timeout_and_shutdown_errors_are_strict_and_retryable() {
        let (sender, receiver) = oneshot::channel::<meshmsg_protocol::Response>();
        let offer_id = "99999999999999999999999999999999".to_owned();
        let timeout_value = lifecycle_command_response(
            async move { Ok(receiver.await?) },
            Duration::from_millis(1),
            None,
            None,
        )
        .await;
        let timeout = response_error(&timeout_value);
        assert_eq!(
            timeout.code,
            meshmsg_protocol::ErrorCode::AttachmentCommandTimeout
        );
        assert_eq!(timeout.outcome, meshmsg_protocol::Outcome::Unknown);
        assert!(timeout.retryable());
        let _ = offer_id;
        drop(sender);

        let shutdown_value = lifecycle_command_response(
            async { anyhow::bail!("closed") },
            Duration::from_secs(1),
            None,
            None,
        )
        .await;
        let shutdown = response_error(&shutdown_value);
        assert_eq!(
            shutdown.code,
            meshmsg_protocol::ErrorCode::AttachmentStorageShutdown
        );
        assert_eq!(shutdown.outcome, meshmsg_protocol::Outcome::Unknown);
    }

    #[tokio::test]
    async fn automatic_retention_is_opt_in_and_removal_failures_are_retryable() {
        let (root, state, store) = lifecycle_test_store("automatic-retention").await;
        let tag = outbound_blob_tag(
            "55555555555555555555555555555555",
            AttachmentKind::File,
            "x",
        );
        pin_test_blob(&store, &root, b"x", std::slice::from_ref(&tag)).await;
        let disabled =
            AttachmentStorage::open(store.clone(), root.join("blobs"), &state, 100, 0, 0)
                .await
                .unwrap();
        assert!(disabled.automatic_retention_pass().await.unwrap().is_none());
        drop(disabled);
        let enabled = AttachmentStorage::open(store.clone(), root.join("blobs"), &state, 100, 0, 1)
            .await
            .unwrap();
        {
            let mut lifecycle = enabled.state.lock().unwrap();
            lifecycle
                .index
                .created_at_ms
                .insert(tag.clone(), unix_timestamp_ms().unwrap() - 2_000);
            persist_attachment_index(&state, &lifecycle.index).unwrap();
        }
        let partial = enabled
            .remove_with_fault(
                RemovalSpec {
                    operation_id: TEST_OPERATION_ID,
                    offer_id: None,
                    direction: None,
                    provider: None,
                    older_than_secs: Some(1),
                    maximum: 1,
                    dry_run: false,
                },
                &|boundary| {
                    if boundary == "attachment_tag_delete" {
                        anyhow::bail!("delete fault")
                    } else {
                        Ok(())
                    }
                },
            )
            .await
            .unwrap();
        let error = response_error(&partial);
        assert_eq!(
            error.code,
            meshmsg_protocol::ErrorCode::AttachmentRemovalPartial
        );
        assert_eq!(error.outcome, meshmsg_protocol::Outcome::Unknown);
        assert_eq!(enabled.status().tags, 1);
        let automatic = enabled.automatic_retention_pass().await.unwrap().unwrap();
        assert_eq!(lifecycle_result(&automatic).removed_tags, 1);
        assert_eq!(enabled.status().tags, 0);
        drop(store);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn cached_attachment_status_is_constant_work_and_responsive() {
        let (root, state, store) = lifecycle_test_store("cached-status").await;
        let storage = AttachmentStorage::open(store.clone(), root.join("blobs"), &state, 2, 0, 0)
            .await
            .unwrap();
        let sampled_at = storage.status().sampled_at_ms;
        let started = StdInstant::now();
        for _ in 0..10_000 {
            assert_eq!(storage.status().sampled_at_ms, sampled_at);
        }
        assert!(started.elapsed() < Duration::from_secs(1));
        drop(store);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn human_offer_warnings_announce_truncation_and_item_errors() {
        assert_eq!(
            offer_listing_warnings(true, 2),
            vec![
                "WARNING: attachment listing truncated; more pinned blobs may exist",
                "WARNING: 2 attachment tag(s) could not be read",
            ]
        );
    }

    #[test]
    fn worst_case_control_body_fits_ipc_event_limit() {
        let secret = SecretKey::generate();
        let timestamp_ms = 1_700_000_000_000;
        let largest_body = (0..=MAX_ENVELOPE_SIZE)
            .rev()
            .find(|length| {
                Envelope::encode_at(
                    &secret,
                    test_topic(),
                    EnvelopeKind::Message,
                    "\0".repeat(*length),
                    timestamp_ms,
                )
                .is_ok()
            })
            .unwrap();
        let envelope =
            unsigned_test_envelope(secret.public(), "\0".repeat(largest_body), timestamp_ms);
        let frame = meshmsg_protocol::EventFrame::new(
            meshmsg_protocol::RequestId::new_random(),
            gossip::message_event(&envelope),
        );
        assert!(
            serde_json::to_vec(&frame).unwrap().len() <= MAX_IPC_EVENT_SIZE,
            "maximum canonical message event exceeds IPC frame"
        );
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

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_subscriber_receives_events_after_write_half_close() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let (commands, _command_rx) = mpsc::channel(1);
        let (events, receiver) = broadcast::channel(1);
        let mut task = tokio::spawn(handle_local_client(
            server,
            commands,
            receiver,
            connected_fixture(),
            None,
        ));
        write_request(&mut client, &IpcRequest::Subscribe)
            .await
            .unwrap();
        client.shutdown().await.unwrap();
        let connected = tokio::time::timeout(
            Duration::from_secs(1),
            read_frame(&mut client, MAX_IPC_EVENT_SIZE),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&connected).unwrap()["type"],
            "connected"
        );
        // Stay quiet across multiple closure polls before publishing an event.
        assert!(tokio::time::timeout(Duration::from_millis(600), &mut task)
            .await
            .is_err());
        events.send(peer_discovered_fixture(1)).unwrap();
        let received = tokio::time::timeout(
            Duration::from_secs(1),
            read_frame(&mut client, MAX_IPC_EVENT_SIZE),
        )
        .await
        .unwrap()
        .unwrap();
        let received: serde_json::Value = serde_json::from_slice(&received).unwrap();
        assert_eq!(received["type"], "peer_discovered");
        assert_eq!(received["peer"]["public_key"], "3".repeat(64));
        assert_eq!(received["protocol_version"], 2);
        assert!(contracts::valid_request_id(
            received["request_id"].as_str().unwrap()
        ));
        drop(client);
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(events.receiver_count(), 0);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_subscriber_exits_when_client_closes_on_a_quiet_topic() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let (commands, _command_rx) = mpsc::channel(1);
        let (events, receiver) = broadcast::channel(1);
        let task = tokio::spawn(handle_local_client(
            server,
            commands,
            receiver,
            connected_fixture(),
            None,
        ));
        write_request(&mut client, &IpcRequest::Subscribe)
            .await
            .unwrap();
        read_frame(&mut client, MAX_IPC_EVENT_SIZE).await.unwrap();
        drop(client);
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(events.receiver_count(), 0);
    }

    #[tokio::test]
    async fn subscriber_gets_connected_then_atomic_startup_snapshot() {
        let (mut client, server) = tokio::io::duplex(MAX_IPC_EVENT_SIZE);
        let (commands, _command_rx) = mpsc::channel(1);
        let (events, receiver) = broadcast::channel(1);
        let startup = meshmsg_protocol::Event::PeersSnapshot(meshmsg_protocol::PeerSnapshot {
            generated_at_ms: 1,
            directory_epoch: "4".repeat(32).parse().unwrap(),
            directory_revision: 1,
            self_peer: meshmsg_protocol::SelfPeer {
                public_key: "2".repeat(64).parse().unwrap(),
                alias: None,
                online: true,
            },
            peers: vec![],
        });
        let task = tokio::spawn(handle_local_client(
            server,
            commands,
            receiver,
            connected_fixture(),
            Some(startup.clone()),
        ));
        write_request(&mut client, &IpcRequest::Subscribe)
            .await
            .unwrap();
        let connected = read_frame(&mut client, MAX_IPC_EVENT_SIZE).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&connected).unwrap()["type"],
            "connected"
        );
        let snapshot = read_frame(&mut client, MAX_IPC_EVENT_SIZE).await.unwrap();
        let snapshot: serde_json::Value = serde_json::from_slice(&snapshot).unwrap();
        assert_eq!(snapshot["type"], "peers_snapshot");
        assert_eq!(snapshot["peers"], serde_json::json!([]));
        assert!(contracts::valid_request_id(
            snapshot["request_id"].as_str().unwrap()
        ));

        drop(events);
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn slow_subscriber_receives_lag_event() {
        let (mut client, server) = tokio::io::duplex(MAX_IPC_EVENT_SIZE);
        let (commands, _command_rx) = mpsc::channel(1);
        let (events, receiver) = broadcast::channel(1);
        events.send(peer_discovered_fixture(1)).unwrap();
        events.send(peer_discovered_fixture(2)).unwrap();
        let task = tokio::spawn(handle_local_client(
            server,
            commands,
            receiver,
            connected_fixture(),
            None,
        ));
        write_request(&mut client, &IpcRequest::Subscribe)
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

    fn short_ipc_timeouts() -> LocalIpcTimeouts {
        LocalIpcTimeouts {
            initial_frame: Duration::from_millis(40),
            response_write: Duration::from_millis(100),
            ordinary_command: Duration::from_millis(40),
            private_command: Duration::from_millis(60),
            list_command: Duration::from_millis(60),
            transfer_command: Duration::from_millis(80),
            rejection_write: Duration::from_millis(20),
        }
    }

    #[cfg(any(unix, windows))]
    #[allow(clippy::too_many_arguments)]
    async fn accept_and_admit_test_client(
        listener: &mut LocalListener,
        dir: &Path,
        limit: &Arc<Semaphore>,
        tasks: &mut tokio::task::JoinSet<()>,
        commands: &mpsc::Sender<DaemonCommand>,
        events: &broadcast::Sender<meshmsg_protocol::Event>,
        preparations: &Arc<std::sync::atomic::AtomicUsize>,
        timeouts: LocalIpcTimeouts,
    ) -> (LocalClientStream, bool) {
        // Named pipes require the server connect future to be polled while the
        // client opens; Unix sockets exercise the same production listener API.
        let (server, client) = tokio::join!(listener.accept(), connect_daemon(dir));
        let admitted = admit_local_client(server.unwrap(), limit, tasks, timeouts, || {
            preparations.fetch_add(1, Ordering::SeqCst);
            Ok(LocalClientSession {
                commands: commands.clone(),
                events: events.subscribe(),
                connected: connected_fixture(),
                startup_peers: None,
            })
        })
        .await
        .unwrap();
        (client.unwrap(), admitted)
    }

    #[cfg(any(unix, windows))]
    #[tokio::test]
    async fn platform_listener_enforces_capacity_skips_saturated_preparation_and_recovers() {
        let dir =
            std::env::temp_dir().join(format!("meshmsg-ipc-capacity-{}", rand::random::<u64>()));
        let state_lock = StateLock::acquire(&dir).unwrap();
        let (mut listener, guard) = bind_local_endpoint(&dir, &state_lock).await.unwrap();
        let limit = Arc::new(Semaphore::new(LOCAL_IPC_CONNECTION_CAPACITY));
        let (commands, mut command_rx) = mpsc::channel(1);
        let (events, _) = broadcast::channel(1);
        let preparations = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut tasks = tokio::task::JoinSet::new();
        let mut timeouts = short_ipc_timeouts();
        timeouts.initial_frame = Duration::from_secs(5);
        let mut clients = Vec::new();

        for _ in 0..LOCAL_IPC_CONNECTION_CAPACITY {
            let (client, admitted) = accept_and_admit_test_client(
                &mut listener,
                &dir,
                &limit,
                &mut tasks,
                &commands,
                &events,
                &preparations,
                timeouts,
            )
            .await;
            assert!(admitted);
            clients.push(client);
        }
        assert_eq!(limit.available_permits(), 0);

        let (mut rejected, admitted) = accept_and_admit_test_client(
            &mut listener,
            &dir,
            &limit,
            &mut tasks,
            &commands,
            &events,
            &preparations,
            timeouts,
        )
        .await;
        assert!(!admitted);
        assert_eq!(
            preparations.load(Ordering::SeqCst),
            LOCAL_IPC_CONNECTION_CAPACITY,
            "saturated client unexpectedly ran per-client preparation"
        );
        let frame = read_frame(&mut rejected, MAX_IPC_EVENT_SIZE).await.unwrap();
        let rejection: meshmsg_protocol::ResponseFrame = serde_json::from_slice(&frame).unwrap();
        assert_eq!(
            rejection.protocol_version,
            meshmsg_protocol::ProtocolVersion
        );
        let meshmsg_protocol::Response::Error(error) = rejection.response else {
            panic!("expected capacity error")
        };
        assert_eq!(error.code, meshmsg_protocol::ErrorCode::IpcCapacity);
        assert_eq!(error.outcome, meshmsg_protocol::Outcome::NotStarted);
        assert!(error.retryable());
        assert!(rejection.request_id.is_none());
        assert_eq!(tasks.len(), LOCAL_IPC_CONNECTION_CAPACITY);

        let operation: meshmsg_protocol::OperationId =
            "11111111111111111111111111111111".parse().unwrap();
        let mutations = vec![
            IpcRequest::Send {
                operation_id: operation.clone(),
                body: meshmsg_protocol::BroadcastBody::new("x").unwrap(),
            },
            IpcRequest::PrivateSend {
                operation_id: operation.clone(),
                to: "2".repeat(64).parse().unwrap(),
                body: meshmsg_protocol::PrivateBody::new("x").unwrap(),
            },
            IpcRequest::Share {
                operation_id: operation.clone(),
                source_digest: "3".repeat(64).parse().unwrap(),
                path: PathBuf::from("x"),
            },
            IpcRequest::OffersRemove {
                operation_id: operation.clone(),
                offer_id: "4".repeat(32).parse().unwrap(),
                direction: None,
                provider: None,
            },
            IpcRequest::OffersPrune {
                operation_id: operation.clone(),
                older_than_secs: 1,
                direction: None,
                dry_run: false,
                max_delete: 1,
            },
            IpcRequest::Download {
                operation_id: operation,
                offer: "x".into(),
                output: PathBuf::from("x"),
                mode: meshmsg_protocol::DownloadMode::Install,
            },
        ];
        for mutation in mutations {
            let (mut client, admitted) = accept_and_admit_test_client(
                &mut listener,
                &dir,
                &limit,
                &mut tasks,
                &commands,
                &events,
                &preparations,
                timeouts,
            )
            .await;
            assert!(!admitted);
            let frame = read_frame(&mut client, MAX_IPC_EVENT_SIZE).await.unwrap();
            let frame: meshmsg_protocol::ResponseFrame = serde_json::from_slice(&frame).unwrap();
            let meshmsg_protocol::Response::Error(transport) = frame.response else {
                panic!("expected transport error")
            };
            crate::ipc::validate_error_for_request(&transport, &mutation).unwrap();
        }

        tokio::time::timeout(Duration::from_secs(7), async {
            while !tasks.is_empty() {
                tasks.join_next().await.unwrap().unwrap();
            }
        })
        .await
        .unwrap();
        assert_eq!(limit.available_permits(), LOCAL_IPC_CONNECTION_CAPACITY);
        let timeout_frame = read_frame(&mut clients[0], MAX_IPC_EVENT_SIZE)
            .await
            .unwrap();
        let timeout_error: meshmsg_protocol::ResponseFrame =
            serde_json::from_slice(&timeout_frame).unwrap();
        let meshmsg_protocol::Response::Error(error) = timeout_error.response else {
            panic!("expected initial-frame timeout error")
        };
        assert_eq!(error.code, meshmsg_protocol::ErrorCode::InitialFrameTimeout);
        assert_eq!(error.outcome, meshmsg_protocol::Outcome::NotStarted);
        assert!(error.retryable());
        assert!(timeout_error.request_id.is_none());

        let (mut recovered, admitted) = accept_and_admit_test_client(
            &mut listener,
            &dir,
            &limit,
            &mut tasks,
            &commands,
            &events,
            &preparations,
            short_ipc_timeouts(),
        )
        .await;
        assert!(admitted);
        assert_eq!(
            preparations.load(Ordering::SeqCst),
            LOCAL_IPC_CONNECTION_CAPACITY + 1
        );
        write_request(&mut recovered, &IpcRequest::Status)
            .await
            .unwrap();
        let DaemonCommand::Status { reply } = command_rx.recv().await.unwrap() else {
            panic!("expected recovered status command")
        };
        reply
            .send(meshmsg_protocol::Response::Stopping {
                outcome: "accepted".into(),
            })
            .unwrap();
        read_frame(&mut recovered, MAX_IPC_EVENT_SIZE)
            .await
            .unwrap();
        tasks.join_next().await.unwrap().unwrap();

        drop(clients);
        drop(rejected);
        drop(recovered);
        drop(listener);
        guard.release_for_test();
        drop(state_lock);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn stop_acknowledges_only_after_command_admission() {
        let (mut client, server) = tokio::io::duplex(1024);
        let (commands, mut command_rx) = mpsc::channel(1);
        let (_events, receiver) = broadcast::channel(1);
        let task = tokio::spawn(handle_local_client_with_timeouts(
            server,
            commands,
            receiver,
            connected_fixture(),
            None,
            short_ipc_timeouts(),
        ));
        write_request(&mut client, &IpcRequest::Stop).await.unwrap();
        assert!(matches!(command_rx.recv().await, Some(DaemonCommand::Stop)));
        let response = read_frame(&mut client, MAX_IPC_EVENT_SIZE).await.unwrap();
        let response: serde_json::Value = serde_json::from_slice(&response).unwrap();
        assert_eq!(response["type"], "stopping");
        assert_eq!(response["outcome"], "accepted");
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn saturated_stop_queue_returns_not_started_without_false_success() {
        let (mut client, server) = tokio::io::duplex(1024);
        let (commands, mut command_rx) = mpsc::channel(1);
        commands.send(DaemonCommand::Stop).await.unwrap();
        let (_events, receiver) = broadcast::channel(1);
        let task = tokio::spawn(handle_local_client_with_timeouts(
            server,
            commands,
            receiver,
            connected_fixture(),
            None,
            short_ipc_timeouts(),
        ));
        write_request(&mut client, &IpcRequest::Stop).await.unwrap();
        let response = read_frame(&mut client, MAX_IPC_EVENT_SIZE).await.unwrap();
        let response: serde_json::Value = serde_json::from_slice(&response).unwrap();
        assert_eq!(response["type"], "error");
        assert_eq!(response["code"], "command_timeout");
        assert_eq!(response["outcome"], "not_started");
        assert!(matches!(command_rx.try_recv(), Ok(DaemonCommand::Stop)));
        assert!(command_rx.try_recv().is_err());
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn closed_stop_channel_returns_not_started_without_false_success() {
        let (mut client, server) = tokio::io::duplex(1024);
        let (commands, command_rx) = mpsc::channel(1);
        drop(command_rx);
        let (_events, receiver) = broadcast::channel(1);
        let task = tokio::spawn(handle_local_client_with_timeouts(
            server,
            commands,
            receiver,
            connected_fixture(),
            None,
            short_ipc_timeouts(),
        ));
        write_request(&mut client, &IpcRequest::Stop).await.unwrap();
        let response = read_frame(&mut client, MAX_IPC_EVENT_SIZE).await.unwrap();
        let response: serde_json::Value = serde_json::from_slice(&response).unwrap();
        assert_eq!(response["type"], "error");
        assert_eq!(response["code"], "daemon_stopping");
        assert_eq!(response["outcome"], "not_started");
        task.await.unwrap().unwrap();
    }

    struct PendingWriter;

    impl AsyncWrite for PendingWriter {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::task::Poll::Pending
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn blocked_capacity_rejection_write_is_bounded() {
        tokio::time::timeout(
            Duration::from_millis(200),
            reject_local_client_at_capacity(PendingWriter, Duration::from_millis(20)),
        )
        .await
        .expect("capacity rejection write did not respect its bound");
    }

    #[tokio::test]
    async fn ordinary_command_deadline_returns_error_and_releases_handler() {
        let (mut client, server) = tokio::io::duplex(1024);
        let (commands, mut command_rx) = mpsc::channel(1);
        let (_events, receiver) = broadcast::channel(1);
        let task = tokio::spawn(handle_local_client_with_timeouts(
            server,
            commands,
            receiver,
            connected_fixture(),
            None,
            short_ipc_timeouts(),
        ));
        write_request(&mut client, &IpcRequest::Status)
            .await
            .unwrap();
        let pending = command_rx.recv().await.unwrap();
        let response = read_frame(&mut client, MAX_IPC_EVENT_SIZE).await.unwrap();
        let response: serde_json::Value = serde_json::from_slice(&response).unwrap();
        assert_eq!(response["code"], "command_timeout");
        assert!(response.get("message").is_none());
        assert!(response.get("retryable").is_none());
        drop(pending);
        task.await.unwrap().unwrap();
    }

    #[cfg(any(unix, windows))]
    #[tokio::test]
    async fn platform_listener_shutdown_drains_and_aborts_handlers() {
        let dir = std::env::temp_dir().join(format!("meshmsg-ipc-drain-{}", rand::random::<u64>()));
        let state_lock = StateLock::acquire(&dir).unwrap();
        let (mut listener, guard) = bind_local_endpoint(&dir, &state_lock).await.unwrap();
        let limit = Arc::new(Semaphore::new(2));
        let (commands, mut command_rx) = mpsc::channel(1);
        let (events, _) = broadcast::channel(1);
        let preparations = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut tasks = tokio::task::JoinSet::new();
        let mut long_timeouts = short_ipc_timeouts();
        long_timeouts.initial_frame = Duration::from_secs(60);

        let (mut subscriber, admitted) = accept_and_admit_test_client(
            &mut listener,
            &dir,
            &limit,
            &mut tasks,
            &commands,
            &events,
            &preparations,
            long_timeouts,
        )
        .await;
        assert!(admitted);
        write_request(&mut subscriber, &IpcRequest::Subscribe)
            .await
            .unwrap();
        read_frame(&mut subscriber, MAX_IPC_EVENT_SIZE)
            .await
            .unwrap();
        let (idle, admitted) = accept_and_admit_test_client(
            &mut listener,
            &dir,
            &limit,
            &mut tasks,
            &commands,
            &events,
            &preparations,
            long_timeouts,
        )
        .await;
        assert!(admitted);

        limit.close();
        command_rx.close();
        drop(events);
        drain_local_client_tasks(&mut tasks, Duration::from_millis(50)).await;
        assert!(tasks.is_empty());
        assert!(limit.clone().try_acquire_owned().is_err());
        assert_eq!(Arc::strong_count(&limit), 1);

        drop(idle);
        drop(subscriber);
        drop(listener);
        guard.release_for_test();
        drop(state_lock);
        std::fs::remove_dir_all(dir).unwrap();
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
