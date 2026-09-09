#[cfg(test)]
use crate::ipc::write_request;
use crate::{
    alias::AliasConfig,
    attachment::{self, AttachmentKind, AttachmentOffer},
    config::{prepare_state_dir, State, StateLock},
    contracts::{self, ErrorEnvelopeV1, API_CONTRACT_CAPABILITY},
    direct::{
        self, DirectHandler, Directory, IncomingDirect, PresenceSourceLimiter, DIRECT_ALPN,
        PRESENCE_ALPN,
    },
    invite::Invite,
    ipc::{
        daemon_error_message, read_frame, send_request_checked, subscribe, subscribe_with_id,
        valid_content_digest, valid_operation_id, validate_success_payload, write_request_with_id,
        write_value, BenchConfig, IpcRequest, IpcRequestFrame, LifecycleErrorV1,
        SubscriptionReader, ATTACHMENT_LIFECYCLE_CAPABILITY, IDEMPOTENT_MUTATIONS_CAPABILITY,
        MAX_IPC_REQUEST_SIZE, PRIVATE_SEND_CAPABILITY, WEB_DOWNLOAD_CAPABILITY,
        WEB_SHARE_CAPABILITY,
    },
    peers::{
        self as peer_api, PeerTransition, MAX_PEER_LIFECYCLE_EVENT_BYTES, PEER_DIRECTORY_CAPABILITY,
    },
};
use anyhow::{Context, Result};
use bytes::Bytes;
use data_encoding::BASE64URL_NOPAD;
use futures_util::{StreamExt, TryStreamExt};
use iroh::{
    address_lookup::memory::MemoryLookup, endpoint::presets, protocol::Router, Endpoint, PublicKey,
    SecretKey, Watcher,
};
use iroh_blobs::{
    api::{
        downloader::{DownloadProgressItem, Downloader},
        Store,
    },
    get::request::get_verified_size,
    store::{
        fs::{options::Options as FsStoreOptions, FsStore},
        GcConfig,
    },
    ticket::BlobTicket,
    BlobFormat, BlobsProtocol,
};
use iroh_gossip::{
    api::{Event, GossipReceiver, GossipSender},
    net::Gossip,
    proto::TopicId,
};
use serde::{Deserialize, Serialize};
use serde_byte_array::ByteArray;
use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    io::{BufRead as _, Read as _},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
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
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::{broadcast, mpsc, oneshot, OwnedSemaphorePermit, Semaphore},
};

#[cfg(test)]
use crate::ipc::MAX_IPC_EVENT_SIZE;

const SIGNATURE_LENGTH: usize = iroh::Signature::LENGTH;
const BROADCAST_ALPN_V2: &[u8] = b"/meshmsg/broadcast-gossip/2";
const ENVELOPE_DOMAIN: &str = "meshmsg-broadcast";
const ENVELOPE_VERSION: u8 = 2;
const ENVELOPE_ACCEPTANCE_WINDOW: Duration = Duration::from_secs(5 * 60);
const ENVELOPE_FUTURE_SKEW: Duration = Duration::from_secs(60);
const REPLAY_BUCKET_WIDTH: Duration = Duration::from_secs(60);
// A bucket may receive an envelope at its last millisecond whose timestamp is
// at the future-skew boundary. Keep that whole bucket for one width beyond the
// five-minute past acceptance window plus the one-minute future allowance.
const REPLAY_BUCKET_RETENTION: Duration = Duration::from_secs(7 * 60);
const PER_SENDER_REPLAY_RATE_PER_SEC: u64 = 100;
const PER_SENDER_REPLAY_BURST: u64 = 200;
const TRANSPORT_SOURCE_RATE_PER_SEC: u64 = 500;
const TRANSPORT_SOURCE_BURST: u64 = 1_000;
const GLOBAL_TRANSPORT_RATE_PER_SEC: u64 = 1_500;
const GLOBAL_TRANSPORT_BURST: u64 = 3_000;
const TRANSPORT_SOURCE_IDLE_LIFETIME: Duration = Duration::from_secs(60);
const MAX_TRANSPORT_SOURCES: usize = 128;
const MAX_REPLAY_SENDERS_PER_SOURCE: usize = 256;
const MAX_REPLAY_SOURCES: usize = 128;
const GLOBAL_REPLAY_RATE_PER_SEC: u64 = 1_000;
const GLOBAL_REPLAY_BURST: u64 = 2_000;
const MAX_REPLAY_SENDERS: usize = 4_096;
const MAX_REPLAY_IDS_PER_SENDER: usize = (PER_SENDER_REPLAY_BURST
    + PER_SENDER_REPLAY_RATE_PER_SEC * REPLAY_BUCKET_RETENTION.as_secs())
    as usize;
const MAX_REPLAY_IDS_PER_SOURCE: usize = (TRANSPORT_SOURCE_BURST
    + TRANSPORT_SOURCE_RATE_PER_SEC * REPLAY_BUCKET_RETENTION.as_secs())
    as usize;
const MAX_ENVELOPE_REPLAY_ENTRIES: usize =
    (GLOBAL_REPLAY_BURST + GLOBAL_REPLAY_RATE_PER_SEC * REPLAY_BUCKET_RETENTION.as_secs()) as usize;
const REJECTION_SAMPLE_INTERVAL: Duration = Duration::from_secs(10);
const _: () = assert!(
    REPLAY_BUCKET_RETENTION.as_secs()
        >= ENVELOPE_ACCEPTANCE_WINDOW.as_secs()
            + ENVELOPE_FUTURE_SKEW.as_secs()
            + REPLAY_BUCKET_WIDTH.as_secs()
);
/// Maximum serialized application envelope accepted for broadcast.
const MAX_ENVELOPE_SIZE: usize = 4096;
/// Iroh's limit includes its own framing, so reserve explicit protocol headroom.
const GOSSIP_PROTOCOL_HEADROOM: usize = 512;
const GOSSIP_MAX_MESSAGE_SIZE: usize = MAX_ENVELOPE_SIZE + GOSSIP_PROTOCOL_HEADROOM;
const MAX_PRESENCE_GOSSIP_MESSAGE_SIZE: usize = 2048 + GOSSIP_PROTOCOL_HEADROOM;
const IPC_EVENT_CAPACITY: usize = 256;
/// Bounds all accepted local IPC connections, including long-lived subscriptions
/// and benchmarks. Connections beyond this limit receive a small rejection and
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
const BENCH_MAGIC: &str = "meshmsg-bench-v1";
const MAX_BENCH_MESSAGES: u64 = 10_000_000;
const MAX_LATENCY_SAMPLES: usize = 1_000_000;
const MAX_PROGRESS_LATENCY_SAMPLES: usize = 4_096;
const MAX_MISSING_SEQUENCE_SAMPLE: usize = 100;
const MAX_LATENCY_MS: u64 = 24 * 60 * 60 * 1000;
const STARTUP_TIMEOUT: Duration = Duration::from_secs(45);
const ENDPOINT_ONLINE_TIMEOUT: Duration = Duration::from_secs(30);
/// Re-issue the gossip join after connectivity loss. `join_peers` only queues a
/// connection attempt, so repeating it also covers attempts made while the
/// network interface is still unavailable.
const REJOIN_INTERVAL: Duration = Duration::from_secs(5);
const PRESENCE_INTERVAL: Duration = Duration::from_secs(30);
const PRESENCE_CLEANUP_INTERVAL: Duration = Duration::from_secs(15);
const DIRECT_CONCURRENCY: usize = 8;
const ATTACHMENT_PREFIX: &str = "meshmsg-attachment-v1:";
const ATTACHMENT_OFFER_VERSION: u8 = 1;
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(60 * 60);
const BLOB_GC_INTERVAL: Duration = Duration::from_secs(60 * 60);
const ATTACHMENT_RETENTION_CHECK_INTERVAL: Duration = Duration::from_secs(60 * 60);
const ATTACHMENT_SPACE_REFRESH_INTERVAL: Duration = Duration::from_secs(30);
const MAX_ATTACHMENT_TAG_SCAN: usize = MAX_ATTACHMENT_TAGS * 2 + 1;
pub(crate) const DEFAULT_MAX_ATTACHMENT_STORAGE_BYTES: u64 = 16 * 1024 * 1024 * 1024;
pub(crate) const DEFAULT_MIN_FREE_SPACE_BYTES: u64 = 1024 * 1024 * 1024;
pub(crate) const DEFAULT_ATTACHMENT_RETENTION_SECS: u64 = 0;
const MAX_PRUNE_TAGS: usize = 512;
const MAX_ATTACHMENT_TAGS: usize = 8_192;
const MAX_ATTACHMENT_INDEX_BYTES: usize = 8 * 1024 * 1024;
const ATTACHMENT_INDEX_NAME: &str = "attachment-retention-v1.json";
const DOWNLOAD_PROGRESS_STEP: u64 = 8 * 1024 * 1024;
const MAX_OFFER_LIST_ENTRIES: usize = 512;
/// Also bound malformed tags and per-item store errors encountered while looking ahead.
const MAX_OFFER_LIST_SCANNED: usize = 4096;
const MAX_ENCODED_TAG_NAME_BYTES: usize = 134;
const MAX_ENCODED_PUBLIC_KEY_BYTES: usize = 64;
const BLOB_TAG_PREFIX: &[u8] = b"meshmsg/";
const OUTBOUND_BLOB_TAG_PREFIX: &str = "meshmsg/out/v1/";
const INBOUND_BLOB_TAG_PREFIX: &str = "meshmsg/in/v1/";
#[cfg(unix)]
const SOCKET_NAME: &str = "daemon.sock";
type Signature = ByteArray<SIGNATURE_LENGTH>;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum EnvelopeKind {
    Message,
    AttachmentOffer,
}

#[derive(Debug, Serialize, Deserialize)]
struct LegacyEnvelopeV1 {
    from: PublicKey,
    timestamp_ms: u64,
    body: String,
    signature: Signature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    domain: String,
    version: u8,
    topic: TopicId,
    from: PublicKey,
    message_id: [u8; 16],
    timestamp_ms: u64,
    kind: EnvelopeKind,
    body: String,
    signature: Signature,
}

#[derive(Debug, Serialize)]
struct EnvelopeSignaturePayload<'a> {
    domain: &'a str,
    version: u8,
    topic: TopicId,
    from: PublicKey,
    message_id: [u8; 16],
    timestamp_ms: u64,
    kind: EnvelopeKind,
    body: &'a str,
}

type EnvelopeReplayKey = (PublicKey, [u8; 16]);

struct ReplayBucket {
    started_at_ms: u64,
    expires_at_ms: u64,
    entries: HashSet<EnvelopeReplayKey>,
}

#[derive(Clone)]
struct TokenBucket {
    milli_tokens: u64,
    burst: u64,
    rate_per_sec: u64,
    last_refill_ms: u64,
}

impl TokenBucket {
    fn new(rate_per_sec: u64, burst: u64, now_ms: u64) -> Self {
        Self {
            milli_tokens: burst.saturating_mul(1_000),
            burst,
            rate_per_sec,
            last_refill_ms: now_ms,
        }
    }

    fn refill(&mut self, now_ms: u64) {
        let elapsed_ms = now_ms.saturating_sub(self.last_refill_ms);
        self.milli_tokens = self
            .milli_tokens
            .saturating_add(elapsed_ms.saturating_mul(self.rate_per_sec))
            .min(self.burst.saturating_mul(1_000));
        self.last_refill_ms = self.last_refill_ms.max(now_ms);
    }

    fn available(&self) -> bool {
        self.milli_tokens >= 1_000
    }

    fn consume(&mut self) {
        self.milli_tokens -= 1_000;
    }
}

struct TransportSourceState {
    limiter: TokenBucket,
    last_seen_ms: u64,
}

struct TransportSourceLimiter {
    sources: HashMap<PublicKey, TransportSourceState>,
    global: TokenBucket,
}

impl Default for TransportSourceLimiter {
    fn default() -> Self {
        Self {
            sources: HashMap::new(),
            global: TokenBucket::new(GLOBAL_TRANSPORT_RATE_PER_SEC, GLOBAL_TRANSPORT_BURST, 0),
        }
    }
}

impl TransportSourceLimiter {
    fn allow(&mut self, source: PublicKey, now_ms: u64) -> bool {
        let idle_ms = TRANSPORT_SOURCE_IDLE_LIFETIME.as_millis() as u64;
        self.sources
            .retain(|_, state| state.last_seen_ms.saturating_add(idle_ms) > now_ms);
        self.global.refill(now_ms);
        if !self.global.available() {
            return false;
        }
        if !self.sources.contains_key(&source) {
            if self.sources.len() >= MAX_TRANSPORT_SOURCES {
                return false;
            }
            self.sources.insert(
                source,
                TransportSourceState {
                    limiter: TokenBucket::new(
                        TRANSPORT_SOURCE_RATE_PER_SEC,
                        TRANSPORT_SOURCE_BURST,
                        now_ms,
                    ),
                    last_seen_ms: now_ms,
                },
            );
        }
        let state = self.sources.get_mut(&source).expect("source was inserted");
        state.limiter.refill(now_ms);
        if !state.limiter.available() {
            return false;
        }
        self.global.consume();
        state.limiter.consume();
        state.last_seen_ms = now_ms;
        true
    }
}

#[derive(Default)]
struct RejectionSampler {
    last_emitted_ms: Option<u64>,
    suppressed: u64,
}

impl RejectionSampler {
    fn event(&mut self, now_ms: u64, message: &str) -> Option<serde_json::Value> {
        let interval_ms = REJECTION_SAMPLE_INTERVAL.as_millis() as u64;
        if self
            .last_emitted_ms
            .is_none_or(|last| now_ms.saturating_sub(last) >= interval_ms)
        {
            let suppressed = std::mem::take(&mut self.suppressed);
            self.last_emitted_ms = Some(now_ms);
            return Some(serde_json::json!({
                "type":"error", "code":"invalid_message", "message":message,
                "rate_limited":true, "suppressed_since_last":suppressed
            }));
        }
        self.suppressed = self.suppressed.saturating_add(1);
        None
    }
}

struct SenderReplayState {
    limiter: TokenBucket,
    live_ids: usize,
    last_seen_ms: u64,
}

struct SourceReplayState {
    live_ids: usize,
    senders: HashMap<PublicKey, usize>,
}

struct EnvelopeReplayCache {
    buckets: VecDeque<ReplayBucket>,
    senders: HashMap<PublicKey, SenderReplayState>,
    sources: HashMap<PublicKey, SourceReplayState>,
    ownership: HashMap<EnvelopeReplayKey, PublicKey>,
    global_limiter: TokenBucket,
    live_ids: usize,
    max_live_ids: usize,
}

impl Default for EnvelopeReplayCache {
    fn default() -> Self {
        Self {
            buckets: VecDeque::new(),
            senders: HashMap::new(),
            sources: HashMap::new(),
            ownership: HashMap::new(),
            global_limiter: TokenBucket::new(GLOBAL_REPLAY_RATE_PER_SEC, GLOBAL_REPLAY_BURST, 0),
            live_ids: 0,
            max_live_ids: MAX_ENVELOPE_REPLAY_ENTRIES,
        }
    }
}

impl EnvelopeReplayCache {
    fn rotate(&mut self, now_ms: u64) {
        while self
            .buckets
            .front()
            .is_some_and(|bucket| bucket.expires_at_ms <= now_ms)
        {
            let expired = self.buckets.pop_front().expect("front exists");
            self.live_ids -= expired.entries.len();
            for key @ (sender, _) in expired.entries {
                if let Some(state) = self.senders.get_mut(&sender) {
                    state.live_ids -= 1;
                }
                if let Some(source) = self.ownership.remove(&key) {
                    if let Some(state) = self.sources.get_mut(&source) {
                        state.live_ids -= 1;
                        if let Some(count) = state.senders.get_mut(&sender) {
                            *count -= 1;
                            if *count == 0 {
                                state.senders.remove(&sender);
                            }
                        }
                    }
                }
            }
        }
        let retention_ms = REPLAY_BUCKET_RETENTION.as_millis() as u64;
        self.senders.retain(|_, state| {
            state.live_ids != 0 || state.last_seen_ms.saturating_add(retention_ms) > now_ms
        });
        self.sources.retain(|_, state| state.live_ids != 0);
    }

    fn contains(&self, key: &EnvelopeReplayKey) -> bool {
        self.buckets
            .iter()
            .any(|bucket| bucket.entries.contains(key))
    }

    fn accept(&mut self, envelope: &Envelope, source: PublicKey, now_ms: u64) -> Result<()> {
        self.rotate(now_ms);
        let oldest = now_ms.saturating_sub(ENVELOPE_ACCEPTANCE_WINDOW.as_millis() as u64);
        let newest = now_ms.saturating_add(ENVELOPE_FUTURE_SKEW.as_millis() as u64);
        anyhow::ensure!(
            (oldest..=newest).contains(&envelope.timestamp_ms),
            "message timestamp is outside the acceptance window"
        );
        let key = (envelope.from, envelope.message_id);
        anyhow::ensure!(!self.contains(&key), "replayed message");

        self.global_limiter.refill(now_ms);
        anyhow::ensure!(
            self.global_limiter.available(),
            "global message rate limit exceeded"
        );
        anyhow::ensure!(
            self.live_ids < self.max_live_ids,
            "global replay capacity reached"
        );
        if !self.sources.contains_key(&source) {
            anyhow::ensure!(
                self.sources.len() < MAX_REPLAY_SOURCES,
                "replay source capacity reached"
            );
            self.sources.insert(
                source,
                SourceReplayState {
                    live_ids: 0,
                    senders: HashMap::new(),
                },
            );
        }
        let source_state = self.sources.get(&source).expect("source was inserted");
        anyhow::ensure!(
            source_state.live_ids < MAX_REPLAY_IDS_PER_SOURCE,
            "transport source replay quota reached"
        );
        anyhow::ensure!(
            source_state.senders.contains_key(&envelope.from)
                || source_state.senders.len() < MAX_REPLAY_SENDERS_PER_SOURCE,
            "transport source sender quota reached"
        );
        if !self.senders.contains_key(&envelope.from) {
            anyhow::ensure!(
                self.senders.len() < MAX_REPLAY_SENDERS,
                "replay sender capacity reached"
            );
            self.senders.insert(
                envelope.from,
                SenderReplayState {
                    limiter: TokenBucket::new(
                        PER_SENDER_REPLAY_RATE_PER_SEC,
                        PER_SENDER_REPLAY_BURST,
                        now_ms,
                    ),
                    live_ids: 0,
                    last_seen_ms: now_ms,
                },
            );
        }
        let sender = self
            .senders
            .get_mut(&envelope.from)
            .expect("sender was inserted");
        sender.limiter.refill(now_ms);
        anyhow::ensure!(
            sender.limiter.available(),
            "sender message rate limit exceeded"
        );
        anyhow::ensure!(
            sender.live_ids < MAX_REPLAY_IDS_PER_SENDER,
            "sender replay quota reached"
        );

        self.global_limiter.consume();
        sender.limiter.consume();
        sender.live_ids += 1;
        sender.last_seen_ms = now_ms;
        let source_state = self.sources.get_mut(&source).expect("source was inserted");
        source_state.live_ids += 1;
        *source_state.senders.entry(envelope.from).or_default() += 1;
        self.ownership.insert(key, source);
        self.live_ids += 1;

        let width_ms = REPLAY_BUCKET_WIDTH.as_millis() as u64;
        let started_at_ms = now_ms - now_ms % width_ms;
        let expires_at_ms =
            started_at_ms.saturating_add(REPLAY_BUCKET_RETENTION.as_millis() as u64);
        if self
            .buckets
            .back()
            .is_none_or(|bucket| bucket.started_at_ms != started_at_ms)
        {
            self.buckets.push_back(ReplayBucket {
                started_at_ms,
                expires_at_ms,
                entries: HashSet::new(),
            });
        }
        self.buckets
            .back_mut()
            .expect("current replay bucket exists")
            .entries
            .insert(key);
        Ok(())
    }
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
    Envelope::encode_at(
        &SecretKey::generate(),
        TopicId::from_bytes([0; 32]),
        EnvelopeKind::Message,
        body,
        9_999_999_999_999,
    )
    .context("payload does not fit the signed application envelope")?;
    Ok(total)
}

pub(crate) fn validate_bench_sender_config(
    run_id: &str,
    rate: u32,
    duration_secs: u64,
    payload_bytes: usize,
) -> Result<u64> {
    validate_bench_config(&BenchConfig {
        run_id: run_id.to_owned(),
        rate,
        duration_secs,
        payload_bytes,
    })
}

#[derive(Debug, Serialize, Deserialize)]
struct AttachmentWire {
    version: u8,
    offer: AttachmentOffer,
}

impl Envelope {
    fn encode_at(
        secret: &SecretKey,
        topic: TopicId,
        kind: EnvelopeKind,
        body: String,
        timestamp_ms: u64,
    ) -> Result<Bytes> {
        Self::encode_with_id_at(secret, topic, kind, body, rand::random(), timestamp_ms)
    }

    fn encode_with_id_at(
        secret: &SecretKey,
        topic: TopicId,
        kind: EnvelopeKind,
        body: String,
        message_id: [u8; 16],
        timestamp_ms: u64,
    ) -> Result<Bytes> {
        let payload = EnvelopeSignaturePayload {
            domain: ENVELOPE_DOMAIN,
            version: ENVELOPE_VERSION,
            topic,
            from: secret.public(),
            message_id,
            timestamp_ms,
            kind,
            body: &body,
        };
        let signed = postcard::to_stdvec(&payload)?;
        let value = Self {
            domain: ENVELOPE_DOMAIN.to_owned(),
            version: ENVELOPE_VERSION,
            topic,
            from: secret.public(),
            message_id,
            timestamp_ms,
            kind,
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

    fn decode(data: &[u8], expected_topic: TopicId) -> Result<Self> {
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
        anyhow::ensure!(value.domain == ENVELOPE_DOMAIN, "invalid message domain");
        anyhow::ensure!(
            value.version == ENVELOPE_VERSION,
            "unsupported message version"
        );
        anyhow::ensure!(
            value.topic == expected_topic,
            "message belongs to another topic"
        );
        let signed = postcard::to_stdvec(&EnvelopeSignaturePayload {
            domain: &value.domain,
            version: value.version,
            topic: value.topic,
            from: value.from,
            message_id: value.message_id,
            timestamp_ms: value.timestamp_ms,
            kind: value.kind,
            body: &value.body,
        })?;
        value
            .from
            .verify(&signed, &iroh::Signature::from_bytes(&value.signature))
            .context("verify message")?;
        Ok(value)
    }
}

fn attachment_body(offer: &AttachmentOffer) -> Result<String> {
    let encoded = postcard::to_stdvec(&AttachmentWire {
        version: ATTACHMENT_OFFER_VERSION,
        offer: offer.clone(),
    })?;
    Ok(format!(
        "{ATTACHMENT_PREFIX}{}",
        BASE64URL_NOPAD.encode(&encoded)
    ))
}

fn parse_attachment_body(body: &str) -> Result<Option<AttachmentOffer>> {
    let Some(encoded) = body.strip_prefix(ATTACHMENT_PREFIX) else {
        return Ok(None);
    };
    let bytes = BASE64URL_NOPAD
        .decode(encoded.as_bytes())
        .context("decode attachment offer")?;
    let (wire, remainder): (AttachmentWire, &[u8]) =
        postcard::take_from_bytes(&bytes).context("parse attachment offer")?;
    anyhow::ensure!(
        remainder.is_empty(),
        "attachment offer contains trailing bytes"
    );
    anyhow::ensure!(
        wire.version == ATTACHMENT_OFFER_VERSION,
        "unsupported attachment offer version"
    );
    attachment::validate_display_name(&wire.offer.name)?;
    anyhow::ensure!(
        wire.offer.offer_id.len() == 32
            && wire
                .offer
                .offer_id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit()),
        "invalid attachment offer ID"
    );
    let ticket: BlobTicket = wire
        .offer
        .ticket
        .parse()
        .context("parse attachment ticket")?;
    anyhow::ensure!(
        ticket.format() == BlobFormat::Raw,
        "unsupported attachment blob format"
    );
    Ok(Some(wire.offer))
}

fn decode_legacy_envelope_v1(data: &[u8]) -> Result<LegacyEnvelopeV1> {
    anyhow::ensure!(
        data.len() <= MAX_ENVELOPE_SIZE,
        "legacy envelope is too large"
    );
    let (value, remainder): (LegacyEnvelopeV1, &[u8]) =
        postcard::take_from_bytes(data).context("decode legacy message")?;
    anyhow::ensure!(
        remainder.is_empty(),
        "legacy message contains trailing bytes"
    );
    let signed = postcard::to_stdvec(&(value.from, value.timestamp_ms, &value.body))?;
    value
        .from
        .verify(&signed, &iroh::Signature::from_bytes(&value.signature))
        .context("verify legacy message")?;
    Ok(value)
}

fn parse_signed_offer_token(
    token: &str,
    expected_topic: TopicId,
) -> Result<(AttachmentOffer, BlobTicket)> {
    let bytes = BASE64URL_NOPAD
        .decode(token.as_bytes())
        .context("decode signed attachment offer")?;
    let envelope = match Envelope::decode(&bytes, expected_topic) {
        Ok(envelope) => envelope,
        Err(v2_error) => {
            if decode_legacy_envelope_v1(&bytes).is_ok() {
                anyhow::bail!(
                    "legacy signed attachment offers are not accepted because they are not topic-bound; ask the sender to share the attachment again"
                );
            }
            return Err(v2_error);
        }
    };
    anyhow::ensure!(
        envelope.kind == EnvelopeKind::AttachmentOffer,
        "token is not an attachment offer"
    );
    let offer =
        parse_attachment_body(&envelope.body)?.context("token is not an attachment offer")?;
    let ticket: BlobTicket = offer.ticket.parse().context("parse attachment ticket")?;
    anyhow::ensure!(
        ticket.addr().id == envelope.from,
        "attachment provider does not match its signature"
    );
    Ok((offer, ticket))
}

fn offer_event(envelope: Envelope, encoded: &[u8], offer: AttachmentOffer) -> serde_json::Value {
    serde_json::json!({
        "type":"attachment_offer", "schema_version":2,
        "from":envelope.from.to_string(),
        "message_id":direct::id_string(&envelope.message_id),
        "timestamp_ms":envelope.timestamp_ms,
        "offer_id":offer.offer_id, "kind":offer.kind,
        "name":offer.name, "size":offer.size, "ticket":offer.ticket,
        "offer":BASE64URL_NOPAD.encode(encoded)
    })
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
}

async fn start(
    state: &State,
    secret: SecretKey,
    state_dir: &Path,
    direct_incoming: mpsc::Sender<IncomingDirect>,
) -> Result<RunningNode> {
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
        .alpn(BROADCAST_ALPN_V2)
        .max_message_size(GOSSIP_MAX_MESSAGE_SIZE)
        .spawn(endpoint.clone());
    // Isolate control-plane membership from the long-standing broadcast Gossip
    // actor. Sharing one actor/connection pool across both topics can perturb
    // broadcast neighbor liveness during failover and rejoin.
    let presence_gossip = Gossip::builder()
        .alpn(PRESENCE_ALPN)
        .max_message_size(MAX_PRESENCE_GOSSIP_MESSAGE_SIZE)
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
    let (direct, direct_replay) =
        DirectHandler::new(secret.clone(), topic, direct_incoming, state_dir)
            .context("open persistent direct replay state")?;
    let router = Router::builder(endpoint.clone())
        .accept(BROADCAST_ALPN_V2, gossip.clone())
        .accept(PRESENCE_ALPN, presence_gossip.clone())
        .accept(iroh_blobs::ALPN, blobs)
        .accept(DIRECT_ALPN, direct)
        .spawn();
    let mut bootstrap = Vec::new();
    let mut bootstrap_addrs = Vec::new();
    if let Some(token) = &state.invite {
        let invite: Invite = token.parse()?;
        for peer in invite.bootstrap_peers {
            if peer.id != endpoint.id() {
                direct::validate_endpoint_addr(&peer, peer.id)
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
            .subscribe(direct::presence_topic(topic), vec![])
            .await?
    } else {
        presence_gossip
            .subscribe_and_join(direct::presence_topic(topic), bootstrap.clone())
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
    })
}

const OPERATION_CACHE_CAPACITY: usize = 1_024;
const OPERATION_CACHE_TTL: Duration = Duration::from_secs(10 * 60);

struct CompletedOperation {
    fingerprint: [u8; 32],
    response: serde_json::Value,
    expires_at: StdInstant,
}

struct InFlightOperation {
    fingerprint: [u8; 32],
    waiters: Vec<oneshot::Sender<serde_json::Value>>,
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

    fn error(operation_id: &str, code: &str, message: &str) -> serde_json::Value {
        serde_json::json!({
            "type":"error", "schema_version":1, "code":code,
            "message":message, "operation_id":operation_id,
            "retryable":false, "outcome":"not_started"
        })
    }

    /// Returns true only for the first caller that must execute the operation.
    fn admit(
        &mut self,
        operation_id: String,
        fingerprint: [u8; 32],
        reply: oneshot::Sender<serde_json::Value>,
        now: StdInstant,
    ) -> bool {
        self.prune(now);
        if let Some(entry) = self.completed.get(&operation_id) {
            let response = if entry.fingerprint == fingerprint {
                entry.response.clone()
            } else {
                Self::error(
                    &operation_id,
                    "operation_id_conflict",
                    "operation ID was already used with different inputs",
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
                    "operation_id_conflict",
                    "operation ID is in flight with different inputs",
                ));
            }
            return false;
        }
        while self.completed.len() + self.in_flight.len() >= self.capacity {
            let Some(oldest) = self.order.pop_front() else {
                let _ = reply.send(Self::error(
                    &operation_id,
                    "operation_capacity",
                    "retry cache is full of in-flight operations",
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
            },
        );
        true
    }

    fn complete(
        &mut self,
        operation_id: &str,
        mut response: serde_json::Value,
        now: StdInstant,
    ) -> serde_json::Value {
        let Some(in_flight) = self.in_flight.remove(operation_id) else {
            return response;
        };
        if let Some(object) = response.as_object_mut() {
            object.insert("operation_id".into(), operation_id.into());
        }
        for waiter in in_flight.waiters {
            let _ = waiter.send(response.clone());
        }
        self.completed.insert(
            operation_id.to_owned(),
            CompletedOperation {
                fingerprint: in_flight.fingerprint,
                response,
                expires_at: now + self.ttl,
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

enum DaemonCommand {
    Send {
        operation_id: String,
        body: String,
        reply: oneshot::Sender<serde_json::Value>,
    },
    PrivateSend {
        operation_id: String,
        to: String,
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
    Peers {
        reply: oneshot::Sender<serde_json::Value>,
    },
    Offers {
        reply: oneshot::Sender<serde_json::Value>,
    },
    OffersRemove {
        offer_id: String,
        direction: Option<String>,
        provider: Option<String>,
        reply: oneshot::Sender<serde_json::Value>,
    },
    OffersPrune {
        older_than_secs: Option<u64>,
        direction: Option<String>,
        dry_run: bool,
        max_delete: usize,
        reply: oneshot::Sender<serde_json::Value>,
    },
    Share {
        operation_id: String,
        source_digest: String,
        path: PathBuf,
        reply: oneshot::Sender<serde_json::Value>,
    },
    Download {
        offer: String,
        output: PathBuf,
        raw_export: bool,
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

fn bench_send_progress(
    config: &BenchConfig,
    total: u64,
    stats: &BenchSendStats,
    elapsed: Duration,
) -> serde_json::Value {
    let elapsed_ms = elapsed.as_millis() as u64;
    let elapsed_seconds = elapsed_ms.max(1) as f64 / 1000.0;
    serde_json::json!({
        "type":"bench_send_progress", "schema_version":1,
        "run_id":config.run_id, "rate":config.rate,
        "duration_secs":config.duration_secs, "payload_bytes":config.payload_bytes,
        "planned":total, "attempted":stats.attempted, "queued":stats.queued,
        "failed":stats.failed, "schedule_missed":stats.schedule_missed,
        "queued_body_bytes":stats.body_bytes, "queued_envelope_bytes":stats.envelope_bytes,
        "elapsed_ms":elapsed_ms,
        "achieved_messages_per_second":stats.queued as f64 / elapsed_seconds,
        "achieved_body_bytes_per_second":stats.body_bytes as f64 / elapsed_seconds,
        "delivery_acknowledged":false
    })
}

fn bench_send_summary(
    config: &BenchConfig,
    total: u64,
    stats: &BenchSendStats,
    reason: &str,
    elapsed: Duration,
) -> serde_json::Value {
    let mut value = bench_send_progress(config, total, stats, elapsed);
    let object = value
        .as_object_mut()
        .expect("benchmark progress is an object");
    object.insert("type".into(), "bench_send_summary".into());
    object.insert("completion_reason".into(), reason.into());
    object.insert("first_error".into(), stats.first_error.clone().into());
    value
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
            return write_local_response(
                stream,
                &serde_json::json!({"type":"error", "code":"invalid_benchmark", "message":error.to_string()}),
                LOCAL_IPC_RESPONSE_WRITE_TIMEOUT,
            )
            .await;
        }
    };
    if benchmark_busy
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return write_local_response(
            stream,
            &serde_json::json!({"type":"error", "code":"benchmark_busy", "message":"another send benchmark is already active"}),
            LOCAL_IPC_RESPONSE_WRITE_TIMEOUT,
        )
        .await;
    }
    let _lease = BenchmarkLease(benchmark_busy);
    write_local_response(
        stream,
        &serde_json::json!({
            "type":"bench_send_started", "schema_version":1,
            "run_id":config.run_id, "rate":config.rate,
            "duration_secs":config.duration_secs, "payload_bytes":config.payload_bytes,
            "planned":total, "delivery_acknowledged":false
        }),
        LOCAL_IPC_RESPONSE_WRITE_TIMEOUT,
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
    let progress_period = Duration::from_millis(250);
    let mut next_progress = progress_period;

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
                eprintln!("benchmark send diagnostic: {error}");
                stats.failed += 1;
                stats.first_error = Some("Message submission failed.".into());
                reason = "send_failed";
                break 'benchmark;
            }
            Some(Err(_)) => {
                reason = "daemon_stopped";
                break 'benchmark;
            }
            None => break 'benchmark,
        }
        let elapsed = started.elapsed();
        if elapsed >= next_progress {
            while next_progress <= elapsed {
                next_progress += progress_period;
            }
            write_local_response(
                stream,
                &bench_send_progress(&config, total, &stats, elapsed),
                LOCAL_IPC_RESPONSE_WRITE_TIMEOUT,
            )
            .await?;
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
    write_local_response(stream, &summary, LOCAL_IPC_RESPONSE_WRITE_TIMEOUT).await
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

tokio::task_local! {
    static IPC_REQUEST_ID: std::cell::RefCell<Option<String>>;
}

fn normalize_ipc_response(value: &serde_json::Value, request_id: &str) -> serde_json::Value {
    if value.get("type").and_then(serde_json::Value::as_str) == Some("error") {
        let code = value
            .get("code")
            .and_then(serde_json::Value::as_str)
            .filter(|code| contracts::known_error_code(code))
            .unwrap_or("internal_contract_error");
        let outcome = value
            .get("outcome")
            .and_then(serde_json::Value::as_str)
            .filter(|outcome| matches!(*outcome, "not_started" | "unknown" | "partial"))
            .unwrap_or(match code {
                "invalid_request" | "unsupported_schema" | "invalid_message"
                | "invalid_benchmark" | "benchmark_busy" | "private_send_busy" => "not_started",
                _ => "unknown",
            });
        let retryable = value
            .get("retryable")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(
                matches!(code, "benchmark_busy" | "private_send_busy") || outcome != "not_started",
            );
        let message = value
            .get("message")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("Daemon request failed.");
        let mut error = ErrorEnvelopeV1::new(code, message, outcome, retryable);
        error.request_id = Some(request_id.to_owned());
        error.operation_id = value
            .get("operation_id")
            .and_then(serde_json::Value::as_str)
            .filter(|id| valid_operation_id(id))
            .map(str::to_owned);
        error.offer_id = value
            .get("offer_id")
            .and_then(serde_json::Value::as_str)
            .filter(|id| valid_operation_id(id))
            .map(str::to_owned);
        error.selected_tags = value
            .get("selected_tags")
            .and_then(serde_json::Value::as_u64)
            .and_then(|count| usize::try_from(count).ok());
        error.removed_tags = value
            .get("removed_tags")
            .and_then(serde_json::Value::as_u64)
            .and_then(|count| usize::try_from(count).ok());
        error.quota_bytes_released = value
            .get("quota_bytes_released")
            .and_then(serde_json::Value::as_u64);
        return error.into_value();
    }
    contracts::correlate(value.clone(), request_id)
}

async fn write_local_response<S>(
    stream: &mut S,
    value: &serde_json::Value,
    deadline: Duration,
) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let correlated = IPC_REQUEST_ID
        .try_with(|current| {
            current
                .borrow()
                .as_deref()
                .map(|id| normalize_ipc_response(value, id))
        })
        .ok()
        .flatten();
    tokio::time::timeout(
        deadline,
        write_value(stream, correlated.as_ref().unwrap_or(value)),
    )
    .await
    .context("timed out writing local IPC response")?
}

fn annotate_operation_response(value: &mut serde_json::Value, operation_id: &str) {
    value["operation_id"] = operation_id.into();
    if value["type"] == "error" && value.get("schema_version").is_none() {
        value["schema_version"] = 1.into();
        value["retryable"] = true.into();
        value["outcome"] = "unknown".into();
    }
}

async fn command_response<F>(operation: F, deadline: Duration) -> serde_json::Value
where
    F: std::future::Future<Output = Result<serde_json::Value>>,
{
    match tokio::time::timeout(deadline, operation).await {
        Ok(Ok(value)) => value,
        Ok(Err(error)) => serde_json::json!({
            "type":"error", "code":"daemon_stopping", "message":error.to_string()
        }),
        Err(_) => serde_json::json!({
            "type":"error", "code":"command_timeout",
            "message":"local IPC command exceeded its deadline; its outcome may be unknown"
        }),
    }
}

async fn lifecycle_command_response<F>(
    operation: F,
    deadline: Duration,
    operation_id: Option<String>,
    offer_id: Option<String>,
) -> serde_json::Value
where
    F: std::future::Future<Output = Result<serde_json::Value>>,
{
    match tokio::time::timeout(deadline, operation).await {
        Ok(Ok(value)) => value,
        Ok(Err(error)) => {
            let mut response = LifecycleErrorV1::new(
                "attachment_storage_shutdown",
                error.to_string(),
                "unknown",
                true,
            );
            response.operation_id = operation_id;
            response.offer_id = offer_id;
            response.into_value()
        }
        Err(_) => {
            let mut response = LifecycleErrorV1::new(
                "attachment_command_timeout",
                "attachment lifecycle command exceeded its deadline; retry to reconcile the outcome",
                "unknown",
                true,
            );
            response.operation_id = operation_id;
            response.offer_id = offer_id;
            response.into_value()
        }
    }
}

async fn send_command(
    commands: &mpsc::Sender<DaemonCommand>,
    command: DaemonCommand,
    response: oneshot::Receiver<serde_json::Value>,
) -> Result<serde_json::Value> {
    commands.send(command).await?;
    Ok(response.await?)
}

#[cfg(test)]
async fn handle_local_client<S>(
    stream: S,
    commands: mpsc::Sender<DaemonCommand>,
    events: broadcast::Receiver<serde_json::Value>,
    connected: serde_json::Value,
    startup_peers: Option<serde_json::Value>,
    benchmark_busy: Arc<AtomicBool>,
) -> Result<()>
where
    S: SubscriptionStream,
{
    IPC_REQUEST_ID
        .scope(
            std::cell::RefCell::new(None),
            handle_local_client_with_timeouts(
                stream,
                commands,
                events,
                connected,
                startup_peers,
                benchmark_busy,
                LocalIpcTimeouts::default(),
            ),
        )
        .await
}

async fn handle_local_client_with_timeouts<S>(
    mut stream: S,
    commands: mpsc::Sender<DaemonCommand>,
    mut events: broadcast::Receiver<serde_json::Value>,
    connected: serde_json::Value,
    startup_peers: Option<serde_json::Value>,
    benchmark_busy: Arc<AtomicBool>,
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
            let error = ErrorEnvelopeV1::new(
                "initial_frame_timeout",
                "The initial local request timed out.",
                "not_started",
                true,
            );
            let _ = write_local_response(&mut stream, &error.into_value(), timeouts.response_write)
                .await;
            return Ok(());
        }
    };
    let request_frame: IpcRequestFrame = match serde_json::from_slice(&frame) {
        Ok(frame) => frame,
        Err(_) => {
            let error = ErrorEnvelopeV1::new(
                "invalid_request",
                "Malformed local IPC request.",
                "not_started",
                false,
            );
            let _ = write_local_response(&mut stream, &error.into_value(), timeouts.response_write)
                .await;
            return Ok(());
        }
    };
    let _ = IPC_REQUEST_ID
        .try_with(|current| *current.borrow_mut() = Some(request_frame.request_id.clone()));
    if request_frame.validate().is_err() {
        let mut error = ErrorEnvelopeV1::new(
            "unsupported_schema",
            "Unsupported or invalid local IPC contract.",
            "not_started",
            false,
        );
        error.request_id = contracts::valid_request_id(&request_frame.request_id)
            .then_some(request_frame.request_id);
        write_local_response(&mut stream, &error.into_value(), timeouts.response_write).await?;
        return Ok(());
    }
    let request = request_frame.request;
    let operation_id = match &request {
        IpcRequest::Send { operation_id, .. }
        | IpcRequest::PrivateSend { operation_id, .. }
        | IpcRequest::Share { operation_id, .. } => Some(operation_id),
        _ => None,
    };
    if operation_id.is_some_and(|id| !valid_operation_id(id)) {
        let id = operation_id.expect("operation ID was present");
        write_local_response(
            &mut stream,
            &OperationCache::error(
                id,
                "invalid_operation_id",
                "operation ID must be 32 lowercase hexadecimal characters",
            ),
            timeouts.response_write,
        )
        .await?;
        return Ok(());
    }
    if let IpcRequest::Share {
        operation_id,
        source_digest,
        ..
    } = &request
    {
        if !valid_content_digest(source_digest) {
            write_local_response(
                &mut stream,
                &OperationCache::error(
                    operation_id,
                    "invalid_source_digest",
                    "source digest must be 64 lowercase hexadecimal characters",
                ),
                timeouts.response_write,
            )
            .await?;
            return Ok(());
        }
    }
    match request {
        IpcRequest::Subscribe => {
            write_local_response(&mut stream, &connected, timeouts.response_write).await?;
            if let Some(snapshot) = startup_peers {
                write_local_response(&mut stream, &snapshot, timeouts.response_write).await?;
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
                    // reclaiming quiet web subscriptions after a full close.
                    _ = tokio::time::sleep(Duration::from_millis(250)), if read_closed => {
                        if stream.subscription_closed_after_eof()? {
                            break;
                        }
                    }
                    value = events.recv() => match value {
                        Ok(value) => write_local_response(
                            &mut stream, &value, timeouts.response_write
                        ).await?,
                        Err(broadcast::error::RecvError::Lagged(count)) => {
                            write_local_response(
                                &mut stream,
                                &serde_json::json!({
                                    "type":"lagged", "source":"local", "dropped":count,
                                    "message":format!("local listener missed {count} events")
                                }),
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
            let mut value = command_response(
                send_command(
                    &commands,
                    DaemonCommand::Send {
                        operation_id,
                        body,
                        reply,
                    },
                    response,
                ),
                timeouts.ordinary_command,
            )
            .await;
            annotate_operation_response(&mut value, &response_operation_id);
            write_local_response(&mut stream, &value, timeouts.response_write).await?;
        }
        IpcRequest::PrivateSend {
            operation_id,
            to,
            body,
        } => {
            let response_operation_id = operation_id.clone();
            let (reply, response) = oneshot::channel();
            let mut value = command_response(
                send_command(
                    &commands,
                    DaemonCommand::PrivateSend {
                        operation_id,
                        to,
                        body,
                        reply,
                    },
                    response,
                ),
                timeouts.private_command,
            )
            .await;
            annotate_operation_response(&mut value, &response_operation_id);
            write_local_response(&mut stream, &value, timeouts.response_write).await?;
        }
        IpcRequest::BenchSend { config } => {
            // The benchmark protocol has its own validated duration and cancellation
            // path; progress writes are independently bounded below.
            handle_bench_send(&mut stream, &commands, config, benchmark_busy).await?;
        }
        IpcRequest::Status => {
            let (reply, response) = oneshot::channel();
            let value = command_response(
                send_command(&commands, DaemonCommand::Status { reply }, response),
                timeouts.ordinary_command,
            )
            .await;
            write_local_response(&mut stream, &value, timeouts.response_write).await?;
        }
        IpcRequest::Peers => {
            let (reply, response) = oneshot::channel();
            let value = command_response(
                send_command(&commands, DaemonCommand::Peers { reply }, response),
                timeouts.ordinary_command,
            )
            .await;
            write_local_response(&mut stream, &value, timeouts.response_write).await?;
        }
        IpcRequest::Offers => {
            let (reply, response) = oneshot::channel();
            let value = command_response(
                send_command(&commands, DaemonCommand::Offers { reply }, response),
                timeouts.list_command,
            )
            .await;
            write_local_response(&mut stream, &value, timeouts.response_write).await?;
        }
        IpcRequest::OffersRemove {
            offer_id,
            direction,
            provider,
        } => {
            let (reply, response) = oneshot::channel();
            let response_offer_id = offer_id.clone();
            let value = lifecycle_command_response(
                send_command(
                    &commands,
                    DaemonCommand::OffersRemove {
                        offer_id,
                        direction,
                        provider,
                        reply,
                    },
                    response,
                ),
                timeouts.list_command,
                None,
                Some(response_offer_id),
            )
            .await;
            write_local_response(&mut stream, &value, timeouts.response_write).await?;
        }
        IpcRequest::OffersPrune {
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
                        older_than_secs,
                        direction,
                        dry_run,
                        max_delete,
                        reply,
                    },
                    response,
                ),
                timeouts.list_command,
                None,
                None,
            )
            .await;
            write_local_response(&mut stream, &value, timeouts.response_write).await?;
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
                        operation_id,
                        source_digest,
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
            write_local_response(&mut stream, &value, timeouts.response_write).await?;
        }
        IpcRequest::Download { offer, output } => {
            let (reply, response) = oneshot::channel();
            let value = lifecycle_command_response(
                send_command(
                    &commands,
                    DaemonCommand::Download {
                        offer,
                        output,
                        raw_export: false,
                        reply,
                    },
                    response,
                ),
                timeouts.transfer_command,
                None,
                None,
            )
            .await;
            write_local_response(&mut stream, &value, timeouts.response_write).await?;
        }
        IpcRequest::WebDownload { offer, output } => {
            let (reply, response) = oneshot::channel();
            let value = lifecycle_command_response(
                send_command(
                    &commands,
                    DaemonCommand::Download {
                        offer,
                        output,
                        raw_export: true,
                        reply,
                    },
                    response,
                ),
                timeouts.transfer_command,
                None,
                None,
            )
            .await;
            write_local_response(&mut stream, &value, timeouts.response_write).await?;
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
                    serde_json::json!({"type":"stopping", "outcome":"accepted"})
                }
                Ok(Err(_)) => serde_json::json!({
                    "type":"error", "code":"daemon_stopping", "outcome":"not_started",
                    "message":"stop command was not admitted because the daemon command channel is closed"
                }),
                Err(_) => serde_json::json!({
                    "type":"error", "code":"command_timeout", "outcome":"not_started",
                    "message":"stop command was not admitted before its deadline; the daemon was not stopped by this request"
                }),
            };
            write_local_response(&mut stream, &response, timeouts.response_write).await?;
        }
    }
    Ok(())
}

#[derive(Debug, Serialize)]
struct PinnedBlobInfo {
    direction: &'static str,
    offer_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    provider: Option<String>,
    name: String,
    kind: &'static str,
    hash: String,
    format: &'static str,
    status: &'static str,
    size: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PinnedBlobTag {
    direction: &'static str,
    offer_id: String,
    provider: Option<String>,
    name: String,
    kind: AttachmentKind,
}

fn attachment_kind_name(kind: AttachmentKind) -> &'static str {
    match kind {
        AttachmentKind::File => "file",
        AttachmentKind::DirectoryTarV1 => "directory_tar_v1",
    }
}

fn parse_attachment_kind(value: &str) -> Option<AttachmentKind> {
    match value {
        "file" => Some(AttachmentKind::File),
        "directory_tar_v1" => Some(AttachmentKind::DirectoryTarV1),
        _ => None,
    }
}

fn valid_offer_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn decode_tag_name(value: &str) -> Option<String> {
    // A valid display name is at most 100 UTF-8 bytes. Reject oversized input
    // before the decoder allocates in proportion to untrusted tag metadata.
    if value.len() > MAX_ENCODED_TAG_NAME_BYTES {
        return None;
    }
    let decoded = BASE64URL_NOPAD.decode(value.as_bytes()).ok()?;
    let name = String::from_utf8(decoded).ok()?;
    attachment::validate_display_name(&name).ok()?;
    Some(name)
}

fn encode_tag_name(value: &str) -> String {
    BASE64URL_NOPAD.encode(value.as_bytes())
}

fn outbound_blob_tag(offer_id: &str, kind: AttachmentKind, name: &str) -> String {
    format!(
        "{OUTBOUND_BLOB_TAG_PREFIX}{offer_id}/{}/{}",
        attachment_kind_name(kind),
        encode_tag_name(name)
    )
}

fn inbound_blob_tag(
    provider: PublicKey,
    offer_id: &str,
    kind: AttachmentKind,
    name: &str,
) -> String {
    format!(
        "{INBOUND_BLOB_TAG_PREFIX}{provider}/{offer_id}/{}/{}",
        attachment_kind_name(kind),
        encode_tag_name(name)
    )
}

fn parse_pinned_blob_tag(name: &[u8]) -> Option<PinnedBlobTag> {
    let name = std::str::from_utf8(name).ok()?;
    let (direction, provider, remainder) =
        if let Some(remainder) = name.strip_prefix(OUTBOUND_BLOB_TAG_PREFIX) {
            ("outgoing", None, remainder)
        } else {
            let remainder = name.strip_prefix(INBOUND_BLOB_TAG_PREFIX)?;
            let (provider, remainder) = remainder.split_once('/')?;
            if provider.len() > MAX_ENCODED_PUBLIC_KEY_BYTES {
                return None;
            }
            let provider = provider.parse::<PublicKey>().ok()?.to_string();
            ("incoming", Some(provider), remainder)
        };
    let mut parts = remainder.split('/');
    let offer_id = parts.next()?;
    let kind = parse_attachment_kind(parts.next()?)?;
    let name = decode_tag_name(parts.next()?)?;
    if parts.next().is_some() || !valid_offer_id(offer_id) {
        return None;
    }
    Some(PinnedBlobTag {
        direction,
        offer_id: offer_id.to_owned(),
        provider,
        name,
        kind,
    })
}

async fn list_pinned_blobs(store: &Store) -> Result<(Vec<PinnedBlobInfo>, bool, usize)> {
    let mut tags = store
        .tags()
        .list_prefix(BLOB_TAG_PREFIX)
        .await
        .context("list attachment blob tags")?;
    // iroh-blobs' fs tag table is a BTree range and list_prefix preserves that
    // order. Consume only a bounded prefix, including one valid lookahead.
    let mut selected = Vec::new();
    let mut scanned = 0;
    let mut item_errors = 0;
    let mut has_more = false;
    while scanned < MAX_OFFER_LIST_SCANNED {
        let Some(item) = tags.next().await else { break };
        scanned += 1;
        let tag = match item {
            Ok(tag) => tag,
            Err(_) => {
                item_errors += 1;
                has_more = true;
                continue;
            }
        };
        if parse_pinned_blob_tag(tag.name.as_ref()).is_none() {
            continue;
        }
        if selected.len() == MAX_OFFER_LIST_ENTRIES {
            has_more = true;
            break;
        }
        selected.push(tag);
    }
    if scanned == MAX_OFFER_LIST_SCANNED {
        has_more = true;
    }

    let mut blobs = Vec::with_capacity(selected.len());
    for tag in selected {
        let parsed = parse_pinned_blob_tag(tag.name.as_ref()).expect("selected tag was validated");
        let (status, size) = match store.blobs().status(tag.hash).await {
            Ok(iroh_blobs::api::proto::BlobStatus::Complete { size }) => ("complete", Some(size)),
            Ok(iroh_blobs::api::proto::BlobStatus::Partial { size }) => ("partial", size),
            Ok(iroh_blobs::api::proto::BlobStatus::NotFound) => ("missing", None),
            Err(_) => ("unknown", None),
        };
        let format = match tag.format {
            BlobFormat::Raw => "raw",
            BlobFormat::HashSeq => "hash_seq",
        };
        blobs.push(PinnedBlobInfo {
            direction: parsed.direction,
            offer_id: parsed.offer_id,
            provider: parsed.provider,
            name: parsed.name,
            kind: attachment_kind_name(parsed.kind),
            hash: tag.hash.to_string(),
            format,
            status,
            size,
        });
    }
    Ok((blobs, has_more, item_errors))
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttachmentRetentionIndex {
    schema_version: u8,
    created_at_ms: BTreeMap<String, u64>,
}

impl Default for AttachmentRetentionIndex {
    fn default() -> Self {
        Self {
            schema_version: 1,
            created_at_ms: BTreeMap::new(),
        }
    }
}

#[derive(Clone)]
struct AttachmentStorage {
    store: Store,
    blob_root: PathBuf,
    state_dir: PathBuf,
    state: Arc<Mutex<AttachmentStorageState>>,
    gate: Arc<Semaphore>,
    quota_bytes: u64,
    min_free_bytes: u64,
    retention_secs: u64,
}

struct AttachmentStorageState {
    index: AttachmentRetentionIndex,
    tags: BTreeMap<String, StorageTag>,
    reservations: HashSet<String>,
    gc_protections: HashMap<iroh_blobs::HashAndFormat, GcProtection>,
    accounting_healthy: bool,
    status: AttachmentStorageStatus,
}

struct GcProtection {
    _tag: iroh_blobs::api::TempTag,
    deadline: GcProtectionDeadline,
}

#[derive(Clone, Copy)]
enum GcProtectionDeadline {
    InFlight,
    Until(StdInstant),
}

struct RemovalGcGuard {
    state: Arc<Mutex<AttachmentStorageState>>,
    records: Vec<(iroh_blobs::HashAndFormat, Option<GcProtectionDeadline>)>,
    finished: bool,
}

impl RemovalGcGuard {
    fn restore_before_deletion(&mut self) {
        let mut state = self
            .state
            .lock()
            .expect("attachment storage state poisoned");
        for (value, previous) in &self.records {
            match previous {
                Some(deadline) => {
                    if let Some(protection) = state.gc_protections.get_mut(value) {
                        protection.deadline = *deadline;
                    }
                }
                None => {
                    state.gc_protections.remove(value);
                }
            }
        }
        self.finished = true;
    }

    fn finish(mut self, possibly_unpinned: &HashSet<iroh_blobs::HashAndFormat>) {
        let expires_at = StdInstant::now() + TRANSFER_TIMEOUT;
        let mut state = self
            .state
            .lock()
            .expect("attachment storage state poisoned");
        for (value, previous) in &self.records {
            if possibly_unpinned.contains(value) {
                if let Some(protection) = state.gc_protections.get_mut(value) {
                    protection.deadline = GcProtectionDeadline::Until(expires_at);
                }
            } else {
                match previous {
                    Some(deadline) => {
                        if let Some(protection) = state.gc_protections.get_mut(value) {
                            protection.deadline = *deadline;
                        }
                    }
                    None => {
                        state.gc_protections.remove(value);
                    }
                }
            }
        }
        drop(state);
        self.finished = true;
    }
}

impl Drop for RemovalGcGuard {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        let expires_at = StdInstant::now() + TRANSFER_TIMEOUT;
        let mut state = self
            .state
            .lock()
            .expect("attachment storage state poisoned");
        for (value, _) in &self.records {
            if let Some(protection) = state.gc_protections.get_mut(value) {
                protection.deadline = GcProtectionDeadline::Until(expires_at);
            }
        }
    }
}

#[derive(Debug, Clone)]
struct StorageTag {
    name: String,
    parsed: PinnedBlobTag,
    hash_and_format: iroh_blobs::HashAndFormat,
    size: u64,
}

#[derive(Debug, Clone, Serialize)]
struct AttachmentStorageStatus {
    tagged_bytes: u64,
    tagged_blobs: usize,
    tags: usize,
    tag_capacity: usize,
    quota_bytes: u64,
    available_bytes: u64,
    min_free_bytes: u64,
    pressure: bool,
    over_quota: bool,
    below_min_free: bool,
    sampled_at_ms: u64,
}

struct RemovalSpec<'a> {
    offer_id: Option<&'a str>,
    direction: Option<&'a str>,
    provider: Option<&'a str>,
    older_than_secs: Option<u64>,
    maximum: usize,
    dry_run: bool,
}

impl AttachmentStorage {
    async fn open(
        store: Store,
        blob_root: PathBuf,
        state_dir: &Path,
        quota_bytes: u64,
        min_free_bytes: u64,
        retention_secs: u64,
    ) -> Result<Self> {
        let state_dir = state_dir.to_owned();
        let index_dir = state_dir.clone();
        let mut index = tokio::task::spawn_blocking(move || load_attachment_index(&index_dir))
            .await
            .context("attachment index load task failed")??;
        let live = collect_storage_tags_bounded(&store).await?;
        anyhow::ensure!(
            live.len() <= MAX_ATTACHMENT_TAGS,
            "attachment tag capacity exceeded: {} pins found, maximum is {MAX_ATTACHMENT_TAGS}; remove pins with a compatible older daemon or restore from backup",
            live.len()
        );
        let now = unix_timestamp_ms()?;
        let tags = live
            .into_iter()
            .map(|tag| (tag.name.clone(), tag))
            .collect::<BTreeMap<_, _>>();
        index
            .created_at_ms
            .retain(|name, _| tags.contains_key(name));
        for name in tags.keys() {
            index.created_at_ms.entry(name.clone()).or_insert(now);
        }
        let persist_dir = state_dir.clone();
        let persist_index = clone_attachment_index(&index);
        tokio::task::spawn_blocking(move || persist_attachment_index(&persist_dir, &persist_index))
            .await
            .context("attachment index reconciliation task failed")??;
        let available_bytes = available_space_off_loop(blob_root.clone()).await?;
        let status = storage_status(
            tags.values(),
            quota_bytes,
            available_bytes,
            min_free_bytes,
            now,
        );
        Ok(Self {
            store,
            blob_root,
            state_dir,
            state: Arc::new(Mutex::new(AttachmentStorageState {
                index,
                tags,
                reservations: HashSet::new(),
                gc_protections: HashMap::new(),
                accounting_healthy: true,
                status,
            })),
            gate: Arc::new(Semaphore::new(1)),
            quota_bytes,
            min_free_bytes,
            retention_secs,
        })
    }

    fn status(&self) -> AttachmentStorageStatus {
        self.state
            .lock()
            .expect("attachment storage state poisoned")
            .status
            .clone()
    }

    async fn refresh_free_space(&self) -> Result<()> {
        let available = available_space_off_loop(self.blob_root.clone()).await?;
        let now = unix_timestamp_ms()?;
        let mut state = self
            .state
            .lock()
            .expect("attachment storage state poisoned");
        let monotonic_now = StdInstant::now();
        state.gc_protections.retain(|_, protection| {
            matches!(protection.deadline, GcProtectionDeadline::InFlight)
                || matches!(
                    protection.deadline,
                    GcProtectionDeadline::Until(deadline) if deadline > monotonic_now
                )
        });
        state.status = storage_status(
            state.tags.values(),
            self.quota_bytes,
            available,
            self.min_free_bytes,
            now,
        );
        Ok(())
    }

    async fn preflight_free_space(&self, additional_bytes: u64) -> Result<()> {
        let available = available_space_off_loop(self.blob_root.clone()).await?;
        let required = self
            .min_free_bytes
            .checked_add(additional_bytes)
            .context("attachment free-space requirement overflow")?;
        {
            let now = unix_timestamp_ms()?;
            let mut state = self
                .state
                .lock()
                .expect("attachment storage state poisoned");
            state.status = storage_status(
                state.tags.values(),
                self.quota_bytes,
                available,
                self.min_free_bytes,
                now,
            );
        }
        anyhow::ensure!(
            available >= required,
            "attachment_min_free_space: attachment needs {additional_bytes} bytes while preserving {} free bytes ({} available)",
            self.min_free_bytes, available
        );
        Ok(())
    }

    fn admit_pin(
        &self,
        tag_name: &str,
        hash_and_format: iroh_blobs::HashAndFormat,
        size: u64,
    ) -> Result<()> {
        anyhow::ensure!(
            hash_and_format.format == BlobFormat::Raw,
            "attachment_lifecycle_internal: unsupported hash_seq attachment format"
        );
        let state = self
            .state
            .lock()
            .expect("attachment storage state poisoned");
        anyhow::ensure!(
            state.accounting_healthy,
            "attachment_lifecycle_internal: attachment accounting requires reconciliation"
        );
        if let Some(existing) = state.tags.get(tag_name) {
            anyhow::ensure!(
                existing.hash_and_format == hash_and_format,
                "attachment_lifecycle_internal: attachment tag is bound to different content"
            );
            return Ok(());
        }
        anyhow::ensure!(
            state.tags.len() + state.reservations.len() < MAX_ATTACHMENT_TAGS,
            "attachment_tag_capacity: attachment pin capacity of {MAX_ATTACHMENT_TAGS} reached"
        );
        let used = state.status.tagged_bytes;
        let deduplicated = state
            .tags
            .values()
            .any(|tag| tag.hash_and_format == hash_and_format);
        let additional = if deduplicated { 0 } else { size };
        anyhow::ensure!(
            used.checked_add(additional).is_some_and(|total| total <= self.quota_bytes),
            "attachment_quota_exceeded: pinning this blob would exceed the {}-byte attachment quota ({} used, {} additional)",
            self.quota_bytes, used, additional
        );
        Ok(())
    }

    async fn commit_pin(
        &self,
        tag_name: &str,
        parsed: PinnedBlobTag,
        hash_and_format: iroh_blobs::HashAndFormat,
        size: u64,
        fault: &(dyn Fn(&'static str) -> Result<()> + Sync),
    ) -> Result<bool> {
        let authoritative_size = complete_blob_size(&self.store, hash_and_format).await?;
        anyhow::ensure!(
            authoritative_size == size,
            "attachment_lifecycle_internal: complete blob size {authoritative_size} differs from expected {size}"
        );
        self.admit_pin(tag_name, hash_and_format, authoritative_size)?;
        {
            let mut state = self
                .state
                .lock()
                .expect("attachment storage state poisoned");
            if state.tags.contains_key(tag_name) {
                return Ok(false);
            }
            anyhow::ensure!(
                state.reservations.insert(tag_name.to_owned()),
                "attachment_lifecycle_internal: duplicate attachment reservation"
            );
        }
        let result = async {
            fault("before_attachment_tag_set")?;
            self.store
                .tags()
                .set(tag_name.as_bytes(), hash_and_format)
                .await?;
            fault("after_attachment_tag_set")?;
            self.store.sync_db().await?;
            fault("after_attachment_tag_sync")?;
            let now = unix_timestamp_ms()?;
            let index = {
                let mut state = self
                    .state
                    .lock()
                    .expect("attachment storage state poisoned");
                state.tags.insert(
                    tag_name.to_owned(),
                    StorageTag {
                        name: tag_name.to_owned(),
                        parsed,
                        hash_and_format,
                        size: authoritative_size,
                    },
                );
                state.index.created_at_ms.insert(tag_name.to_owned(), now);
                state.reservations.remove(tag_name);
                let available = state.status.available_bytes;
                state.status = storage_status(
                    state.tags.values(),
                    self.quota_bytes,
                    available,
                    self.min_free_bytes,
                    now,
                );
                clone_attachment_index(&state.index)
            };
            fault("before_attachment_index_persist")?;
            persist_attachment_index_off_loop(self.state_dir.clone(), index).await?;
            fault("after_attachment_index_persist")?;
            self.recalculate_cached_status().await?;
            Ok::<(), anyhow::Error>(())
        }
        .await;
        if let Err(error) = result {
            let rollback = self.rollback_new_pin(tag_name, fault).await;
            return match rollback {
                Ok(()) => Err(error),
                Err(rollback_error) => Err(error.context(format!(
                    "attachment pin rollback failed and was reconciled: {rollback_error:#}"
                ))),
            };
        }
        Ok(true)
    }

    async fn rollback_new_pin(
        &self,
        tag_name: &str,
        fault: &(dyn Fn(&'static str) -> Result<()> + Sync),
    ) -> Result<()> {
        let rollback = async {
            fault("before_attachment_tag_rollback")?;
            self.store.tags().delete(tag_name.as_bytes()).await?;
            self.store.sync_db().await?;
            fault("after_attachment_tag_rollback")?;
            let index = {
                let mut state = self
                    .state
                    .lock()
                    .expect("attachment storage state poisoned");
                state.tags.remove(tag_name);
                state.reservations.remove(tag_name);
                state.index.created_at_ms.remove(tag_name);
                let available = state.status.available_bytes;
                state.status = storage_status(
                    state.tags.values(),
                    self.quota_bytes,
                    available,
                    self.min_free_bytes,
                    unix_timestamp_ms()?,
                );
                clone_attachment_index(&state.index)
            };
            persist_attachment_index_off_loop(self.state_dir.clone(), index).await?;
            self.recalculate_cached_status().await?;
            Ok::<(), anyhow::Error>(())
        }
        .await;
        if rollback.is_err() {
            self.reconcile()
                .await
                .context("reconcile after attachment rollback failure")?;
        }
        rollback
    }

    async fn rollback_committed_pin(&self, tag_name: &str, newly_created: bool) -> Result<()> {
        if newly_created {
            self.rollback_new_pin(tag_name, &|_| Ok(())).await
        } else {
            Ok(())
        }
    }

    async fn recalculate_cached_status(&self) -> Result<()> {
        let available = available_space_off_loop(self.blob_root.clone()).await?;
        let now = unix_timestamp_ms()?;
        let mut state = self
            .state
            .lock()
            .expect("attachment storage state poisoned");
        state.status = storage_status(
            state.tags.values(),
            self.quota_bytes,
            available,
            self.min_free_bytes,
            now,
        );
        Ok(())
    }

    async fn reconcile(&self) -> Result<()> {
        self.state
            .lock()
            .expect("attachment storage state poisoned")
            .accounting_healthy = false;
        let tags = collect_storage_tags_bounded(&self.store)
            .await?
            .into_iter()
            .map(|tag| (tag.name.clone(), tag))
            .collect::<BTreeMap<_, _>>();
        anyhow::ensure!(
            tags.len() <= MAX_ATTACHMENT_TAGS,
            "attachment tag capacity exceeded during reconciliation"
        );
        let now = unix_timestamp_ms()?;
        let index = {
            let mut state = self
                .state
                .lock()
                .expect("attachment storage state poisoned");
            state
                .index
                .created_at_ms
                .retain(|name, _| tags.contains_key(name));
            for name in tags.keys() {
                state.index.created_at_ms.entry(name.clone()).or_insert(now);
            }
            state.tags = tags;
            state.reservations.clear();
            let available = state.status.available_bytes;
            state.status = storage_status(
                state.tags.values(),
                self.quota_bytes,
                available,
                self.min_free_bytes,
                now,
            );
            state.accounting_healthy = true;
            clone_attachment_index(&state.index)
        };
        persist_attachment_index_off_loop(self.state_dir.clone(), index).await?;
        self.recalculate_cached_status().await
    }

    async fn automatic_retention_pass(&self) -> Result<Option<serde_json::Value>> {
        if self.retention_secs == 0 {
            return Ok(None);
        }
        self.remove(
            None,
            None,
            None,
            Some(self.retention_secs),
            MAX_PRUNE_TAGS,
            false,
        )
        .await
        .map(Some)
    }

    async fn protect_removed_blobs_from_gc(
        &self,
        values: impl IntoIterator<Item = iroh_blobs::HashAndFormat>,
    ) -> Result<RemovalGcGuard> {
        let values = values.into_iter().collect::<HashSet<_>>();
        let mut guard = RemovalGcGuard {
            state: self.state.clone(),
            records: Vec::with_capacity(values.len()),
            finished: false,
        };
        for value in values {
            // The named pin still exists while this await runs. Once acquired,
            // lookup and transition to InFlight happen under one state lock.
            let temporary = match self.store.tags().temp_tag(value).await {
                Ok(temporary) => temporary,
                Err(error) => {
                    guard.restore_before_deletion();
                    return Err(anyhow::Error::new(error)
                        .context("protect attachment blob from GC before pin removal"));
                }
            };
            let now = StdInstant::now();
            let mut state = self
                .state
                .lock()
                .expect("attachment storage state poisoned");
            state.gc_protections.retain(|_, protection| {
                matches!(protection.deadline, GcProtectionDeadline::InFlight)
                    || matches!(
                        protection.deadline,
                        GcProtectionDeadline::Until(deadline) if deadline > now
                    )
            });
            if !state.gc_protections.contains_key(&value)
                && state.gc_protections.len() >= MAX_ATTACHMENT_TAGS
            {
                drop(state);
                drop(temporary);
                guard.restore_before_deletion();
                anyhow::bail!(
                    "attachment_storage_busy: active-transfer GC protection capacity reached"
                );
            }
            let previous = match state.gc_protections.entry(value) {
                std::collections::hash_map::Entry::Occupied(mut entry) => {
                    let previous = entry.get().deadline;
                    entry.get_mut().deadline = GcProtectionDeadline::InFlight;
                    Some(previous)
                }
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(GcProtection {
                        _tag: temporary,
                        deadline: GcProtectionDeadline::InFlight,
                    });
                    guard.records.push((value, None));
                    continue;
                }
            };
            drop(state);
            drop(temporary);
            guard.records.push((value, previous));
        }
        Ok(guard)
    }

    async fn remove(
        &self,
        offer_id: Option<&str>,
        direction: Option<&str>,
        provider: Option<&str>,
        older_than_secs: Option<u64>,
        maximum: usize,
        dry_run: bool,
    ) -> Result<serde_json::Value> {
        self.remove_with_fault(
            RemovalSpec {
                offer_id,
                direction,
                provider,
                older_than_secs,
                maximum,
                dry_run,
            },
            &|_| Ok(()),
        )
        .await
    }

    async fn remove_with_fault(
        &self,
        spec: RemovalSpec<'_>,
        fault: &(dyn Fn(&'static str) -> Result<()> + Sync),
    ) -> Result<serde_json::Value> {
        let RemovalSpec {
            offer_id,
            direction,
            provider,
            older_than_secs,
            maximum,
            dry_run,
        } = spec;
        let _permit = self.gate.clone().try_acquire_owned().map_err(|_| {
            anyhow::anyhow!(
                "attachment_storage_busy: an attachment transfer or lifecycle operation is active"
            )
        })?;
        let now = unix_timestamp_ms()?;
        let cutoff =
            older_than_secs.map(|seconds| now.saturating_sub(seconds.saturating_mul(1000)));
        let (before, mut selected, tags) = {
            let state = self
                .state
                .lock()
                .expect("attachment storage state poisoned");
            let mut selected = state
                .tags
                .values()
                .filter(|tag| {
                    offer_id.is_none_or(|id| tag.parsed.offer_id == id)
                        && direction.is_none_or(|value| tag.parsed.direction == value)
                        && provider
                            .is_none_or(|value| tag.parsed.provider.as_deref() == Some(value))
                        && cutoff.is_none_or(|boundary| {
                            state
                                .index
                                .created_at_ms
                                .get(&tag.name)
                                .copied()
                                .unwrap_or(now)
                                <= boundary
                        })
                })
                .map(|tag| {
                    (
                        state
                            .index
                            .created_at_ms
                            .get(&tag.name)
                            .copied()
                            .unwrap_or(now),
                        tag.name.clone(),
                    )
                })
                .collect::<Vec<_>>();
            selected.sort();
            (state.status.tagged_bytes, selected, state.tags.clone())
        };
        let limited = selected.len() > maximum;
        selected.truncate(maximum);
        let selected_names = selected
            .into_iter()
            .map(|(_, name)| name)
            .collect::<Vec<_>>();
        let selected_set = selected_names.iter().cloned().collect::<HashSet<_>>();
        let projected = tags
            .values()
            .filter(|tag| !selected_set.contains(&tag.name));
        let projected_usage = unique_storage_usage(projected).0;
        if dry_run {
            return Ok(serde_json::json!({
                "type":"offers_pruned", "schema_version":1, "dry_run":true,
                "selected_tags":selected_names.len(), "removed_tags":0,
                "released_bytes":before.saturating_sub(projected_usage),
                "limited":limited, "cutoff_ms":cutoff
            }));
        }
        let protection = self
            .protect_removed_blobs_from_gc(
                selected_names
                    .iter()
                    .filter_map(|name| tags.get(name).map(|tag| tag.hash_and_format)),
            )
            .await?;
        let mut removed = Vec::new();
        let mut failures = 0_usize;
        let mut possibly_unpinned = HashSet::new();
        for name in &selected_names {
            if fault("attachment_tag_delete").is_err() {
                failures += 1;
                continue;
            }
            if let Some(tag) = tags.get(name) {
                // Once deletion is attempted, an error or zero count cannot
                // prove that a durable pin remains. Retain the conservative guard.
                possibly_unpinned.insert(tag.hash_and_format);
            }
            match self.store.tags().delete(name.as_bytes()).await {
                Ok(count) if count != 0 => removed.push(name.clone()),
                Ok(_) => {}
                Err(_) => failures += 1,
            }
        }
        let sync_error = match fault("attachment_removal_sync") {
            Ok(()) => self
                .store
                .sync_db()
                .await
                .err()
                .map(|error| error.to_string()),
            Err(error) => Some(error.to_string()),
        };
        if failures != 0 || sync_error.is_some() {
            // Keep every guard nonexpiring through failure reconciliation, then
            // start grace only for values whose deletion may have taken effect.
            let reconcile_error = self.reconcile().await.err();
            protection.finish(&possibly_unpinned);
            let after = self.status().tagged_bytes;
            let mut error = LifecycleErrorV1::new(
                "attachment_removal_partial",
                sync_error
                    .unwrap_or_else(|| format!("{failures} attachment tag deletion(s) failed")),
                if removed.is_empty() {
                    "unknown"
                } else {
                    "partial"
                },
                true,
            );
            error.offer_id = offer_id.map(str::to_owned);
            error.selected_tags = Some(selected_names.len());
            error.removed_tags = Some(removed.len());
            error.quota_bytes_released = Some(before.saturating_sub(after));
            if let Some(reconcile_error) = reconcile_error {
                error.message = format!(
                    "{}; reconciliation failed: {reconcile_error}",
                    error.message
                );
                error.message.truncate(1024);
            }
            return Ok(error.into_value());
        }
        // Successful deletion is now database-durable. Start a complete grace
        // interval from this boundary, not from pre-deletion guard acquisition.
        protection.finish(&possibly_unpinned);
        let index = {
            let mut state = self
                .state
                .lock()
                .expect("attachment storage state poisoned");
            for name in &removed {
                state.tags.remove(name);
                state.index.created_at_ms.remove(name);
            }
            clone_attachment_index(&state.index)
        };
        if fault("attachment_removal_index_persist").is_err()
            || persist_attachment_index_off_loop(self.state_dir.clone(), index)
                .await
                .is_err()
        {
            self.recalculate_cached_status().await?;
            let mut error = LifecycleErrorV1::new(
                "attachment_removal_partial",
                "attachment tags were removed but retention-index persistence failed",
                if removed.is_empty() {
                    "unknown"
                } else {
                    "partial"
                },
                true,
            );
            error.offer_id = offer_id.map(str::to_owned);
            error.selected_tags = Some(selected_names.len());
            error.removed_tags = Some(removed.len());
            error.quota_bytes_released = Some(before.saturating_sub(self.status().tagged_bytes));
            return Ok(error.into_value());
        }
        self.recalculate_cached_status().await?;
        Ok(serde_json::json!({
            "type":if offer_id.is_some() { "offer_removed" } else { "offers_pruned" },
            "schema_version":1, "dry_run":false,
            "selected_tags":selected_names.len(), "removed_tags":removed.len(),
            "released_bytes":before.saturating_sub(self.status().tagged_bytes),
            "limited":limited, "cutoff_ms":cutoff
        }))
    }
}

fn clone_attachment_index(index: &AttachmentRetentionIndex) -> AttachmentRetentionIndex {
    AttachmentRetentionIndex {
        schema_version: index.schema_version,
        created_at_ms: index.created_at_ms.clone(),
    }
}

fn load_attachment_index(state_dir: &Path) -> Result<AttachmentRetentionIndex> {
    let path = state_dir.join(ATTACHMENT_INDEX_NAME);
    if !path.exists() {
        return Ok(AttachmentRetentionIndex::default());
    }
    let bytes = std::fs::read(path).context("read attachment retention index")?;
    anyhow::ensure!(
        bytes.len() <= MAX_ATTACHMENT_INDEX_BYTES,
        "attachment retention index is too large"
    );
    let index: AttachmentRetentionIndex =
        serde_json::from_slice(&bytes).context("parse attachment retention index")?;
    anyhow::ensure!(
        index.schema_version == 1,
        "unsupported attachment retention index version"
    );
    anyhow::ensure!(
        index.created_at_ms.len() <= MAX_ATTACHMENT_TAGS,
        "attachment retention index exceeds pin capacity"
    );
    Ok(index)
}

fn persist_attachment_index(state_dir: &Path, index: &AttachmentRetentionIndex) -> Result<()> {
    let encoded = serde_json::to_vec_pretty(index)?;
    anyhow::ensure!(
        encoded.len() <= MAX_ATTACHMENT_INDEX_BYTES,
        "attachment retention index exceeds its size bound"
    );
    crate::config::atomic_write(state_dir, ATTACHMENT_INDEX_NAME, &encoded, 0o600)
        .context("persist attachment retention index")
}

async fn persist_attachment_index_off_loop(
    state_dir: PathBuf,
    index: AttachmentRetentionIndex,
) -> Result<()> {
    tokio::task::spawn_blocking(move || persist_attachment_index(&state_dir, &index))
        .await
        .context("attachment index persistence task failed")?
}

async fn available_space_off_loop(path: PathBuf) -> Result<u64> {
    tokio::task::spawn_blocking(move || {
        fs2::available_space(path).context("query attachment store free space")
    })
    .await
    .context("attachment free-space task failed")?
}

async fn complete_blob_size(
    store: &Store,
    hash_and_format: iroh_blobs::HashAndFormat,
) -> Result<u64> {
    anyhow::ensure!(
        hash_and_format.format == BlobFormat::Raw,
        "attachment_lifecycle_internal: unsupported hash_seq attachment format"
    );
    match store.blobs().status(hash_and_format.hash).await {
        Ok(iroh_blobs::api::proto::BlobStatus::Complete { size }) => Ok(size),
        Ok(iroh_blobs::api::proto::BlobStatus::Partial { size }) => anyhow::bail!(
            "attachment_lifecycle_internal: attachment blob is incomplete (reported size {size:?})"
        ),
        Ok(iroh_blobs::api::proto::BlobStatus::NotFound) => {
            anyhow::bail!("attachment_lifecycle_internal: attachment blob is missing")
        }
        Err(error) => Err(anyhow::Error::new(error)
            .context("attachment_lifecycle_internal: query attachment blob completeness")),
    }
}

async fn collect_storage_tags_bounded(store: &Store) -> Result<Vec<StorageTag>> {
    let mut stream = store
        .tags()
        .list_prefix(BLOB_TAG_PREFIX)
        .await
        .context("list attachment tags for storage reconciliation")?;
    let mut result = Vec::new();
    let mut scanned = 0_usize;
    while let Some(item) = stream.next().await {
        scanned += 1;
        anyhow::ensure!(
            scanned <= MAX_ATTACHMENT_TAG_SCAN,
            "attachment reserved-prefix scan exceeded {MAX_ATTACHMENT_TAG_SCAN} entries"
        );
        let tag = item.context("read attachment tag for storage reconciliation")?;
        let Some(parsed) = parse_pinned_blob_tag(tag.name.as_ref()) else {
            continue;
        };
        anyhow::ensure!(
            result.len() < MAX_ATTACHMENT_TAGS,
            "attachment tag capacity exceeded: more than {MAX_ATTACHMENT_TAGS} pins"
        );
        anyhow::ensure!(
            tag.format == BlobFormat::Raw,
            "unsupported hash_seq format in meshmsg attachment tag"
        );
        let name = std::str::from_utf8(tag.name.as_ref())
            .context("attachment tag is not UTF-8")?
            .to_owned();
        let hash_and_format = iroh_blobs::HashAndFormat {
            hash: tag.hash,
            format: tag.format,
        };
        let size = complete_blob_size(store, hash_and_format)
            .await
            .with_context(|| format!("validate complete attachment blob for tag {name}"))?;
        result.push(StorageTag {
            name,
            parsed,
            hash_and_format,
            size,
        });
    }
    Ok(result)
}

fn unique_storage_usage<'a>(tags: impl IntoIterator<Item = &'a StorageTag>) -> (u64, usize) {
    let mut values = HashSet::new();
    let mut bytes = 0_u64;
    for tag in tags {
        if values.insert(tag.hash_and_format) {
            bytes = bytes.saturating_add(tag.size);
        }
    }
    (bytes, values.len())
}

fn storage_status<'a>(
    tags: impl IntoIterator<Item = &'a StorageTag>,
    quota_bytes: u64,
    available_bytes: u64,
    min_free_bytes: u64,
    sampled_at_ms: u64,
) -> AttachmentStorageStatus {
    let tags = tags.into_iter().collect::<Vec<_>>();
    let (tagged_bytes, tagged_blobs) = unique_storage_usage(tags.iter().copied());
    let over_quota = tagged_bytes > quota_bytes;
    let below_min_free = available_bytes < min_free_bytes;
    AttachmentStorageStatus {
        tagged_bytes,
        tagged_blobs,
        tags: tags.len(),
        tag_capacity: MAX_ATTACHMENT_TAGS,
        quota_bytes,
        available_bytes,
        min_free_bytes,
        pressure: over_quota || below_min_free,
        over_quota,
        below_min_free,
        sampled_at_ms,
    }
}

fn hash_file(path: &Path) -> Result<iroh_blobs::Hash> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(iroh_blobs::Hash::from_bytes(*hasher.finalize().as_bytes()))
}

fn storage_operation_error(
    default_code: &str,
    error: &anyhow::Error,
    share: bool,
    operation_id: Option<&str>,
    offer_id: Option<&str>,
) -> serde_json::Value {
    let message = format!("{error:#}");
    let has_code = |expected: &str| {
        error
            .chain()
            .any(|cause| cause.to_string().starts_with(expected))
    };
    let (code, outcome, retryable) = if has_code("attachment_quota_exceeded:") {
        ("attachment_quota_exceeded", "not_started", false)
    } else if has_code("attachment_min_free_space:") {
        ("attachment_min_free_space", "not_started", true)
    } else if has_code("attachment_tag_capacity:") {
        ("attachment_tag_capacity", "not_started", false)
    } else if has_code("attachment_storage_busy:") {
        ("attachment_storage_busy", "not_started", true)
    } else {
        (
            default_code,
            if share || default_code.starts_with("offers_") {
                "unknown"
            } else {
                "not_started"
            },
            true,
        )
    };
    let code = if default_code.starts_with("offers_") && code == default_code {
        "attachment_lifecycle_internal"
    } else {
        code
    };
    let mut response = LifecycleErrorV1::new(code, message, outcome, retryable);
    response.operation_id = operation_id.map(str::to_owned);
    response.offer_id = offer_id.map(str::to_owned);
    response.into_value()
}

fn try_admit_transfer(
    limit: &Arc<Semaphore>,
    busy_code: &'static str,
    busy_message: &'static str,
) -> Result<OwnedSemaphorePermit, serde_json::Value> {
    limit
        .clone()
        .try_acquire_owned()
        .map_err(|_| serde_json::json!({"type":"error", "code":busy_code, "message":busy_message}))
}

struct ShareResources {
    store: Store,
    storage: AttachmentStorage,
    endpoint: Endpoint,
    secret: SecretKey,
    topic: TopicId,
    sender: GossipSender,
    state_dir: PathBuf,
}

async fn share_attachment(
    resources: ShareResources,
    operation_id: String,
    source_digest: String,
    path: PathBuf,
    max_attachment_bytes: u64,
) -> Result<serde_json::Value> {
    let ShareResources {
        store,
        storage,
        endpoint,
        secret,
        topic,
        sender,
        state_dir,
    } = resources;
    storage.preflight_free_space(0).await?;
    let metadata = tokio::fs::symlink_metadata(&path)
        .await
        .with_context(|| format!("inspect shared path {}", path.display()))?;
    anyhow::ensure!(
        !metadata.file_type().is_symlink(),
        "symbolic links cannot be shared"
    );
    let directory = metadata.is_dir();
    anyhow::ensure!(
        directory || metadata.is_file(),
        "shared path must be a regular file or directory"
    );
    let name = attachment::file_name(&path, directory)?;
    let staging = attachment::staging_file_near(
        &state_dir.join("attachment-stage"),
        if directory { ".tar" } else { ".blob" },
    )?;
    let source = path.clone();
    let expected_digest = source_digest.clone();
    let staged = tokio::task::spawn_blocking(move || {
        let staged = attachment::StagedFile::new(staging);
        let size = if directory {
            attachment::create_deterministic_tar(&source, staged.path(), max_attachment_bytes)?
        } else {
            attachment::copy_bounded(&source, staged.path(), max_attachment_bytes)?
        };
        let actual_digest =
            attachment::staged_share_digest(staged.path(), directory, max_attachment_bytes)?;
        anyhow::ensure!(
            actual_digest == expected_digest,
            "shared source digest does not match the staged content"
        );
        Ok::<_, anyhow::Error>((size, staged))
    })
    .await
    .context("attachment staging task failed")??;
    let (size, staged) = staged;
    storage.preflight_free_space(size).await?;
    let staged_path = staged.path().to_owned();
    let content_hash = tokio::task::spawn_blocking(move || hash_file(&staged_path))
        .await
        .context("attachment hash task failed")??;
    let offer_id = operation_id;
    let kind = if directory {
        AttachmentKind::DirectoryTarV1
    } else {
        AttachmentKind::File
    };
    let tag_name = outbound_blob_tag(&offer_id, kind, &name);
    let imported = store
        .blobs()
        .add_path(staged.path())
        .temp_tag()
        .await
        .context("import attachment with a temporary pin")?;
    drop(staged);
    anyhow::ensure!(
        imported.format() == BlobFormat::Raw && imported.hash() == content_hash,
        "attachment_lifecycle_internal: imported attachment identity is unsupported or changed"
    );

    let publish_result = async {
        let ticket = BlobTicket::new(endpoint.addr(), imported.hash(), imported.format());
        let offer = AttachmentOffer {
            offer_id,
            kind,
            name,
            size,
            ticket: ticket.to_string(),
        };
        let body = attachment_body(&offer)?;
        let timestamp_ms = unix_timestamp_ms()?;
        let encoded = Envelope::encode_with_id_at(
            &secret,
            topic,
            EnvelopeKind::AttachmentOffer,
            body,
            operation_id_bytes(&offer.offer_id),
            timestamp_ms,
        )?;
        let message_id = Envelope::decode(&encoded, topic)
            .expect("locally encoded attachment envelope must decode")
            .message_id;
        storage
            .commit_pin(
                &tag_name,
                PinnedBlobTag {
                    direction: "outgoing",
                    offer_id: offer.offer_id.clone(),
                    provider: None,
                    name: offer.name.clone(),
                    kind: offer.kind,
                },
                imported.hash_and_format(),
                size,
                &|_| Ok(()),
            )
            .await
            .context("commit attachment pin before publication")?;
        // From this point an error cannot prove that no peer observed the offer.
        // Retain the committed pin for retry and remote availability.
        sender
            .broadcast(encoded.clone())
            .await
            .context("broadcast attachment offer after durable pin")?;
        Ok(serde_json::json!({
            "type":"attachment_shared", "schema_version":3,
            "from":secret.public().to_string(),
            "message_id":direct::id_string(&message_id), "timestamp_ms":timestamp_ms,
            "offer_id":offer.offer_id, "source_digest":source_digest,
            "kind":offer.kind, "name":offer.name, "size":offer.size,
            "ticket":offer.ticket, "offer":BASE64URL_NOPAD.encode(&encoded),
            "delivery_acknowledged":false
        }))
    }
    .await;

    publish_result
}

fn raw_ticket_offer_id(ticket: &BlobTicket) -> String {
    use sha2::{Digest, Sha256};

    let mut digest = Sha256::new();
    digest.update(b"meshmsg-raw-ticket-pin-v1\0");
    digest.update(ticket.addr().id.to_string().as_bytes());
    digest.update(b"\0");
    digest.update(ticket.hash().to_string().as_bytes());
    digest.update(b"\0raw");
    direct::id_string(
        &digest.finalize()[..16]
            .try_into()
            .expect("fixed digest prefix"),
    )
}

fn raw_ticket_blob_tag(ticket: &BlobTicket) -> String {
    inbound_blob_tag(
        ticket.addr().id,
        &raw_ticket_offer_id(ticket),
        AttachmentKind::File,
        "raw-ticket.blob",
    )
}

fn validate_declared_attachment_size(declared_size: Option<u64>, actual_size: u64) -> Result<()> {
    if let Some(declared_size) = declared_size {
        anyhow::ensure!(
            actual_size == declared_size,
            "provider size does not match the signed offer"
        );
    }
    Ok(())
}

struct DownloadResources {
    store: Store,
    storage: AttachmentStorage,
    topic: TopicId,
    downloader: Downloader,
    endpoint: Endpoint,
    lookup: MemoryLookup,
}

#[derive(Debug)]
struct DownloadCommitOutcome {
    destination_synced: bool,
    cleanup_complete: bool,
    warnings: Vec<String>,
}

struct DownloadCommit<'a> {
    store: &'a Store,
    tag_name: &'a [u8],
    hash_and_format: iroh_blobs::HashAndFormat,
    staging: attachment::StagedFile,
    output: &'a Path,
    kind: AttachmentKind,
    raw_export: bool,
    max_attachment_bytes: u64,
    pin_already_committed: bool,
}

/// Commits the local half of a download. The named blob pin is made durable
/// before the no-clobber destination operation. Once installation succeeds,
/// subsequent sync/cleanup errors are partial-success metadata, never a false
/// `download_failed` result that would make a safe retry impossible.
async fn commit_download(
    commit: DownloadCommit<'_>,
    fault: &(dyn Fn(&'static str) -> Result<()> + Sync),
) -> Result<DownloadCommitOutcome> {
    let DownloadCommit {
        store,
        tag_name,
        hash_and_format,
        staging,
        output,
        kind,
        raw_export,
        max_attachment_bytes,
        pin_already_committed,
    } = commit;
    if !pin_already_committed {
        fault("blob_tag_persist")?;
        store.tags().set(tag_name, hash_and_format).await?;
        fault("after_blob_tag_persist")?;
        fault("blob_tag_sync")?;
        store.sync_db().await?;
        fault("after_blob_tag_sync")?;
    }

    fault("destination_install")?;
    let directory = !raw_export && kind == AttachmentKind::DirectoryTarV1;
    let output_for_task = output.to_owned();
    let staging = tokio::task::spawn_blocking(move || {
        if directory {
            attachment::extract_staged_tar_no_clobber(
                &staging,
                &output_for_task,
                max_attachment_bytes,
            )?;
        } else {
            attachment::link_file_no_clobber(staging.path(), &output_for_task)?;
        }
        Ok::<_, anyhow::Error>(staging)
    })
    .await
    .context("install task failed")??;

    // The destination now exists. Do not return Err below this line: no-clobber
    // makes a retry unsuitable, so accurately report any durability/cleanup
    // degradation as a successful installation with warnings.
    let mut warnings = Vec::new();
    if let Err(error) = fault("after_destination_install") {
        warnings.push(format!(
            "interrupted after destination installation: {error}"
        ));
    }
    let content_synced = match fault("destination_sync") {
        Ok(()) => {
            let output_for_task = output.to_owned();
            match tokio::task::spawn_blocking(move || {
                attachment::sync_installed_destination(&output_for_task, directory)
            })
            .await
            {
                Ok(Ok(())) => true,
                Ok(Err(error)) => {
                    warnings.push(format!("installed content sync failed: {error}"));
                    false
                }
                Err(error) => {
                    warnings.push(format!("installed content sync task failed: {error}"));
                    false
                }
            }
        }
        Err(error) => {
            warnings.push(format!("installed content sync failed: {error}"));
            false
        }
    };
    let parent_synced = match fault("parent_sync") {
        Ok(()) => {
            let output_for_task = output.to_owned();
            match tokio::task::spawn_blocking(move || {
                attachment::sync_output_parent(&output_for_task)
            })
            .await
            {
                Ok(Ok(())) => true,
                Ok(Err(error)) => {
                    warnings.push(format!("installed output parent sync failed: {error}"));
                    false
                }
                Err(error) => {
                    warnings.push(format!("installed output parent sync task failed: {error}"));
                    false
                }
            }
        }
        Err(error) => {
            warnings.push(format!("installed output parent sync failed: {error}"));
            false
        }
    };
    let destination_synced = content_synced && parent_synced;
    if let Err(error) = fault("after_destination_sync") {
        warnings.push(format!("interrupted after destination sync: {error}"));
    }

    let cleanup_complete = match fault("staging_cleanup") {
        Ok(()) => match tokio::task::spawn_blocking(move || staging.cleanup()).await {
            Ok(Ok(())) => match fault("after_staging_cleanup") {
                Ok(()) => true,
                Err(error) => {
                    warnings.push(format!("interrupted after staging cleanup: {error}"));
                    true
                }
            },
            Ok(Err(error)) => {
                warnings.push(format!("installed output staging cleanup failed: {error}"));
                false
            }
            Err(error) => {
                warnings.push(format!("installed output cleanup task failed: {error}"));
                false
            }
        },
        Err(error) => {
            warnings.push(format!("installed output staging cleanup failed: {error}"));
            // Dropping the guard makes a final best-effort cleanup attempt.
            drop(staging);
            false
        }
    };

    Ok(DownloadCommitOutcome {
        destination_synced,
        cleanup_complete,
        warnings,
    })
}

async fn download_attachment(
    resources: DownloadResources,
    events: broadcast::Sender<serde_json::Value>,
    offer_token: String,
    output: PathBuf,
    max_attachment_bytes: u64,
    raw_export: bool,
) -> Result<serde_json::Value> {
    let DownloadResources {
        store,
        storage,
        topic,
        downloader,
        endpoint,
        lookup,
    } = resources;
    storage.preflight_free_space(0).await?;
    anyhow::ensure!(
        !output.exists(),
        "output already exists: {}",
        output.display()
    );
    // Validate the existing durability boundary before network or store work.
    let staging_path = attachment::staging_file_near(&output, ".download")?;
    let parsed_signed = parse_signed_offer_token(&offer_token, topic);
    let (offer, ticket, declared_size, raw_ticket) = match parsed_signed {
        Ok((offer, ticket)) => {
            let declared_size = Some(offer.size);
            (offer, ticket, declared_size, false)
        }
        Err(signed_error) => {
            let ticket: BlobTicket = offer_token.parse().map_err(|_| signed_error)?;
            anyhow::ensure!(
                ticket.format() == BlobFormat::Raw,
                "only raw blob tickets are supported"
            );
            let name = output
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or("attachment")
                .to_owned();
            (
                AttachmentOffer {
                    offer_id: raw_ticket_offer_id(&ticket),
                    kind: AttachmentKind::File,
                    name,
                    size: 0,
                    ticket: ticket.to_string(),
                },
                ticket,
                None,
                true,
            )
        }
    };
    anyhow::ensure!(
        ticket.format() == BlobFormat::Raw,
        "only raw attachment blob formats are supported by lifecycle storage"
    );
    if let Some(declared_size) = declared_size {
        anyhow::ensure!(
            declared_size <= max_attachment_bytes,
            "attachment exceeds the configured size limit of {max_attachment_bytes} bytes"
        );
    }
    lookup.add_endpoint_info(ticket.addr().clone());
    // Protect complete or partial content from periodic GC until installation
    // and creation of the durable inbound pin have both completed.
    let _download_pin = store
        .tags()
        .temp_tag(ticket.hash_and_format())
        .await
        .context("temporarily pin attachment download")?;
    let existing_size = match store.blobs().status(ticket.hash()).await? {
        iroh_blobs::api::proto::BlobStatus::Complete { size } => Some(size),
        _ => None,
    };
    let size = if let Some(size) = existing_size {
        size
    } else {
        let connection = tokio::time::timeout(
            ENDPOINT_ONLINE_TIMEOUT,
            endpoint.connect(ticket.addr().clone(), iroh_blobs::ALPN),
        )
        .await
        .context("attachment size check timed out")?
        .context("connect to attachment provider")?;
        let (verified_size, _) = tokio::time::timeout(
            ENDPOINT_ONLINE_TIMEOUT,
            get_verified_size(&connection, &ticket.hash()),
        )
        .await
        .context("attachment size check timed out")?
        .context("verify attachment size")?;
        anyhow::ensure!(
            verified_size <= max_attachment_bytes,
            "attachment exceeds the configured size limit of {max_attachment_bytes} bytes"
        );
        validate_declared_attachment_size(declared_size, verified_size)?;
        storage.preflight_free_space(verified_size).await?;
        let download = downloader.download(ticket.hash_and_format(), Some(ticket.addr().id));
        let mut progress = download
            .stream()
            .await
            .context("start attachment download")?;
        let transfer = async {
            let mut next_report = DOWNLOAD_PROGRESS_STEP;
            while let Some(item) = progress.next().await {
                match item {
                    DownloadProgressItem::Error(error) => {
                        anyhow::bail!("attachment download failed: {error}")
                    }
                    DownloadProgressItem::DownloadError => {
                        anyhow::bail!("attachment download failed")
                    }
                    DownloadProgressItem::Progress(received_bytes)
                        if received_bytes >= next_report || received_bytes == verified_size =>
                    {
                        let _ = events.send(serde_json::json!({
                            "type":"download_progress", "schema_version":1,
                            "received_bytes":received_bytes.min(verified_size),
                            "total_bytes":verified_size, "output":output
                        }));
                        next_report = received_bytes
                            .saturating_div(DOWNLOAD_PROGRESS_STEP)
                            .saturating_add(1)
                            .saturating_mul(DOWNLOAD_PROGRESS_STEP);
                    }
                    _ => {}
                }
            }
            Ok::<(), anyhow::Error>(())
        };
        tokio::time::timeout(TRANSFER_TIMEOUT, transfer)
            .await
            .context("attachment download timed out")??;
        match store.blobs().status(ticket.hash()).await? {
            iroh_blobs::api::proto::BlobStatus::Complete { size } => size,
            _ => anyhow::bail!("download did not produce a complete blob"),
        }
    };
    anyhow::ensure!(
        size <= max_attachment_bytes,
        "download exceeds the configured size limit of {max_attachment_bytes} bytes"
    );
    validate_declared_attachment_size(declared_size, size)
        .context("validate downloaded attachment size")?;
    let staging = attachment::StagedFile::new(staging_path);
    let export_store = store.clone();
    let export_hash = ticket.hash();
    let staging = tokio::spawn(async move {
        export_store
            .blobs()
            .export(export_hash, staging.path())
            .await
            .context("export downloaded attachment")?;
        attachment::sync_staged_file(staging.path())?;
        Ok::<_, anyhow::Error>(staging)
    })
    .await
    .context("attachment export task failed")??;
    let tag_name = if raw_ticket {
        raw_ticket_blob_tag(&ticket)
    } else {
        inbound_blob_tag(ticket.addr().id, &offer.offer_id, offer.kind, &offer.name)
    };
    let parsed_tag = parse_pinned_blob_tag(tag_name.as_bytes())
        .context("generated attachment tag is invalid")?;
    let newly_created = storage
        .commit_pin(
            &tag_name,
            parsed_tag,
            ticket.hash_and_format(),
            size,
            &|_| Ok(()),
        )
        .await
        .context("commit downloaded attachment pin")?;
    let commit_result = commit_download(
        DownloadCommit {
            store: &store,
            tag_name: tag_name.as_bytes(),
            hash_and_format: ticket.hash_and_format(),
            staging,
            output: &output,
            kind: offer.kind,
            raw_export,
            max_attachment_bytes,
            pin_already_committed: true,
        },
        &|_| Ok(()),
    )
    .await;
    let commit = match commit_result {
        Ok(commit) => commit,
        Err(error) => {
            storage
                .rollback_committed_pin(&tag_name, newly_created)
                .await
                .context("roll back pin after download installation failure")?;
            return Err(error);
        }
    };
    Ok(serde_json::json!({
        "type":"download_complete", "schema_version":1,
        "offer_id":offer.offer_id, "kind":offer.kind,
        "name":offer.name, "size":size, "from":ticket.addr().id.to_string(),
        "output":output, "installed":true, "pinned":true,
        "destination_synced":commit.destination_synced,
        "cleanup_complete":commit.cleanup_complete,
        "warnings":commit.warnings
    }))
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

fn local_peer_online(node: &RunningNode) -> bool {
    node.endpoint
        .home_relay_status()
        .get()
        .iter()
        .any(|status| status.is_connected())
        && node.receiver.is_joined()
}

fn peer_snapshot(
    node: &RunningNode,
    directory: &Directory,
    self_peer: &str,
    self_alias: Option<&str>,
    generated_at_ms: u64,
    directory_epoch: &str,
    directory_revision: u64,
) -> serde_json::Value {
    peer_api::snapshot_value(
        self_peer,
        self_alias,
        local_peer_online(node),
        generated_at_ms,
        directory_epoch,
        directory_revision,
        directory.peers(),
    )
}

async fn reject_local_client_at_capacity<S>(mut stream: S, write_timeout: Duration)
where
    S: AsyncWrite + Unpin,
{
    let error = ErrorEnvelopeV1::new(
        "ipc_capacity",
        "Local capacity is currently unavailable.",
        "not_started",
        true,
    );
    let _ = write_local_response(&mut stream, &error.into_value(), write_timeout).await;
}

struct LocalClientSession {
    commands: mpsc::Sender<DaemonCommand>,
    events: broadcast::Receiver<serde_json::Value>,
    connected: serde_json::Value,
    startup_peers: Option<serde_json::Value>,
    benchmark_busy: Arc<AtomicBool>,
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
    IPC_REQUEST_ID
        .scope(
            std::cell::RefCell::new(None),
            handle_local_client_with_timeouts(
                stream,
                session.commands,
                session.events,
                session.connected,
                session.startup_peers,
                session.benchmark_busy,
                timeouts,
            ),
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
        if let Err(error) = handle_admitted_local_client(stream, session, timeouts, permit).await {
            if !is_local_disconnect(&error) {
                eprintln!("local client error: {error:#}");
            }
        }
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

fn emit_peer_transitions(
    transitions: impl IntoIterator<Item = PeerTransition>,
    events: &broadcast::Sender<serde_json::Value>,
    json: bool,
    directory_epoch: &str,
    directory_revision: &mut u64,
) {
    for transition in transitions {
        let candidate_revision = directory_revision
            .checked_add(1)
            .expect("directory revision overflow");
        let value = peer_api::transition_value(transition, directory_epoch, candidate_revision);
        // The type-level field bounds make this unreachable; keep an explicit
        // final guard so future schema changes fail closed instead of creating
        // unexpectedly large subscription events.
        if serde_json::to_vec(&value)
            .is_ok_and(|encoded| encoded.len() <= MAX_PEER_LIFECYCLE_EVENT_BYTES)
        {
            *directory_revision = candidate_revision;
            let _ = events.send(value.clone());
            event(json, value);
        }
    }
}

fn direct_replay_status(health: crate::direct_replay::ReplayHealth) -> serde_json::Value {
    serde_json::json!({
        "available":health.available,
        "error":health.error,
    })
}

pub async fn run_daemon(
    dir: &Path,
    json: bool,
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
    let (direct_incoming_tx, mut direct_incoming_rx) = mpsc::channel(256);
    let startup = tokio::select! {
        result = tokio::time::timeout(
            STARTUP_TIMEOUT,
            start(&state, secret, dir, direct_incoming_tx),
        ) => result,
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
            node.direct_replay.shutdown().await?;
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
    let initial_storage_status = attachment_storage.status();

    // Expose IPC only after networking is ready, so clients never connect to a
    // socket whose daemon is still blocked during bootstrap.
    let (mut listener, _endpoint_guard) = bind_local_endpoint(dir, &state_lock).await?;
    let peer = node.endpoint.id().to_string();
    let started = serde_json::json!({
        "type":"daemon_started", "peer":peer, "topic":state.topic,
        "advertises_self":state.advertise_self, "has_invite":has_invite,
        "bootstrap_peer_count":bootstrap_peer_count, "self_advertised":self_advertised,
        "endpoint_online":true, "topic_joined":node.receiver.is_joined(),
        "alias":alias_config.effective(), "alias_enabled":alias_config.enabled(),
        "max_attachment_bytes":max_attachment_bytes,
        "attachment_storage":initial_storage_status,
        "attachment_retention_secs":attachment_retention_secs
    });
    event(json, started);

    let (command_tx, mut command_rx) = mpsc::channel(32);
    let (event_tx, _) = broadcast::channel(IPC_EVENT_CAPACITY);
    let benchmark_busy = Arc::new(AtomicBool::new(false));
    let transfer_limit = Arc::new(Semaphore::new(2));
    let offer_list_limit = Arc::new(Semaphore::new(1));
    let direct_limit = Arc::new(Semaphore::new(DIRECT_CONCURRENCY));
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
    if direct::validate_endpoint_addr(&node.endpoint.addr(), node.endpoint.id()).is_ok() {
        directory.pin(node.endpoint.addr())?;
    }
    let mut presence = tokio::time::interval(PRESENCE_INTERVAL);
    presence.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut presence_cleanup = tokio::time::interval(PRESENCE_CLEANUP_INTERVAL);
    presence_cleanup.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut presence_sources = PresenceSourceLimiter::default();
    let mut envelope_replay = EnvelopeReplayCache::default();
    let mut broadcast_sources = TransportSourceLimiter::default();
    let mut broadcast_rejections = RejectionSampler::default();
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
                        emit_peer_transitions(directory.cleanup(), &event_tx, json, &directory_epoch, &mut directory_revision);
                        let generated_at_ms = unix_timestamp_ms()?;
                        let startup_peers = peer_snapshot(
                            &node, &directory, &peer, alias_config.effective(), generated_at_ms,
                            &directory_epoch, directory_revision,
                        );
                        let connected = serde_json::json!({
                            "type":"connected", "peer":peer, "endpoint_online":true,
                            "topic_joined":node.receiver.is_joined(),
                            "alias":alias_config.effective(),
                            "ipc_capabilities":[API_CONTRACT_CAPABILITY, PRIVATE_SEND_CAPABILITY, PEER_DIRECTORY_CAPABILITY, WEB_DOWNLOAD_CAPABILITY, WEB_SHARE_CAPABILITY, IDEMPOTENT_MUTATIONS_CAPABILITY, ATTACHMENT_LIFECYCLE_CAPABILITY]
                        });
                        Ok(LocalClientSession {
                            commands: command_tx.clone(),
                            events: event_tx.subscribe(),
                            connected,
                            startup_peers: Some(startup_peers),
                            benchmark_busy: benchmark_busy.clone(),
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
                        Ok(timestamp_ms) => match Envelope::encode_with_id_at(
                            &node.secret, topic, EnvelopeKind::Message, body.clone(),
                            operation_id_bytes(&operation_id), timestamp_ms,
                        ) {
                            Ok(envelope) => match node.sender.broadcast(envelope).await {
                                Ok(()) => queued_event(
                                    &peer, operation_id_bytes(&operation_id), body, timestamp_ms
                                ),
                                Err(error) => serde_json::json!({"type":"error", "schema_version":1, "code":"send_failed", "message":error.to_string(), "outcome":"unknown", "retryable":true}),
                            },
                            Err(error) => serde_json::json!({"type":"error", "schema_version":1, "code":"invalid_message", "message":error.to_string(), "outcome":"not_started", "retryable":false}),
                        },
                        Err(error) => serde_json::json!({"type":"error", "schema_version":1, "code":"invalid_message", "message":error.to_string(), "outcome":"not_started", "retryable":false}),
                    };
                    let response = operation_cache.lock().expect("operation cache poisoned")
                        .complete(&operation_id, response, StdInstant::now());
                    if response["type"] == "queued" {
                        let _ = event_tx.send(response.clone());
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
                    emit_peer_transitions(directory.cleanup(), &event_tx, json, &directory_epoch, &mut directory_revision);
                    let address = match directory.resolve(&to) {
                        Ok(address) => address,
                        Err(error) => {
                            operation_cache.lock().expect("operation cache poisoned").complete(
                                &operation_id,
                                serde_json::json!({
                                    "type":"error", "schema_version":1,
                                    "code":"recipient_unresolved", "message":error.to_string(),
                                    "outcome":"not_started", "retryable":false
                                }),
                                StdInstant::now(),
                            );
                            continue;
                        }
                    };
                    let permit = match direct_limit.clone().try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            operation_cache.lock().expect("operation cache poisoned").complete(
                                &operation_id,
                                serde_json::json!({
                                    "type":"error", "schema_version":1,
                                    "code":"private_send_busy",
                                    "message":"private-message send capacity reached",
                                    "outcome":"not_started", "retryable":true
                                }),
                                StdInstant::now(),
                            );
                            continue;
                        }
                    };
                    let endpoint = node.endpoint.clone();
                    let secret = node.secret.clone();
                    let operation_cache = operation_cache.clone();
                    transfer_tasks.spawn(async move {
                        let _permit = permit;
                        let response = match direct::send(
                            endpoint, secret, topic, address, body,
                            operation_id_bytes(&operation_id),
                        ).await {
                            Ok(direct::DirectSendOutcome::Accepted(accepted)) => serde_json::json!({
                                "type":"private_accepted", "schema_version":3,
                                "to":accepted.recipient.to_string(),
                                "message_id":direct::id_string(&accepted.id),
                                "timestamp_ms":accepted.timestamp_ms,
                                "body_bytes":accepted.body_bytes,
                                "acceptance_acknowledged":true,
                                "duplicate_accepted":accepted.duplicate,
                                "durable":false, "read":false
                            }),
                            Ok(direct::DirectSendOutcome::Rejected(rejection)) => match rejection {
                                direct::DirectRejection::Conflict => serde_json::json!({
                                    "type":"error", "schema_version":1,
                                    "code":"private_message_conflict",
                                    "message":"recipient has the same message ID bound to different content",
                                    "outcome":"not_started", "retryable":false
                                }),
                                direct::DirectRejection::Busy => serde_json::json!({
                                    "type":"error", "schema_version":1,
                                    "code":"private_recipient_busy",
                                    "message":"recipient replay or delivery capacity is busy",
                                    "outcome":"not_started", "retryable":true
                                }),
                                direct::DirectRejection::Unavailable => serde_json::json!({
                                    "type":"error", "schema_version":1,
                                    "code":"private_replay_unavailable",
                                    "message":"recipient replay persistence is unavailable",
                                    "outcome":"not_started", "retryable":true
                                }),
                                direct::DirectRejection::DeliveryOutcomeUnknown => serde_json::json!({
                                    "type":"error", "schema_version":1,
                                    "code":"private_delivery_unknown",
                                    "message":"recipient durably recorded this message ID but cannot prove whether its volatile delivery was queued",
                                    "outcome":"unknown", "retryable":false
                                }),
                            },
                            Err(error) => serde_json::json!({
                                "type":"error", "schema_version":1,
                                "code":"private_send_failed", "message":format!("{error:#}"),
                                "outcome":"unknown", "retryable":true
                            }),
                        };
                        operation_cache.lock().expect("operation cache poisoned")
                            .complete(&operation_id, response, StdInstant::now());
                    });
                }
                Some(DaemonCommand::BenchMessage { body, timestamp_ms, cancel, reply }) => {
                    match Envelope::encode_at(
                        &node.secret, topic, EnvelopeKind::Message, body, timestamp_ms,
                    ) {
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
                    let replay_status = direct_replay_status(node.direct_replay.health());
                    let attachment_status = attachment_storage.status();
                    let _ = reply.send(serde_json::json!({
                        "type":"status", "running":true, "peer":peer, "topic":state.topic,
                        "advertises_self":state.advertise_self, "has_invite":has_invite,
                        "bootstrap_peer_count":bootstrap_peer_count,
                        "self_advertised":self_advertised, "neighbors":neighbors,
                        "endpoint_online":endpoint_online, "topic_joined":node.receiver.is_joined(),
                        "alias":alias_config.effective(),
                        "alias_enabled":alias_config.enabled(),
                        "captured_hostname":alias_config.hostname(),
                        "custom_alias":alias_config.custom(),
                        "advertised_aliases":directory.advertised_aliases(),
                        "ipc_capabilities":[API_CONTRACT_CAPABILITY, PRIVATE_SEND_CAPABILITY, PEER_DIRECTORY_CAPABILITY, WEB_DOWNLOAD_CAPABILITY, WEB_SHARE_CAPABILITY, IDEMPOTENT_MUTATIONS_CAPABILITY, ATTACHMENT_LIFECYCLE_CAPABILITY],
                        "operation_cache_capacity":OPERATION_CACHE_CAPACITY,
                        "operation_cache_ttl_ms":OPERATION_CACHE_TTL.as_millis() as u64,
                        "operation_cache_persistent":false,
                        "direct_replay_available":replay_status["available"],
                        "direct_replay_error":replay_status["error"],
                        "direct_replay_capacity":crate::direct_replay::MAX_REPLAY_ENTRIES,
                        "direct_replay_per_sender_capacity":crate::direct_replay::MAX_REPLAY_ENTRIES_PER_SENDER,
                        "direct_replay_queue_capacity":crate::direct_replay::REPLAY_QUEUE_CAPACITY,
                        "direct_replay_global_rate_per_second":crate::direct_replay::GLOBAL_RATE_PER_SECOND as u64,
                        "direct_replay_global_rate_burst":crate::direct_replay::GLOBAL_RATE_BURST as u64,
                        "direct_replay_sender_rate_per_second":crate::direct_replay::SENDER_RATE_PER_SECOND as u64,
                        "direct_replay_sender_rate_burst":crate::direct_replay::SENDER_RATE_BURST as u64,
                        "max_attachment_bytes":max_attachment_bytes,
                        "attachment_storage":attachment_status,
                        "attachment_retention_secs":attachment_retention_secs
                    }));
                }
                Some(DaemonCommand::Peers { reply }) => {
                    emit_peer_transitions(directory.cleanup(), &event_tx, json, &directory_epoch, &mut directory_revision);
                    let generated_at_ms = unix_timestamp_ms()?;
                    let _ = reply.send(peer_snapshot(
                        &node, &directory, &peer, alias_config.effective(), generated_at_ms,
                        &directory_epoch, directory_revision,
                    ));
                }
                Some(DaemonCommand::Offers { reply }) => {
                    let permit = match try_admit_transfer(
                        &offer_list_limit, "offers_busy", "attachment listing already in progress"
                    ) {
                        Ok(permit) => permit,
                        Err(response) => {
                            let _ = reply.send(response);
                            continue;
                        }
                    };
                    let store = node.blob_store.clone();
                    offer_list_tasks.spawn(async move {
                        let _permit = permit;
                        let response = match list_pinned_blobs(&store).await {
                            Ok((blobs, has_more, item_errors)) => {
                                serde_json::json!({
                                    "type":"offers", "schema_version":1, "blobs":blobs,
                                    "truncated":has_more, "has_more":has_more,
                                    "item_errors":item_errors
                                })
                            }
                            Err(error) => serde_json::json!({
                                "type":"error", "code":"offers_failed", "message":error.to_string()
                            }),
                        };
                        let _ = reply.send(response);
                    });
                }
                Some(DaemonCommand::OffersRemove { offer_id, direction, provider, reply }) => {
                    let valid_direction = direction.as_deref().is_none_or(|value| matches!(value, "incoming" | "outgoing"));
                    let provider = match provider {
                        Some(value) => match value.parse::<PublicKey>() {
                            Ok(key) if key.to_string() == value => Some(value),
                            _ => {
                                let mut error = LifecycleErrorV1::new(
                                    "invalid_offer_selector", "provider must be a canonical public key",
                                    "not_started", false,
                                );
                                error.offer_id = Some(offer_id.clone());
                                let _ = reply.send(error.into_value());
                                continue;
                            }
                        },
                        None => None,
                    };
                    if !valid_offer_id(&offer_id) || !valid_direction {
                        let mut error = LifecycleErrorV1::new(
                            "invalid_offer_selector", "offer ID or direction is invalid",
                            "not_started", false,
                        );
                        if valid_offer_id(&offer_id) { error.offer_id = Some(offer_id.clone()); }
                        let _ = reply.send(error.into_value());
                        continue;
                    }
                    let storage = attachment_storage.clone();
                    offer_list_tasks.spawn(async move {
                        let response = match storage.remove(
                            Some(&offer_id), direction.as_deref(), provider.as_deref(), None,
                            MAX_PRUNE_TAGS, false,
                        ).await {
                            Ok(value) => value,
                            Err(error) => storage_operation_error("offers_remove_failed", &error, false, None, Some(&offer_id)),
                        };
                        let _ = reply.send(response);
                    });
                }
                Some(DaemonCommand::OffersPrune { older_than_secs, direction, dry_run, max_delete, reply }) => {
                    if !direction.as_deref().is_none_or(|value| matches!(value, "incoming" | "outgoing"))
                        || !(1..=MAX_PRUNE_TAGS).contains(&max_delete)
                    {
                        let _ = reply.send(LifecycleErrorV1::new(
                            "invalid_prune_request", "prune direction or maximum is invalid",
                            "not_started", false,
                        ).into_value());
                        continue;
                    }
                    let age = older_than_secs.unwrap_or(attachment_retention_secs);
                    let storage = attachment_storage.clone();
                    offer_list_tasks.spawn(async move {
                        let response = match storage.remove(
                            None, direction.as_deref(), None, Some(age), max_delete, dry_run,
                        ).await {
                            Ok(value) => value,
                            Err(error) => storage_operation_error("offers_prune_failed", &error, false, None, None),
                        };
                        let _ = reply.send(response);
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
                            let mut response = LifecycleErrorV1::new(
                                "attachment_storage_busy", "attachment transfer capacity reached",
                                "not_started", true,
                            );
                            response.operation_id = Some(operation_id.clone());
                            operation_cache.lock().expect("operation cache poisoned")
                                .complete(&operation_id, response.into_value(), StdInstant::now());
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
                        let storage_permit = storage.gate.clone().acquire_owned().await;
                        let response = match storage_permit {
                            Ok(_storage_permit) => match share_attachment(
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
                        ).await {
                            Ok(value) => value,
                            Err(error) => storage_operation_error("share_failed", &error, true, Some(&operation_id), None),
                        },
                            Err(_) => {
                                let mut error = LifecycleErrorV1::new(
                                    "attachment_storage_shutdown", "attachment storage is shutting down",
                                    "not_started", true,
                                );
                                error.operation_id = Some(operation_id.clone());
                                error.into_value()
                            },
                        };
                        let response = operation_cache.lock().expect("operation cache poisoned")
                            .complete(&operation_id, response, StdInstant::now());
                        if response["type"] == "attachment_shared" {
                            let _ = events.send(response);
                        }
                    });
                }
                Some(DaemonCommand::Download { offer, output, raw_export, reply }) => {
                    let permit = match try_admit_transfer(
                        &transfer_limit, "download_busy", "attachment transfer capacity reached"
                    ) {
                        Ok(permit) => permit,
                        Err(_) => {
                            let _ = reply.send(LifecycleErrorV1::new(
                                "attachment_storage_busy", "attachment transfer capacity reached",
                                "not_started", true,
                            ).into_value());
                            continue;
                        }
                    };
                    let store = node.blob_store.clone();
                    let storage = attachment_storage.clone();
                    let downloader = node.downloader.clone();
                    let endpoint = node.endpoint.clone();
                    let lookup = node.lookup.clone();
                    let events = event_tx.clone();
                    transfer_tasks.spawn(async move {
                        let _permit = permit;
                        let storage_permit = storage.gate.clone().acquire_owned().await;
                        let response = match storage_permit {
                            Ok(_storage_permit) => {
                        let started = serde_json::json!({"type":"download_started", "schema_version":1, "output":output});
                        let _ = events.send(started);
                        match download_attachment(
                            DownloadResources {
                                store,
                                storage,
                                topic,
                                downloader,
                                endpoint,
                                lookup,
                            },
                            events.clone(),
                            offer,
                            output,
                            max_attachment_bytes,
                            raw_export,
                        ).await {
                            Ok(value) => value,
                            Err(error) => storage_operation_error("download_failed", &error, false, None, None),
                        }
                            }
                            Err(_) => LifecycleErrorV1::new(
                                "attachment_storage_shutdown", "attachment storage is shutting down",
                                "not_started", true,
                            ).into_value(),
                        };
                        if response["type"] == "download_complete" {
                            let _ = events.send(response.clone());
                        }
                        let _ = reply.send(response);
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
                        if let Ok(record) = direct::encode_presence(
                            &node.secret,
                            topic,
                            alias_config.effective(),
                            node.endpoint.addr(),
                        ) {
                            let _ = node.presence_sender.broadcast(record).await;
                        }
                    }
                    let values = network_event(
                        value,
                        topic,
                        &mut envelope_replay,
                        &mut broadcast_sources,
                        &mut broadcast_rejections,
                        unix_timestamp_ms()?,
                    );
                    for full_value in values {
                        let _ = event_tx.send(full_value.clone());
                        event(json, suppress_message_body(full_value));
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
                        emit_peer_transitions(directory.cleanup(), &event_tx, json, &directory_epoch, &mut directory_revision);
                        if let Ok(Some(transition)) = directory.receive(&message.content, topic) {
                            emit_peer_transitions([transition], &event_tx, json, &directory_epoch, &mut directory_revision);
                        }
                    }
                }
                Some(Event::NeighborDown(source)) => presence_sources.remove(source),
                Some(Event::NeighborUp(_) | Event::Lagged) => {}
                None => break,
            },
            incoming = direct_incoming_rx.recv() => {
                if let Some(message) = incoming {
                    let value = private_message_event(message);
                    let _ = event_tx.send(value.clone());
                    event(json, suppress_message_body(value));
                }
            },
            _ = presence.tick() => {
                if let Ok(record) = direct::encode_presence(
                    &node.secret,
                    topic,
                    alias_config.effective(),
                    node.endpoint.addr(),
                ) {
                    let _ = node.presence_sender.broadcast(record).await;
                }
            },
            _ = presence_cleanup.tick() => {
                emit_peer_transitions(directory.cleanup(), &event_tx, json, &directory_epoch, &mut directory_revision);
                presence_sources.cleanup();
            },
            _ = attachment_space_refresh.tick() => {
                let storage = attachment_storage.clone();
                offer_list_tasks.spawn(async move {
                    if let Err(error) = storage.refresh_free_space().await {
                        eprintln!("attachment free-space refresh failed: {error:#}");
                    }
                });
            }
            _ = retention_check.tick(), if attachment_retention_secs != 0 => {
                let storage = attachment_storage.clone();
                offer_list_tasks.spawn(async move {
                    if let Err(error) = storage.automatic_retention_pass().await {
                        if !error.to_string().starts_with("attachment_storage_busy:") {
                            eprintln!("automatic attachment prune failed: {error:#}");
                        }
                    }
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
                if let Some(Err(error)) = completed {
                    eprintln!("local client task error: {error}");
                }
            },
            completed = transfer_tasks.join_next(), if !transfer_tasks.is_empty() => {
                if let Some(Err(error)) = completed {
                    eprintln!("attachment task error: {error}");
                }
            },
            completed = offer_list_tasks.join_next(), if !offer_list_tasks.is_empty() => {
                if let Some(Err(error)) = completed {
                    eprintln!("attachment listing task error: {error}");
                }
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
    direct_limit.close();
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

fn received_envelope_event(envelope: Envelope, encoded: &[u8]) -> serde_json::Value {
    if envelope.kind == EnvelopeKind::Message {
        return message_event(envelope);
    }
    match parse_attachment_body(&envelope.body) {
        Ok(Some(offer)) => match offer.ticket.parse::<BlobTicket>() {
            Ok(ticket) if ticket.addr().id == envelope.from => {
                offer_event(envelope, encoded, offer)
            }
            Ok(_) => {
                serde_json::json!({"type":"error", "code":"invalid_attachment_offer", "message":"attachment provider does not match its signature"})
            }
            Err(error) => {
                serde_json::json!({"type":"error", "code":"invalid_attachment_offer", "message":error.to_string()})
            }
        },
        // The prefix predates typed attachments as valid signed message text.
        // Only a fully valid typed payload opts into attachment semantics.
        Ok(None) | Err(_) => serde_json::json!({
            "type":"error", "code":"invalid_attachment_offer",
            "message":"attachment envelope does not contain a valid offer"
        }),
    }
}

fn network_event(
    value: Event,
    topic: TopicId,
    replay: &mut EnvelopeReplayCache,
    sources: &mut TransportSourceLimiter,
    rejections: &mut RejectionSampler,
    now_ms: u64,
) -> Vec<serde_json::Value> {
    match value {
        Event::Received(message) => {
            let source = message.delivered_from;
            if !sources.allow(source, now_ms) {
                return rejections
                    .event(now_ms, "broadcast transport source rate limit exceeded")
                    .into_iter()
                    .collect();
            }
            match Envelope::decode(&message.content, topic).and_then(|envelope| {
                replay.accept(&envelope, source, now_ms)?;
                Ok(envelope)
            }) {
                Ok(envelope) => {
                    let event = received_envelope_event(envelope, &message.content);
                    if event["type"] == "error" {
                        return rejections
                            .event(
                                now_ms,
                                event["message"]
                                    .as_str()
                                    .unwrap_or("invalid broadcast message"),
                            )
                            .into_iter()
                            .collect();
                    }
                    vec![event]
                }
                Err(error) => rejections
                    .event(now_ms, &error.to_string())
                    .into_iter()
                    .collect(),
            }
        }
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

fn queued_event(
    peer: &str,
    message_id: [u8; 16],
    body: String,
    timestamp_ms: u64,
) -> serde_json::Value {
    serde_json::json!({
        "type":"queued", "schema_version":3,
        "from":peer, "operation_id":direct::id_string(&message_id),
        "message_id":direct::id_string(&message_id),
        "timestamp_ms":timestamp_ms, "body":body,
        "delivery_acknowledged":false
    })
}

fn message_event(msg: Envelope) -> serde_json::Value {
    serde_json::json!({
        "type":"message", "schema_version":2, "from":msg.from.to_string(),
        "message_id":direct::id_string(&msg.message_id),
        "timestamp_ms":msg.timestamp_ms, "body":msg.body
    })
}

fn private_message_event(msg: IncomingDirect) -> serde_json::Value {
    serde_json::json!({
        "type":"private_message", "schema_version":1, "private":true,
        "from":msg.from.to_string(), "message_id":direct::id_string(&msg.id),
        "timestamp_ms":msg.timestamp_ms, "body":msg.body,
        "acceptance_acknowledged":true, "durable":false, "read":false
    })
}

fn suppress_message_body(value: serde_json::Value) -> serde_json::Value {
    if value["type"] == "message" {
        return serde_json::json!({
            "type":"message", "from":value["from"], "message_id":value["message_id"],
            "timestamp_ms":value["timestamp_ms"],
            "body_bytes":value["body"].as_str().map(str::len).unwrap_or(0), "body_suppressed":true
        });
    }
    if value["type"] == "private_message" {
        return serde_json::json!({
            "type":"private_message", "from":value["from"],
            "message_id":value["message_id"], "timestamp_ms":value["timestamp_ms"],
            "body_bytes":value["body"].as_str().map(str::len).unwrap_or(0),
            "body_suppressed":true, "private":true
        });
    }
    if value["type"] == "attachment_offer" {
        return serde_json::json!({
            "type":"attachment_offer", "from":value["from"],
            "message_id":value["message_id"], "timestamp_ms":value["timestamp_ms"],
            "size":value["size"],
            "details_suppressed":true
        });
    }
    value
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

fn ensure_success(value: &serde_json::Value) -> Result<()> {
    if value["type"] == "error" {
        anyhow::bail!("daemon rejected request: {}", daemon_error_message(value));
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateAcceptedResponse {
    #[serde(rename = "type")]
    kind: String,
    schema_version: u64,
    request_id: String,
    operation_id: String,
    to: String,
    message_id: String,
    timestamp_ms: u64,
    body_bytes: usize,
    acceptance_acknowledged: bool,
    duplicate_accepted: bool,
    durable: bool,
    read: bool,
}

fn validate_private_acceptance(
    value: &serde_json::Value,
    operation_id: &str,
    body_bytes: usize,
) -> Result<()> {
    let accepted: PrivateAcceptedResponse = serde_json::from_value(value.clone())
        .context("daemon returned an invalid private-send acceptance")?;
    anyhow::ensure!(
        accepted.kind == "private_accepted"
            && accepted.schema_version == 3
            && accepted.acceptance_acknowledged
            && !accepted.durable
            && !accepted.read,
        "daemon returned an invalid private-send acceptance"
    );
    anyhow::ensure!(
        contracts::valid_request_id(&accepted.request_id),
        "private-send acceptance request ID is invalid"
    );
    let _duplicate_accepted = accepted.duplicate_accepted;
    anyhow::ensure!(
        accepted.operation_id == operation_id && accepted.message_id == operation_id,
        "private-send acceptance operation ID does not match the request"
    );
    let recipient = accepted
        .to
        .parse::<PublicKey>()
        .context("private-send acceptance contains an invalid recipient")?;
    anyhow::ensure!(
        recipient.to_string() == accepted.to,
        "private-send acceptance recipient is not canonical"
    );
    anyhow::ensure!(
        accepted.message_id.len() == 32
            && accepted
                .message_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "private-send acceptance contains an invalid message ID"
    );
    anyhow::ensure!(
        accepted.timestamp_ms != 0 && accepted.body_bytes == body_bytes,
        "private-send acceptance metadata does not match the request"
    );
    Ok(())
}

fn advertises_capability(status: &serde_json::Value, expected: &str) -> bool {
    status["type"] == "status"
        && status["ipc_capabilities"]
            .as_array()
            .is_some_and(|capabilities| {
                capabilities
                    .iter()
                    .any(|capability| capability.as_str() == Some(expected))
            })
}

fn advertises_private_send(status: &serde_json::Value) -> bool {
    advertises_capability(status, PRIVATE_SEND_CAPABILITY)
}

pub async fn send_once(
    dir: &Path,
    operation_id: Option<String>,
    to: Option<&str>,
    body: &str,
    json: bool,
) -> Result<()> {
    let operation_id = operation_id.unwrap_or_else(crate::ipc::new_operation_id);
    let status = send_request_checked(dir, &IpcRequest::Status, "status", None).await?;
    anyhow::ensure!(
        advertises_capability(&status, IDEMPOTENT_MUTATIONS_CAPABILITY),
        "daemon does not advertise retry-safe operation IDs; upgrade and restart the daemon (operation was not submitted)"
    );
    let value = if let Some(to) = to {
        // Negotiate without the body first. A daemon swap after this check is
        // still safe because private_send is never interpreted as broadcast.
        anyhow::ensure!(
            advertises_private_send(&status),
            "daemon does not advertise safe private-send IPC; upgrade and restart the daemon (message was not submitted)"
        );
        let value = send_request_checked(
            dir,
            &IpcRequest::PrivateSend {
                operation_id: operation_id.clone(),
                to: to.to_owned(),
                body: body.to_owned(),
            },
            "private_accepted",
            Some(3),
        )
        .await
        .with_context(|| format!("operation {operation_id}"))?;
        validate_private_acceptance(&value, &operation_id, body.len())?;
        value
    } else {
        let value = send_request_checked(
            dir,
            &IpcRequest::Send {
                operation_id: operation_id.clone(),
                body: body.to_owned(),
            },
            "queued",
            Some(3),
        )
        .await
        .with_context(|| format!("operation {operation_id}"))?;
        anyhow::ensure!(
            value["operation_id"].as_str() == Some(&operation_id)
                && value["message_id"].as_str() == Some(&operation_id),
            "daemon returned mismatched broadcast operation metadata"
        );
        value
    };
    event(json, value);
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
    let status = send_request_checked(dir, &IpcRequest::Status, "status", None).await?;
    anyhow::ensure!(
        advertises_capability(&status, IDEMPOTENT_MUTATIONS_CAPABILITY),
        "daemon does not advertise retry-safe operation IDs; upgrade and restart the daemon (operation was not submitted)"
    );
    let path = caller_path(path)?;
    let maximum = status["max_attachment_bytes"]
        .as_u64()
        .context("daemon status omitted its attachment limit")?;
    let digest_path = path.clone();
    let source_digest =
        tokio::task::spawn_blocking(move || attachment::share_source_digest(&digest_path, maximum))
            .await
            .context("attachment digest task failed")??;
    let value = send_lifecycle_request(
        dir,
        &IpcRequest::Share {
            operation_id: operation_id.clone(),
            source_digest: source_digest.clone(),
            path,
        },
        "attachment_shared",
        3,
        Some(&operation_id),
        None,
    )
    .await
    .with_context(|| format!("operation {operation_id}"))?;
    anyhow::ensure!(
        value["operation_id"].as_str() == Some(&operation_id)
            && value["message_id"].as_str() == Some(&operation_id)
            && value["offer_id"].as_str() == Some(&operation_id)
            && value["source_digest"].as_str() == Some(&source_digest),
        "daemon returned mismatched share operation metadata"
    );
    event(json, value);
    Ok(())
}

pub async fn peers(dir: &Path, json: bool) -> Result<()> {
    // Negotiate before sending a command that legacy daemons do not know. A
    // daemon swap remains safe because `peers` is a distinct, fieldless command
    // and all IPC enums reject unknown fields.
    let status = send_request_checked(dir, &IpcRequest::Status, "status", None).await?;
    anyhow::ensure!(
        advertises_capability(&status, PEER_DIRECTORY_CAPABILITY),
        "daemon does not advertise peer-directory IPC; upgrade and restart the daemon"
    );
    let value = send_request_checked(
        dir,
        &IpcRequest::Peers,
        "peers_snapshot",
        Some(peer_api::PEER_SCHEMA_VERSION.into()),
    )
    .await
    .context("request peer directory; the daemon may need to be upgraded and restarted")?;
    event(json, value);
    Ok(())
}

pub async fn offers(dir: &Path, json: bool) -> Result<()> {
    let value = send_request_checked(dir, &IpcRequest::Offers, "offers", Some(1)).await?;
    event(json, value);
    Ok(())
}

async fn send_lifecycle_request(
    dir: &Path,
    request: &IpcRequest,
    expected_type: &str,
    expected_schema_version: u64,
    expected_operation_id: Option<&str>,
    expected_offer_id: Option<&str>,
) -> Result<serde_json::Value> {
    let value = crate::ipc::send_request(dir, request).await?;
    if value.get("type").and_then(serde_json::Value::as_str) == Some("error") {
        let error = LifecycleErrorV1::from_value(&value)?;
        anyhow::ensure!(
            expected_operation_id.is_none_or(|id| error.operation_id.as_deref() == Some(id)),
            "daemon lifecycle error operation ID does not match the request"
        );
        anyhow::ensure!(
            expected_offer_id.is_none_or(|id| error.offer_id.as_deref() == Some(id)),
            "daemon lifecycle error offer ID does not match the request"
        );
        return Err(anyhow::Error::new(contracts::ContractFailure(error)));
    }
    crate::ipc::validate_response(&value, expected_type, Some(expected_schema_version))?;
    Ok(value)
}

pub async fn offers_remove(
    dir: &Path,
    offer_id: &str,
    direction: Option<&str>,
    provider: Option<&str>,
    json: bool,
) -> Result<()> {
    let status = send_request_checked(dir, &IpcRequest::Status, "status", None).await?;
    anyhow::ensure!(
        advertises_capability(&status, ATTACHMENT_LIFECYCLE_CAPABILITY),
        "daemon does not advertise attachment lifecycle IPC; upgrade and restart the daemon"
    );
    let value = send_lifecycle_request(
        dir,
        &IpcRequest::OffersRemove {
            offer_id: offer_id.to_owned(),
            direction: direction.map(str::to_owned),
            provider: provider.map(str::to_owned),
        },
        "offer_removed",
        1,
        None,
        Some(offer_id),
    )
    .await?;
    validate_lifecycle_response(&value, "offer_removed")?;
    event(json, value);
    Ok(())
}

pub async fn offers_prune(
    dir: &Path,
    older_than_secs: Option<u64>,
    direction: Option<&str>,
    dry_run: bool,
    max_delete: usize,
    json: bool,
) -> Result<()> {
    let status = send_request_checked(dir, &IpcRequest::Status, "status", None).await?;
    anyhow::ensure!(
        advertises_capability(&status, ATTACHMENT_LIFECYCLE_CAPABILITY),
        "daemon does not advertise attachment lifecycle IPC; upgrade and restart the daemon"
    );
    let value = send_lifecycle_request(
        dir,
        &IpcRequest::OffersPrune {
            older_than_secs,
            direction: direction.map(str::to_owned),
            dry_run,
            max_delete,
        },
        "offers_pruned",
        1,
        None,
        None,
    )
    .await?;
    validate_lifecycle_response(&value, "offers_pruned")?;
    event(json, value);
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LifecycleResponse {
    #[serde(rename = "type")]
    kind: String,
    schema_version: u8,
    request_id: String,
    dry_run: bool,
    selected_tags: usize,
    removed_tags: usize,
    released_bytes: u64,
    limited: bool,
    cutoff_ms: Option<u64>,
}

fn validate_lifecycle_response(value: &serde_json::Value, expected: &str) -> Result<()> {
    let response: LifecycleResponse = serde_json::from_value(value.clone())
        .context("daemon returned an invalid attachment lifecycle response")?;
    anyhow::ensure!(
        response.kind == expected && response.schema_version == 1,
        "daemon returned an invalid attachment lifecycle response"
    );
    anyhow::ensure!(
        contracts::valid_request_id(&response.request_id),
        "daemon lifecycle response request ID is invalid"
    );
    anyhow::ensure!(
        response.removed_tags <= response.selected_tags,
        "daemon returned impossible attachment lifecycle counts"
    );
    let _ = (
        response.dry_run,
        response.released_bytes,
        response.limited,
        response.cutoff_ms,
    );
    Ok(())
}

pub async fn download(dir: &Path, offer: &str, output: &Path, json: bool) -> Result<()> {
    let value = send_lifecycle_request(
        dir,
        &IpcRequest::Download {
            offer: offer.to_owned(),
            output: caller_path(output)?,
        },
        "download_complete",
        1,
        None,
        None,
    )
    .await?;
    event(json, value);
    Ok(())
}

fn generated_run_id() -> String {
    rand::random::<[u8; 16]>()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
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
        Some("bench_send_progress" | "bench_receive_progress") => {}
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

const BENCH_CLIENT_STARTUP_TIMEOUT: Duration = Duration::from_secs(10);

async fn await_bench_startup<T>(
    startup: impl std::future::Future<Output = Result<T>>,
    cancellation: &mut oneshot::Receiver<()>,
    timeout: Duration,
) -> Result<T> {
    tokio::select! {
        result = startup => result,
        _ = cancellation => anyhow::bail!("benchmark interrupted during daemon handshake"),
        _ = tokio::time::sleep(timeout) => anyhow::bail!("timed out waiting for daemon benchmark handshake"),
    }
}

fn benchmark_subscription_value(
    result: Result<Option<serde_json::Value>>,
    stopped_message: &'static str,
    read_context: &'static str,
) -> Result<serde_json::Value> {
    match result {
        Ok(Some(value)) => Ok(value),
        Ok(None) => anyhow::bail!(stopped_message),
        Err(error) => Err(error).context(read_context),
    }
}

fn disconnected_send_summary(
    config: &BenchConfig,
    total: u64,
    latest_progress: Option<&serde_json::Value>,
    elapsed: Duration,
    request_id: &str,
) -> serde_json::Value {
    if let Some(progress) = latest_progress {
        let mut summary = progress.clone();
        let object = summary
            .as_object_mut()
            .expect("benchmark progress is an object");
        object.insert("type".into(), "bench_send_summary".into());
        object.insert("completion_reason".into(), "daemon_stopped".into());
        object.insert("first_error".into(), serde_json::Value::Null);
        summary
    } else {
        contracts::correlate(
            bench_send_summary(
                config,
                total,
                &BenchSendStats::default(),
                "daemon_stopped",
                elapsed,
            ),
            request_id,
        )
    }
}

fn emit_bench_progress(events: &mpsc::Sender<serde_json::Value>, value: serde_json::Value) {
    // Progress is best-effort. Never let a blocked renderer or stdout pipe
    // perturb the benchmark's scheduling or subscription consumption.
    let _ = events.try_send(value);
}

async fn emit_bench_terminal(events: &mpsc::Sender<serde_json::Value>, value: serde_json::Value) {
    // Started and summary records are part of the stable stream contract.
    let _ = events.send(value).await;
}

async fn bench_send_events(
    dir: &Path,
    run_id: Option<String>,
    rate: u32,
    duration_secs: u64,
    payload_bytes: usize,
    events: mpsc::Sender<serde_json::Value>,
    mut cancellation: oneshot::Receiver<()>,
) -> Result<()> {
    let config = BenchConfig {
        run_id: run_id.unwrap_or_else(generated_run_id),
        rate,
        duration_secs,
        payload_bytes,
    };
    let total = validate_bench_config(&config)?;
    let request_id = contracts::new_request_id();
    let startup = async {
        let mut stream = connect_daemon(dir).await?;
        write_request_with_id(
            &mut stream,
            &IpcRequest::BenchSend {
                config: config.clone(),
            },
            &request_id,
        )
        .await?;
        let mut reader = SubscriptionReader::new_correlated(stream, request_id.clone());
        let started = reader
            .read()
            .await?
            .context("local daemon stopped before benchmark start")?;
        Result::<_>::Ok((reader, started))
    };
    let (mut reader, started) =
        await_bench_startup(startup, &mut cancellation, BENCH_CLIENT_STARTUP_TIMEOUT).await?;
    ensure_success(&started)?;
    anyhow::ensure!(
        started["type"] == "bench_send_started",
        "unexpected benchmark response"
    );
    let client_started = StdInstant::now();
    emit_bench_terminal(&events, started).await;

    let mut latest_progress = None;
    let mut interrupted = false;
    let mut interrupted_deadline = None;
    let summary = loop {
        let value = tokio::select! {
            value = reader.read() => match benchmark_subscription_value(
                value,
                "local daemon stopped before benchmark summary",
                "read benchmark summary from local daemon",
            ) {
                Ok(value) => value,
                Err(error) => {
                    let summary = disconnected_send_summary(
                        &config,
                        total,
                        latest_progress.as_ref(),
                        client_started.elapsed(),
                        &request_id,
                    );
                    emit_bench_terminal(&events, summary).await;
                    return Err(error);
                }
            },
            result = &mut cancellation, if !interrupted => {
                let _ = result;
                reader.get_mut().write_all(b"\n").await?;
                interrupted = true;
                interrupted_deadline = Some(tokio::time::Instant::now() + Duration::from_secs(5));
                continue;
            }
            _ = async {
                match interrupted_deadline {
                    Some(deadline) => tokio::time::sleep_until(deadline).await,
                    None => std::future::pending().await,
                }
            }, if interrupted => {
                anyhow::bail!("timed out waiting for interrupted benchmark summary")
            }
        };
        ensure_success(&value)?;
        match value["type"].as_str() {
            Some("bench_send_progress") => {
                latest_progress = Some(value.clone());
                emit_bench_progress(&events, value);
            }
            Some("bench_send_summary") => break value,
            _ => anyhow::bail!("unexpected benchmark response"),
        }
    };
    emit_bench_terminal(&events, summary.clone()).await;
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

fn bench_output_worker(
    json: bool,
) -> (mpsc::Sender<serde_json::Value>, tokio::task::JoinHandle<()>) {
    let (events, mut output) = mpsc::channel(16);
    let worker = tokio::task::spawn_blocking(move || {
        while let Some(value) = output.blocking_recv() {
            print_bench_value(json, &value);
        }
    });
    (events, worker)
}

pub async fn bench_send(
    dir: &Path,
    run_id: Option<String>,
    rate: u32,
    duration_secs: u64,
    payload_bytes: usize,
    json: bool,
) -> Result<()> {
    let (cancel_tx, cancel_rx) = oneshot::channel();
    let signal = tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            let _ = cancel_tx.send(());
        } else {
            std::future::pending::<()>().await;
        }
    });
    let (events, output) = bench_output_worker(json);
    let result = bench_send_events(
        dir,
        run_id,
        rate,
        duration_secs,
        payload_bytes,
        events,
        cancel_rx,
    )
    .await;
    signal.abort();
    output.await.context("benchmark output worker failed")?;
    result
}

pub(crate) async fn bench_send_tui(
    dir: &Path,
    run_id: String,
    rate: u32,
    duration_secs: u64,
    payload_bytes: usize,
    events: mpsc::Sender<serde_json::Value>,
    cancellation: oneshot::Receiver<()>,
) -> Result<()> {
    bench_send_events(
        dir,
        Some(run_id),
        rate,
        duration_secs,
        payload_bytes,
        events,
        cancellation,
    )
    .await
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

    fn progress(&self, elapsed: Duration) -> serde_json::Value {
        // Keep live percentile work small enough that rendering cannot starve the
        // subscription loop. The final summary still uses the full reservoir.
        let stride = self
            .latencies
            .len()
            .div_ceil(MAX_PROGRESS_LATENCY_SAMPLES)
            .max(1);
        let mut latencies = self
            .latencies
            .iter()
            .step_by(stride)
            .take(MAX_PROGRESS_LATENCY_SAMPLES)
            .copied()
            .collect::<Vec<_>>();
        latencies.sort_unstable();
        let elapsed_ms = elapsed.as_millis() as u64;
        let elapsed_seconds = elapsed_ms.max(1) as f64 / 1000.0;
        let missing = self
            .expected
            .map(|expected| expected.saturating_sub(self.unique));
        let incomplete = self.local_lag_events > 0 || self.gossip_lag_events > 0;
        serde_json::json!({
            "type":"bench_receive_progress", "schema_version":1,
            "run_id":self.run_id, "elapsed_ms":elapsed_ms, "expected":self.expected,
            "unique":self.unique, "missing":missing,
            "duplicates":self.duplicates, "out_of_order":self.out_of_order,
            "highest_sequence":self.highest_sequence, "body_bytes":self.body_bytes,
            "achieved_messages_per_second":self.unique as f64 / elapsed_seconds,
            "achieved_body_bytes_per_second":self.body_bytes as f64 / elapsed_seconds,
            "latency":{
                "observations":self.latency_observations,
                "samples":latencies.len(),
                "sampled":self.latency_sampled || self.latencies.len() > latencies.len(),
                "clock_invalid":self.latency_clock_invalid,
                "p50_ms":Self::percentile(&latencies, 50),
                "p95_ms":Self::percentile(&latencies, 95),
                "p99_ms":Self::percentile(&latencies, 99)
            },
            "lag":{
                "local_events":self.local_lag_events, "local_dropped":self.local_dropped,
                "gossip_events":self.gossip_lag_events, "incomplete":incomplete
            },
            "malformed_messages":self.malformed_messages
        })
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

async fn bench_receive_events(
    dir: &Path,
    run_id: String,
    duration_secs: u64,
    expected: Option<u64>,
    events: mpsc::Sender<serde_json::Value>,
    mut cancellation: oneshot::Receiver<()>,
) -> Result<()> {
    anyhow::ensure!(valid_run_id(&run_id), "invalid benchmark run ID");
    anyhow::ensure!(
        (1..=86_400).contains(&duration_secs),
        "duration must be between 1 and 86400 seconds"
    );
    let mut stats = BenchReceiveStats::new(run_id.clone(), expected)?;
    let request_id = contracts::new_request_id();
    let startup = async {
        let mut reader = subscribe_with_id(dir, &request_id).await?;
        let connected = reader
            .read()
            .await?
            .context("local daemon stopped before benchmark receiver connected")?;
        Result::<_>::Ok((reader, connected))
    };
    let (mut reader, connected) =
        await_bench_startup(startup, &mut cancellation, BENCH_CLIENT_STARTUP_TIMEOUT).await?;
    anyhow::ensure!(
        connected["type"] == "connected",
        "unexpected daemon subscription response"
    );
    let started_value = contracts::correlate(
        serde_json::json!({
            "type":"bench_receive_started", "schema_version":1,
            "run_id":run_id, "duration_secs":duration_secs, "expected":expected
        }),
        &request_id,
    );
    validate_success_payload(&started_value)?;
    emit_bench_terminal(&events, started_value).await;
    let started = StdInstant::now();
    let deadline = tokio::time::sleep(Duration::from_secs(duration_secs));
    tokio::pin!(deadline);
    let mut progress = tokio::time::interval(Duration::from_millis(250));
    progress.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    progress.tick().await;
    let mut completion_reason = "deadline";
    let mut daemon_error = None;
    loop {
        tokio::select! {
            value = reader.read() => match benchmark_subscription_value(
                value,
                "local daemon stopped during benchmark receive",
                "read benchmark events from local daemon",
            ) {
                Ok(value) => stats.record_event(&value),
                Err(error) => {
                    completion_reason = "daemon_stopped";
                    daemon_error = Some(error);
                    break;
                }
            },
            _ = &mut deadline => break,
            _ = progress.tick() => {
                let value = contracts::correlate(stats.progress(started.elapsed()), &request_id);
                validate_success_payload(&value)?;
                emit_bench_progress(&events, value);
            },
            _ = &mut cancellation => {
                completion_reason = "interrupted";
                break;
            }
        }
    }
    let summary = contracts::correlate(
        stats.summary(completion_reason, started.elapsed()),
        &request_id,
    );
    validate_success_payload(&summary)?;
    emit_bench_terminal(&events, summary).await;
    if let Some(error) = daemon_error {
        return Err(error);
    }
    Ok(())
}

pub async fn bench_receive(
    dir: &Path,
    run_id: String,
    duration_secs: u64,
    expected: Option<u64>,
    json: bool,
) -> Result<()> {
    let (cancel_tx, cancel_rx) = oneshot::channel();
    let signal = tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            let _ = cancel_tx.send(());
        } else {
            std::future::pending::<()>().await;
        }
    });
    let (events, output) = bench_output_worker(json);
    let result =
        bench_receive_events(dir, run_id, duration_secs, expected, events, cancel_rx).await;
    signal.abort();
    output.await.context("benchmark output worker failed")?;
    result
}

pub(crate) async fn bench_receive_tui(
    dir: &Path,
    run_id: String,
    duration_secs: u64,
    expected: Option<u64>,
    events: mpsc::Sender<serde_json::Value>,
    cancellation: oneshot::Receiver<()>,
) -> Result<()> {
    bench_receive_events(dir, run_id, duration_secs, expected, events, cancellation).await
}

pub async fn listen(dir: &Path, json: bool) -> Result<()> {
    let mut reader = subscribe(dir).await?;
    loop {
        tokio::select! {
            value = reader.read() => match value? {
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
                    send_request_checked(
                        dir,
                        &IpcRequest::Send {
                            operation_id: crate::ipc::new_operation_id(),
                            body,
                        },
                        "queued",
                        Some(3),
                    )
                    .await?;
                }
                None => break,
            },
            value = reader.read() => match value? {
                Some(value) => event(json, value),
                None => anyhow::bail!("local daemon stopped; restart it with `meshmsg daemon`"),
            },
            _ = tokio::signal::ctrl_c() => break,
        }
    }
    Ok(())
}

pub async fn status(dir: &Path, json: bool) -> Result<()> {
    let value = send_request_checked(dir, &IpcRequest::Status, "status", None).await?;
    if json {
        println!("{value}");
    } else {
        println!(
            "daemon: running\npeer: {}\ntopic: {}\nalias: {}\nalias enabled: {}\nadvertised aliases: {}\nadvertises self: {}\nhas invite: {}\nbootstrap peers: {}\nself advertised: {}\nendpoint online: {}\ntopic joined: {}\nneighbors: {}\nattachment storage: {} / {} bytes ({} unique blobs, {} / {} pins)\nattachment filesystem available: {} bytes (minimum {})\nattachment storage pressure: {}\nattachment retention: {} seconds",
            value["peer"].as_str().unwrap_or(""),
            value["topic"].as_str().unwrap_or(""),
            value["alias"].as_str().unwrap_or("(disabled)"),
            value["alias_enabled"].as_bool().unwrap_or(false),
            value["advertised_aliases"].as_u64().unwrap_or(0),
            value["advertises_self"].as_bool().unwrap_or(false),
            value["has_invite"].as_bool().unwrap_or(false),
            value["bootstrap_peer_count"].as_u64().unwrap_or(0),
            value["self_advertised"].as_bool().unwrap_or(false),
            value["endpoint_online"].as_bool().unwrap_or(false),
            value["topic_joined"].as_bool().unwrap_or(false),
            value["neighbors"].as_u64().unwrap_or(0),
            value["attachment_storage"]["tagged_bytes"].as_u64().unwrap_or(0),
            value["attachment_storage"]["quota_bytes"].as_u64().unwrap_or(0),
            value["attachment_storage"]["tagged_blobs"].as_u64().unwrap_or(0),
            value["attachment_storage"]["tags"].as_u64().unwrap_or(0),
            value["attachment_storage"]["tag_capacity"].as_u64().unwrap_or(0),
            value["attachment_storage"]["available_bytes"].as_u64().unwrap_or(0),
            value["attachment_storage"]["min_free_bytes"].as_u64().unwrap_or(0),
            value["attachment_storage"]["pressure"].as_bool().unwrap_or(false),
            value["attachment_retention_secs"].as_u64().unwrap_or(0)
        );
    }
    Ok(())
}

pub async fn stop(dir: &Path, json: bool) -> Result<()> {
    let value = send_request_checked(dir, &IpcRequest::Stop, "stopping", None).await?;
    event(json, value);
    Ok(())
}

pub async fn doctor(dir: &Path, json: bool) -> Result<()> {
    let (state, secret) = State::load_for_doctor(dir)?;
    state.validate_for_identity(secret.public())?;
    let alias_config = AliasConfig::load_for_identity(dir, secret.public())?;
    let (has_invite, bootstrap_peer_count, self_advertised) =
        invite_details(&state, secret.public())?;
    let value = serde_json::json!({
        "type":"doctor", "ok":true, "peer":secret.public().to_string(), "topic":state.topic,
        "advertises_self":state.advertise_self, "has_invite":has_invite,
        "bootstrap_peer_count":bootstrap_peer_count, "self_advertised":self_advertised,
        "alias":alias_config.effective(), "alias_enabled":alias_config.enabled(),
        "captured_hostname":alias_config.hostname(), "custom_alias":alias_config.custom()
    });
    if json {
        println!(
            "{}",
            contracts::correlate(value, &contracts::new_request_id())
        );
    } else {
        println!("ok: state, identity, topic, and invite are valid");
    }
    Ok(())
}

#[cfg(test)]
fn startup_error_value(_phase: &str, message: &str) -> serde_json::Value {
    let mut error = ErrorEnvelopeV1::new("startup_failed", message, "not_started", true);
    error.request_id = Some(contracts::new_request_id());
    error.into_value()
}

fn startup_error(_json: bool, _phase: &str, _message: &str) {
    // The top-level JSON failure path emits exactly one standard error record.
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

fn offer_listing_warnings(value: &serde_json::Value) -> Vec<String> {
    let mut warnings = Vec::new();
    if value["truncated"].as_bool() == Some(true) {
        warnings
            .push("WARNING: attachment listing truncated; more pinned blobs may exist".to_owned());
    }
    if let Some(errors) = value["item_errors"].as_u64() {
        warnings.push(format!(
            "WARNING: {errors} attachment tag(s) could not be read"
        ));
    }
    warnings
}

fn event(json: bool, mut value: serde_json::Value) {
    if json {
        if value.get("schema_version").is_none() {
            value["schema_version"] = contracts::SCHEMA_VERSION.into();
        }
        if value.get("type").and_then(serde_json::Value::as_str) == Some("error") {
            let request_id = value
                .get("request_id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("00000000000000000000000000000000");
            let mut normalized = normalize_ipc_response(&value, request_id);
            if value.get("request_id").is_none() {
                normalized
                    .as_object_mut()
                    .expect("error object")
                    .remove("request_id");
            }
            value = normalized;
        }
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
            "private_message" if value["body_suppressed"].as_bool() == Some(true) => println!(
                "private message from {} ({} bytes; body suppressed)",
                value["from"].as_str().unwrap_or("peer"),
                value["body_bytes"].as_u64().unwrap_or(0)
            ),
            "private_message" => println!(
                "private from {}: {}",
                value["from"].as_str().unwrap_or("peer"),
                terminal_safe(value["body"].as_str().unwrap_or(""))
            ),
            "private_accepted" if value["duplicate_accepted"].as_bool() == Some(true) => println!(
                "private message was previously accepted by {} (not redelivered; not durable or read)",
                value["to"].as_str().unwrap_or("peer")
            ),
            "private_accepted" => println!(
                "private message accepted by {} (acceptance only; not durable or read)",
                value["to"].as_str().unwrap_or("peer")
            ),
            "queued" => println!(
                "queued locally (delivery not acknowledged): {}",
                terminal_safe(value["body"].as_str().unwrap_or(""))
            ),
            "offer_removed" => println!(
                "removed {} attachment pin(s); {} quota bytes released",
                value["removed_tags"].as_u64().unwrap_or(0),
                value["released_bytes"].as_u64().unwrap_or(0)
            ),
            "offers_pruned" => println!(
                "{} {} attachment pin(s); {} quota bytes released{}",
                if value["dry_run"].as_bool() == Some(true) { "would remove" } else { "removed" },
                if value["dry_run"].as_bool() == Some(true) { value["selected_tags"].as_u64().unwrap_or(0) } else { value["removed_tags"].as_u64().unwrap_or(0) },
                value["released_bytes"].as_u64().unwrap_or(0),
                if value["limited"].as_bool() == Some(true) { " (more eligible pins remain)" } else { "" }
            ),
            "offers" => {
                let blobs = value["blobs"].as_array().map(Vec::as_slice).unwrap_or(&[]);
                if blobs.is_empty() {
                    println!("no pinned attachment blobs");
                } else {
                    for blob in blobs {
                        let size = blob["size"]
                            .as_u64()
                            .map(|value| value.to_string())
                            .unwrap_or_else(|| "?".to_owned());
                        println!(
                            "{}  {}  {}  {}  {}  {}  {}  {} bytes  {}",
                            terminal_safe(blob["direction"].as_str().unwrap_or("unknown")),
                            terminal_safe(blob["name"].as_str().unwrap_or("?")),
                            terminal_safe(blob["kind"].as_str().unwrap_or("?")),
                            terminal_safe(blob["offer_id"].as_str().unwrap_or("")),
                            terminal_safe(blob["provider"].as_str().unwrap_or("-")),
                            terminal_safe(blob["format"].as_str().unwrap_or("unknown")),
                            terminal_safe(blob["status"].as_str().unwrap_or("unknown")),
                            size,
                            terminal_safe(blob["hash"].as_str().unwrap_or(""))
                        );
                    }
                }
                for warning in offer_listing_warnings(&value) {
                    println!("{warning}");
                }
            }
            "attachment_shared" => println!(
                "shared {} ({} bytes)\noffer: {}\ndelivery acknowledged: no",
                terminal_safe(value["name"].as_str().unwrap_or("attachment")),
                value["size"].as_u64().unwrap_or(0),
                value["offer"].as_str().unwrap_or("")
            ),
            "attachment_offer" if value["details_suppressed"].as_bool() == Some(true) => println!(
                "attachment offer from {} ({} bytes; details suppressed)",
                value["from"].as_str().unwrap_or("peer"),
                value["size"].as_u64().unwrap_or(0)
            ),
            "attachment_offer" => println!(
                "{} shared {} ({} bytes)\ndownload with: meshmsg download '{}' --output PATH",
                value["from"].as_str().unwrap_or("peer"),
                terminal_safe(value["name"].as_str().unwrap_or("attachment")),
                value["size"].as_u64().unwrap_or(0),
                value["offer"].as_str().unwrap_or("")
            ),
            "download_started" => println!("attachment download started"),
            "download_progress" => println!(
                "attachment download: {} / {} bytes",
                value["received_bytes"].as_u64().unwrap_or(0),
                value["total_bytes"].as_u64().unwrap_or(0)
            ),
            "download_complete" => println!(
                "downloaded {} bytes to {}",
                value["size"].as_u64().unwrap_or(0),
                value["output"].as_str().unwrap_or("")
            ),
            "peers_snapshot" => {
                let self_peer = &value["self"];
                println!(
                    "self: {}{} ({})",
                    self_peer["public_key"].as_str().unwrap_or(""),
                    self_peer["alias"]
                        .as_str()
                        .map(|alias| format!(" ({alias})"))
                        .unwrap_or_default(),
                    if self_peer["online"].as_bool() == Some(true) {
                        "online"
                    } else {
                        "offline"
                    }
                );
                for peer in value["peers"].as_array().map(Vec::as_slice).unwrap_or(&[]) {
                    println!(
                        "peer: {}{} ({})",
                        peer["public_key"].as_str().unwrap_or(""),
                        peer["alias"]
                            .as_str()
                            .map(|alias| format!(" ({alias})"))
                            .unwrap_or_default(),
                        if peer["online"].as_bool() == Some(true) {
                            "online"
                        } else {
                            "offline"
                        }
                    );
                }
            }
            "peer_discovered" | "peer_updated" | "peer_expired" => {
                let peer = &value["peer"];
                let action = value["type"].as_str().unwrap_or("peer");
                println!(
                    "{}: {}{}",
                    action.replace('_', " "),
                    peer["public_key"].as_str().unwrap_or(""),
                    peer["alias"]
                        .as_str()
                        .map(|alias| format!(" ({alias})"))
                        .unwrap_or_default()
                );
            }
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

        let (reply1, response1) = oneshot::channel();
        assert!(cache.admit(id1.into(), fp1, reply1, now));
        let (duplicate, duplicate_response) = oneshot::channel();
        assert!(!cache.admit(id1.into(), fp1, duplicate, now));
        let (conflict, conflict_response) = oneshot::channel();
        assert!(!cache.admit(id1.into(), different, conflict, now));
        assert_eq!(
            conflict_response.await.unwrap()["code"],
            "operation_id_conflict"
        );

        let terminal = serde_json::json!({
            "type":"error", "schema_version":1, "code":"send_failed"
        });
        let stored = cache.complete(id1, terminal, now);
        assert_eq!(stored["operation_id"], id1);
        assert_eq!(response1.await.unwrap(), stored);
        assert_eq!(duplicate_response.await.unwrap(), stored);
        let (cached, cached_response) = oneshot::channel();
        assert!(!cache.admit(id1.into(), fp1, cached, now));
        assert_eq!(cached_response.await.unwrap(), stored);

        let fp2 = operation_fingerprint("send", &[b"two"]);
        let (reply2, _response2) = oneshot::channel();
        assert!(cache.admit(id2.into(), fp2, reply2, now));
        cache.complete(id2, serde_json::json!({"type":"queued"}), now);
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
        expired.complete(id1, serde_json::json!({"type":"queued"}), now);
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
    fn attachment_admission_is_fail_fast_even_when_limit_is_closed() {
        let limit = Arc::new(Semaphore::new(1));
        let permit = try_admit_transfer(&limit, "share_busy", "capacity reached").unwrap();
        let busy = try_admit_transfer(&limit, "download_busy", "capacity reached").unwrap_err();
        assert_eq!(busy["code"], "download_busy");
        drop(permit);
        assert!(try_admit_transfer(&limit, "download_busy", "capacity reached").is_ok());
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

        let oversized_name = format!(
            "meshmsg/out/v1/0123456789abcdef0123456789abcdef/file/{}",
            "A".repeat(MAX_ENCODED_TAG_NAME_BYTES + 1)
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
        let encoded = Envelope::encode_at(
            &secret,
            test_topic(),
            EnvelopeKind::AttachmentOffer,
            attachment_body(&offer).unwrap(),
            42,
        )
        .unwrap();
        let token = BASE64URL_NOPAD.encode(&encoded);

        let (decoded, ticket) = parse_signed_offer_token(&token, test_topic()).unwrap();
        assert_eq!(decoded, offer);
        assert_eq!(ticket.addr().id, secret.public());

        let mut tampered = encoded.to_vec();
        let last = tampered.last_mut().unwrap();
        *last ^= 1;
        assert!(
            parse_signed_offer_token(&BASE64URL_NOPAD.encode(&tampered), test_topic()).is_err()
        );
    }

    #[test]
    fn legacy_signed_attachment_tokens_are_rejected_with_migration_guidance() {
        let secret = SecretKey::generate();
        let body = attachment_body(&sample_offer(secret.public())).unwrap();
        let timestamp_ms = 42;
        let signed = postcard::to_stdvec(&(secret.public(), timestamp_ms, &body)).unwrap();
        let legacy = LegacyEnvelopeV1 {
            from: secret.public(),
            timestamp_ms,
            body,
            signature: ByteArray::new(secret.sign(&signed).to_bytes()),
        };
        let token = BASE64URL_NOPAD.encode(&postcard::to_stdvec(&legacy).unwrap());

        let error = parse_signed_offer_token(&token, test_topic()).unwrap_err();
        assert_eq!(
            error.to_string(),
            "legacy signed attachment offers are not accepted because they are not topic-bound; ask the sender to share the attachment again"
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
    fn transport_limiter_precedes_decode_and_rejection_events_are_sampled() {
        let source = SecretKey::generate().public();
        let now_ms = 1_700_000_040_000;
        let mut sources = TransportSourceLimiter::default();
        for _ in 0..TRANSPORT_SOURCE_BURST {
            assert!(sources.allow(source, now_ms));
        }
        let mut replay = EnvelopeReplayCache::default();
        let mut sampler = RejectionSampler::default();
        let values = network_event(
            Event::Received(iroh_gossip::api::Message {
                content: Bytes::from_static(b"not an envelope"),
                scope: iroh_gossip::proto::DeliveryScope::Neighbors,
                delivered_from: source,
            }),
            test_topic(),
            &mut replay,
            &mut sources,
            &mut sampler,
            now_ms,
        );
        assert_eq!(values.len(), 1);
        assert_eq!(values[0]["rate_limited"], true);
        assert_eq!(
            values[0]["message"],
            "broadcast transport source rate limit exceeded"
        );
        assert_eq!(replay.live_ids, 0);

        for _ in 0..100 {
            assert!(sampler.event(now_ms + 1, "rejected").is_none());
        }
        let sampled = sampler
            .event(
                now_ms + REJECTION_SAMPLE_INTERVAL.as_millis() as u64,
                "rejected",
            )
            .unwrap();
        assert_eq!(sampled["suppressed_since_last"], 100);
    }

    #[test]
    fn transport_source_limiter_isolates_sources_and_bounds_source_rotation() {
        let now_ms = 1_700_000_040_000;
        let abusive = SecretKey::generate().public();
        let other = SecretKey::generate().public();
        let mut limiter = TransportSourceLimiter::default();
        for _ in 0..TRANSPORT_SOURCE_BURST {
            assert!(limiter.allow(abusive, now_ms));
        }
        assert!(!limiter.allow(abusive, now_ms));
        assert!(limiter.allow(other, now_ms));

        let mut source_limited = TransportSourceLimiter::default();
        for _ in 0..MAX_TRANSPORT_SOURCES {
            assert!(source_limited.allow(SecretKey::generate().public(), now_ms));
        }
        assert!(!source_limited.allow(SecretKey::generate().public(), now_ms));
        assert!(source_limited.allow(
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

        let mut capacity_limited = EnvelopeReplayCache {
            max_live_ids: 3,
            ..EnvelopeReplayCache::default()
        };
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
    fn broadcast_v2_uses_an_explicitly_new_gossip_protocol() {
        assert_ne!(BROADCAST_ALPN_V2, iroh_gossip::net::GOSSIP_ALPN);
    }

    #[test]
    fn attachment_wire_rejects_provider_mismatch_version_and_trailing_bytes() {
        let signer = SecretKey::generate();
        let other = SecretKey::generate();
        let mismatched = sample_offer(other.public());
        let encoded = Envelope::encode_at(
            &signer,
            test_topic(),
            EnvelopeKind::AttachmentOffer,
            attachment_body(&mismatched).unwrap(),
            42,
        )
        .unwrap();
        assert!(parse_signed_offer_token(&BASE64URL_NOPAD.encode(&encoded), test_topic()).is_err());

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
        let largest_body = (0..=MAX_ENVELOPE_SIZE)
            .rev()
            .find(|length| {
                Envelope::encode_at(
                    &secret,
                    test_topic(),
                    EnvelopeKind::Message,
                    "a".repeat(*length),
                    timestamp_ms,
                )
                .is_ok()
            })
            .expect("an empty message must fit");
        let encoded = Envelope::encode_at(
            &secret,
            test_topic(),
            EnvelopeKind::Message,
            "a".repeat(largest_body),
            timestamp_ms,
        )
        .unwrap();
        assert_eq!(encoded.len(), MAX_ENVELOPE_SIZE);
        assert!(Envelope::encode_at(
            &secret,
            test_topic(),
            EnvelopeKind::Message,
            "a".repeat(largest_body + 1),
            timestamp_ms,
        )
        .is_err());
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
                Envelope::encode_at(
                    &secret,
                    test_topic(),
                    EnvelopeKind::Message,
                    body,
                    9_999_999_999_999,
                )
                .is_ok()
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

    #[tokio::test]
    async fn benchmark_startup_cancellation_breaks_a_stalled_handshake() {
        let (cancel, mut cancellation) = oneshot::channel();
        cancel.send(()).unwrap();
        let error = await_bench_startup(
            std::future::pending::<Result<()>>(),
            &mut cancellation,
            Duration::from_secs(60),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("interrupted"));
    }

    #[tokio::test]
    async fn benchmark_progress_never_waits_for_a_blocked_sink_and_summary_is_retained() {
        let (events, mut output) = mpsc::channel(1);
        emit_bench_terminal(&events, serde_json::json!({"type":"started"})).await;

        emit_bench_progress(&events, serde_json::json!({"type":"progress"}));
        assert_eq!(output.recv().await.unwrap()["type"], "started");
        assert!(output.try_recv().is_err());

        emit_bench_terminal(&events, serde_json::json!({"type":"occupied"})).await;
        let terminal = tokio::spawn({
            let events = events.clone();
            async move {
                emit_bench_terminal(&events, serde_json::json!({"type":"summary"})).await;
            }
        });
        tokio::task::yield_now().await;
        assert!(!terminal.is_finished());
        assert_eq!(output.recv().await.unwrap()["type"], "occupied");
        terminal.await.unwrap();
        assert_eq!(output.recv().await.unwrap()["type"], "summary");
    }

    #[test]
    fn benchmark_subscription_disconnect_classifies_eof_and_read_errors() {
        let eof =
            benchmark_subscription_value(Ok(None), "daemon stopped cleanly", "read daemon stream")
                .unwrap_err();
        assert_eq!(eof.to_string(), "daemon stopped cleanly");

        let reset = benchmark_subscription_value(
            Err(std::io::Error::new(std::io::ErrorKind::ConnectionReset, "scripted reset").into()),
            "daemon stopped cleanly",
            "read daemon stream",
        )
        .unwrap_err();
        assert_eq!(reset.to_string(), "read daemon stream");
        assert!(format!("{reset:#}").contains("scripted reset"));
    }

    #[test]
    fn disconnected_sender_summary_preserves_latest_partial_snapshot() {
        let config = BenchConfig {
            run_id: "0123456789abcdef0123456789abcdef".into(),
            rate: 10,
            duration_secs: 1,
            payload_bytes: 128,
        };
        let progress = bench_send_progress(
            &config,
            10,
            &BenchSendStats {
                attempted: 4,
                queued: 3,
                schedule_missed: 1,
                ..BenchSendStats::default()
            },
            Duration::from_millis(400),
        );
        let summary = disconnected_send_summary(
            &config,
            10,
            Some(&progress),
            Duration::from_secs(1),
            "11111111111111111111111111111111",
        );
        assert_eq!(summary["type"], "bench_send_summary");
        assert_eq!(summary["completion_reason"], "daemon_stopped");
        assert_eq!(summary["attempted"], 4);
        assert_eq!(summary["queued"], 3);
        assert_eq!(summary["schedule_missed"], 1);
        assert!(summary["first_error"].is_null());
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
        let progress = bench_send_progress(&config, 10, &stats, Duration::from_millis(500));
        assert_object_keys(
            &progress,
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
                "delivery_acknowledged",
            ],
        );
        assert_eq!(progress["type"], "bench_send_progress");
        assert_eq!(progress["schema_version"], 1);
        assert_eq!(progress["delivery_acknowledged"], false);

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
    fn benchmark_receiver_progress_is_stable_and_does_not_reorder_samples() {
        let mut stats =
            BenchReceiveStats::new("0123456789abcdef0123456789abcdef".into(), None).unwrap();
        stats.latencies = vec![30, 10, 20];
        stats.latency_observations = 3;
        stats.unique = 2;
        let progress = stats.progress(Duration::from_millis(500));

        assert_object_keys(
            &progress,
            &[
                "type",
                "schema_version",
                "run_id",
                "elapsed_ms",
                "expected",
                "unique",
                "missing",
                "duplicates",
                "out_of_order",
                "highest_sequence",
                "body_bytes",
                "achieved_messages_per_second",
                "achieved_body_bytes_per_second",
                "latency",
                "lag",
                "malformed_messages",
            ],
        );
        assert_eq!(progress["type"], "bench_receive_progress");
        assert_eq!(progress["schema_version"], 1);
        assert!(progress["missing"].is_null());
        assert_eq!(progress["latency"]["p50_ms"], 20);
        assert_eq!(progress["latency"]["p95_ms"], 30);
        assert_eq!(stats.latencies, vec![30, 10, 20]);
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
    fn daemon_log_message_event_suppresses_body_but_keeps_metadata() {
        let secret = SecretKey::generate();
        let value = suppress_message_body(message_event(unsigned_test_envelope(
            secret.public(),
            "private text".to_owned(),
            42,
        )));
        assert_eq!(value["timestamp_ms"], 42);
        assert_eq!(value["body_bytes"], 12);
        assert_eq!(value["body_suppressed"], true);
        assert!(value.get("body").is_none());

        let direct = suppress_message_body(private_message_event(IncomingDirect {
            from: secret.public(),
            id: [7; 16],
            timestamp_ms: 43,
            body: "dm secret".to_owned(),
        }));
        assert_eq!(direct["type"], "private_message");
        assert_eq!(direct["body_bytes"], 9);
        assert_eq!(direct["private"], true);
        assert!(direct.get("body").is_none());
        assert!(!direct.to_string().contains("dm secret"));
    }

    #[test]
    fn queued_event_has_canonical_send_metadata_and_does_not_claim_delivery() {
        let value = queued_event("peer", [4; 16], "hello".to_owned(), 1_700_000_000_000);

        assert_eq!(value["type"], "queued");
        assert_eq!(value["schema_version"], 3);
        assert_eq!(value["operation_id"], "04040404040404040404040404040404");
        assert_eq!(value["message_id"], "04040404040404040404040404040404");
        assert_eq!(value["from"], "peer");
        assert_eq!(value["body"], "hello");
        assert_eq!(value["timestamp_ms"], 1_700_000_000_000_u64);
        assert_eq!(value["delivery_acknowledged"], false);
        assert_object_keys(
            &value,
            &[
                "type",
                "schema_version",
                "from",
                "operation_id",
                "message_id",
                "timestamp_ms",
                "body",
                "delivery_acknowledged",
            ],
        );
    }

    #[test]
    fn private_send_capability_and_acceptance_are_validated_strictly() {
        assert!(!advertises_private_send(
            &serde_json::json!({"type":"status"})
        ));
        assert!(!advertises_private_send(&serde_json::json!({
            "type":"connected", "ipc_capabilities":[PRIVATE_SEND_CAPABILITY]
        })));
        assert!(advertises_private_send(&serde_json::json!({
            "type":"status", "ipc_capabilities":[PRIVATE_SEND_CAPABILITY]
        })));

        let recipient = SecretKey::generate().public().to_string();
        let accepted = serde_json::json!({
            "type":"private_accepted", "schema_version":3,
            "request_id":"11111111111111111111111111111111",
            "operation_id":"0123456789abcdef0123456789abcdef",
            "to":recipient, "message_id":"0123456789abcdef0123456789abcdef",
            "timestamp_ms":1_700_000_000_000_u64, "body_bytes":6,
            "acceptance_acknowledged":true, "duplicate_accepted":false,
            "durable":false, "read":false
        });
        validate_private_acceptance(&accepted, "0123456789abcdef0123456789abcdef", "秘密".len())
            .unwrap();

        for invalid in [
            {
                let mut value = accepted.clone();
                value["type"] = "queued".into();
                value
            },
            {
                let mut value = accepted.clone();
                value["body_bytes"] = 7.into();
                value
            },
            {
                let mut value = accepted.clone();
                value["body"] = "secret".into();
                value
            },
            {
                let mut value = accepted.clone();
                value["message_id"] = "0123456789ABCDEF0123456789ABCDEF".into();
                value
            },
        ] {
            assert!(
                validate_private_acceptance(&invalid, "0123456789abcdef0123456789abcdef", 6)
                    .is_err()
            );
        }
    }

    #[test]
    fn startup_errors_are_structured_and_retryable() {
        let value = startup_error_value("topic_join", "bootstrap peer unavailable");

        assert_eq!(value["type"], "error");
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["code"], "startup_failed");
        assert_eq!(value["outcome"], "not_started");
        assert_eq!(value["retryable"], true);
        assert!(contracts::valid_request_id(
            value["request_id"].as_str().unwrap()
        ));
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
    fn direct_replay_terminal_health_has_stable_status_fields() {
        let status = direct_replay_status(crate::direct_replay::ReplayHealth {
            available: false,
            error: Some("direct replay persistence worker failed".into()),
        });
        assert_eq!(status["available"], false);
        assert_eq!(status["error"], "direct replay persistence worker failed");
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
                raw_export: true,
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
            assert!(valid_offer_id(&offer_id));
            assert_eq!(offer_id, raw_ticket_offer_id(&ticket));
            let tag = raw_ticket_blob_tag(&ticket);
            let options = FsStoreOptions::new(&root.join("store"));
            let store: Store = FsStore::load_with_opts(root.join("blobs.db"), options)
                .await
                .unwrap()
                .into();
            let (pins, _, _) = list_pinned_blobs(&store).await.unwrap();
            assert_eq!(pins.len(), 1);
            assert_eq!(pins[0].direction, "incoming");
            assert_eq!(pins[0].offer_id, offer_id);
            assert_eq!(pins[0].hash, ticket.hash().to_string());
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
                        raw_export: true,
                        max_attachment_bytes: DEFAULT_MAX_ATTACHMENT_BYTES,
                        pin_already_committed: false,
                    },
                    &|_| Ok(()),
                )
                .await
                .unwrap();
                assert!(outcome.destination_synced);
                assert!(outcome.cleanup_complete);
                let (pins, _, _) = list_pinned_blobs(&store).await.unwrap();
                assert_eq!(pins.len(), 1, "raw retry created a duplicate permanent pin");
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
                    raw_export: false,
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
            let (failed_pins, _, _) = list_pinned_blobs(&store).await.unwrap();
            assert_eq!(
                failed_pins.len(),
                usize::from(boundary != "blob_tag_persist"),
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
                    raw_export: false,
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
            let (pins, _, _) = list_pinned_blobs(&store).await.unwrap();
            assert_eq!(pins.len(), 1);
            assert_eq!(pins[0].direction, "incoming");
            assert_eq!(pins[0].provider.as_deref(), Some(provider_text.as_str()));
            assert_eq!(pins[0].hash, hash_and_format.hash.to_string());
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
                    raw_export: false,
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
            let (pins, _, _) = list_pinned_blobs(&store).await.unwrap();
            assert_eq!(pins.len(), 1);
            assert_eq!(pins[0].direction, "incoming");
            assert_eq!(pins[0].provider.as_deref(), Some(provider_text.as_str()));
            assert_eq!(pins[0].hash, hash_and_format.hash.to_string());
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
                raw_export: false,
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
        let (pins, _, _) = list_pinned_blobs(&store).await.unwrap();
        assert_eq!(pins.len(), 1);
        assert_eq!(pins[0].direction, "incoming");
        assert_eq!(pins[0].offer_id, offer_id);
        assert_eq!(pins[0].hash, hash_and_format.hash.to_string());
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
        let hash = iroh_blobs::Hash::new(b"listing test");
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

        let (blobs, has_more, item_errors) = list_pinned_blobs(&store).await.unwrap();
        assert_eq!(blobs.len(), MAX_OFFER_LIST_ENTRIES);
        assert!(has_more);
        assert_eq!(item_errors, 0);
        assert_eq!(blobs[0].offer_id, format!("{:032x}", 0));
        assert_eq!(
            blobs.last().unwrap().offer_id,
            format!("{:032x}", MAX_OFFER_LIST_ENTRIES - 1)
        );
        assert!(
            serde_json::to_vec(&serde_json::json!({
                "type":"offers", "schema_version":1, "blobs":blobs,
                "truncated":true, "has_more":true
            }))
            .unwrap()
            .len()
                <= MAX_IPC_EVENT_SIZE
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
        (root, state, store)
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
        let error = LifecycleErrorV1::from_value(&result).unwrap();
        assert_eq!(error.removed_tags, Some(0));
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
        let error = LifecycleErrorV1::from_value(&result).unwrap();
        assert_eq!(error.code, "attachment_removal_partial");
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
                Some("00000000000000000000000000000001"),
                None,
                None,
                None,
                512,
                false,
            )
            .await
            .unwrap();
        assert_eq!(removed["removed_tags"], 1);
        assert_eq!(removed["released_bytes"], 0);
        let removed = storage
            .remove(
                Some("00000000000000000000000000000002"),
                None,
                None,
                None,
                512,
                false,
            )
            .await
            .unwrap();
        assert_eq!(removed["released_bytes"], 10);
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
            .remove(None, None, None, Some(10), 1, true)
            .await
            .unwrap();
        assert_eq!(dry["selected_tags"], 1);
        assert_eq!(dry["removed_tags"], 0);
        assert_eq!(dry["limited"], true);
        assert_eq!(storage.status().tags, 3);
        let pruned = storage
            .remove(None, None, None, Some(10), 2, false)
            .await
            .unwrap();
        assert_eq!(pruned["removed_tags"], 2, "the exact cutoff is inclusive");
        assert_eq!(storage.status().tags, 1);
        let held = storage.gate.clone().acquire_owned().await.unwrap();
        let busy = storage
            .remove(None, None, None, Some(0), 1, false)
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
            let error = LifecycleErrorV1::from_value(&value).unwrap();
            assert_eq!(error.code, "attachment_removal_partial");
            assert_eq!(error.removed_tags, Some(1));
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
        let error = LifecycleErrorV1::from_value(&value).unwrap();
        assert_eq!(error.outcome, "partial");
        assert_eq!(error.selected_tags, Some(2));
        assert_eq!(error.removed_tags, Some(1));
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
                raw_export: true,
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
        let (sender, receiver) = oneshot::channel::<serde_json::Value>();
        let offer_id = "99999999999999999999999999999999".to_owned();
        let timeout_value = lifecycle_command_response(
            async move { Ok(receiver.await?) },
            Duration::from_millis(1),
            None,
            Some(offer_id.clone()),
        )
        .await;
        let timeout = LifecycleErrorV1::from_value(&timeout_value).unwrap();
        assert_eq!(timeout.code, "attachment_command_timeout");
        assert_eq!(timeout.outcome, "unknown");
        assert!(timeout.retryable);
        assert_eq!(timeout.offer_id.as_deref(), Some(offer_id.as_str()));
        drop(sender);

        let shutdown_value = lifecycle_command_response(
            async { anyhow::bail!("closed") },
            Duration::from_secs(1),
            None,
            None,
        )
        .await;
        let shutdown = LifecycleErrorV1::from_value(&shutdown_value).unwrap();
        assert_eq!(shutdown.code, "attachment_storage_shutdown");
        assert_eq!(shutdown.outcome, "unknown");
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
        let error = LifecycleErrorV1::from_value(&partial).unwrap();
        assert_eq!(error.code, "attachment_removal_partial");
        assert_eq!(error.outcome, "unknown");
        assert_eq!(enabled.status().tags, 1);
        let automatic = enabled.automatic_retention_pass().await.unwrap().unwrap();
        assert_eq!(automatic["removed_tags"], 1);
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
            offer_listing_warnings(&serde_json::json!({
                "type":"offers", "truncated":true, "item_errors":2
            })),
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
        let value = message_event(unsigned_test_envelope(
            secret.public(),
            "\0".repeat(largest_body),
            timestamp_ms,
        ));
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
            None,
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
            None,
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
        assert_eq!(summary["first_error"], "Message submission failed.");
        task.await.unwrap().unwrap();
        assert!(command_rx.try_recv().is_err());
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
            serde_json::json!({"type":"connected"}),
            None,
            Arc::new(AtomicBool::new(false)),
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
        let event = serde_json::json!({"type":"message", "body":"after half-close"});
        events.send(event.clone()).unwrap();
        let received = tokio::time::timeout(
            Duration::from_secs(1),
            read_frame(&mut client, MAX_IPC_EVENT_SIZE),
        )
        .await
        .unwrap()
        .unwrap();
        let received: serde_json::Value = serde_json::from_slice(&received).unwrap();
        assert_eq!(received["type"], event["type"]);
        assert_eq!(received["body"], event["body"]);
        assert_eq!(received["schema_version"], 1);
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
            serde_json::json!({"type":"connected"}),
            None,
            Arc::new(AtomicBool::new(false)),
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
        let startup = serde_json::json!({
            "type":"peers_snapshot", "schema_version":2,
            "generated_at_ms":1, "self":{"public_key":"self", "alias":null, "online":true},
            "peers":[]
        });
        let task = tokio::spawn(handle_local_client(
            server,
            commands,
            receiver,
            serde_json::json!({"type":"connected"}),
            Some(startup.clone()),
            Arc::new(AtomicBool::new(false)),
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
        assert_eq!(snapshot["type"], startup["type"]);
        assert_eq!(snapshot["peers"], startup["peers"]);
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
        events.send(serde_json::json!({"type":"first"})).unwrap();
        events.send(serde_json::json!({"type":"second"})).unwrap();
        let task = tokio::spawn(handle_local_client(
            server,
            commands,
            receiver,
            serde_json::json!({"type":"connected"}),
            None,
            Arc::new(AtomicBool::new(false)),
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
        events: &broadcast::Sender<serde_json::Value>,
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
                connected: serde_json::json!({"type":"connected"}),
                startup_peers: None,
                benchmark_busy: Arc::new(AtomicBool::new(false)),
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
        let rejection: serde_json::Value = serde_json::from_slice(&frame).unwrap();
        let rejection = ErrorEnvelopeV1::from_value(&rejection).unwrap();
        assert_eq!(rejection.code, "ipc_capacity");
        assert_eq!(rejection.outcome, "not_started");
        assert!(rejection.retryable);
        assert!(rejection.request_id.is_none());
        assert_eq!(tasks.len(), LOCAL_IPC_CONNECTION_CAPACITY);

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
        let timeout_error = serde_json::from_slice::<serde_json::Value>(&timeout_frame).unwrap();
        let timeout_error = ErrorEnvelopeV1::from_value(&timeout_error).unwrap();
        assert_eq!(timeout_error.code, "initial_frame_timeout");
        assert_eq!(timeout_error.outcome, "not_started");
        assert!(timeout_error.retryable);
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
        reply.send(serde_json::json!({"type":"status"})).unwrap();
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
            serde_json::json!({"type":"connected"}),
            None,
            Arc::new(AtomicBool::new(false)),
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
            serde_json::json!({"type":"connected"}),
            None,
            Arc::new(AtomicBool::new(false)),
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
            serde_json::json!({"type":"connected"}),
            None,
            Arc::new(AtomicBool::new(false)),
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
            serde_json::json!({"type":"connected"}),
            None,
            Arc::new(AtomicBool::new(false)),
            short_ipc_timeouts(),
        ));
        write_request(&mut client, &IpcRequest::Status)
            .await
            .unwrap();
        let pending = command_rx.recv().await.unwrap();
        let response = read_frame(&mut client, MAX_IPC_EVENT_SIZE).await.unwrap();
        let response: serde_json::Value = serde_json::from_slice(&response).unwrap();
        assert_eq!(response["code"], "command_timeout");
        assert!(response["message"].as_str().unwrap().contains("unknown"));
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
