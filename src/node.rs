#[cfg(test)]
use crate::ipc::write_request;
use crate::{
    alias::AliasConfig,
    attachment::{self, AttachmentKind, AttachmentOffer},
    config::{prepare_state_dir, State, StateLock},
    contracts::{self, ErrorEnvelopeV1},
    direct::{self, DIRECT_ALPN},
    invite::Invite,
    ipc::{
        read_frame, send_request_checked, subscribe, valid_content_digest, valid_operation_id,
        AttachmentOperationKind, IpcRequest, IpcRequestFrame, LifecycleErrorV1,
        LifecycleRequestContext, LifecycleSuccessV3, OfferItemV1, OffersV1, MAX_IPC_REQUEST_SIZE,
        MAX_OFFER_LIST_ENTRIES, MAX_OFFER_LIST_SCANNED,
    },
    peers as peer_api,
    presence::{self, Directory, PresenceSourceLimiter},
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
use crate::ipc::{write_request_with_id, MAX_IPC_EVENT_SIZE};
#[cfg(test)]
use std::sync::atomic::Ordering;
#[cfg(test)]
use tokio::io::AsyncWriteExt;

const SIGNATURE_LENGTH: usize = iroh::Signature::LENGTH;
const BROADCAST_ALPN_V2: &[u8] = b"/meshmsg/broadcast-gossip/2";
const ENVELOPE_DOMAIN: &str = "meshmsg-broadcast";
const ENVELOPE_VERSION: u8 = 2;
pub(crate) const ENVELOPE_ACCEPTANCE_WINDOW: Duration = Duration::from_secs(5 * 60);
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
const MAX_ENCODED_TAG_NAME_BYTES: usize = 134;
const MAX_ENCODED_PUBLIC_KEY_BYTES: usize = 64;
const BLOB_TAG_PREFIX: &[u8] = b"meshmsg/";
const OUTBOUND_BLOB_TAG_PREFIX: &str = "meshmsg/out/v1/";
const INBOUND_BLOB_TAG_PREFIX: &str = "meshmsg/in/v1/";
const MAX_ATTACHMENT_INDEX_TAG_BYTES: usize = INBOUND_BLOB_TAG_PREFIX.len()
    + MAX_ENCODED_PUBLIC_KEY_BYTES
    + 1
    + 32
    + 1
    + "directory_tar_v1".len()
    + 1
    + MAX_ENCODED_TAG_NAME_BYTES;
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
    verification_limiter: TokenBucket,
    admission_limiter: TokenBucket,
    last_seen_ms: u64,
}

struct TransportSourceLimiter {
    sources: HashMap<PublicKey, TransportSourceState>,
    verification_global: TokenBucket,
    admission_global: TokenBucket,
}

impl Default for TransportSourceLimiter {
    fn default() -> Self {
        Self {
            sources: HashMap::new(),
            verification_global: TokenBucket::new(
                GLOBAL_TRANSPORT_RATE_PER_SEC,
                GLOBAL_TRANSPORT_BURST,
                0,
            ),
            admission_global: TokenBucket::new(
                GLOBAL_TRANSPORT_RATE_PER_SEC,
                GLOBAL_TRANSPORT_BURST,
                0,
            ),
        }
    }
}

impl TransportSourceLimiter {
    fn prepare_source(&mut self, source: PublicKey, now_ms: u64) -> bool {
        let idle_ms = TRANSPORT_SOURCE_IDLE_LIFETIME.as_millis() as u64;
        self.sources
            .retain(|_, state| state.last_seen_ms.saturating_add(idle_ms) > now_ms);
        if !self.sources.contains_key(&source) {
            if self.sources.len() >= MAX_TRANSPORT_SOURCES {
                return false;
            }
            self.sources.insert(
                source,
                TransportSourceState {
                    verification_limiter: TokenBucket::new(
                        TRANSPORT_SOURCE_RATE_PER_SEC,
                        TRANSPORT_SOURCE_BURST,
                        now_ms,
                    ),
                    admission_limiter: TokenBucket::new(
                        TRANSPORT_SOURCE_RATE_PER_SEC,
                        TRANSPORT_SOURCE_BURST,
                        now_ms,
                    ),
                    last_seen_ms: now_ms,
                },
            );
        }
        true
    }

    /// Cheap authenticated-hop bound paid by every frame before postcard or
    /// signature work. It is deliberately separate from accepted-message
    /// accounting, so malformed/stale/replayed frames cannot consume the
    /// transport tokens needed by later valid traffic.
    fn allow_verification(&mut self, source: PublicKey, now_ms: u64) -> bool {
        if !self.prepare_source(source, now_ms) {
            return false;
        }
        self.verification_global.refill(now_ms);
        if !self.verification_global.available() {
            return false;
        }
        let state = self.sources.get_mut(&source).expect("source was inserted");
        state.verification_limiter.refill(now_ms);
        if !state.verification_limiter.available() {
            return false;
        }
        self.verification_global.consume();
        state.verification_limiter.consume();
        state.last_seen_ms = now_ms;
        true
    }

    fn admission_available(&mut self, source: PublicKey, now_ms: u64) -> bool {
        if !self.prepare_source(source, now_ms) {
            return false;
        }
        self.admission_global.refill(now_ms);
        let state = self.sources.get_mut(&source).expect("source was inserted");
        state.admission_limiter.refill(now_ms);
        self.admission_global.available() && state.admission_limiter.available()
    }

    fn consume_admission(&mut self, source: PublicKey, now_ms: u64) {
        debug_assert!(self.admission_available(source, now_ms));
        self.admission_global.consume();
        let state = self.sources.get_mut(&source).expect("source was reserved");
        state.admission_limiter.consume();
        state.last_seen_ms = now_ms;
    }
}

#[derive(Default)]
struct RejectionSampler {
    last_emitted_ms: Option<u64>,
    suppressed: u64,
}

#[derive(Default)]
struct InternalContractGuard {
    last_emitted_ms: Option<u64>,
    suppressed: u64,
}

impl InternalContractGuard {
    fn rejection(&mut self, now_ms: u64, _family: &str) -> Option<serde_json::Value> {
        let interval_ms = REJECTION_SAMPLE_INTERVAL.as_millis() as u64;
        if self
            .last_emitted_ms
            .is_some_and(|last| now_ms.saturating_sub(last) < interval_ms)
        {
            self.suppressed = self.suppressed.saturating_add(1);
            return None;
        }
        let suppressed = std::mem::take(&mut self.suppressed);
        self.last_emitted_ms = Some(now_ms);
        let mut error = ErrorEnvelopeV1::new(
            "internal_contract_error",
            "generated event failed its strict contract",
            "unknown",
            false,
        );
        error.suppressed_since_last = Some(suppressed);
        Some(error.into_value())
    }
}

impl RejectionSampler {
    fn event(&mut self, now_ms: u64, _private_diagnostic: &str) -> Option<serde_json::Value> {
        let interval_ms = REJECTION_SAMPLE_INTERVAL.as_millis() as u64;
        if self
            .last_emitted_ms
            .is_none_or(|last| now_ms.saturating_sub(last) >= interval_ms)
        {
            let suppressed = std::mem::take(&mut self.suppressed);
            self.last_emitted_ms = Some(now_ms);
            let mut error =
                ErrorEnvelopeV1::try_new_public("network_event_rejected", "not_started", false)
                    .ok()?;
            error.suppressed_since_last = Some(suppressed);
            return Some(error.into_value());
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

fn unix_timestamp_ms() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64)
}

fn unix_timestamp_ms_saturating(now: SystemTime) -> u64 {
    now.duration_since(UNIX_EPOCH)
        .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

#[derive(Debug, Serialize, Deserialize)]
struct AttachmentWire {
    version: u8,
    offer: AttachmentOffer,
}

impl Envelope {
    #[cfg(test)]
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
        if kind == EnvelopeKind::Message {
            crate::message::validate_broadcast_body(&body)?;
        }
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
        value.validate_semantics()?;
        let encoded = postcard::to_stdvec(&value)?;
        anyhow::ensure!(
            encoded.len() <= MAX_ENVELOPE_SIZE,
            "encoded message is {} bytes; maximum is {MAX_ENVELOPE_SIZE} bytes",
            encoded.len()
        );
        Ok(encoded.into())
    }

    fn decode(data: &[u8], expected_topic: TopicId) -> Result<Self> {
        let value = Self::decode_signed(data)?;
        anyhow::ensure!(
            value.topic == expected_topic,
            "message belongs to another topic"
        );
        Ok(value)
    }

    fn decode_signed(data: &[u8]) -> Result<Self> {
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
        value.validate_semantics()?;
        Ok(value)
    }

    fn validate_semantics(&self) -> Result<()> {
        match self.kind {
            EnvelopeKind::Message => crate::message::validate_v2_message_body(&self.body),
            EnvelopeKind::AttachmentOffer => validate_attachment_envelope(self).map(|_| ()),
        }
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
        crate::ipc::valid_operation_id(&wire.offer.offer_id),
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
    anyhow::ensure!(
        ticket.to_string() == wire.offer.ticket,
        "attachment ticket is not canonical"
    );
    Ok(Some(wire.offer))
}

fn validate_attachment_envelope(envelope: &Envelope) -> Result<AttachmentOffer> {
    anyhow::ensure!(
        envelope.kind == EnvelopeKind::AttachmentOffer,
        "message is not an attachment offer"
    );
    anyhow::ensure!(
        envelope.timestamp_ms != 0,
        "attachment envelope timestamp is invalid"
    );
    let offer = parse_attachment_body(&envelope.body)?
        .context("attachment envelope does not contain a typed offer")?;
    anyhow::ensure!(
        direct::id_string(&envelope.message_id) == offer.offer_id,
        "attachment envelope message ID does not match offer ID"
    );
    let ticket: BlobTicket = offer.ticket.parse().context("parse attachment ticket")?;
    anyhow::ensure!(
        ticket.addr().id == envelope.from,
        "attachment provider does not match its signature"
    );
    Ok(offer)
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
    let offer = validate_attachment_envelope(&envelope)?;
    let ticket: BlobTicket = offer.ticket.parse().context("parse attachment ticket")?;
    Ok((offer, ticket))
}

/// Validate an IPC/HTTP attachment event against the complete signed offer,
/// rather than trusting duplicated presentation fields. The active daemon has
/// already checked the topic; local consumers can still prove that one topic,
/// provider, timestamp, kind, ticket/hash/format, name, size, and canonical ID
/// were signed together.
pub(crate) fn validate_attachment_event(
    expected_topic: Option<TopicId>,
    live_now_ms: Option<u64>,
    from: &str,
    message_id: &str,
    timestamp_ms: u64,
    offer: &AttachmentOffer,
    token: &str,
) -> Result<()> {
    anyhow::ensure!(
        crate::contracts::valid_operation_id(message_id),
        "invalid attachment message ID"
    );
    anyhow::ensure!(
        offer.offer_id == message_id,
        "attachment event IDs do not match"
    );
    let encoded = BASE64URL_NOPAD
        .decode(token.as_bytes())
        .context("decode signed attachment event")?;
    let envelope = Envelope::decode_signed(&encoded)?;
    if let Some(expected_topic) = expected_topic {
        anyhow::ensure!(
            envelope.topic == expected_topic,
            "attachment event belongs to another topic"
        );
    }
    if let Some(now_ms) = live_now_ms {
        let oldest = now_ms.saturating_sub(ENVELOPE_ACCEPTANCE_WINDOW.as_millis() as u64);
        let newest = now_ms.saturating_add(ENVELOPE_FUTURE_SKEW.as_millis() as u64);
        anyhow::ensure!(
            (oldest..=newest).contains(&envelope.timestamp_ms),
            "attachment event timestamp is outside the live acceptance window"
        );
    }
    let signed_offer = validate_attachment_envelope(&envelope)?;
    anyhow::ensure!(
        envelope.from.to_string() == from,
        "attachment event provider does not match"
    );
    anyhow::ensure!(
        direct::id_string(&envelope.message_id) == message_id,
        "attachment event message ID does not match"
    );
    anyhow::ensure!(
        envelope.timestamp_ms == timestamp_ms && timestamp_ms != 0,
        "attachment event timestamp does not match"
    );
    anyhow::ensure!(
        &signed_offer == offer,
        "attachment event metadata does not match its signed offer"
    );
    Ok(())
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

#[cfg(debug_assertions)]
pub(crate) fn signed_attachment_fixture(
    dir: &Path,
    offer_id: &str,
    kind: &str,
    name: &str,
    size: u64,
) -> Result<serde_json::Value> {
    anyhow::ensure!(
        contracts::valid_operation_id(offer_id),
        "invalid fixture offer ID"
    );
    attachment::validate_display_name(name)?;
    let kind = match kind {
        "file" => AttachmentKind::File,
        "directory_tar_v1" => AttachmentKind::DirectoryTarV1,
        _ => anyhow::bail!("invalid fixture attachment kind"),
    };
    let (state, secret) = State::load_for_doctor(dir)?;
    let topic = state.topic_id()?;
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_millis() as u64;
    let offer = AttachmentOffer {
        offer_id: offer_id.to_owned(),
        kind,
        name: name.to_owned(),
        size,
        ticket: BlobTicket::new(
            iroh::EndpointAddr::new(secret.public()),
            iroh_blobs::Hash::new(format!("{offer_id}:{kind:?}:{name}:{size}").as_bytes()),
            BlobFormat::Raw,
        )
        .to_string(),
    };
    let encoded = Envelope::encode_with_id_at(
        &secret,
        topic,
        EnvelopeKind::AttachmentOffer,
        attachment_body(&offer)?,
        operation_id_bytes(offer_id),
        timestamp_ms,
    )?;
    let envelope = Envelope::decode(&encoded, topic)?;
    Ok(offer_event(envelope, &encoded, offer))
}

#[cfg(test)]
pub(crate) fn signed_attachment_event_for_test(
    secret: &SecretKey,
    offer_id: &str,
    kind: AttachmentKind,
    name: &str,
    size: u64,
    timestamp_ms: u64,
) -> serde_json::Value {
    signed_attachment_event_for_topic_for_test(
        secret,
        TopicId::from_bytes([7; 32]),
        offer_id,
        kind,
        name,
        size,
        timestamp_ms,
    )
}

#[cfg(test)]
pub(crate) fn signed_attachment_event_for_topic_for_test(
    secret: &SecretKey,
    topic: TopicId,
    offer_id: &str,
    kind: AttachmentKind,
    name: &str,
    size: u64,
    timestamp_ms: u64,
) -> serde_json::Value {
    let offer = AttachmentOffer {
        offer_id: offer_id.to_owned(),
        kind,
        name: name.to_owned(),
        size,
        ticket: BlobTicket::new(
            iroh::EndpointAddr::new(secret.public()),
            iroh_blobs::Hash::new(b"test attachment"),
            BlobFormat::Raw,
        )
        .to_string(),
    };
    let encoded = Envelope::encode_with_id_at(
        secret,
        topic,
        EnvelopeKind::AttachmentOffer,
        attachment_body(&offer).expect("test offer body"),
        operation_id_bytes(offer_id),
        timestamp_ms,
    )
    .expect("test signed attachment envelope");
    let envelope = Envelope::decode(&encoded, topic).expect("test offer decode");
    offer_event(envelope, &encoded, offer)
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
    direct_incoming: mpsc::Receiver<serde_json::Value>,
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
        .alpn(BROADCAST_ALPN_V2)
        .max_message_size(GOSSIP_MAX_MESSAGE_SIZE)
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
        .accept(BROADCAST_ALPN_V2, gossip.clone())
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
    response: serde_json::Value,
    expires_at: StdInstant,
    prune_resolution: Option<PruneResolution>,
}

struct InFlightOperation {
    fingerprint: [u8; 32],
    waiters: Vec<oneshot::Sender<serde_json::Value>>,
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

    fn error(operation_id: &str, code: &str, diagnostic: &str) -> serde_json::Value {
        let mut error = ErrorEnvelopeV1::new(
            code,
            diagnostic,
            "not_started",
            code == "operation_capacity",
        );
        error.operation_id = Some(operation_id.to_owned());
        error.into_value()
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
                if let Some(resolution) = entry.prune_resolution {
                    if entry
                        .response
                        .get("cutoff_ms")
                        .is_some_and(|value| !value.is_null())
                    {
                        debug_assert_eq!(
                            entry
                                .response
                                .get("older_than_secs")
                                .and_then(serde_json::Value::as_u64),
                            Some(resolution.older_than_secs)
                        );
                        debug_assert_eq!(
                            entry
                                .response
                                .get("cutoff_ms")
                                .and_then(serde_json::Value::as_u64),
                            Some(resolution.cutoff_ms)
                        );
                    }
                }
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
        reply: oneshot::Sender<serde_json::Value>,
    },
    PrivateSend {
        operation_id: String,
        to: String,
        body: String,
        reply: oneshot::Sender<serde_json::Value>,
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
        operation_id: String,
        offer_id: String,
        direction: Option<String>,
        provider: Option<String>,
        reply: oneshot::Sender<serde_json::Value>,
    },
    OffersPrune {
        operation_id: String,
        older_than_secs: u64,
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
        operation_id: String,
        offer: String,
        output: PathBuf,
        mode: meshmsg_protocol::DownloadMode,
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
                | "private_send_busy" => "not_started",
                _ => "unknown",
            });
        let retryable = value
            .get("retryable")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(code == "private_send_busy" || outcome != "not_started");
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
        error.direction = value
            .get("direction")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        error.provider = value
            .get("provider")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        error.older_than_secs = value
            .get("older_than_secs")
            .and_then(serde_json::Value::as_u64);
        error.maximum = value
            .get("maximum")
            .and_then(serde_json::Value::as_u64)
            .and_then(|count| usize::try_from(count).ok());
        error.dry_run = value.get("dry_run").and_then(serde_json::Value::as_bool);
        error.cutoff_ms = value.get("cutoff_ms").and_then(serde_json::Value::as_u64);
        error.suppressed_since_last = value
            .get("suppressed_since_last")
            .and_then(serde_json::Value::as_u64)
            .filter(|_| code == "internal_contract_error");
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
    let mut response = IPC_REQUEST_ID
        .try_with(|current| {
            current
                .borrow()
                .as_deref()
                .map(|id| normalize_ipc_response(value, id))
        })
        .ok()
        .flatten()
        .unwrap_or_else(|| value.clone());
    response["protocol_version"] = meshmsg_protocol::PROTOCOL_VERSION.into();
    let response: meshmsg_protocol::DaemonFrame = serde_json::from_value(response.clone())
        .with_context(|| format!("daemon produced a noncanonical typed local frame: {response}"))?;
    tokio::time::timeout(
        deadline,
        meshmsg_protocol::write_json(stream, &response, meshmsg_protocol::FrameLimit::Event),
    )
    .await
    .context("timed out writing local IPC response")?
    .map_err(anyhow::Error::from)
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
        Ok(Err(_)) => serde_json::json!({
            "type":"error", "code":"daemon_stopping", "retryable":true,
            "message":"The daemon is shutting down or unavailable."
        }),
        Err(_) => serde_json::json!({
            "type":"error", "code":"command_timeout", "retryable":true,
            "message":"The request timed out; reconcile before retrying."
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
                LocalIpcTimeouts::default(),
            ),
        )
        .await
}

async fn handle_local_client_with_timeouts<S>(
    stream: S,
    commands: mpsc::Sender<DaemonCommand>,
    events: broadcast::Receiver<serde_json::Value>,
    connected: serde_json::Value,
    startup_peers: Option<serde_json::Value>,
    timeouts: LocalIpcTimeouts,
) -> Result<()>
where
    S: SubscriptionStream,
{
    IPC_REQUEST_ID
        .scope(
            std::cell::RefCell::new(None),
            handle_local_client_inner(stream, commands, events, connected, startup_peers, timeouts),
        )
        .await
}

async fn handle_local_client_inner<S>(
    mut stream: S,
    commands: mpsc::Sender<DaemonCommand>,
    mut events: broadcast::Receiver<serde_json::Value>,
    connected: serde_json::Value,
    startup_peers: Option<serde_json::Value>,
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
            // Preserve the established reusable-operation behavior for a
            // structurally valid v2 send envelope whose bounded typed body is
            // the only rejected field. No command is admitted from this path.
            let raw = serde_json::from_slice::<serde_json::Value>(&frame).ok();
            let recoverable_send = raw.as_ref().and_then(|value| {
                let request_id = value.get("request_id")?.as_str()?;
                let request = value.get("request")?;
                let operation_id = request.get("operation_id")?.as_str()?;
                let body = request.get("body")?.as_str()?;
                (value.get("protocol_version")?.as_u64()
                    == Some(u64::from(meshmsg_protocol::PROTOCOL_VERSION))
                    && request.get("command")?.as_str() == Some("send")
                    && contracts::valid_request_id(request_id)
                    && valid_operation_id(operation_id)
                    && crate::message::validate_broadcast_body(body).is_err())
                .then(|| (request_id.to_owned(), operation_id.to_owned()))
            });
            let mut error = if recoverable_send.is_some() {
                ErrorEnvelopeV1::new(
                    "invalid_message",
                    "The message is invalid.",
                    "not_started",
                    false,
                )
            } else {
                ErrorEnvelopeV1::new(
                    "invalid_request",
                    "The request contract is invalid or unsupported.",
                    "not_started",
                    false,
                )
            };
            if let Some((request_id, operation_id)) = recoverable_send {
                error.request_id = Some(request_id);
                error.operation_id = Some(operation_id);
            }
            let _ = write_local_response(&mut stream, &error.into_value(), timeouts.response_write)
                .await;
            return Ok(());
        }
    };
    let _ = IPC_REQUEST_ID.try_with(|current| {
        *current.borrow_mut() = Some(request_frame.request_id.to_string());
    });
    let request = request_frame.request;
    let operation_id = match &request {
        IpcRequest::Send { operation_id, .. }
        | IpcRequest::PrivateSend { operation_id, .. }
        | IpcRequest::OffersRemove { operation_id, .. }
        | IpcRequest::OffersPrune { operation_id, .. }
        | IpcRequest::Share { operation_id, .. }
        | IpcRequest::Download { operation_id, .. } => Some(operation_id),
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
    let invalid_message = match &request {
        IpcRequest::Send { operation_id, body } => crate::message::validate_broadcast_body(body)
            .err()
            .map(|error| (operation_id, error)),
        IpcRequest::PrivateSend {
            operation_id, body, ..
        } => crate::message::validate_private_body(body)
            .err()
            .map(|error| (operation_id, error)),
        _ => None,
    };
    if let Some((operation_id, error)) = invalid_message {
        write_local_response(
            &mut stream,
            &OperationCache::error(operation_id, "invalid_message", &error.to_string()),
            timeouts.response_write,
        )
        .await?;
        return Ok(());
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
                        operation_id: operation_id.into_string(),
                        body: body.into_string(),
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
                        operation_id: operation_id.into_string(),
                        to: to.into_string(),
                        body: body.into_string(),
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
                Some(operation_id.into_string()),
                None,
            )
            .await;
            write_local_response(&mut stream, &value, timeouts.response_write).await?;
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
                Some(operation_id.into_string()),
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
                        operation_id: operation_id.into_string(),
                        source_digest: source_digest.into_string(),
                        path,
                        reply,
                    },
                    response,
                ),
                timeouts.transfer_command,
                Some(response_operation_id.into_string()),
                None,
            )
            .await;
            write_local_response(&mut stream, &value, timeouts.response_write).await?;
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
                Some(operation_id.into_string()),
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
                    "retryable":true, "message":"The daemon is shutting down or unavailable."
                }),
                Err(_) => serde_json::json!({
                    "type":"error", "code":"command_timeout", "outcome":"not_started",
                    "retryable":true, "message":"The request timed out; reconcile before retrying."
                }),
            };
            write_local_response(&mut stream, &response, timeouts.response_write).await?;
        }
    }
    Ok(())
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
    assert!(
        contracts::valid_operation_id(offer_id),
        "invalid attachment offer ID before tag generation"
    );
    attachment::validate_display_name(name).expect("invalid attachment name before tag generation");
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
    assert!(
        contracts::valid_operation_id(offer_id),
        "invalid attachment offer ID before tag generation"
    );
    attachment::validate_display_name(name).expect("invalid attachment name before tag generation");
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
            let canonical_provider = provider.parse::<PublicKey>().ok()?.to_string();
            if canonical_provider != provider {
                return None;
            }
            ("incoming", Some(canonical_provider), remainder)
        };
    let mut parts = remainder.split('/');
    let offer_id = parts.next()?;
    let kind = parse_attachment_kind(parts.next()?)?;
    let name = decode_tag_name(parts.next()?)?;
    if parts.next().is_some() || !contracts::valid_operation_id(offer_id) {
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

async fn list_pinned_blobs(store: &Store) -> Result<(Vec<OfferItemV1>, bool, usize)> {
    let mut tags = store
        .tags()
        .list_prefix(BLOB_TAG_PREFIX)
        .await
        .context("list attachment blob tags")?;
    // Validate at most 4096 records plus one presence-only lookahead. Continuing
    // after filling the public page accounts malformed/unavailable omitted items
    // without allocating an unbounded response.
    let mut blobs = Vec::new();
    let mut scanned = 0_usize;
    let mut item_errors = 0_usize;
    let mut has_more = false;
    while scanned < MAX_OFFER_LIST_SCANNED {
        let Some(item) = tags.next().await else { break };
        scanned += 1;
        let tag = match item {
            Ok(tag) => tag,
            Err(_) => {
                item_errors += 1;
                continue;
            }
        };
        let Some(parsed) = parse_pinned_blob_tag(tag.name.as_ref()) else {
            item_errors += 1;
            continue;
        };
        let size = match (tag.format, store.blobs().status(tag.hash).await) {
            (BlobFormat::Raw, Ok(iroh_blobs::api::proto::BlobStatus::Complete { size })) => size,
            (_, Ok(_)) => {
                item_errors += 1;
                continue;
            }
            (_, Err(_)) => {
                item_errors += 1;
                continue;
            }
        };
        if blobs.len() == MAX_OFFER_LIST_ENTRIES {
            has_more = true;
        } else {
            blobs.push(OfferItemV1 {
                direction: parsed.direction.into(),
                offer_id: parsed.offer_id,
                provider: parsed.provider,
                name: parsed.name,
                kind: attachment_kind_name(parsed.kind).into(),
                hash: tag.hash.to_string(),
                format: "raw".into(),
                status: "complete".into(),
                size: Some(size),
            });
        }
    }
    if scanned == MAX_OFFER_LIST_SCANNED {
        has_more |= tags.next().await.is_some();
    }
    has_more |= item_errors != 0;
    Ok((blobs, has_more, item_errors))
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttachmentRetentionIndex {
    schema_version: u8,
    #[serde(deserialize_with = "deserialize_attachment_index_entries")]
    created_at_ms: BTreeMap<String, u64>,
}

#[derive(Deserialize)]
struct AttachmentIndexVersionProbe {
    schema_version: u64,
}

fn deserialize_attachment_index_entries<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct EntriesVisitor;
    impl<'de> serde::de::Visitor<'de> for EntriesVisitor {
        type Value = BTreeMap<String, u64>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                formatter,
                "at most {MAX_ATTACHMENT_TAGS} bounded attachment index entries"
            )
        }

        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut access: A,
        ) -> Result<Self::Value, A::Error> {
            let mut entries = BTreeMap::new();
            while let Some(key) = access
                .next_key::<crate::persistent::BoundedString<MAX_ATTACHMENT_INDEX_TAG_BYTES>>()?
            {
                if entries.len() == MAX_ATTACHMENT_TAGS {
                    return Err(serde::de::Error::invalid_length(entries.len() + 1, &self));
                }
                let value = access.next_value::<u64>()?;
                if entries.insert(key.into_string(), value).is_some() {
                    return Err(serde::de::Error::custom(
                        "duplicate attachment retention index key",
                    ));
                }
            }
            Ok(entries)
        }
    }
    deserializer.deserialize_map(EntriesVisitor)
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
    status: meshmsg_protocol::AttachmentStorageStatus,
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

struct RemovalSpec<'a> {
    operation_id: &'a str,
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

    fn status(&self) -> meshmsg_protocol::AttachmentStorageStatus {
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
        let operation_id = crate::ipc::new_operation_id();
        self.remove(
            &operation_id,
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

    #[allow(clippy::too_many_arguments)] // Internal selector wrapper used outside strict IPC.
    async fn remove(
        &self,
        operation_id: &str,
        offer_id: Option<&str>,
        direction: Option<&str>,
        provider: Option<&str>,
        older_than_secs: Option<u64>,
        maximum: usize,
        dry_run: bool,
    ) -> Result<serde_json::Value> {
        let cutoff_ms = match older_than_secs {
            Some(age) => Some(crate::ipc::prune_cutoff_upper_bound(
                unix_timestamp_ms()?,
                age,
            )),
            None if offer_id.is_none() => Some(unix_timestamp_ms()?),
            None => None,
        };
        self.remove_at_cutoff(
            operation_id,
            offer_id,
            direction,
            provider,
            older_than_secs,
            cutoff_ms,
            maximum,
            dry_run,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)] // Mirrors the complete lifecycle selector contract.
    async fn remove_at_cutoff(
        &self,
        operation_id: &str,
        offer_id: Option<&str>,
        direction: Option<&str>,
        provider: Option<&str>,
        older_than_secs: Option<u64>,
        cutoff_ms: Option<u64>,
        maximum: usize,
        dry_run: bool,
    ) -> Result<serde_json::Value> {
        self.remove_with_fault_at_cutoff(
            RemovalSpec {
                operation_id,
                offer_id,
                direction,
                provider,
                older_than_secs,
                maximum,
                dry_run,
            },
            cutoff_ms,
            &|_| Ok(()),
        )
        .await
    }

    #[cfg(test)]
    async fn remove_with_fault(
        &self,
        spec: RemovalSpec<'_>,
        fault: &(dyn Fn(&'static str) -> Result<()> + Sync),
    ) -> Result<serde_json::Value> {
        let cutoff_ms = match spec.older_than_secs {
            Some(age) => Some(crate::ipc::prune_cutoff_upper_bound(
                unix_timestamp_ms()?,
                age,
            )),
            None if spec.offer_id.is_none() => Some(unix_timestamp_ms()?),
            None => None,
        };
        self.remove_with_fault_at_cutoff(spec, cutoff_ms, fault)
            .await
    }

    async fn remove_with_fault_at_cutoff(
        &self,
        spec: RemovalSpec<'_>,
        cutoff_ms: Option<u64>,
        fault: &(dyn Fn(&'static str) -> Result<()> + Sync),
    ) -> Result<serde_json::Value> {
        let RemovalSpec {
            operation_id,
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
        anyhow::ensure!(
            offer_id.is_some() == cutoff_ms.is_none(),
            "invalid internal lifecycle cutoff context"
        );
        let cutoff = cutoff_ms;
        let lifecycle_context = match (offer_id, older_than_secs) {
            (Some(offer_id), None) => LifecycleRequestContext::Remove {
                operation_id,
                offer_id,
                direction,
                provider,
                maximum,
            },
            (None, older_than_secs) => LifecycleRequestContext::Prune {
                operation_id,
                older_than_secs: older_than_secs.unwrap_or(0),
                cutoff_ms: Some(cutoff.context("prune cutoff missing")?),
                direction,
                dry_run,
                maximum,
            },
            _ => anyhow::bail!("invalid internal lifecycle request context"),
        };
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
            return Ok(LifecycleSuccessV3::new(
                &lifecycle_context,
                selected_names.len(),
                0,
                before.saturating_sub(projected_usage),
                limited,
                cutoff,
            )?
            .into_value());
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
            let _ = self.reconcile().await;
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
            bind_partial_lifecycle_error(&mut error, &lifecycle_context, cutoff);
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
            bind_partial_lifecycle_error(&mut error, &lifecycle_context, cutoff);
            return Ok(error.into_value());
        }
        self.recalculate_cached_status().await?;
        Ok(LifecycleSuccessV3::new(
            &lifecycle_context,
            selected_names.len(),
            removed.len(),
            before.saturating_sub(self.status().tagged_bytes),
            limited,
            cutoff,
        )?
        .into_value())
    }
}

fn bind_partial_lifecycle_error(
    error: &mut LifecycleErrorV1,
    context: &LifecycleRequestContext<'_>,
    cutoff_ms: Option<u64>,
) {
    match context {
        LifecycleRequestContext::Remove {
            direction,
            provider,
            maximum,
            ..
        } => {
            error.direction = direction.map(str::to_owned);
            error.provider = provider.map(str::to_owned);
            error.older_than_secs = None;
            error.maximum = Some(*maximum);
            error.dry_run = Some(false);
            error.cutoff_ms = None;
        }
        LifecycleRequestContext::Prune {
            older_than_secs,
            direction,
            dry_run,
            maximum,
            ..
        } => {
            error.direction = direction.map(str::to_owned);
            error.provider = None;
            error.older_than_secs = Some(*older_than_secs);
            error.maximum = Some(*maximum);
            error.dry_run = Some(*dry_run);
            error.cutoff_ms = cutoff_ms;
        }
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
    let Some(bytes) = crate::persistent::read_optional_file_bounded(
        &path,
        "attachment retention index",
        MAX_ATTACHMENT_INDEX_BYTES,
    )?
    else {
        return Ok(AttachmentRetentionIndex::default());
    };
    let probe: AttachmentIndexVersionProbe = crate::persistent::parse_json_bounded_strings(
        &bytes,
        "attachment retention index",
        MAX_ATTACHMENT_INDEX_TAG_BYTES,
    )?;
    if probe.schema_version != 1 {
        return Err(crate::persistent::PersistentError::unsupported_version(
            "attachment retention index",
            probe.schema_version,
        )
        .into());
    }
    let index: AttachmentRetentionIndex = crate::persistent::parse_json_bounded_strings(
        &bytes,
        "attachment retention index",
        MAX_ATTACHMENT_INDEX_TAG_BYTES,
    )?;
    if index.schema_version != 1 {
        return Err(crate::persistent::PersistentError::unsupported_version(
            "attachment retention index",
            u64::from(index.schema_version),
        )
        .into());
    }
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
) -> meshmsg_protocol::AttachmentStorageStatus {
    let tags = tags.into_iter().collect::<Vec<_>>();
    let (tagged_bytes, tagged_blobs) = unique_storage_usage(tags.iter().copied());
    let over_quota = tagged_bytes > quota_bytes;
    let below_min_free = available_bytes < min_free_bytes;
    meshmsg_protocol::AttachmentStorageStatus {
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

fn try_admit_offer_listing(
    limit: &Arc<Semaphore>,
) -> Result<OwnedSemaphorePermit, serde_json::Value> {
    limit.clone().try_acquire_owned().map_err(|_| {
        LifecycleErrorV1::new(
            "offers_busy",
            "Attachment listing is currently busy.",
            "not_started",
            true,
        )
        .into_value()
    })
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
        let validated = Envelope::decode(&encoded, topic)
            .expect("locally encoded attachment envelope must decode");
        let message_id = validated.message_id;
        let validated_offer = validate_attachment_envelope(&validated)
            .expect("locally encoded attachment semantics must validate");
        anyhow::ensure!(
            validated_offer == offer,
            "locally encoded attachment offer changed"
        );
        let tag_name = outbound_blob_tag(&offer.offer_id, offer.kind, &offer.name);
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

pub(crate) fn download_request_context(
    operation_id: &str,
    token: &str,
    output: &Path,
    topic: TopicId,
) -> Result<crate::ipc::DownloadRequestContext> {
    let (offer_id, provider, kind, name, declared_size) =
        match parse_signed_offer_token(token, topic) {
            Ok((offer, ticket)) => (
                offer.offer_id,
                ticket.addr().id.to_string(),
                match offer.kind {
                    AttachmentKind::File => "file".to_owned(),
                    AttachmentKind::DirectoryTarV1 => "directory_tar_v1".to_owned(),
                },
                offer.name,
                Some(offer.size),
            ),
            Err(signed_error) => {
                let ticket: BlobTicket = token.parse().map_err(|_| signed_error)?;
                anyhow::ensure!(
                    ticket.format() == BlobFormat::Raw,
                    "only raw blob tickets are supported"
                );
                (
                    raw_ticket_offer_id(&ticket),
                    ticket.addr().id.to_string(),
                    "file".to_owned(),
                    output
                        .file_name()
                        .and_then(|value| value.to_str())
                        .unwrap_or("attachment")
                        .to_owned(),
                    None,
                )
            }
        };
    Ok(crate::ipc::DownloadRequestContext {
        operation_id: operation_id.to_owned(),
        token_digest: crate::ipc::download_token_digest(token),
        offer_id,
        provider,
        kind,
        name,
        declared_size,
        output: output.to_path_buf(),
    })
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
    operation_id: &str,
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
    let token_digest = crate::ipc::download_token_digest(&offer_token);
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
                        if verified_size > 0
                            && (received_bytes >= next_report
                                || received_bytes == verified_size) =>
                    {
                        let _ = events.send(serde_json::json!({
                            "type":"download_progress", "schema_version":2,
                            "operation_id":operation_id,
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
    if size == 0 {
        let _ = events.send(serde_json::json!({
            "type":"download_progress", "schema_version":2,
            "operation_id":operation_id,
            "received_bytes":0, "total_bytes":0, "output":output
        }));
    }
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
        "type":"download_complete", "schema_version":2,
        "operation_id":operation_id, "token_digest":token_digest,
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
    let mut envelope_replay = EnvelopeReplayCache::default();
    let mut broadcast_sources = TransportSourceLimiter::default();
    let mut broadcast_rejections = RejectionSampler::default();
    let internal_contract_guard = Arc::new(Mutex::new(InternalContractGuard::default()));
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
                        let connected = serde_json::json!({
                            "type":"connected", "peer":peer, "endpoint_online":true,
                            "topic_joined":node.receiver.is_joined(),
                            "alias":alias_config.effective(),
                        });
                        Ok(LocalClientSession {
                            commands: command_tx.clone(),
                            events: event_tx.subscribe(),
                            connected,
                            startup_peers: Some(startup_peers),
                        })
                    },
                ).await?;
            }
            command = command_rx.recv() => match command {
                Some(DaemonCommand::Send { operation_id, body, reply }) => {
                    if let Err(error) = crate::message::validate_broadcast_body(&body) {
                        let _ = reply.send(OperationCache::error(
                            &operation_id, "invalid_message", &error.to_string(),
                        ));
                        continue;
                    }
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
                        publish_daemon_message_event(
                            &event_tx,
                            response.clone(),
                            &mut internal_contract_guard.lock().expect("contract guard poisoned"),
                            topic,
                            unix_timestamp_ms().unwrap_or(0),
                        );
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
                    let permit = match direct_sender.try_reserve() {
                        Ok(permit) => permit,
                        Err(response) => {
                            operation_cache.lock().expect("operation cache poisoned").complete(
                                &operation_id, response, StdInstant::now(),
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
                    let _ = reply.send(serde_json::to_value(meshmsg_protocol::Response::Status(
                        status,
                    ))?);
                }
                Some(DaemonCommand::Peers { reply }) => {
                    presence::emit_transitions(directory.cleanup(), &event_tx, &directory_epoch, &mut directory_revision);
                    let generated_at_ms = unix_timestamp_ms()?;
                    let _ = reply.send(presence::snapshot(
                        (&node.endpoint, &node.receiver),
                        &directory,
                        &peer,
                        alias_config.effective(),
                        generated_at_ms,
                        &directory_epoch,
                        directory_revision,
                    ));
                }
                Some(DaemonCommand::Offers { reply }) => {
                    let permit = match try_admit_offer_listing(&offer_list_limit) {
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
                            Ok((blobs, has_more, item_errors)) => match OffersV1::new(
                                blobs, has_more, item_errors,
                            ) {
                                Ok(offers) => offers.into_value(),
                                Err(error) => ErrorEnvelopeV1::new(
                                    "offers_failed", error.to_string(), "unknown", true,
                                ).into_value(),
                            },
                            Err(error) => serde_json::json!({
                                "type":"error", "code":"offers_failed", "message":error.to_string()
                            }),
                        };
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
                                let mut error = LifecycleErrorV1::new(
                                    "invalid_offer_selector", "provider must be a canonical public key",
                                    "not_started", false,
                                );
                                error.operation_id = Some(operation_id.clone());
                                error.offer_id = Some(offer_id.clone());
                                operation_cache.lock().expect("operation cache poisoned").complete(
                                    &operation_id, error.into_value(), StdInstant::now());
                                continue;
                            }
                        },
                        None => None,
                    };
                    if !contracts::valid_operation_id(&offer_id) || !valid_direction {
                        let mut error = LifecycleErrorV1::new(
                            "invalid_offer_selector", "offer ID or direction is invalid",
                            "not_started", false,
                        );
                        error.operation_id = Some(operation_id.clone());
                        if contracts::valid_operation_id(&offer_id) { error.offer_id = Some(offer_id.clone()); }
                        operation_cache.lock().expect("operation cache poisoned").complete(
                            &operation_id, error.into_value(), StdInstant::now());
                        continue;
                    }
                    let storage = attachment_storage.clone();
                    let operation_cache = operation_cache.clone();
                    offer_list_tasks.spawn(async move {
                        let response = match storage.remove_at_cutoff(
                            &operation_id, Some(&offer_id), direction.as_deref(), provider.as_deref(), None,
                            None, MAX_PRUNE_TAGS, false,
                        ).await {
                            Ok(value) => value,
                            // Only selector and partial-removal errors are offer-specific.
                            // Generic capacity/storage failures remain operation-bound.
                            Err(error) => storage_operation_error("offers_remove_failed", &error, false, Some(&operation_id), None),
                        };
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
                        let mut error = LifecycleErrorV1::new(
                            "invalid_prune_request", "prune direction or maximum is invalid",
                            "not_started", false,
                        );
                        error.operation_id = Some(operation_id.clone());
                        operation_cache.lock().expect("operation cache poisoned").complete(
                            &operation_id, error.into_value(), StdInstant::now());
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
                        let response = match storage.remove_at_cutoff(
                            &operation_id, None, direction.as_deref(), None, Some(age), Some(cutoff), max_delete, dry_run,
                        ).await {
                            Ok(value) => value,
                            Err(error) => storage_operation_error("offers_prune_failed", &error, false, Some(&operation_id), None),
                        };
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
                    let contract_guard = internal_contract_guard.clone();
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
                                    "unknown", true,
                                );
                                error.operation_id = Some(operation_id.clone());
                                error.into_value()
                            },
                        };
                        let response = operation_cache.lock().expect("operation cache poisoned")
                            .complete(&operation_id, response, StdInstant::now());
                        if response["type"] == "attachment_shared" {
                            publish_daemon_message_event(
                                &events,
                                response,
                                &mut contract_guard.lock().expect("contract guard poisoned"),
                                topic,
                                unix_timestamp_ms().unwrap_or(0),
                            );
                        }
                    });
                }
                Some(DaemonCommand::Download { operation_id, offer, output, mode, reply }) => {
                    let mode_name = match mode {
                        meshmsg_protocol::DownloadMode::Install => "install",
                        meshmsg_protocol::DownloadMode::Raw => "raw",
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
                            let mut error = LifecycleErrorV1::new(
                                "attachment_storage_busy", "attachment transfer capacity reached",
                                "not_started", true,
                            );
                            error.operation_id = Some(operation_id.clone());
                            operation_cache.lock().expect("operation cache poisoned").complete(
                                &operation_id, error.into_value(), StdInstant::now());
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
                        let storage_permit = storage.gate.clone().acquire_owned().await;
                        let response = match storage_permit {
                            Ok(_storage_permit) => {
                        let started = serde_json::json!({"type":"download_started", "schema_version":2, "operation_id":operation_id, "output":output});
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
                            &operation_id,
                            offer,
                            output,
                            max_attachment_bytes,
                            mode == meshmsg_protocol::DownloadMode::Raw,
                        ).await {
                            Ok(value) => value,
                            Err(error) => storage_operation_error("download_failed", &error, false, Some(&operation_id), None),
                        }
                            }
                            Err(_) => {
                                let mut error = LifecycleErrorV1::new(
                                    "attachment_storage_shutdown", "attachment storage is shutting down",
                                    "unknown", true,
                                );
                                error.operation_id = Some(operation_id.clone());
                                error.into_value()
                            },
                        };
                        let response = operation_cache.lock().expect("operation cache poisoned")
                            .complete(&operation_id, response, StdInstant::now());
                        if response["type"] == "download_complete" {
                            let _ = events.send(response);
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
                    let values = network_event(
                        value,
                        topic,
                        &mut envelope_replay,
                        &mut broadcast_sources,
                        &mut broadcast_rejections,
                        now_ms,
                    );
                    for full_value in values {
                        publish_daemon_message_event(
                            &event_tx,
                            full_value,
                            &mut internal_contract_guard.lock().expect("contract guard poisoned"),
                            topic,
                            now_ms,
                        );
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

fn received_envelope_event(envelope: Envelope, encoded: &[u8]) -> serde_json::Value {
    if envelope.kind == EnvelopeKind::Message {
        return message_event(envelope);
    }
    match validate_attachment_envelope(&envelope) {
        Ok(offer) => offer_event(envelope, encoded, offer),
        Err(error) => serde_json::json!({
            "type":"error", "code":"invalid_attachment_offer",
            "message":error.to_string()
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
            if !sources.allow_verification(source, now_ms) {
                return rejections
                    .event(now_ms, "broadcast verification rate limit exceeded")
                    .into_iter()
                    .collect();
            }
            // Signature and complete semantics come before accepted-traffic
            // accounting. Freshness/replay admission also comes first, so
            // stale, future, replayed, and malformed frames pay only the
            // separate cheap verification-attempt budget.
            match Envelope::decode(&message.content, topic).and_then(|envelope| {
                anyhow::ensure!(
                    sources.admission_available(source, now_ms),
                    "broadcast transport source rate limit exceeded"
                );
                replay.accept(&envelope, source, now_ms)?;
                sources.consume_admission(source, now_ms);
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

fn valid_daemon_message_event(value: &serde_json::Value, topic: TopicId, now_ms: u64) -> bool {
    match value.get("type").and_then(serde_json::Value::as_str) {
        Some("message" | "queued" | "attachment_offer" | "attachment_shared") => {
            let correlated = contracts::correlate(value.clone(), &contracts::new_request_id());
            crate::ipc::validate_success_payload_for_context(&correlated, Some(topic), Some(now_ms))
                .is_ok()
        }
        _ => true,
    }
}

fn publish_daemon_message_event(
    events: &broadcast::Sender<serde_json::Value>,
    value: serde_json::Value,
    guard: &mut InternalContractGuard,
    topic: TopicId,
    now_ms: u64,
) -> bool {
    if valid_daemon_message_event(&value, topic, now_ms) {
        let _ = events.send(value);
        return true;
    }
    let family = value
        .get("type")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");
    if let Some(error) = guard.rejection(now_ms, family) {
        let _ = events.send(error);
    }
    false
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
                operation_id: operation_id.parse()?,
                body: meshmsg_protocol::BroadcastBody::new(body)?,
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
            operation_id: operation_id.parse()?,
            source_digest: source_digest.parse()?,
            path,
        },
        "attachment_shared",
        3,
        AttachmentOperationKind::Share,
        &operation_id,
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
    operation_kind: AttachmentOperationKind,
    expected_operation_id: &str,
    lifecycle_context: Option<&LifecycleRequestContext<'_>>,
) -> Result<serde_json::Value> {
    let value = crate::ipc::send_request(dir, request).await?;
    if value.get("type").and_then(serde_json::Value::as_str) == Some("error") {
        let error = crate::ipc::validate_lifecycle_error_for_request(
            &value,
            operation_kind,
            expected_operation_id,
            lifecycle_context.and_then(|context| match context {
                LifecycleRequestContext::Remove { offer_id, .. } => Some(*offer_id),
                LifecycleRequestContext::Prune { .. } => None,
            }),
            lifecycle_context,
        )?;
        return Err(anyhow::Error::new(contracts::ContractFailure(error)));
    }
    crate::ipc::validate_response(&value, expected_type, Some(expected_schema_version))?;
    Ok(value)
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
    let lifecycle_context = LifecycleRequestContext::Remove {
        operation_id: &operation_id,
        offer_id,
        direction,
        provider,
        maximum: MAX_PRUNE_TAGS,
    };
    let value = send_lifecycle_request(
        dir,
        &IpcRequest::OffersRemove {
            operation_id: operation_id.parse()?,
            offer_id: offer_id.parse()?,
            direction: direction.map(str::parse).transpose()?,
            provider: provider.map(str::parse).transpose()?,
        },
        "offer_removed",
        3,
        AttachmentOperationKind::Remove,
        &operation_id,
        Some(&lifecycle_context),
    )
    .await?;
    LifecycleSuccessV3::from_value_for_request(&value, &lifecycle_context)?;
    event(json, value);
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
    let status = send_request_checked(dir, &IpcRequest::Status, "status", None).await?;
    let effective_age = older_than_secs
        .unwrap_or_else(|| status["attachment_retention_secs"].as_u64().unwrap_or(0));
    let lifecycle_context = LifecycleRequestContext::Prune {
        operation_id: &operation_id,
        older_than_secs: effective_age,
        cutoff_ms: None,
        direction,
        dry_run,
        maximum: max_delete,
    };
    let value = send_lifecycle_request(
        dir,
        &IpcRequest::OffersPrune {
            operation_id: operation_id.parse()?,
            older_than_secs: effective_age,
            direction: direction.map(str::parse).transpose()?,
            dry_run,
            max_delete,
        },
        "offers_pruned",
        3,
        AttachmentOperationKind::Prune,
        &operation_id,
        Some(&lifecycle_context),
    )
    .await?;
    LifecycleSuccessV3::from_value_for_request(&value, &lifecycle_context)?;
    event(json, value);
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
    let status = send_request_checked(dir, &IpcRequest::Status, "status", None).await?;
    // Retain the exact absolute representation submitted to the daemon. Do not
    // canonicalize through symlinks or require the not-yet-created destination.
    let requested_output = caller_path(output)?;
    let topic_bytes: [u8; 32] = data_encoding::HEXLOWER
        .decode(
            status["topic"]
                .as_str()
                .context("daemon status omitted its topic")?
                .as_bytes(),
        )
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
    let value = send_lifecycle_request(
        dir,
        &IpcRequest::Download {
            operation_id: operation_id.parse()?,
            offer: offer.to_owned(),
            output: requested_output.clone(),
            mode: meshmsg_protocol::DownloadMode::Install,
        },
        "download_complete",
        2,
        AttachmentOperationKind::Download,
        &operation_id,
        None,
    )
    .await?;
    crate::ipc::DownloadCompleteV2::validate_for_request(&value, &expected)?;
    event(json, value);
    Ok(())
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

    fn connected_fixture() -> serde_json::Value {
        serde_json::json!({
            "type":"connected", "peer":"2".repeat(64),
            "endpoint_online":true, "topic_joined":true,
            "alias":null
        })
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

        let partial = serde_json::json!({
            "type":"download_complete", "schema_version":2,
            "destination_synced":false, "cleanup_complete":false,
            "warnings":["sync warning"]
        });
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
        let mut removal_error =
            LifecycleErrorV1::new("attachment_removal_partial", "private", "partial", true);
        removal_error.offer_id = Some("cccccccccccccccccccccccccccccccc".into());
        removal_error.selected_tags = Some(2);
        removal_error.removed_tags = Some(1);
        removal_error.quota_bytes_released = Some(4);
        let removal = partial_cache.complete(removal_id, removal_error.into_value(), now);
        assert_eq!(removal_response.await.unwrap(), removal);
        let (removal_retry, removal_retry_response) = oneshot::channel();
        assert!(!partial_cache.admit(removal_id.into(), removal_fp, removal_retry, now));
        assert_eq!(removal_retry_response.await.unwrap(), removal);

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
    fn lifecycle_partial_errors_survive_cache_normalization_and_strict_consumption() {
        let now = StdInstant::now();
        let operation = "11111111111111111111111111111111";
        let offer = "22222222222222222222222222222222";
        let provider = SecretKey::generate().public().to_string();
        for (kind, context, cutoff) in [
            (
                AttachmentOperationKind::Remove,
                LifecycleRequestContext::Remove {
                    operation_id: operation,
                    offer_id: offer,
                    direction: Some("incoming"),
                    provider: Some(&provider),
                    maximum: 7,
                },
                None,
            ),
            (
                AttachmentOperationKind::Prune,
                LifecycleRequestContext::Prune {
                    operation_id: operation,
                    older_than_secs: 60,
                    cutoff_ms: Some(10_000),
                    direction: Some("outgoing"),
                    dry_run: false,
                    maximum: 7,
                },
                Some(10_000),
            ),
        ] {
            let mut producer = LifecycleErrorV1::new(
                "attachment_removal_partial",
                "private store failure",
                "partial",
                true,
            );
            producer.selected_tags = Some(3);
            producer.removed_tags = Some(1);
            producer.quota_bytes_released = Some(4);
            producer.offer_id = (kind == AttachmentOperationKind::Remove).then(|| offer.into());
            bind_partial_lifecycle_error(&mut producer, &context, cutoff);

            let mut cache = OperationCache::new(2, Duration::from_secs(60));
            let (reply, _receiver) = oneshot::channel();
            assert!(cache.admit(operation.into(), [7; 32], reply, now));
            let cached = cache.complete(operation, producer.into_value(), now);
            let normalized = normalize_ipc_response(&cached, "33333333333333333333333333333333");
            let consumed = crate::ipc::validate_lifecycle_error_for_request(
                &normalized,
                kind,
                operation,
                (kind == AttachmentOperationKind::Remove).then_some(offer),
                Some(&context),
            )
            .unwrap();
            assert_eq!(consumed.direction.as_deref(), context_direction(&context));
            assert_eq!(consumed.maximum, Some(7));
            assert_eq!(consumed.dry_run, Some(false));
            assert_eq!(consumed.cutoff_ms, cutoff);
            match &context {
                LifecycleRequestContext::Remove { provider, .. } => {
                    assert_eq!(consumed.provider.as_deref(), *provider);
                    assert_eq!(consumed.older_than_secs, None);
                }
                LifecycleRequestContext::Prune {
                    older_than_secs, ..
                } => {
                    assert_eq!(consumed.provider, None);
                    assert_eq!(consumed.older_than_secs, Some(*older_than_secs));
                }
            }
        }
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
        let terminal = serde_json::json!({
            "type":"offers_pruned", "older_than_secs":60, "cutoff_ms":40_000
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
        assert_eq!(replayed["type"], terminal["type"]);
        assert_eq!(replayed["cutoff_ms"], terminal["cutoff_ms"]);
        assert_eq!(replayed["operation_id"], operation);

        let (conflict_reply, conflict_receiver) = oneshot::channel();
        assert!(!cache.admit(
            operation.into(),
            fingerprint(61),
            conflict_reply,
            now + Duration::from_secs(1),
        ));
        let conflict = conflict_receiver.blocking_recv().unwrap();
        assert_eq!(conflict["code"], "operation_id_conflict");
        assert_eq!(conflict["operation_id"], operation);
    }

    fn context_direction<'a>(context: &'a LifecycleRequestContext<'a>) -> Option<&'a str> {
        match context {
            LifecycleRequestContext::Remove { direction, .. }
            | LifecycleRequestContext::Prune { direction, .. } => *direction,
        }
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
    fn concurrent_offer_listing_returns_the_stable_retryable_busy_contract() {
        let limit = Arc::new(Semaphore::new(1));
        let active_listing = try_admit_offer_listing(&limit).unwrap();
        let busy = try_admit_offer_listing(&limit).unwrap_err();
        let request_id = "11111111111111111111111111111111";
        let normalized = normalize_ipc_response(&busy, request_id);
        let error = ErrorEnvelopeV1::from_value(&normalized).unwrap();
        assert_eq!(error.code, "offers_busy");
        assert_eq!(error.message, "Attachment listing is currently busy.");
        assert_eq!(error.outcome, "not_started");
        assert!(error.retryable);
        assert_eq!(error.request_id.as_deref(), Some(request_id));
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
        assert_eq!(context.offer_id, offer.offer_id);
        assert_eq!(context.provider, secret.public().to_string());
        assert_eq!(context.kind, "file");
        assert_eq!(context.name, "report.txt");
        assert_eq!(context.declared_size, Some(6));
        assert_eq!(
            context.token_digest,
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
        assert!(Envelope::decode(&zero_time, test_topic()).is_err());
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
        let mut rejections = RejectionSampler::default();

        let rejected = network_event(
            Event::Received(iroh_gossip::api::Message {
                content: signed_envelope(String::new()).into(),
                scope: iroh_gossip::proto::DeliveryScope::Neighbors,
                delivered_from: source,
            }),
            topic,
            &mut replay,
            &mut sources,
            &mut rejections,
            now_ms,
        );
        assert_eq!(rejected.len(), 1);
        let strict_rejection = ErrorEnvelopeV1::from_value(&rejected[0]).unwrap();
        assert_eq!(strict_rejection.code, "network_event_rejected");
        assert_eq!(strict_rejection.message, "A network event was rejected.");
        assert_eq!(strict_rejection.outcome, "not_started");
        assert!(!strict_rejection.retryable);
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
            &mut rejections,
            now_ms,
        );
        assert_eq!(accepted.len(), 1);
        assert_eq!(accepted[0]["type"], "message");
        assert_eq!(accepted[0]["body"], "still connected");
        assert_eq!(replay.live_ids, 1);
    }

    #[tokio::test]
    async fn local_daemon_interoperates_with_v2_and_rejects_legacy_versions() {
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
        // the public event DTO, not through an in-crate compatibility shape.
        let (mut client, server) = tokio::io::duplex(4096);
        let (commands, _command_rx) = mpsc::channel(1);
        let (events, _) = broadcast::channel(1);
        let subscriber = tokio::spawn(handle_local_client(
            server,
            commands,
            events.subscribe(),
            serde_json::json!({
                "type":"connected", "peer":"2".repeat(64),
                "endpoint_online":true, "topic_joined":true,
                "alias":null
            }),
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
    }

    #[tokio::test]
    async fn generated_event_guard_keeps_live_strict_subscribers_and_reports_bounded_errors() {
        let secret = SecretKey::generate();
        let canonical = message_event(unsigned_test_envelope(
            secret.public(),
            "subscriber remains connected".to_owned(),
            42,
        ));
        let (events, _) = broadcast::channel(8);
        let (commands, _command_rx) = mpsc::channel(1);
        let (mut first, first_server) = tokio::io::duplex(MAX_IPC_EVENT_SIZE);
        let (mut second, second_server) = tokio::io::duplex(MAX_IPC_EVENT_SIZE);
        let first_task = tokio::spawn(handle_local_client(
            first_server,
            commands.clone(),
            events.subscribe(),
            connected_fixture(),
            None,
        ));
        let second_task = tokio::spawn(handle_local_client(
            second_server,
            commands,
            events.subscribe(),
            connected_fixture(),
            None,
        ));
        write_request(&mut first, &IpcRequest::Subscribe)
            .await
            .unwrap();
        write_request(&mut second, &IpcRequest::Subscribe)
            .await
            .unwrap();
        let first_connected: serde_json::Value =
            serde_json::from_slice(&read_frame(&mut first, MAX_IPC_EVENT_SIZE).await.unwrap())
                .unwrap();
        let second_connected: serde_json::Value =
            serde_json::from_slice(&read_frame(&mut second, MAX_IPC_EVENT_SIZE).await.unwrap())
                .unwrap();
        let subscriber_ids = [
            first_connected["request_id"].as_str().unwrap().to_owned(),
            second_connected["request_id"].as_str().unwrap().to_owned(),
        ];
        assert_ne!(subscriber_ids[0], subscriber_ids[1]);

        let mut guard = InternalContractGuard::default();
        let now_ms = 1_700_000_000_000;
        let mut malformed_message = canonical.clone();
        malformed_message["body"] = "".into();
        assert!(!publish_daemon_message_event(
            &events,
            malformed_message,
            &mut guard,
            test_topic(),
            now_ms
        ));
        for (index, stream) in [&mut first, &mut second].into_iter().enumerate() {
            let frame = read_frame(stream, MAX_IPC_EVENT_SIZE).await.unwrap();
            let mut error: serde_json::Value = serde_json::from_slice(&frame).unwrap();
            assert_eq!(
                error["protocol_version"],
                meshmsg_protocol::PROTOCOL_VERSION
            );
            error.as_object_mut().unwrap().remove("protocol_version");
            let error = ErrorEnvelopeV1::from_value(&error).unwrap();
            assert_eq!(error.code, "internal_contract_error");
            assert_eq!(
                error.request_id.as_deref(),
                Some(subscriber_ids[index].as_str())
            );
            assert_eq!(error.suppressed_since_last, Some(0));
        }

        let mut suppressed_message = canonical.clone();
        suppressed_message["body"] = "".into();
        assert!(!publish_daemon_message_event(
            &events,
            suppressed_message,
            &mut guard,
            test_topic(),
            now_ms + 1,
        ));
        assert_eq!(guard.suppressed, 1);

        let malformed_queued = queued_event(
            &secret.public().to_string(),
            [8; 16],
            "x".repeat(crate::message::MAX_V2_MESSAGE_BODY_BYTES + 1),
            43,
        );
        assert!(!publish_daemon_message_event(
            &events,
            malformed_queued,
            &mut guard,
            test_topic(),
            now_ms + REJECTION_SAMPLE_INTERVAL.as_millis() as u64,
        ));
        for (index, stream) in [&mut first, &mut second].into_iter().enumerate() {
            let frame = read_frame(stream, MAX_IPC_EVENT_SIZE).await.unwrap();
            let mut error: serde_json::Value = serde_json::from_slice(&frame).unwrap();
            assert_eq!(
                error["protocol_version"],
                meshmsg_protocol::PROTOCOL_VERSION
            );
            error.as_object_mut().unwrap().remove("protocol_version");
            let error = ErrorEnvelopeV1::from_value(&error).unwrap();
            assert_eq!(error.code, "internal_contract_error");
            assert_eq!(
                error.request_id.as_deref(),
                Some(subscriber_ids[index].as_str())
            );
            assert_eq!(error.suppressed_since_last, Some(1));
        }

        let attachment_signer = SecretKey::generate();
        let mut malformed_offer = signed_attachment_event_for_test(
            &attachment_signer,
            "09090909090909090909090909090909",
            AttachmentKind::File,
            "safe.txt",
            4,
            44,
        );
        malformed_offer["size"] = 5.into();
        assert!(!publish_daemon_message_event(
            &events,
            malformed_offer,
            &mut guard,
            test_topic(),
            now_ms + REJECTION_SAMPLE_INTERVAL.as_millis() as u64 + 1,
        ));

        assert!(publish_daemon_message_event(
            &events,
            canonical,
            &mut guard,
            test_topic(),
            now_ms + REJECTION_SAMPLE_INTERVAL.as_millis() as u64 + 2,
        ));
        for (index, stream) in [&mut first, &mut second].into_iter().enumerate() {
            let frame = read_frame(stream, MAX_IPC_EVENT_SIZE).await.unwrap();
            let mut value: serde_json::Value = serde_json::from_slice(&frame).unwrap();
            assert_eq!(
                value["protocol_version"],
                meshmsg_protocol::PROTOCOL_VERSION
            );
            value.as_object_mut().unwrap().remove("protocol_version");
            crate::ipc::validate_success_payload(&value).unwrap();
            assert_eq!(value["request_id"], subscriber_ids[index]);
            assert_eq!(value["body"], "subscriber remains connected");
        }

        let mut shared = signed_attachment_event_for_test(
            &attachment_signer,
            "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
            AttachmentKind::File,
            "shared.txt",
            4,
            now_ms + 3,
        );
        shared["type"] = "attachment_shared".into();
        shared["schema_version"] = 3.into();
        shared["operation_id"] = shared["message_id"].clone();
        shared["source_digest"] = "01".repeat(32).into();
        shared["delivery_acknowledged"] = false.into();
        assert!(publish_daemon_message_event(
            &events,
            shared,
            &mut guard,
            test_topic(),
            now_ms + 3,
        ));
        for stream in [&mut first, &mut second] {
            let frame = read_frame(stream, MAX_IPC_EVENT_SIZE).await.unwrap();
            let mut value: serde_json::Value = serde_json::from_slice(&frame).unwrap();
            assert_eq!(
                value["protocol_version"],
                meshmsg_protocol::PROTOCOL_VERSION
            );
            value.as_object_mut().unwrap().remove("protocol_version");
            crate::ipc::validate_success_payload_for_context(
                &value,
                Some(test_topic()),
                Some(now_ms + 3),
            )
            .unwrap();
            assert_eq!(value["type"], "attachment_shared");
        }

        drop(first);
        drop(second);
        drop(events);
        first_task.await.unwrap().unwrap();
        second_task.await.unwrap().unwrap();
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
            let mut rejections = RejectionSampler::default();
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
                &mut rejections,
                now_ms,
            );
            assert_eq!(rejected.len(), 1);
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
                &mut rejections,
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
        let mut rejections = RejectionSampler::default();
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
            &mut rejections,
            now_ms,
        );
        assert_eq!(accepted[0]["type"], "attachment_offer");
        assert_eq!(replay.live_ids, 1);

        let duplicate = network_event(
            received(canonical),
            test_topic(),
            &mut replay,
            &mut sources,
            &mut rejections,
            now_ms,
        );
        assert_eq!(duplicate.len(), 1);
        assert_eq!(duplicate[0]["message"], "A network event was rejected.");
        ErrorEnvelopeV1::from_value(&duplicate[0]).unwrap();
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
            &mut rejections,
            now_ms,
        );
        assert!(
            bypass.is_empty(),
            "sampled malformed offer should be suppressed"
        );
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
        let mut rejections = RejectionSampler::default();
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
                &mut rejections,
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
                &mut rejections,
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
            &mut rejections,
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
                &mut rejections,
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
    fn semantic_validation_precedes_rate_admission_and_rejections_are_sampled() {
        let source = SecretKey::generate().public();
        let now_ms = 1_700_000_040_000;
        let mut sources = TransportSourceLimiter::default();
        for _ in 0..TRANSPORT_SOURCE_BURST {
            assert!(sources.allow_verification(source, now_ms));
        }
        let global_tokens_before_malformed = sources.admission_global.milli_tokens;
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
        let rejection = ErrorEnvelopeV1::from_value(&values[0]).unwrap();
        assert_eq!(rejection.code, "network_event_rejected");
        assert_eq!(rejection.message, "A network event was rejected.");
        assert_eq!(rejection.outcome, "not_started");
        assert!(!rejection.retryable);
        assert_eq!(replay.live_ids, 0);
        assert_eq!(sources.sources.len(), 1);
        assert_eq!(
            sources.admission_global.milli_tokens,
            global_tokens_before_malformed
        );

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
        assert!(Envelope::encode_with_id_at(
            &signer,
            test_topic(),
            EnvelopeKind::AttachmentOffer,
            attachment_body(&mismatched).unwrap(),
            operation_id_bytes(&mismatched.offer_id),
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
            assert!(valid_daemon_message_event(
                &message_event(envelope),
                test_topic(),
                1,
            ));
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
    fn private_send_acceptance_is_validated_strictly() {
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

        for (code, message, outcome, retryable) in [
            ("private_replay_unavailable", "recipient replay persistence is unavailable", "not_started", true),
            ("private_delivery_unknown", "recipient durably recorded this message ID but cannot prove whether its volatile delivery was queued", "unknown", false),
            ("private_send_failed", "private transport failed", "unknown", true),
        ] {
            let raw = serde_json::json!({
                "type":"error", "schema_version":1, "code":code,
                "message":message, "outcome":outcome, "retryable":retryable
            });
            let mut normalized = normalize_ipc_response(&raw, "11111111111111111111111111111111");
            normalized["operation_id"] = "0123456789abcdef0123456789abcdef".into();
            let error = ErrorEnvelopeV1::from_value(&normalized).unwrap();
            error.validate_for_operation(
                contracts::ErrorOperationKind::PrivateSend,
                Some("0123456789abcdef0123456789abcdef"),
            ).unwrap();
            assert_eq!((error.outcome.as_str(), error.retryable), (outcome, retryable));
        }

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

        let (blobs, has_more, item_errors) = list_pinned_blobs(&store).await.unwrap();
        assert_eq!(blobs.len(), MAX_OFFER_LIST_ENTRIES);
        assert!(has_more);
        assert_eq!(item_errors, 1);
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
            let (listed, has_more, item_errors) = list_pinned_blobs(&store).await.unwrap();
            assert!(listed.is_empty());
            assert!(has_more);
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
        let (listed, has_more, item_errors) = list_pinned_blobs(&store).await.unwrap();
        assert!(listed.is_empty());
        assert!(has_more);
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
        assert_eq!(removed["removed_tags"], 1);
        assert_eq!(removed["released_bytes"], 0);
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

    #[test]
    fn attachment_index_read_is_bounded_versioned_and_permission_safe() {
        let state = std::env::temp_dir().join(format!(
            "meshmsg-attachment-index-test-{}",
            rand::random::<u64>()
        ));
        crate::config::prepare_state_dir(&state).unwrap();
        let path = state.join(ATTACHMENT_INDEX_NAME);
        assert!(load_attachment_index(&state)
            .unwrap()
            .created_at_ms
            .is_empty());

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
        assert_eq!(dry["selected_tags"], 1);
        assert_eq!(dry["removed_tags"], 0);
        assert_eq!(dry["limited"], true);
        assert_eq!(storage.status().tags, 3);
        let pruned = storage
            .remove(TEST_OPERATION_ID, None, None, None, Some(10), 2, false)
            .await
            .unwrap();
        assert_eq!(pruned["removed_tags"], 2, "the exact cutoff is inclusive");
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
        let (listed, has_more, item_errors) = list_pinned_blobs(&store).await.unwrap();
        assert!(listed.is_empty());
        assert!(has_more);
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
            None,
        )
        .await;
        let timeout = LifecycleErrorV1::from_value(&timeout_value).unwrap();
        assert_eq!(timeout.code, "attachment_command_timeout");
        assert_eq!(timeout.outcome, "unknown");
        assert!(timeout.retryable);
        assert_eq!(timeout.offer_id, None);
        let _ = offer_id;
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
        let event = serde_json::json!({"type":"peer_up", "peer":"3".repeat(64)});
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
        assert_eq!(received["peer"], event["peer"]);
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
        let startup = serde_json::json!({
            "type":"peers_snapshot", "schema_version":2,
            "generated_at_ms":1, "directory_epoch":"4".repeat(32),
            "directory_revision":1,
            "self":{"public_key":"2".repeat(64), "alias":null, "online":true},
            "peers":[]
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
        events
            .send(serde_json::json!({"type":"peer_up", "peer":"3".repeat(64)}))
            .unwrap();
        events
            .send(serde_json::json!({"type":"peer_down", "peer":"3".repeat(64)}))
            .unwrap();
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
        let mut rejection: serde_json::Value = serde_json::from_slice(&frame).unwrap();
        assert_eq!(
            rejection["protocol_version"],
            meshmsg_protocol::PROTOCOL_VERSION
        );
        rejection
            .as_object_mut()
            .unwrap()
            .remove("protocol_version");
        let rejection = ErrorEnvelopeV1::from_value(&rejection).unwrap();
        assert_eq!(rejection.code, "ipc_capacity");
        assert_eq!(rejection.outcome, "not_started");
        assert!(rejection.retryable);
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
                operation_id: operation.clone(),
                offer: "x".into(),
                output: PathBuf::from("x"),
                mode: meshmsg_protocol::DownloadMode::Install,
            },
            IpcRequest::Download {
                operation_id: operation,
                offer: "x".into(),
                output: PathBuf::from("x"),
                mode: meshmsg_protocol::DownloadMode::Raw,
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
            let mut value: serde_json::Value = serde_json::from_slice(&frame).unwrap();
            assert_eq!(
                value["protocol_version"],
                meshmsg_protocol::PROTOCOL_VERSION
            );
            value.as_object_mut().unwrap().remove("protocol_version");
            let transport = ErrorEnvelopeV1::from_value(&value).unwrap();
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
        let mut timeout_error =
            serde_json::from_slice::<serde_json::Value>(&timeout_frame).unwrap();
        assert_eq!(
            timeout_error["protocol_version"],
            meshmsg_protocol::PROTOCOL_VERSION
        );
        timeout_error
            .as_object_mut()
            .unwrap()
            .remove("protocol_version");
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
        reply
            .send(serde_json::json!({"type":"stopping", "outcome":"accepted"}))
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
        assert!(response["message"].as_str().unwrap().contains("reconcile"));
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
