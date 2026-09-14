use crate::ids::id_string;
use anyhow::{Context, Result};
use bytes::Bytes;
use iroh::{PublicKey, SecretKey};
use iroh_gossip::{api::Event, proto::TopicId};
use serde::{Deserialize, Serialize};
use serde_byte_array::ByteArray;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    time::Duration,
};

pub(crate) const ALPN: &[u8] = b"/meshmsg/broadcast-gossip/3";
pub(crate) const ENVELOPE_DOMAIN: &str = "meshmsg-broadcast";
pub(crate) const ENVELOPE_VERSION: u8 = meshmsg_protocol::SIGNED_BROADCAST_ENVELOPE_VERSION;
pub(crate) const ENVELOPE_FUTURE_SKEW: Duration = Duration::from_secs(60);
pub(crate) const ENVELOPE_ACCEPTANCE_WINDOW: Duration = Duration::from_secs(5 * 60);
const REPLAY_BUCKET_WIDTH: Duration = Duration::from_secs(60);
// A bucket may receive an envelope at its last millisecond at the future-skew
// boundary. Retain that whole bucket beyond the past and future windows.
const REPLAY_BUCKET_RETENTION: Duration = Duration::from_secs(7 * 60);
const PER_SENDER_REPLAY_RATE_PER_SEC: u64 = 100;
const PER_SENDER_REPLAY_BURST: u64 = 200;
const TRANSPORT_SOURCE_RATE_PER_SEC: u64 = 500;
const TRANSPORT_SOURCE_BURST: u64 = 1_000;
const GLOBAL_TRANSPORT_RATE_PER_SEC: u64 = 1_500;
const GLOBAL_TRANSPORT_BURST: u64 = 3_000;
/// Byte budgets prevent the 16x larger envelope from turning count-based
/// verification/admission limits into unbounded bandwidth and fanout work.
const TRANSPORT_SOURCE_BYTES_PER_SEC: u64 = 4 * 1024 * 1024;
const TRANSPORT_SOURCE_BYTE_BURST: u64 = 8 * 1024 * 1024;
const GLOBAL_TRANSPORT_BYTES_PER_SEC: u64 = 16 * 1024 * 1024;
const GLOBAL_TRANSPORT_BYTE_BURST: u64 = 32 * 1024 * 1024;
const TRANSPORT_SOURCE_IDLE_LIFETIME: Duration = Duration::from_secs(60);
pub(crate) const MAX_TRANSPORT_SOURCES: usize = 128;
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
const _: () = assert!(
    REPLAY_BUCKET_RETENTION.as_secs()
        >= ENVELOPE_ACCEPTANCE_WINDOW.as_secs()
            + ENVELOPE_FUTURE_SKEW.as_secs()
            + REPLAY_BUCKET_WIDTH.as_secs()
);
pub(crate) const MAX_ENVELOPE_SIZE: usize = meshmsg_protocol::MAX_SIGNED_BROADCAST_ENVELOPE_BYTES;
/// Iroh 0.101's data frame adds a 32-byte topic, 32-byte content hash, enum
/// discriminants, a payload-length varint, and delivery scope/round. Their
/// postcard representation is bounded well below this audited 128-byte ceiling.
const IROH_GOSSIP_0101_DATA_HEADER_BOUND: usize = 128;
/// Iroh's configured limit includes that postcard protocol header. Keep an
/// explicit conservative allowance while preserving a full 65,536-byte payload.
const PROTOCOL_HEADROOM: usize = 512;
const _: () = assert!(PROTOCOL_HEADROOM >= IROH_GOSSIP_0101_DATA_HEADER_BOUND);
pub(crate) const MAX_MESSAGE_SIZE: usize = MAX_ENVELOPE_SIZE + PROTOCOL_HEADROOM;
pub(crate) const SIGNATURE_LENGTH: usize = iroh::Signature::LENGTH;
type Signature = ByteArray<SIGNATURE_LENGTH>;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EnvelopeKind {
    Message,
    AttachmentOffer,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Envelope {
    pub(crate) domain: String,
    pub(crate) version: u8,
    pub(crate) topic: TopicId,
    pub(crate) from: PublicKey,
    pub(crate) message_id: [u8; 16],
    pub(crate) timestamp_ms: u64,
    pub(crate) kind: EnvelopeKind,
    pub(crate) body: String,
    pub(crate) signature: Signature,
}

#[derive(Debug, Serialize)]
pub(crate) struct EnvelopeSignaturePayload<'a> {
    pub(crate) domain: &'a str,
    pub(crate) version: u8,
    pub(crate) topic: TopicId,
    pub(crate) from: PublicKey,
    pub(crate) message_id: [u8; 16],
    pub(crate) timestamp_ms: u64,
    pub(crate) kind: EnvelopeKind,
    pub(crate) body: &'a str,
}

type ReplayKey = (PublicKey, [u8; 16]);

struct ReplayBucket {
    started_at_ms: u64,
    expires_at_ms: u64,
    entries: HashSet<ReplayKey>,
}

#[derive(Clone)]
pub(crate) struct TokenBucket {
    milli_tokens: u64,
    burst: u64,
    rate_per_sec: u64,
    last_refill_ms: u64,
}

impl TokenBucket {
    pub(crate) fn new(rate_per_sec: u64, burst: u64, now_ms: u64) -> Self {
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

    pub(crate) fn available(&self) -> bool {
        self.available_amount(1)
    }

    fn available_amount(&self, amount: u64) -> bool {
        amount
            .checked_mul(1_000)
            .is_some_and(|required| self.milli_tokens >= required)
    }

    pub(crate) fn consume(&mut self) {
        self.consume_amount(1);
    }

    fn consume_amount(&mut self, amount: u64) {
        let required = amount.checked_mul(1_000).expect("bounded token amount");
        debug_assert!(self.milli_tokens >= required);
        self.milli_tokens -= required;
    }
}

struct TransportSourceState {
    verification_limiter: TokenBucket,
    verification_byte_limiter: TokenBucket,
    admission_limiter: TokenBucket,
    last_seen_ms: u64,
}

struct TransportSourceLimiter {
    sources: HashMap<PublicKey, TransportSourceState>,
    verification_global: TokenBucket,
    verification_bytes_global: TokenBucket,
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
            verification_bytes_global: TokenBucket::new(
                GLOBAL_TRANSPORT_BYTES_PER_SEC,
                GLOBAL_TRANSPORT_BYTE_BURST,
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
                    verification_byte_limiter: TokenBucket::new(
                        TRANSPORT_SOURCE_BYTES_PER_SEC,
                        TRANSPORT_SOURCE_BYTE_BURST,
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

    fn allow_verification(&mut self, source: PublicKey, now_ms: u64, frame_bytes: usize) -> bool {
        let Ok(frame_bytes) = u64::try_from(frame_bytes) else {
            return false;
        };
        if frame_bytes == 0 || !self.prepare_source(source, now_ms) {
            return false;
        }
        self.verification_global.refill(now_ms);
        self.verification_bytes_global.refill(now_ms);
        if !self.verification_global.available()
            || !self.verification_bytes_global.available_amount(frame_bytes)
        {
            return false;
        }
        let state = self.sources.get_mut(&source).expect("source was inserted");
        state.verification_limiter.refill(now_ms);
        state.verification_byte_limiter.refill(now_ms);
        if !state.verification_limiter.available()
            || !state
                .verification_byte_limiter
                .available_amount(frame_bytes)
        {
            return false;
        }
        self.verification_global.consume();
        self.verification_bytes_global.consume_amount(frame_bytes);
        state.verification_limiter.consume();
        state.verification_byte_limiter.consume_amount(frame_bytes);
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
    ownership: HashMap<ReplayKey, PublicKey>,
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
    #[cfg(test)]
    pub(crate) fn with_capacity(max_live_ids: usize) -> Self {
        Self {
            max_live_ids,
            ..Self::default()
        }
    }

    pub(crate) fn rotate(&mut self, now_ms: u64) {
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

    fn contains(&self, key: &ReplayKey) -> bool {
        self.buckets
            .iter()
            .any(|bucket| bucket.entries.contains(key))
    }

    pub(crate) fn accept(
        &mut self,
        envelope: &Envelope,
        source: PublicKey,
        now_ms: u64,
    ) -> Result<()> {
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

impl Envelope {
    #[cfg(test)]
    pub(crate) fn encode_at(
        secret: &SecretKey,
        topic: TopicId,
        kind: EnvelopeKind,
        body: String,
        timestamp_ms: u64,
    ) -> Result<Bytes> {
        Self::encode_with_id_at(secret, topic, kind, body, rand::random(), timestamp_ms)
    }

    pub(crate) fn encode_message_with_id_at(
        secret: &SecretKey,
        topic: TopicId,
        body: String,
        message_id: [u8; 16],
        timestamp_ms: u64,
    ) -> Result<Bytes> {
        Self::encode_with_id_at(
            secret,
            topic,
            EnvelopeKind::Message,
            body,
            message_id,
            timestamp_ms,
        )
    }

    pub(crate) fn encode_with_id_at(
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
        value.validate_general_semantics()?;
        let encoded = postcard::to_stdvec(&value)?;
        anyhow::ensure!(
            encoded.len() <= MAX_ENVELOPE_SIZE,
            "encoded message is {} bytes; maximum is {MAX_ENVELOPE_SIZE} bytes",
            encoded.len()
        );
        Ok(encoded.into())
    }

    pub(crate) fn decode(data: &[u8], expected_topic: TopicId) -> Result<Self> {
        let value = Self::decode_signed(data)?;
        anyhow::ensure!(
            value.topic == expected_topic,
            "message belongs to another topic"
        );
        Ok(value)
    }

    pub(crate) fn decode_signed(data: &[u8]) -> Result<Self> {
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
        value.validate_general_semantics()?;
        Ok(value)
    }

    fn validate_general_semantics(&self) -> Result<()> {
        if self.kind == EnvelopeKind::Message {
            crate::message::validate_broadcast_body(&self.body)?;
        }
        Ok(())
    }
}

pub(crate) struct AttachmentEnvelope<'a> {
    pub(crate) from: PublicKey,
    pub(crate) message_id: [u8; 16],
    pub(crate) timestamp_ms: u64,
    pub(crate) body: &'a str,
    pub(crate) encoded: &'a [u8],
}

#[derive(Default)]
pub(crate) struct EventHandler {
    replay: EnvelopeReplayCache,
    sources: TransportSourceLimiter,
}

impl EventHandler {
    pub(crate) fn handle<F>(
        &mut self,
        value: Event,
        topic: TopicId,
        now_ms: u64,
        attachment_event: F,
    ) -> Vec<meshmsg_protocol::Event>
    where
        F: FnOnce(AttachmentEnvelope<'_>) -> Result<meshmsg_protocol::Event>,
    {
        network_event(
            value,
            topic,
            &mut self.replay,
            &mut self.sources,
            now_ms,
            attachment_event,
        )
    }
}

fn network_event<F>(
    value: Event,
    topic: TopicId,
    replay: &mut EnvelopeReplayCache,
    sources: &mut TransportSourceLimiter,
    now_ms: u64,
    attachment_event: F,
) -> Vec<meshmsg_protocol::Event>
where
    F: FnOnce(AttachmentEnvelope<'_>) -> Result<meshmsg_protocol::Event>,
{
    match value {
        Event::Received(message) => {
            // Bound work by the authenticated transport hop, not the signed
            // identity, which an invite holder can rotate cheaply.
            let source = message.delivered_from;
            if !sources.allow_verification(source, now_ms, message.content.len()) {
                return Vec::new();
            }
            process_received(
                source,
                &message.content,
                topic,
                replay,
                sources,
                now_ms,
                attachment_event,
            )
        }
        Event::NeighborUp(_) | Event::NeighborDown(_) => Vec::new(),
        Event::Lagged => vec![meshmsg_protocol::Event::Lagged {
            source: meshmsg_protocol::EventSource::Gossip,
            dropped: 0,
            message: "receiver fell behind; one or more events were dropped".into(),
        }],
    }
}

fn process_received<F>(
    source: PublicKey,
    content: &[u8],
    topic: TopicId,
    replay: &mut EnvelopeReplayCache,
    sources: &mut TransportSourceLimiter,
    now_ms: u64,
    attachment_event: F,
) -> Vec<meshmsg_protocol::Event>
where
    F: FnOnce(AttachmentEnvelope<'_>) -> Result<meshmsg_protocol::Event>,
{
    // Complete signature and kind-specific semantics precede freshness, replay,
    // accepted-traffic accounting, and subscriber fanout.
    let accepted = Envelope::decode(content, topic).and_then(|envelope| {
        let event = match envelope.kind {
            EnvelopeKind::Message => message_event(&envelope),
            EnvelopeKind::AttachmentOffer => attachment_event(AttachmentEnvelope {
                from: envelope.from,
                message_id: envelope.message_id,
                timestamp_ms: envelope.timestamp_ms,
                body: &envelope.body,
                encoded: content,
            })?,
        };
        anyhow::ensure!(
            sources.admission_available(source, now_ms),
            "broadcast transport source rate limit exceeded"
        );
        replay.accept(&envelope, source, now_ms)?;
        sources.consume_admission(source, now_ms);
        Ok(event)
    });
    accepted.map_or_else(|_| Vec::new(), |event| vec![event])
}

pub(crate) fn queued_event(
    peer: &str,
    message_id: [u8; 16],
    body: String,
    timestamp_ms: u64,
) -> meshmsg_protocol::Queued {
    meshmsg_protocol::Queued {
        operation_id: id_string(&message_id)
            .parse()
            .expect("operation ID is canonical"),
        from: peer.parse().expect("public key is canonical"),
        message_id: id_string(&message_id)
            .parse()
            .expect("message ID is canonical"),
        timestamp_ms,
        body: meshmsg_protocol::BroadcastBody::new(body).expect("validated broadcast body"),
        delivery_acknowledged: false,
    }
}

pub(crate) fn message_event(msg: &Envelope) -> meshmsg_protocol::Event {
    meshmsg_protocol::Event::Message(meshmsg_protocol::Message {
        from: msg
            .from
            .to_string()
            .parse()
            .expect("public key is canonical"),
        message_id: id_string(&msg.message_id)
            .parse()
            .expect("message ID is canonical"),
        timestamp_ms: msg.timestamp_ms,
        body: meshmsg_protocol::BroadcastBody::new(msg.body.clone())
            .expect("validated broadcast body"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broadcast_v3_uses_one_bounded_envelope_with_fixed_protocol_headroom() {
        assert_ne!(ALPN, iroh_gossip::net::GOSSIP_ALPN);
        assert_eq!(MAX_ENVELOPE_SIZE, 65_536);
        assert_eq!(IROH_GOSSIP_0101_DATA_HEADER_BOUND, 128);
        assert_eq!(PROTOCOL_HEADROOM, 512);
        assert_eq!(MAX_MESSAGE_SIZE, 66_048);
    }
    use crate::{
        attachment::protocol::{
            attachment_body, offer_event, validate_offer_binding, ATTACHMENT_PREFIX,
        },
        contracts,
    };
    use iroh_blobs::{ticket::BlobTicket, BlobFormat};

    fn test_topic() -> TopicId {
        TopicId::from_bytes([7; 32])
    }

    fn operation_id_bytes(operation_id: &str) -> [u8; 16] {
        operation_id
            .parse::<meshmsg_protocol::OperationId>()
            .expect("validated operation ID")
            .to_bytes()
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

    fn sample_offer(provider: PublicKey) -> crate::attachment::AttachmentOffer {
        crate::attachment::AttachmentOffer {
            offer_id: "0123456789abcdef0123456789abcdef".to_owned(),
            kind: crate::attachment::AttachmentKind::File,
            name: "report.txt".to_owned(),
            size: 6,
            ticket: iroh_blobs::ticket::BlobTicket::new(
                iroh::EndpointAddr::new(provider),
                iroh_blobs::Hash::new(b"report"),
                iroh_blobs::BlobFormat::Raw,
            )
            .to_string(),
        }
    }

    fn network_event(
        value: Event,
        topic: TopicId,
        replay: &mut EnvelopeReplayCache,
        sources: &mut TransportSourceLimiter,
        now_ms: u64,
    ) -> Vec<serde_json::Value> {
        super::network_event(value, topic, replay, sources, now_ms, |envelope| {
            let offer = validate_offer_binding(
                envelope.from,
                envelope.message_id,
                envelope.timestamp_ms,
                envelope.body,
            )?;
            Ok(offer_event(
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

    fn queued_event(
        peer: &str,
        message_id: [u8; 16],
        body: String,
        timestamp_ms: u64,
    ) -> serde_json::Value {
        serde_json::to_value(meshmsg_protocol::ResponseFrame::new(
            Some(meshmsg_protocol::RequestId::new_random()),
            meshmsg_protocol::Response::Queued(super::queued_event(
                peer,
                message_id,
                body,
                timestamp_ms,
            )),
        ))
        .expect("test queued serialization")
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
    #[test]
    fn envelope_v3_is_topic_bound_and_replay_and_time_bounded() {
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
    fn crafted_signed_invalid_messages_are_rejected_before_replay_and_next_message_survives() {
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

        for body in [
            String::new(),
            "x".repeat(crate::message::MAX_BROADCAST_BODY_BYTES + 1),
        ] {
            let rejected = network_event(
                Event::Received(iroh_gossip::api::Message {
                    content: signed_envelope(body).into(),
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
            assert_eq!(
                sources.admission_global.milli_tokens,
                GLOBAL_TRANSPORT_BURST * 1_000,
                "invalid semantics consumed admission capacity"
            );
        }

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
            assert!(sources.allow_verification(source, now_ms, 1));
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
            assert!(limiter.allow_verification(abusive, now_ms, 1));
        }
        assert!(!limiter.allow_verification(abusive, now_ms, 1));
        assert!(limiter.allow_verification(other, now_ms, 1));

        let mut source_limited = TransportSourceLimiter::default();
        for _ in 0..MAX_TRANSPORT_SOURCES {
            assert!(source_limited.allow_verification(SecretKey::generate().public(), now_ms, 1));
        }
        assert!(!source_limited.allow_verification(SecretKey::generate().public(), now_ms, 1));
        assert!(source_limited.allow_verification(
            SecretKey::generate().public(),
            now_ms + TRANSPORT_SOURCE_IDLE_LIFETIME.as_millis() as u64,
            1,
        ));
    }

    #[test]
    fn transport_byte_budget_bounds_maximum_envelopes_and_refills() {
        let now_ms = 1_700_000_040_000;
        let source = SecretKey::generate().public();
        let other = SecretKey::generate().public();
        let mut limiter = TransportSourceLimiter::default();
        let frames = TRANSPORT_SOURCE_BYTE_BURST / MAX_ENVELOPE_SIZE as u64;
        assert_eq!(frames, 128);
        for _ in 0..frames {
            assert!(limiter.allow_verification(source, now_ms, MAX_ENVELOPE_SIZE));
        }
        assert!(!limiter.allow_verification(source, now_ms, MAX_ENVELOPE_SIZE));
        assert!(limiter.allow_verification(other, now_ms, MAX_ENVELOPE_SIZE));
        assert!(limiter.allow_verification(source, now_ms + 16, MAX_ENVELOPE_SIZE));
        assert!(!limiter.allow_verification(source, now_ms + 16, 0));
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
    fn envelope_boundary_matches_single_message_transport_headroom() {
        assert_eq!(MAX_MESSAGE_SIZE - MAX_ENVELOPE_SIZE, PROTOCOL_HEADROOM);
        assert_eq!(MAX_ENVELOPE_SIZE, 65_536);
        assert_eq!(crate::message::MAX_BROADCAST_BODY_BYTES, 65_358);
        let secret = SecretKey::generate();
        // Every postcard u64 varint-width transition, including both sides of
        // each boundary, is exercised against every relevant string-length
        // varint transition and the admitted body maximum.
        let timestamps = [
            0,
            127,
            128,
            16_383,
            16_384,
            2_097_151,
            2_097_152,
            268_435_455,
            268_435_456,
            34_359_738_367,
            34_359_738_368,
            4_398_046_511_103,
            4_398_046_511_104,
            562_949_953_421_311,
            562_949_953_421_312,
            72_057_594_037_927_935,
            72_057_594_037_927_936,
            9_223_372_036_854_775_807,
            9_223_372_036_854_775_808,
            u64::MAX,
        ];
        for body_len in [1, 127, 128, 16_383, 16_384, 65_358] {
            for timestamp in timestamps {
                let encoded = Envelope::encode_at(
                    &secret,
                    test_topic(),
                    EnvelopeKind::Message,
                    "a".repeat(body_len),
                    timestamp,
                )
                .unwrap();
                assert!(encoded.len() <= MAX_ENVELOPE_SIZE);
                if body_len == crate::message::MAX_BROADCAST_BODY_BYTES && timestamp == u64::MAX {
                    assert_eq!(encoded.len(), MAX_ENVELOPE_SIZE);
                }
            }
        }
    }

    #[test]
    fn decode_rejects_exactly_65537_byte_envelope_and_v2() {
        let secret = SecretKey::generate();
        let body = "a".repeat(crate::message::MAX_BROADCAST_BODY_BYTES + 1);
        let envelope = unsigned_test_envelope(secret.public(), body, u64::MAX);
        let encoded = postcard::to_stdvec(&envelope).unwrap();
        assert_eq!(encoded.len(), MAX_ENVELOPE_SIZE + 1);
        assert!(Envelope::decode(&encoded, test_topic()).is_err());

        let mut v2 = unsigned_test_envelope(secret.public(), "v2".to_owned(), 1);
        v2.version = 2;
        assert!(Envelope::decode(&postcard::to_stdvec(&v2).unwrap(), test_topic()).is_err());
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
        assert_eq!(value["protocol_version"], 4);
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
            message_event(&envelope),
        );
        assert!(
            serde_json::to_vec(&frame).unwrap().len() <= crate::ipc::MAX_IPC_EVENT_SIZE,
            "maximum canonical message event exceeds IPC frame"
        );
    }
}
