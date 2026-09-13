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

pub(crate) const ALPN: &[u8] = b"/meshmsg/broadcast-gossip/2";
pub(crate) const ENVELOPE_DOMAIN: &str = "meshmsg-broadcast";
pub(crate) const ENVELOPE_VERSION: u8 = 2;
pub(crate) const ENVELOPE_FUTURE_SKEW: Duration = Duration::from_secs(60);
pub(crate) const ENVELOPE_ACCEPTANCE_WINDOW: Duration = Duration::from_secs(5 * 60);
pub(crate) const REPLAY_BUCKET_WIDTH: Duration = Duration::from_secs(60);
// A bucket may receive an envelope at its last millisecond at the future-skew
// boundary. Retain that whole bucket beyond the past and future windows.
pub(crate) const REPLAY_BUCKET_RETENTION: Duration = Duration::from_secs(7 * 60);
const PER_SENDER_REPLAY_RATE_PER_SEC: u64 = 100;
pub(crate) const PER_SENDER_REPLAY_BURST: u64 = 200;
const TRANSPORT_SOURCE_RATE_PER_SEC: u64 = 500;
pub(crate) const TRANSPORT_SOURCE_BURST: u64 = 1_000;
const GLOBAL_TRANSPORT_RATE_PER_SEC: u64 = 1_500;
pub(crate) const GLOBAL_TRANSPORT_BURST: u64 = 3_000;
pub(crate) const TRANSPORT_SOURCE_IDLE_LIFETIME: Duration = Duration::from_secs(60);
pub(crate) const MAX_TRANSPORT_SOURCES: usize = 128;
pub(crate) const MAX_REPLAY_SENDERS_PER_SOURCE: usize = 256;
const MAX_REPLAY_SOURCES: usize = 128;
const GLOBAL_REPLAY_RATE_PER_SEC: u64 = 1_000;
pub(crate) const GLOBAL_REPLAY_BURST: u64 = 2_000;
const MAX_REPLAY_SENDERS: usize = 4_096;
pub(crate) const MAX_REPLAY_IDS_PER_SENDER: usize = (PER_SENDER_REPLAY_BURST
    + PER_SENDER_REPLAY_RATE_PER_SEC * REPLAY_BUCKET_RETENTION.as_secs())
    as usize;
const MAX_REPLAY_IDS_PER_SOURCE: usize = (TRANSPORT_SOURCE_BURST
    + TRANSPORT_SOURCE_RATE_PER_SEC * REPLAY_BUCKET_RETENTION.as_secs())
    as usize;
pub(crate) const MAX_ENVELOPE_REPLAY_ENTRIES: usize =
    (GLOBAL_REPLAY_BURST + GLOBAL_REPLAY_RATE_PER_SEC * REPLAY_BUCKET_RETENTION.as_secs()) as usize;
const _: () = assert!(
    REPLAY_BUCKET_RETENTION.as_secs()
        >= ENVELOPE_ACCEPTANCE_WINDOW.as_secs()
            + ENVELOPE_FUTURE_SKEW.as_secs()
            + REPLAY_BUCKET_WIDTH.as_secs()
);
pub(crate) const MAX_ENVELOPE_SIZE: usize = 4096;
pub(crate) const PROTOCOL_HEADROOM: usize = 512;
pub(crate) const MAX_MESSAGE_SIZE: usize = MAX_ENVELOPE_SIZE + PROTOCOL_HEADROOM;
pub(crate) const SIGNATURE_LENGTH: usize = iroh::Signature::LENGTH;
type Signature = ByteArray<SIGNATURE_LENGTH>;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EnvelopeKind {
    Message,
    AttachmentOffer,
}

#[cfg(test)]
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct LegacyEnvelopeV1 {
    pub(crate) from: PublicKey,
    pub(crate) timestamp_ms: u64,
    pub(crate) body: String,
    pub(crate) signature: Signature,
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

pub(crate) struct ReplayBucket {
    pub(crate) started_at_ms: u64,
    expires_at_ms: u64,
    entries: HashSet<ReplayKey>,
}

#[derive(Clone)]
pub(crate) struct TokenBucket {
    pub(crate) milli_tokens: u64,
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

    pub(crate) fn refill(&mut self, now_ms: u64) {
        let elapsed_ms = now_ms.saturating_sub(self.last_refill_ms);
        self.milli_tokens = self
            .milli_tokens
            .saturating_add(elapsed_ms.saturating_mul(self.rate_per_sec))
            .min(self.burst.saturating_mul(1_000));
        self.last_refill_ms = self.last_refill_ms.max(now_ms);
    }

    pub(crate) fn available(&self) -> bool {
        self.milli_tokens >= 1_000
    }

    pub(crate) fn consume(&mut self) {
        self.milli_tokens -= 1_000;
    }
}

pub(crate) struct TransportSourceState {
    verification_limiter: TokenBucket,
    pub(crate) admission_limiter: TokenBucket,
    last_seen_ms: u64,
}

pub(crate) struct TransportSourceLimiter {
    pub(crate) sources: HashMap<PublicKey, TransportSourceState>,
    pub(crate) verification_global: TokenBucket,
    pub(crate) admission_global: TokenBucket,
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

    pub(crate) fn allow_verification(&mut self, source: PublicKey, now_ms: u64) -> bool {
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

pub(crate) struct SenderReplayState {
    limiter: TokenBucket,
    pub(crate) live_ids: usize,
    last_seen_ms: u64,
}

struct SourceReplayState {
    live_ids: usize,
    senders: HashMap<PublicKey, usize>,
}

pub(crate) struct EnvelopeReplayCache {
    pub(crate) buckets: VecDeque<ReplayBucket>,
    pub(crate) senders: HashMap<PublicKey, SenderReplayState>,
    sources: HashMap<PublicKey, SourceReplayState>,
    ownership: HashMap<ReplayKey, PublicKey>,
    global_limiter: TokenBucket,
    pub(crate) live_ids: usize,
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
            crate::message::validate_v2_message_body(&self.body)?;
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

pub(crate) fn network_event<F>(
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
            if !sources.allow_verification(source, now_ms) {
                return Vec::new();
            }
            // Complete wire and kind-specific semantics precede freshness,
            // replay, and accepted-traffic accounting. Rejected frames pay
            // only the separate verification-attempt budget.
            let accepted = Envelope::decode(&message.content, topic).and_then(|envelope| {
                let event = match envelope.kind {
                    EnvelopeKind::Message => message_event(&envelope),
                    EnvelopeKind::AttachmentOffer => attachment_event(AttachmentEnvelope {
                        from: envelope.from,
                        message_id: envelope.message_id,
                        timestamp_ms: envelope.timestamp_ms,
                        body: &envelope.body,
                        encoded: &message.content,
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
        Event::NeighborUp(peer) => vec![meshmsg_protocol::Event::PeerUp {
            peer: peer.to_string().parse().expect("public key is canonical"),
        }],
        Event::NeighborDown(peer) => vec![meshmsg_protocol::Event::PeerDown {
            peer: peer.to_string().parse().expect("public key is canonical"),
        }],
        Event::Lagged => vec![meshmsg_protocol::Event::Lagged {
            source: meshmsg_protocol::EventSource::Gossip,
            dropped: 0,
            message: "receiver fell behind; one or more events were dropped".into(),
        }],
    }
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
        body: meshmsg_protocol::MessageBody::new(msg.body.clone()).expect("validated message body"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broadcast_v2_uses_an_explicit_protocol_with_bounded_headroom() {
        assert_ne!(ALPN, iroh_gossip::net::GOSSIP_ALPN);
        assert_eq!(MAX_MESSAGE_SIZE - MAX_ENVELOPE_SIZE, PROTOCOL_HEADROOM);
    }
}
