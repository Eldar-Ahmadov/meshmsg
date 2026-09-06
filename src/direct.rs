use crate::alias::{normalize_alias, validate_alias};
use anyhow::{Context, Result};
use bytes::Bytes;
use iroh::{
    address_lookup::memory::MemoryLookup,
    endpoint::Connection,
    protocol::{AcceptError, ProtocolHandler},
    Endpoint, EndpointAddr, PublicKey, SecretKey, TransportAddr,
};
use iroh_gossip::proto::TopicId;
use serde::{Deserialize, Serialize};
use serde_byte_array::ByteArray;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    str::FromStr,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::mpsc;

pub(crate) const DIRECT_ALPN: &[u8] = b"/meshmsg/direct/1";
pub(crate) const PRESENCE_ALPN: &[u8] = b"/meshmsg/presence-gossip/1";
const VERSION: u8 = 1;
const SIGNATURE_LENGTH: usize = iroh::Signature::LENGTH;
const MAX_DIRECT_FRAME: usize = 6 * 1024;
const MAX_BODY_BYTES: usize = 4096;
const MAX_PRESENCE_FRAME: usize = 2048;
const MAX_ENDPOINT_ADDRS: usize = 8;
pub(crate) const MAX_DYNAMIC_PRESENCE_IDENTITIES: usize = 1024;
const MAX_PINNED_ENDPOINTS: usize = crate::invite::MAX_BOOTSTRAP_PEERS + 1;
const PRESENCE_LIFETIME: Duration = Duration::from_secs(150);
const MAX_CLOCK_SKEW: Duration = Duration::from_secs(5 * 60);
const PRESENCE_REPLAY_LIFETIME: Duration = Duration::from_secs(450);
const MAX_PRESENCE_TRANSPORT_SOURCES: usize = 32;
const MAX_PRESENCE_RECORDS_PER_SOURCE: usize = 128;
const PRESENCE_SOURCE_WINDOW: Duration = Duration::from_secs(1);
const DIRECT_TIMEOUT: Duration = Duration::from_secs(30);
const REPLAY_LIFETIME: Duration = Duration::from_secs(10 * 60);
const MAX_REPLAY_ENTRIES: usize = 65_536;
const PRESENCE_DOMAIN: &[u8] = b"meshmsg-presence-v1";
const MESSAGE_DOMAIN: &[u8] = b"meshmsg-direct-message-v1";
const ACK_DOMAIN: &[u8] = b"meshmsg-direct-ack-v1";
type Signature = ByteArray<SIGNATURE_LENGTH>;
type ReplayCache = Arc<Mutex<HashMap<(PublicKey, [u8; 16]), Instant>>>;

fn now_ms() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64)
}

pub(crate) fn presence_topic(topic: TopicId) -> TopicId {
    let mut hasher = Sha256::new();
    hasher.update(PRESENCE_DOMAIN);
    hasher.update(topic.as_bytes());
    TopicId::from_bytes(hasher.finalize().into())
}

pub(crate) fn validate_endpoint_addr(addr: &EndpointAddr, expected: PublicKey) -> Result<()> {
    anyhow::ensure!(
        addr.id == expected,
        "endpoint public key does not match signer"
    );
    anyhow::ensure!(
        !addr.addrs.is_empty(),
        "endpoint has no advertised addresses"
    );
    anyhow::ensure!(
        addr.addrs.len() <= MAX_ENDPOINT_ADDRS,
        "endpoint advertises too many addresses"
    );
    let mut relay_count = 0usize;
    for address in &addr.addrs {
        match address {
            TransportAddr::Relay(_) => {
                relay_count += 1;
                anyhow::ensure!(relay_count <= 1, "endpoint advertises multiple relays");
            }
            TransportAddr::Ip(socket) => {
                let ip = socket.ip();
                anyhow::ensure!(socket.port() != 0, "endpoint IP address has port zero");
                anyhow::ensure!(!ip.is_unspecified(), "endpoint IP address is unspecified");
                anyhow::ensure!(!ip.is_multicast(), "endpoint IP address is multicast");
                if let std::net::IpAddr::V4(ip) = ip {
                    anyhow::ensure!(!ip.is_broadcast(), "endpoint IP address is broadcast");
                }
            }
            _ => anyhow::bail!("custom endpoint addresses are not accepted"),
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PresencePayload {
    version: u8,
    topic: TopicId,
    sender: PublicKey,
    alias: Option<String>,
    endpoint: EndpointAddr,
    issued_ms: u64,
    expires_ms: u64,
    id: [u8; 16],
}

#[derive(Debug, Serialize, Deserialize)]
struct SignedPresence {
    payload: PresencePayload,
    signature: Signature,
}

impl SignedPresence {
    pub(crate) fn encode(
        secret: &SecretKey,
        topic: TopicId,
        alias: Option<&str>,
        endpoint: EndpointAddr,
    ) -> Result<Bytes> {
        Self::encode_at(secret, topic, alias, endpoint, now_ms()?, rand::random())
    }

    fn encode_at(
        secret: &SecretKey,
        topic: TopicId,
        alias: Option<&str>,
        endpoint: EndpointAddr,
        issued_ms: u64,
        id: [u8; 16],
    ) -> Result<Bytes> {
        validate_endpoint_addr(&endpoint, secret.public())?;
        let alias = alias.map(normalize_alias).transpose()?;
        let payload = PresencePayload {
            version: VERSION,
            topic,
            sender: secret.public(),
            alias,
            endpoint,
            issued_ms,
            expires_ms: issued_ms
                .checked_add(PRESENCE_LIFETIME.as_millis() as u64)
                .context("presence expiration overflow")?,
            id,
        };
        let signed = postcard::to_stdvec(&(PRESENCE_DOMAIN, &payload))?;
        let record = Self {
            payload,
            signature: ByteArray::new(secret.sign(&signed).to_bytes()),
        };
        let encoded = postcard::to_stdvec(&record)?;
        anyhow::ensure!(
            encoded.len() <= MAX_PRESENCE_FRAME,
            "presence record exceeds {MAX_PRESENCE_FRAME} bytes"
        );
        Ok(encoded.into())
    }

    fn decode(bytes: &[u8], topic: TopicId, at_ms: u64) -> Result<PresencePayload> {
        anyhow::ensure!(
            bytes.len() <= MAX_PRESENCE_FRAME,
            "presence record exceeds {MAX_PRESENCE_FRAME} bytes"
        );
        let (record, remainder): (Self, &[u8]) =
            postcard::take_from_bytes(bytes).context("decode presence record")?;
        anyhow::ensure!(
            remainder.is_empty(),
            "presence record contains trailing bytes"
        );
        anyhow::ensure!(
            record.payload.version == VERSION,
            "unsupported presence version"
        );
        anyhow::ensure!(record.payload.topic == topic, "presence topic mismatch");
        if let Some(alias) = &record.payload.alias {
            validate_alias(alias)?;
        }
        validate_endpoint_addr(&record.payload.endpoint, record.payload.sender)?;
        let signed = postcard::to_stdvec(&(PRESENCE_DOMAIN, &record.payload))?;
        record
            .payload
            .sender
            .verify(&signed, &iroh::Signature::from_bytes(&record.signature))
            .context("verify presence signature")?;
        let skew_ms = MAX_CLOCK_SKEW.as_millis() as u64;
        anyhow::ensure!(
            record.payload.issued_ms <= at_ms.saturating_add(skew_ms),
            "presence timestamp is too far in the future"
        );
        anyhow::ensure!(
            record.payload.expires_ms
                == record
                    .payload
                    .issued_ms
                    .saturating_add(PRESENCE_LIFETIME.as_millis() as u64),
            "presence lifetime is invalid"
        );
        anyhow::ensure!(
            at_ms <= record.payload.expires_ms,
            "presence record is expired"
        );
        Ok(record.payload)
    }
}

#[derive(Debug, Clone)]
struct DynamicDirectoryEntry {
    endpoint: EndpointAddr,
    alias: Option<String>,
    expires: Instant,
    issued_ms: u64,
}

#[derive(Debug, Clone)]
struct PresenceReplayWatermark {
    issued_ms: u64,
    forget_at: Instant,
}

#[derive(Debug)]
pub(crate) struct Directory {
    pinned: HashMap<PublicKey, EndpointAddr>,
    dynamic: HashMap<PublicKey, DynamicDirectoryEntry>,
    replay_watermarks: HashMap<PublicKey, PresenceReplayWatermark>,
    presence_lookup: MemoryLookup,
}

impl Directory {
    pub(crate) fn new(presence_lookup: MemoryLookup) -> Self {
        Self {
            pinned: HashMap::new(),
            dynamic: HashMap::new(),
            replay_watermarks: HashMap::new(),
            presence_lookup,
        }
    }

    pub(crate) fn pin(&mut self, endpoint: EndpointAddr) -> Result<()> {
        validate_endpoint_addr(&endpoint, endpoint.id)?;
        anyhow::ensure!(
            self.pinned.contains_key(&endpoint.id) || self.pinned.len() < MAX_PINNED_ENDPOINTS,
            "pinned endpoint capacity reached"
        );
        self.pinned.entry(endpoint.id).or_insert(endpoint);
        Ok(())
    }

    pub(crate) fn receive(&mut self, bytes: &[u8], topic: TopicId) -> Result<()> {
        self.receive_at(bytes, topic, now_ms()?, Instant::now())
    }

    fn receive_at(
        &mut self,
        bytes: &[u8],
        topic: TopicId,
        wall_ms: u64,
        monotonic_now: Instant,
    ) -> Result<()> {
        self.cleanup_at(monotonic_now);
        let payload = SignedPresence::decode(bytes, topic, wall_ms)?;
        if self
            .dynamic
            .get(&payload.sender)
            .is_some_and(|entry| entry.issued_ms >= payload.issued_ms)
            || self
                .replay_watermarks
                .get(&payload.sender)
                .is_some_and(|entry| entry.issued_ms >= payload.issued_ms)
        {
            anyhow::bail!("presence record is not newer than the current record");
        }
        let already_tracked = self.dynamic.contains_key(&payload.sender)
            || self.replay_watermarks.contains_key(&payload.sender);
        anyhow::ensure!(
            already_tracked
                || self.dynamic.len() + self.replay_watermarks.len()
                    < MAX_DYNAMIC_PRESENCE_IDENTITIES,
            "dynamic presence identity capacity reached"
        );
        let remaining = Duration::from_millis(payload.expires_ms.saturating_sub(wall_ms))
            .min(PRESENCE_LIFETIME);
        anyhow::ensure!(!remaining.is_zero(), "presence record is expired");
        let endpoint = payload.endpoint;
        self.replay_watermarks.remove(&payload.sender);
        self.dynamic.insert(
            payload.sender,
            DynamicDirectoryEntry {
                endpoint: endpoint.clone(),
                alias: payload.alias,
                expires: monotonic_now + remaining,
                issued_ms: payload.issued_ms,
            },
        );
        // MemoryLookup::add_endpoint_info merges direct addresses forever. Presence
        // records are snapshots, so replace this source's record in full instead.
        self.presence_lookup.set_endpoint_info(endpoint);
        Ok(())
    }

    pub(crate) fn cleanup(&mut self) {
        self.cleanup_at(Instant::now());
    }

    fn cleanup_at(&mut self, now: Instant) {
        self.replay_watermarks
            .retain(|_, watermark| watermark.forget_at > now);
        let expired: Vec<_> = self
            .dynamic
            .iter()
            .filter_map(|(key, entry)| (entry.expires <= now).then_some(*key))
            .collect();
        for key in expired {
            if let Some(entry) = self.dynamic.remove(&key) {
                self.presence_lookup.remove_endpoint_info(key);
                self.replay_watermarks.insert(
                    key,
                    PresenceReplayWatermark {
                        issued_ms: entry.issued_ms,
                        forget_at: now + PRESENCE_REPLAY_LIFETIME,
                    },
                );
            }
        }
    }

    pub(crate) fn resolve(&mut self, recipient: &str) -> Result<EndpointAddr> {
        self.cleanup();
        if let Ok(key) = PublicKey::from_str(recipient) {
            anyhow::ensure!(
                key.to_string() == recipient,
                "public key recipient must use its canonical encoding"
            );
            return self
                .dynamic
                .get(&key)
                .map(|entry| entry.endpoint.clone())
                .or_else(|| self.pinned.get(&key).cloned())
                .context("recipient has no current signed presence or pinned endpoint address");
        }

        let alias = normalize_alias(recipient)
            .context("recipient is neither a public key nor a valid alias")?;
        let mut matches = self
            .dynamic
            .values()
            .filter(|entry| entry.alias.as_deref() == Some(alias.as_str()));
        let first = matches.next().context("no peer advertises that alias")?;
        anyhow::ensure!(
            matches.next().is_none(),
            "alias is advertised by multiple peers; use a full public key"
        );
        Ok(first.endpoint.clone())
    }

    pub(crate) fn advertised_aliases(&self) -> usize {
        let now = Instant::now();
        self.dynamic
            .values()
            .filter(|entry| entry.expires > now && entry.alias.is_some())
            .count()
    }
}

#[derive(Debug, Clone)]
struct PresenceSourceWindow {
    started: Instant,
    accepted: usize,
}

#[derive(Debug, Default)]
pub(crate) struct PresenceSourceLimiter {
    sources: HashMap<PublicKey, PresenceSourceWindow>,
}

impl PresenceSourceLimiter {
    pub(crate) fn allow(&mut self, transport_source: PublicKey) -> bool {
        self.allow_at(transport_source, Instant::now())
    }

    fn allow_at(&mut self, transport_source: PublicKey, now: Instant) -> bool {
        self.cleanup_at(now);
        if let Some(window) = self.sources.get_mut(&transport_source) {
            if now.duration_since(window.started) >= PRESENCE_SOURCE_WINDOW {
                *window = PresenceSourceWindow {
                    started: now,
                    accepted: 1,
                };
                return true;
            }
            if window.accepted >= MAX_PRESENCE_RECORDS_PER_SOURCE {
                return false;
            }
            window.accepted += 1;
            return true;
        }
        if self.sources.len() >= MAX_PRESENCE_TRANSPORT_SOURCES {
            return false;
        }
        self.sources.insert(
            transport_source,
            PresenceSourceWindow {
                started: now,
                accepted: 1,
            },
        );
        true
    }

    pub(crate) fn remove(&mut self, transport_source: PublicKey) {
        self.sources.remove(&transport_source);
    }

    pub(crate) fn cleanup(&mut self) {
        self.cleanup_at(Instant::now());
    }

    fn cleanup_at(&mut self, now: Instant) {
        self.sources
            .retain(|_, window| now.duration_since(window.started) < PRESENCE_SOURCE_WINDOW);
    }
}

pub(crate) fn encode_presence(
    secret: &SecretKey,
    topic: TopicId,
    alias: Option<&str>,
    endpoint: EndpointAddr,
) -> Result<Bytes> {
    SignedPresence::encode(secret, topic, alias, endpoint)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DirectPayload {
    version: u8,
    sender: PublicKey,
    recipient: PublicKey,
    topic: TopicId,
    id: [u8; 16],
    timestamp_ms: u64,
    body: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct DirectFrame {
    payload: DirectPayload,
    signature: Signature,
}

impl DirectFrame {
    fn new(secret: &SecretKey, recipient: PublicKey, topic: TopicId, body: String) -> Result<Self> {
        anyhow::ensure!(!body.is_empty(), "private message cannot be empty");
        anyhow::ensure!(
            body.len() <= MAX_BODY_BYTES,
            "private message exceeds {MAX_BODY_BYTES} UTF-8 bytes"
        );
        let payload = DirectPayload {
            version: VERSION,
            sender: secret.public(),
            recipient,
            topic,
            id: rand::random(),
            timestamp_ms: now_ms()?,
            body,
        };
        let signed = postcard::to_stdvec(&(MESSAGE_DOMAIN, &payload))?;
        Ok(Self {
            payload,
            signature: ByteArray::new(secret.sign(&signed).to_bytes()),
        })
    }

    fn encode(&self) -> Result<Vec<u8>> {
        let bytes = postcard::to_stdvec(self)?;
        anyhow::ensure!(
            bytes.len() <= MAX_DIRECT_FRAME,
            "private message frame is too large"
        );
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        anyhow::ensure!(
            bytes.len() <= MAX_DIRECT_FRAME,
            "private message frame is too large"
        );
        let (frame, remainder): (Self, &[u8]) =
            postcard::take_from_bytes(bytes).context("decode private message")?;
        anyhow::ensure!(
            remainder.is_empty(),
            "private message contains trailing bytes"
        );
        anyhow::ensure!(
            frame.payload.version == VERSION,
            "unsupported private message version"
        );
        anyhow::ensure!(
            !frame.payload.body.is_empty(),
            "private message cannot be empty"
        );
        anyhow::ensure!(
            frame.payload.body.len() <= MAX_BODY_BYTES,
            "private message body is too large"
        );
        let signed = postcard::to_stdvec(&(MESSAGE_DOMAIN, &frame.payload))?;
        frame
            .payload
            .sender
            .verify(&signed, &iroh::Signature::from_bytes(&frame.signature))
            .context("verify private message signature")?;
        let at_ms = now_ms()?;
        let skew_ms = MAX_CLOCK_SKEW.as_millis() as u64;
        anyhow::ensure!(
            frame.payload.timestamp_ms <= at_ms.saturating_add(skew_ms),
            "private message timestamp is too far in the future"
        );
        anyhow::ensure!(
            at_ms <= frame.payload.timestamp_ms.saturating_add(skew_ms),
            "private message is stale"
        );
        Ok(frame)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
enum AckReason {
    Accepted,
    Busy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AckPayload {
    version: u8,
    sender: PublicKey,
    recipient: PublicKey,
    topic: TopicId,
    id: [u8; 16],
    accepted: bool,
    reason: AckReason,
}

#[derive(Debug, Serialize, Deserialize)]
struct AckFrame {
    payload: AckPayload,
    signature: Signature,
}

impl AckFrame {
    fn new(
        secret: &SecretKey,
        message: &DirectPayload,
        accepted: bool,
        reason: AckReason,
    ) -> Result<Self> {
        let payload = AckPayload {
            version: VERSION,
            sender: secret.public(),
            recipient: message.sender,
            topic: message.topic,
            id: message.id,
            accepted,
            reason,
        };
        let signed = postcard::to_stdvec(&(ACK_DOMAIN, &payload))?;
        Ok(Self {
            payload,
            signature: ByteArray::new(secret.sign(&signed).to_bytes()),
        })
    }

    fn encode(&self) -> Result<Vec<u8>> {
        let bytes = postcard::to_stdvec(self)?;
        anyhow::ensure!(
            bytes.len() <= MAX_DIRECT_FRAME,
            "private acknowledgement is too large"
        );
        Ok(bytes)
    }

    fn decode(bytes: &[u8], message: &DirectPayload) -> Result<Self> {
        anyhow::ensure!(
            bytes.len() <= MAX_DIRECT_FRAME,
            "private acknowledgement is too large"
        );
        let (ack, remainder): (Self, &[u8]) =
            postcard::take_from_bytes(bytes).context("decode private acknowledgement")?;
        anyhow::ensure!(
            remainder.is_empty(),
            "private acknowledgement contains trailing bytes"
        );
        anyhow::ensure!(
            ack.payload.version == VERSION,
            "unsupported private acknowledgement version"
        );
        anyhow::ensure!(
            ack.payload.sender == message.recipient,
            "private acknowledgement has wrong sender"
        );
        anyhow::ensure!(
            ack.payload.recipient == message.sender,
            "private acknowledgement has wrong recipient"
        );
        anyhow::ensure!(
            ack.payload.topic == message.topic && ack.payload.id == message.id,
            "private acknowledgement does not match message"
        );
        anyhow::ensure!(
            matches!(
                (ack.payload.accepted, ack.payload.reason),
                (true, AckReason::Accepted) | (false, AckReason::Busy)
            ),
            "private acknowledgement status is inconsistent"
        );
        let signed = postcard::to_stdvec(&(ACK_DOMAIN, &ack.payload))?;
        ack.payload
            .sender
            .verify(&signed, &iroh::Signature::from_bytes(&ack.signature))
            .context("verify private acknowledgement signature")?;
        Ok(ack)
    }
}

#[derive(Debug)]
pub(crate) struct IncomingDirect {
    pub(crate) from: PublicKey,
    pub(crate) id: [u8; 16],
    pub(crate) timestamp_ms: u64,
    pub(crate) body: String,
}

#[derive(Debug, Clone)]
pub(crate) struct DirectHandler {
    secret: SecretKey,
    topic: TopicId,
    incoming: mpsc::Sender<IncomingDirect>,
    replay: ReplayCache,
    connections: Arc<tokio::sync::Semaphore>,
}

impl DirectHandler {
    pub(crate) fn new(
        secret: SecretKey,
        topic: TopicId,
        incoming: mpsc::Sender<IncomingDirect>,
    ) -> Self {
        Self {
            secret,
            topic,
            incoming,
            replay: Arc::new(Mutex::new(HashMap::new())),
            connections: Arc::new(tokio::sync::Semaphore::new(32)),
        }
    }

    fn accept_message(&self, remote: PublicKey, bytes: &[u8]) -> Result<AckFrame> {
        let frame = DirectFrame::decode(bytes)?;
        anyhow::ensure!(
            frame.payload.sender == remote,
            "TLS peer does not match message sender"
        );
        anyhow::ensure!(
            frame.payload.recipient == self.secret.public(),
            "private message has wrong recipient"
        );
        anyhow::ensure!(
            frame.payload.topic == self.topic,
            "private message has wrong topic"
        );

        let key = (frame.payload.sender, frame.payload.id);
        let mut replay = self
            .replay
            .lock()
            .map_err(|_| anyhow::anyhow!("replay cache poisoned"))?;
        let now = Instant::now();
        replay.retain(|_, seen| now.duration_since(*seen) < REPLAY_LIFETIME);
        if replay.contains_key(&key) {
            // The original request was already accepted into this daemon's queue.
            // Re-acknowledge it without delivering the plaintext a second time.
            return AckFrame::new(&self.secret, &frame.payload, true, AckReason::Accepted);
        }
        // Never evict a still-valid ID: doing so would permit a replay after
        // cache-pressure eviction. Capacity exhaustion fails closed until TTL
        // pruning makes room.
        if replay.len() >= MAX_REPLAY_ENTRIES {
            return AckFrame::new(&self.secret, &frame.payload, false, AckReason::Busy);
        }
        let incoming = IncomingDirect {
            from: frame.payload.sender,
            id: frame.payload.id,
            timestamp_ms: frame.payload.timestamp_ms,
            body: frame.payload.body.clone(),
        };
        if self.incoming.try_send(incoming).is_err() {
            return AckFrame::new(&self.secret, &frame.payload, false, AckReason::Busy);
        }
        replay.insert(key, now);
        AckFrame::new(&self.secret, &frame.payload, true, AckReason::Accepted)
    }
}

impl ProtocolHandler for DirectHandler {
    async fn accept(&self, connection: Connection) -> std::result::Result<(), AcceptError> {
        let remote = connection.remote_id();
        let connections = self.connections.clone();
        let result = async {
            let _permit = connections
                .try_acquire_owned()
                .context("private-message connection capacity reached")?;
            tokio::time::timeout(DIRECT_TIMEOUT, async {
                let (mut send, mut recv) = connection.accept_bi().await?;
                let request = recv.read_to_end(MAX_DIRECT_FRAME).await?;
                let ack = self.accept_message(remote, &request)?.encode()?;
                send.write_all(&ack).await?;
                send.finish()?;
                // Keep the connection alive until the authenticated peer has
                // consumed the acknowledgement; dropping immediately can reset it.
                send.stopped().await?;
                Ok::<(), anyhow::Error>(())
            })
            .await
            .context("private-message request timed out")??;
            Ok::<(), anyhow::Error>(())
        }
        .await;
        result.map_err(|error| AcceptError::from_boxed(error.into_boxed_dyn_error()))
    }
}

#[derive(Debug)]
pub(crate) struct AcceptedDirect {
    pub(crate) recipient: PublicKey,
    pub(crate) id: [u8; 16],
    pub(crate) timestamp_ms: u64,
    pub(crate) body_bytes: usize,
}

pub(crate) async fn send(
    endpoint: Endpoint,
    secret: SecretKey,
    topic: TopicId,
    address: EndpointAddr,
    body: String,
) -> Result<AcceptedDirect> {
    validate_endpoint_addr(&address, address.id)?;
    let frame = DirectFrame::new(&secret, address.id, topic, body)?;
    let encoded = frame.encode()?;
    let body_bytes = frame.payload.body.len();
    let recipient = frame.payload.recipient;
    let id = frame.payload.id;
    let timestamp_ms = frame.payload.timestamp_ms;
    let operation = async {
        let connection = endpoint
            .connect(address, DIRECT_ALPN)
            .await
            .context("connect to private-message recipient")?;
        anyhow::ensure!(
            connection.remote_id() == recipient,
            "connected peer does not match recipient"
        );
        let (mut send, mut recv) = connection
            .open_bi()
            .await
            .context("open private-message stream")?;
        send.write_all(&encoded)
            .await
            .context("send private message")?;
        send.finish().context("finish private message")?;
        let bytes = recv
            .read_to_end(MAX_DIRECT_FRAME)
            .await
            .context("read private-message acknowledgement")?;
        let ack = AckFrame::decode(&bytes, &frame.payload)?;
        anyhow::ensure!(
            ack.payload.accepted,
            "recipient rejected private message ({:?})",
            ack.payload.reason
        );
        Ok(AcceptedDirect {
            recipient,
            id,
            timestamp_ms,
            body_bytes,
        })
    };
    tokio::time::timeout(DIRECT_TIMEOUT, operation)
        .await
        .context("private-message operation timed out")?
}

pub(crate) fn id_string(id: &[u8; 16]) -> String {
    data_encoding::HEXLOWER.encode(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(secret: &SecretKey, port: u16) -> EndpointAddr {
        EndpointAddr::new(secret.public()).with_ip_addr(([127, 0, 0, 1], port).into())
    }

    #[test]
    fn presence_is_signed_topic_bound_and_bounded() {
        let secret = SecretKey::generate();
        let topic = TopicId::from_bytes([7; 32]);
        let bytes = SignedPresence::encode(&secret, topic, Some("node-1"), endpoint(&secret, 7777))
            .unwrap();
        let decoded = SignedPresence::decode(&bytes, topic, now_ms().unwrap()).unwrap();
        assert_eq!(decoded.sender, secret.public());
        assert_eq!(decoded.alias.as_deref(), Some("node-1"));
        assert!(
            SignedPresence::decode(&bytes, TopicId::from_bytes([8; 32]), now_ms().unwrap())
                .is_err()
        );
        let mut tampered = bytes.to_vec();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(SignedPresence::decode(&tampered, topic, now_ms().unwrap()).is_err());

        let mut directory = Directory::new(MemoryLookup::new());
        directory.receive(&bytes, topic).unwrap();
        assert!(directory.receive(&bytes, topic).is_err());
    }

    #[test]
    fn resolution_prefers_canonical_keys_and_fails_closed_on_collision() {
        let one = SecretKey::generate();
        let two = SecretKey::generate();
        let topic = TopicId::from_bytes([3; 32]);
        let mut directory = Directory::new(MemoryLookup::new());
        for (secret, port) in [(&one, 1111), (&two, 2222)] {
            let bytes = SignedPresence::encode(secret, topic, Some("same"), endpoint(secret, port))
                .unwrap();
            directory.receive(&bytes, topic).unwrap();
        }
        assert!(directory
            .resolve("same")
            .unwrap_err()
            .to_string()
            .contains("multiple peers"));
        assert_eq!(
            directory.resolve(&one.public().to_string()).unwrap().id,
            one.public()
        );
        assert!(directory
            .resolve(&one.public().to_string().to_ascii_uppercase())
            .is_err());
        assert!(directory.resolve("does-not-exist").is_err());
    }

    #[test]
    fn dynamic_directory_has_a_hard_fail_closed_identity_cap() {
        let topic = TopicId::from_bytes([5; 32]);
        let wall = now_ms().unwrap();
        let monotonic = Instant::now();
        let lookup = MemoryLookup::new();
        let mut directory = Directory::new(lookup.clone());
        let mut admitted = Vec::new();

        for index in 0..MAX_DYNAMIC_PRESENCE_IDENTITIES {
            let secret = SecretKey::generate();
            let bytes = SignedPresence::encode_at(
                &secret,
                topic,
                None,
                endpoint(&secret, 10_000 + index as u16),
                wall,
                [index as u8; 16],
            )
            .unwrap();
            directory
                .receive_at(&bytes, topic, wall, monotonic)
                .unwrap();
            admitted.push(secret.public());
        }
        let rejected = SecretKey::generate();
        let bytes = SignedPresence::encode_at(
            &rejected,
            topic,
            None,
            endpoint(&rejected, 20_000),
            wall,
            [255; 16],
        )
        .unwrap();
        assert!(directory
            .receive_at(&bytes, topic, wall, monotonic)
            .unwrap_err()
            .to_string()
            .contains("capacity"));

        assert_eq!(directory.dynamic.len(), MAX_DYNAMIC_PRESENCE_IDENTITIES);
        assert_eq!(directory.replay_watermarks.len(), 0);
        assert!(lookup.get_endpoint_info(rejected.public()).is_none());
        assert!(admitted
            .iter()
            .all(|key| lookup.get_endpoint_info(*key).is_some()));
        let before = directory.dynamic.len();
        assert_eq!(directory.advertised_aliases(), 0);
        assert_eq!(directory.dynamic.len(), before);
    }

    #[test]
    fn newer_presence_replaces_rotating_addresses_in_directory_and_lookup() {
        let secret = SecretKey::generate();
        let topic = TopicId::from_bytes([6; 32]);
        let wall = now_ms().unwrap();
        let monotonic = Instant::now();
        let lookup = MemoryLookup::new();
        let mut directory = Directory::new(lookup.clone());
        let mut latest = endpoint(&secret, 30_000);

        for sequence in 0..32_u64 {
            latest = endpoint(&secret, 30_000 + sequence as u16);
            let bytes = SignedPresence::encode_at(
                &secret,
                topic,
                Some("rotating"),
                latest.clone(),
                wall + sequence,
                [sequence as u8; 16],
            )
            .unwrap();
            directory
                .receive_at(
                    &bytes,
                    topic,
                    wall + sequence,
                    monotonic + Duration::from_millis(sequence),
                )
                .unwrap();
        }

        assert_eq!(directory.dynamic.len(), 1);
        assert_eq!(directory.resolve("rotating").unwrap(), latest);
        let lookup_addr: EndpointAddr = lookup.get_endpoint_info(secret.public()).unwrap().into();
        assert_eq!(lookup_addr, latest);
        assert_eq!(lookup_addr.addrs.len(), 1);
    }

    #[test]
    fn periodic_expiry_removes_only_dynamic_route_preserves_pin_and_rejects_replay() {
        let secret = SecretKey::generate();
        let topic = TopicId::from_bytes([10; 32]);
        let wall = now_ms().unwrap();
        let monotonic = Instant::now();
        let pinned = endpoint(&secret, 40_001);
        let dynamic = endpoint(&secret, 40_002);
        let stable_lookup = MemoryLookup::with_provenance("test_stable");
        let presence_lookup = MemoryLookup::with_provenance("test_presence");
        stable_lookup.set_endpoint_info(pinned.clone());
        let mut directory = Directory::new(presence_lookup.clone());
        directory.pin(pinned.clone()).unwrap();
        let bytes = SignedPresence::encode_at(
            &secret,
            topic,
            Some("expires"),
            dynamic.clone(),
            wall,
            [7; 16],
        )
        .unwrap();
        directory
            .receive_at(&bytes, topic, wall, monotonic)
            .unwrap();
        assert_eq!(directory.resolve("expires").unwrap(), dynamic);

        // This is the daemon's periodic cleanup path; no status or resolution
        // call is needed to expire the active state and its lookup source.
        let after_expiry = monotonic + PRESENCE_LIFETIME + Duration::from_millis(1);
        directory.cleanup_at(after_expiry);
        assert!(directory.dynamic.is_empty());
        assert!(presence_lookup.get_endpoint_info(secret.public()).is_none());
        let stable_addr: EndpointAddr = stable_lookup
            .get_endpoint_info(secret.public())
            .unwrap()
            .into();
        assert_eq!(stable_addr, pinned);
        assert_eq!(
            directory.resolve(&secret.public().to_string()).unwrap(),
            pinned
        );
        assert!(directory.resolve("expires").is_err());

        // Replaying the exact signed record cannot renew its lifetime or route.
        assert!(directory
            .receive_at(&bytes, topic, wall, after_expiry)
            .is_err());
        assert!(directory.dynamic.is_empty());
        assert!(presence_lookup.get_endpoint_info(secret.public()).is_none());
    }

    #[test]
    fn presence_rate_limit_uses_bounded_transport_sources() {
        let source = SecretKey::generate().public();
        let start = Instant::now();
        let mut limiter = PresenceSourceLimiter::default();
        for _ in 0..MAX_PRESENCE_RECORDS_PER_SOURCE {
            assert!(limiter.allow_at(source, start));
        }
        assert!(!limiter.allow_at(source, start));

        for _ in 1..MAX_PRESENCE_TRANSPORT_SOURCES {
            assert!(limiter.allow_at(SecretKey::generate().public(), start));
        }
        assert!(!limiter.allow_at(SecretKey::generate().public(), start));
        assert!(limiter.allow_at(source, start + PRESENCE_SOURCE_WINDOW));
        assert_eq!(limiter.sources.len(), 1);
    }

    #[test]
    fn replay_is_reacknowledged_without_redelivery() {
        let sender = SecretKey::generate();
        let receiver = SecretKey::generate();
        let topic = TopicId::from_bytes([9; 32]);
        let (tx, mut rx) = mpsc::channel(2);
        let handler = DirectHandler::new(receiver.clone(), topic, tx);
        let frame =
            DirectFrame::new(&sender, receiver.public(), topic, "deliver once".into()).unwrap();
        let bytes = frame.encode().unwrap();

        for _ in 0..2 {
            let ack = handler.accept_message(sender.public(), &bytes).unwrap();
            assert!(ack.payload.accepted);
            assert_eq!(ack.payload.id, frame.payload.id);
        }
        assert_eq!(rx.try_recv().unwrap().body, "deliver once");
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn direct_frame_binds_all_fields_and_detects_tampering() {
        let sender = SecretKey::generate();
        let receiver = SecretKey::generate();
        let topic = TopicId::from_bytes([4; 32]);
        let frame = DirectFrame::new(&sender, receiver.public(), topic, "secret".into()).unwrap();
        let bytes = frame.encode().unwrap();
        let decoded = DirectFrame::decode(&bytes).unwrap();
        assert_eq!(decoded.payload.sender, sender.public());
        assert_eq!(decoded.payload.recipient, receiver.public());
        assert_eq!(decoded.payload.topic, topic);
        assert_eq!(decoded.payload.body, "secret");
        let mut tampered = bytes;
        *tampered.last_mut().unwrap() ^= 1;
        assert!(DirectFrame::decode(&tampered).is_err());
    }
}
