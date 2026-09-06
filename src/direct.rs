use crate::alias::{normalize_alias, validate_alias};
use anyhow::{Context, Result};
use bytes::Bytes;
use iroh::{
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
const PRESENCE_LIFETIME: Duration = Duration::from_secs(150);
const MAX_CLOCK_SKEW: Duration = Duration::from_secs(5 * 60);
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
        validate_endpoint_addr(&endpoint, secret.public())?;
        let alias = alias.map(normalize_alias).transpose()?;
        let issued_ms = now_ms()?;
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
            id: rand::random(),
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
struct DirectoryEntry {
    endpoint: EndpointAddr,
    alias: Option<String>,
    expires: Option<Instant>,
    issued_ms: u64,
    pinned: bool,
}

#[derive(Debug, Default)]
pub(crate) struct Directory {
    entries: HashMap<PublicKey, DirectoryEntry>,
}

impl Directory {
    pub(crate) fn pin(&mut self, endpoint: EndpointAddr) -> Result<()> {
        validate_endpoint_addr(&endpoint, endpoint.id)?;
        self.entries.entry(endpoint.id).or_insert(DirectoryEntry {
            endpoint,
            alias: None,
            expires: None,
            issued_ms: 0,
            pinned: true,
        });
        Ok(())
    }

    pub(crate) fn receive(&mut self, bytes: &[u8], topic: TopicId) -> Result<EndpointAddr> {
        let payload = SignedPresence::decode(bytes, topic, now_ms()?)?;
        let endpoint = payload.endpoint.clone();
        if self
            .entries
            .get(&payload.sender)
            .is_some_and(|entry| entry.issued_ms >= payload.issued_ms)
        {
            anyhow::bail!("presence record is not newer than the current record");
        }
        let pinned = self
            .entries
            .get(&payload.sender)
            .is_some_and(|entry| entry.pinned);
        let remaining = Duration::from_millis(payload.expires_ms.saturating_sub(now_ms()?))
            .min(PRESENCE_LIFETIME);
        self.entries.insert(
            payload.sender,
            DirectoryEntry {
                endpoint: endpoint.clone(),
                alias: payload.alias,
                expires: Some(Instant::now() + remaining),
                issued_ms: payload.issued_ms,
                pinned,
            },
        );
        Ok(endpoint)
    }

    fn prune(&mut self) {
        let now = Instant::now();
        self.entries.retain(|_, entry| {
            if entry.expires.is_some_and(|expires| expires <= now) {
                if entry.pinned {
                    entry.alias = None;
                    entry.expires = None;
                    entry.issued_ms = 0;
                    true
                } else {
                    false
                }
            } else {
                true
            }
        });
    }

    pub(crate) fn resolve(&mut self, recipient: &str) -> Result<EndpointAddr> {
        self.prune();
        if let Ok(key) = PublicKey::from_str(recipient) {
            anyhow::ensure!(
                key.to_string() == recipient,
                "public key recipient must use its canonical encoding"
            );
            return self
                .entries
                .get(&key)
                .map(|entry| entry.endpoint.clone())
                .context("recipient has no current signed presence or pinned endpoint address");
        }

        let alias = normalize_alias(recipient)
            .context("recipient is neither a public key nor a valid alias")?;
        let mut matches = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.alias.as_deref() == Some(alias.as_str()));
        let first = matches.next().context("no peer advertises that alias")?;
        anyhow::ensure!(
            matches.next().is_none(),
            "alias is advertised by multiple peers; use a full public key"
        );
        Ok(first.1.endpoint.clone())
    }

    pub(crate) fn advertised_aliases(&mut self) -> usize {
        self.prune();
        self.entries
            .values()
            .filter(|entry| entry.alias.is_some())
            .count()
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

        let mut directory = Directory::default();
        directory.receive(&bytes, topic).unwrap();
        assert!(directory.receive(&bytes, topic).is_err());
    }

    #[test]
    fn resolution_prefers_canonical_keys_and_fails_closed_on_collision() {
        let one = SecretKey::generate();
        let two = SecretKey::generate();
        let topic = TopicId::from_bytes([3; 32]);
        let mut directory = Directory::default();
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
