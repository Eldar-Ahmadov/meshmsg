use crate::{
    alias::{normalize_alias, validate_alias},
    clock::unix_timestamp_ms,
    ids::peer_id,
};
use anyhow::{Context, Result};
use bytes::Bytes;
use iroh::{
    address_lookup::memory::MemoryLookup, Endpoint, EndpointAddr, PublicKey, SecretKey,
    TransportAddr, Watcher,
};
use iroh_gossip::{
    api::{GossipReceiver, GossipSender},
    proto::TopicId,
};
use meshmsg_protocol::{Event, OperationId, PeerId, PeerSnapshot, RemotePeer};
use serde::{Deserialize, Serialize};
use serde_byte_array::ByteArray;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    str::FromStr,
    time::{Duration, Instant},
};

/// Maximum lifetime of a signed remote presence lease. Snapshot expiry is
/// locally derived and never extends beyond this bound.
pub(crate) const PEER_LEASE_MS: u64 = meshmsg_protocol::PEER_LEASE_MS;
/// Documented ceiling for one encoded lifecycle event. The typed field bounds
/// guarantee it; the test below proves the worst case.
#[cfg(test)]
pub(crate) const MAX_PEER_LIFECYCLE_EVENT_BYTES: usize = 512;
pub(crate) const MAX_DYNAMIC_IDENTITIES: usize = meshmsg_protocol::MAX_PEERS;

pub(crate) const ALPN: &[u8] = b"/meshmsg/presence-gossip/1";
pub(crate) const ANNOUNCE_INTERVAL: Duration = Duration::from_secs(30);
pub(crate) const CLEANUP_INTERVAL: Duration = Duration::from_secs(15);
const PRESENCE_VERSION: u8 = 1;
const SIGNATURE_LENGTH: usize = iroh::Signature::LENGTH;
const MAX_PRESENCE_FRAME: usize = 2048;
pub(crate) const MAX_GOSSIP_MESSAGE_SIZE: usize = MAX_PRESENCE_FRAME + 512;
const MAX_ENDPOINT_ADDRS: usize = 8;
const MAX_PINNED_ENDPOINTS: usize = crate::invite::MAX_BOOTSTRAP_PEERS + 1;
const PRESENCE_LIFETIME: Duration = Duration::from_millis(PEER_LEASE_MS);
const PRESENCE_FUTURE_SKEW: Duration = Duration::from_secs(60);
const PRESENCE_REPLAY_LIFETIME: Duration = Duration::from_secs(450);
const MAX_TRANSPORT_SOURCES: usize = 32;
const MAX_RECORDS_PER_SOURCE: usize = 128;
const SOURCE_WINDOW: Duration = Duration::from_secs(1);
const PRESENCE_DOMAIN: &[u8] = b"meshmsg-presence-v1";
type Signature = ByteArray<SIGNATURE_LENGTH>;

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
    fn encode(
        secret: &SecretKey,
        topic: TopicId,
        alias: Option<&str>,
        endpoint: EndpointAddr,
    ) -> Result<Bytes> {
        Self::encode_at(
            secret,
            topic,
            alias,
            endpoint,
            unix_timestamp_ms()?,
            rand::random(),
        )
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
            version: PRESENCE_VERSION,
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
            record.payload.version == PRESENCE_VERSION,
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
        let skew_ms = PRESENCE_FUTURE_SKEW.as_millis() as u64;
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
    presence_id: [u8; 16],
    last_seen_ms: u64,
    expires_at_ms: u64,
}

impl DynamicDirectoryEntry {
    /// The sanitized local-API view: no routing data ever leaves the daemon.
    fn public(&self, key: PublicKey) -> RemotePeer {
        RemotePeer {
            public_key: peer_id(key),
            alias: self
                .alias
                .as_deref()
                .map(str::parse)
                .transpose()
                .expect("validated alias"),
            // Local receipt time, never the peer-controlled signed issue time.
            last_seen_ms: self.last_seen_ms,
            // Locally bounded lease deadline.
            expires_at_ms: self.expires_at_ms,
        }
    }
}

#[derive(Debug, Clone)]
struct PresenceReplayWatermark {
    issued_ms: u64,
    presence_id: [u8; 16],
    forget_at: Instant,
}

#[derive(Debug)]
pub(crate) struct Directory {
    pinned: HashMap<PublicKey, EndpointAddr>,
    dynamic: HashMap<PublicKey, DynamicDirectoryEntry>,
    replay_watermarks: HashMap<PublicKey, PresenceReplayWatermark>,
    presence_lookup: MemoryLookup,
    /// Names this daemon lifetime's revision sequence to local subscribers.
    epoch: OperationId,
    /// Advanced once for every lifecycle event this directory produces.
    revision: u64,
}

impl Directory {
    pub(crate) fn new(presence_lookup: MemoryLookup) -> Self {
        Self {
            pinned: HashMap::new(),
            dynamic: HashMap::new(),
            replay_watermarks: HashMap::new(),
            presence_lookup,
            epoch: OperationId::new_random(),
            revision: 0,
        }
    }

    fn lifecycle_event(
        &mut self,
        kind: fn(meshmsg_protocol::PeerTransition) -> Event,
        peer: RemotePeer,
    ) -> Event {
        self.revision = self
            .revision
            .checked_add(1)
            .expect("directory revision overflow");
        kind(meshmsg_protocol::PeerTransition {
            directory_epoch: self.epoch,
            directory_revision: self.revision,
            peer,
        })
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

    /// Admits one signed record and returns the lifecycle event it causes, if
    /// any. The caller must publish that event: its revision is already taken.
    #[must_use = "the lifecycle event's revision is already taken; publish it"]
    pub(crate) fn receive(&mut self, bytes: &[u8], topic: TopicId) -> Result<Option<Event>> {
        self.receive_at(bytes, topic, unix_timestamp_ms()?, Instant::now())
    }

    fn receive_at(
        &mut self,
        bytes: &[u8],
        topic: TopicId,
        wall_ms: u64,
        monotonic_now: Instant,
    ) -> Result<Option<Event>> {
        let payload = SignedPresence::decode(bytes, topic, wall_ms)?;
        let ordering = (payload.issued_ms, payload.id);
        if self
            .dynamic
            .get(&payload.sender)
            .is_some_and(|entry| (entry.issued_ms, entry.presence_id) >= ordering)
            || self
                .replay_watermarks
                .get(&payload.sender)
                .is_some_and(|entry| (entry.issued_ms, entry.presence_id) >= ordering)
        {
            anyhow::bail!("presence record is not newer than the current record");
        }
        let already_tracked = self.dynamic.contains_key(&payload.sender)
            || self.replay_watermarks.contains_key(&payload.sender);
        anyhow::ensure!(
            already_tracked
                || self.dynamic.len() + self.replay_watermarks.len() < MAX_DYNAMIC_IDENTITIES,
            "dynamic presence identity capacity reached"
        );
        let remaining = Duration::from_millis(payload.expires_ms.saturating_sub(wall_ms))
            .min(PRESENCE_LIFETIME);
        anyhow::ensure!(!remaining.is_zero(), "presence record is expired");
        let endpoint = payload.endpoint;
        let kind: Option<fn(_) -> _> = match self.dynamic.get(&payload.sender) {
            None => Some(Event::PeerDiscovered),
            // Routing changes remain internal: only changes to public directory
            // fields produce an externally observable lifecycle event.
            Some(entry) if entry.alias != payload.alias => Some(Event::PeerUpdated),
            Some(_) => None,
        };
        let last_seen_ms = wall_ms;
        let expires_at_ms = wall_ms.saturating_add(remaining.as_millis() as u64);
        self.replay_watermarks.remove(&payload.sender);
        let entry = DynamicDirectoryEntry {
            endpoint: endpoint.clone(),
            alias: payload.alias,
            expires: monotonic_now + remaining,
            issued_ms: payload.issued_ms,
            presence_id: payload.id,
            last_seen_ms,
            expires_at_ms,
        };
        let transition = kind.map(|kind| self.lifecycle_event(kind, entry.public(payload.sender)));
        self.dynamic.insert(payload.sender, entry);
        // MemoryLookup::add_endpoint_info merges direct addresses forever. Presence
        // records are snapshots, so replace this source's record in full instead.
        self.presence_lookup.set_endpoint_info(endpoint);
        Ok(transition)
    }

    /// Expires overdue leases and returns their lifecycle events in key order.
    /// The caller must publish them: their revisions are already taken.
    #[must_use = "the lifecycle events' revisions are already taken; publish them"]
    pub(crate) fn cleanup(&mut self) -> Vec<Event> {
        self.cleanup_at(Instant::now())
    }

    fn cleanup_at(&mut self, now: Instant) -> Vec<Event> {
        self.replay_watermarks
            .retain(|_, watermark| watermark.forget_at > now);
        let mut expired: Vec<_> = self
            .dynamic
            .iter()
            .filter_map(|(key, entry)| (entry.expires <= now).then_some(*key))
            .collect();
        expired.sort_unstable_by_key(PublicKey::to_string);
        let mut transitions = Vec::with_capacity(expired.len());
        for key in expired {
            if let Some(entry) = self.dynamic.remove(&key) {
                self.presence_lookup.remove_endpoint_info(key);
                self.replay_watermarks.insert(
                    key,
                    PresenceReplayWatermark {
                        issued_ms: entry.issued_ms,
                        presence_id: entry.presence_id,
                        forget_at: now + PRESENCE_REPLAY_LIFETIME,
                    },
                );
                transitions.push(self.lifecycle_event(Event::PeerExpired, entry.public(key)));
            }
        }
        transitions
    }

    pub(crate) fn snapshot(
        &self,
        connectivity: LocalConnectivity,
        self_peer: PeerId,
        self_alias: Option<&str>,
        generated_at_ms: u64,
    ) -> PeerSnapshot {
        let now = Instant::now();
        // Never depend on Gossip loopback behavior. Self has one explicit,
        // authoritative object and is excluded from the remote lease array.
        let mut peers: Vec<RemotePeer> = self
            .dynamic
            .iter()
            .filter(|(_, entry)| entry.expires > now)
            .map(|(key, entry)| entry.public(*key))
            .filter(|peer| peer.public_key != self_peer)
            .collect();
        peers.sort_unstable_by_key(|peer| peer.public_key);
        PeerSnapshot {
            generated_at_ms,
            directory_epoch: self.epoch,
            directory_revision: self.revision,
            self_peer: meshmsg_protocol::SelfPeer {
                public_key: self_peer,
                alias: self_alias
                    .map(str::parse)
                    .transpose()
                    .expect("validated alias"),
                online: connectivity.peer_online(),
            },
            peers,
        }
    }

    pub(crate) fn resolve(&mut self, recipient: &str) -> Result<EndpointAddr> {
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
            if now.duration_since(window.started) >= SOURCE_WINDOW {
                *window = PresenceSourceWindow {
                    started: now,
                    accepted: 1,
                };
                return true;
            }
            if window.accepted >= MAX_RECORDS_PER_SOURCE {
                return false;
            }
            window.accepted += 1;
            return true;
        }
        if self.sources.len() >= MAX_TRANSPORT_SOURCES {
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
            .retain(|_, window| now.duration_since(window.started) < SOURCE_WINDOW);
    }
}

fn encode_presence(
    secret: &SecretKey,
    topic: TopicId,
    alias: Option<&str>,
    endpoint: EndpointAddr,
) -> Result<Bytes> {
    SignedPresence::encode(secret, topic, alias, endpoint)
}

pub(crate) async fn announce(
    sender: &GossipSender,
    secret: &SecretKey,
    topic: TopicId,
    alias: Option<&str>,
    endpoint: EndpointAddr,
) {
    if let Ok(record) = encode_presence(secret, topic, alias, endpoint) {
        let _ = sender.broadcast(record).await;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LocalConnectivity {
    pub(crate) endpoint_online: bool,
    pub(crate) topic_joined: bool,
}

impl LocalConnectivity {
    fn peer_online(self) -> bool {
        self.endpoint_online && self.topic_joined
    }
}

pub(crate) fn local_connectivity(
    endpoint: &Endpoint,
    receiver: &GossipReceiver,
) -> LocalConnectivity {
    LocalConnectivity {
        endpoint_online: endpoint
            .home_relay_status()
            .get()
            .iter()
            .any(|status| status.is_connected()),
        topic_joined: receiver.is_joined(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(secret: &SecretKey, port: u16) -> EndpointAddr {
        EndpointAddr::new(secret.public()).with_ip_addr(([127, 0, 0, 1], port).into())
    }

    fn snapshot(directory: &Directory, self_peer: PeerId) -> PeerSnapshot {
        directory.snapshot(
            LocalConnectivity {
                endpoint_online: false,
                topic_joined: false,
            },
            self_peer,
            None,
            0,
        )
    }

    fn snapshot_frame_value(snapshot: PeerSnapshot) -> serde_json::Value {
        serde_json::to_value(meshmsg_protocol::ResponseFrame::new(
            Some(meshmsg_protocol::RequestId::new_random()),
            meshmsg_protocol::Response::PeersSnapshot(snapshot),
        ))
        .unwrap()
    }

    fn event_frame_value(event: Event) -> serde_json::Value {
        serde_json::to_value(meshmsg_protocol::EventFrame::new(
            meshmsg_protocol::RequestId::new_random(),
            event,
        ))
        .unwrap()
    }

    #[test]
    fn presence_is_signed_topic_bound_and_bounded() {
        let secret = SecretKey::generate();
        let topic = TopicId::from_bytes([7; 32]);
        let bytes = SignedPresence::encode(&secret, topic, Some("node-1"), endpoint(&secret, 7777))
            .unwrap();
        let decoded = SignedPresence::decode(&bytes, topic, unix_timestamp_ms().unwrap()).unwrap();
        assert_eq!(decoded.sender, secret.public());
        assert_eq!(decoded.alias.as_deref(), Some("node-1"));
        assert!(SignedPresence::decode(
            &bytes,
            TopicId::from_bytes([8; 32]),
            unix_timestamp_ms().unwrap()
        )
        .is_err());
        let mut tampered = bytes.to_vec();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(SignedPresence::decode(&tampered, topic, unix_timestamp_ms().unwrap()).is_err());

        let mut directory = Directory::new(MemoryLookup::new());
        directory.receive(&bytes, topic).unwrap();
        assert!(directory.receive(&bytes, topic).is_err());
    }

    #[test]
    fn presence_order_is_total_and_future_skew_is_tightly_bounded() {
        let secret = SecretKey::generate();
        let topic = TopicId::from_bytes([12; 32]);
        let wall = unix_timestamp_ms().unwrap();
        let monotonic = Instant::now();
        let mut directory = Directory::new(MemoryLookup::new());

        let first = SignedPresence::encode_at(
            &secret,
            topic,
            None,
            endpoint(&secret, 8_001),
            wall,
            [2; 16],
        )
        .unwrap();
        directory
            .receive_at(&first, topic, wall, monotonic)
            .unwrap();

        let lower_id = SignedPresence::encode_at(
            &secret,
            topic,
            None,
            endpoint(&secret, 8_002),
            wall,
            [1; 16],
        )
        .unwrap();
        assert!(directory
            .receive_at(&lower_id, topic, wall, monotonic)
            .is_err());

        let higher_id = SignedPresence::encode_at(
            &secret,
            topic,
            None,
            endpoint(&secret, 8_003),
            wall,
            [3; 16],
        )
        .unwrap();
        assert!(directory
            .receive_at(&higher_id, topic, wall, monotonic)
            .unwrap()
            .is_none());
        assert_eq!(
            directory.resolve(&secret.public().to_string()).unwrap(),
            endpoint(&secret, 8_003)
        );

        let at_limit = SignedPresence::encode_at(
            &secret,
            topic,
            None,
            endpoint(&secret, 8_004),
            wall + PRESENCE_FUTURE_SKEW.as_millis() as u64,
            [4; 16],
        )
        .unwrap();
        SignedPresence::decode(&at_limit, topic, wall).unwrap();
        let beyond_limit = SignedPresence::encode_at(
            &secret,
            topic,
            None,
            endpoint(&secret, 8_005),
            wall + PRESENCE_FUTURE_SKEW.as_millis() as u64 + 1,
            [5; 16],
        )
        .unwrap();
        assert!(SignedPresence::decode(&beyond_limit, topic, wall).is_err());
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
        let wall = unix_timestamp_ms().unwrap();
        let monotonic = Instant::now();
        let lookup = MemoryLookup::new();
        let mut directory = Directory::new(lookup.clone());
        let mut admitted = Vec::new();

        for index in 0..MAX_DYNAMIC_IDENTITIES {
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

        assert_eq!(directory.dynamic.len(), MAX_DYNAMIC_IDENTITIES);
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
        let wall = unix_timestamp_ms().unwrap();
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
        let wall = unix_timestamp_ms().unwrap();
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
    fn directory_transitions_coalesce_refresh_update_expire_and_rediscover() {
        let secret = SecretKey::generate();
        let topic = TopicId::from_bytes([11; 32]);
        let wall = unix_timestamp_ms().unwrap();
        let monotonic = Instant::now();
        let first_endpoint = endpoint(&secret, 41_001);

        let first = SignedPresence::encode_at(
            &secret,
            topic,
            Some("first"),
            first_endpoint.clone(),
            wall,
            [1; 16],
        )
        .unwrap();
        let mut directory = Directory::new(MemoryLookup::new());
        let discovered = directory
            .receive_at(&first, topic, wall, monotonic)
            .unwrap()
            .unwrap();
        let Event::PeerDiscovered(discovered) = discovered else {
            panic!("expected a discovery, got {discovered:?}")
        };
        assert_eq!(discovered.peer.alias, Some("first".parse().unwrap()));
        assert_eq!(discovered.directory_revision, 1);

        let refresh = SignedPresence::encode_at(
            &secret,
            topic,
            Some("first"),
            first_endpoint,
            wall + 1,
            [2; 16],
        )
        .unwrap();
        assert!(directory
            .receive_at(
                &refresh,
                topic,
                wall + 1_000,
                monotonic + Duration::from_millis(1_000),
            )
            .unwrap()
            .is_none());
        let refreshed = snapshot(&directory, PeerId::from_bytes([0; 32]))
            .peers
            .pop()
            .unwrap();
        assert_eq!(refreshed.last_seen_ms, wall + 1_000);
        assert!(refreshed.expires_at_ms - refreshed.last_seen_ms <= PEER_LEASE_MS);

        let alias_update = SignedPresence::encode_at(
            &secret,
            topic,
            Some("renamed"),
            endpoint(&secret, 41_001),
            wall + 2,
            [3; 16],
        )
        .unwrap();
        let updated = directory
            .receive_at(
                &alias_update,
                topic,
                wall + 1_001,
                monotonic + Duration::from_millis(1_001),
            )
            .unwrap()
            .unwrap();
        let Event::PeerUpdated(updated) = updated else {
            panic!("expected an update, got {updated:?}")
        };
        assert_eq!(updated.peer.alias, Some("renamed".parse().unwrap()));
        assert_eq!(updated.directory_revision, 2);

        let route_update = SignedPresence::encode_at(
            &secret,
            topic,
            Some("renamed"),
            endpoint(&secret, 41_002),
            wall + 3,
            [4; 16],
        )
        .unwrap();
        assert!(directory
            .receive_at(
                &route_update,
                topic,
                wall + 1_002,
                monotonic + Duration::from_millis(1_002),
            )
            .unwrap()
            .is_none());
        assert_eq!(
            directory.resolve("renamed").unwrap(),
            endpoint(&secret, 41_002)
        );

        let after_expiry = monotonic + PRESENCE_LIFETIME + Duration::from_secs(2);
        let expired = directory.cleanup_at(after_expiry);
        assert_eq!(expired.len(), 1);
        let Event::PeerExpired(expiry) = &expired[0] else {
            panic!("expected an expiry, got {expired:?}")
        };
        assert_eq!(expiry.directory_epoch, discovered.directory_epoch);
        assert_eq!(expiry.directory_revision, 3);
        assert!(directory.cleanup_at(after_expiry).is_empty());

        let rediscovery_wall = wall + PEER_LEASE_MS + 3_000;
        let rediscovery = SignedPresence::encode_at(
            &secret,
            topic,
            Some("renamed"),
            endpoint(&secret, 41_003),
            rediscovery_wall,
            [5; 16],
        )
        .unwrap();
        let rediscovered = directory
            .receive_at(&rediscovery, topic, rediscovery_wall, after_expiry)
            .unwrap()
            .unwrap();
        assert!(matches!(rediscovered, Event::PeerDiscovered(_)));
        assert_eq!(
            snapshot(&directory, PeerId::from_bytes([0; 32])).directory_revision,
            4
        );
    }

    #[test]
    fn snapshot_is_sorted_with_one_separate_authoritative_self() {
        let topic = TopicId::from_bytes([13; 32]);
        let wall = unix_timestamp_ms().unwrap();
        let monotonic = Instant::now();
        let mut directory = Directory::new(MemoryLookup::new());
        let local = SecretKey::generate();
        let mut remotes = Vec::new();
        // The local record models Gossip loopback; it must not become a remote.
        for (index, (secret, alias)) in [
            (SecretKey::generate(), None),
            (local.clone(), Some("loopback")),
            (SecretKey::generate(), Some("one")),
            (SecretKey::generate(), None),
        ]
        .into_iter()
        .enumerate()
        {
            let bytes = SignedPresence::encode_at(
                &secret,
                topic,
                alias,
                endpoint(&secret, 42_000 + index as u16),
                wall,
                [index as u8; 16],
            )
            .unwrap();
            directory
                .receive_at(&bytes, topic, wall, monotonic)
                .unwrap();
            if secret.public() != local.public() {
                remotes.push(secret.public().to_string());
            }
        }
        remotes.sort_unstable();

        let value = snapshot_frame_value(directory.snapshot(
            LocalConnectivity {
                endpoint_online: true,
                topic_joined: true,
            },
            peer_id(local.public()),
            Some("local"),
            wall,
        ));
        assert_eq!(value["type"], "peers_snapshot");
        assert_eq!(value["protocol_version"], 5);
        assert!(value["request_id"].as_str().is_some());
        assert_eq!(value["directory_epoch"], directory.epoch.to_string());
        assert_eq!(value["directory_revision"], 4);
        assert_eq!(value["self"]["public_key"], local.public().to_string());
        assert_eq!(value["self"]["alias"], "local");
        assert_eq!(value["self"]["online"], true);
        assert_eq!(
            value["peers"]
                .as_array()
                .unwrap()
                .iter()
                .map(|entry| entry["public_key"].as_str().unwrap())
                .collect::<Vec<_>>(),
            remotes
        );
    }

    #[test]
    fn maximum_complete_snapshot_fits_the_bounded_ipc_frame() {
        let topic = TopicId::from_bytes([14; 32]);
        let wall = unix_timestamp_ms().unwrap();
        let monotonic = Instant::now();
        let mut directory = Directory::new(MemoryLookup::new());
        let alias = "a".repeat(crate::alias::MAX_ALIAS_BYTES);
        for index in 0..MAX_DYNAMIC_IDENTITIES {
            let secret = SecretKey::generate();
            let bytes = SignedPresence::encode_at(
                &secret,
                topic,
                Some(&alias),
                endpoint(&secret, 10_000 + index as u16),
                wall,
                [index as u8; 16],
            )
            .unwrap();
            directory
                .receive_at(&bytes, topic, wall, monotonic)
                .unwrap();
        }
        let snapshot = directory.snapshot(
            LocalConnectivity {
                endpoint_online: true,
                topic_joined: true,
            },
            PeerId::from_bytes([0xff; 32]),
            Some("self"),
            wall,
        );
        assert_eq!(snapshot.peers.len(), MAX_DYNAMIC_IDENTITIES);
        let frame = meshmsg_protocol::ResponseFrame::new(
            Some(meshmsg_protocol::RequestId::new_random()),
            meshmsg_protocol::Response::PeersSnapshot(snapshot),
        );
        assert!(
            serde_json::to_vec(&frame).unwrap().len() <= crate::ipc::MAX_IPC_EVENT_SIZE,
            "maximum canonical peer snapshot response exceeds IPC frame"
        );
    }

    #[test]
    fn maximum_lifecycle_event_has_a_small_fixed_bound() {
        let mut directory = Directory::new(MemoryLookup::new());
        directory.revision = u64::MAX - 1;
        let value = event_frame_value(directory.lifecycle_event(
            Event::PeerExpired,
            RemotePeer {
                public_key: PeerId::from_bytes([0xff; 32]),
                alias: Some("a".repeat(crate::alias::MAX_ALIAS_BYTES).parse().unwrap()),
                last_seen_ms: u64::MAX,
                expires_at_ms: u64::MAX,
            },
        ));
        assert_eq!(value["directory_revision"], u64::MAX);
        assert!(serde_json::to_vec(&value).unwrap().len() <= MAX_PEER_LIFECYCLE_EVENT_BYTES);
        assert!(value.get("body").is_none());
    }

    #[test]
    fn wire_objects_have_only_the_documented_sanitized_fields() {
        let secret = SecretKey::generate();
        let topic = TopicId::from_bytes([15; 32]);
        let mut directory = Directory::new(MemoryLookup::new());
        let bytes =
            SignedPresence::encode(&secret, topic, None, endpoint(&secret, 43_001)).unwrap();
        let discovered = directory.receive(&bytes, topic).unwrap().unwrap();
        let discovered = event_frame_value(discovered);
        assert_eq!(discovered["type"], "peer_discovered");
        assert_eq!(discovered["protocol_version"], 5);
        assert!(discovered["request_id"].as_str().is_some());
        assert_eq!(discovered["directory_epoch"], directory.epoch.to_string());
        assert_eq!(discovered["directory_revision"], 1);
        assert_eq!(
            discovered["peer"]["public_key"],
            secret.public().to_string()
        );
        assert_eq!(discovered["peer"]["alias"], serde_json::Value::Null);
        let encoded = discovered.to_string();
        for forbidden in [
            "endpoint",
            "address",
            "relay",
            "socket",
            "record",
            "signature",
            "body",
        ] {
            assert!(!encoded.contains(forbidden), "leaked {forbidden}");
        }
    }

    #[test]
    fn presence_rate_limit_uses_bounded_transport_sources() {
        let source = SecretKey::generate().public();
        let start = Instant::now();
        let mut limiter = PresenceSourceLimiter::default();
        for _ in 0..MAX_RECORDS_PER_SOURCE {
            assert!(limiter.allow_at(source, start));
        }
        assert!(!limiter.allow_at(source, start));

        for _ in 1..MAX_TRANSPORT_SOURCES {
            assert!(limiter.allow_at(SecretKey::generate().public(), start));
        }
        assert!(!limiter.allow_at(SecretKey::generate().public(), start));
        assert!(limiter.allow_at(source, start + SOURCE_WINDOW));
        assert_eq!(limiter.sources.len(), 1);
    }
}
