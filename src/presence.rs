use crate::{
    alias::{normalize_alias, validate_alias},
    peers::{self as peer_api, PeerTransition, PeerTransitionKind, RemotePeer, PEER_LEASE_MS},
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
use serde::{Deserialize, Serialize};
use serde_byte_array::ByteArray;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    str::FromStr,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::broadcast;

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
    fn encode(
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
    fn public(&self, key: PublicKey, online: bool) -> RemotePeer {
        RemotePeer {
            public_key: key.to_string(),
            alias: self.alias.clone(),
            online,
            last_seen_ms: self.last_seen_ms,
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

    pub(crate) fn receive(
        &mut self,
        bytes: &[u8],
        topic: TopicId,
    ) -> Result<Option<PeerTransition>> {
        self.receive_at(bytes, topic, now_ms()?, Instant::now())
    }

    fn receive_at(
        &mut self,
        bytes: &[u8],
        topic: TopicId,
        wall_ms: u64,
        monotonic_now: Instant,
    ) -> Result<Option<PeerTransition>> {
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
                || self.dynamic.len() + self.replay_watermarks.len()
                    < peer_api::MAX_DYNAMIC_IDENTITIES,
            "dynamic presence identity capacity reached"
        );
        let remaining = Duration::from_millis(payload.expires_ms.saturating_sub(wall_ms))
            .min(PRESENCE_LIFETIME);
        anyhow::ensure!(!remaining.is_zero(), "presence record is expired");
        let endpoint = payload.endpoint;
        let kind = match self.dynamic.get(&payload.sender) {
            None => Some(PeerTransitionKind::Discovered),
            // Routing changes remain internal: only changes to public directory
            // fields produce an externally observable lifecycle event.
            Some(entry) if entry.alias != payload.alias => Some(PeerTransitionKind::Updated),
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
        let transition = kind.map(|kind| PeerTransition {
            kind,
            peer: entry.public(payload.sender, true),
        });
        self.dynamic.insert(payload.sender, entry);
        // MemoryLookup::add_endpoint_info merges direct addresses forever. Presence
        // records are snapshots, so replace this source's record in full instead.
        self.presence_lookup.set_endpoint_info(endpoint);
        Ok(transition)
    }

    pub(crate) fn cleanup(&mut self) -> Vec<PeerTransition> {
        self.cleanup_at(Instant::now())
    }

    fn cleanup_at(&mut self, now: Instant) -> Vec<PeerTransition> {
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
                transitions.push(PeerTransition {
                    kind: PeerTransitionKind::Expired,
                    peer: entry.public(key, false),
                });
            }
        }
        transitions
    }

    pub(crate) fn peers(&self) -> Vec<RemotePeer> {
        let now = Instant::now();
        self.dynamic
            .iter()
            .filter(|(_, entry)| entry.expires > now)
            .map(|(key, entry)| entry.public(*key, true))
            .collect()
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

fn local_peer_online(endpoint: &Endpoint, receiver: &GossipReceiver) -> bool {
    endpoint
        .home_relay_status()
        .get()
        .iter()
        .any(|status| status.is_connected())
        && receiver.is_joined()
}

pub(crate) fn snapshot(
    local_network: (&Endpoint, &GossipReceiver),
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
        local_peer_online(local_network.0, local_network.1),
        generated_at_ms,
        directory_epoch,
        directory_revision,
        directory.peers(),
    )
}

pub(crate) fn emit_transitions(
    transitions: impl IntoIterator<Item = PeerTransition>,
    events: &broadcast::Sender<serde_json::Value>,
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
            .is_ok_and(|encoded| encoded.len() <= peer_api::MAX_PEER_LIFECYCLE_EVENT_BYTES)
        {
            *directory_revision = candidate_revision;
            let _ = events.send(value.clone());
        }
    }
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
    fn presence_order_is_total_and_future_skew_is_tightly_bounded() {
        let secret = SecretKey::generate();
        let topic = TopicId::from_bytes([12; 32]);
        let wall = now_ms().unwrap();
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
        let wall = now_ms().unwrap();
        let monotonic = Instant::now();
        let lookup = MemoryLookup::new();
        let mut directory = Directory::new(lookup.clone());
        let mut admitted = Vec::new();

        for index in 0..peer_api::MAX_DYNAMIC_IDENTITIES {
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

        assert_eq!(directory.dynamic.len(), peer_api::MAX_DYNAMIC_IDENTITIES);
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
    fn directory_transitions_coalesce_refresh_update_expire_and_rediscover() {
        let secret = SecretKey::generate();
        let topic = TopicId::from_bytes([11; 32]);
        let wall = now_ms().unwrap();
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
        assert_eq!(discovered.kind, PeerTransitionKind::Discovered);
        assert_eq!(discovered.peer.alias.as_deref(), Some("first"));

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
        let refreshed = directory.peers().pop().unwrap();
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
        assert_eq!(updated.kind, PeerTransitionKind::Updated);
        assert_eq!(updated.peer.alias.as_deref(), Some("renamed"));

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
        assert_eq!(expired[0].kind, PeerTransitionKind::Expired);
        assert!(!expired[0].peer.online);
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
        assert_eq!(rediscovered.kind, PeerTransitionKind::Discovered);
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
