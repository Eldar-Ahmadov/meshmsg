use anyhow::{Context, Result};
use iroh::PublicKey;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

/// Maximum lifetime of a signed remote presence lease. Snapshot expiry is
/// locally derived and never extends beyond this bound.
pub(crate) const PEER_LEASE_MS: u64 = 150_000;
pub(crate) const PEER_DIRECTORY_CAPABILITY: &str = "peer_directory_v2";
pub(crate) const PEER_SCHEMA_VERSION: u8 = 2;
pub(crate) const MAX_PEER_LIFECYCLE_EVENT_BYTES: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RemotePeer {
    /// Canonical Iroh public-key encoding.
    pub(crate) public_key: String,
    /// Always serialized; null means the peer did not advertise an alias.
    pub(crate) alias: Option<String>,
    /// True exactly while the authenticated presence lease is current. This is
    /// not a reachability probe and is independent of Gossip neighbor state.
    pub(crate) online: bool,
    /// Local receipt time, never the peer-controlled signed issue time.
    pub(crate) last_seen_ms: u64,
    /// Locally bounded lease deadline.
    pub(crate) expires_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct SelfPeer<'a> {
    public_key: &'a str,
    alias: Option<&'a str>,
    online: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PeerTransitionKind {
    Discovered,
    Updated,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PeerTransition {
    pub(crate) kind: PeerTransitionKind,
    pub(crate) peer: RemotePeer,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnedSelfPeer {
    public_key: String,
    alias: Option<String>,
    online: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotV2 {
    #[serde(rename = "type")]
    kind: String,
    schema_version: u8,
    request_id: String,
    generated_at_ms: u64,
    directory_epoch: String,
    directory_revision: u64,
    #[serde(rename = "self")]
    self_peer: OwnedSelfPeer,
    peers: Vec<RemotePeer>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransitionV2 {
    #[serde(rename = "type")]
    kind: String,
    schema_version: u8,
    request_id: String,
    directory_epoch: String,
    directory_revision: u64,
    peer: RemotePeer,
}

fn valid_epoch(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_remote_identity(peer: &RemotePeer) -> Result<()> {
    let key = PublicKey::from_str(&peer.public_key).context("invalid remote peer key")?;
    anyhow::ensure!(
        key.to_string() == peer.public_key,
        "noncanonical remote peer key"
    );
    if let Some(alias) = &peer.alias {
        crate::alias::validate_alias(alias)?;
    }
    anyhow::ensure!(
        peer.expires_at_ms >= peer.last_seen_ms
            && peer.expires_at_ms.saturating_sub(peer.last_seen_ms) <= PEER_LEASE_MS,
        "invalid remote peer lease"
    );
    Ok(())
}

pub(crate) fn validate_transition(value: &serde_json::Value, expected: &str) -> Result<()> {
    let transition: TransitionV2 = serde_json::from_value(value.clone())
        .context("daemon returned malformed peer transition")?;
    anyhow::ensure!(
        transition.kind == expected
            && transition.schema_version == PEER_SCHEMA_VERSION
            && matches!(
                expected,
                "peer_discovered" | "peer_updated" | "peer_expired"
            ),
        "unsupported peer transition"
    );
    anyhow::ensure!(
        crate::contracts::valid_request_id(&transition.request_id)
            && valid_epoch(&transition.directory_epoch),
        "invalid peer transition envelope"
    );
    validate_remote_identity(&transition.peer)?;
    anyhow::ensure!(
        transition.peer.online == (expected != "peer_expired"),
        "invalid peer transition online state"
    );
    let _ = transition.directory_revision;
    Ok(())
}

pub(crate) fn validate_snapshot(value: &serde_json::Value) -> Result<()> {
    let snapshot: SnapshotV2 =
        serde_json::from_value(value.clone()).context("daemon returned malformed peer snapshot")?;
    anyhow::ensure!(
        snapshot.kind == "peers_snapshot" && snapshot.schema_version == PEER_SCHEMA_VERSION,
        "unsupported peer snapshot"
    );
    anyhow::ensure!(
        crate::contracts::valid_request_id(&snapshot.request_id),
        "peer snapshot request ID is invalid"
    );
    anyhow::ensure!(
        valid_epoch(&snapshot.directory_epoch),
        "peer directory epoch is invalid"
    );
    let self_key =
        PublicKey::from_str(&snapshot.self_peer.public_key).context("invalid self peer key")?;
    anyhow::ensure!(
        self_key.to_string() == snapshot.self_peer.public_key,
        "noncanonical self peer key"
    );
    if let Some(alias) = &snapshot.self_peer.alias {
        crate::alias::validate_alias(alias)?;
    }
    anyhow::ensure!(
        snapshot.peers.len() <= crate::direct::MAX_DYNAMIC_PRESENCE_IDENTITIES,
        "peer snapshot is too large"
    );
    let mut previous: Option<&str> = None;
    for peer in &snapshot.peers {
        validate_remote_identity(peer)?;
        anyhow::ensure!(
            peer.public_key != snapshot.self_peer.public_key,
            "invalid remote peer identity"
        );
        anyhow::ensure!(
            previous.is_none_or(|old| old < peer.public_key.as_str()),
            "peer snapshot is unsorted or duplicated"
        );
        if let Some(alias) = &peer.alias {
            crate::alias::validate_alias(alias)?;
        }
        anyhow::ensure!(
            peer.online
                && peer.last_seen_ms <= snapshot.generated_at_ms
                && peer.expires_at_ms >= snapshot.generated_at_ms
                && peer.expires_at_ms.saturating_sub(peer.last_seen_ms) <= PEER_LEASE_MS,
            "invalid remote peer lease"
        );
        previous = Some(&peer.public_key);
    }
    let _ = (snapshot.directory_revision, snapshot.self_peer.online);
    Ok(())
}

pub(crate) fn snapshot_value(
    self_peer: &str,
    self_alias: Option<&str>,
    self_online: bool,
    generated_at_ms: u64,
    directory_epoch: &str,
    directory_revision: u64,
    mut remotes: Vec<RemotePeer>,
) -> serde_json::Value {
    // Never depend on Gossip loopback behavior. Self has one explicit,
    // authoritative object and is excluded from the remote lease array.
    remotes.retain(|entry| entry.public_key != self_peer);
    remotes.sort_unstable_by(|left, right| left.public_key.cmp(&right.public_key));
    serde_json::json!({
        "type":"peers_snapshot", "schema_version":PEER_SCHEMA_VERSION,
        "generated_at_ms":generated_at_ms,
        "directory_epoch":directory_epoch, "directory_revision":directory_revision,
        "self":SelfPeer { public_key:self_peer, alias:self_alias, online:self_online },
        "peers":remotes
    })
}

pub(crate) fn transition_value(
    transition: PeerTransition,
    directory_epoch: &str,
    directory_revision: u64,
) -> serde_json::Value {
    let event_type = match transition.kind {
        PeerTransitionKind::Discovered => "peer_discovered",
        PeerTransitionKind::Updated => "peer_updated",
        PeerTransitionKind::Expired => "peer_expired",
    };
    serde_json::json!({
        "type":event_type, "schema_version":PEER_SCHEMA_VERSION,
        "directory_epoch":directory_epoch, "directory_revision":directory_revision,
        "peer":transition.peer
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn remote(public_key: &str, alias: Option<&str>) -> RemotePeer {
        RemotePeer {
            public_key: public_key.into(),
            alias: alias.map(str::to_owned),
            online: true,
            last_seen_ms: 100,
            expires_at_ms: 200,
        }
    }

    #[test]
    fn snapshot_is_sorted_with_one_separate_authoritative_self() {
        let value = snapshot_value(
            "b",
            Some("local"),
            true,
            1_000,
            "epoch",
            0,
            vec![
                remote("c", None),
                remote("b", Some("loopback")),
                remote("a", Some("one")),
            ],
        );
        assert_eq!(value["type"], "peers_snapshot");
        assert_eq!(value["schema_version"], 2);
        assert_eq!(value["self"]["public_key"], "b");
        assert_eq!(value["self"]["alias"], "local");
        assert_eq!(value["self"]["online"], true);
        let entries = value["peers"].as_array().unwrap();
        assert_eq!(
            entries
                .iter()
                .map(|entry| entry["public_key"].as_str().unwrap())
                .collect::<Vec<_>>(),
            ["a", "c"]
        );
    }

    #[test]
    fn maximum_complete_snapshot_fits_the_bounded_ipc_frame() {
        let peers = (0..crate::direct::MAX_DYNAMIC_PRESENCE_IDENTITIES)
            .map(|index| RemotePeer {
                public_key: format!("{index:064x}"),
                alias: Some("a".repeat(crate::alias::MAX_ALIAS_BYTES)),
                online: true,
                last_seen_ms: 1_000,
                expires_at_ms: 1_000 + PEER_LEASE_MS,
            })
            .collect();
        let snapshot = snapshot_value(
            &"f".repeat(64),
            Some("self"),
            true,
            1_000,
            "epoch",
            0,
            peers,
        );
        assert!(
            serde_json::to_vec(&snapshot).unwrap().len() <= crate::ipc::MAX_IPC_EVENT_SIZE,
            "maximum complete peer snapshot exceeds IPC frame"
        );
    }

    #[test]
    fn snapshot_dto_rejects_unknown_missing_wrong_version_and_semantics() {
        let self_peer = iroh::SecretKey::generate().public().to_string();
        let remote_peer = iroh::SecretKey::generate().public().to_string();
        let value = crate::contracts::correlate(
            snapshot_value(
                &self_peer,
                Some("self-node"),
                true,
                150,
                "11111111111111111111111111111111",
                1,
                vec![RemotePeer {
                    public_key: remote_peer,
                    alias: Some("remote-node".into()),
                    online: true,
                    last_seen_ms: 100,
                    expires_at_ms: 200,
                }],
            ),
            "22222222222222222222222222222222",
        );
        validate_snapshot(&value).unwrap();
        for malformed in [
            {
                let mut v = value.clone();
                v["extra"] = true.into();
                v
            },
            {
                let mut v = value.clone();
                v.as_object_mut().unwrap().remove("generated_at_ms");
                v
            },
            {
                let mut v = value.clone();
                v["schema_version"] = 3.into();
                v
            },
            {
                let mut v = value.clone();
                v["peers"][0]["online"] = false.into();
                v
            },
            {
                let mut v = value.clone();
                v["peers"][0]["expires_at_ms"] = 99.into();
                v
            },
        ] {
            assert!(validate_snapshot(&malformed).is_err());
        }
    }

    #[test]
    fn transition_dto_rejects_unknown_missing_wrong_version_and_semantics() {
        let peer = RemotePeer {
            public_key: iroh::SecretKey::generate().public().to_string(),
            alias: Some("remote".into()),
            online: true,
            last_seen_ms: 100,
            expires_at_ms: 200,
        };
        let value = crate::contracts::correlate(
            transition_value(
                PeerTransition {
                    kind: PeerTransitionKind::Discovered,
                    peer,
                },
                "11111111111111111111111111111111",
                1,
            ),
            "22222222222222222222222222222222",
        );
        validate_transition(&value, "peer_discovered").unwrap();
        for malformed in [
            {
                let mut v = value.clone();
                v["extra"] = true.into();
                v
            },
            {
                let mut v = value.clone();
                v.as_object_mut().unwrap().remove("request_id");
                v
            },
            {
                let mut v = value.clone();
                v["schema_version"] = 3.into();
                v
            },
            {
                let mut v = value.clone();
                v["peer"]["online"] = false.into();
                v
            },
            {
                let mut v = value.clone();
                v["peer"]["alias"] = "bad\talias".into();
                v
            },
        ] {
            assert!(validate_transition(&malformed, "peer_discovered").is_err());
        }
    }

    #[test]
    fn maximum_lifecycle_event_has_a_small_fixed_bound() {
        let value = transition_value(
            PeerTransition {
                kind: PeerTransitionKind::Expired,
                peer: RemotePeer {
                    public_key: "f".repeat(64),
                    alias: Some("a".repeat(crate::alias::MAX_ALIAS_BYTES)),
                    online: false,
                    last_seen_ms: u64::MAX,
                    expires_at_ms: u64::MAX,
                },
            },
            "epoch",
            1,
        );
        assert!(serde_json::to_vec(&value).unwrap().len() <= MAX_PEER_LIFECYCLE_EVENT_BYTES);
        assert!(value.get("body").is_none());
    }

    #[test]
    fn wire_objects_have_only_the_documented_sanitized_fields() {
        let discovered = transition_value(
            PeerTransition {
                kind: PeerTransitionKind::Discovered,
                peer: remote("canonical-key", None),
            },
            "epoch",
            1,
        );
        assert_eq!(
            discovered,
            serde_json::json!({
                "type":"peer_discovered", "schema_version":2,
                "directory_epoch":"epoch", "directory_revision":1,
                "peer":{
                    "public_key":"canonical-key", "alias":null, "online":true,
                    "last_seen_ms":100, "expires_at_ms":200
                }
            })
        );
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
}
