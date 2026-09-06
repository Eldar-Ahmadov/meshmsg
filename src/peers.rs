use serde::Serialize;

/// Maximum lifetime of a signed remote presence lease. Snapshot expiry is
/// locally derived and never extends beyond this bound.
pub(crate) const PEER_LEASE_MS: u64 = 150_000;
pub(crate) const PEER_DIRECTORY_CAPABILITY: &str = "peer_directory_v2";
pub(crate) const PEER_SCHEMA_VERSION: u8 = 2;
pub(crate) const MAX_PEER_LIFECYCLE_EVENT_BYTES: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
