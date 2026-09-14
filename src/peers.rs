use serde::{Deserialize, Serialize};

/// Maximum lifetime of a signed remote presence lease. Snapshot expiry is
/// locally derived and never extends beyond this bound.
pub(crate) const PEER_LEASE_MS: u64 = meshmsg_protocol::PEER_LEASE_MS;
pub(crate) const MAX_PEER_LIFECYCLE_EVENT_BYTES: usize = 512;
pub(crate) const MAX_DYNAMIC_IDENTITIES: usize = meshmsg_protocol::MAX_PEERS;

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
) -> meshmsg_protocol::PeerSnapshot {
    // Never depend on Gossip loopback behavior. Self has one explicit,
    // authoritative object and is excluded from the remote lease array.
    remotes.retain(|entry| entry.public_key != self_peer);
    remotes.sort_unstable_by(|left, right| left.public_key.cmp(&right.public_key));
    meshmsg_protocol::PeerSnapshot {
        generated_at_ms,
        directory_epoch: directory_epoch
            .parse()
            .expect("directory epoch is canonical"),
        directory_revision,
        self_peer: meshmsg_protocol::SelfPeer {
            public_key: self_peer.parse().expect("public key is canonical"),
            alias: self_alias
                .map(str::parse)
                .transpose()
                .expect("validated alias"),
            online: self_online,
        },
        peers: remotes.into_iter().map(protocol_remote).collect(),
    }
}

pub(crate) fn transition_value(
    transition: PeerTransition,
    directory_epoch: &str,
    directory_revision: u64,
) -> meshmsg_protocol::Event {
    let value = meshmsg_protocol::PeerTransition {
        directory_epoch: directory_epoch
            .parse()
            .expect("directory epoch is canonical"),
        directory_revision,
        peer: protocol_remote(transition.peer),
    };
    match transition.kind {
        PeerTransitionKind::Discovered => meshmsg_protocol::Event::PeerDiscovered(value),
        PeerTransitionKind::Updated => meshmsg_protocol::Event::PeerUpdated(value),
        PeerTransitionKind::Expired => meshmsg_protocol::Event::PeerExpired(value),
    }
}

fn protocol_remote(peer: RemotePeer) -> meshmsg_protocol::RemotePeer {
    meshmsg_protocol::RemotePeer {
        public_key: peer.public_key.parse().expect("public key is canonical"),
        alias: peer
            .alias
            .map(|alias| alias.parse())
            .transpose()
            .expect("validated alias"),
        online: peer.online,
        last_seen_ms: peer.last_seen_ms,
        expires_at_ms: peer.expires_at_ms,
    }
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
            expires_at_ms: 1_100,
        }
    }

    fn snapshot_frame_value(snapshot: meshmsg_protocol::PeerSnapshot) -> serde_json::Value {
        serde_json::to_value(meshmsg_protocol::ResponseFrame::new(
            Some(meshmsg_protocol::RequestId::new_random()),
            meshmsg_protocol::Response::PeersSnapshot(snapshot),
        ))
        .unwrap()
    }

    fn event_frame_value(event: meshmsg_protocol::Event) -> serde_json::Value {
        serde_json::to_value(meshmsg_protocol::EventFrame::new(
            meshmsg_protocol::RequestId::new_random(),
            event,
        ))
        .unwrap()
    }

    #[test]
    fn snapshot_is_sorted_with_one_separate_authoritative_self() {
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        let c = "c".repeat(64);
        let value = snapshot_frame_value(snapshot_value(
            &b,
            Some("local"),
            true,
            1_000,
            "0".repeat(32).as_str(),
            0,
            vec![
                remote(&c, None),
                remote(&b, Some("loopback")),
                remote(&a, Some("one")),
            ],
        ));
        assert_eq!(value["type"], "peers_snapshot");
        assert_eq!(value["protocol_version"], 4);
        assert!(value["request_id"].as_str().is_some());
        assert_eq!(value["self"]["public_key"], b);
        assert_eq!(value["self"]["alias"], "local");
        assert_eq!(value["self"]["online"], true);
        let entries = value["peers"].as_array().unwrap();
        assert_eq!(
            entries
                .iter()
                .map(|entry| entry["public_key"].as_str().unwrap())
                .collect::<Vec<_>>(),
            [a.as_str(), c.as_str()]
        );
    }

    #[test]
    fn maximum_complete_snapshot_fits_the_bounded_ipc_frame() {
        let peers = (0..MAX_DYNAMIC_IDENTITIES)
            .map(|index| RemotePeer {
                public_key: format!("{index:064x}"),
                alias: Some("a".repeat(crate::alias::MAX_ALIAS_BYTES)),
                online: true,
                last_seen_ms: 1_000,
                expires_at_ms: 1_000 + PEER_LEASE_MS,
            })
            .collect();
        let frame = meshmsg_protocol::ResponseFrame::new(
            Some(meshmsg_protocol::RequestId::new_random()),
            meshmsg_protocol::Response::PeersSnapshot(snapshot_value(
                &"f".repeat(64),
                Some("self"),
                true,
                1_000,
                &"0".repeat(32),
                0,
                peers,
            )),
        );
        assert!(
            serde_json::to_vec(&frame).unwrap().len() <= crate::ipc::MAX_IPC_EVENT_SIZE,
            "maximum canonical peer snapshot response exceeds IPC frame"
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
            &"0".repeat(32),
            1,
        );
        let value = event_frame_value(value);
        assert!(serde_json::to_vec(&value).unwrap().len() <= MAX_PEER_LIFECYCLE_EVENT_BYTES);
        assert!(value.get("body").is_none());
    }

    #[test]
    fn wire_objects_have_only_the_documented_sanitized_fields() {
        let discovered = transition_value(
            PeerTransition {
                kind: PeerTransitionKind::Discovered,
                peer: remote(&"c".repeat(64), None),
            },
            &"0".repeat(32),
            1,
        );
        let discovered = event_frame_value(discovered);
        assert_eq!(discovered["type"], "peer_discovered");
        assert_eq!(discovered["protocol_version"], 4);
        assert!(discovered["request_id"].as_str().is_some());
        assert_eq!(discovered["directory_revision"], 1);
        assert_eq!(discovered["peer"]["public_key"], "c".repeat(64));
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
