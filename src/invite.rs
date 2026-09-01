use anyhow::{Context, Result};
use data_encoding::BASE32_NOPAD;
use iroh::{EndpointAddr, PublicKey};
use iroh_gossip::proto::TopicId;
use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};

pub const MAX_BOOTSTRAP_PEERS: usize = 16;
const INVITE_WIRE_MAGIC: [u8; 12] = *b"MESHMSG\0INV2";
const INVITE_WIRE_VERSION: u8 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Invite {
    pub topic: TopicId,
    pub bootstrap_peers: Vec<EndpointAddr>,
}

#[derive(Serialize, Deserialize)]
struct InviteWire {
    magic: [u8; 12],
    version: u8,
    invite: Invite,
}

impl Invite {
    pub fn deduplicate(&mut self) {
        self.bootstrap_peers.sort_by_key(|peer| peer.id);
        self.bootstrap_peers.dedup_by_key(|peer| peer.id);
    }

    pub fn ensure_room_for_new_bootstrap_peer(&self) -> Result<()> {
        anyhow::ensure!(
            self.bootstrap_peers.len() < MAX_BOOTSTRAP_PEERS,
            "bootstrap peer list already contains the maximum of {MAX_BOOTSTRAP_PEERS} peers"
        );
        Ok(())
    }

    pub fn ensure_can_advertise(&self, identity: PublicKey) -> Result<()> {
        if self.bootstrap_peers.iter().any(|peer| peer.id == identity) {
            return Ok(());
        }
        anyhow::ensure!(
            self.bootstrap_peers.len() < MAX_BOOTSTRAP_PEERS,
            "cannot advertise self: bootstrap peer list contains the maximum of {MAX_BOOTSTRAP_PEERS} peers and does not contain this identity"
        );
        Ok(())
    }

    pub fn upsert_bootstrap_peer(&mut self, peer: EndpointAddr) -> Result<()> {
        self.ensure_can_advertise(peer.id)?;
        if let Some(existing) = self
            .bootstrap_peers
            .iter_mut()
            .find(|existing| existing.id == peer.id)
        {
            *existing = peer;
        } else {
            self.bootstrap_peers.push(peer);
        }
        self.deduplicate();
        Ok(())
    }
}

impl fmt::Display for Invite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let wire = InviteWire {
            magic: INVITE_WIRE_MAGIC,
            version: INVITE_WIRE_VERSION,
            invite: self.clone(),
        };
        let mut encoded =
            BASE32_NOPAD.encode(&postcard::to_stdvec(&wire).expect("invite serialization"));
        encoded.make_ascii_lowercase();
        f.write_str(&encoded)
    }
}

impl FromStr for Invite {
    type Err = anyhow::Error;
    fn from_str(value: &str) -> Result<Self> {
        let bytes = BASE32_NOPAD
            .decode(value.to_ascii_uppercase().as_bytes())
            .context("invalid invite token")?;
        let (wire, remainder): (InviteWire, &[u8]) = postcard::take_from_bytes(&bytes)
            .context("invalid invite contents or unsupported format")?;
        anyhow::ensure!(remainder.is_empty(), "invite contains trailing data");
        anyhow::ensure!(wire.magic == INVITE_WIRE_MAGIC, "unsupported invite format");
        anyhow::ensure!(
            wire.version == INVITE_WIRE_VERSION,
            "unsupported invite version {}",
            wire.version
        );
        let mut invite = wire.invite;
        invite.deduplicate();
        anyhow::ensure!(
            !invite.bootstrap_peers.is_empty(),
            "invite contains no bootstrap peers"
        );
        anyhow::ensure!(
            invite.bootstrap_peers.len() <= MAX_BOOTSTRAP_PEERS,
            "invite contains more than {MAX_BOOTSTRAP_PEERS} bootstrap peers"
        );
        Ok(invite)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::SecretKey;

    fn endpoint() -> EndpointAddr {
        EndpointAddr::new(SecretKey::generate().public())
    }

    fn invite_with_peer_count(count: usize) -> Invite {
        Invite {
            topic: TopicId::from_bytes([7; 32]),
            bootstrap_peers: (0..count).map(|_| endpoint()).collect(),
        }
    }

    #[test]
    fn previous_two_field_invite_format_is_rejected() {
        let invite = invite_with_peer_count(1);
        let bytes = postcard::to_stdvec(&(invite.topic, invite.bootstrap_peers)).unwrap();
        let mut token = BASE32_NOPAD.encode(&bytes);
        token.make_ascii_lowercase();

        assert!(token.parse::<Invite>().is_err());
    }

    #[test]
    fn wire_discriminator_and_version_are_validated() {
        let invite = invite_with_peer_count(1);
        for wire in [
            InviteWire {
                magic: [0; 12],
                version: INVITE_WIRE_VERSION,
                invite: invite.clone(),
            },
            InviteWire {
                magic: INVITE_WIRE_MAGIC,
                version: INVITE_WIRE_VERSION + 1,
                invite: invite.clone(),
            },
        ] {
            let mut token = BASE32_NOPAD.encode(&postcard::to_stdvec(&wire).unwrap());
            token.make_ascii_lowercase();
            assert!(token.parse::<Invite>().is_err());
        }
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let invite = invite_with_peer_count(1);
        let wire = InviteWire {
            magic: INVITE_WIRE_MAGIC,
            version: INVITE_WIRE_VERSION,
            invite,
        };
        let mut bytes = postcard::to_stdvec(&wire).unwrap();
        bytes.push(0);
        let mut token = BASE32_NOPAD.encode(&bytes);
        token.make_ascii_lowercase();

        assert!(token.parse::<Invite>().is_err());
    }

    #[test]
    fn failed_full_list_insertion_does_not_mutate_the_invite() {
        let mut invite = invite_with_peer_count(MAX_BOOTSTRAP_PEERS);
        let original = invite.clone();

        assert!(invite.ensure_room_for_new_bootstrap_peer().is_err());
        assert!(invite.upsert_bootstrap_peer(endpoint()).is_err());
        assert_eq!(invite, original);
    }

    #[test]
    fn full_invite_can_refresh_an_existing_identity() {
        let mut invite = invite_with_peer_count(MAX_BOOTSTRAP_PEERS);
        let existing = invite.bootstrap_peers[0].clone();
        let replacement =
            EndpointAddr::new(existing.id).with_ip_addr("127.0.0.1:7777".parse().unwrap());

        invite.upsert_bootstrap_peer(replacement.clone()).unwrap();

        assert_eq!(invite.bootstrap_peers.len(), MAX_BOOTSTRAP_PEERS);
        assert_eq!(
            invite
                .bootstrap_peers
                .iter()
                .filter(|peer| peer.id == existing.id)
                .count(),
            1
        );
        assert!(invite.bootstrap_peers.contains(&replacement));
        assert!(!invite.bootstrap_peers.contains(&existing));
    }
}
