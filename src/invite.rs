use anyhow::{Context, Result};
use data_encoding::BASE32_NOPAD;
use iroh::EndpointAddr;
use iroh_gossip::proto::TopicId;
use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};

pub const MAX_SEEDS: usize = 16;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invite {
    pub topic: TopicId,
    pub seeds: Vec<EndpointAddr>,
}

impl Invite {
    pub fn deduplicate(&mut self) {
        self.seeds.sort_by_key(|seed| seed.id);
        self.seeds.dedup_by_key(|seed| seed.id);
    }

    pub fn ensure_room_for_new_seed(&self) -> Result<()> {
        anyhow::ensure!(
            self.seeds.len() < MAX_SEEDS,
            "seed set already contains the maximum of {MAX_SEEDS} seeds"
        );
        Ok(())
    }

    pub fn upsert_seed(&mut self, seed: EndpointAddr) -> Result<()> {
        self.seeds.retain(|existing| existing.id != seed.id);
        self.ensure_room_for_new_seed()?;
        self.seeds.push(seed);
        self.deduplicate();
        Ok(())
    }
}

impl fmt::Display for Invite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut encoded =
            BASE32_NOPAD.encode(&postcard::to_stdvec(self).expect("invite serialization"));
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
        let mut invite: Self = postcard::from_bytes(&bytes).context("invalid invite contents")?;
        invite.deduplicate();
        anyhow::ensure!(!invite.seeds.is_empty(), "invite contains no seeds");
        anyhow::ensure!(
            invite.seeds.len() <= MAX_SEEDS,
            "invite contains more than {MAX_SEEDS} seeds"
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

    fn invite_with_seed_count(count: usize) -> Invite {
        Invite {
            topic: TopicId::from_bytes([7; 32]),
            seeds: (0..count).map(|_| endpoint()).collect(),
        }
    }

    #[test]
    fn full_invite_cannot_add_a_new_seed() {
        let mut invite = invite_with_seed_count(MAX_SEEDS);
        assert!(invite.ensure_room_for_new_seed().is_err());
        assert!(invite.upsert_seed(endpoint()).is_err());
        assert_eq!(invite.seeds.len(), MAX_SEEDS);
    }

    #[test]
    fn full_invite_can_replace_an_existing_seed_endpoint() {
        let mut invite = invite_with_seed_count(MAX_SEEDS);
        let existing = invite.seeds[0].clone();
        let replacement =
            EndpointAddr::new(existing.id).with_ip_addr("127.0.0.1:7777".parse().unwrap());

        invite.upsert_seed(replacement.clone()).unwrap();

        assert_eq!(invite.seeds.len(), MAX_SEEDS);
        assert_eq!(
            invite
                .seeds
                .iter()
                .filter(|seed| seed.id == existing.id)
                .count(),
            1
        );
        assert!(invite.seeds.contains(&replacement));
        assert!(!invite.seeds.contains(&existing));
    }
}
