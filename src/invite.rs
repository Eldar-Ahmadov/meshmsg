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
