use crate::invite::Invite;
use anyhow::{bail, Context, Result};
use data_encoding::HEXLOWER;
use iroh::SecretKey;
use iroh_gossip::proto::TopicId;
use serde::{Deserialize, Serialize};
use std::{fs, path::Path, str::FromStr};

#[derive(Debug, Serialize, Deserialize)]
pub struct State {
    pub role: Role,
    pub topic: String,
    pub invite: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Seed,
    Member,
}

impl State {
    pub fn new_seed() -> Self {
        Self {
            role: Role::Seed,
            topic: TopicId::from_bytes(rand::random()).to_string(),
            invite: None,
        }
    }

    pub fn from_invite(role: Role, token: String, invite: &Invite) -> Self {
        Self {
            role,
            topic: invite.topic.to_string(),
            invite: Some(token),
        }
    }

    pub fn topic_id(&self) -> Result<TopicId> {
        TopicId::from_str(&self.topic).context("invalid topic in state")
    }

    pub fn load_secret(dir: &Path) -> Result<SecretKey> {
        let text = fs::read_to_string(dir.join("secret.key")).context("read secret.key")?;
        let bytes = HEXLOWER
            .decode(text.trim().as_bytes())
            .context("decode secret.key")?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("secret.key must contain 32 bytes"))?;
        Ok(SecretKey::from_bytes(&bytes))
    }

    pub fn load(dir: &Path) -> Result<Self> {
        serde_json::from_slice(&fs::read(dir.join("config.json")).context("state not initialized")?)
            .context("parse config.json")
    }

    pub fn save_new(&self, dir: &Path, force: bool) -> Result<()> {
        if dir.join("config.json").exists() && !force {
            bail!("state already exists (use --force to replace it)");
        }
        fs::create_dir_all(dir).context("create state directory")?;
        let secret = SecretKey::generate();
        write_secret(dir, &secret)?;
        self.save(dir)
    }

    pub fn save(&self, dir: &Path) -> Result<()> {
        fs::write(dir.join("config.json"), serde_json::to_vec_pretty(self)?)
            .context("write config.json")
    }
}

pub fn write_secret(dir: &Path, key: &SecretKey) -> Result<()> {
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    let path = dir.join("secret.key");
    let mut opts = fs::OpenOptions::new();
    opts.create(true).write(true).truncate(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let mut file = opts.open(path).context("write secret.key")?;
    file.write_all(HEXLOWER.encode(&key.to_bytes()).as_bytes())?;
    Ok(())
}
