use crate::invite::Invite;
use anyhow::{bail, Context, Result};
use data_encoding::HEXLOWER;
use fs2::FileExt;
use iroh::SecretKey;
use iroh_gossip::proto::TopicId;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    str::FromStr,
};

const LOCK_NAME: &str = ".meshmsg.lock";

/// Exclusive ownership of mutable state and the network identity.
pub struct StateLock {
    _file: fs::File,
}

impl StateLock {
    pub fn acquire(dir: &Path) -> Result<Self> {
        prepare_state_dir(dir)?;
        let path = dir.join(LOCK_NAME);
        let mut options = fs::OpenOptions::new();
        options.create(true).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(&path).context("open state lock")?;
        file.try_lock_exclusive().map_err(|error| {
            let lock_contended = error.kind() == std::io::ErrorKind::WouldBlock
                || (cfg!(windows) && error.raw_os_error() == Some(33));
            if lock_contended {
                anyhow::anyhow!("state is in use by a running meshmsg daemon")
            } else {
                anyhow::Error::new(error).context("lock meshmsg state")
            }
        })?;
        Ok(Self { _file: file })
    }
}

pub fn prepare_state_dir(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir).context("create state directory")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let metadata = fs::symlink_metadata(dir).context("inspect state directory")?;
        anyhow::ensure!(
            metadata.file_type().is_dir(),
            "state path is not a directory"
        );
        // SAFETY: geteuid has no preconditions and only reads process credentials.
        let effective_uid = unsafe { libc::geteuid() };
        anyhow::ensure!(
            metadata.uid() == effective_uid,
            "state directory is not owned by the current user"
        );
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
            .context("restrict state directory permissions")?;
    }
    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct State {
    pub role: Role,
    pub topic: String,
    pub invite: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
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

    pub fn ensure_role(&self, expected: Role) -> Result<()> {
        anyhow::ensure!(
            self.role == expected,
            "command requires {:?} state, but this state is {:?}",
            expected,
            self.role
        );
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        let topic = self.topic_id()?;
        match (&self.role, &self.invite) {
            (Role::Member, None) => bail!("member state must contain an invite"),
            (_, Some(token)) => {
                let invite: Invite = token.parse().context("invalid invite in state")?;
                anyhow::ensure!(
                    invite.topic == topic,
                    "configured invite topic does not match state topic"
                );
            }
            (Role::Seed, None) => {}
        }
        Ok(())
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
        let lock = StateLock::acquire(dir)?;
        if dir.join("config.json").exists() && !force {
            bail!("state already exists (use --force to replace it)");
        }
        let secret = SecretKey::generate();
        write_secret(dir, &secret)?;
        self.save(dir, &lock)
    }

    pub fn save(&self, dir: &Path, _lock: &StateLock) -> Result<()> {
        atomic_write(dir, "config.json", &serde_json::to_vec_pretty(self)?, 0o600)
            .context("write config.json")
    }
}

fn write_secret(dir: &Path, key: &SecretKey) -> Result<()> {
    atomic_write(
        dir,
        "secret.key",
        HEXLOWER.encode(&key.to_bytes()).as_bytes(),
        0o600,
    )
    .context("write secret.key")
}

fn atomic_write(dir: &Path, name: &str, contents: &[u8], _mode: u32) -> Result<()> {
    prepare_state_dir(dir)?;
    let destination = dir.join(name);
    let temporary = temporary_path(dir, name);
    let result = (|| -> Result<()> {
        let mut options = fs::OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(_mode);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(contents)?;
        file.sync_all()?;
        atomic_replace(&temporary, &destination)?;
        #[cfg(unix)]
        fs::File::open(dir)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(unix)]
fn atomic_replace(source: &Path, destination: &Path) -> std::io::Result<()> {
    fs::rename(source, destination)
}

#[cfg(windows)]
fn atomic_replace(source: &Path, destination: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };

    let source: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    let moved = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if moved == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn temporary_path(dir: &Path, name: &str) -> PathBuf {
    dir.join(format!(
        ".{name}.tmp-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_new_does_not_replace_existing_state_or_identity_without_force() {
        let dir =
            std::env::temp_dir().join(format!("meshmsg-config-test-{}", rand::random::<u64>()));
        let original = State::new_seed();
        original.save_new(&dir, false).unwrap();
        let config_before = fs::read(dir.join("config.json")).unwrap();
        let secret_before = fs::read(dir.join("secret.key")).unwrap();

        let replacement = State::new_seed();
        let error = replacement.save_new(&dir, false).unwrap_err();

        assert!(error.to_string().contains("state already exists"));
        assert_eq!(fs::read(dir.join("config.json")).unwrap(), config_before);
        assert_eq!(fs::read(dir.join("secret.key")).unwrap(), secret_before);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn active_state_lock_rejects_forced_identity_replacement() {
        let dir =
            std::env::temp_dir().join(format!("meshmsg-config-test-{}", rand::random::<u64>()));
        let original = State::new_seed();
        original.save_new(&dir, false).unwrap();
        let secret_before = fs::read(dir.join("secret.key")).unwrap();
        let lock = StateLock::acquire(&dir).unwrap();

        let error = State::new_seed().save_new(&dir, true).unwrap_err();

        assert!(error.to_string().contains("state is in use"));
        assert_eq!(fs::read(dir.join("secret.key")).unwrap(), secret_before);
        drop(lock);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn seed_only_commands_reject_member_state() {
        let state = State {
            role: Role::Member,
            topic: TopicId::from_bytes(rand::random()).to_string(),
            invite: None,
        };

        let error = state.ensure_role(Role::Seed).unwrap_err();
        assert!(error.to_string().contains("requires Seed state"));
    }

    #[test]
    fn member_state_requires_an_invite() {
        let state = State {
            role: Role::Member,
            topic: TopicId::from_bytes(rand::random()).to_string(),
            invite: None,
        };

        assert!(state
            .validate()
            .unwrap_err()
            .to_string()
            .contains("must contain"));
    }

    #[test]
    fn configured_invite_must_match_state_topic() {
        let invite = Invite {
            topic: TopicId::from_bytes(rand::random()),
            seeds: vec![iroh::EndpointAddr::new(SecretKey::generate().public())],
        };
        let state = State {
            role: Role::Seed,
            topic: TopicId::from_bytes(rand::random()).to_string(),
            invite: Some(invite.to_string()),
        };

        let error = state.validate().unwrap_err();
        assert!(error.to_string().contains("does not match"));
    }

    #[test]
    fn state_save_is_atomic_and_leaves_no_temporary_file() {
        let dir =
            std::env::temp_dir().join(format!("meshmsg-config-test-{}", rand::random::<u64>()));
        let state = State::new_seed();
        state.save_new(&dir, false).unwrap();
        let state_lock = StateLock::acquire(&dir).unwrap();
        state.save(&dir, &state_lock).unwrap();

        let loaded = State::load(&dir).unwrap();
        assert_eq!(loaded.topic, state.topic);
        assert!(fs::read_dir(&dir).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains(".tmp-")));
        fs::remove_dir_all(dir).unwrap();
    }
}
