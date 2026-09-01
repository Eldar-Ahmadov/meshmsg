use crate::invite::Invite;
use anyhow::{bail, Context, Result};
use data_encoding::HEXLOWER;
use fs2::FileExt;
use iroh::{PublicKey, SecretKey};
use iroh_gossip::proto::TopicId;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    str::FromStr,
};

const LOCK_NAME: &str = ".meshmsg.lock";
const LEGACY_SECRET_NAME: &str = "secret.key";
const IDENTITY_VERSION: u8 = 1;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct State {
    pub role: Role,
    pub topic: String,
    pub invite: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    identity: Option<IdentityBinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IdentityBinding {
    version: u8,
    generation: String,
    public_key: String,
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
            identity: None,
        }
    }

    pub fn from_invite(role: Role, token: String, invite: &Invite) -> Self {
        Self {
            role,
            topic: invite.topic.to_string(),
            invite: Some(token),
            identity: None,
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

    pub fn load(dir: &Path) -> Result<Self> {
        serde_json::from_slice(&fs::read(dir.join("config.json")).context("state not initialized")?)
            .context("parse config.json")
    }

    /// Load state while holding daemon ownership, migrating legacy identity metadata if needed.
    pub fn load_locked(dir: &Path, lock: &StateLock) -> Result<(Self, SecretKey)> {
        let mut state = Self::load(dir)?;
        if state.identity.is_none() {
            migrate_legacy(dir, lock, &mut state)?;
        }
        let secret = load_bound_secret(
            dir,
            state
                .identity
                .as_ref()
                .context("identity binding missing after migration")?,
        )?;
        Ok((state, secret))
    }

    /// Doctor remains lock-free for current state, but serializes a required legacy migration.
    pub fn load_for_doctor(dir: &Path) -> Result<(Self, SecretKey)> {
        let state = Self::load(dir)?;
        if let Some(binding) = &state.identity {
            let secret = load_bound_secret(dir, binding)?;
            return Ok((state, secret));
        }
        let lock = match StateLock::acquire(dir) {
            Ok(lock) => lock,
            Err(error) => {
                // Daemon startup may have completed migration between our first read and
                // lock attempt. Reload once before reporting that migration is blocked.
                let refreshed = Self::load(dir)?;
                if let Some(binding) = &refreshed.identity {
                    let secret = load_bound_secret(dir, binding)?;
                    return Ok((refreshed, secret));
                }
                bail!(
                    "legacy identity metadata requires migration; stop the daemon and retry doctor: {error}"
                );
            }
        };
        Self::load_locked(dir, &lock)
    }

    /// Create and durably select a new immutable identity generation.
    pub fn save_new(&self, dir: &Path, force: bool) -> Result<String> {
        self.save_new_inner(dir, force, false)
    }

    fn save_new_inner(&self, dir: &Path, force: bool, fail_after_identity: bool) -> Result<String> {
        let lock = StateLock::acquire(dir)?;
        if dir.join("config.json").exists() && !force {
            bail!("state already exists (use --force to replace it)");
        }
        let secret = SecretKey::generate();
        let generation = new_generation();
        write_generation(dir, &generation, &secret)?;
        if fail_after_identity {
            bail!("injected failure after identity installation");
        }
        let public_key = secret.public().to_string();
        let mut committed = self.clone();
        committed.identity = Some(IdentityBinding {
            version: IDENTITY_VERSION,
            generation,
            public_key: public_key.clone(),
        });
        committed.save(dir, &lock)?;
        Ok(public_key)
    }

    pub fn save(&self, dir: &Path, _lock: &StateLock) -> Result<()> {
        anyhow::ensure!(
            self.identity.is_some(),
            "refusing to save state without an identity binding"
        );
        atomic_write(dir, "config.json", &serde_json::to_vec_pretty(self)?, 0o600)
            .context("write config.json")
    }
}

fn migrate_legacy(dir: &Path, lock: &StateLock, state: &mut State) -> Result<()> {
    let legacy_path = dir.join(LEGACY_SECRET_NAME);
    let (_legacy_file, secret) = open_secret(&legacy_path).context("load legacy identity")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        _legacy_file
            .set_permissions(fs::Permissions::from_mode(0o600))
            .context("restrict legacy secret.key permissions")?;
    }
    let generation = new_generation();
    write_generation(dir, &generation, &secret)?;
    state.identity = Some(IdentityBinding {
        version: IDENTITY_VERSION,
        generation,
        public_key: secret.public().to_string(),
    });
    state
        .save(dir, lock)
        .context("commit legacy identity migration")
}

fn new_generation() -> String {
    HEXLOWER.encode(&rand::random::<[u8; 16]>())
}

fn generation_name(generation: &str) -> Result<String> {
    anyhow::ensure!(
        generation.len() == 32
            && generation
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "invalid identity generation"
    );
    Ok(format!(".secret-{generation}.key"))
}

fn write_generation(dir: &Path, generation: &str, key: &SecretKey) -> Result<()> {
    let name = generation_name(generation)?;
    atomic_write(
        dir,
        &name,
        HEXLOWER.encode(&key.to_bytes()).as_bytes(),
        0o600,
    )
    .with_context(|| format!("write identity generation {generation}"))
}

fn load_bound_secret(dir: &Path, binding: &IdentityBinding) -> Result<SecretKey> {
    anyhow::ensure!(
        binding.version == IDENTITY_VERSION,
        "unsupported identity binding version {}",
        binding.version
    );
    let name = generation_name(&binding.generation)?;
    let expected = PublicKey::from_str(&binding.public_key)
        .context("invalid expected public key in config.json")?;
    let secret = read_secret(&dir.join(name)).context("read selected identity generation")?;
    anyhow::ensure!(
        secret.public() == expected,
        "configured public key does not match selected identity"
    );
    Ok(secret)
}

fn read_secret(path: &Path) -> Result<SecretKey> {
    open_secret(path).map(|(_, secret)| secret)
}

fn open_secret(path: &Path) -> Result<(fs::File, SecretKey)> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    anyhow::ensure!(
        file.metadata()
            .with_context(|| format!("inspect {}", path.display()))?
            .is_file(),
        "{} is not a regular file",
        path.display()
    );
    let mut text = String::new();
    file.read_to_string(&mut text)
        .with_context(|| format!("read {}", path.display()))?;
    let bytes = HEXLOWER
        .decode(text.trim().as_bytes())
        .with_context(|| format!("decode {}", path.display()))?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{} must contain 32 bytes", path.display()))?;
    Ok((file, SecretKey::from_bytes(&bytes)))
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

    fn test_dir() -> PathBuf {
        std::env::temp_dir().join(format!("meshmsg-config-test-{}", rand::random::<u64>()))
    }

    fn load_bundle(dir: &Path) -> Result<(State, SecretKey)> {
        let state = State::load(dir)?;
        let secret = match &state.identity {
            Some(binding) => load_bound_secret(dir, binding)?,
            None => read_secret(&dir.join(LEGACY_SECRET_NAME))?,
        };
        Ok((state, secret))
    }

    fn member_without_invite() -> State {
        State {
            role: Role::Member,
            topic: TopicId::from_bytes(rand::random()).to_string(),
            invite: None,
            identity: None,
        }
    }

    #[test]
    fn save_new_does_not_replace_existing_state_or_identity_without_force() {
        let dir = test_dir();
        let original = State::new_seed();
        original.save_new(&dir, false).unwrap();
        let config_before = fs::read(dir.join("config.json")).unwrap();

        let error = State::new_seed().save_new(&dir, false).unwrap_err();

        assert!(error.to_string().contains("state already exists"));
        assert_eq!(fs::read(dir.join("config.json")).unwrap(), config_before);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn active_state_lock_rejects_forced_identity_replacement() {
        let dir = test_dir();
        State::new_seed().save_new(&dir, false).unwrap();
        let config_before = fs::read(dir.join("config.json")).unwrap();
        let lock = StateLock::acquire(&dir).unwrap();

        let error = State::new_seed().save_new(&dir, true).unwrap_err();

        assert!(error.to_string().contains("state is in use"));
        assert_eq!(fs::read(dir.join("config.json")).unwrap(), config_before);
        drop(lock);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn legacy_state_migrates_without_changing_state_or_public_key() {
        let dir = test_dir();
        prepare_state_dir(&dir).unwrap();
        let state = State::new_seed();
        let secret = SecretKey::generate();
        fs::write(
            dir.join(LEGACY_SECRET_NAME),
            HEXLOWER.encode(&secret.to_bytes()),
        )
        .unwrap();
        atomic_write(
            &dir,
            "config.json",
            &serde_json::to_vec_pretty(&state).unwrap(),
            0o600,
        )
        .unwrap();

        let lock = StateLock::acquire(&dir).unwrap();
        let (migrated, loaded_secret) = State::load_locked(&dir, &lock).unwrap();

        assert_eq!(migrated.role, state.role);
        assert_eq!(migrated.topic, state.topic);
        assert_eq!(migrated.invite, state.invite);
        assert_eq!(loaded_secret.public(), secret.public());
        assert!(migrated.identity.is_some());
        assert!(dir.join(LEGACY_SECRET_NAME).exists());
        drop(lock);
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn legacy_migration_rejects_symlink_without_chmodding_target() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let dir = test_dir();
        prepare_state_dir(&dir).unwrap();
        let external =
            std::env::temp_dir().join(format!("meshmsg-external-secret-{}", rand::random::<u64>()));
        fs::write(
            &external,
            HEXLOWER.encode(&SecretKey::generate().to_bytes()),
        )
        .unwrap();
        fs::set_permissions(&external, fs::Permissions::from_mode(0o644)).unwrap();
        symlink(&external, dir.join(LEGACY_SECRET_NAME)).unwrap();
        let state = State::new_seed();
        atomic_write(
            &dir,
            "config.json",
            &serde_json::to_vec_pretty(&state).unwrap(),
            0o600,
        )
        .unwrap();

        let lock = StateLock::acquire(&dir).unwrap();
        let error = State::load_locked(&dir, &lock).unwrap_err();

        assert!(format!("{error:#}").contains("open"));
        assert_eq!(
            fs::metadata(&external).unwrap().permissions().mode() & 0o777,
            0o644
        );
        assert!(State::load(&dir).unwrap().identity.is_none());
        drop(lock);
        fs::remove_dir_all(dir).unwrap();
        fs::remove_file(external).unwrap();
    }

    #[test]
    fn failed_replacement_after_identity_install_keeps_old_commit_loadable() {
        let dir = test_dir();
        let old = State::new_seed();
        let old_peer = old.save_new(&dir, false).unwrap();

        let error = State::new_seed()
            .save_new_inner(&dir, true, true)
            .unwrap_err();
        let (loaded, secret) = load_bundle(&dir).unwrap();

        assert!(error.to_string().contains("injected failure"));
        assert_eq!(loaded.topic, old.topic);
        assert_eq!(secret.public().to_string(), old_peer);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn expected_public_key_mismatch_is_rejected() {
        let dir = test_dir();
        State::new_seed().save_new(&dir, false).unwrap();
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(dir.join("config.json")).unwrap()).unwrap();
        value["identity"]["public_key"] = SecretKey::generate().public().to_string().into();
        atomic_write(
            &dir,
            "config.json",
            &serde_json::to_vec_pretty(&value).unwrap(),
            0o600,
        )
        .unwrap();

        let error = State::load_for_doctor(&dir).unwrap_err();
        assert!(error.to_string().contains("does not match"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn malformed_generation_and_missing_selected_secret_are_rejected() {
        let dir = test_dir();
        State::new_seed().save_new(&dir, false).unwrap();
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(dir.join("config.json")).unwrap()).unwrap();
        value["identity"]["generation"] = "../secret.key".into();
        atomic_write(
            &dir,
            "config.json",
            &serde_json::to_vec_pretty(&value).unwrap(),
            0o600,
        )
        .unwrap();
        assert!(load_bundle(&dir)
            .unwrap_err()
            .to_string()
            .contains("invalid identity generation"));

        value["identity"]["generation"] = new_generation().into();
        atomic_write(
            &dir,
            "config.json",
            &serde_json::to_vec_pretty(&value).unwrap(),
            0o600,
        )
        .unwrap();
        assert!(format!("{:#}", load_bundle(&dir).unwrap_err()).contains("read selected"));

        value["identity"]["version"] = 99.into();
        atomic_write(
            &dir,
            "config.json",
            &serde_json::to_vec_pretty(&value).unwrap(),
            0o600,
        )
        .unwrap();
        assert!(load_bundle(&dir)
            .unwrap_err()
            .to_string()
            .contains("unsupported identity binding version"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn seed_only_commands_reject_member_state() {
        let error = member_without_invite().ensure_role(Role::Seed).unwrap_err();
        assert!(error.to_string().contains("requires Seed state"));
    }

    #[test]
    fn member_state_requires_an_invite() {
        assert!(member_without_invite()
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
            identity: None,
        };

        assert!(state
            .validate()
            .unwrap_err()
            .to_string()
            .contains("does not match"));
    }

    #[test]
    fn state_save_preserves_identity_binding_and_is_atomic() {
        let dir = test_dir();
        State::new_seed().save_new(&dir, false).unwrap();
        let state_lock = StateLock::acquire(&dir).unwrap();
        let (mut state, secret) = load_bundle(&dir).unwrap();
        let identity = state.identity.clone().unwrap();
        state.invite = None;
        state.save(&dir, &state_lock).unwrap();

        let (loaded, loaded_secret) = load_bundle(&dir).unwrap();
        assert_eq!(loaded.identity.unwrap().generation, identity.generation);
        assert_eq!(loaded_secret.public(), secret.public());
        assert!(fs::read_dir(&dir).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains(".tmp-")));
        drop(state_lock);
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn state_files_retain_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = test_dir();
        State::new_seed().save_new(&dir, false).unwrap();
        let state = State::load(&dir).unwrap();
        let generation = state.identity.unwrap().generation;
        assert_eq!(
            fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        for name in [
            LOCK_NAME.to_owned(),
            "config.json".to_owned(),
            generation_name(&generation).unwrap(),
        ] {
            assert_eq!(
                fs::metadata(dir.join(name)).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        fs::remove_dir_all(dir).unwrap();
    }
}
