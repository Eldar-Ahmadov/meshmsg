use crate::{
    alias::AliasConfig,
    invite::Invite,
    persistent::{self, PersistentError},
};
use anyhow::{bail, Context, Result};
use data_encoding::HEXLOWER;
use fs2::FileExt;
use iroh::{PublicKey, SecretKey};
use iroh_gossip::proto::TopicId;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    str::FromStr,
};

const LOCK_NAME: &str = ".meshmsg.lock";
const CONFIG_NAME: &str = "config.json";
const CONFIG_SCHEMA_VERSION: u8 = 1;
const IDENTITY_VERSION: u8 = 1;
pub(crate) const MAX_CONFIG_BYTES: usize = 64 * 1024;
const MAX_SECRET_BYTES: usize = 256;

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

impl Drop for StateLock {
    fn drop(&mut self) {
        // Explicitly unlock before close. On Unix, a concurrently forked child can
        // briefly inherit the open file description before exec closes CLOEXEC
        // descriptors; relying only on close would let that child extend the lock.
        let _ = fs2::FileExt::unlock(&self._file);
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
#[serde(deny_unknown_fields)]
pub struct State {
    schema_version: u8,
    pub advertise_self: bool,
    pub topic: String,
    pub invite: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    identity: Option<IdentityBinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityBinding {
    version: u8,
    generation: String,
    public_key: String,
}

#[derive(Deserialize)]
struct StateVersionProbe {
    #[serde(default)]
    schema_version: Option<u64>,
}

impl State {
    pub fn new_topic() -> Self {
        Self {
            schema_version: CONFIG_SCHEMA_VERSION,
            advertise_self: true,
            topic: TopicId::from_bytes(rand::random()).to_string(),
            invite: None,
            identity: None,
        }
    }

    pub fn from_invite(token: String, invite: &Invite, advertise_self: bool) -> Self {
        Self {
            schema_version: CONFIG_SCHEMA_VERSION,
            advertise_self,
            topic: invite.topic.to_string(),
            invite: Some(token),
            identity: None,
        }
    }

    pub fn topic_id(&self) -> Result<TopicId> {
        TopicId::from_str(&self.topic).context("invalid topic in state")
    }

    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            self.schema_version == CONFIG_SCHEMA_VERSION,
            "unsupported config.json schema version {}",
            self.schema_version
        );
        let topic = self.topic_id()?;
        if let Some(token) = &self.invite {
            let invite: Invite = token.parse().context("invalid invite in state")?;
            anyhow::ensure!(
                invite.topic == topic,
                "configured invite topic does not match state topic"
            );
        } else {
            anyhow::ensure!(
                self.advertise_self,
                "state without an invite must advertise itself"
            );
        }
        Ok(())
    }

    pub fn validate_for_identity(&self, identity: PublicKey) -> Result<()> {
        self.validate()?;
        if self.advertise_self {
            if let Some(token) = &self.invite {
                let invite: Invite = token.parse().context("invalid invite in state")?;
                invite.ensure_can_advertise(identity)?;
            }
        }
        Ok(())
    }

    pub fn load(dir: &Path) -> Result<Self> {
        let bytes =
            persistent::read_file_bounded(&dir.join(CONFIG_NAME), CONFIG_NAME, MAX_CONFIG_BYTES)?;
        decode_state(&bytes)
    }

    pub fn load_locked(dir: &Path, _lock: &StateLock) -> Result<(Self, SecretKey)> {
        let bytes =
            persistent::read_file_bounded(&dir.join(CONFIG_NAME), CONFIG_NAME, MAX_CONFIG_BYTES)?;
        let state = decode_state(&bytes)?;
        state.validate().context("validate config.json")?;
        let secret = load_bound_secret(
            dir,
            state
                .identity
                .as_ref()
                .context("identity binding missing from config.json")?,
        )?;
        state
            .validate_for_identity(secret.public())
            .context("validate config.json for selected identity")?;
        Ok((state, secret))
    }

    /// Current state is immutable while the daemon runs and can be diagnosed lock-free.
    pub fn load_for_doctor(dir: &Path) -> Result<(Self, SecretKey)> {
        let state = Self::load(dir)?;
        let secret = load_bound_secret(
            dir,
            state
                .identity
                .as_ref()
                .context("identity binding missing from config.json")?,
        )?;
        Ok((state, secret))
    }

    /// Test helper for committing state without alias metadata.
    #[cfg(test)]
    pub fn save_new(&self, dir: &Path, force: bool) -> Result<String> {
        self.save_new_inner(dir, force, false)
    }

    /// Commit identity/state and its separately stored alias selection under
    /// one state lock. alias.json is identity-bound, so a crash between the two
    /// atomic renames fails closed instead of reusing a stale enabled alias.
    pub fn save_new_with_alias(
        &self,
        dir: &Path,
        force: bool,
        alias: &mut AliasConfig,
    ) -> Result<String> {
        self.save_new_inner_impl(dir, force, false, Some(alias))
    }

    #[cfg(test)]
    fn save_new_inner(&self, dir: &Path, force: bool, fail_after_identity: bool) -> Result<String> {
        self.save_new_inner_impl(dir, force, fail_after_identity, None)
    }

    fn save_new_inner_impl(
        &self,
        dir: &Path,
        force: bool,
        fail_after_identity: bool,
        alias: Option<&mut AliasConfig>,
    ) -> Result<String> {
        let lock = StateLock::acquire(dir)?;
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
        if force {
            committed.save(dir, &lock)?;
        } else {
            let encoded = serde_json::to_vec_pretty(&committed)?;
            atomic_write_new(dir, CONFIG_NAME, &encoded, 0o600)?;
        }
        if let Some(alias) = alias {
            alias.bind_identity(secret.public());
            alias.install_locked(dir, &lock)?;
        }
        Ok(public_key)
    }

    pub fn save(&self, dir: &Path, _lock: &StateLock) -> Result<()> {
        anyhow::ensure!(
            self.identity.is_some(),
            "refusing to save state without an identity binding"
        );
        atomic_write(dir, CONFIG_NAME, &serde_json::to_vec_pretty(self)?, 0o600)
            .context("write config.json")
    }
}

fn decode_state(bytes: &[u8]) -> Result<State> {
    let probe: StateVersionProbe = persistent::parse_json(bytes, CONFIG_NAME)?;
    let Some(version) = probe.schema_version else {
        return Err(PersistentError::unsupported_version(CONFIG_NAME, 0).into());
    };
    if version != u64::from(CONFIG_SCHEMA_VERSION) {
        return Err(PersistentError::unsupported_version(CONFIG_NAME, version).into());
    }
    Ok(persistent::parse_json(bytes, CONFIG_NAME)?)
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
    let contents = persistent::read_file_bounded(path, "identity secret", MAX_SECRET_BYTES)?;
    let text = std::str::from_utf8(&contents)
        .map_err(|_| PersistentError::corrupt("identity secret", "not valid UTF-8"))?;
    let bytes = HEXLOWER
        .decode(text.trim().as_bytes())
        .map_err(|_| PersistentError::corrupt("identity secret", "invalid hexadecimal encoding"))?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| PersistentError::corrupt("identity secret", "wrong key length"))?;
    Ok(SecretKey::from_bytes(&bytes))
}

#[derive(Debug)]
struct NoReplaceCollision;

impl std::fmt::Display for NoReplaceCollision {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "state already exists (use --force to replace it)"
        )
    }
}

impl std::error::Error for NoReplaceCollision {}

pub(crate) fn atomic_write(dir: &Path, name: &str, contents: &[u8], mode: u32) -> Result<()> {
    atomic_write_impl(dir, name, contents, mode, true, || {})
}

fn atomic_write_new(dir: &Path, name: &str, contents: &[u8], mode: u32) -> Result<()> {
    atomic_write_new_with_hook_impl(dir, name, contents, mode, || {})
}

#[cfg(test)]
fn atomic_write_new_with_hook(
    dir: &Path,
    name: &str,
    contents: &[u8],
    mode: u32,
    before_commit: impl FnOnce(),
) -> Result<()> {
    atomic_write_new_with_hook_impl(dir, name, contents, mode, before_commit)
}

fn atomic_write_new_with_hook_impl(
    dir: &Path,
    name: &str,
    contents: &[u8],
    mode: u32,
    before_commit: impl FnOnce(),
) -> Result<()> {
    atomic_write_impl(dir, name, contents, mode, false, before_commit)
}

fn atomic_write_impl(
    dir: &Path,
    name: &str,
    contents: &[u8],
    _mode: u32,
    replace: bool,
    before_commit: impl FnOnce(),
) -> Result<()> {
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
        drop(file);
        before_commit();
        if replace {
            atomic_replace(&temporary, &destination)?;
            sync_state_dir(dir)?;
        } else {
            if let Err(error) = fs::hard_link(&temporary, &destination) {
                if error.kind() == std::io::ErrorKind::AlreadyExists
                    || fs::symlink_metadata(&destination).is_ok()
                {
                    return Err(NoReplaceCollision.into());
                }
                return Err(error.into());
            }
            // Persist creation of the authoritative name before removing and
            // durably cleaning up its same-filesystem temporary hard link.
            sync_state_dir(dir)?;
            fs::remove_file(&temporary)?;
            sync_state_dir(dir)?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn sync_state_dir(dir: &Path) -> Result<()> {
    #[cfg(unix)]
    fs::File::open(dir)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
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
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn test_dir() -> PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before Unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "meshmsg-config-test-{}-{nonce}-{}",
            std::process::id(),
            TEST_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn load_bundle(dir: &Path) -> Result<(State, SecretKey)> {
        let state = State::load(dir)?;
        let secret = load_bound_secret(dir, state.identity.as_ref().context("missing identity")?)?;
        Ok((state, secret))
    }

    #[test]
    fn fresh_state_advertises_self_and_has_no_invite() {
        let state = State::new_topic();
        assert!(state.advertise_self);
        assert!(state.invite.is_none());
        state.validate().unwrap();
    }

    #[test]
    fn save_new_does_not_replace_existing_state_or_identity_without_force() {
        let dir = test_dir();
        let original = State::new_topic();
        original.save_new(&dir, false).unwrap();
        let config_before = fs::read(dir.join("config.json")).unwrap();

        let error = State::new_topic().save_new(&dir, false).unwrap_err();

        assert!(error.to_string().contains("state already exists"));
        assert_eq!(fs::read(dir.join("config.json")).unwrap(), config_before);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn atomic_no_replace_rejects_a_destination_created_at_commit_boundary() {
        for destination_kind in ["file", "directory"] {
            let dir = test_dir();
            prepare_state_dir(&dir).unwrap();
            let destination = dir.join(CONFIG_NAME);
            let error = atomic_write_new_with_hook(&dir, CONFIG_NAME, b"new config", 0o600, || {
                match destination_kind {
                    "file" => fs::write(&destination, b"concurrent config").unwrap(),
                    "directory" => fs::create_dir(&destination).unwrap(),
                    _ => unreachable!(),
                }
            })
            .unwrap_err();
            assert!(error.to_string().contains("state already exists"));
            if destination_kind == "file" {
                assert_eq!(fs::read(&destination).unwrap(), b"concurrent config");
            } else {
                assert!(destination.is_dir());
            }
            assert!(!fs::read_dir(&dir).unwrap().any(|entry| entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".config.json.tmp-")));
            fs::remove_dir_all(dir).unwrap();
        }
    }

    #[test]
    fn forced_initialization_still_atomically_replaces_existing_config() {
        let dir = test_dir();
        let original_peer = State::new_topic().save_new(&dir, false).unwrap();
        let replacement = State::new_topic();
        let replacement_peer = replacement.save_new(&dir, true).unwrap();
        let (loaded, secret) = load_bundle(&dir).unwrap();
        assert_ne!(replacement_peer, original_peer);
        assert_eq!(loaded.topic, replacement.topic);
        assert_eq!(secret.public().to_string(), replacement_peer);
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn no_replace_commit_rejects_a_symlink_created_at_commit_boundary() {
        use std::os::unix::fs::symlink;
        let dir = test_dir();
        prepare_state_dir(&dir).unwrap();
        let destination = dir.join(CONFIG_NAME);
        let target = dir.join("concurrent-target");
        fs::write(&target, b"target").unwrap();
        let error = atomic_write_new_with_hook(&dir, CONFIG_NAME, b"new config", 0o600, || {
            symlink(&target, &destination).unwrap();
        })
        .unwrap_err();
        assert!(error.to_string().contains("state already exists"));
        assert!(fs::symlink_metadata(&destination)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(fs::read(target).unwrap(), b"target");
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn no_replace_commit_rejects_a_reparse_point_created_at_commit_boundary() {
        use std::os::windows::fs::symlink_file;
        let dir = test_dir();
        prepare_state_dir(&dir).unwrap();
        let destination = dir.join(CONFIG_NAME);
        let target = dir.join("concurrent-target");
        fs::write(&target, b"target").unwrap();
        let error = atomic_write_new_with_hook(&dir, CONFIG_NAME, b"new config", 0o600, || {
            symlink_file(&target, &destination).unwrap();
        })
        .unwrap_err();
        assert!(error.to_string().contains("state already exists"));
        assert!(fs::symlink_metadata(&destination)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(fs::read(target).unwrap(), b"target");
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn no_force_initialization_rejects_a_dangling_config_symlink() {
        use std::os::unix::fs::symlink;
        let dir = test_dir();
        prepare_state_dir(&dir).unwrap();
        let config = dir.join(CONFIG_NAME);
        symlink(dir.join("missing-target"), &config).unwrap();

        let error = State::new_topic().save_new(&dir, false).unwrap_err();
        assert!(error.to_string().contains("state already exists"));
        assert!(fs::symlink_metadata(&config)
            .unwrap()
            .file_type()
            .is_symlink());
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn no_force_initialization_rejects_a_dangling_config_reparse_point() {
        use std::os::windows::fs::symlink_file;
        let dir = test_dir();
        prepare_state_dir(&dir).unwrap();
        let config = dir.join(CONFIG_NAME);
        symlink_file(dir.join("missing-target"), &config).unwrap();

        let error = State::new_topic().save_new(&dir, false).unwrap_err();
        assert!(error.to_string().contains("state already exists"));
        assert!(fs::symlink_metadata(&config)
            .unwrap()
            .file_type()
            .is_symlink());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn active_state_lock_rejects_forced_identity_replacement() {
        let dir = test_dir();
        State::new_topic().save_new(&dir, false).unwrap();
        let config_before = fs::read(dir.join("config.json")).unwrap();
        let lock = StateLock::acquire(&dir).unwrap();

        let error = State::new_topic().save_new(&dir, true).unwrap_err();

        assert!(error.to_string().contains("state is in use"));
        assert_eq!(fs::read(dir.join("config.json")).unwrap(), config_before);
        drop(lock);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn current_state_with_unknown_fields_or_missing_identity_is_rejected() {
        let dir = test_dir();
        prepare_state_dir(&dir).unwrap();
        let state_with_deprecated_field = serde_json::json!({
            "schema_version": 1,
            "advertise_self":true,
            "topic":TopicId::from_bytes([1; 32]).to_string(),
            "invite":null,
            "identity": null,
            "deprecated":true
        });
        fs::write(
            dir.join("config.json"),
            serde_json::to_vec(&state_with_deprecated_field).unwrap(),
        )
        .unwrap();
        assert!(format!("{:#}", State::load(&dir).unwrap_err()).contains("unknown field"));

        let current_without_identity = serde_json::json!({
            "schema_version": 1,
            "advertise_self":true,
            "topic":TopicId::from_bytes([1; 32]).to_string(),
            "invite":null
        });
        fs::write(
            dir.join("config.json"),
            serde_json::to_vec(&current_without_identity).unwrap(),
        )
        .unwrap();
        let lock = StateLock::acquire(&dir).unwrap();
        assert!(State::load_locked(&dir, &lock)
            .unwrap_err()
            .to_string()
            .contains("identity binding missing"));
        drop(lock);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn failed_replacement_after_identity_install_keeps_old_commit_loadable() {
        let dir = test_dir();
        let old = State::new_topic();
        let old_peer = old.save_new(&dir, false).unwrap();

        let error = State::new_topic()
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
        State::new_topic().save_new(&dir, false).unwrap();
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
        State::new_topic().save_new(&dir, false).unwrap();
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
    fn identity_secret_is_bounded_and_errors_do_not_expose_its_path() {
        let dir = test_dir();
        State::new_topic().save_new(&dir, false).unwrap();
        let state = State::load(&dir).unwrap();
        let secret_path = dir.join(generation_name(&state.identity.unwrap().generation).unwrap());
        fs::write(&secret_path, vec![b'a'; MAX_SECRET_BYTES + 1]).unwrap();

        let error = State::load_for_doctor(&dir).unwrap_err();
        assert!(format!("{error:#}").contains("identity secret exceeds its size limit"));
        assert!(!error
            .to_string()
            .contains(&dir.to_string_lossy().to_string()));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn configured_invite_must_match_state_topic() {
        let invite = Invite {
            topic: TopicId::from_bytes(rand::random()),
            bootstrap_peers: vec![iroh::EndpointAddr::new(SecretKey::generate().public())],
        };
        let state = State {
            schema_version: CONFIG_SCHEMA_VERSION,
            advertise_self: false,
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
    fn nonadvertising_state_requires_an_invite() {
        let state = State {
            schema_version: CONFIG_SCHEMA_VERSION,
            advertise_self: false,
            topic: TopicId::from_bytes(rand::random()).to_string(),
            invite: None,
            identity: None,
        };
        assert!(state
            .validate()
            .unwrap_err()
            .to_string()
            .contains("advertise"));
    }

    #[test]
    fn advertising_state_rejects_a_full_invite_without_its_identity() {
        let invite = Invite {
            topic: TopicId::from_bytes(rand::random()),
            bootstrap_peers: (0..crate::invite::MAX_BOOTSTRAP_PEERS)
                .map(|_| iroh::EndpointAddr::new(SecretKey::generate().public()))
                .collect(),
        };
        let listed_identity = invite.bootstrap_peers[0].id;
        let state = State::from_invite(invite.to_string(), &invite, true);

        state.validate_for_identity(listed_identity).unwrap();
        let error = state
            .validate_for_identity(SecretKey::generate().public())
            .unwrap_err();
        assert!(error.to_string().contains("cannot advertise self"));
    }

    #[test]
    fn state_save_preserves_identity_binding_and_is_atomic() {
        let dir = test_dir();
        State::new_topic().save_new(&dir, false).unwrap();
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

    #[test]
    fn config_bounds_truncation_and_future_versions_fail_closed() {
        let dir = test_dir();
        prepare_state_dir(&dir).unwrap();
        fs::write(dir.join(CONFIG_NAME), vec![b' '; MAX_CONFIG_BYTES + 1]).unwrap();
        let too_large = State::load(&dir).unwrap_err();
        assert_eq!(
            too_large
                .downcast_ref::<PersistentError>()
                .expect("typed persistent error")
                .kind(),
            crate::persistent::PersistentErrorKind::TooLarge
        );

        fs::write(dir.join(CONFIG_NAME), b"{\"schema_version\":1").unwrap();
        let truncated = State::load(&dir).unwrap_err();
        assert_eq!(
            truncated
                .downcast_ref::<PersistentError>()
                .expect("typed persistent error")
                .kind(),
            crate::persistent::PersistentErrorKind::Parse
        );

        let unversioned = serde_json::to_vec(&serde_json::json!({
            "advertise_self": true,
            "topic": TopicId::from_bytes([1; 32]).to_string(),
            "invite": null,
            "identity": null
        }))
        .unwrap();
        fs::write(dir.join(CONFIG_NAME), &unversioned).unwrap();
        let unsupported = State::load(&dir).unwrap_err();
        assert_eq!(
            unsupported
                .downcast_ref::<PersistentError>()
                .expect("typed persistent error")
                .kind(),
            crate::persistent::PersistentErrorKind::UnsupportedVersion
        );
        assert_eq!(fs::read(dir.join(CONFIG_NAME)).unwrap(), unversioned);

        let future = serde_json::to_vec(&serde_json::json!({"schema_version":256})).unwrap();
        fs::write(dir.join(CONFIG_NAME), &future).unwrap();
        let lock = StateLock::acquire(&dir).unwrap();
        let error = State::load_locked(&dir, &lock).unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<PersistentError>()
                .expect("typed persistent error")
                .kind(),
            crate::persistent::PersistentErrorKind::UnsupportedVersion
        );
        assert_eq!(fs::read(dir.join(CONFIG_NAME)).unwrap(), future);
        drop(lock);
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn state_files_retain_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = test_dir();
        State::new_topic().save_new(&dir, false).unwrap();
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
