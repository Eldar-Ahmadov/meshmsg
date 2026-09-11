use crate::{
    config::{atomic_write, State, StateLock},
    persistent,
};
use anyhow::{Context, Result};
use iroh::PublicKey;
use serde::{Deserialize, Serialize};
#[cfg(test)]
use std::fs;
use std::{path::Path, str::FromStr};

const ALIAS_CONFIG_NAME: &str = "alias.json";
const ALIAS_CONFIG_VERSION: u8 = 1;
pub(crate) const MAX_ALIAS_BYTES: usize = 63;
pub(crate) const MAX_ALIAS_CONFIG_BYTES: usize = 4 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct AliasConfig {
    version: u8,
    /// Binds this file to the identity selected by config.json. Legacy missing
    /// files are safe opt-out; an existing unbound/mismatched file is rejected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    identity: Option<String>,
    /// The short hostname captured explicitly at init/join or reset-hostname time.
    hostname: Option<String>,
    /// A user override. `None` means use the captured hostname when enabled.
    alias: Option<String>,
    enabled: bool,
}

#[derive(Deserialize)]
struct AliasVersionProbe {
    version: u64,
}

impl AliasConfig {
    /// Capture and validate before a potentially destructive `--force` state replacement.
    pub(crate) fn prepare(enabled: bool) -> Result<Self> {
        let hostname = if enabled {
            Some(short_hostname()?)
        } else {
            None
        };
        Ok(Self {
            version: ALIAS_CONFIG_VERSION,
            identity: None,
            hostname,
            alias: None,
            enabled,
        })
    }

    pub(crate) fn bind_identity(&mut self, identity: PublicKey) {
        self.identity = Some(identity.to_string());
    }

    pub(crate) fn install_locked(&self, dir: &Path, _lock: &StateLock) -> Result<()> {
        self.save_unlocked(dir)
    }

    /// Missing alias.json is a compatible, opted-out legacy configuration.
    #[cfg(test)]
    pub(crate) fn load(dir: &Path) -> Result<Self> {
        Self::load_with_presence(dir).map(|(value, _present)| value)
    }

    fn load_with_presence(dir: &Path) -> Result<(Self, bool)> {
        let path = dir.join(ALIAS_CONFIG_NAME);
        let Some(bytes) = persistent::read_optional_file_bounded(
            &path,
            ALIAS_CONFIG_NAME,
            MAX_ALIAS_CONFIG_BYTES,
        )?
        else {
            return Ok((
                Self {
                    version: ALIAS_CONFIG_VERSION,
                    identity: None,
                    hostname: None,
                    alias: None,
                    enabled: false,
                },
                false,
            ));
        };
        let probe: AliasVersionProbe = persistent::parse_json(&bytes, ALIAS_CONFIG_NAME)?;
        if probe.version != u64::from(ALIAS_CONFIG_VERSION) {
            return Err(crate::persistent::PersistentError::unsupported_version(
                "alias configuration",
                probe.version,
            )
            .into());
        }
        let value: Self = persistent::parse_json(&bytes, ALIAS_CONFIG_NAME)?;
        if let Some(identity) = &value.identity {
            let parsed = PublicKey::from_str(identity).context("invalid identity in alias.json")?;
            anyhow::ensure!(
                parsed.to_string() == *identity,
                "alias identity must use its canonical public-key encoding"
            );
        }
        if let Some(hostname) = &value.hostname {
            validate_alias(hostname)?;
        }
        if let Some(alias) = &value.alias {
            validate_alias(alias)?;
        }
        Ok((value, true))
    }

    pub(crate) fn load_for_identity(dir: &Path, identity: PublicKey) -> Result<Self> {
        let (value, present) = Self::load_with_presence(dir)?;
        if present {
            let expected = identity.to_string();
            anyhow::ensure!(
                value.identity.as_deref() == Some(expected.as_str()),
                "alias configuration does not match the selected identity"
            );
        }
        Ok(value)
    }

    pub(crate) fn effective(&self) -> Option<&str> {
        if !self.enabled {
            return None;
        }
        self.alias.as_deref().or(self.hostname.as_deref())
    }

    pub(crate) fn hostname(&self) -> Option<&str> {
        self.hostname.as_deref()
    }

    pub(crate) fn custom(&self) -> Option<&str> {
        self.alias.as_deref()
    }

    pub(crate) fn enabled(&self) -> bool {
        self.enabled
    }

    fn save_unlocked(&self, dir: &Path) -> Result<()> {
        let mut contents = serde_json::to_vec_pretty(self).context("write alias.json")?;
        contents.push(b'\n');
        atomic_write(dir, ALIAS_CONFIG_NAME, &contents, 0o600).context("install alias.json")
    }

    fn mutate(dir: &Path, update: impl FnOnce(&mut Self) -> Result<()>) -> Result<Self> {
        let lock = StateLock::acquire(dir)?;
        let (state, secret) = State::load_locked(dir, &lock)?;
        state.validate_for_identity(secret.public())?;
        let mut config = Self::load_for_identity(dir, secret.public())?;
        update(&mut config)?;
        config.bind_identity(secret.public());
        config.install_locked(dir, &lock)?;
        drop(lock);
        Ok(config)
    }

    pub(crate) fn set(dir: &Path, alias: &str) -> Result<Self> {
        let alias = normalize_alias(alias)?;
        Self::mutate(dir, move |config| {
            config.alias = Some(alias);
            config.enabled = true;
            Ok(())
        })
    }

    /// Explicit alias-advertising opt-out. The captured hostname remains local
    /// so `show` can explain the state; reset-hostname is the explicit way back.
    pub(crate) fn clear(dir: &Path) -> Result<Self> {
        Self::mutate(dir, |config| {
            config.alias = None;
            config.enabled = false;
            Ok(())
        })
    }

    pub(crate) fn reset_hostname(dir: &Path) -> Result<Self> {
        let hostname = short_hostname()?;
        Self::mutate(dir, move |config| {
            config.hostname = Some(hostname);
            config.alias = None;
            config.enabled = true;
            Ok(())
        })
    }
}

pub(crate) fn normalize_alias(value: &str) -> Result<String> {
    let normalized = value.to_ascii_lowercase();
    validate_alias(&normalized)?;
    Ok(normalized)
}

pub(crate) fn validate_alias(value: &str) -> Result<()> {
    anyhow::ensure!(!value.is_empty(), "alias cannot be empty");
    anyhow::ensure!(
        value.len() <= MAX_ALIAS_BYTES,
        "alias exceeds {MAX_ALIAS_BYTES} bytes"
    );
    anyhow::ensure!(value.is_ascii(), "alias must contain only ASCII characters");
    anyhow::ensure!(
        value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'),
        "alias may contain only ASCII letters, digits, and hyphens"
    );
    anyhow::ensure!(
        value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
            && value
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric),
        "alias must start and end with a letter or digit"
    );
    anyhow::ensure!(
        value.bytes().all(|byte| !byte.is_ascii_uppercase()),
        "alias must be lowercase"
    );
    Ok(())
}

fn short_hostname() -> Result<String> {
    let hostname = hostname::get().context("read OS hostname")?;
    let hostname = hostname
        .to_str()
        .context("OS hostname is not valid UTF-8")?
        .split('.')
        .next()
        .context("OS hostname is empty")?;
    normalize_alias(hostname).context("OS short hostname is not a valid node alias")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_dir() -> std::path::PathBuf {
        std::env::temp_dir().join(format!("meshmsg-alias-test-{}", rand::random::<u64>()))
    }

    #[test]
    fn validation_is_bounded_canonical_and_hostname_safe() {
        for valid in ["a", "node-1", "abc123"] {
            assert!(validate_alias(valid).is_ok(), "{valid}");
        }
        for invalid in ["", "A", "-node", "node-", "node.local", "node_1", "é"] {
            assert!(validate_alias(invalid).is_err(), "{invalid}");
        }
        assert!(validate_alias(&"a".repeat(MAX_ALIAS_BYTES)).is_ok());
        assert!(validate_alias(&"a".repeat(MAX_ALIAS_BYTES + 1)).is_err());
        assert_eq!(normalize_alias("My-Node").unwrap(), "my-node");
    }

    #[test]
    fn override_clear_and_opt_out_are_persistent() {
        let dir = test_dir();
        let state = State::new_topic();
        let mut alias = AliasConfig {
            version: ALIAS_CONFIG_VERSION,
            identity: None,
            hostname: Some("captured-host".into()),
            alias: None,
            enabled: true,
        };
        state.save_new_with_alias(&dir, false, &mut alias).unwrap();

        let set = AliasConfig::set(&dir, "My-Node").unwrap();
        assert_eq!(set.effective(), Some("my-node"));
        let cleared = AliasConfig::clear(&dir).unwrap();
        assert_eq!(cleared.hostname(), Some("captured-host"));
        assert_eq!(cleared.effective(), None);
        assert!(!cleared.enabled());
        assert_eq!(AliasConfig::load(&dir).unwrap().effective(), None);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(dir.join(ALIAS_CONFIG_NAME))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn stale_alias_file_fails_closed_after_identity_replacement() {
        let dir = test_dir();
        let mut alias = AliasConfig {
            version: ALIAS_CONFIG_VERSION,
            identity: None,
            hostname: Some("old-host".into()),
            alias: Some("old-custom".into()),
            enabled: true,
        };
        State::new_topic()
            .save_new_with_alias(&dir, false, &mut alias)
            .unwrap();

        // Simulate a crash after config.json replacement but before alias.json
        // replacement by using the legacy state-only helper.
        let new_peer = State::new_topic().save_new(&dir, true).unwrap();
        let new_peer = PublicKey::from_str(&new_peer).unwrap();
        let error = AliasConfig::load_for_identity(&dir, new_peer).unwrap_err();
        assert!(error.to_string().contains("does not match"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn bounded_alias_state_rejects_truncation_oversize_and_future_versions() {
        let dir = test_dir();
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join(ALIAS_CONFIG_NAME);

        fs::write(&path, b"{\"version\":1").unwrap();
        assert!(AliasConfig::load(&dir)
            .unwrap_err()
            .to_string()
            .contains("could not parse alias.json"));

        fs::write(&path, vec![b' '; MAX_ALIAS_CONFIG_BYTES + 1]).unwrap();
        assert!(AliasConfig::load(&dir)
            .unwrap_err()
            .to_string()
            .contains("exceeds its size limit"));

        fs::write(
            &path,
            br#"{"version":256,"identity":null,"hostname":null,"alias":null,"enabled":false}"#,
        )
        .unwrap();
        assert!(AliasConfig::load(&dir)
            .unwrap_err()
            .to_string()
            .contains("unsupported alias configuration schema version 256"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn dangling_alias_link_is_not_treated_as_legacy_absence() {
        use std::os::unix::fs::symlink;
        let dir = test_dir();
        fs::create_dir_all(&dir).unwrap();
        symlink(dir.join("missing"), dir.join(ALIAS_CONFIG_NAME)).unwrap();
        assert!(AliasConfig::load(&dir).is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn missing_file_is_legacy_opt_out() {
        let dir = test_dir();
        fs::create_dir_all(&dir).unwrap();
        let config = AliasConfig::load(&dir).unwrap();
        assert!(!config.enabled());
        assert_eq!(config.effective(), None);
        fs::remove_dir_all(dir).unwrap();
    }
}
