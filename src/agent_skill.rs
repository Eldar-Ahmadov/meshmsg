use crate::cli::SkillAgent;
use anyhow::{bail, Context, Result};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

const SKILL_NAME: &str = "meshmsg";
const SKILL_DOCUMENT: &str = include_str!("../skills/meshmsg/SKILL.md");

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct InstallResult {
    pub(crate) path: PathBuf,
    pub(crate) changed: bool,
}

pub(crate) fn install(agent: SkillAgent, force: bool) -> Result<InstallResult> {
    let home = dirs::home_dir().context("cannot determine the user home directory")?;
    install_in_home(&home, agent, force)
}

fn install_in_home(home: &Path, agent: SkillAgent, force: bool) -> Result<InstallResult> {
    let skill_dir = agent.skills_dir(home).join(SKILL_NAME);
    fs::create_dir_all(&skill_dir)
        .with_context(|| format!("create agent skill directory {}", skill_dir.display()))?;
    let destination = skill_dir.join("SKILL.md");
    let replace = match fs::symlink_metadata(&destination) {
        Ok(metadata) => {
            if metadata.file_type().is_file() {
                let current = fs::read(&destination)
                    .with_context(|| format!("read existing skill {}", destination.display()))?;
                if current == SKILL_DOCUMENT.as_bytes() {
                    return Ok(InstallResult {
                        path: destination,
                        changed: false,
                    });
                }
            }
            if metadata.file_type().is_dir() {
                bail!(
                    "cannot replace skill document {} because it is a directory",
                    destination.display()
                );
            }
            if !force {
                bail!(
                    "{} already exists and differs from the bundled meshmsg skill; rerun with --force to replace it",
                    destination.display()
                );
            }
            true
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => {
            return Err(error)
                .with_context(|| format!("inspect skill destination {}", destination.display()))
        }
    };

    atomic_write(&skill_dir, &destination, SKILL_DOCUMENT.as_bytes(), replace)?;
    Ok(InstallResult {
        path: destination,
        changed: true,
    })
}

fn atomic_write(dir: &Path, destination: &Path, contents: &[u8], replace: bool) -> Result<()> {
    let temporary = dir.join(format!(
        ".SKILL.md.tmp-{}-{:016x}",
        std::process::id(),
        rand::random::<u64>()
    ));
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .with_context(|| format!("create temporary skill {}", temporary.display()))?;
        file.write_all(contents)
            .with_context(|| format!("write temporary skill {}", temporary.display()))?;
        file.sync_all()
            .with_context(|| format!("sync temporary skill {}", temporary.display()))?;
        drop(file);

        if replace {
            atomic_replace(&temporary, destination)?;
        } else {
            fs::hard_link(&temporary, destination).with_context(|| {
                format!(
                    "install skill at {}; a file may already exist",
                    destination.display()
                )
            })?;
            fs::remove_file(&temporary)
                .with_context(|| format!("remove temporary skill {}", temporary.display()))?;
        }
        sync_dir(dir)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(unix)]
fn atomic_replace(source: &Path, destination: &Path) -> Result<()> {
    fs::rename(source, destination).with_context(|| {
        format!(
            "replace skill {} with {}",
            destination.display(),
            source.display()
        )
    })
}

#[cfg(windows)]
fn atomic_replace(source: &Path, destination: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };

    let source_wide = source
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let destination_wide = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let moved = unsafe {
        MoveFileExW(
            source_wide.as_ptr(),
            destination_wide.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if moved == 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| {
            format!(
                "replace skill {} with {}",
                destination.display(),
                source.display()
            )
        });
    }
    Ok(())
}

fn sync_dir(dir: &Path) -> Result<()> {
    #[cfg(unix)]
    fs::File::open(dir)
        .and_then(|directory| directory.sync_all())
        .with_context(|| format!("sync agent skill directory {}", dir.display()))?;
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temporary_home() -> PathBuf {
        std::env::temp_dir().join(format!(
            "meshmsg-agent-skill-test-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ))
    }

    #[test]
    fn target_paths_are_agent_specific() {
        let home = Path::new("home");
        assert_eq!(
            SkillAgent::Shared.skills_dir(home),
            home.join(".agents/skills")
        );
        assert_eq!(
            SkillAgent::Codex.skills_dir(home),
            home.join(".agents/skills")
        );
        assert_eq!(
            SkillAgent::Claude.skills_dir(home),
            home.join(".claude/skills")
        );
        assert_eq!(
            SkillAgent::Pi.skills_dir(home),
            home.join(".pi/agent/skills")
        );
    }

    #[test]
    fn install_is_idempotent_and_requires_force_for_different_content() {
        let home = temporary_home();
        let installed = install_in_home(&home, SkillAgent::Shared, false).unwrap();
        assert!(installed.changed);
        assert_eq!(fs::read_to_string(&installed.path).unwrap(), SKILL_DOCUMENT);

        let unchanged = install_in_home(&home, SkillAgent::Shared, false).unwrap();
        assert!(!unchanged.changed);
        assert_eq!(unchanged.path, installed.path);

        fs::write(&installed.path, "local changes").unwrap();
        let error = install_in_home(&home, SkillAgent::Shared, false).unwrap_err();
        assert!(error.to_string().contains("--force"));
        assert_eq!(
            fs::read_to_string(&installed.path).unwrap(),
            "local changes"
        );

        let replaced = install_in_home(&home, SkillAgent::Shared, true).unwrap();
        assert!(replaced.changed);
        assert_eq!(fs::read_to_string(&replaced.path).unwrap(), SKILL_DOCUMENT);
        fs::remove_dir_all(home).unwrap();
    }
}
