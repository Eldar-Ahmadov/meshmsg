use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, Metadata, OpenOptions},
    io::{self, Read, Write},
    path::{Component, Path, PathBuf},
};

#[cfg(unix)]
use rustix::fs::{openat, Dir, Mode, OFlags, CWD};
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::os::unix::ffi::OsStrExt as _;
#[cfg(windows)]
use std::os::windows::{
    ffi::OsStrExt as _,
    fs::{MetadataExt as _, OpenOptionsExt as _},
};
#[cfg(unix)]
use std::{ffi::CString, os::unix::fs::OpenOptionsExt as _};

pub const DEFAULT_MAX_ATTACHMENT_BYTES: u64 = 4 * 1024 * 1024 * 1024;
pub const MAX_ARCHIVE_ENTRIES: usize = 10_000;
const MAX_ARCHIVE_DEPTH: usize = 64;
const MAX_COMPONENT_BYTES: usize = 100;
const MAX_ARCHIVE_PATH_BYTES: usize = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttachmentKind {
    File,
    DirectoryTarV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentOffer {
    pub offer_id: String,
    pub kind: AttachmentKind,
    pub name: String,
    pub size: u64,
    pub ticket: String,
}

pub fn validate_display_name(name: &str) -> Result<()> {
    validate_component(name)?;
    anyhow::ensure!(name.len() <= 255, "attachment name is too long");
    Ok(())
}

fn validate_component(component: &str) -> Result<()> {
    anyhow::ensure!(!component.is_empty(), "empty path component");
    anyhow::ensure!(
        component != "." && component != "..",
        "unsafe path component"
    );
    anyhow::ensure!(
        component.len() <= MAX_COMPONENT_BYTES,
        "path component is too long"
    );
    anyhow::ensure!(
        !component.chars().any(char::is_control),
        "path component contains a control character"
    );
    anyhow::ensure!(
        !component.contains('/') && !component.contains('\\'),
        "path component contains a separator"
    );
    anyhow::ensure!(
        !component
            .chars()
            .any(|character| matches!(character, '<' | '>' | ':' | '"' | '|' | '?' | '*')),
        "path component contains a Windows-forbidden character"
    );
    anyhow::ensure!(
        !component.ends_with('.') && !component.ends_with(' '),
        "path component has a non-portable suffix"
    );
    let stem = component.split('.').next().unwrap_or(component);
    anyhow::ensure!(
        !matches!(
            stem.to_ascii_uppercase().as_str(),
            "CON"
                | "PRN"
                | "AUX"
                | "NUL"
                | "COM1"
                | "COM2"
                | "COM3"
                | "COM4"
                | "COM5"
                | "COM6"
                | "COM7"
                | "COM8"
                | "COM9"
                | "LPT1"
                | "LPT2"
                | "LPT3"
                | "LPT4"
                | "LPT5"
                | "LPT6"
                | "LPT7"
                | "LPT8"
                | "LPT9"
        ),
        "path component uses a reserved device name"
    );
    Ok(())
}

fn canonical_relative(path: &Path) -> Result<String> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => {
                let value = value.to_str().context("attachment paths must be UTF-8")?;
                validate_component(value)?;
                parts.push(value);
            }
            _ => anyhow::bail!("attachment path is not relative and normalized"),
        }
    }
    anyhow::ensure!(!parts.is_empty(), "empty attachment path");
    anyhow::ensure!(
        parts.len() <= MAX_ARCHIVE_DEPTH,
        "attachment path is too deep"
    );
    let path = parts.join("/");
    anyhow::ensure!(
        path.len() <= MAX_ARCHIVE_PATH_BYTES,
        "attachment path is too long"
    );
    Ok(path)
}

#[cfg(not(unix))]
#[derive(Debug)]
struct SourceEntry {
    source: PathBuf,
    archive_path: String,
    directory: bool,
    size: u64,
}

#[cfg(windows)]
fn is_windows_reparse_point(metadata: &Metadata) -> bool {
    metadata.file_attributes()
        & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
        != 0
}

#[cfg(windows)]
fn open_directory_no_follow(path: &Path) -> Result<File> {
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
    };

    let file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .with_context(|| {
            format!(
                "open directory without following reparse points {}",
                path.display()
            )
        })?;
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.is_dir() && !is_windows_reparse_point(&metadata),
        "shared directory is a reparse point or is not a directory: {}",
        path.display()
    );
    Ok(file)
}

#[cfg(not(unix))]
fn collect_entries(
    root: &Path,
    current: &Path,
    entries: &mut Vec<SourceEntry>,
    total: &mut u64,
    max_attachment_bytes: u64,
    #[cfg(windows)] directory_locks: &mut Vec<File>,
) -> Result<()> {
    // Denying FILE_SHARE_DELETE on each no-follow directory handle prevents
    // replacement until all collected files have been opened for archiving.
    #[cfg(windows)]
    directory_locks.push(open_directory_no_follow(current)?);
    let mut children = fs::read_dir(current)
        .with_context(|| format!("read directory {}", current.display()))?
        .collect::<io::Result<Vec<_>>>()?;
    children.sort_by_key(|entry| entry.file_name());
    for child in children {
        anyhow::ensure!(
            entries.len() < MAX_ARCHIVE_ENTRIES,
            "directory contains too many entries"
        );
        let path = child.path();
        let metadata =
            fs::symlink_metadata(&path).with_context(|| format!("inspect {}", path.display()))?;
        #[cfg(windows)]
        anyhow::ensure!(
            !is_windows_reparse_point(&metadata),
            "reparse points are not supported: {}",
            path.display()
        );
        anyhow::ensure!(
            !metadata.file_type().is_symlink(),
            "symbolic links are not supported: {}",
            path.display()
        );
        let relative = path
            .strip_prefix(root)
            .context("build relative archive path")?;
        let archive_path = canonical_relative(relative)?;
        if metadata.is_dir() {
            entries.push(SourceEntry {
                source: path.clone(),
                archive_path,
                directory: true,
                size: 0,
            });
            collect_entries(
                root,
                &path,
                entries,
                total,
                max_attachment_bytes,
                #[cfg(windows)]
                directory_locks,
            )?;
        } else if metadata.is_file() {
            *total = total
                .checked_add(metadata.len())
                .context("directory size overflow")?;
            anyhow::ensure!(
                *total <= max_attachment_bytes,
                "directory contents exceed the {}-byte limit",
                max_attachment_bytes
            );
            entries.push(SourceEntry {
                source: path,
                archive_path,
                directory: false,
                size: metadata.len(),
            });
        } else {
            anyhow::bail!("special files are not supported: {}", path.display());
        }
    }
    Ok(())
}

#[cfg(unix)]
fn append_directory_from_handle<W: Write>(
    builder: &mut tar::Builder<W>,
    directory: &File,
    prefix: &Path,
    count: &mut usize,
    total: &mut u64,
    max_attachment_bytes: u64,
) -> Result<()> {
    let mut names = Dir::read_from(directory)
        .context("read shared directory handle")?
        .map(|entry| {
            let entry = entry.context("read shared directory entry")?;
            CString::new(entry.file_name().to_bytes()).context("directory entry contains null")
        })
        .collect::<Result<Vec<_>>>()?;
    names.retain(|name| name.as_bytes() != b"." && name.as_bytes() != b"..");
    names.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));

    for name in names {
        *count += 1;
        anyhow::ensure!(
            *count <= MAX_ARCHIVE_ENTRIES,
            "directory contains too many entries"
        );
        let name_str =
            std::str::from_utf8(name.as_bytes()).context("attachment paths must be UTF-8")?;
        let relative_path = prefix.join(name_str);
        let archive_path = canonical_relative(&relative_path)?;
        let fd = openat(
            directory,
            name.as_c_str(),
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .with_context(|| format!("open shared entry without following links {archive_path}"))?;
        let mut child = File::from(fd);
        let metadata = child.metadata()?;
        if metadata.is_dir() {
            let mut header = normalized_header(&archive_path, 0, true)?;
            builder.append_data(&mut header, &archive_path, io::empty())?;
            append_directory_from_handle(
                builder,
                &child,
                &relative_path,
                count,
                total,
                max_attachment_bytes,
            )?;
        } else if metadata.is_file() {
            let size = metadata.len();
            *total = total.checked_add(size).context("directory size overflow")?;
            anyhow::ensure!(
                *total <= max_attachment_bytes,
                "directory contents exceed the {}-byte limit",
                max_attachment_bytes
            );
            let mut header = normalized_header(&archive_path, size, false)?;
            builder.append_data(&mut header, &archive_path, &mut child)?;
            anyhow::ensure!(
                child.metadata()?.len() == size,
                "file changed while archiving: {archive_path}"
            );
        } else {
            anyhow::bail!("special files are not supported: {archive_path}");
        }
    }
    Ok(())
}

fn open_regular_file_no_follow(path: &Path) -> Result<(File, Metadata)> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW);
    #[cfg(windows)]
    options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    let file = options.open(path).with_context(|| {
        format!(
            "open regular file without following links {}",
            path.display()
        )
    })?;
    let metadata = file.metadata()?;
    #[cfg(windows)]
    anyhow::ensure!(
        !is_windows_reparse_point(&metadata),
        "shared path is a reparse point: {}",
        path.display()
    );
    anyhow::ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "shared path is not a regular file: {}",
        path.display()
    );
    Ok((file, metadata))
}

fn normalized_header(path: &str, size: u64, directory: bool) -> Result<tar::Header> {
    let mut header = tar::Header::new_gnu();
    header.set_path(path).context("set archive path")?;
    header.set_size(size);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_mode(if directory { 0o755 } else { 0o644 });
    header.set_entry_type(if directory {
        tar::EntryType::Directory
    } else {
        tar::EntryType::Regular
    });
    header.set_cksum();
    Ok(header)
}

fn write_deterministic_tar<W: Write>(
    source: &Path,
    writer: W,
    max_attachment_bytes: u64,
) -> Result<W> {
    let mut builder = tar::Builder::new(writer);
    builder.mode(tar::HeaderMode::Deterministic);

    #[cfg(unix)]
    {
        let root = File::from(
            openat(
                CWD,
                source,
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
                Mode::empty(),
            )
            .context("open shared directory without following links")?,
        );
        let mut count = 0;
        let mut total = 0;
        append_directory_from_handle(
            &mut builder,
            &root,
            Path::new(""),
            &mut count,
            &mut total,
            max_attachment_bytes,
        )?;
    }

    #[cfg(not(unix))]
    {
        let metadata = fs::symlink_metadata(source).context("inspect shared directory")?;
        anyhow::ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "shared path is not a directory"
        );
        let mut entries = Vec::new();
        let mut total = 0_u64;
        #[cfg(windows)]
        let mut directory_locks = Vec::new();
        collect_entries(
            source,
            source,
            &mut entries,
            &mut total,
            max_attachment_bytes,
            #[cfg(windows)]
            &mut directory_locks,
        )?;
        entries.sort_by(|a, b| a.archive_path.as_bytes().cmp(b.archive_path.as_bytes()));
        for entry in entries {
            let mut header = normalized_header(&entry.archive_path, entry.size, entry.directory)?;
            if entry.directory {
                builder.append_data(&mut header, &entry.archive_path, io::empty())?;
            } else {
                let (mut file, before) = open_regular_file_no_follow(&entry.source)?;
                anyhow::ensure!(
                    before.len() == entry.size,
                    "file changed while archiving: {}",
                    entry.source.display()
                );
                builder.append_data(&mut header, &entry.archive_path, &mut file)?;
                anyhow::ensure!(
                    file.metadata()?.len() == entry.size,
                    "file changed while archiving: {}",
                    entry.source.display()
                );
            }
        }
    }

    builder.finish()?;
    Ok(builder.into_inner()?)
}

pub fn create_deterministic_tar(
    source: &Path,
    output: &Path,
    max_attachment_bytes: u64,
) -> Result<u64> {
    let output_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(output)
        .with_context(|| format!("create staging archive {}", output.display()))?;
    let file = write_deterministic_tar(source, output_file, max_attachment_bytes)?;
    file.sync_all()?;
    let size = file.metadata()?.len();
    anyhow::ensure!(
        size <= max_attachment_bytes,
        "archive exceeds the {}-byte limit",
        max_attachment_bytes
    );
    Ok(size)
}

struct DigestWriter {
    digest: Sha256,
    bytes: u64,
}

impl Write for DigestWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.digest.update(buffer);
        self.bytes = self
            .bytes
            .checked_add(buffer.len() as u64)
            .ok_or_else(|| io::Error::other("digest size overflow"))?;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn regular_file_digest(
    source: &Path,
    kind_domain: &[u8],
    max_attachment_bytes: u64,
) -> Result<String> {
    let metadata = fs::symlink_metadata(source)
        .with_context(|| format!("inspect shared path {}", source.display()))?;
    anyhow::ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "shared path is not a regular file"
    );
    anyhow::ensure!(
        metadata.len() <= max_attachment_bytes,
        "file exceeds the {}-byte limit",
        max_attachment_bytes
    );
    let mut writer = DigestWriter {
        digest: Sha256::new(),
        bytes: 0,
    };
    writer.digest.update(b"meshmsg-share-source-v1\0");
    writer.digest.update(kind_domain);
    let (mut file, before) = open_regular_file_no_follow(source)?;
    anyhow::ensure!(before.len() == metadata.len(), "file changed while hashing");
    io::copy(&mut file, &mut writer)?;
    anyhow::ensure!(
        writer.bytes == metadata.len() && file.metadata()?.len() == metadata.len(),
        "file changed while hashing"
    );
    Ok(data_encoding::HEXLOWER.encode(&writer.digest.finalize()))
}

pub fn staged_share_digest(
    staged: &Path,
    directory: bool,
    max_attachment_bytes: u64,
) -> Result<String> {
    regular_file_digest(
        staged,
        if directory {
            b"directory_tar_v1\0"
        } else {
            b"file\0"
        },
        max_attachment_bytes,
    )
}

pub fn share_source_digest(source: &Path, max_attachment_bytes: u64) -> Result<String> {
    let metadata = fs::symlink_metadata(source)
        .with_context(|| format!("inspect shared path {}", source.display()))?;
    if metadata.is_file() && !metadata.file_type().is_symlink() {
        return regular_file_digest(source, b"file\0", max_attachment_bytes);
    }
    let mut writer = DigestWriter {
        digest: Sha256::new(),
        bytes: 0,
    };
    writer.digest.update(b"meshmsg-share-source-v1\0");
    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        writer.digest.update(b"directory_tar_v1\0");
        writer = write_deterministic_tar(source, writer, max_attachment_bytes)?;
        anyhow::ensure!(
            writer.bytes <= max_attachment_bytes,
            "archive exceeds the {}-byte limit",
            max_attachment_bytes
        );
    } else {
        anyhow::bail!("shared path is not a regular file or directory");
    }
    Ok(data_encoding::HEXLOWER.encode(&writer.digest.finalize()))
}

fn unique_staging_path(parent: &Path, suffix: &str) -> PathBuf {
    loop {
        let path = parent.join(format!(
            ".meshmsg-part-{:016x}{suffix}",
            rand::random::<u64>()
        ));
        if !path.exists() {
            return path;
        }
    }
}

pub fn staging_file_near(destination: &Path, suffix: &str) -> Result<PathBuf> {
    let parent = destination.parent().unwrap_or_else(|| Path::new("."));
    let metadata = fs::metadata(parent)
        .with_context(|| format!("output parent does not exist: {}", parent.display()))?;
    anyhow::ensure!(
        metadata.is_dir(),
        "output parent is not a directory: {}",
        parent.display()
    );
    Ok(unique_staging_path(parent, suffix))
}

fn state_staging_name(name: &str) -> bool {
    let Some(rest) = name.strip_prefix(".meshmsg-part-") else {
        return false;
    };
    let Some((id, suffix)) = rest.split_once('.') else {
        return false;
    };
    id.len() == 16
        && id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && matches!(suffix, "blob" | "tar")
}

/// Removes only regular share-staging files in meshmsg's owner-only state root.
/// Arbitrary output directories are intentionally never scanned.
pub fn cleanup_stale_state_staging(state_dir: &Path) -> Result<usize> {
    let mut removed = 0;
    for item in fs::read_dir(state_dir)
        .with_context(|| format!("inspect state staging in {}", state_dir.display()))?
    {
        let item = item?;
        let Some(name) = item.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if !state_staging_name(&name) {
            continue;
        }
        let metadata = fs::symlink_metadata(item.path())?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            continue;
        }
        fs::remove_file(item.path())
            .with_context(|| format!("remove stale state staging file {name}"))?;
        removed += 1;
    }
    if removed != 0 {
        sync_directory(state_dir)?;
    }
    Ok(removed)
}

/// Owns a staging path so detached blocking work cleans up its output on drop.
pub struct StagedFile(Option<PathBuf>);

impl StagedFile {
    pub fn new(path: PathBuf) -> Self {
        Self(Some(path))
    }

    pub fn path(&self) -> &Path {
        self.0.as_deref().expect("staged file path was consumed")
    }

    /// Removes the staging name after the destination has committed.
    pub fn cleanup(mut self) -> Result<()> {
        let path = self.0.take().expect("staged file path was consumed");
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(error) => {
                // Restore ownership so Drop performs one final best-effort retry.
                self.0 = Some(path.clone());
                Err(error).with_context(|| format!("remove staging file {}", path.display()))
            }
        }
    }
}

impl Drop for StagedFile {
    fn drop(&mut self) {
        if let Some(path) = &self.0 {
            let _ = fs::remove_file(path);
        }
    }
}

/// Flushes an exported file before it participates in the durable commit.
pub fn sync_staged_file(staging: &Path) -> Result<()> {
    File::open(staging)
        .with_context(|| format!("open staged output {}", staging.display()))?
        .sync_all()
        .with_context(|| format!("sync staged output {}", staging.display()))
}

/// Atomically creates the destination name without removing the staging name.
pub fn link_file_no_clobber(staging: &Path, destination: &Path) -> Result<()> {
    anyhow::ensure!(
        !destination.exists(),
        "output already exists: {}",
        destination.display()
    );
    fs::hard_link(staging, destination).with_context(|| {
        format!(
            "install output without overwriting {}",
            destination.display()
        )
    })
}

struct RemoveOnDrop(PathBuf);
impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
        let _ = fs::remove_file(&self.0);
    }
}

fn rename_directory_no_replace(staging: &Path, destination: &Path) -> Result<()> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let staging_c = CString::new(staging.as_os_str().as_bytes())
            .context("staging path contains a null byte")?;
        let destination_c = CString::new(destination.as_os_str().as_bytes())
            .context("destination path contains a null byte")?;
        // renameat2 with RENAME_NOREPLACE is atomic and never replaces even an
        // empty directory created between validation and installation.
        // Use the syscall entry point because musl does not export renameat2
        // as a linkable libc symbol on all supported toolchains.
        let result = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                libc::AT_FDCWD,
                staging_c.as_ptr(),
                libc::AT_FDCWD,
                destination_c.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error())
                .with_context(|| format!("install extracted directory {}", destination.display()));
        }
        Ok(())
    }

    #[cfg(windows)]
    {
        use std::iter;
        use windows_sys::Win32::Storage::FileSystem::MoveFileExW;

        let staging_wide: Vec<u16> = staging
            .as_os_str()
            .encode_wide()
            .chain(iter::once(0))
            .collect();
        let destination_wide: Vec<u16> = destination
            .as_os_str()
            .encode_wide()
            .chain(iter::once(0))
            .collect();
        // Unlike std::fs::rename on Windows, omitting MOVEFILE_REPLACE_EXISTING
        // fails atomically when the destination already exists.
        let result = unsafe {
            MoveFileExW(
                staging_wide.as_ptr(),
                destination_wide.as_ptr(),
                windows_sys::Win32::Storage::FileSystem::MOVEFILE_WRITE_THROUGH,
            )
        };
        if result == 0 {
            return Err(io::Error::last_os_error())
                .with_context(|| format!("install extracted directory {}", destination.display()));
        }
        Ok(())
    }

    #[cfg(not(any(target_os = "linux", target_os = "android", windows)))]
    {
        let _ = staging;
        anyhow::bail!(
            "atomic no-replace directory installation is unsupported on this target; download the raw tar instead"
        )
    }
}

fn register_archive_path(
    seen: &mut BTreeMap<String, (String, bool)>,
    relative: &str,
    directory: bool,
) -> Result<()> {
    let parts: Vec<_> = relative.split('/').collect();
    for end in 1..=parts.len() {
        let path = parts[..end].join("/");
        let key = path.to_ascii_lowercase();
        let is_directory = end < parts.len() || directory;
        if let Some((previous, previous_is_directory)) = seen.get(&key) {
            anyhow::ensure!(previous == &path, "archive contains case-colliding paths");
            anyhow::ensure!(
                *previous_is_directory && is_directory && end < parts.len(),
                "archive contains duplicate or file/directory-colliding paths"
            );
        } else {
            seen.insert(key, (path, is_directory));
        }
    }
    Ok(())
}

pub fn extract_tar_no_clobber(
    archive_path: &Path,
    destination: &Path,
    max_attachment_bytes: u64,
) -> Result<()> {
    anyhow::ensure!(
        !destination.exists(),
        "output already exists: {}",
        destination.display()
    );
    let parent = destination.parent().unwrap_or_else(|| Path::new("."));
    let parent_metadata = fs::metadata(parent)
        .with_context(|| format!("output parent does not exist: {}", parent.display()))?;
    anyhow::ensure!(
        parent_metadata.is_dir(),
        "output parent is not a directory: {}",
        parent.display()
    );
    let staging = unique_staging_path(parent, "");
    fs::create_dir(&staging).context("create extraction staging directory")?;
    let guard = RemoveOnDrop(staging.clone());
    let file = File::open(archive_path).context("open downloaded archive")?;
    let mut archive = tar::Archive::new(file);
    let mut seen = BTreeMap::new();
    let mut count = 0_usize;
    let mut total = 0_u64;
    let entries = archive.entries().context("read archive entries")?.raw(true);
    for item in entries {
        let entry = item.context("read archive entry")?;
        count += 1;
        anyhow::ensure!(
            count <= MAX_ARCHIVE_ENTRIES,
            "archive contains too many entries"
        );
        let kind = entry.header().entry_type();
        anyhow::ensure!(
            kind.is_file() || kind.is_dir(),
            "archive contains a link or special entry"
        );
        let path = entry.path().context("decode archive path")?;
        let relative = canonical_relative(&path)?;
        register_archive_path(&mut seen, &relative, kind.is_dir())?;
        let target = staging.join(relative.replace('/', std::path::MAIN_SEPARATOR_STR));
        if kind.is_dir() {
            fs::create_dir_all(&target).context("create extracted directory")?;
        } else {
            let size = entry.header().size().context("read archive entry size")?;
            total = total.checked_add(size).context("archive size overflow")?;
            anyhow::ensure!(
                total <= max_attachment_bytes,
                "archive contents exceed the extraction limit"
            );
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent).context("create extracted parent")?;
            }
            let mut output = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&target)
                .context("create extracted file")?;
            let copied = io::copy(&mut entry.take(size + 1), &mut output)?;
            anyhow::ensure!(copied == size, "archive entry size mismatch");
            output.sync_all()?;
        }
    }
    // Files were synced as they were extracted. Sync every staging directory
    // before its root is atomically renamed so the installed tree is not only
    // namespace-atomic but also crash durable when the platform supports it.
    sync_directory_tree(&staging)?;
    anyhow::ensure!(
        !destination.exists(),
        "output already exists: {}",
        destination.display()
    );
    rename_directory_no_replace(&staging, destination)?;
    std::mem::forget(guard);
    Ok(())
}

/// Extracts an owned download staging archive and cleans it on every exit path.
pub fn extract_staged_tar_no_clobber(
    staging: &StagedFile,
    destination: &Path,
    max_attachment_bytes: u64,
) -> Result<()> {
    extract_tar_no_clobber(staging.path(), destination, max_attachment_bytes)
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .with_context(|| format!("open directory for sync {}", path.display()))?
        .sync_all()
        .with_context(|| format!("sync directory {}", path.display()))
}

#[cfg(windows)]
fn sync_directory(path: &Path) -> Result<()> {
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    OpenOptions::new()
        .write(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .with_context(|| format!("open directory for sync {}", path.display()))?
        .sync_all()
        .with_context(|| format!("sync directory {}", path.display()))
}

fn sync_directory_tree(root: &Path) -> Result<()> {
    for entry in fs::read_dir(root).with_context(|| format!("read directory {}", root.display()))? {
        let path = entry?.path();
        if fs::symlink_metadata(&path)?.is_dir() {
            sync_directory_tree(&path)?;
        }
    }
    sync_directory(root)
}

#[cfg(not(windows))]
fn sync_installed_file(path: &Path) -> Result<()> {
    File::open(path)
        .with_context(|| format!("open installed output {}", path.display()))?
        .sync_all()
        .with_context(|| format!("sync installed output {}", path.display()))
}

#[cfg(windows)]
fn sync_installed_file(path: &Path) -> Result<()> {
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    // FlushFileBuffers requires write access even though no content is changed.
    OpenOptions::new()
        .write(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .open(path)
        .with_context(|| format!("open installed output {}", path.display()))?
        .sync_all()
        .with_context(|| format!("sync installed output {}", path.display()))
}

/// Flushes installed content after the atomic no-clobber operation.
pub fn sync_installed_destination(destination: &Path, directory: bool) -> Result<()> {
    if directory {
        sync_directory(destination)
    } else {
        sync_installed_file(destination)
    }
}

/// Flushes the existing parent whose namespace gained the destination entry.
pub fn sync_output_parent(destination: &Path) -> Result<()> {
    sync_directory(destination.parent().unwrap_or_else(|| Path::new(".")))
}

pub fn file_name(path: &Path, directory: bool) -> Result<String> {
    let raw = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("shared path must have a UTF-8 file name")?;
    let name = if directory {
        format!("{raw}.tar")
    } else {
        raw.to_owned()
    };
    validate_display_name(&name)?;
    Ok(name)
}

pub fn copy_bounded(source: &Path, destination: &Path, max_attachment_bytes: u64) -> Result<u64> {
    let (mut input, metadata) = open_regular_file_no_follow(source)?;
    anyhow::ensure!(
        metadata.len() <= max_attachment_bytes,
        "file exceeds the {}-byte limit",
        max_attachment_bytes
    );
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(destination)
        .context("create staging file")?;
    let copied = io::copy(
        &mut Read::by_ref(&mut input).take(max_attachment_bytes.saturating_add(1)),
        &mut output,
    )?;
    anyhow::ensure!(
        copied <= max_attachment_bytes,
        "file exceeds the {}-byte limit",
        max_attachment_bytes
    );
    anyhow::ensure!(copied == metadata.len(), "file changed while being staged");
    anyhow::ensure!(
        input.metadata()?.len() == metadata.len(),
        "file changed while being staged"
    );
    output.flush()?;
    output.sync_all()?;
    Ok(copied)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(label: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("meshmsg-{label}-{:016x}", rand::random::<u64>()));
        fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn deterministic_tar_ignores_creation_order_and_mode() {
        let one = temp_dir("tar-one");
        let two = temp_dir("tar-two");
        fs::create_dir(one.join("empty")).unwrap();
        fs::write(one.join("b.txt"), b"b").unwrap();
        fs::write(one.join("a.txt"), b"a").unwrap();
        fs::write(two.join("a.txt"), b"a").unwrap();
        fs::write(two.join("b.txt"), b"b").unwrap();
        fs::create_dir(two.join("empty")).unwrap();
        let out_one = temp_dir("tar-out-one").join("one.tar");
        let out_two = temp_dir("tar-out-two").join("two.tar");
        create_deterministic_tar(&one, &out_one, DEFAULT_MAX_ATTACHMENT_BYTES).unwrap();
        create_deterministic_tar(&two, &out_two, DEFAULT_MAX_ATTACHMENT_BYTES).unwrap();
        assert_eq!(fs::read(out_one).unwrap(), fs::read(out_two).unwrap());
        let _ = fs::remove_dir_all(one);
        let _ = fs::remove_dir_all(two);
    }

    #[test]
    fn share_source_digest_is_kind_bound_deterministic_and_content_sensitive() {
        let root = temp_dir("share-digest");
        let file = root.join("same.bin");
        fs::write(&file, b"aaaa").unwrap();
        let first = share_source_digest(&file, DEFAULT_MAX_ATTACHMENT_BYTES).unwrap();
        assert_eq!(first.len(), 64);
        assert_eq!(
            first,
            share_source_digest(&file, DEFAULT_MAX_ATTACHMENT_BYTES).unwrap()
        );
        fs::write(&file, b"bbbb").unwrap();
        let changed = share_source_digest(&file, DEFAULT_MAX_ATTACHMENT_BYTES).unwrap();
        assert_ne!(first, changed, "equal-size content change was not detected");

        let directory = root.join("directory");
        fs::create_dir(&directory).unwrap();
        fs::write(directory.join("same.bin"), b"bbbb").unwrap();
        let directory_digest =
            share_source_digest(&directory, DEFAULT_MAX_ATTACHMENT_BYTES).unwrap();
        assert_ne!(
            changed, directory_digest,
            "source kind was not digest-bound"
        );
        let archive = root.join("directory.tar");
        create_deterministic_tar(&directory, &archive, DEFAULT_MAX_ATTACHMENT_BYTES).unwrap();
        assert_eq!(
            directory_digest,
            staged_share_digest(&archive, true, DEFAULT_MAX_ATTACHMENT_BYTES).unwrap(),
            "directory source and staged archive digests diverged"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn extraction_rejects_traversal_and_leaves_destination_absent() {
        let root = temp_dir("unsafe-tar");
        let tar_path = root.join("bad.tar");
        let file = File::create(&tar_path).unwrap();
        let mut builder = tar::Builder::new(file);
        let mut header = tar::Header::new_gnu();
        header.set_size(1);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        // set_path rejects traversal, so write a crafted name directly.
        header.as_mut_bytes()[..9].copy_from_slice(b"../x.txt\0");
        header.set_cksum();
        builder.append(&header, b"x".as_slice()).unwrap();
        builder.finish().unwrap();
        let destination = root.join("out");
        assert!(
            extract_tar_no_clobber(&tar_path, &destination, DEFAULT_MAX_ATTACHMENT_BYTES,).is_err()
        );
        assert!(!destination.exists());
        assert!(!root.parent().unwrap().join("x.txt").exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn extraction_refuses_existing_destination() {
        let root = temp_dir("existing-output");
        let destination = root.join("out");
        fs::write(&destination, b"keep").unwrap();
        assert!(extract_tar_no_clobber(
            &root.join("missing.tar"),
            &destination,
            DEFAULT_MAX_ATTACHMENT_BYTES,
        )
        .is_err());
        assert_eq!(fs::read(destination).unwrap(), b"keep");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn staging_and_extraction_require_an_existing_output_parent() {
        let root = temp_dir("missing-output-parent");
        let destination = root.join("missing").join("out");
        assert!(staging_file_near(&destination, ".download")
            .unwrap_err()
            .to_string()
            .contains("output parent does not exist"));

        let archive = root.join("empty.tar");
        let file = File::create(&archive).unwrap();
        tar::Builder::new(file).finish().unwrap();
        assert!(
            extract_tar_no_clobber(&archive, &destination, DEFAULT_MAX_ATTACHMENT_BYTES)
                .unwrap_err()
                .to_string()
                .contains("output parent does not exist")
        );
        assert!(!root.join("missing").exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn stale_state_recovery_removes_only_owned_regular_share_staging() {
        let root = temp_dir("stale-state-staging");
        let stale_blob = root.join(".meshmsg-part-0123456789abcdef.blob");
        let stale_tar = root.join(".meshmsg-part-fedcba9876543210.tar");
        let download = root.join(".meshmsg-part-0123456789abcdef.download");
        let malformed = root.join(".meshmsg-part-NOT-OURS.blob");
        let directory = root.join(".meshmsg-part-aaaaaaaaaaaaaaaa.blob");
        for path in [&stale_blob, &stale_tar, &download, &malformed] {
            fs::write(path, b"stale").unwrap();
        }
        fs::create_dir(&directory).unwrap();

        assert_eq!(cleanup_stale_state_staging(&root).unwrap(), 2);
        assert!(!stale_blob.exists());
        assert!(!stale_tar.exists());
        assert!(download.exists());
        assert!(malformed.exists());
        assert!(directory.is_dir());
        assert_eq!(cleanup_stale_state_staging(&root).unwrap(), 0);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn install_file_refuses_existing_destination() {
        let root = temp_dir("existing-file-output");
        let staging = root.join("staging");
        let destination = root.join("out");
        fs::write(&staging, b"new").unwrap();
        fs::write(&destination, b"keep").unwrap();
        assert!(link_file_no_clobber(&staging, &destination).is_err());
        assert_eq!(fs::read(destination).unwrap(), b"keep");
        assert_eq!(fs::read(staging).unwrap(), b"new");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn directory_install_does_not_replace_an_empty_destination() {
        let root = temp_dir("directory-install-race");
        let staging = root.join("staging");
        let destination = root.join("out");
        fs::create_dir(&staging).unwrap();
        fs::write(staging.join("file"), b"new").unwrap();
        fs::create_dir(&destination).unwrap();
        assert!(rename_directory_no_replace(&staging, &destination).is_err());
        assert!(staging.join("file").exists());
        assert!(destination.read_dir().unwrap().next().is_none());
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(not(any(target_os = "linux", target_os = "android", windows)))]
    #[test]
    fn unsupported_directory_install_target_fails_closed() {
        let root = temp_dir("unsupported-directory-install");
        let staging = root.join("staging");
        let destination = root.join("out");
        fs::create_dir(&staging).unwrap();
        let error = rename_directory_no_replace(&staging, &destination).unwrap_err();
        assert!(error.to_string().contains("unsupported on this target"));
        assert!(staging.is_dir());
        assert!(!destination.exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn archive_path_registry_rejects_case_duplicate_and_type_collisions() {
        let mut seen = BTreeMap::new();
        register_archive_path(&mut seen, "Dir/one", false).unwrap();
        register_archive_path(&mut seen, "Dir/two", false).unwrap();
        assert!(register_archive_path(&mut seen, "dir/three", false).is_err());
        assert!(register_archive_path(&mut seen, "Dir/one", false).is_err());

        let mut seen = BTreeMap::new();
        register_archive_path(&mut seen, "item", false).unwrap();
        assert!(register_archive_path(&mut seen, "item/child", false).is_err());
    }

    #[test]
    fn offered_directory_name_is_validated_after_suffixing() {
        let root = temp_dir("directory-name");
        let valid = "a".repeat(MAX_COMPONENT_BYTES - 4);
        assert_eq!(
            file_name(&root.join(&valid), true).unwrap(),
            format!("{valid}.tar")
        );
        let too_long = "a".repeat(MAX_COMPONENT_BYTES - 3);
        assert!(file_name(&root.join(too_long), true).is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn portable_components_reject_windows_forbidden_characters() {
        for character in ['<', '>', ':', '"', '|', '?', '*'] {
            assert!(validate_component(&format!("file{character}name")).is_err());
        }
        validate_component("portable-name.txt").unwrap();
    }

    #[test]
    fn archive_paths_longer_than_the_direct_header_limit_are_rejected() {
        let root = temp_dir("long-archive-path");
        let directory = "a".repeat(60);
        let file = "b".repeat(40);
        fs::create_dir(root.join(&directory)).unwrap();
        fs::write(root.join(directory).join(file), b"data").unwrap();
        let output = temp_dir("long-archive-output").join("out.tar");
        assert!(create_deterministic_tar(&root, &output, DEFAULT_MAX_ATTACHMENT_BYTES).is_err());
        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_file(output);
    }

    #[test]
    fn extraction_rejects_large_extension_before_reading_its_body() {
        let root = temp_dir("large-extension");
        let archive_path = root.join("extension.tar");
        let mut header = tar::Header::new_gnu();
        header.set_path("pax").unwrap();
        header.set_size(DEFAULT_MAX_ATTACHMENT_BYTES);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::XHeader);
        header.set_cksum();
        fs::write(&archive_path, header.as_bytes()).unwrap();
        let destination = root.join("out");
        assert!(
            extract_tar_no_clobber(&archive_path, &destination, DEFAULT_MAX_ATTACHMENT_BYTES,)
                .is_err()
        );
        assert!(!destination.exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn staged_file_ownership_cleans_failed_install_without_clobbering() {
        let root = temp_dir("staged-file-drop");
        let staging = root.join("part.download");
        let destination = root.join("destination");
        fs::write(&staging, b"new").unwrap();
        fs::write(&destination, b"keep").unwrap();

        let guard = StagedFile::new(staging.clone());
        assert!(link_file_no_clobber(guard.path(), &destination).is_err());
        drop(guard);
        assert!(!staging.exists());
        assert_eq!(fs::read(destination).unwrap(), b"keep");

        let successful_staging = root.join("successful.download");
        let successful_destination = root.join("installed");
        fs::write(&successful_staging, b"installed").unwrap();
        let guard = StagedFile::new(successful_staging.clone());
        link_file_no_clobber(guard.path(), &successful_destination).unwrap();
        guard.cleanup().unwrap();
        assert!(!successful_staging.exists());
        assert_eq!(fs::read(successful_destination).unwrap(), b"installed");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn staged_archive_ownership_cleans_failed_extraction() {
        let root = temp_dir("staged-archive-drop");
        let staging = root.join("part.download");
        let destination = root.join("destination");
        fs::write(&staging, b"not a tar archive").unwrap();

        assert!(extract_staged_tar_no_clobber(
            &StagedFile::new(staging.clone()),
            &destination,
            DEFAULT_MAX_ATTACHMENT_BYTES,
        )
        .is_err());
        assert!(!staging.exists());
        assert!(!destination.exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn file_copy_uses_the_configured_size_limit() {
        let root = temp_dir("copy-limit");
        let source = root.join("source");
        fs::write(&source, b"1234").unwrap();

        let error = copy_bounded(&source, &root.join("output"), 3).unwrap_err();

        assert!(error.to_string().contains("3-byte limit"));
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn copying_and_archiving_symbolic_links_are_rejected() {
        use std::os::unix::fs::symlink;

        let root = temp_dir("copy-symlink");
        let target = root.join("target");
        let link = root.join("link");
        fs::write(&target, b"secret").unwrap();
        symlink(&target, &link).unwrap();
        assert!(copy_bounded(&link, &root.join("output"), DEFAULT_MAX_ATTACHMENT_BYTES,).is_err());
        assert!(!root.join("output").exists());

        let tree = root.join("tree");
        fs::create_dir(&tree).unwrap();
        symlink(&target, tree.join("nested-link")).unwrap();
        assert!(create_deterministic_tar(
            &tree,
            &root.join("tree.tar"),
            DEFAULT_MAX_ATTACHMENT_BYTES,
        )
        .is_err());
        let _ = fs::remove_dir_all(root);
    }
}
