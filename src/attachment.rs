use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
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

pub const MAX_ATTACHMENT_BYTES: u64 = 1024 * 1024 * 1024;
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
                #[cfg(windows)]
                directory_locks,
            )?;
        } else if metadata.is_file() {
            *total = total
                .checked_add(metadata.len())
                .context("directory size overflow")?;
            anyhow::ensure!(
                *total <= MAX_ATTACHMENT_BYTES,
                "directory contents exceed the {}-byte limit",
                MAX_ATTACHMENT_BYTES
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
fn append_directory_from_handle(
    builder: &mut tar::Builder<File>,
    directory: &File,
    prefix: &Path,
    count: &mut usize,
    total: &mut u64,
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
            append_directory_from_handle(builder, &child, &relative_path, count, total)?;
        } else if metadata.is_file() {
            let size = metadata.len();
            *total = total.checked_add(size).context("directory size overflow")?;
            anyhow::ensure!(
                *total <= MAX_ATTACHMENT_BYTES,
                "directory contents exceed the {}-byte limit",
                MAX_ATTACHMENT_BYTES
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

pub fn create_deterministic_tar(source: &Path, output: &Path) -> Result<u64> {
    let output_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(output)
        .with_context(|| format!("create staging archive {}", output.display()))?;
    let mut builder = tar::Builder::new(output_file);
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
        append_directory_from_handle(&mut builder, &root, Path::new(""), &mut count, &mut total)?;
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
    let file = builder.into_inner()?;
    file.sync_all()?;
    let size = file.metadata()?.len();
    anyhow::ensure!(
        size <= MAX_ATTACHMENT_BYTES,
        "archive exceeds the {}-byte limit",
        MAX_ATTACHMENT_BYTES
    );
    Ok(size)
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
    fs::create_dir_all(parent)
        .with_context(|| format!("create output parent {}", parent.display()))?;
    Ok(unique_staging_path(parent, suffix))
}

/// Owns a staging path so detached blocking work cleans up its output on drop.
pub struct StagedFile(PathBuf);

impl StagedFile {
    pub fn new(path: PathBuf) -> Self {
        Self(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for StagedFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

pub fn install_file_no_clobber(staging: &Path, destination: &Path) -> Result<()> {
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
    })?;
    fs::remove_file(staging).context("remove staging file")?;
    Ok(())
}

/// Installs an owned download staging file and cleans it on every exit path.
pub fn install_staged_file_no_clobber(staging: StagedFile, destination: &Path) -> Result<()> {
    install_file_no_clobber(staging.path(), destination)
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
        let result = unsafe { MoveFileExW(staging_wide.as_ptr(), destination_wide.as_ptr(), 0) };
        if result == 0 {
            return Err(io::Error::last_os_error())
                .with_context(|| format!("install extracted directory {}", destination.display()));
        }
        Ok(())
    }

    #[cfg(not(any(target_os = "linux", target_os = "android", windows)))]
    {
        fs::rename(staging, destination)
            .with_context(|| format!("install extracted directory {}", destination.display()))
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

pub fn extract_tar_no_clobber(archive_path: &Path, destination: &Path) -> Result<()> {
    anyhow::ensure!(
        !destination.exists(),
        "output already exists: {}",
        destination.display()
    );
    let parent = destination.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .with_context(|| format!("create output parent {}", parent.display()))?;
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
                total <= MAX_ATTACHMENT_BYTES,
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
pub fn extract_staged_tar_no_clobber(staging: StagedFile, destination: &Path) -> Result<()> {
    extract_tar_no_clobber(staging.path(), destination)
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

pub fn copy_bounded(source: &Path, destination: &Path) -> Result<u64> {
    let (mut input, metadata) = open_regular_file_no_follow(source)?;
    anyhow::ensure!(
        metadata.len() <= MAX_ATTACHMENT_BYTES,
        "file exceeds the {}-byte limit",
        MAX_ATTACHMENT_BYTES
    );
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(destination)
        .context("create staging file")?;
    let copied = io::copy(
        &mut Read::by_ref(&mut input).take(MAX_ATTACHMENT_BYTES + 1),
        &mut output,
    )?;
    anyhow::ensure!(
        copied <= MAX_ATTACHMENT_BYTES,
        "file exceeds the {}-byte limit",
        MAX_ATTACHMENT_BYTES
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
        create_deterministic_tar(&one, &out_one).unwrap();
        create_deterministic_tar(&two, &out_two).unwrap();
        assert_eq!(fs::read(out_one).unwrap(), fs::read(out_two).unwrap());
        let _ = fs::remove_dir_all(one);
        let _ = fs::remove_dir_all(two);
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
        assert!(extract_tar_no_clobber(&tar_path, &destination).is_err());
        assert!(!destination.exists());
        assert!(!root.parent().unwrap().join("x.txt").exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn extraction_refuses_existing_destination() {
        let root = temp_dir("existing-output");
        let destination = root.join("out");
        fs::write(&destination, b"keep").unwrap();
        assert!(extract_tar_no_clobber(&root.join("missing.tar"), &destination).is_err());
        assert_eq!(fs::read(destination).unwrap(), b"keep");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn install_file_refuses_existing_destination() {
        let root = temp_dir("existing-file-output");
        let staging = root.join("staging");
        let destination = root.join("out");
        fs::write(&staging, b"new").unwrap();
        fs::write(&destination, b"keep").unwrap();
        assert!(install_file_no_clobber(&staging, &destination).is_err());
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
        assert!(create_deterministic_tar(&root, &output).is_err());
        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_file(output);
    }

    #[test]
    fn extraction_rejects_large_extension_before_reading_its_body() {
        let root = temp_dir("large-extension");
        let archive_path = root.join("extension.tar");
        let mut header = tar::Header::new_gnu();
        header.set_path("pax").unwrap();
        header.set_size(MAX_ATTACHMENT_BYTES);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::XHeader);
        header.set_cksum();
        fs::write(&archive_path, header.as_bytes()).unwrap();
        let destination = root.join("out");
        assert!(extract_tar_no_clobber(&archive_path, &destination).is_err());
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

        assert!(
            install_staged_file_no_clobber(StagedFile::new(staging.clone()), &destination).is_err()
        );
        assert!(!staging.exists());
        assert_eq!(fs::read(destination).unwrap(), b"keep");

        let successful_staging = root.join("successful.download");
        let successful_destination = root.join("installed");
        fs::write(&successful_staging, b"installed").unwrap();
        install_staged_file_no_clobber(
            StagedFile::new(successful_staging.clone()),
            &successful_destination,
        )
        .unwrap();
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

        assert!(
            extract_staged_tar_no_clobber(StagedFile::new(staging.clone()), &destination).is_err()
        );
        assert!(!staging.exists());
        assert!(!destination.exists());
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
        assert!(copy_bounded(&link, &root.join("output")).is_err());
        assert!(!root.join("output").exists());

        let tree = root.join("tree");
        fs::create_dir(&tree).unwrap();
        symlink(&target, tree.join("nested-link")).unwrap();
        assert!(create_deterministic_tar(&tree, &root.join("tree.tar")).is_err());
        let _ = fs::remove_dir_all(root);
    }
}
