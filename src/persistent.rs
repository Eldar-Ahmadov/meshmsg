use serde::{
    de::{DeserializeOwned, Visitor},
    Deserialize, Deserializer,
};
use std::{
    error::Error,
    fmt, fs,
    io::{self, Read},
    path::Path,
};

const READ_CHUNK_BYTES: usize = 8 * 1024;

pub(crate) struct BoundedString<const MAX: usize>(String);

impl<const MAX: usize> BoundedString<MAX> {
    pub(crate) fn into_string(self) -> String {
        self.0
    }
}

impl<'de, const MAX: usize> Deserialize<'de> for BoundedString<MAX> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct BoundedStringVisitor<const MAX: usize>;
        impl<const MAX: usize> Visitor<'_> for BoundedStringVisitor<MAX> {
            type Value = BoundedString<MAX>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "a string of at most {MAX} bytes")
            }

            fn visit_borrowed_str<E: serde::de::Error>(
                self,
                value: &str,
            ) -> Result<Self::Value, E> {
                self.visit_str(value)
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                if value.len() > MAX {
                    return Err(E::invalid_length(value.len(), &self));
                }
                Ok(BoundedString(value.to_owned()))
            }
        }
        deserializer.deserialize_str(BoundedStringVisitor::<MAX>)
    }
}

fn deserialize_bounded_string<'de, D: Deserializer<'de>, const MAX: usize>(
    deserializer: D,
) -> Result<String, D::Error> {
    BoundedString::<MAX>::deserialize(deserializer).map(BoundedString::into_string)
}

pub(crate) fn string_32<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    deserialize_bounded_string::<D, 32>(deserializer)
}

pub(crate) fn string_64<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    deserialize_bounded_string::<D, 64>(deserializer)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PersistentErrorKind {
    Missing,
    TooLarge,
    Io,
    Parse,
    Corrupt,
    UnsupportedVersion,
}

#[derive(Debug)]
pub(crate) struct PersistentError {
    kind: PersistentErrorKind,
    label: &'static str,
    detail: Option<String>,
    source: Option<Box<dyn Error + Send + Sync>>,
}

impl PersistentError {
    fn new(kind: PersistentErrorKind, label: &'static str) -> Self {
        Self {
            kind,
            label,
            detail: None,
            source: None,
        }
    }

    fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    fn with_source(mut self, source: impl Error + Send + Sync + 'static) -> Self {
        self.source = Some(Box::new(source));
        self
    }

    pub(crate) fn kind(&self) -> PersistentErrorKind {
        self.kind
    }

    pub(crate) fn too_large(label: &'static str, limit: usize) -> Self {
        Self::new(PersistentErrorKind::TooLarge, label)
            .with_detail(format!("maximum {limit} bytes"))
    }

    pub(crate) fn corrupt(label: &'static str, detail: impl Into<String>) -> Self {
        Self::new(PersistentErrorKind::Corrupt, label).with_detail(detail)
    }

    pub(crate) fn unsupported_version(label: &'static str, version: u64) -> Self {
        Self::new(PersistentErrorKind::UnsupportedVersion, label)
            .with_detail(format!("schema version {version}"))
    }
}

impl fmt::Display for PersistentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            PersistentErrorKind::Missing => write!(formatter, "{} is missing", self.label),
            PersistentErrorKind::TooLarge => write!(
                formatter,
                "{} exceeds its size limit{}",
                self.label,
                self.detail
                    .as_deref()
                    .map(|detail| format!(" ({detail})"))
                    .unwrap_or_default()
            ),
            PersistentErrorKind::Io => write!(formatter, "could not read {}", self.label),
            PersistentErrorKind::Parse => write!(formatter, "could not parse {}", self.label),
            PersistentErrorKind::Corrupt => write!(
                formatter,
                "{} is corrupt{}",
                self.label,
                self.detail
                    .as_deref()
                    .map(|detail| format!(": {detail}"))
                    .unwrap_or_default()
            ),
            PersistentErrorKind::UnsupportedVersion => write!(
                formatter,
                "unsupported {} {}",
                self.label,
                self.detail.as_deref().unwrap_or("schema version")
            ),
        }
    }
}

impl Error for PersistentError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn Error + 'static))
    }
}

fn open_existing(
    path: &Path,
    label: &'static str,
    read: bool,
    write: bool,
    append: bool,
) -> Result<fs::File, PersistentError> {
    let mut options = fs::OpenOptions::new();
    options.read(read).write(write).append(append);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            PersistentError::new(PersistentErrorKind::Missing, label).with_source(error)
        } else {
            PersistentError::new(PersistentErrorKind::Io, label).with_source(error)
        }
    })?;
    let metadata = file
        .metadata()
        .map_err(|error| PersistentError::new(PersistentErrorKind::Io, label).with_source(error))?;
    let redirected = metadata.file_type().is_symlink();
    #[cfg(windows)]
    let redirected = {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
        redirected || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    };
    if !metadata.is_file() || redirected {
        return Err(PersistentError::corrupt(
            label,
            "not a non-redirected regular file",
        ));
    }
    Ok(file)
}

pub(crate) fn open_read_write(
    path: &Path,
    label: &'static str,
) -> Result<fs::File, PersistentError> {
    open_existing(path, label, true, true, false)
}

pub(crate) fn open_read_append(
    path: &Path,
    label: &'static str,
) -> Result<fs::File, PersistentError> {
    open_existing(path, label, true, true, true)
}

pub(crate) fn opened_file_is_current_path(
    file: &fs::File,
    path: &Path,
    label: &'static str,
) -> Result<bool, PersistentError> {
    let current = open_existing(path, label, true, false, false)?;
    let original_metadata = file
        .metadata()
        .map_err(|error| PersistentError::new(PersistentErrorKind::Io, label).with_source(error))?;
    let current_metadata = current
        .metadata()
        .map_err(|error| PersistentError::new(PersistentErrorKind::Io, label).with_source(error))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(original_metadata.dev() == current_metadata.dev()
            && original_metadata.ino() == current_metadata.ino())
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        Ok(
            match (
                original_metadata.volume_serial_number(),
                original_metadata.file_index(),
                current_metadata.volume_serial_number(),
                current_metadata.file_index(),
            ) {
                (
                    Some(original_volume),
                    Some(original_index),
                    Some(current_volume),
                    Some(current_index),
                ) => original_volume == current_volume && original_index == current_index,
                _ => false,
            },
        )
    }
}

pub(crate) fn read_file_bounded(
    path: &Path,
    label: &'static str,
    limit: usize,
) -> Result<Vec<u8>, PersistentError> {
    let mut file = open_existing(path, label, true, false, false)?;
    let metadata = file
        .metadata()
        .map_err(|error| PersistentError::new(PersistentErrorKind::Io, label).with_source(error))?;
    if metadata.len() > limit as u64 {
        return Err(PersistentError::too_large(label, limit));
    }
    read_bounded(
        &mut file,
        label,
        limit,
        usize::try_from(metadata.len()).unwrap_or(limit),
    )
}

pub(crate) fn read_optional_file_bounded(
    path: &Path,
    label: &'static str,
    limit: usize,
) -> Result<Option<Vec<u8>>, PersistentError> {
    match read_file_bounded(path, label, limit) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == PersistentErrorKind::Missing => Ok(None),
        Err(error) => Err(error),
    }
}

pub(crate) fn read_bounded(
    reader: &mut impl Read,
    label: &'static str,
    limit: usize,
    size_hint: usize,
) -> Result<Vec<u8>, PersistentError> {
    let mut bytes = Vec::new();
    let initial = size_hint.min(limit);
    bytes
        .try_reserve_exact(initial)
        .map_err(|error| PersistentError::new(PersistentErrorKind::Io, label).with_source(error))?;
    let mut chunk = [0_u8; READ_CHUNK_BYTES];
    loop {
        let remaining = limit.saturating_sub(bytes.len());
        let request = chunk.len().min(remaining.saturating_add(1));
        let read = reader.read(&mut chunk[..request]).map_err(|error| {
            PersistentError::new(PersistentErrorKind::Io, label).with_source(error)
        })?;
        if read == 0 {
            return Ok(bytes);
        }
        if read > remaining {
            return Err(PersistentError::too_large(label, limit));
        }
        bytes.try_reserve(read).map_err(|error| {
            PersistentError::new(PersistentErrorKind::Io, label).with_source(error)
        })?;
        bytes.extend_from_slice(&chunk[..read]);
    }
}

pub(crate) fn parse_json<T: DeserializeOwned>(
    bytes: &[u8],
    label: &'static str,
) -> Result<T, PersistentError> {
    serde_json::from_slice(bytes)
        .map_err(|error| PersistentError::new(PersistentErrorKind::Parse, label).with_source(error))
}

/// Reject JSON strings by decoded UTF-8 length before serde_json can allocate
/// its escape-decoding scratch buffer. Field-specific `BoundedString` visitors
/// still enforce their tighter limits after this allocation-independent pass.
pub(crate) fn parse_json_bounded_strings<T: DeserializeOwned>(
    bytes: &[u8],
    label: &'static str,
    max_decoded_string_bytes: usize,
) -> Result<T, PersistentError> {
    validate_json_string_lengths(bytes, label, max_decoded_string_bytes)?;
    parse_json(bytes, label)
}

fn validate_json_string_lengths(
    bytes: &[u8],
    label: &'static str,
    max_decoded_string_bytes: usize,
) -> Result<(), PersistentError> {
    fn hex(byte: u8) -> Option<u16> {
        match byte {
            b'0'..=b'9' => Some(u16::from(byte - b'0')),
            b'a'..=b'f' => Some(u16::from(byte - b'a' + 10)),
            b'A'..=b'F' => Some(u16::from(byte - b'A' + 10)),
            _ => None,
        }
    }

    fn unicode_escape(bytes: &[u8], offset: usize) -> Option<u16> {
        let digits = bytes.get(offset..offset + 4)?;
        let mut value = 0_u16;
        for byte in digits {
            value = value.checked_mul(16)?.checked_add(hex(*byte)?)?;
        }
        Some(value)
    }

    let oversized = || {
        PersistentError::new(PersistentErrorKind::Parse, label).with_detail(format!(
            "decoded JSON string exceeds {max_decoded_string_bytes} bytes"
        ))
    };
    let mut offset = 0;
    while offset < bytes.len() {
        if bytes[offset] != b'"' {
            offset += 1;
            continue;
        }
        offset += 1;
        let mut decoded = 0_usize;
        loop {
            let Some(&byte) = bytes.get(offset) else {
                return Ok(()); // serde_json reports the unterminated string.
            };
            match byte {
                b'"' => {
                    offset += 1;
                    break;
                }
                b'\\' => {
                    let Some(&escape) = bytes.get(offset + 1) else {
                        return Ok(());
                    };
                    match escape {
                        b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => {
                            decoded = decoded.saturating_add(1);
                            offset += 2;
                        }
                        b'u' => {
                            let Some(first) = unicode_escape(bytes, offset + 2) else {
                                return Ok(());
                            };
                            if (0xD800..=0xDBFF).contains(&first) {
                                if bytes.get(offset + 6..offset + 8) != Some(b"\\u") {
                                    return Ok(());
                                }
                                let Some(second) = unicode_escape(bytes, offset + 8) else {
                                    return Ok(());
                                };
                                if !(0xDC00..=0xDFFF).contains(&second) {
                                    return Ok(());
                                }
                                decoded = decoded.saturating_add(4);
                                offset += 12;
                            } else if (0xDC00..=0xDFFF).contains(&first) {
                                return Ok(());
                            } else {
                                decoded = decoded.saturating_add(if first <= 0x7f {
                                    1
                                } else if first <= 0x7ff {
                                    2
                                } else {
                                    3
                                });
                                offset += 6;
                            }
                        }
                        _ => return Ok(()),
                    }
                }
                _ => {
                    // For unescaped UTF-8 the encoded and decoded byte lengths match.
                    decoded = decoded.saturating_add(1);
                    offset += 1;
                }
            }
            if decoded > max_decoded_string_bytes {
                return Err(oversized());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct SlowReader {
        bytes: Vec<u8>,
        offset: usize,
        chunk: usize,
    }

    impl Read for SlowReader {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            if self.offset == self.bytes.len() {
                return Ok(0);
            }
            let count = output
                .len()
                .min(self.chunk)
                .min(self.bytes.len() - self.offset);
            output[..count].copy_from_slice(&self.bytes[self.offset..self.offset + count]);
            self.offset += count;
            Ok(count)
        }
    }

    #[test]
    fn bounded_reader_handles_slow_exact_and_limit_plus_one_inputs() {
        for chunk in [1, 2, 7, READ_CHUNK_BYTES] {
            let mut exact = SlowReader {
                bytes: vec![b'x'; 32],
                offset: 0,
                chunk,
            };
            assert_eq!(
                read_bounded(&mut exact, "test state", 32, 0).unwrap().len(),
                32
            );

            let mut oversized = SlowReader {
                bytes: vec![b'x'; 33],
                offset: 0,
                chunk,
            };
            let error = read_bounded(&mut oversized, "test state", 32, 0).unwrap_err();
            assert_eq!(error.kind(), PersistentErrorKind::TooLarge);
            assert_eq!(oversized.offset, 33);
        }
    }

    #[test]
    fn json_string_prescan_counts_escapes_unicode_and_surrogate_pairs() {
        for (exact, oversized, limit) in [
            (
                r#""\u0061\u0061\u0061\u0061""#,
                r#""\u0061\u0061\u0061\u0061\u0061""#,
                4,
            ),
            (r#""\\\\\\\\""#, r#""\\\\\\\\\\""#, 4),
            (
                r#""\uD83D\uDE00\uD83D\uDE00""#,
                r#""\uD83D\uDE00\uD83D\uDE00\uD83D\uDE00""#,
                8,
            ),
        ] {
            let decoded: String =
                parse_json_bounded_strings(exact.as_bytes(), "test JSON", limit).unwrap();
            assert_eq!(decoded.len(), limit);
            assert!(
                parse_json_bounded_strings::<String>(oversized.as_bytes(), "test JSON", limit,)
                    .is_err()
            );
        }
    }

    #[test]
    fn file_preflight_distinguishes_missing_and_oversized_before_reading() {
        let dir = std::env::temp_dir().join(format!(
            "meshmsg-persistent-reader-test-{}",
            rand::random::<u64>()
        ));
        fs::create_dir_all(&dir).unwrap();
        let missing = read_file_bounded(&dir.join("missing"), "test state", 8).unwrap_err();
        assert_eq!(missing.kind(), PersistentErrorKind::Missing);

        let path = dir.join("state");
        fs::write(&path, b"12345678").unwrap();
        assert_eq!(
            read_file_bounded(&path, "test state", 8).unwrap(),
            b"12345678"
        );
        fs::write(&path, b"123456789").unwrap();
        let oversized = read_file_bounded(&path, "test state", 8).unwrap_err();
        assert_eq!(oversized.kind(), PersistentErrorKind::TooLarge);
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn optional_reader_rejects_dangling_links_instead_of_treating_them_as_absent() {
        use std::os::unix::fs::symlink;
        let dir = std::env::temp_dir().join(format!(
            "meshmsg-persistent-link-test-{}",
            rand::random::<u64>()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state");
        symlink(dir.join("missing-target"), &path).unwrap();
        let error = read_optional_file_bounded(&path, "test state", 8).unwrap_err();
        assert_ne!(error.kind(), PersistentErrorKind::Missing);
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn optional_reader_rejects_dangling_reparse_points_instead_of_absence() {
        use std::os::windows::fs::symlink_file;
        let dir = std::env::temp_dir().join(format!(
            "meshmsg-persistent-link-test-{}",
            rand::random::<u64>()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state");
        symlink_file(dir.join("missing-target"), &path).unwrap();
        let error = read_optional_file_bounded(&path, "test state", 8).unwrap_err();
        assert_ne!(error.kind(), PersistentErrorKind::Missing);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn errors_distinguish_io_parse_corruption_and_versions_without_paths() {
        struct BrokenReader;
        impl Read for BrokenReader {
            fn read(&mut self, _output: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("private path /secret"))
            }
        }
        let io = read_bounded(&mut BrokenReader, "test state", 8, 0).unwrap_err();
        assert_eq!(io.kind(), PersistentErrorKind::Io);
        assert!(!io.to_string().contains("/secret"));

        let parse = parse_json::<serde_json::Value>(b"{", "test state").unwrap_err();
        assert_eq!(parse.kind(), PersistentErrorKind::Parse);
        assert_eq!(
            PersistentError::corrupt("test state", "checksum").kind(),
            PersistentErrorKind::Corrupt
        );
        assert_eq!(
            PersistentError::unsupported_version("test state", 99).kind(),
            PersistentErrorKind::UnsupportedVersion
        );
        assert!(!parse.to_string().contains('/'));
    }
}
