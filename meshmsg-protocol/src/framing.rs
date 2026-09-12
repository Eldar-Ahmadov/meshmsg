use serde::{de::DeserializeOwned, Serialize};
use std::{fmt, io};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

/// Maximum encoded request frame, excluding its newline delimiter.
pub const MAX_REQUEST_FRAME_BYTES: usize = 4096 * 6 + 1024;
/// Maximum encoded response or event frame, excluding its newline delimiter.
pub const MAX_EVENT_FRAME_BYTES: usize = 512 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameLimit {
    Request,
    Event,
    Custom(usize),
}

impl FrameLimit {
    pub const fn bytes(self) -> usize {
        match self {
            Self::Request => MAX_REQUEST_FRAME_BYTES,
            Self::Event => MAX_EVENT_FRAME_BYTES,
            Self::Custom(bytes) => bytes,
        }
    }
}

#[derive(Debug)]
pub enum ProtocolIoError {
    Io(io::Error),
    Json(serde_json::Error),
    EmptyFrame,
    IncompleteFrame,
    FrameTooLarge { maximum: usize },
    Poisoned,
}

impl fmt::Display for ProtocolIoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "local IPC I/O failed: {error}"),
            Self::Json(error) => write!(formatter, "local IPC frame is invalid JSON: {error}"),
            Self::EmptyFrame => formatter.write_str("local IPC frame is empty"),
            Self::IncompleteFrame => formatter.write_str("local IPC stream closed mid-frame"),
            Self::FrameTooLarge { maximum } => {
                write!(formatter, "local IPC frame exceeds {maximum} bytes")
            }
            Self::Poisoned => formatter.write_str("local IPC frame reader is poisoned"),
        }
    }
}

impl std::error::Error for ProtocolIoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Json(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for ProtocolIoError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for ProtocolIoError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

/// A buffered, cancellation-safe reader for a sequence of bounded frames.
pub struct FrameReader<S> {
    reader: BufReader<S>,
    frame: Vec<u8>,
    poisoned: bool,
}

impl<S: AsyncRead> FrameReader<S> {
    pub fn new(stream: S) -> Self {
        Self {
            reader: BufReader::new(stream),
            frame: Vec::new(),
            poisoned: false,
        }
    }

    pub fn get_mut(&mut self) -> &mut S {
        self.reader.get_mut()
    }
}

impl<S: AsyncRead + Unpin> FrameReader<S> {
    /// Read one frame. An oversized or incomplete frame poisons this reader:
    /// subsequent reads fail rather than interpreting an attacker-controlled
    /// suffix as a new frame. Reconnect to resume after either terminal error.
    pub async fn read_frame(&mut self, limit: FrameLimit) -> Result<Vec<u8>, ProtocolIoError> {
        if self.poisoned {
            return Err(ProtocolIoError::Poisoned);
        }
        let maximum = limit.bytes();
        let buffered_maximum = maximum
            .checked_add(1)
            .ok_or(ProtocolIoError::FrameTooLarge { maximum })?;
        loop {
            if self.frame.len() > maximum {
                self.frame.clear();
                self.poisoned = true;
                return Err(ProtocolIoError::FrameTooLarge { maximum });
            }
            let remaining = buffered_maximum - self.frame.len();
            let count = (&mut self.reader)
                .take(remaining as u64)
                .read_until(b'\n', &mut self.frame)
                .await?;
            if count == 0 {
                self.frame.clear();
                self.poisoned = true;
                return Err(ProtocolIoError::IncompleteFrame);
            }
            if self.frame.ends_with(b"\n") {
                self.frame.pop();
                if self.frame.is_empty() {
                    return Err(ProtocolIoError::EmptyFrame);
                }
                return Ok(std::mem::take(&mut self.frame));
            }
            if self.frame.len() > maximum {
                self.frame.clear();
                self.poisoned = true;
                return Err(ProtocolIoError::FrameTooLarge { maximum });
            }
        }
    }

    pub async fn read_json<T>(&mut self, limit: FrameLimit) -> Result<T, ProtocolIoError>
    where
        T: DeserializeOwned,
    {
        let frame = self.read_frame(limit).await?;
        Ok(serde_json::from_slice(&frame)?)
    }
}

/// Read one non-empty newline-delimited frame without ever buffering more than
/// `limit + 1` bytes. Use [`FrameReader`] for a sequence of frames.
pub async fn read_frame<S>(stream: &mut S, limit: FrameLimit) -> Result<Vec<u8>, ProtocolIoError>
where
    S: AsyncRead + Unpin,
{
    let maximum = limit.bytes();
    let mut frame = Vec::with_capacity(maximum.min(8192));
    let mut byte = [0_u8; 1];
    loop {
        let count = stream.read(&mut byte).await?;
        if count == 0 {
            return Err(ProtocolIoError::IncompleteFrame);
        }
        if byte[0] == b'\n' {
            return if frame.is_empty() {
                Err(ProtocolIoError::EmptyFrame)
            } else {
                Ok(frame)
            };
        }
        if frame.len() == maximum {
            return Err(ProtocolIoError::FrameTooLarge { maximum });
        }
        frame.push(byte[0]);
    }
}

pub async fn read_json<S, T>(stream: &mut S, limit: FrameLimit) -> Result<T, ProtocolIoError>
where
    S: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let frame = read_frame(stream, limit).await?;
    Ok(serde_json::from_slice(&frame)?)
}

/// Serialize and write one bounded JSON frame followed by exactly one newline.
pub async fn write_json<S, T>(
    stream: &mut S,
    value: &T,
    limit: FrameLimit,
) -> Result<(), ProtocolIoError>
where
    S: AsyncWrite + Unpin,
    T: Serialize + ?Sized,
{
    let maximum = limit.bytes();
    let mut frame = serde_json::to_vec(value)?;
    if frame.is_empty() {
        return Err(ProtocolIoError::EmptyFrame);
    }
    if frame.len() > maximum {
        return Err(ProtocolIoError::FrameTooLarge { maximum });
    }
    frame.push(b'\n');
    stream.write_all(&frame).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
    #[serde(deny_unknown_fields)]
    struct Example {
        value: u8,
    }

    #[tokio::test]
    async fn json_frames_round_trip() {
        let (mut writer, reader) = tokio::io::duplex(128);
        write_json(&mut writer, &Example { value: 7 }, FrameLimit::Custom(64))
            .await
            .unwrap();
        write_json(&mut writer, &Example { value: 8 }, FrameLimit::Custom(64))
            .await
            .unwrap();
        let mut reader = FrameReader::new(reader);
        assert_eq!(
            reader
                .read_json::<Example>(FrameLimit::Custom(64))
                .await
                .unwrap(),
            Example { value: 7 }
        );
        assert_eq!(
            reader
                .read_json::<Example>(FrameLimit::Custom(64))
                .await
                .unwrap(),
            Example { value: 8 }
        );
    }

    #[tokio::test]
    async fn oversized_and_incomplete_frames_fail() {
        let mut oversized: &[u8] = b"12345\n";
        assert!(matches!(
            read_frame(&mut oversized, FrameLimit::Custom(4)).await,
            Err(ProtocolIoError::FrameTooLarge { maximum: 4 })
        ));

        let mut incomplete: &[u8] = b"{}";
        assert!(matches!(
            read_frame(&mut incomplete, FrameLimit::Custom(4)).await,
            Err(ProtocolIoError::IncompleteFrame)
        ));

        let mut reader = FrameReader::new(&b"12345\n{}\n"[..]);
        assert!(matches!(
            reader.read_frame(FrameLimit::Custom(4)).await,
            Err(ProtocolIoError::FrameTooLarge { maximum: 4 })
        ));
        assert!(matches!(
            reader.read_frame(FrameLimit::Custom(4)).await,
            Err(ProtocolIoError::Poisoned)
        ));
    }
}
