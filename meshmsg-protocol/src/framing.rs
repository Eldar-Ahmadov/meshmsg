use serde::{de::DeserializeOwned, Serialize};
use std::{
    fmt, io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

/// JSON can expand every UTF-8 input byte to a six-byte `\\u00XX` escape.
const JSON_ESCAPE_EXPANSION: usize = 6;
const REQUEST_PROTOCOL_HEADROOM_BYTES: usize = 16 * 1024;
const EVENT_PROTOCOL_HEADROOM_BYTES: usize = 64 * 1024;
const PEER_RECORD_TEXT_BUDGET_BYTES: usize = 256;
const OFFER_RECORD_TEXT_BUDGET_BYTES: usize = 512;

const fn checked_product(left: usize, right: usize) -> usize {
    match left.checked_mul(right) {
        Some(value) => value,
        None => panic!("IPC frame-size multiplication overflow"),
    }
}

const fn checked_sum(left: usize, right: usize) -> usize {
    match left.checked_add(right) {
        Some(value) => value,
        None => panic!("IPC frame-size addition overflow"),
    }
}

const REQUEST_ACCEPTED_TEXT_BYTES: usize = checked_sum(
    checked_sum(
        crate::MAX_BROADCAST_BODY_BYTES,
        crate::MAX_SIGNED_ATTACHMENT_TOKEN_BYTES,
    ),
    crate::MAX_IPC_PATH_BYTES,
);
const EVENT_ACCEPTED_TEXT_BYTES: usize = checked_sum(
    checked_sum(
        checked_sum(
            crate::MAX_BROADCAST_BODY_BYTES,
            checked_product(crate::MAX_SIGNED_ATTACHMENT_TOKEN_BYTES, 2),
        ),
        checked_sum(
            crate::MAX_IPC_PATH_BYTES,
            checked_product(crate::MAX_WARNINGS, crate::MAX_PUBLIC_TEXT_BYTES),
        ),
    ),
    checked_sum(
        checked_product(crate::MAX_PEERS, PEER_RECORD_TEXT_BUDGET_BYTES),
        checked_product(crate::MAX_OFFERS, OFFER_RECORD_TEXT_BUDGET_BYTES),
    ),
);

/// Maximum encoded request frame, excluding its newline delimiter. This
/// deliberately sums the body, token, and path maxima even though tagged request
/// variants cannot carry all three simultaneously, then applies worst-case JSON
/// escaping and fixed protocol headroom.
pub const MAX_REQUEST_FRAME_BYTES: usize = checked_sum(
    checked_product(REQUEST_ACCEPTED_TEXT_BYTES, JSON_ESCAPE_EXPANSION),
    REQUEST_PROTOCOL_HEADROOM_BYTES,
);
/// Maximum encoded response or event frame, excluding its newline delimiter.
/// The derivation conservatively sums every largest accepted DTO family: body,
/// two attachment tokens, path, warnings, peer snapshot, and offer listing.
pub const MAX_EVENT_FRAME_BYTES: usize = checked_sum(
    checked_product(EVENT_ACCEPTED_TEXT_BYTES, JSON_ESCAPE_EXPANSION),
    EVENT_PROTOCOL_HEADROOM_BYTES,
);

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

    pub fn get_ref(&self) -> &S {
        self.reader.get_ref()
    }

    pub fn get_mut(&mut self) -> &mut S {
        self.reader.get_mut()
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for FrameReader<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(self.reader.get_mut()).poll_write(context, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(self.reader.get_mut()).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(self.reader.get_mut()).poll_shutdown(context)
    }
}

impl<S: AsyncRead + Unpin> FrameReader<S> {
    /// Read one frame. An oversized or incomplete frame poisons this reader:
    /// subsequent reads fail rather than interpreting an attacker-controlled
    /// suffix as a new frame. Reconnect to resume after either terminal error.
    pub async fn read_frame(&mut self, limit: FrameLimit) -> Result<Vec<u8>, ProtocolIoError> {
        self.read_frame_or_eof(limit)
            .await?
            .ok_or(ProtocolIoError::IncompleteFrame)
    }

    /// Read one frame, returning `None` only when the stream closes cleanly
    /// before any bytes of the next frame. Buffered bytes after a prior frame
    /// are retained and consumed before the underlying stream is polled.
    pub async fn read_frame_or_eof(
        &mut self,
        limit: FrameLimit,
    ) -> Result<Option<Vec<u8>>, ProtocolIoError> {
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
            let read_limit =
                u64::try_from(remaining).map_err(|_| ProtocolIoError::FrameTooLarge { maximum })?;
            let count = (&mut self.reader)
                .take(read_limit)
                .read_until(b'\n', &mut self.frame)
                .await?;
            if count == 0 {
                if self.frame.is_empty() {
                    return Ok(None);
                }
                self.frame.clear();
                self.poisoned = true;
                return Err(ProtocolIoError::IncompleteFrame);
            }
            if self.frame.ends_with(b"\n") {
                self.frame.pop();
                if self.frame.is_empty() {
                    return Err(ProtocolIoError::EmptyFrame);
                }
                return Ok(Some(std::mem::take(&mut self.frame)));
            }
            if self.frame.len() > maximum {
                self.frame.clear();
                self.poisoned = true;
                return Err(ProtocolIoError::FrameTooLarge { maximum });
            }
        }
    }

    /// Read non-framing bytes without bypassing bytes already buffered while
    /// parsing the preceding frame.
    pub async fn read(&mut self, buffer: &mut [u8]) -> Result<usize, ProtocolIoError> {
        Ok(self.reader.read(buffer).await?)
    }

    pub async fn read_json<T>(&mut self, limit: FrameLimit) -> Result<T, ProtocolIoError>
    where
        T: DeserializeOwned,
    {
        let frame = self.read_frame(limit).await?;
        Ok(serde_json::from_slice(&frame)?)
    }
}

/// Read one non-empty newline-delimited frame with bounded buffering. Use one
/// persistent [`FrameReader`] whenever more data may follow this frame.
pub async fn read_frame<S>(stream: &mut S, limit: FrameLimit) -> Result<Vec<u8>, ProtocolIoError>
where
    S: AsyncRead + Unpin,
{
    FrameReader::new(stream).read_frame(limit).await
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

    fn native_absolute_ascii_path(serialized_bytes: usize) -> std::path::PathBuf {
        let prefix = if cfg!(windows) { r"C:\" } else { "/" };
        assert!(serialized_bytes >= prefix.len());
        std::path::PathBuf::from(format!(
            "{prefix}{}",
            "x".repeat(serialized_bytes - prefix.len())
        ))
    }

    #[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
    #[serde(deny_unknown_fields)]
    struct Example {
        value: u8,
    }

    #[test]
    fn ipc_limits_cover_worst_case_json_escaping() {
        assert_eq!(crate::MAX_BROADCAST_BODY_BYTES, 65_358);
        assert_eq!(MAX_REQUEST_FRAME_BYTES, 1_129_432);
        assert_eq!(MAX_EVENT_FRAME_BYTES, 5_045_212);
        let escaped_broadcast =
            checked_product(crate::MAX_BROADCAST_BODY_BYTES, JSON_ESCAPE_EXPANSION);
        assert!(
            checked_sum(escaped_broadcast, REQUEST_PROTOCOL_HEADROOM_BYTES)
                <= MAX_REQUEST_FRAME_BYTES
        );
        let request = crate::RequestFrame::new(
            crate::RequestId::new_random(),
            crate::Request::Send {
                operation_id: crate::OperationId::new_random(),
                body: crate::BroadcastBody::new("\0".repeat(crate::MAX_BROADCAST_BODY_BYTES))
                    .unwrap(),
            },
        );
        assert!(serde_json::to_vec(&request).unwrap().len() <= MAX_REQUEST_FRAME_BYTES);

        let path = native_absolute_ascii_path(crate::MAX_IPC_PATH_BYTES);
        assert!(path.is_absolute());
        assert_eq!(
            path.as_os_str().as_encoded_bytes().len(),
            crate::MAX_IPC_PATH_BYTES
        );
        let token =
            crate::AttachmentToken::new("A".repeat(crate::MAX_SIGNED_ATTACHMENT_TOKEN_BYTES))
                .unwrap();
        let download = crate::RequestFrame::new(
            crate::RequestId::new_random(),
            crate::Request::Download {
                operation_id: crate::OperationId::new_random(),
                offer: token.as_str().to_owned(),
                output: path.clone(),
                mode: crate::DownloadMode::Install,
            },
        );
        assert!(serde_json::to_vec(&download).unwrap().len() <= MAX_REQUEST_FRAME_BYTES);

        let operation = crate::OperationId::new_random();
        let peer: crate::PeerId = "1".repeat(64).parse().unwrap();
        let attachment = crate::EventFrame::new(
            crate::RequestId::new_random(),
            crate::Event::AttachmentShared(crate::AttachmentShared {
                operation_id: operation.clone(),
                from: peer.clone(),
                message_id: operation.as_str().parse().unwrap(),
                timestamp_ms: u64::MAX,
                offer_id: operation.as_str().parse().unwrap(),
                source_digest: "a".repeat(64).parse().unwrap(),
                kind: crate::AttachmentKind::File,
                name: crate::AttachmentName::new("x".repeat(100)).unwrap(),
                size: u64::MAX,
                ticket: token.clone(),
                offer: token,
                delivery_acknowledged: false,
            }),
        );
        assert!(serde_json::to_vec(&attachment).unwrap().len() <= MAX_EVENT_FRAME_BYTES);
        let message = crate::EventFrame::new(
            crate::RequestId::new_random(),
            crate::Event::Message(crate::Message {
                from: "2".repeat(64).parse().unwrap(),
                message_id: crate::MessageId::new_random(),
                timestamp_ms: u64::MAX,
                body: crate::BroadcastBody::new("\0".repeat(crate::MAX_BROADCAST_BODY_BYTES))
                    .unwrap(),
            }),
        );
        assert!(serde_json::to_vec(&message).unwrap().len() <= MAX_EVENT_FRAME_BYTES);

        let completion = crate::ResponseFrame::new(
            Some(crate::RequestId::new_random()),
            crate::Response::DownloadComplete(crate::DownloadResult {
                operation_id: operation.clone(),
                token_digest: "b".repeat(64).parse().unwrap(),
                offer_id: operation.as_str().parse().unwrap(),
                kind: crate::AttachmentKind::File,
                name: crate::AttachmentName::new("x".repeat(100)).unwrap(),
                size: u64::MAX,
                from: peer,
                output: path,
                mode: crate::DownloadMode::Install,
                installed: true,
                pinned: true,
                destination_synced: false,
                cleanup_complete: false,
                warnings: vec!["x".repeat(crate::MAX_PUBLIC_TEXT_BYTES); crate::MAX_WARNINGS],
            }),
        );
        assert!(serde_json::to_vec(&completion).unwrap().len() <= MAX_EVENT_FRAME_BYTES);

        let offers = (0..crate::MAX_OFFERS)
            .map(|index| crate::OfferListItem {
                direction: crate::OfferDirection::Incoming,
                offer_id: format!("{index:032x}").parse().unwrap(),
                provider: Some("3".repeat(64).parse().unwrap()),
                name: crate::AttachmentName::new("x".repeat(100)).unwrap(),
                kind: crate::AttachmentKind::DirectoryTarV1,
                hash: "c".repeat(64).parse().unwrap(),
                format: "raw".into(),
                status: "complete".into(),
                size: Some(u64::MAX),
            })
            .collect();
        let offers = crate::ResponseFrame::new(
            Some(crate::RequestId::new_random()),
            crate::Response::Offers(crate::OffersList {
                blobs: offers,
                truncated: false,
                item_errors: 0,
            }),
        );
        assert!(serde_json::to_vec(&offers).unwrap().len() <= MAX_EVENT_FRAME_BYTES);

        let generated_at_ms = 1_700_000_000_000;
        let peers = (0..crate::MAX_PEERS)
            .map(|index| crate::RemotePeer {
                public_key: format!("{index:064x}").parse().unwrap(),
                alias: Some(crate::Alias::new("x".repeat(63)).unwrap()),
                online: true,
                last_seen_ms: generated_at_ms,
                expires_at_ms: generated_at_ms + crate::PEER_LEASE_MS,
            })
            .collect();
        let snapshot = crate::ResponseFrame::new(
            Some(crate::RequestId::new_random()),
            crate::Response::PeersSnapshot(crate::PeerSnapshot {
                generated_at_ms,
                directory_epoch: crate::OperationId::new_random(),
                directory_revision: u64::MAX,
                self_peer: crate::SelfPeer {
                    public_key: "f".repeat(64).parse().unwrap(),
                    alias: Some(crate::Alias::new("x".repeat(63)).unwrap()),
                    online: true,
                },
                peers,
            }),
        );
        assert!(serde_json::to_vec(&snapshot).unwrap().len() <= MAX_EVENT_FRAME_BYTES);
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
    async fn buffered_bytes_are_preserved_for_frames_and_post_frame_reads() {
        let mut frames = FrameReader::new(&b"{\"value\":7}\n{\"value\":8}\n"[..]);
        assert_eq!(
            frames
                .read_json::<Example>(FrameLimit::Custom(64))
                .await
                .unwrap(),
            Example { value: 7 }
        );
        assert_eq!(
            frames
                .read_json::<Example>(FrameLimit::Custom(64))
                .await
                .unwrap(),
            Example { value: 8 }
        );
        assert!(frames
            .read_frame_or_eof(FrameLimit::Custom(64))
            .await
            .unwrap()
            .is_none());

        let mut subscription = FrameReader::new(&b"{}\nunexpected"[..]);
        assert_eq!(
            subscription
                .read_frame(FrameLimit::Custom(64))
                .await
                .unwrap(),
            b"{}"
        );
        let mut buffered = [0; 10];
        subscription.read(&mut buffered).await.unwrap();
        assert_eq!(&buffered, b"unexpected");
    }

    #[tokio::test]
    async fn exact_request_and_event_frame_limits_accept_maximum_and_reject_max_plus_one() {
        for limit in [FrameLimit::Request, FrameLimit::Event] {
            let maximum = limit.bytes();
            let mut exact = vec![b'x'; maximum];
            exact.push(b'\n');
            assert_eq!(
                read_frame(&mut exact.as_slice(), limit)
                    .await
                    .unwrap()
                    .len(),
                maximum
            );

            let mut oversized = vec![b'x'; maximum.checked_add(1).unwrap()];
            oversized.push(b'\n');
            assert!(matches!(
                read_frame(&mut oversized.as_slice(), limit).await,
                Err(ProtocolIoError::FrameTooLarge { maximum: value }) if value == maximum
            ));
        }
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
