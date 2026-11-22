//! Shared bounded newline-delimited local daemon protocol.
pub(crate) mod server;
mod transport;

use crate::contracts::ContractFailure;
use anyhow::{Context, Result};
use meshmsg_protocol::{Request, RequestFrame, RequestId};
use std::path::Path;
use tokio::io::{AsyncRead, AsyncWrite};
#[cfg(test)]
pub(crate) use transport::LocalListener;
pub(crate) use transport::{
    bind_local_endpoint, connect_daemon, LocalClientStream, SubscriptionStream,
};

// The shared protocol crate owns the local framing bounds.
#[cfg(test)]
pub(crate) use meshmsg_protocol::framing::MAX_EVENT_FRAME_BYTES as MAX_IPC_EVENT_SIZE;
#[cfg(test)]
pub(crate) use meshmsg_protocol::framing::MAX_REQUEST_FRAME_BYTES as MAX_IPC_REQUEST_SIZE;

fn decode_event_frame(
    bytes: &[u8],
    expected_request_id: &RequestId,
) -> Result<meshmsg_protocol::EventFrame> {
    let frame: meshmsg_protocol::EventFrame =
        serde_json::from_slice(bytes).context("invalid typed event from local daemon")?;
    anyhow::ensure!(
        &frame.request_id == expected_request_id,
        "daemon event request ID does not match the subscription"
    );
    Ok(frame)
}

fn decode_response_frame(
    frame: &[u8],
    expected_request_id: &RequestId,
) -> Result<meshmsg_protocol::ResponseFrame> {
    let frame: meshmsg_protocol::ResponseFrame =
        serde_json::from_slice(frame).context("invalid typed response from local daemon")?;
    match &frame.response {
        meshmsg_protocol::Response::Error(error)
            if frame.request_id.is_none()
                && matches!(
                    error.code,
                    meshmsg_protocol::ErrorCode::IpcCapacity
                        | meshmsg_protocol::ErrorCode::InitialFrameTimeout
                ) => {}
        _ => anyhow::ensure!(
            frame.request_id.as_ref() == Some(expected_request_id),
            "daemon response request ID does not match the request"
        ),
    }
    Ok(frame)
}

#[cfg(test)]
pub(crate) async fn read_frame<S>(stream: &mut S, maximum: usize) -> Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    meshmsg_protocol::read_frame(stream, meshmsg_protocol::FrameLimit::Custom(maximum))
        .await
        .map_err(anyhow::Error::from)
}

pub(crate) async fn send_request(
    dir: &Path,
    request: &Request,
) -> Result<meshmsg_protocol::ResponseFrame> {
    let request_id = RequestId::new_random();
    let mut stream = connect_daemon(dir).await?;
    write_request(&mut stream, request, request_id.clone()).await?;
    let mut reader = meshmsg_protocol::FrameReader::new(stream);
    let bytes = reader
        .read_frame(meshmsg_protocol::FrameLimit::Event)
        .await
        .map_err(anyhow::Error::from)?;
    let frame = decode_response_frame(&bytes, &request_id)?;
    request
        .validate_response(&frame.response)
        .map_err(anyhow::Error::msg)?;
    Ok(frame)
}

#[cfg(test)]
pub(crate) fn validate_error_for_request(
    error: &meshmsg_protocol::ProtocolError,
    request: &Request,
) -> Result<()> {
    request
        .validate_response(&meshmsg_protocol::Response::Error(error.clone()))
        .map_err(anyhow::Error::msg)
}

pub(crate) async fn send_request_checked(
    dir: &Path,
    request: &Request,
) -> Result<meshmsg_protocol::ResponseFrame> {
    let frame = send_request(dir, request).await?;
    if let meshmsg_protocol::Response::Error(error) = frame.response.clone() {
        return Err(anyhow::Error::new(ContractFailure::new(
            frame.request_id,
            error,
        )));
    }
    Ok(frame)
}

pub(crate) async fn write_request<S: AsyncWrite + Unpin>(
    stream: &mut S,
    request: &Request,
    request_id: RequestId,
) -> Result<()> {
    let frame = RequestFrame::try_new(request_id, request.clone())
        .map_err(anyhow::Error::msg)
        .context("invalid local IPC request")?;
    meshmsg_protocol::write_json(stream, &frame, meshmsg_protocol::FrameLimit::Request)
        .await
        .map_err(anyhow::Error::from)
}

pub(crate) struct SubscriptionReader<S> {
    reader: meshmsg_protocol::FrameReader<S>,
    request_id: RequestId,
}

impl<S: AsyncRead + Unpin> SubscriptionReader<S> {
    pub(crate) fn new(stream: S, request_id: RequestId) -> Self {
        Self {
            reader: meshmsg_protocol::FrameReader::new(stream),
            request_id,
        }
    }

    /// Reads one event while retaining any bytes consumed if this future is
    /// cancelled by a competing `select!` branch.
    pub(crate) async fn read(&mut self) -> Result<Option<meshmsg_protocol::EventFrame>> {
        let Some(frame) = self
            .reader
            .read_frame_or_eof(meshmsg_protocol::FrameLimit::Event)
            .await
            .map_err(anyhow::Error::from)?
        else {
            return Ok(None);
        };
        decode_event_frame(&frame, &self.request_id)
            .context("invalid daemon event")
            .map(Some)
    }
}

pub(crate) async fn subscribe(dir: &Path) -> Result<SubscriptionReader<LocalClientStream>> {
    let request_id = RequestId::new_random();
    let mut stream = connect_daemon(dir).await?;
    write_request(&mut stream, &Request::Subscribe, request_id.clone()).await?;
    Ok(SubscriptionReader::new(stream, request_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn native_absolute_ascii_path(serialized_bytes: usize) -> std::path::PathBuf {
        let prefix = if cfg!(windows) { r"C:\" } else { "/" };
        assert!(serialized_bytes >= prefix.len());
        std::path::PathBuf::from(format!(
            "{prefix}{}",
            "x".repeat(serialized_bytes - prefix.len())
        ))
    }

    #[tokio::test]
    async fn oversized_caller_path_returns_error_before_frame_construction() {
        let output = native_absolute_ascii_path(meshmsg_protocol::MAX_IPC_PATH_BYTES + 1);
        assert!(output.is_absolute());
        assert_eq!(
            output.as_os_str().as_encoded_bytes().len(),
            meshmsg_protocol::MAX_IPC_PATH_BYTES + 1
        );
        let request = Request::Download {
            operation_id: meshmsg_protocol::OperationId::new_random(),
            offer: meshmsg_protocol::AttachmentToken::new("x").unwrap(),
            output,
        };
        let mut bytes = Vec::new();
        let error = write_request(&mut bytes, &request, RequestId::new_random())
            .await
            .unwrap_err();
        assert!(error.to_string().contains("invalid local IPC request"));
        assert!(bytes.is_empty());
    }

    #[test]
    fn response_decoder_rejects_error_presentation_fields() {
        let request_id = "0123456789abcdef0123456789abcdef";
        let malformed = serde_json::json!({
            "protocol_version": meshmsg_protocol::PROTOCOL_VERSION,
            "request_id": request_id,
            "type": "error",
            "code": "invalid_request",
            "outcome": "not_started",
            "message": "not part of IPC",
            "retryable": false
        });
        assert!(decode_response_frame(
            &serde_json::to_vec(&malformed).unwrap(),
            &request_id.parse().unwrap()
        )
        .is_err());
    }

    #[test]
    fn response_decoder_rejects_structurally_valid_semantic_forgery() {
        let request_id = "0123456789abcdef0123456789abcdef";
        let malformed = serde_json::json!({
            "protocol_version": meshmsg_protocol::PROTOCOL_VERSION,
            "request_id": request_id,
            "type": "queued",
            "operation_id": "11111111111111111111111111111111",
            "from": "2".repeat(64),
            "timestamp_ms": 0,
            "body": "accepted JSON, forged semantics"
        });
        assert!(decode_response_frame(
            &serde_json::to_vec(&malformed).unwrap(),
            &request_id.parse().unwrap()
        )
        .is_err());
    }

    #[tokio::test]
    async fn subscription_reader_rejects_semantically_malformed_event() {
        let request_id = "0123456789abcdef0123456789abcdef";
        let (mut writer, reader) = tokio::io::duplex(4096);
        let malformed = serde_json::json!({
            "protocol_version": meshmsg_protocol::PROTOCOL_VERSION,
            "request_id": request_id,
            "type": "download_progress",
            "operation_id": "11111111111111111111111111111111",
            "received_bytes": 2,
            "total_bytes": 1,
            "output": "/tmp/output"
        });
        tokio::spawn(async move {
            let mut bytes = serde_json::to_vec(&malformed).unwrap();
            bytes.push(b'\n');
            tokio::io::AsyncWriteExt::write_all(&mut writer, &bytes)
                .await
                .unwrap();
        });
        let mut subscription = SubscriptionReader::new(reader, request_id.parse().unwrap());
        assert!(subscription.read().await.is_err());
    }

    #[test]
    fn ipc_uses_protocol_request_response_family_and_operation_validation() {
        let operation_id = meshmsg_protocol::OperationId::new_random();
        let request = Request::Send {
            operation_id: operation_id.clone(),
            body: meshmsg_protocol::BroadcastBody::new("hello").unwrap(),
        };
        let wrong_operation = meshmsg_protocol::OperationId::new_random();
        let mismatched = meshmsg_protocol::Response::Queued(meshmsg_protocol::Queued {
            operation_id: wrong_operation,
            from: "1".repeat(64).parse().unwrap(),
            timestamp_ms: 1,
            body: meshmsg_protocol::BroadcastBody::new("hello").unwrap(),
        });
        assert!(request.validate_response(&mismatched).is_err());

        let error = meshmsg_protocol::ProtocolError::new(
            Some(meshmsg_protocol::OperationId::new_random()),
            meshmsg_protocol::ErrorCode::CommandTimeout,
            meshmsg_protocol::Outcome::Unknown,
        );
        assert!(validate_error_for_request(&error, &request).is_err());
    }

    #[test]
    fn response_decoder_requires_exact_correlation() {
        let frame = meshmsg_protocol::ResponseFrame::new(
            Some("0123456789abcdef0123456789abcdef".parse().unwrap()),
            meshmsg_protocol::Response::Stopping {},
        );
        let bytes = serde_json::to_vec(&frame).unwrap();
        let other = "11111111111111111111111111111111".parse().unwrap();
        assert!(decode_response_frame(&bytes, &other).is_err());
    }

    #[tokio::test]
    async fn ipc_reader_rejects_oversized_request() {
        use tokio::io::AsyncWriteExt;

        let (mut left, mut right) = tokio::io::duplex(MAX_IPC_REQUEST_SIZE + 1);
        let writer = tokio::spawn(async move {
            right
                .write_all(&vec![b'a'; MAX_IPC_REQUEST_SIZE + 1])
                .await
                .unwrap();
        });
        let error = read_frame(&mut left, MAX_IPC_REQUEST_SIZE)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("exceeds"));
        writer.await.unwrap();
    }
}
