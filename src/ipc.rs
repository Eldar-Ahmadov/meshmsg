//! Shared bounded newline-delimited local daemon protocol. Platform connection
//! ownership checks remain in node::connect_daemon for CLI and benchmark clients.
use crate::{
    config::State,
    contracts::{self, ProtocolErrorAdapter},
    node::{connect_daemon, LocalClientStream},
};
use anyhow::{Context, Result};
use iroh_gossip::proto::TopicId;
use std::path::Path;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, BufReader};

// The shared protocol crate owns framing bounds. Legacy in-crate DTOs use
// these aliases until their producers and consumers migrate to protocol v2.
pub(crate) use contracts::valid_operation_id;
pub(crate) use meshmsg_protocol::framing::{
    MAX_EVENT_FRAME_BYTES as MAX_IPC_EVENT_SIZE, MAX_REQUEST_FRAME_BYTES as MAX_IPC_REQUEST_SIZE,
};

pub(crate) fn prune_cutoff_upper_bound(now_ms: u64, older_than_secs: u64) -> u64 {
    now_ms.saturating_sub(older_than_secs.saturating_mul(1000))
}

pub(crate) fn new_operation_id() -> String {
    meshmsg_protocol::OperationId::new_random().into_string()
}

#[derive(Debug, Clone)]
pub(crate) enum LifecycleRequestContext<'a> {
    Remove {
        operation_id: &'a str,
        offer_id: &'a str,
        direction: Option<&'a str>,
        provider: Option<&'a str>,
        maximum: usize,
    },
    Prune {
        operation_id: &'a str,
        older_than_secs: u64,
        direction: Option<&'a str>,
        dry_run: bool,
        maximum: usize,
    },
}

impl LifecycleRequestContext<'_> {
    pub(crate) fn operation_id(&self) -> &str {
        match self {
            Self::Remove { operation_id, .. } | Self::Prune { operation_id, .. } => operation_id,
        }
    }
}

pub(crate) use meshmsg_protocol::DownloadRequestContext;

pub(crate) fn download_token_digest(token: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut digest = Sha256::new();
    digest.update(b"meshmsg-download-token-v1\0");
    digest.update((token.len() as u64).to_le_bytes());
    digest.update(token.as_bytes());
    data_encoding::HEXLOWER.encode(&digest.finalize())
}

pub(crate) const MAX_OFFER_LIST_ENTRIES: usize = meshmsg_protocol::MAX_OFFERS;
pub(crate) const MAX_OFFER_LIST_SCANNED: usize = meshmsg_protocol::MAX_OFFER_SCAN;

pub(crate) use meshmsg_protocol::{Request as IpcRequest, RequestFrame as IpcRequestFrame};

fn expected_error_operation_id(request: &IpcRequest) -> Option<&str> {
    match request {
        IpcRequest::Send { operation_id, .. }
        | IpcRequest::PrivateSend { operation_id, .. }
        | IpcRequest::OffersRemove { operation_id, .. }
        | IpcRequest::OffersPrune { operation_id, .. }
        | IpcRequest::Share { operation_id, .. }
        | IpcRequest::Download { operation_id, .. } => Some(operation_id.as_str()),
        IpcRequest::Subscribe
        | IpcRequest::Offers
        | IpcRequest::Status
        | IpcRequest::Peers
        | IpcRequest::Stop => None,
    }
}

fn decode_event_frame(
    bytes: &[u8],
    expected_request_id: &meshmsg_protocol::RequestId,
    expected_topic: Option<TopicId>,
) -> Result<meshmsg_protocol::EventFrame> {
    let frame: meshmsg_protocol::EventFrame =
        serde_json::from_slice(bytes).context("invalid typed event from local daemon")?;
    anyhow::ensure!(
        &frame.request_id == expected_request_id,
        "daemon event request ID does not match the subscription"
    );
    if let Some(topic) = expected_topic {
        validate_typed_attachment_event(topic, &frame.event)?;
    }
    Ok(frame)
}

fn validate_typed_attachment_event(topic: TopicId, event: &meshmsg_protocol::Event) -> Result<()> {
    let (from, message_id, timestamp_ms, offer_id, kind, name, size, ticket, token) = match event {
        meshmsg_protocol::Event::AttachmentOffer(value) => (
            &value.from,
            &value.message_id,
            value.timestamp_ms,
            &value.offer_id,
            value.kind,
            &value.name,
            value.size,
            &value.ticket,
            &value.offer,
        ),
        meshmsg_protocol::Event::AttachmentShared(value) => (
            &value.from,
            &value.message_id,
            value.timestamp_ms,
            &value.offer_id,
            value.kind,
            &value.name,
            value.size,
            &value.ticket,
            &value.offer,
        ),
        _ => return Ok(()),
    };
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock before Unix epoch")?
        .as_millis() as u64;
    meshmsg_protocol::validate_attachment_event(
        meshmsg_protocol::AttachmentEventRef {
            from,
            message_id,
            timestamp_ms,
            offer_id,
            kind,
            name,
            size,
            ticket,
            offer: token,
        },
        &topic.to_string().parse()?,
        now_ms,
    )
    .map_err(anyhow::Error::from)
}

fn decode_response_frame(
    frame: &[u8],
    expected_request_id: &meshmsg_protocol::RequestId,
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
fn decode_response(frame: &[u8], expected_request_id: &str) -> Result<serde_json::Value> {
    response_payload(decode_response_frame(frame, &expected_request_id.parse()?)?)
}

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
    request: &IpcRequest,
) -> Result<meshmsg_protocol::ResponseFrame> {
    let request_id = meshmsg_protocol::RequestId::new_random();
    send_request_with_id(dir, request, request_id.as_ref()).await
}

pub(crate) async fn send_request_with_id(
    dir: &Path,
    request: &IpcRequest,
    request_id: &str,
) -> Result<meshmsg_protocol::ResponseFrame> {
    let request_id: meshmsg_protocol::RequestId = request_id.parse()?;
    let mut stream = connect_daemon(dir).await?;
    write_request_with_id(&mut stream, request, request_id.as_ref()).await?;
    let bytes = read_frame(&mut stream, MAX_IPC_EVENT_SIZE).await?;
    let frame = decode_response_frame(&bytes, &request_id)?;
    if let meshmsg_protocol::Response::Error(error) = &frame.response {
        validate_error_for_request(error, request)?;
    }
    Ok(frame)
}

pub(crate) fn validate_error_for_request(
    error: &meshmsg_protocol::ProtocolError,
    request: &IpcRequest,
) -> Result<()> {
    let pre_admission = error.operation_id.is_none()
        && matches!(
            error.code,
            meshmsg_protocol::ErrorCode::IpcCapacity
                | meshmsg_protocol::ErrorCode::InitialFrameTimeout
        );
    anyhow::ensure!(
        pre_admission
            || error
                .operation_id
                .as_ref()
                .map(ToString::to_string)
                .as_deref()
                == expected_error_operation_id(request),
        "error operation ID does not match request"
    );
    Ok(())
}

pub(crate) fn response_payload(
    frame: meshmsg_protocol::ResponseFrame,
) -> Result<serde_json::Value> {
    meshmsg_protocol::DaemonFrame::Response(frame)
        .into_payload_value()
        .map_err(anyhow::Error::from)
}

pub(crate) fn event_payload(frame: meshmsg_protocol::EventFrame) -> Result<serde_json::Value> {
    meshmsg_protocol::DaemonFrame::Event(frame)
        .into_payload_value()
        .map_err(anyhow::Error::from)
}

pub(crate) async fn send_request_checked(
    dir: &Path,
    request: &IpcRequest,
    expected_type: &str,
    _expected_schema_version: Option<u64>,
) -> Result<meshmsg_protocol::ResponseFrame> {
    let frame = send_request(dir, request).await?;
    let matches = matches!(
        (&frame.response, expected_type),
        (meshmsg_protocol::Response::Status(_), "status")
            | (meshmsg_protocol::Response::Queued(_), "queued")
            | (
                meshmsg_protocol::Response::PrivateAccepted(_),
                "private_accepted"
            )
            | (
                meshmsg_protocol::Response::PeersSnapshot(_),
                "peers_snapshot"
            )
            | (meshmsg_protocol::Response::Offers(_), "offers")
            | (
                meshmsg_protocol::Response::AttachmentShared(_),
                "attachment_shared"
            )
            | (meshmsg_protocol::Response::OfferRemoved(_), "offer_removed")
            | (meshmsg_protocol::Response::OffersPruned(_), "offers_pruned")
            | (
                meshmsg_protocol::Response::DownloadComplete(_),
                "download_complete"
            )
            | (meshmsg_protocol::Response::Stopping { .. }, "stopping")
    );
    if let meshmsg_protocol::Response::Error(error) = frame.response.clone() {
        return Err(anyhow::Error::new(contracts::ContractFailure(
            ProtocolErrorAdapter::from_typed(frame.request_id.map(|id| id.to_string()), error),
        )));
    }
    anyhow::ensure!(
        matches,
        "daemon returned unexpected response type (expected {expected_type})"
    );
    Ok(frame)
}

#[cfg(test)]
pub(crate) async fn write_request<S: AsyncWrite + Unpin>(
    stream: &mut S,
    request: &IpcRequest,
) -> Result<()> {
    write_request_with_id(stream, request, &contracts::new_request_id()).await
}

pub(crate) async fn write_request_with_id<S: AsyncWrite + Unpin>(
    stream: &mut S,
    request: &IpcRequest,
    request_id: &str,
) -> Result<()> {
    anyhow::ensure!(
        contracts::valid_request_id(request_id),
        "invalid local IPC request ID"
    );
    let frame = IpcRequestFrame::new(request_id.parse()?, request.clone());
    meshmsg_protocol::write_json(stream, &frame, meshmsg_protocol::FrameLimit::Request)
        .await
        .map_err(anyhow::Error::from)
}

pub(crate) struct SubscriptionReader<S> {
    reader: BufReader<S>,
    frame: Vec<u8>,
    request_id: meshmsg_protocol::RequestId,
    expected_topic: Option<TopicId>,
}

impl<S: AsyncRead + Unpin> SubscriptionReader<S> {
    pub(crate) fn new_correlated_for_topic(
        stream: S,
        request_id: String,
        expected_topic: Option<TopicId>,
    ) -> Self {
        Self {
            reader: BufReader::new(stream),
            frame: Vec::new(),
            request_id: request_id
                .parse()
                .expect("validated subscription request ID"),
            expected_topic,
        }
    }

    /// Reads one event while retaining any bytes consumed if this future is
    /// cancelled by a competing `select!` branch.
    pub(crate) async fn read(&mut self) -> Result<Option<meshmsg_protocol::EventFrame>> {
        let limit = MAX_IPC_EVENT_SIZE + 2;
        anyhow::ensure!(self.frame.len() < limit, "daemon event is too large");
        let remaining = limit - self.frame.len();
        let read = (&mut self.reader)
            .take(remaining as u64)
            .read_until(b'\n', &mut self.frame)
            .await?;
        if read == 0 && self.frame.is_empty() {
            return Ok(None);
        }
        anyhow::ensure!(
            self.frame.len() <= MAX_IPC_EVENT_SIZE + 1,
            "daemon event is too large"
        );
        anyhow::ensure!(self.frame.ends_with(b"\n"), "incomplete daemon event");
        let result = decode_event_frame(&self.frame, &self.request_id, self.expected_topic)
            .context("invalid daemon event");
        self.frame.clear();
        result.map(Some)
    }
}

pub(crate) async fn subscribe(dir: &Path) -> Result<SubscriptionReader<LocalClientStream>> {
    subscribe_with_id(dir, &contracts::new_request_id()).await
}

pub(crate) async fn subscribe_with_id(
    dir: &Path,
    request_id: &str,
) -> Result<SubscriptionReader<LocalClientStream>> {
    let mut stream = connect_daemon(dir).await?;
    // Load after connecting so a stopped daemon's atomic state/socket
    // replacement cannot pair a new subscription with the previous topic.
    let expected_topic = Some(State::load(dir)?.topic_id()?);
    write_request_with_id(&mut stream, &IpcRequest::Subscribe, request_id).await?;
    Ok(SubscriptionReader::new_correlated_for_topic(
        stream,
        request_id.to_owned(),
        expected_topic,
    ))
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_decoder_rejects_legacy_error_presentation_fields() {
        let request_id = "0123456789abcdef0123456789abcdef";
        let legacy = serde_json::json!({
            "protocol_version": meshmsg_protocol::PROTOCOL_VERSION,
            "request_id": request_id,
            "type": "error",
            "schema_version": 2,
            "code": "invalid_request",
            "outcome": "rejected",
            "message": "legacy",
            "retryable": false
        });
        assert!(decode_response(&serde_json::to_vec(&legacy).unwrap(), request_id).is_err());
    }

    #[test]
    fn response_decoder_rejects_structurally_valid_semantic_forgery() {
        let request_id = "0123456789abcdef0123456789abcdef";
        let malformed = serde_json::json!({
            "protocol_version": 2,
            "schema_version": 3,
            "request_id": request_id,
            "type": "queued",
            "operation_id": "11111111111111111111111111111111",
            "from": "2".repeat(64),
            "message_id": "33333333333333333333333333333333",
            "timestamp_ms": 1,
            "body": "accepted JSON, forged semantics",
            "delivery_acknowledged": false
        });
        assert!(decode_response(&serde_json::to_vec(&malformed).unwrap(), request_id).is_err());
    }

    #[tokio::test]
    async fn subscription_reader_rejects_semantically_malformed_event() {
        let request_id = "0123456789abcdef0123456789abcdef";
        let (mut writer, reader) = tokio::io::duplex(4096);
        let malformed = serde_json::json!({
            "protocol_version": 2,
            "schema_version": 2,
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
        let mut subscription =
            SubscriptionReader::new_correlated_for_topic(reader, request_id.to_owned(), None);
        assert!(subscription.read().await.is_err());
    }

    async fn rejects_attachment_frame(
        event_topic: TopicId,
        expected_topic: TopicId,
        mutate: impl FnOnce(&mut serde_json::Value),
    ) {
        let request_id = "0123456789abcdef0123456789abcdef";
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let secret = iroh::SecretKey::generate();
        let mut event = crate::attachment::protocol::signed_attachment_event_for_topic_for_test(
            &secret,
            event_topic,
            "11111111111111111111111111111111",
            crate::attachment::AttachmentKind::File,
            "safe.txt",
            7,
            now_ms,
        );
        event["protocol_version"] = meshmsg_protocol::PROTOCOL_VERSION.into();
        event["request_id"] = request_id.into();
        mutate(&mut event);
        let (mut writer, reader) = tokio::io::duplex(16 * 1024);
        tokio::spawn(async move {
            let mut bytes = serde_json::to_vec(&event).unwrap();
            bytes.push(b'\n');
            tokio::io::AsyncWriteExt::write_all(&mut writer, &bytes)
                .await
                .unwrap();
        });
        let mut subscription = SubscriptionReader::new_correlated_for_topic(
            reader,
            request_id.to_owned(),
            Some(expected_topic),
        );
        assert!(subscription.read().await.is_err());
    }

    #[tokio::test]
    async fn default_subscription_rejects_forged_cross_topic_and_malformed_attachment_events() {
        let topic = TopicId::from_bytes([7; 32]);
        rejects_attachment_frame(topic, topic, |event| {
            let offer = event["offer"].as_str().unwrap();
            let replacement = if offer.ends_with('A') { 'B' } else { 'A' };
            event["offer"] = format!("{}{replacement}", &offer[..offer.len() - 1]).into();
        })
        .await;
        rejects_attachment_frame(TopicId::from_bytes([8; 32]), topic, |_| {}).await;
        rejects_attachment_frame(topic, topic, |event| {
            event["ticket"] = "not-a-ticket".into();
        })
        .await;
    }

    #[test]
    fn response_decoder_requires_exact_correlation() {
        let frame = meshmsg_protocol::ResponseFrame::new(
            Some("0123456789abcdef0123456789abcdef".parse().unwrap()),
            meshmsg_protocol::Response::Stopping {
                outcome: "stopping".to_owned(),
            },
        );
        let bytes = serde_json::to_vec(&frame).unwrap();
        assert!(decode_response(&bytes, "11111111111111111111111111111111").is_err());
    }
}
