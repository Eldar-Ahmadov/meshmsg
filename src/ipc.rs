//! Shared bounded newline-delimited local daemon protocol. Platform connection
//! ownership checks remain in node::connect_daemon for both CLI and web clients.
#[cfg(feature = "web")]
use crate::attachment::AttachmentOffer;
use crate::{
    config::State,
    contracts::{self, ProtocolErrorAdapter},
    node::{connect_daemon, LocalClientStream},
};
use anyhow::{Context, Result};
use iroh_gossip::proto::TopicId;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, BufReader};

// The shared protocol crate owns framing bounds. Legacy in-crate DTOs use
// these aliases until their producers and consumers migrate to protocol v2.
pub(crate) use contracts::valid_operation_id;
pub(crate) use meshmsg_protocol::framing::{
    MAX_EVENT_FRAME_BYTES as MAX_IPC_EVENT_SIZE, MAX_REQUEST_FRAME_BYTES as MAX_IPC_REQUEST_SIZE,
};

#[cfg(feature = "web")]
pub(crate) fn validate_lifecycle_error_for_request(
    value: &serde_json::Value,
    operation_id: &str,
) -> Result<ProtocolErrorAdapter> {
    let error = ProtocolErrorAdapter::from_value(value)?;
    error.validate_operation_id(Some(operation_id))?;
    Ok(error)
}

pub(crate) fn valid_content_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn prune_cutoff_upper_bound(now_ms: u64, older_than_secs: u64) -> u64 {
    now_ms.saturating_sub(older_than_secs.saturating_mul(1000))
}

pub(crate) fn new_operation_id() -> String {
    meshmsg_protocol::OperationId::new_random().into_string()
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct LifecycleSuccessV3 {
    #[serde(rename = "type")]
    pub(crate) family: String,
    pub(crate) schema_version: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) request_id: Option<String>,
    pub(crate) operation_id: String,
    pub(crate) offer_id: Option<String>,
    pub(crate) direction: Option<String>,
    pub(crate) provider: Option<String>,
    pub(crate) older_than_secs: Option<u64>,
    pub(crate) maximum: usize,
    pub(crate) dry_run: bool,
    pub(crate) selected_tags: usize,
    pub(crate) removed_tags: usize,
    pub(crate) released_bytes: u64,
    pub(crate) limited: bool,
    pub(crate) cutoff_ms: Option<u64>,
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
        /// `None` for a caller validating a daemon-resolved cutoff; `Some` for
        /// the daemon producer and generic strict response validation.
        cutoff_ms: Option<u64>,
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

impl LifecycleSuccessV3 {
    pub(crate) fn new(
        context: &LifecycleRequestContext<'_>,
        selected_tags: usize,
        removed_tags: usize,
        released_bytes: u64,
        limited: bool,
        cutoff_ms: Option<u64>,
    ) -> Result<Self> {
        let (
            family,
            operation_id,
            offer_id,
            direction,
            provider,
            older_than_secs,
            maximum,
            dry_run,
        ) = match context {
            LifecycleRequestContext::Remove {
                operation_id,
                offer_id,
                direction,
                provider,
                maximum,
            } => (
                "offer_removed",
                *operation_id,
                Some(*offer_id),
                *direction,
                *provider,
                None,
                *maximum,
                false,
            ),
            LifecycleRequestContext::Prune {
                operation_id,
                older_than_secs,
                direction,
                dry_run,
                maximum,
                ..
            } => (
                "offers_pruned",
                *operation_id,
                None,
                *direction,
                None,
                Some(*older_than_secs),
                *maximum,
                *dry_run,
            ),
        };
        let result = Self {
            family: family.into(),
            schema_version: 3,
            request_id: None,
            operation_id: operation_id.into(),
            offer_id: offer_id.map(str::to_owned),
            direction: direction.map(str::to_owned),
            provider: provider.map(str::to_owned),
            older_than_secs,
            maximum,
            dry_run,
            selected_tags,
            removed_tags,
            released_bytes,
            limited,
            cutoff_ms,
        };
        result.validate_for_request(context, false)?;
        Ok(result)
    }

    pub(crate) fn from_value_for_request(
        value: &serde_json::Value,
        context: &LifecycleRequestContext<'_>,
    ) -> Result<Self> {
        let dto: Self =
            serde_json::from_value(value.clone()).context("malformed lifecycle response")?;
        dto.validate_for_request(context, true)?;
        Ok(dto)
    }

    fn validate_for_request(
        &self,
        context: &LifecycleRequestContext<'_>,
        correlated: bool,
    ) -> Result<()> {
        let expected = match context {
            LifecycleRequestContext::Remove {
                operation_id,
                offer_id,
                direction,
                provider,
                maximum,
            } => (
                "offer_removed",
                *operation_id,
                Some(*offer_id),
                *direction,
                *provider,
                None,
                *maximum,
                false,
            ),
            LifecycleRequestContext::Prune {
                operation_id,
                older_than_secs,
                direction,
                dry_run,
                maximum,
                ..
            } => (
                "offers_pruned",
                *operation_id,
                None,
                *direction,
                None,
                Some(*older_than_secs),
                *maximum,
                *dry_run,
            ),
        };
        anyhow::ensure!(
            self.family == expected.0
                && self.schema_version == 3
                && self.operation_id == expected.1
                && self.offer_id.as_deref() == expected.2
                && self.direction.as_deref() == expected.3
                && self.provider.as_deref() == expected.4
                && self.older_than_secs == expected.5
                && self.maximum == expected.6
                && self.dry_run == expected.7,
            "lifecycle response does not match its request"
        );
        anyhow::ensure!(
            valid_operation_id(&self.operation_id)
                && self.maximum > 0
                && self.selected_tags <= self.maximum
                && self.removed_tags <= self.selected_tags
                && (!self.dry_run || self.removed_tags == 0)
                && (self.dry_run || self.removed_tags == self.selected_tags)
                && (!self.limited || self.selected_tags == self.maximum)
                && (self.selected_tags != 0 || self.released_bytes == 0),
            "invalid lifecycle selection/count/byte invariants"
        );
        anyhow::ensure!(
            self.direction
                .as_deref()
                .is_none_or(|v| matches!(v, "incoming" | "outgoing"))
                && self.provider.as_deref().is_none_or(valid_peer_id),
            "invalid lifecycle selectors"
        );
        anyhow::ensure!(
            match context {
                LifecycleRequestContext::Remove { .. } => self.cutoff_ms.is_none(),
                LifecycleRequestContext::Prune { cutoff_ms, .. } =>
                    cutoff_ms.is_none_or(|expected| self.cutoff_ms == Some(expected))
                        && self.cutoff_ms.is_some(),
            },
            "invalid lifecycle cutoff"
        );
        anyhow::ensure!(
            if correlated {
                self.request_id
                    .as_deref()
                    .is_some_and(contracts::valid_request_id)
            } else {
                self.request_id.is_none()
            },
            "invalid lifecycle request correlation"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DownloadCompleteV2 {
    #[serde(rename = "type")]
    family: String,
    schema_version: u8,
    request_id: String,
    pub(crate) operation_id: String,
    pub(crate) token_digest: String,
    pub(crate) offer_id: String,
    pub(crate) kind: String,
    pub(crate) name: String,
    pub(crate) size: u64,
    pub(crate) from: String,
    pub(crate) output: PathBuf,
    installed: bool,
    pinned: bool,
    destination_synced: bool,
    cleanup_complete: bool,
    warnings: Vec<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct DownloadRequestContext {
    pub(crate) operation_id: String,
    pub(crate) token_digest: String,
    pub(crate) offer_id: String,
    pub(crate) provider: String,
    pub(crate) kind: String,
    pub(crate) name: String,
    pub(crate) declared_size: Option<u64>,
    pub(crate) output: PathBuf,
}

pub(crate) fn download_token_digest(token: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut digest = Sha256::new();
    digest.update(b"meshmsg-download-token-v1\0");
    digest.update((token.len() as u64).to_le_bytes());
    digest.update(token.as_bytes());
    data_encoding::HEXLOWER.encode(&digest.finalize())
}

impl DownloadCompleteV2 {
    pub(crate) fn from_value(value: &serde_json::Value) -> Result<Self> {
        let dto: Self = serde_json::from_value(value.clone())
            .context("malformed download-complete response")?;
        anyhow::ensure!(
            valid_family(
                &dto.family,
                "download_complete",
                dto.schema_version,
                &dto.request_id
            ) && dto.schema_version == 2
                && valid_operation_id(&dto.operation_id)
                && valid_content_digest(&dto.token_digest)
                && valid_operation_id(&dto.offer_id)
                && matches!(dto.kind.as_str(), "file" | "directory_tar_v1")
                && valid_public_text(&dto.name, 255)
                && valid_peer_id(&dto.from)
                && !dto.output.as_os_str().is_empty()
                && dto.installed
                && dto.pinned
                && dto.warnings.len() <= 32
                && dto
                    .warnings
                    .iter()
                    .all(|warning| valid_public_text(warning, contracts::MAX_PUBLIC_MESSAGE_BYTES)),
            "invalid download-complete response"
        );
        let _ = (dto.size, dto.destination_synced, dto.cleanup_complete);
        Ok(dto)
    }

    pub(crate) fn validate_for_request(
        value: &serde_json::Value,
        expected: &DownloadRequestContext,
    ) -> Result<Self> {
        let dto = Self::from_value(value)?;
        anyhow::ensure!(
            dto.operation_id == expected.operation_id,
            "download operation ID mismatch"
        );
        anyhow::ensure!(
            dto.token_digest == expected.token_digest,
            "download token identity mismatch"
        );
        anyhow::ensure!(
            dto.offer_id == expected.offer_id,
            "download offer ID mismatch"
        );
        anyhow::ensure!(dto.from == expected.provider, "download provider mismatch");
        anyhow::ensure!(dto.kind == expected.kind, "download kind mismatch");
        anyhow::ensure!(dto.name == expected.name, "download name mismatch");
        anyhow::ensure!(
            expected.declared_size.is_none_or(|size| dto.size == size),
            "download declared size mismatch"
        );
        anyhow::ensure!(
            dto.output.as_os_str() == expected.output.as_os_str(),
            "download output mismatch"
        );
        Ok(dto)
    }
}

#[cfg(feature = "web")]
pub(crate) fn validate_attachment_event_fields(
    expected_topic: Option<TopicId>,
    live_now_ms: Option<u64>,
    from: &str,
    message_id: &str,
    timestamp_ms: u64,
    offer: &AttachmentOffer,
    offer_token: &str,
) -> bool {
    crate::attachment::protocol::validate_attachment_event(
        expected_topic,
        live_now_ms,
        from,
        message_id,
        timestamp_ms,
        offer,
        offer_token,
    )
    .is_ok()
}

fn valid_peer_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_family(family: &str, expected: &str, version: u8, request_id: &str) -> bool {
    family == expected && version > 0 && contracts::valid_request_id(request_id)
}

fn valid_public_text(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && !value.chars().any(char::is_control)
}

pub(crate) const MAX_OFFER_LIST_ENTRIES: usize = 512;
pub(crate) const MAX_OFFER_LIST_SCANNED: usize = 4096;

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
    #[cfg(feature = "web")]
    if let Some(topic) = expected_topic {
        validate_typed_attachment_event(topic, &frame.event)?;
    }
    #[cfg(not(feature = "web"))]
    let _ = expected_topic;
    Ok(frame)
}

#[cfg(feature = "web")]
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
    let offer = AttachmentOffer {
        offer_id: offer_id.to_string(),
        kind: match kind {
            meshmsg_protocol::AttachmentKind::File => crate::attachment::AttachmentKind::File,
            meshmsg_protocol::AttachmentKind::DirectoryTarV1 => {
                crate::attachment::AttachmentKind::DirectoryTarV1
            }
        },
        name: name.as_str().to_owned(),
        size,
        ticket: ticket.as_str().to_owned(),
    };
    crate::attachment::protocol::validate_attachment_event(
        Some(topic),
        None,
        from.as_str(),
        message_id.as_str(),
        timestamp_ms,
        &offer,
        token.as_str(),
    )
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
    #[cfg(feature = "web")]
    expected_topic: Option<TopicId>,
}

impl<S: AsyncRead + Unpin> SubscriptionReader<S> {
    pub(crate) fn new_correlated_for_topic(
        stream: S,
        request_id: String,
        expected_topic: Option<TopicId>,
    ) -> Self {
        #[cfg(not(feature = "web"))]
        let _ = expected_topic;
        Self {
            reader: BufReader::new(stream),
            frame: Vec::new(),
            request_id: request_id
                .parse()
                .expect("validated subscription request ID"),
            #[cfg(feature = "web")]
            expected_topic,
        }
    }

    #[cfg(feature = "web")]
    pub(crate) fn expected_topic(&self) -> Option<TopicId> {
        self.expected_topic
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
        let result = decode_event_frame(&self.frame, &self.request_id, {
            #[cfg(feature = "web")]
            {
                self.expected_topic
            }
            #[cfg(not(feature = "web"))]
            {
                None
            }
        })
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
    #[cfg(not(test))]
    let expected_topic = Some(State::load(dir)?.topic_id()?);
    #[cfg(test)]
    let expected_topic = State::load(dir)
        .ok()
        .and_then(|state| state.topic_id().ok());
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
