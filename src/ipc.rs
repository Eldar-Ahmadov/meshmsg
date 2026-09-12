//! Shared bounded newline-delimited local daemon protocol. Platform connection
//! ownership checks remain in node::connect_daemon for both CLI and web clients.
use crate::{
    attachment::{AttachmentKind, AttachmentOffer},
    config::State,
    contracts::{self, ErrorEnvelopeV1},
    message::validate_v2_message_body,
    node::{connect_daemon, LocalClientStream},
};
use anyhow::{Context, Result};
use iroh_gossip::proto::TopicId;
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
#[cfg(test)]
use tokio::io::AsyncWriteExt;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, BufReader};

// The shared protocol crate owns framing bounds. Legacy in-crate DTOs use
// these aliases until their producers and consumers migrate to protocol v2.
pub(crate) use meshmsg_protocol::framing::{
    MAX_EVENT_FRAME_BYTES as MAX_IPC_EVENT_SIZE, MAX_REQUEST_FRAME_BYTES as MAX_IPC_REQUEST_SIZE,
};
pub(crate) type LifecycleErrorV1 = ErrorEnvelopeV1;

pub(crate) use contracts::valid_operation_id;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AttachmentOperationKind {
    Share,
    Remove,
    Prune,
    Download,
}

fn contract_operation_kind(kind: AttachmentOperationKind) -> contracts::ErrorOperationKind {
    match kind {
        AttachmentOperationKind::Share => contracts::ErrorOperationKind::Share,
        AttachmentOperationKind::Remove => contracts::ErrorOperationKind::Remove,
        AttachmentOperationKind::Prune => contracts::ErrorOperationKind::Prune,
        AttachmentOperationKind::Download => contracts::ErrorOperationKind::Download,
    }
}

pub(crate) fn validate_lifecycle_error_for_request(
    value: &serde_json::Value,
    kind: AttachmentOperationKind,
    operation_id: &str,
    expected_offer_id: Option<&str>,
    lifecycle_context: Option<&LifecycleRequestContext<'_>>,
) -> Result<LifecycleErrorV1> {
    let error = LifecycleErrorV1::from_value(value)?;
    error.validate_for_operation(contract_operation_kind(kind), Some(operation_id))?;
    anyhow::ensure!(
        error.operation_id.as_deref() == Some(operation_id),
        "daemon lifecycle error operation ID does not match the request"
    );
    let partial_removal = error.code == "attachment_removal_partial";
    let offer_specific = error.code == "invalid_offer_selector"
        || (partial_removal && kind == AttachmentOperationKind::Remove);
    if offer_specific {
        let expected =
            expected_offer_id.context("offer-specific lifecycle request omitted its selector")?;
        anyhow::ensure!(
            if valid_operation_id(expected) {
                error.offer_id.as_deref() == Some(expected)
            } else {
                error.offer_id.is_none()
            },
            "offer-specific lifecycle error omitted or mismatched its offer ID"
        );
    } else {
        anyhow::ensure!(
            error.offer_id.is_none(),
            "daemon lifecycle error included an inapplicable offer ID"
        );
    }
    anyhow::ensure!(
        partial_removal == error.selected_tags.is_some()
            && partial_removal == error.removed_tags.is_some()
            && partial_removal == error.quota_bytes_released.is_some(),
        "daemon lifecycle error included inapplicable removal accounting"
    );
    if partial_removal {
        let context = lifecycle_context.context("partial lifecycle error lacks request context")?;
        let (direction, provider, age, maximum, dry_run) = match context {
            LifecycleRequestContext::Remove {
                operation_id: expected,
                direction,
                provider,
                maximum,
                ..
            } => {
                anyhow::ensure!(
                    *expected == operation_id && kind == AttachmentOperationKind::Remove,
                    "partial remove context is mismatched"
                );
                (*direction, *provider, None, *maximum, false)
            }
            LifecycleRequestContext::Prune {
                operation_id: expected,
                older_than_secs,
                direction,
                dry_run,
                maximum,
                ..
            } => {
                anyhow::ensure!(
                    *expected == operation_id && kind == AttachmentOperationKind::Prune,
                    "partial prune context is mismatched"
                );
                (*direction, None, Some(*older_than_secs), *maximum, *dry_run)
            }
        };
        anyhow::ensure!(
            error.direction.as_deref() == direction
                && error.provider.as_deref() == provider
                && error.older_than_secs == age
                && error.maximum == Some(maximum)
                && error.dry_run == Some(dry_run),
            "partial lifecycle context does not match request"
        );
        anyhow::ensure!(
            !dry_run && maximum > 0,
            "dry-run cannot report partial mutation"
        );
        anyhow::ensure!(
            match (age, context) {
                (None, _) => error.cutoff_ms.is_none(),
                (Some(_), LifecycleRequestContext::Prune { cutoff_ms, .. }) =>
                    cutoff_ms.is_none_or(|expected| error.cutoff_ms == Some(expected))
                        && error.cutoff_ms.is_some(),
                _ => false,
            },
            "partial lifecycle cutoff is invalid"
        );
        let selected = error.selected_tags.unwrap();
        let removed = error.removed_tags.unwrap();
        let released = error.quota_bytes_released.unwrap();
        anyhow::ensure!(
            selected > 0
                && selected <= maximum
                && removed <= selected
                && ((error.outcome == "partial" && removed > 0)
                    || (error.outcome == "unknown" && removed == 0))
                && (removed > 0 || released == 0),
            "partial lifecycle counts/outcome/bytes are impossible"
        );
    } else {
        anyhow::ensure!(
            error.direction.is_none()
                && error.provider.is_none()
                && error.older_than_secs.is_none()
                && error.maximum.is_none()
                && error.dry_run.is_none()
                && error.cutoff_ms.is_none(),
            "non-partial error included lifecycle context"
        );
    }
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

pub(crate) use meshmsg_protocol::Status;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct QueuedV3 {
    #[serde(rename = "type")]
    pub(crate) kind: String,
    pub(crate) schema_version: u8,
    pub(crate) request_id: String,
    pub(crate) operation_id: String,
    pub(crate) from: String,
    pub(crate) message_id: String,
    pub(crate) timestamp_ms: u64,
    pub(crate) body: String,
    pub(crate) delivery_acknowledged: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConnectedV1 {
    #[serde(rename = "type")]
    kind: String,
    schema_version: u8,
    request_id: String,
    peer: String,
    endpoint_online: bool,
    topic_joined: bool,
    alias: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MessageV2 {
    #[serde(rename = "type")]
    kind: String,
    schema_version: u8,
    request_id: String,
    from: String,
    message_id: String,
    timestamp_ms: u64,
    body: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateMessageV1 {
    #[serde(rename = "type")]
    kind: String,
    schema_version: u8,
    request_id: String,
    private: bool,
    from: String,
    message_id: String,
    timestamp_ms: u64,
    body: String,
    acceptance_acknowledged: bool,
    durable: bool,
    read: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateAcceptedV3 {
    #[serde(rename = "type")]
    kind: String,
    schema_version: u8,
    request_id: String,
    operation_id: String,
    to: String,
    message_id: String,
    timestamp_ms: u64,
    body_bytes: usize,
    acceptance_acknowledged: bool,
    duplicate_accepted: bool,
    durable: bool,
    read: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttachmentOfferV2 {
    #[serde(rename = "type")]
    family: String,
    schema_version: u8,
    request_id: String,
    from: String,
    message_id: String,
    timestamp_ms: u64,
    offer_id: String,
    kind: String,
    name: String,
    size: u64,
    ticket: String,
    offer: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttachmentSharedV3 {
    #[serde(rename = "type")]
    family: String,
    schema_version: u8,
    request_id: String,
    operation_id: String,
    from: String,
    message_id: String,
    timestamp_ms: u64,
    offer_id: String,
    source_digest: String,
    kind: String,
    name: String,
    size: u64,
    ticket: String,
    offer: String,
    delivery_acknowledged: bool,
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

    pub(crate) fn into_value(self) -> serde_json::Value {
        serde_json::to_value(self).expect("lifecycle success serialization cannot fail")
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DownloadStartedV2 {
    #[serde(rename = "type")]
    family: String,
    schema_version: u8,
    request_id: String,
    operation_id: String,
    output: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DownloadProgressV2 {
    #[serde(rename = "type")]
    family: String,
    schema_version: u8,
    request_id: String,
    operation_id: String,
    received_bytes: u64,
    total_bytes: u64,
    output: PathBuf,
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoppingV1 {
    #[serde(rename = "type")]
    family: String,
    schema_version: u8,
    request_id: String,
    outcome: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LaggedV1 {
    #[serde(rename = "type")]
    family: String,
    schema_version: u8,
    request_id: String,
    source: String,
    dropped: Option<u64>,
    message: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PeerConnectivityV1 {
    #[serde(rename = "type")]
    family: String,
    schema_version: u8,
    request_id: String,
    peer: String,
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

pub(crate) fn validate_attachment_event_fields(
    expected_topic: Option<TopicId>,
    live_now_ms: Option<u64>,
    from: &str,
    message_id: &str,
    timestamp_ms: u64,
    offer: &AttachmentOffer,
    offer_token: &str,
) -> bool {
    crate::node::validate_attachment_event(
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

#[cfg(test)]
pub(crate) fn validate_success_payload(value: &serde_json::Value) -> Result<()> {
    validate_success_payload_for_context(value, None, None)
}

pub(crate) fn validate_success_payload_for_context(
    value: &serde_json::Value,
    expected_topic: Option<TopicId>,
    live_now_ms: Option<u64>,
) -> Result<()> {
    let family = value
        .get("type")
        .and_then(serde_json::Value::as_str)
        .context("response type is missing")?;
    let version = value
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        .context("response schema version is missing")?;
    match (family, version) {
        ("status", 1) => {
            status_from_value(value)?;
        }
        ("queued", 3) => {
            let dto: QueuedV3 =
                serde_json::from_value(value.clone()).context("malformed queued record")?;
            dto.validate()?;
        }
        ("connected", 1) => {
            let dto: ConnectedV1 =
                serde_json::from_value(value.clone()).context("malformed connected event")?;
            anyhow::ensure!(
                valid_family(&dto.kind, family, dto.schema_version, &dto.request_id)
                    && valid_peer_id(&dto.peer),
                "invalid connected event"
            );
            anyhow::ensure!(
                dto.alias
                    .as_deref()
                    .is_none_or(|alias| valid_public_text(alias, 63)),
                "invalid connected alias"
            );
            let _ = (dto.endpoint_online, dto.topic_joined);
        }
        ("message", 2) => {
            let dto: MessageV2 =
                serde_json::from_value(value.clone()).context("malformed message event")?;
            anyhow::ensure!(
                valid_family(&dto.kind, family, dto.schema_version, &dto.request_id)
                    && valid_peer_id(&dto.from)
                    && valid_operation_id(&dto.message_id)
                    && dto.timestamp_ms != 0
                    && validate_v2_message_body(&dto.body).is_ok(),
                "invalid message event"
            );
        }
        ("private_message", 1) => {
            let dto: PrivateMessageV1 =
                serde_json::from_value(value.clone()).context("malformed private message event")?;
            anyhow::ensure!(
                valid_family(&dto.kind, family, dto.schema_version, &dto.request_id)
                    && dto.private
                    && dto.acceptance_acknowledged
                    && !dto.durable
                    && !dto.read
                    && valid_peer_id(&dto.from)
                    && valid_operation_id(&dto.message_id)
                    && dto.timestamp_ms != 0
                    && !dto.body.is_empty()
                    && dto.body.len() <= 4096,
                "invalid private message event"
            );
        }
        ("private_accepted", 3) => {
            let dto: PrivateAcceptedV3 =
                serde_json::from_value(value.clone()).context("malformed private acceptance")?;
            anyhow::ensure!(
                valid_family(&dto.kind, family, dto.schema_version, &dto.request_id)
                    && valid_operation_id(&dto.operation_id)
                    && dto.message_id == dto.operation_id
                    && valid_peer_id(&dto.to)
                    && dto.timestamp_ms != 0
                    && dto.body_bytes > 0
                    && dto.body_bytes <= 4096
                    && dto.acceptance_acknowledged
                    && !dto.durable
                    && !dto.read,
                "invalid private acceptance"
            );
            let _ = dto.duplicate_accepted;
        }
        ("attachment_offer", 2) => {
            let dto: AttachmentOfferV2 =
                serde_json::from_value(value.clone()).context("malformed attachment offer")?;
            let kind = match dto.kind.as_str() {
                "file" => AttachmentKind::File,
                "directory_tar_v1" => AttachmentKind::DirectoryTarV1,
                _ => anyhow::bail!("invalid attachment offer"),
            };
            let offer = AttachmentOffer {
                offer_id: dto.offer_id.clone(),
                kind,
                name: dto.name.clone(),
                size: dto.size,
                ticket: dto.ticket.clone(),
            };
            anyhow::ensure!(
                valid_family(&dto.family, family, dto.schema_version, &dto.request_id)
                    && valid_peer_id(&dto.from)
                    && valid_operation_id(&dto.message_id)
                    && dto.offer_id == dto.message_id
                    && dto.timestamp_ms != 0
                    && valid_public_text(&dto.name, 255)
                    && validate_attachment_event_fields(
                        expected_topic,
                        live_now_ms,
                        &dto.from,
                        &dto.message_id,
                        dto.timestamp_ms,
                        &offer,
                        &dto.offer,
                    ),
                "invalid attachment offer"
            );
        }
        ("attachment_shared", 3) => {
            let dto: AttachmentSharedV3 =
                serde_json::from_value(value.clone()).context("malformed attachment share")?;
            let kind = match dto.kind.as_str() {
                "file" => AttachmentKind::File,
                "directory_tar_v1" => AttachmentKind::DirectoryTarV1,
                _ => anyhow::bail!("invalid attachment share"),
            };
            let offer = AttachmentOffer {
                offer_id: dto.offer_id.clone(),
                kind,
                name: dto.name.clone(),
                size: dto.size,
                ticket: dto.ticket.clone(),
            };
            anyhow::ensure!(
                valid_family(&dto.family, family, dto.schema_version, &dto.request_id)
                    && valid_operation_id(&dto.operation_id)
                    && dto.message_id == dto.operation_id
                    && dto.offer_id == dto.operation_id
                    && valid_content_digest(&dto.source_digest)
                    && valid_peer_id(&dto.from)
                    && dto.timestamp_ms != 0
                    && valid_public_text(&dto.name, 255)
                    && validate_attachment_event_fields(
                        expected_topic,
                        live_now_ms,
                        &dto.from,
                        &dto.message_id,
                        dto.timestamp_ms,
                        &offer,
                        &dto.offer,
                    )
                    && !dto.delivery_acknowledged,
                "invalid attachment share"
            );
        }
        ("offers", 1) => {
            let dto: OffersV1 =
                serde_json::from_value(value.clone()).context("malformed offers response")?;
            dto.validate()?;
        }
        ("offer_removed" | "offers_pruned", 3) => {
            let dto: LifecycleSuccessV3 =
                serde_json::from_value(value.clone()).context("malformed lifecycle response")?;
            let context = if family == "offer_removed" {
                LifecycleRequestContext::Remove {
                    operation_id: &dto.operation_id,
                    offer_id: dto
                        .offer_id
                        .as_deref()
                        .context("removed offer ID missing")?,
                    direction: dto.direction.as_deref(),
                    provider: dto.provider.as_deref(),
                    maximum: dto.maximum,
                }
            } else {
                LifecycleRequestContext::Prune {
                    operation_id: &dto.operation_id,
                    older_than_secs: dto.older_than_secs.context("prune age missing")?,
                    cutoff_ms: Some(dto.cutoff_ms.context("prune cutoff missing")?),
                    direction: dto.direction.as_deref(),
                    dry_run: dto.dry_run,
                    maximum: dto.maximum,
                }
            };
            dto.validate_for_request(&context, true)?;
        }
        ("download_started", 2) => {
            let dto: DownloadStartedV2 = serde_json::from_value(value.clone())
                .context("malformed download-started event")?;
            anyhow::ensure!(
                valid_family(&dto.family, family, dto.schema_version, &dto.request_id)
                    && valid_operation_id(&dto.operation_id)
                    && !dto.output.as_os_str().is_empty(),
                "invalid download-started event"
            );
        }
        ("download_progress", 2) => {
            let dto: DownloadProgressV2 = serde_json::from_value(value.clone())
                .context("malformed download-progress event")?;
            anyhow::ensure!(
                valid_family(&dto.family, family, dto.schema_version, &dto.request_id)
                    && valid_operation_id(&dto.operation_id)
                    && !dto.output.as_os_str().is_empty()
                    && dto.received_bytes <= dto.total_bytes
                    && (dto.total_bytes > 0 || dto.received_bytes == 0),
                "invalid download-progress event"
            );
        }
        ("download_complete", 2) => {
            DownloadCompleteV2::from_value(value)?;
        }
        ("stopping", 1) => {
            let dto: StoppingV1 =
                serde_json::from_value(value.clone()).context("malformed stop response")?;
            anyhow::ensure!(
                valid_family(&dto.family, family, dto.schema_version, &dto.request_id)
                    && dto.outcome == "accepted",
                "invalid stop response"
            );
        }
        ("peers_snapshot", 2) => crate::peers::validate_snapshot(value)?,
        ("peer_discovered" | "peer_updated" | "peer_expired", 2) => {
            crate::peers::validate_transition(value, family)?
        }
        ("peer_up" | "peer_down", 1) => {
            let dto: PeerConnectivityV1 = serde_json::from_value(value.clone())
                .context("malformed peer connectivity event")?;
            anyhow::ensure!(
                valid_family(&dto.family, family, dto.schema_version, &dto.request_id)
                    && valid_peer_id(&dto.peer),
                "invalid peer connectivity event"
            );
        }
        ("lagged", 1) => {
            let dto: LaggedV1 =
                serde_json::from_value(value.clone()).context("malformed lag event")?;
            anyhow::ensure!(
                valid_family(&dto.family, family, dto.schema_version, &dto.request_id)
                    && matches!(dto.source.as_str(), "local" | "gossip")
                    && valid_public_text(&dto.message, contracts::MAX_PUBLIC_MESSAGE_BYTES)
                    && ((dto.source == "local" && dto.dropped.is_some_and(|n| n > 0))
                        || (dto.source == "gossip" && dto.dropped.is_none())),
                "invalid lag event"
            );
        }
        _ => anyhow::bail!("unknown or unsupported IPC response family {family} schema {version}"),
    }
    Ok(())
}

impl QueuedV3 {
    fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            self.kind == "queued" && self.schema_version == 3,
            "invalid queued response version"
        );
        anyhow::ensure!(
            contracts::valid_request_id(&self.request_id),
            "invalid queued request ID"
        );
        anyhow::ensure!(
            valid_operation_id(&self.operation_id) && self.operation_id == self.message_id,
            "invalid queued operation identity"
        );
        anyhow::ensure!(
            valid_peer_id(&self.from)
                && self.timestamp_ms != 0
                && validate_v2_message_body(&self.body).is_ok()
                && !self.delivery_acknowledged,
            "invalid queued response values"
        );
        Ok(())
    }
}

pub(crate) const MAX_OFFER_LIST_ENTRIES: usize = 512;
pub(crate) const MAX_OFFER_LIST_SCANNED: usize = 4096;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OfferItemV1 {
    pub(crate) direction: String,
    pub(crate) offer_id: String,
    #[serde(default)]
    pub(crate) provider: Option<String>,
    pub(crate) name: String,
    pub(crate) kind: String,
    pub(crate) hash: String,
    pub(crate) format: String,
    pub(crate) status: String,
    #[serde(default)]
    pub(crate) size: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OffersV1 {
    #[serde(rename = "type")]
    kind: String,
    schema_version: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<String>,
    blobs: Vec<OfferItemV1>,
    truncated: bool,
    has_more: bool,
    item_errors: usize,
}

impl OffersV1 {
    pub(crate) fn new(blobs: Vec<OfferItemV1>, has_more: bool, item_errors: usize) -> Result<Self> {
        let result = Self {
            kind: "offers".into(),
            schema_version: 1,
            request_id: None,
            blobs,
            truncated: has_more,
            has_more,
            item_errors,
        };
        result.validate_common(false)?;
        Ok(result)
    }

    pub(crate) fn into_value(self) -> serde_json::Value {
        serde_json::to_value(self).expect("offers serialization cannot fail")
    }

    fn validate(&self) -> Result<()> {
        self.validate_common(true)
    }

    fn validate_common(&self, correlated: bool) -> Result<()> {
        anyhow::ensure!(
            self.kind == "offers" && self.schema_version == 1,
            "invalid offers response version"
        );
        anyhow::ensure!(
            if correlated {
                self.request_id
                    .as_deref()
                    .is_some_and(contracts::valid_request_id)
            } else {
                self.request_id.is_none()
            },
            "invalid offers request ID"
        );
        anyhow::ensure!(
            self.blobs.len() <= MAX_OFFER_LIST_ENTRIES
                && self.truncated == self.has_more
                && (self.item_errors == 0 || self.has_more),
            "invalid offers bounds"
        );
        for item in &self.blobs {
            anyhow::ensure!(
                matches!(item.direction.as_str(), "incoming" | "outgoing")
                    && valid_operation_id(&item.offer_id),
                "invalid offer identity"
            );
            anyhow::ensure!(
                valid_public_text(&item.name, 255)
                    && matches!(item.kind.as_str(), "file" | "directory_tar_v1")
                    && valid_content_digest(&item.hash)
                    && item.format == "raw"
                    && item.status == "complete"
                    && item.size.is_some()
                    && match item.direction.as_str() {
                        "incoming" => item.provider.as_deref().is_some_and(valid_peer_id),
                        "outgoing" => item.provider.is_none(),
                        _ => false,
                    },
                "invalid offer metadata"
            );
        }
        anyhow::ensure!(
            self.item_errors <= MAX_OFFER_LIST_SCANNED,
            "invalid offer item error count"
        );
        Ok(())
    }
}

pub(crate) fn status_from_value(value: &serde_json::Value) -> Result<Status> {
    anyhow::ensure!(
        value.get("type").and_then(serde_json::Value::as_str) == Some("status")
            && value
                .get("schema_version")
                .and_then(serde_json::Value::as_u64)
                == Some(u64::from(contracts::SCHEMA_VERSION))
            && value
                .get("request_id")
                .and_then(serde_json::Value::as_str)
                .is_some_and(contracts::valid_request_id),
        "daemon returned unsupported status metadata"
    );
    let mut payload = value.clone();
    let object = payload
        .as_object_mut()
        .context("daemon returned malformed status")?;
    object.remove("type");
    object.remove("schema_version");
    object.remove("request_id");
    let status: Status =
        serde_json::from_value(payload).context("daemon returned malformed status")?;
    status.validate().map_err(anyhow::Error::msg)?;
    Ok(status)
}

pub(crate) use meshmsg_protocol::{Request as IpcRequest, RequestFrame as IpcRequestFrame};

fn error_expectation(request: &IpcRequest) -> (contracts::ErrorOperationKind, Option<&str>) {
    match request {
        IpcRequest::Send { operation_id, .. } => {
            (contracts::ErrorOperationKind::Send, Some(operation_id))
        }
        IpcRequest::PrivateSend { operation_id, .. } => (
            contracts::ErrorOperationKind::PrivateSend,
            Some(operation_id),
        ),
        IpcRequest::Subscribe => (contracts::ErrorOperationKind::Feed, None),
        IpcRequest::Offers => (contracts::ErrorOperationKind::Offers, None),
        IpcRequest::OffersRemove { operation_id, .. } => {
            (contracts::ErrorOperationKind::Remove, Some(operation_id))
        }
        IpcRequest::OffersPrune { operation_id, .. } => {
            (contracts::ErrorOperationKind::Prune, Some(operation_id))
        }
        IpcRequest::Share { operation_id, .. } => {
            (contracts::ErrorOperationKind::Share, Some(operation_id))
        }
        IpcRequest::Download { operation_id, .. } => {
            (contracts::ErrorOperationKind::Download, Some(operation_id))
        }
        IpcRequest::Status | IpcRequest::Peers | IpcRequest::Stop => {
            (contracts::ErrorOperationKind::General, None)
        }
    }
}

#[cfg(test)]
fn decode_response(frame: &[u8], expected_request_id: &str) -> Result<serde_json::Value> {
    decode_response_for_context(frame, expected_request_id, None, None)
}

fn decode_response_for_context(
    frame: &[u8],
    expected_request_id: &str,
    expected_topic: Option<TopicId>,
    live_now_ms: Option<u64>,
) -> Result<serde_json::Value> {
    let typed: meshmsg_protocol::DaemonFrame =
        serde_json::from_slice(frame).context("invalid typed frame from local daemon")?;
    let request_id = typed.request_id().map(ToString::to_string);
    let value = typed
        .into_payload_value()
        .context("re-encode typed daemon frame")?;
    let kind = value
        .get("type")
        .and_then(serde_json::Value::as_str)
        .context("daemon response type is missing")?
        .to_owned();
    if kind == "error" {
        let error = ErrorEnvelopeV1::from_value(&value)?;
        match error.request_id.as_deref() {
            Some(request_id) => anyhow::ensure!(
                request_id == expected_request_id,
                "daemon response request ID does not match the request"
            ),
            None => anyhow::ensure!(
                matches!(
                    error.code.as_str(),
                    "ipc_capacity" | "initial_frame_timeout"
                ),
                "daemon omitted error request ID"
            ),
        }
        return Ok(value);
    }
    anyhow::ensure!(
        request_id.as_deref() == Some(expected_request_id),
        "daemon response request ID does not match the request"
    );
    validate_success_payload_for_context(&value, expected_topic, live_now_ms)?;
    Ok(value)
}

pub(crate) async fn read_frame<S>(stream: &mut S, maximum: usize) -> Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    meshmsg_protocol::read_frame(stream, meshmsg_protocol::FrameLimit::Custom(maximum))
        .await
        .map_err(anyhow::Error::from)
}

pub(crate) async fn send_request(dir: &Path, request: &IpcRequest) -> Result<serde_json::Value> {
    send_request_with_id(dir, request, &contracts::new_request_id()).await
}

pub(crate) async fn send_request_with_id(
    dir: &Path,
    request: &IpcRequest,
    request_id: &str,
) -> Result<serde_json::Value> {
    anyhow::ensure!(
        contracts::valid_request_id(request_id),
        "invalid local IPC request ID"
    );
    let mut stream = connect_daemon(dir).await?;
    write_request_with_id(&mut stream, request, request_id).await?;
    let frame = read_frame(&mut stream, MAX_IPC_EVENT_SIZE).await?;
    let value = decode_response_for_context(&frame, request_id, None, None)?;
    if value["type"] == "error" {
        validate_error_for_request(&ErrorEnvelopeV1::from_value(&value)?, request)?;
    }
    if matches!(
        value["type"].as_str(),
        Some("attachment_offer" | "attachment_shared")
    ) {
        // One-shot attachment results may be operation-cache replays and
        // contain a portable signed token. Bind their configured topic and
        // nonzero signed timestamp, but apply freshness only to live events.
        let expected_topic = State::load(dir)?.topic_id()?;
        validate_success_payload_for_context(&value, Some(expected_topic), None)?;
    }
    Ok(value)
}

pub(crate) fn validate_error_for_request(
    error: &ErrorEnvelopeV1,
    request: &IpcRequest,
) -> Result<()> {
    let pre_admission_transport_error = error.request_id.is_none()
        && error.operation_id.is_none()
        && matches!(
            error.code.as_str(),
            "ipc_capacity" | "initial_frame_timeout"
        );
    if !pre_admission_transport_error {
        let (kind, operation_id) = error_expectation(request);
        error.validate_for_operation(kind, operation_id)?;
    }
    Ok(())
}

fn json_kind(value: Option<&serde_json::Value>) -> &'static str {
    match value {
        None => "missing",
        Some(serde_json::Value::Null) => "null",
        Some(serde_json::Value::Bool(_)) => "boolean",
        Some(serde_json::Value::Number(_)) => "number",
        Some(serde_json::Value::String(_)) => "string",
        Some(serde_json::Value::Array(_)) => "array",
        Some(serde_json::Value::Object(_)) => "object",
    }
}

const MAX_DIAGNOSTIC_CHARS: usize = 80;

fn diagnostic_string(value: Option<&serde_json::Value>, fallback: &str) -> String {
    match value.and_then(serde_json::Value::as_str) {
        Some(text) => {
            let mut chars = text.chars();
            let mut quoted = String::from("\"");
            for character in chars.by_ref().take(MAX_DIAGNOSTIC_CHARS) {
                match character {
                    '\"' => quoted.push_str("\\\""),
                    '\\' => quoted.push_str("\\\\"),
                    '\u{8}' => quoted.push_str("\\b"),
                    '\u{c}' => quoted.push_str("\\f"),
                    '\n' => quoted.push_str("\\n"),
                    '\r' => quoted.push_str("\\r"),
                    '\t' => quoted.push_str("\\t"),
                    control if control.is_control() => {
                        use std::fmt::Write as _;
                        write!(quoted, "\\u{:04x}", control as u32).unwrap();
                    }
                    visible => quoted.push(visible),
                }
            }
            quoted.push('\"');
            if chars.next().is_some() {
                quoted.push('…');
            }
            quoted
        }
        None => fallback.to_owned(),
    }
}

fn observed_string(value: Option<&serde_json::Value>) -> String {
    diagnostic_string(value, json_kind(value))
}

/// Validate the common response envelope before command-specific code consumes it.
/// A missing schema version is intentional for the original, unversioned IPC replies.
/// Diagnostics include only bounded, escaped discriminators and never serialize
/// the complete response, which may contain message or token data.
pub(crate) fn validate_response(
    value: &serde_json::Value,
    expected_type: &str,
    expected_schema_version: Option<u64>,
) -> Result<()> {
    if value.get("type").and_then(serde_json::Value::as_str) == Some("error") {
        let error = ErrorEnvelopeV1::from_value(value)?;
        return Err(anyhow::Error::new(contracts::ContractFailure(error)));
    }
    let response_type = value.get("type");
    anyhow::ensure!(
        response_type.and_then(serde_json::Value::as_str) == Some(expected_type),
        "daemon returned unexpected response type (expected {expected_type}, observed {})",
        observed_string(response_type)
    );
    if let Some(version) = expected_schema_version {
        let observed_version = value.get("schema_version");
        anyhow::ensure!(
            observed_version.and_then(serde_json::Value::as_u64) == Some(version),
            "daemon returned unsupported {expected_type} response version (expected {version}, observed {})",
            observed_version
                .and_then(serde_json::Value::as_u64)
                .map_or_else(|| observed_string(observed_version), |value| value.to_string())
        );
    }
    Ok(())
}

pub(crate) async fn send_request_checked(
    dir: &Path,
    request: &IpcRequest,
    expected_type: &str,
    expected_schema_version: Option<u64>,
) -> Result<serde_json::Value> {
    let value = send_request(dir, request).await?;
    validate_response(&value, expected_type, expected_schema_version)?;
    match expected_type {
        "status" => {
            status_from_value(&value)?;
        }
        "queued" => {
            let queued: QueuedV3 = serde_json::from_value(value.clone())
                .context("daemon returned malformed queued response")?;
            queued.validate()?;
        }
        "offers" => {
            let offers: OffersV1 = serde_json::from_value(value.clone())
                .context("daemon returned malformed offers response")?;
            offers.validate()?;
        }
        "peers_snapshot" => crate::peers::validate_snapshot(&value)?,
        _ => {}
    }
    Ok(value)
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
    // Apply the same strict shared deserializer to locally constructed DTOs so
    // invalid IDs and command-specific body bounds cannot be serialized.
    let frame = serde_json::from_value::<IpcRequestFrame>(serde_json::to_value(frame)?)?;
    meshmsg_protocol::write_json(stream, &frame, meshmsg_protocol::FrameLimit::Request)
        .await
        .map_err(anyhow::Error::from)
}

pub(crate) struct SubscriptionReader<S> {
    reader: BufReader<S>,
    frame: Vec<u8>,
    request_id: Option<String>,
    expected_topic: Option<TopicId>,
    error_operation: contracts::ErrorOperationKind,
    last_attachment_rejection: Option<Instant>,
    suppressed_attachment_rejections: u64,
}

impl<S: AsyncRead + Unpin> SubscriptionReader<S> {
    #[cfg(test)]
    pub(crate) fn new(stream: S) -> Self {
        Self {
            reader: BufReader::new(stream),
            frame: Vec::new(),
            request_id: None,
            expected_topic: None,
            error_operation: contracts::ErrorOperationKind::Feed,
            last_attachment_rejection: None,
            suppressed_attachment_rejections: 0,
        }
    }

    #[cfg(test)]
    pub(crate) fn new_correlated(stream: S, request_id: String) -> Self {
        Self {
            reader: BufReader::new(stream),
            frame: Vec::new(),
            request_id: Some(request_id),
            expected_topic: None,
            error_operation: contracts::ErrorOperationKind::Feed,
            last_attachment_rejection: None,
            suppressed_attachment_rejections: 0,
        }
    }

    pub(crate) fn new_correlated_for_topic(
        stream: S,
        request_id: String,
        expected_topic: Option<TopicId>,
    ) -> Self {
        Self {
            reader: BufReader::new(stream),
            frame: Vec::new(),
            request_id: Some(request_id),
            expected_topic,
            error_operation: contracts::ErrorOperationKind::Feed,
            last_attachment_rejection: None,
            suppressed_attachment_rejections: 0,
        }
    }

    #[cfg(feature = "web")]
    pub(crate) fn expected_topic(&self) -> Option<TopicId> {
        self.expected_topic
    }

    /// Reads one event while retaining any bytes consumed if this future is
    /// cancelled by a competing `select!` branch.
    pub(crate) async fn read(&mut self) -> Result<Option<serde_json::Value>> {
        loop {
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
            let decoded = match &self.request_id {
                Some(request_id) => decode_response_for_context(
                    &self.frame,
                    request_id,
                    self.expected_topic,
                    self.expected_topic
                        .map(|_| {
                            SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .context("system clock is before the Unix epoch")
                                .map(|elapsed| elapsed.as_millis() as u64)
                        })
                        .transpose()?,
                )
                .context("invalid daemon event"),
                None => serde_json::from_slice(&self.frame).context("invalid daemon event"),
            };
            match decoded {
                Ok(value) => {
                    self.frame.clear();
                    if value["type"] == "error" {
                        ErrorEnvelopeV1::from_value(&value)?
                            .validate_for_operation(self.error_operation, None)?;
                    }
                    return Ok(Some(value));
                }
                Err(error) => {
                    let attachment_family =
                        serde_json::from_slice::<serde_json::Value>(&self.frame)
                            .ok()
                            .and_then(|value| value["type"].as_str().map(str::to_owned))
                            .is_some_and(|family| {
                                matches!(family.as_str(), "attachment_offer" | "attachment_shared")
                            });
                    self.frame.clear();
                    if !attachment_family {
                        return Err(error);
                    }
                    let now = Instant::now();
                    if self
                        .last_attachment_rejection
                        .is_some_and(|last| now.duration_since(last) < Duration::from_secs(1))
                    {
                        self.suppressed_attachment_rejections =
                            self.suppressed_attachment_rejections.saturating_add(1);
                        continue;
                    }
                    let suppressed = std::mem::take(&mut self.suppressed_attachment_rejections);
                    self.last_attachment_rejection = Some(now);
                    let mut rejection = ErrorEnvelopeV1::new(
                        "internal_contract_error",
                        "invalid attachment event",
                        "unknown",
                        false,
                    );
                    rejection.request_id = self.request_id.clone();
                    rejection.suppressed_since_last = Some(suppressed);
                    return Ok(Some(rejection.into_value()));
                }
            }
        }
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
    fn command_response_validation_rejects_errors_wrong_types_and_versions() {
        let error = validate_response(
            &ErrorEnvelopeV1::new("send_failed", "ignored", "unknown", true).into_value(),
            "queued",
            None,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("send_failed") && error.contains("unknown"));
        assert!(!error.contains("useful diagnostic"));

        let c1 = observed_string(Some(&serde_json::json!("left\u{009b}right")));
        assert_eq!(c1, "\"left\\u009bright\"");
        assert!(!c1.chars().any(char::is_control));

        let long_observed = observed_string(Some(&serde_json::json!(
            "x".repeat(MAX_DIAGNOSTIC_CHARS + 1)
        )));
        assert_eq!(long_observed, format!("\"{}\"…", "x".repeat(80)));

        let malformed_error = validate_response(
            &serde_json::json!({"type":"error", "message":"legacy"}),
            "queued",
            None,
        )
        .unwrap_err()
        .to_string();
        assert!(malformed_error.contains("malformed"));

        for value in [
            serde_json::json!({"type":"unexpected"}),
            serde_json::json!({"type":"status"}),
            serde_json::json!({"message":"success-shaped but untyped"}),
        ] {
            assert!(validate_response(&value, "queued", None).is_err());
        }
        let wrong_version = validate_response(
            &serde_json::json!({"type":"offers", "schema_version":2, "body":"secret"}),
            "offers",
            Some(1),
        )
        .unwrap_err()
        .to_string();
        assert!(wrong_version.contains("expected 1, observed 2"));
        assert!(!wrong_version.contains("secret"));
        let wrong_type = validate_response(
            &serde_json::json!({"type":"wrong\nforged", "body":"secret"}),
            "offers",
            Some(1),
        )
        .unwrap_err()
        .to_string();
        assert!(wrong_type.contains("observed \"wrong\\nforged\""));
        assert!(!wrong_type.contains("secret"));
        validate_response(
            &serde_json::json!({"type":"offers", "schema_version":1}),
            "offers",
            Some(1),
        )
        .unwrap();
    }

    #[tokio::test]
    async fn subscription_preserves_frames_and_handles_clean_eof() {
        let data = b"{\"type\":\"connected\"}\n{\"type\":\"message\",\"body\":\"a\\nb\"}\n";
        let mut reader = SubscriptionReader::new(&data[..]);
        assert_eq!(reader.read().await.unwrap().unwrap()["type"], "connected");
        assert_eq!(reader.read().await.unwrap().unwrap()["body"], "a\nb");
        assert!(reader.read().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn malformed_attachment_event_reports_error_without_terminating_subscription() {
        let request_id = "11111111111111111111111111111111";
        let operation_id = "22222222222222222222222222222222";
        let (mut writer, reader) = tokio::io::duplex(4096);
        let mut subscription = SubscriptionReader::new_correlated(reader, request_id.into());
        let malformed = serde_json::json!({
            "protocol_version":2, "type":"attachment_offer", "schema_version":2, "request_id":request_id,
            "from":"4".repeat(64), "message_id":operation_id, "timestamp_ms":1,
            "offer_id":operation_id.to_ascii_uppercase(), "kind":"file",
            "name":"safe.txt", "size":4, "ticket":"malformed", "offer":"malformed"
        });
        let valid = serde_json::json!({
            "protocol_version":2, "type":"message", "schema_version":2, "request_id":request_id,
            "from":"4".repeat(64), "message_id":operation_id,
            "timestamp_ms":2, "body":"feed continues"
        });
        writer
            .write_all(format!("{malformed}\n{malformed}\n{malformed}\n").as_bytes())
            .await
            .unwrap();
        let rejection = subscription.read().await.unwrap().unwrap();
        assert_eq!(rejection["type"], "error");
        assert_eq!(rejection["code"], "internal_contract_error");
        assert_eq!(rejection["request_id"], request_id);
        assert_eq!(rejection["suppressed_since_last"], 0);
        let delayed = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(1_010)).await;
            writer
                .write_all(format!("{malformed}\n{valid}\n").as_bytes())
                .await
                .unwrap();
        });
        let sampled = subscription.read().await.unwrap().unwrap();
        assert_eq!(sampled["code"], "internal_contract_error");
        assert_eq!(sampled["request_id"], request_id);
        assert_eq!(sampled["suppressed_since_last"], 2);
        let continued = subscription.read().await.unwrap().unwrap();
        assert_eq!(continued["type"], "message");
        assert_eq!(continued["body"], "feed continues");
        delayed.await.unwrap();
    }

    #[tokio::test]
    async fn subscription_rejects_incomplete_and_oversized_frames_before_eof() {
        let mut incomplete = SubscriptionReader::new(&b"{\"type\":\"connected\"}"[..]);
        assert!(incomplete
            .read()
            .await
            .unwrap_err()
            .to_string()
            .contains("incomplete"));
        let (mut writer, reader) = tokio::io::duplex(MAX_IPC_EVENT_SIZE + 2);
        writer
            .write_all(&vec![b'x'; MAX_IPC_EVENT_SIZE + 2])
            .await
            .unwrap();
        // Writer deliberately stays open. The bound must not depend on EOF/newline.
        let mut reader = SubscriptionReader::new(reader);
        let error = tokio::time::timeout(std::time::Duration::from_secs(1), reader.read())
            .await
            .unwrap()
            .unwrap_err();
        assert!(error.to_string().contains("too large"));
    }

    #[tokio::test]
    async fn subscription_retains_partial_frame_when_select_cancels_read() {
        let (mut writer, stream) = tokio::io::duplex(64);
        let mut reader = SubscriptionReader::new(stream);
        writer.write_all(b"{\"type\":\"mes").await.unwrap();

        tokio::select! {
            result = reader.read() => panic!("partial frame unexpectedly completed: {result:?}"),
            _ = tokio::time::sleep(std::time::Duration::from_millis(10)) => {}
        }

        writer
            .write_all(b"sage\",\"body\":\"ok\"}\n")
            .await
            .unwrap();
        let event = reader.read().await.unwrap().unwrap();
        assert_eq!(event["type"], "message");
        assert_eq!(event["body"], "ok");
    }

    #[tokio::test]
    async fn request_wire_format_is_versioned_correlated_and_bounded() {
        let mut bytes = Vec::new();
        write_request_with_id(
            &mut bytes,
            &IpcRequest::Send {
                operation_id: "0123456789abcdef0123456789abcdef".parse().unwrap(),
                body: meshmsg_protocol::BroadcastBody::new("a\nb").unwrap(),
            },
            "11111111111111111111111111111111",
        )
        .await
        .unwrap();
        assert_eq!(bytes, b"{\"protocol_version\":2,\"request_id\":\"11111111111111111111111111111111\",\"request\":{\"command\":\"send\",\"operation_id\":\"0123456789abcdef0123456789abcdef\",\"body\":\"a\\nb\"}}\n");
        assert!(meshmsg_protocol::BroadcastBody::new("x".repeat(MAX_IPC_REQUEST_SIZE)).is_err());
    }

    #[tokio::test]
    async fn download_mode_is_explicit_in_the_canonical_command() {
        let mut bytes = Vec::new();
        write_request(
            &mut bytes,
            &IpcRequest::Download {
                operation_id: "0123456789abcdef0123456789abcdef".parse().unwrap(),
                offer: "signed-offer".into(),
                output: PathBuf::from("server-selected.blob"),
                mode: meshmsg_protocol::DownloadMode::Raw,
            },
        )
        .await
        .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["request"]["command"], "download");
        assert_eq!(value["request"]["mode"], "raw");
        assert_eq!(value["request"]["offer"], "signed-offer");
        assert_eq!(value["request"]["output"], "server-selected.blob");
        for obsolete in [
            serde_json::json!({
                "command":"download", "operation_id":"0123456789abcdef0123456789abcdef",
                "offer":"signed-offer", "output":"server-selected.blob"
            }),
            serde_json::json!({
                "command":"web_download", "operation_id":"0123456789abcdef0123456789abcdef",
                "offer":"signed-offer", "output":"server-selected.blob"
            }),
        ] {
            assert!(serde_json::from_value::<IpcRequest>(obsolete).is_err());
        }
    }

    #[test]
    fn lifecycle_error_dto_rejects_malformed_unknown_and_incompatible_values() {
        let mut error =
            LifecycleErrorV1::new("attachment_storage_busy", "busy", "not_started", true);
        let value = error.clone().into_value();
        assert_eq!(LifecycleErrorV1::from_value(&value).unwrap(), error);
        error.offer_id = Some("0123456789abcdef0123456789abcdef".into());
        assert!(LifecycleErrorV1::from_value(&error.into_value()).is_err());
        for malformed in [
            serde_json::json!({"type":"error","schema_version":2,"code":"attachment_storage_busy","message":"busy","outcome":"not_started","retryable":true}),
            serde_json::json!({"type":"error","schema_version":1,"code":"attachment_storage_busy","message":"busy","outcome":"started","retryable":true}),
            serde_json::json!({"type":"error","schema_version":1,"code":"attachment_storage_busy","message":"busy","outcome":"not_started","retryable":true,"extra":1}),
        ] {
            assert!(LifecycleErrorV1::from_value(&malformed).is_err());
        }
    }

    #[test]
    fn prune_cutoff_is_age_bound_overflow_safe_and_replay_stable() {
        let operation = "11111111111111111111111111111111";
        for (now_ms, age) in [
            (100_000, 0),
            (100_001, 0),
            (100_000, 60),
            (100_000, u64::MAX),
            (u64::MAX, u64::MAX / 1000 + 1),
        ] {
            let cutoff = prune_cutoff_upper_bound(now_ms, age);
            assert_eq!(cutoff, now_ms.saturating_sub(age.saturating_mul(1000)));
            let context = LifecycleRequestContext::Prune {
                operation_id: operation,
                older_than_secs: age,
                cutoff_ms: Some(cutoff),
                direction: None,
                dry_run: false,
                maximum: 2,
            };
            let success = LifecycleSuccessV3::new(&context, 1, 1, 1, false, Some(cutoff)).unwrap();
            success.validate_for_request(&context, false).unwrap();
            let mut partial =
                LifecycleErrorV1::new("attachment_removal_partial", "private", "partial", true);
            partial.operation_id = Some(operation.into());
            partial.older_than_secs = Some(age);
            partial.maximum = Some(2);
            partial.dry_run = Some(false);
            partial.selected_tags = Some(1);
            partial.removed_tags = Some(1);
            partial.quota_bytes_released = Some(1);
            partial.cutoff_ms = Some(cutoff);
            validate_lifecycle_error_for_request(
                &partial.into_value(),
                AttachmentOperationKind::Prune,
                operation,
                None,
                Some(&context),
            )
            .unwrap();

            let wrong = cutoff.saturating_add(1);
            if wrong != cutoff {
                assert!(LifecycleSuccessV3::new(&context, 1, 1, 1, false, Some(wrong)).is_err());
            }
        }
        // Exact cutoff binding, rather than the later wall clock, makes delayed,
        // near-TTL, and backward-clock replay stable.
        let replay = LifecycleRequestContext::Prune {
            operation_id: operation,
            older_than_secs: 60,
            cutoff_ms: Some(40_000),
            direction: None,
            dry_run: false,
            maximum: 1,
        };
        LifecycleSuccessV3::new(&replay, 0, 0, 0, false, Some(40_000)).unwrap();
    }

    #[test]
    fn lifecycle_success_is_shared_request_bound_and_semantically_strict() {
        let operation = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let offer = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let provider = "1".repeat(64);
        let remove = LifecycleRequestContext::Remove {
            operation_id: operation,
            offer_id: offer,
            direction: Some("incoming"),
            provider: Some(&provider),
            maximum: 512,
        };
        let produced = LifecycleSuccessV3::new(&remove, 1, 1, 9, false, None).unwrap();
        let correlated =
            contracts::correlate(produced.into_value(), "cccccccccccccccccccccccccccccccc");
        assert!(LifecycleSuccessV3::from_value_for_request(&correlated, &remove).is_ok());
        for (field, replacement) in [
            (
                "operation_id",
                serde_json::json!("dddddddddddddddddddddddddddddddd"),
            ),
            (
                "offer_id",
                serde_json::json!("dddddddddddddddddddddddddddddddd"),
            ),
            ("direction", serde_json::json!("outgoing")),
            ("provider", serde_json::Value::Null),
            ("dry_run", serde_json::json!(true)),
            ("maximum", serde_json::json!(1)),
            ("cutoff_ms", serde_json::json!(1)),
        ] {
            let mut malformed = correlated.clone();
            malformed[field] = replacement;
            assert!(
                LifecycleSuccessV3::from_value_for_request(&malformed, &remove).is_err(),
                "request mismatch {field} admitted"
            );
        }
        for malformed in [
            {
                let mut v = correlated.clone();
                v["selected_tags"] = 0.into();
                v
            },
            {
                let mut v = correlated.clone();
                v["removed_tags"] = 0.into();
                v
            },
            {
                let mut v = correlated.clone();
                v["limited"] = true.into();
                v
            },
        ] {
            assert!(LifecycleSuccessV3::from_value_for_request(&malformed, &remove).is_err());
        }

        let cutoff = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
            - 60_000;
        let prune = LifecycleRequestContext::Prune {
            operation_id: operation,
            older_than_secs: 60,
            cutoff_ms: Some(cutoff),
            direction: Some("outgoing"),
            dry_run: true,
            maximum: 2,
        };
        let produced = LifecycleSuccessV3::new(&prune, 2, 0, 10, true, Some(cutoff)).unwrap();
        let correlated =
            contracts::correlate(produced.into_value(), "cccccccccccccccccccccccccccccccc");
        assert!(LifecycleSuccessV3::from_value_for_request(&correlated, &prune).is_ok());
        for field in ["older_than_secs", "direction", "dry_run", "maximum"] {
            let mut malformed = correlated.clone();
            malformed[field] = match field {
                "dry_run" => false.into(),
                "direction" => serde_json::Value::Null,
                _ => 1.into(),
            };
            assert!(LifecycleSuccessV3::from_value_for_request(&malformed, &prune).is_err());
        }
        let mut impossible = correlated;
        impossible["removed_tags"] = 1.into();
        assert!(LifecycleSuccessV3::from_value_for_request(&impossible, &prune).is_err());
    }

    #[test]
    fn offers_shared_dto_enforces_documented_cap_and_truncation() {
        let item = || OfferItemV1 {
            direction: "outgoing".into(),
            offer_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            provider: None,
            name: "safe.txt".into(),
            kind: "file".into(),
            hash: "b".repeat(64),
            format: "raw".into(),
            status: "complete".into(),
            size: Some(1),
        };
        for count in [0, 512] {
            let produced = OffersV1::new((0..count).map(|_| item()).collect(), false, 0).unwrap();
            let value =
                contracts::correlate(produced.into_value(), "cccccccccccccccccccccccccccccccc");
            let decoded: OffersV1 = serde_json::from_value(value).unwrap();
            decoded.validate().unwrap();
        }
        assert!(OffersV1::new((0..513).map(|_| item()).collect(), true, 0).is_err());
        assert!(OffersV1::new(vec![item()], false, 1).is_err());
        let truncated = OffersV1::new(vec![item()], true, 1).unwrap();
        let mut value =
            contracts::correlate(truncated.into_value(), "cccccccccccccccccccccccccccccccc");
        value["truncated"] = false.into();
        let decoded: OffersV1 = serde_json::from_value(value).unwrap();
        assert!(decoded.validate().is_err());
    }

    #[test]
    fn lifecycle_errors_are_kind_applicable_canonical_and_request_bound() {
        let operation = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let offer = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let cases = [
            (
                AttachmentOperationKind::Share,
                "share_failed",
                "unknown",
                true,
            ),
            (
                AttachmentOperationKind::Remove,
                "invalid_offer_selector",
                "not_started",
                false,
            ),
            (
                AttachmentOperationKind::Prune,
                "invalid_prune_request",
                "not_started",
                false,
            ),
            (
                AttachmentOperationKind::Download,
                "download_failed",
                "not_started",
                true,
            ),
        ];
        for (kind, code, outcome, retryable) in cases {
            let mut error = LifecycleErrorV1::new(code, "private", outcome, retryable);
            error.operation_id = Some(operation.into());
            if code == "invalid_offer_selector" {
                error.offer_id = Some(offer.into());
            }
            let value = error.clone().into_value();
            assert!(validate_lifecycle_error_for_request(
                &value,
                kind,
                operation,
                Some(offer),
                None
            )
            .is_ok());
            for wrong_kind in [
                AttachmentOperationKind::Share,
                AttachmentOperationKind::Remove,
                AttachmentOperationKind::Prune,
                AttachmentOperationKind::Download,
            ] {
                if wrong_kind != kind {
                    assert!(
                        validate_lifecycle_error_for_request(
                            &value,
                            wrong_kind,
                            operation,
                            Some(offer),
                            None
                        )
                        .is_err(),
                        "{code} crossed into {wrong_kind:?}"
                    );
                }
            }
            let mut wrong_retry = error.clone();
            wrong_retry.retryable = !retryable;
            assert!(validate_lifecycle_error_for_request(
                &wrong_retry.into_value(),
                kind,
                operation,
                Some(offer),
                None
            )
            .is_err());
            let mut wrong_outcome = error;
            wrong_outcome.outcome = "partial".into();
            assert!(validate_lifecycle_error_for_request(
                &wrong_outcome.into_value(),
                kind,
                operation,
                Some(offer),
                None
            )
            .is_err());
        }

        for kind in [
            AttachmentOperationKind::Share,
            AttachmentOperationKind::Remove,
            AttachmentOperationKind::Prune,
            AttachmentOperationKind::Download,
        ] {
            for (code, outcome, retryable) in [
                ("operation_id_conflict", "not_started", false),
                ("operation_capacity", "not_started", true),
                ("attachment_storage_busy", "not_started", true),
                ("attachment_command_timeout", "unknown", true),
                ("attachment_storage_shutdown", "unknown", true),
            ] {
                let mut error = LifecycleErrorV1::new(code, "private", outcome, retryable);
                error.operation_id = Some(operation.into());
                assert!(validate_lifecycle_error_for_request(
                    &error.into_value(),
                    kind,
                    operation,
                    Some(offer),
                    None
                )
                .is_ok());
            }
        }

        let remove_context = LifecycleRequestContext::Remove {
            operation_id: operation,
            offer_id: offer,
            direction: Some("incoming"),
            provider: Some("1111111111111111111111111111111111111111111111111111111111111111"),
            maximum: 3,
        };
        let prune_context = LifecycleRequestContext::Prune {
            operation_id: operation,
            older_than_secs: 60,
            cutoff_ms: Some(40_000),
            direction: Some("outgoing"),
            dry_run: false,
            maximum: 3,
        };
        for (kind, context, with_offer) in [
            (AttachmentOperationKind::Remove, &remove_context, true),
            (AttachmentOperationKind::Prune, &prune_context, false),
        ] {
            for outcome in ["partial", "unknown"] {
                let mut partial = LifecycleErrorV1::try_new(
                    "attachment_removal_partial",
                    "private",
                    outcome,
                    true,
                )
                .unwrap();
                partial.operation_id = Some(operation.into());
                partial.offer_id = with_offer.then(|| offer.into());
                partial.selected_tags = Some(2);
                partial.removed_tags = Some(usize::from(outcome == "partial"));
                partial.quota_bytes_released = Some(usize::from(outcome == "partial") as u64 * 4);
                partial.maximum = Some(3);
                partial.dry_run = Some(false);
                match context {
                    LifecycleRequestContext::Remove {
                        direction,
                        provider,
                        ..
                    } => {
                        partial.direction = direction.map(str::to_owned);
                        partial.provider = provider.map(str::to_owned);
                    }
                    LifecycleRequestContext::Prune {
                        older_than_secs,
                        cutoff_ms,
                        direction,
                        ..
                    } => {
                        partial.direction = direction.map(str::to_owned);
                        partial.older_than_secs = Some(*older_than_secs);
                        partial.cutoff_ms = *cutoff_ms;
                    }
                }
                assert!(validate_lifecycle_error_for_request(
                    &partial.clone().into_value(),
                    kind,
                    operation,
                    Some(offer),
                    Some(context),
                )
                .is_ok());
                partial.selected_tags = Some(4);
                assert!(validate_lifecycle_error_for_request(
                    &partial.into_value(),
                    kind,
                    operation,
                    Some(offer),
                    Some(context),
                )
                .is_err());
            }
        }

        let mut generic =
            LifecycleErrorV1::new("operation_capacity", "private", "not_started", true);
        generic.operation_id = Some(operation.into());
        generic.offer_id = Some(offer.into());
        assert!(validate_lifecycle_error_for_request(
            &generic.into_value(),
            AttachmentOperationKind::Remove,
            operation,
            Some(offer),
            None
        )
        .is_err());
    }

    #[tokio::test]
    async fn attachment_lifecycle_requests_are_strict_and_versioned_by_response_contract() {
        let mut bytes = Vec::new();
        write_request(
            &mut bytes,
            &IpcRequest::OffersRemove {
                operation_id: "fedcba9876543210fedcba9876543210".parse().unwrap(),
                offer_id: "0123456789abcdef0123456789abcdef".parse().unwrap(),
                direction: Some("outgoing".parse().unwrap()),
                provider: None,
            },
        )
        .await
        .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["request"]["command"], "offers_remove");
        let prune = IpcRequest::OffersPrune {
            operation_id: "fedcba9876543210fedcba9876543210".parse().unwrap(),
            older_than_secs: 0,
            direction: None,
            dry_run: true,
            max_delete: 1,
        };
        let encoded = serde_json::to_value(&prune).unwrap();
        assert!(encoded.get("cutoff_ms").is_none());
        assert!(serde_json::from_slice::<IpcRequest>(
            br#"{"command":"offers_prune","operation_id":"fedcba9876543210fedcba9876543210","older_than_secs":0,"direction":null,"dry_run":true,"max_delete":1}"#
        ).is_ok());
        // Schema-v1 has exactly one prune request representation: caller age
        // and selectors only. A raw client cannot omit age or supply any
        // matching, future, saturated, or selector-specific cutoff.
        for malformed in [
            br#"{"command":"offers_prune","operation_id":"fedcba9876543210fedcba9876543210","cutoff_ms":1,"direction":null,"dry_run":true,"max_delete":1}"#.as_slice(),
            br#"{"command":"offers_prune","operation_id":"fedcba9876543210fedcba9876543210","older_than_secs":0,"cutoff_ms":18446744073709551615,"direction":null,"dry_run":true,"max_delete":1}"#.as_slice(),
            br#"{"command":"offers_prune","operation_id":"fedcba9876543210fedcba9876543210","older_than_secs":18446744073709551615,"cutoff_ms":0,"direction":"incoming","dry_run":true,"max_delete":1}"#.as_slice(),
        ] {
            assert!(serde_json::from_slice::<IpcRequest>(malformed).is_err());
        }
        assert!(validate_success_payload(&serde_json::json!({
            "type":"offers_pruned", "schema_version":1,
            "request_id":"11111111111111111111111111111111"
        }))
        .is_err());
    }

    #[tokio::test]
    async fn peers_uses_a_distinct_fieldless_wire_command() {
        let mut bytes = Vec::new();
        write_request(&mut bytes, &IpcRequest::Peers).await.unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["protocol_version"], 2);
        assert!(contracts::valid_request_id(
            value["request_id"].as_str().unwrap()
        ));
        assert_eq!(value["request"]["command"], "peers");

        #[allow(dead_code)]
        #[derive(Deserialize)]
        #[serde(tag = "command", rename_all = "snake_case")]
        enum LegacyRequest {
            Send { body: String },
            Status,
        }
        assert!(serde_json::from_slice::<LegacyRequest>(&bytes).is_err());
    }

    #[tokio::test]
    async fn private_send_uses_a_distinct_wire_command_rejected_by_legacy_daemons() {
        let mut bytes = Vec::new();
        write_request(
            &mut bytes,
            &IpcRequest::PrivateSend {
                operation_id: "0123456789abcdef0123456789abcdef".parse().unwrap(),
                to: "2".repeat(64).parse().unwrap(),
                body: meshmsg_protocol::PrivateBody::new("private text").unwrap(),
            },
        )
        .await
        .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["protocol_version"], 2);
        assert_eq!(value["request"]["command"], "private_send");
        assert_eq!(
            value["request"]["operation_id"],
            "0123456789abcdef0123456789abcdef"
        );

        #[allow(dead_code)]
        #[derive(Deserialize)]
        #[serde(tag = "command", rename_all = "snake_case")]
        enum LegacyRequest {
            Send { body: String },
            Status,
        }

        assert!(serde_json::from_slice::<LegacyRequest>(&bytes).is_err());
    }

    #[test]
    fn request_envelope_rejects_missing_unknown_duplicate_wrong_ids_and_versions() {
        let valid = br#"{"protocol_version":2,"request_id":"11111111111111111111111111111111","request":{"command":"status"}}"#;
        let frame: IpcRequestFrame = serde_json::from_slice(valid).unwrap();
        frame.validate().unwrap();
        for malformed in [
            br#"{"request_id":"11111111111111111111111111111111","request":{"command":"status"}}"#.as_slice(),
            br#"{"protocol_version":2,"request_id":"11111111111111111111111111111111","request":{"command":"status"},"extra":true}"#.as_slice(),
            br#"{"protocol_version":2,"protocol_version":2,"request_id":"11111111111111111111111111111111","request":{"command":"status"}}"#.as_slice(),
            br#"{"protocol_version":2,"request_id":1,"request":{"command":"status"}}"#.as_slice(),
        ] {
            assert!(serde_json::from_slice::<IpcRequestFrame>(malformed).is_err());
        }
        for unsupported in [
            br#"{"protocol_version":1,"request_id":"11111111111111111111111111111111","request":{"command":"status"}}"#.as_slice(),
            br#"{"protocol_version":3,"request_id":"11111111111111111111111111111111","request":{"command":"status"}}"#.as_slice(),
            br#"{"protocol_version":2,"request_id":"UPPER000000000000000000000000000","request":{"command":"status"}}"#.as_slice(),
        ] {
            assert!(serde_json::from_slice::<IpcRequestFrame>(unsupported).is_err());
        }
    }

    #[test]
    fn attachment_event_contract_binds_every_field_to_the_signed_offer() {
        let signer = iroh::SecretKey::generate();
        let id = "0123456789abcdef0123456789abcdef";
        let request_id = "11111111111111111111111111111111";
        let valid = contracts::correlate(
            crate::node::signed_attachment_event_for_test(
                &signer,
                id,
                AttachmentKind::File,
                "safe.txt",
                4,
                42,
            ),
            request_id,
        );
        validate_success_payload(&valid).unwrap();
        validate_success_payload_for_context(&valid, Some(TopicId::from_bytes([7; 32])), Some(42))
            .unwrap();
        assert!(validate_success_payload_for_context(
            &valid,
            Some(TopicId::from_bytes([8; 32])),
            Some(42),
        )
        .is_err());
        assert!(validate_success_payload_for_context(
            &valid,
            Some(TopicId::from_bytes([7; 32])),
            Some(42 + crate::node::ENVELOPE_ACCEPTANCE_WINDOW.as_millis() as u64 + 1),
        )
        .is_err());
        for (field, replacement) in [
            (
                "from",
                serde_json::json!(iroh::SecretKey::generate().public().to_string()),
            ),
            (
                "message_id",
                serde_json::json!("fedcba9876543210fedcba9876543210"),
            ),
            (
                "offer_id",
                serde_json::json!("fedcba9876543210fedcba9876543210"),
            ),
            (
                "offer_id",
                serde_json::json!("0123456789abcdeF0123456789abcdef"),
            ),
            ("timestamp_ms", serde_json::json!(43)),
            ("kind", serde_json::json!("directory_tar_v1")),
            ("name", serde_json::json!("other.txt")),
            ("size", serde_json::json!(5)),
            ("ticket", serde_json::json!("not-the-signed-ticket")),
            ("offer", serde_json::json!("malformed-signed-body")),
        ] {
            let mut malformed = valid.clone();
            malformed[field] = replacement;
            assert!(
                validate_success_payload(&malformed).is_err(),
                "accepted mismatched attachment field {field}"
            );
        }
    }

    #[test]
    fn every_ipc_mutation_consumer_enforces_its_operation_id_and_kind() {
        let operation = "11111111111111111111111111111111";
        let requests = [
            IpcRequest::Send {
                operation_id: operation.parse().unwrap(),
                body: meshmsg_protocol::BroadcastBody::new("x").unwrap(),
            },
            IpcRequest::PrivateSend {
                operation_id: operation.parse().unwrap(),
                to: "2".repeat(64).parse().unwrap(),
                body: meshmsg_protocol::PrivateBody::new("x").unwrap(),
            },
            IpcRequest::Share {
                operation_id: operation.parse().unwrap(),
                source_digest: "3".repeat(64).parse().unwrap(),
                path: PathBuf::from("x"),
            },
            IpcRequest::OffersRemove {
                operation_id: operation.parse().unwrap(),
                offer_id: "4".repeat(32).parse().unwrap(),
                direction: None,
                provider: None,
            },
            IpcRequest::OffersPrune {
                operation_id: operation.parse().unwrap(),
                older_than_secs: 1,
                direction: None,
                dry_run: false,
                max_delete: 1,
            },
            IpcRequest::Download {
                operation_id: operation.parse().unwrap(),
                offer: "x".into(),
                output: PathBuf::from("x"),
                mode: meshmsg_protocol::DownloadMode::Install,
            },
        ];
        for request in requests {
            let mut canonical =
                ErrorEnvelopeV1::new("operation_id_conflict", "private", "not_started", false);
            canonical.operation_id = Some(operation.into());
            validate_error_for_request(&canonical, &request).unwrap();
            canonical.operation_id = Some("22222222222222222222222222222222".into());
            assert!(validate_error_for_request(&canonical, &request).is_err());
        }
    }

    #[test]
    fn response_envelope_rejects_duplicate_or_mismatched_correlation() {
        let id = "11111111111111111111111111111111";
        let valid = br#"{"protocol_version":2,"type":"stopping","schema_version":1,"request_id":"11111111111111111111111111111111","outcome":"accepted"}"#;
        assert!(decode_response(valid, id).is_ok());
        assert!(decode_response(br#"{"type":"stopping","schema_version":1,"request_id":"11111111111111111111111111111111","outcome":"accepted"}"#, id).is_err());
        assert!(decode_response(br#"{"protocol_version":3,"type":"stopping","schema_version":1,"request_id":"11111111111111111111111111111111","outcome":"accepted"}"#, id).is_err());
        assert!(decode_response(br#"{"protocol_version":2,"type":"stopping","type":"stopping","schema_version":1,"request_id":"11111111111111111111111111111111","outcome":"accepted"}"#, id).is_err());
        assert!(decode_response(br#"{"protocol_version":2,"type":"stopping","schema_version":1,"request_id":"22222222222222222222222222222222","outcome":"accepted"}"#, id).is_err());
        assert!(decode_response(
            br#"{"protocol_version":2,"type":"stopping","request_id":"11111111111111111111111111111111","outcome":"accepted"}"#,
            id
        )
        .is_err());
    }

    #[test]
    fn status_dto_is_exact_and_rejects_unknown_missing_and_wrong_version() {
        let status = Status {
            running: true,
            peer: "2".repeat(64).parse().unwrap(),
            topic: "3".repeat(64).parse().unwrap(),
            advertises_self: true,
            has_invite: true,
            bootstrap_peer_count: 1,
            self_advertised: true,
            neighbors: 1,
            endpoint_online: true,
            topic_joined: true,
            alias: Some("node".parse().unwrap()),
            alias_enabled: true,
            captured_hostname: Some("node".into()),
            custom_alias: None,
            advertised_aliases: 1,
            operation_cache_capacity: 1024,
            operation_cache_ttl_ms: 600_000,
            operation_cache_persistent: false,
            direct_replay_available: true,
            direct_replay_error: None,
            direct_replay_capacity: 8192,
            direct_replay_per_sender_capacity: 512,
            direct_replay_queue_capacity: 64,
            direct_replay_global_rate_per_second: 1000,
            direct_replay_global_rate_burst: 2000,
            direct_replay_sender_rate_per_second: 100,
            direct_replay_sender_rate_burst: 200,
            max_attachment_bytes: 1024,
            attachment_storage: meshmsg_protocol::AttachmentStorageStatus {
                tagged_bytes: 0,
                tagged_blobs: 0,
                tags: 0,
                tag_capacity: 8192,
                quota_bytes: 1024,
                available_bytes: 1024,
                min_free_bytes: 0,
                pressure: false,
                over_quota: false,
                below_min_free: false,
                sampled_at_ms: 1,
            },
            attachment_retention_secs: 0,
        };
        let mut value = serde_json::to_value(&status).unwrap();
        value["type"] = "status".into();
        value["schema_version"] = 1.into();
        value["request_id"] = "11111111111111111111111111111111".into();
        validate_success_payload(&value).unwrap();
        let mut status_with_diagnostics = value.clone();
        status_with_diagnostics["diagnostic_records_accepted"] = 1.into();
        assert!(validate_success_payload(&status_with_diagnostics).is_err());

        for malformed in [
            {
                let mut v = value.clone();
                v["extra"] = true.into();
                v
            },
            {
                let mut v = value.clone();
                v.as_object_mut().unwrap().remove("running");
                v
            },
            {
                let mut v = value.clone();
                v["schema_version"] = 2.into();
                v
            },
            {
                let mut v = value.clone();
                v["attachment_storage"]["pressure"] = true.into();
                v
            },
        ] {
            assert!(validate_success_payload(&malformed).is_err());
        }
    }

    #[test]
    fn every_stream_and_command_family_is_exact_strict_and_semantically_checked() {
        let request_id = "11111111111111111111111111111111";
        let operation_id = "22222222222222222222222222222222";
        let digest = "3".repeat(64);
        let attachment_signer = iroh::SecretKey::generate();
        let peer = attachment_signer.public().to_string();
        let attachment_offer = contracts::correlate(
            crate::node::signed_attachment_event_for_test(
                &attachment_signer,
                operation_id,
                AttachmentKind::File,
                "safe.txt",
                4,
                1,
            ),
            request_id,
        );
        let mut attachment_shared = attachment_offer.clone();
        attachment_shared["type"] = "attachment_shared".into();
        attachment_shared["schema_version"] = 3.into();
        attachment_shared["operation_id"] = operation_id.into();
        attachment_shared["source_digest"] = digest.clone().into();
        attachment_shared["delivery_acknowledged"] = false.into();
        let cutoff_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
            - 1_000;
        let fixtures = vec![
            serde_json::json!({"type":"connected","schema_version":1,"request_id":request_id,"peer":peer,"endpoint_online":true,"topic_joined":true,"alias":"node"}),
            serde_json::json!({"type":"message","schema_version":2,"request_id":request_id,"from":peer,"message_id":operation_id,"timestamp_ms":1,"body":"hello"}),
            serde_json::json!({"type":"private_message","schema_version":1,"request_id":request_id,"private":true,"from":peer,"message_id":operation_id,"timestamp_ms":1,"body":"secret","acceptance_acknowledged":true,"durable":false,"read":false}),
            serde_json::json!({"type":"queued","schema_version":3,"request_id":request_id,"operation_id":operation_id,"from":peer,"message_id":operation_id,"timestamp_ms":1,"body":"hello","delivery_acknowledged":false}),
            serde_json::json!({"type":"private_accepted","schema_version":3,"request_id":request_id,"operation_id":operation_id,"to":peer,"message_id":operation_id,"timestamp_ms":1,"body_bytes":6,"acceptance_acknowledged":true,"duplicate_accepted":false,"durable":false,"read":false}),
            attachment_offer,
            attachment_shared,
            serde_json::json!({"type":"offers","schema_version":1,"request_id":request_id,"blobs":[{"direction":"outgoing","offer_id":operation_id,"name":"safe.txt","kind":"file","hash":digest,"format":"raw","status":"complete","size":4}],"truncated":false,"has_more":false,"item_errors":0}),
            serde_json::json!({"type":"offer_removed","schema_version":3,"request_id":request_id,"operation_id":operation_id,"offer_id":operation_id,"direction":null,"provider":null,"older_than_secs":null,"maximum":512,"dry_run":false,"selected_tags":1,"removed_tags":1,"released_bytes":4,"limited":false,"cutoff_ms":null}),
            serde_json::json!({"type":"offers_pruned","schema_version":3,"request_id":request_id,"operation_id":operation_id,"offer_id":null,"direction":null,"provider":null,"older_than_secs":1,"maximum":512,"dry_run":true,"selected_tags":1,"removed_tags":0,"released_bytes":4,"limited":false,"cutoff_ms":cutoff_ms}),
            serde_json::json!({"type":"download_started","schema_version":2,"request_id":request_id,"operation_id":operation_id,"output":"/tmp/file"}),
            serde_json::json!({"type":"download_progress","schema_version":2,"request_id":request_id,"operation_id":operation_id,"received_bytes":2,"total_bytes":4,"output":"/tmp/file"}),
            serde_json::json!({"type":"download_progress","schema_version":2,"request_id":request_id,"operation_id":operation_id,"received_bytes":0,"total_bytes":0,"output":"/tmp/empty"}),
            serde_json::json!({"type":"download_complete","schema_version":2,"request_id":request_id,"operation_id":operation_id,"token_digest":digest,"offer_id":operation_id,"kind":"file","name":"safe.txt","size":4,"from":peer,"output":"/tmp/file","installed":true,"pinned":true,"destination_synced":true,"cleanup_complete":true,"warnings":[]}),
            serde_json::json!({"type":"stopping","schema_version":1,"request_id":request_id,"outcome":"accepted"}),
            serde_json::json!({"type":"peer_up","schema_version":1,"request_id":request_id,"peer":peer}),
            serde_json::json!({"type":"peer_down","schema_version":1,"request_id":request_id,"peer":peer}),
            serde_json::json!({"type":"lagged","schema_version":1,"request_id":request_id,"source":"local","dropped":2,"message":"listener missed events"}),
        ];
        for fixture in fixtures {
            validate_success_payload(&fixture).unwrap_or_else(|error| {
                panic!("valid {} fixture rejected: {error:#}", fixture["type"])
            });
            let mut unknown = fixture.clone();
            unknown["unexpected"] = true.into();
            assert!(
                validate_success_payload(&unknown).is_err(),
                "unknown field accepted for {}",
                fixture["type"]
            );
            let mut missing = fixture.clone();
            missing.as_object_mut().unwrap().remove("request_id");
            assert!(
                validate_success_payload(&missing).is_err(),
                "missing request ID accepted for {}",
                fixture["type"]
            );
            let mut wrong_version = fixture.clone();
            wrong_version["schema_version"] = 99.into();
            assert!(
                validate_success_payload(&wrong_version).is_err(),
                "wrong version accepted for {}",
                fixture["type"]
            );
        }
        assert!(validate_success_payload(
            &serde_json::json!({"type":"future_event","schema_version":1,"request_id":request_id})
        )
        .is_err());
    }

    #[test]
    fn ambiguous_legacy_send_with_recipient_is_rejected() {
        let ambiguous = br#"{"command":"send","body":"private text","to":"peer"}"#;
        assert!(serde_json::from_slice::<IpcRequest>(ambiguous).is_err());
        assert!(
            serde_json::from_slice::<IpcRequest>(br#"{"command":"send","body":"broadcast"}"#)
                .is_err()
        );
        assert!(matches!(
            serde_json::from_slice::<IpcRequest>(br#"{"command":"send","operation_id":"0123456789abcdef0123456789abcdef","body":"broadcast"}"#)
                .unwrap(),
            IpcRequest::Send { body, .. } if body.as_str() == "broadcast"
        ));
    }
}
