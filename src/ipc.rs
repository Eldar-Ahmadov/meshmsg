//! Shared bounded newline-delimited local daemon protocol. Platform connection
//! ownership checks remain in node::connect_daemon for both CLI and web clients.
use crate::{
    attachment::{AttachmentKind, AttachmentOffer},
    config::State,
    contracts::{self, ErrorEnvelopeV1},
    message::{validate_v2_message_body, MAX_V2_MESSAGE_BODY_BYTES},
    node::{connect_daemon, LocalClientStream},
};
use anyhow::{Context, Result};
use iroh_gossip::proto::TopicId;
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

// JSON may escape each envelope byte as six ASCII bytes.
pub(crate) const MAX_IPC_REQUEST_SIZE: usize = 4096 * 6 + 1024;
// A complete, non-paginated directory can contain the bounded maximum of 1024
// remote identities. Individual live events remain tiny reconstructed objects,
// while this hard frame limit accommodates the proven worst-case snapshot.
pub(crate) const MAX_IPC_EVENT_SIZE: usize = 512 * 1024;
pub(crate) const PRIVATE_SEND_CAPABILITY: &str = "private_send_v2";
pub(crate) const WEB_DOWNLOAD_CAPABILITY: &str = "web_download_v1";
pub(crate) const WEB_SHARE_CAPABILITY: &str = "web_share_v1";
pub(crate) const IDEMPOTENT_MUTATIONS_CAPABILITY: &str = "idempotent_mutations_v1";
pub(crate) const IDEMPOTENT_ATTACHMENT_OPERATIONS_CAPABILITY: &str =
    "idempotent_attachment_operations_v1";
pub(crate) const ATTACHMENT_LIFECYCLE_CAPABILITY: &str = "attachment_lifecycle_v3";
pub(crate) const DIAGNOSTIC_STATUS_V2_CAPABILITY: &str = "diagnostic_status_v2";
pub(crate) const DIAGNOSTIC_STATUS_V3_CAPABILITY: &str = "diagnostic_status_v3";
pub(crate) type LifecycleErrorV1 = ErrorEnvelopeV1;

pub(crate) use contracts::valid_operation_id;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AttachmentOperationKind {
    Share,
    Remove,
    Prune,
    Download,
    WebDownload,
}

fn contract_operation_kind(kind: AttachmentOperationKind) -> contracts::ErrorOperationKind {
    match kind {
        AttachmentOperationKind::Share => contracts::ErrorOperationKind::Share,
        AttachmentOperationKind::Remove => contracts::ErrorOperationKind::Remove,
        AttachmentOperationKind::Prune => contracts::ErrorOperationKind::Prune,
        AttachmentOperationKind::Download => contracts::ErrorOperationKind::Download,
        AttachmentOperationKind::WebDownload => contracts::ErrorOperationKind::WebDownload,
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
    data_encoding::HEXLOWER.encode(&rand::random::<[u8; 16]>())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BenchConfig {
    pub(crate) run_id: String,
    pub(crate) rate: u32,
    pub(crate) duration_secs: u64,
    pub(crate) payload_bytes: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AttachmentStorageStatusV1 {
    pub(crate) tagged_bytes: u64,
    pub(crate) tagged_blobs: usize,
    pub(crate) tags: usize,
    pub(crate) tag_capacity: usize,
    pub(crate) quota_bytes: u64,
    pub(crate) available_bytes: u64,
    pub(crate) min_free_bytes: u64,
    pub(crate) pressure: bool,
    pub(crate) over_quota: bool,
    pub(crate) below_min_free: bool,
    pub(crate) sampled_at_ms: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StatusV1 {
    #[serde(rename = "type")]
    pub(crate) kind: String,
    pub(crate) schema_version: u8,
    pub(crate) request_id: String,
    pub(crate) running: bool,
    pub(crate) peer: String,
    pub(crate) topic: String,
    pub(crate) advertises_self: bool,
    pub(crate) has_invite: bool,
    pub(crate) bootstrap_peer_count: usize,
    pub(crate) self_advertised: bool,
    pub(crate) neighbors: usize,
    pub(crate) endpoint_online: bool,
    pub(crate) topic_joined: bool,
    pub(crate) alias: Option<String>,
    pub(crate) alias_enabled: bool,
    pub(crate) captured_hostname: Option<String>,
    pub(crate) custom_alias: Option<String>,
    pub(crate) advertised_aliases: usize,
    pub(crate) ipc_capabilities: Vec<String>,
    pub(crate) operation_cache_capacity: usize,
    pub(crate) operation_cache_ttl_ms: u64,
    pub(crate) operation_cache_persistent: bool,
    pub(crate) direct_replay_available: bool,
    pub(crate) direct_replay_error: Option<String>,
    pub(crate) direct_replay_capacity: usize,
    pub(crate) direct_replay_per_sender_capacity: usize,
    pub(crate) direct_replay_queue_capacity: usize,
    pub(crate) direct_replay_global_rate_per_second: u64,
    pub(crate) direct_replay_global_rate_burst: u64,
    pub(crate) direct_replay_sender_rate_per_second: u64,
    pub(crate) direct_replay_sender_rate_burst: u64,
    pub(crate) max_attachment_bytes: u64,
    pub(crate) attachment_storage: AttachmentStorageStatusV1,
    pub(crate) attachment_retention_secs: u64,
}

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
    ipc_capabilities: Vec<String>,
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BenchSendStartedV2 {
    #[serde(rename = "type")]
    family: String,
    schema_version: u8,
    request_id: String,
    run_id: String,
    rate: u32,
    duration_secs: u64,
    payload_bytes: usize,
    planned: u64,
    delivery_acknowledged: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BenchSendProgressV2 {
    #[serde(rename = "type")]
    family: String,
    schema_version: u8,
    request_id: String,
    run_id: String,
    rate: u32,
    duration_secs: u64,
    payload_bytes: usize,
    planned: u64,
    attempted: u64,
    queued: u64,
    failed: u64,
    incomplete: u64,
    schedule_missed: u64,
    queued_body_bytes: u64,
    queued_envelope_bytes: u64,
    elapsed_ms: u64,
    achieved_messages_per_second: f64,
    achieved_body_bytes_per_second: f64,
    delivery_acknowledged: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BenchSendSummaryV2 {
    #[serde(rename = "type")]
    family: String,
    schema_version: u8,
    request_id: String,
    run_id: String,
    rate: u32,
    duration_secs: u64,
    payload_bytes: usize,
    planned: u64,
    attempted: u64,
    queued: u64,
    failed: u64,
    incomplete: u64,
    schedule_missed: u64,
    queued_body_bytes: u64,
    queued_envelope_bytes: u64,
    elapsed_ms: u64,
    achieved_messages_per_second: f64,
    achieved_body_bytes_per_second: f64,
    delivery_acknowledged: bool,
    accounting_complete: bool,
    completion_reason: String,
    first_error: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BenchLatencyV1 {
    observations: u64,
    samples: usize,
    sampled: bool,
    clock_invalid: u64,
    p50_ms: Option<u64>,
    p95_ms: Option<u64>,
    p99_ms: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BenchLagV1 {
    local_events: u64,
    local_dropped: u64,
    gossip_events: u64,
    incomplete: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BenchReceiveStartedV1 {
    #[serde(rename = "type")]
    family: String,
    schema_version: u8,
    request_id: String,
    run_id: String,
    duration_secs: u64,
    expected: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BenchReceiveProgressV1 {
    #[serde(rename = "type")]
    family: String,
    schema_version: u8,
    request_id: String,
    run_id: String,
    elapsed_ms: u64,
    expected: Option<u64>,
    unique: u64,
    missing: Option<u64>,
    duplicates: u64,
    out_of_order: u64,
    highest_sequence: Option<u64>,
    body_bytes: u64,
    achieved_messages_per_second: f64,
    achieved_body_bytes_per_second: f64,
    latency: BenchLatencyV1,
    lag: BenchLagV1,
    malformed_messages: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BenchReceiveSummaryV1 {
    #[serde(rename = "type")]
    family: String,
    schema_version: u8,
    request_id: String,
    run_id: String,
    completion_reason: String,
    elapsed_ms: u64,
    expected: Option<u64>,
    complete: bool,
    measurement_valid: bool,
    unique: u64,
    missing: Option<u64>,
    missing_sequence_sample: Vec<u64>,
    duplicates: u64,
    out_of_order: u64,
    highest_sequence: Option<u64>,
    body_bytes: u64,
    achieved_messages_per_second: f64,
    achieved_body_bytes_per_second: f64,
    latency: BenchLatencyV1,
    lag: BenchLagV1,
    peer_up: u64,
    peer_down: u64,
    ignored_messages: u64,
    malformed_messages: u64,
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

fn validate_bench_base(
    run_id: &str,
    duration_secs: u64,
    expected: Option<u64>,
    request_id: &str,
) -> Result<()> {
    anyhow::ensure!(valid_operation_id(run_id), "invalid benchmark run ID");
    anyhow::ensure!(
        contracts::valid_request_id(request_id),
        "invalid benchmark request ID"
    );
    anyhow::ensure!(
        (1..=86_400).contains(&duration_secs),
        "invalid benchmark duration"
    );
    anyhow::ensure!(
        expected.is_none_or(|count| (1..=10_000_000).contains(&count)),
        "invalid benchmark count"
    );
    Ok(())
}

fn coherent_benchmark_rate(reported: f64, count: u64, elapsed_ms: u64) -> bool {
    if !reported.is_finite() || reported < 0.0 {
        return false;
    }
    let expected = count as f64 * 1000.0 / elapsed_ms.max(1) as f64;
    let tolerance = expected.abs().mul_add(1e-12, 1e-9);
    (reported - expected).abs() <= tolerance
}

fn benchmark_eligible_slot_bounds(rate: u32, elapsed_ms: u64, planned: u64) -> Option<(u64, u64)> {
    let period_ns = 1_000_000_000_u64.checked_div(u64::from(rate))?;
    if period_ns == 0 {
        return None;
    }
    let lower_ns = u128::from(elapsed_ms).checked_mul(1_000_000)?;
    let upper_ns = lower_ns.checked_add(999_999)?;
    let eligible = |elapsed_ns: u128| {
        u64::try_from(elapsed_ns.checked_div(u128::from(period_ns))?)
            .unwrap_or(u64::MAX)
            .checked_add(1)
            .map(|slots| slots.min(planned))
    };
    Some((eligible(lower_ns)?, eligible(upper_ns)?))
}

fn validate_send_metrics(
    config: (u32, u64, usize, u64),
    counts: (u64, u64, u64, u64, u64),
    bytes: (u64, u64),
    timing: (u64, f64, f64),
    final_record: bool,
) -> Result<()> {
    let (rate, duration_secs, payload_bytes, planned) = config;
    let (attempted, queued, failed, incomplete, schedule_missed) = counts;
    let (queued_body_bytes, queued_envelope_bytes) = bytes;
    let (elapsed_ms, achieved_messages_per_second, achieved_body_bytes_per_second) = timing;
    anyhow::ensure!(
        (1..=10_000).contains(&rate)
            && (1..=86_400).contains(&duration_secs)
            && (106..=MAX_V2_MESSAGE_BODY_BYTES).contains(&payload_bytes),
        "invalid benchmark send configuration"
    );
    let payload_bytes = u64::try_from(payload_bytes).context("invalid benchmark payload size")?;
    let expected_planned = u64::from(rate)
        .checked_mul(duration_secs)
        .context("invalid benchmark planned count")?;
    let accounted = queued
        .checked_add(failed)
        .and_then(|count| count.checked_add(incomplete));
    let scheduled = attempted.checked_add(schedule_missed);
    let eligible = benchmark_eligible_slot_bounds(rate, elapsed_ms, planned)
        .context("invalid benchmark scheduler bounds")?;
    let expected_body_bytes = queued.checked_mul(payload_bytes);
    let minimum_envelope_bytes = expected_body_bytes.and_then(|bytes| bytes.checked_add(queued));
    let maximum_envelope_bytes = queued.checked_mul(4096);
    anyhow::ensure!(
        planned == expected_planned
            && accounted == Some(attempted)
            && scheduled.is_some_and(|count| {
                count <= eligible.1 && (!final_record || count >= eligible.0)
            })
            && failed <= 1
            && incomplete <= 1
            && expected_body_bytes == Some(queued_body_bytes)
            && minimum_envelope_bytes.is_some_and(|minimum| {
                queued_envelope_bytes >= minimum
                    && maximum_envelope_bytes
                        .is_some_and(|maximum| queued_envelope_bytes <= maximum)
            })
            && coherent_benchmark_rate(achieved_messages_per_second, queued, elapsed_ms)
            && coherent_benchmark_rate(
                achieved_body_bytes_per_second,
                queued_body_bytes,
                elapsed_ms,
            ),
        "invalid benchmark send metrics"
    );
    Ok(())
}

fn greatest_unlisted_at_or_below(limit: u64, sorted_listed: &[u64]) -> Option<u64> {
    let mut candidate = Some(limit);
    for listed in sorted_listed.iter().rev() {
        let value = candidate?;
        if *listed == value {
            candidate = value.checked_sub(1);
        } else if *listed < value {
            return candidate;
        }
    }
    candidate
}

fn coherent_missing_sequence_sample(
    expected: Option<u64>,
    unique: u64,
    missing: Option<u64>,
    highest: Option<u64>,
    sample: &[u64],
) -> bool {
    const SAMPLE_CAP: u64 = 100;
    let Some(expected) = expected else {
        return unique == 0 && missing.is_none() && highest.is_none() && sample.is_empty();
    };
    let Some(missing) = missing else {
        return false;
    };
    let Ok(sample_len) = u64::try_from(sample.len()) else {
        return false;
    };
    if sample_len != missing.min(SAMPLE_CAP)
        || !sample.windows(2).all(|pair| pair[0] < pair[1])
        || sample.iter().any(|sequence| *sequence >= expected)
    {
        return false;
    }

    if missing <= SAMPLE_CAP {
        // The whole complement is present. Its greatest unlisted member must
        // therefore be the reported greatest observed sequence.
        return expected
            .checked_sub(1)
            .and_then(|last| greatest_unlisted_at_or_below(last, sample))
            == highest;
    }

    // A capped sample is the ascending prefix of the missing set. Every value
    // through its last member that is not listed is therefore known observed.
    let Some(last) = sample.last().copied() else {
        return false;
    };
    let Some(prefix_slots) = last.checked_add(1) else {
        return false;
    };
    let Some(prefix_observed) = prefix_slots.checked_sub(sample_len) else {
        return false;
    };
    if prefix_observed > unique {
        return false;
    }
    let remaining_observed = unique - prefix_observed;
    match highest {
        None => prefix_observed == 0 && remaining_observed == 0,
        Some(highest) if highest <= last => {
            remaining_observed == 0 && greatest_unlisted_at_or_below(last, sample) == Some(highest)
        }
        Some(highest) => highest
            .checked_sub(last)
            .is_some_and(|available| (1..=available).contains(&remaining_observed)),
    }
}

fn validate_bench_metrics(
    delivery: (Option<u64>, u64, Option<u64>, Option<u64>, u64, u64),
    timing: (u64, f64, f64),
    latency: (&BenchLatencyV1, usize),
    lag: &BenchLagV1,
) -> Result<()> {
    let (expected, unique, missing, highest, body_bytes, duplicates) = delivery;
    let (elapsed_ms, achieved_messages_per_second, achieved_body_bytes_per_second) = timing;
    let (latency, maximum_latency_samples) = latency;
    let coherent_expected = match expected {
        Some(count) => unique <= count,
        None => unique == 0,
    };
    let coherent_highest = match (unique, highest) {
        (0, None) => true,
        (0, Some(_)) | (_, None) => false,
        (count, Some(value)) => {
            value.checked_add(1).is_some_and(|range| count <= range)
                && expected.is_none_or(|expected| value < expected)
        }
    };
    let minimum_body_bytes = unique.checked_mul(106);
    let maximum_body_bytes = unique.checked_mul(MAX_V2_MESSAGE_BODY_BYTES as u64);
    let latency_samples = u64::try_from(latency.samples).ok();
    let samples_within_cap = latency.samples <= maximum_latency_samples;
    let rank = |percentile: usize| {
        percentile
            .checked_mul(latency.samples)?
            .checked_add(99)?
            .checked_div(100)
    };
    let coherent_percentiles = samples_within_cap
        && match (latency.p50_ms, latency.p95_ms, latency.p99_ms) {
            (None, None, None) => latency.samples == 0,
            (Some(p50), Some(p95), Some(p99)) => match (rank(50), rank(95), rank(99)) {
                (Some(rank50), Some(rank95), Some(rank99)) => {
                    latency.samples > 0
                        && p50 <= p95
                        && p95 <= p99
                        && p99 <= 86_400_000
                        && (rank50 != rank95 || p50 == p95)
                        && (rank95 != rank99 || p95 == p99)
                }
                _ => false,
            },
            _ => false,
        };
    anyhow::ensure!(
        coherent_benchmark_rate(achieved_messages_per_second, unique, elapsed_ms)
            && coherent_benchmark_rate(achieved_body_bytes_per_second, body_bytes, elapsed_ms),
        "invalid benchmark rates"
    );
    anyhow::ensure!(
        coherent_expected && expected.and_then(|count| count.checked_sub(unique)) == missing,
        "invalid benchmark missing count"
    );
    anyhow::ensure!(coherent_highest, "invalid benchmark highest sequence");
    anyhow::ensure!(
        minimum_body_bytes.is_some_and(|minimum| body_bytes >= minimum)
            && maximum_body_bytes.is_some_and(|maximum| body_bytes <= maximum),
        "invalid benchmark body-byte count"
    );
    anyhow::ensure!(
        samples_within_cap
            && latency_samples.is_some_and(|samples| samples <= latency.observations)
            && (latency.observations == 0 || latency.samples > 0)
            && latency_samples
                .is_some_and(|samples| latency.sampled == (samples != latency.observations))
            && latency.observations.checked_add(latency.clock_invalid) == Some(unique)
            && coherent_percentiles,
        "invalid benchmark latency counts"
    );
    anyhow::ensure!(
        lag.incomplete == (lag.local_events > 0 || lag.gossip_events > 0)
            && ((lag.local_events == 0 && lag.local_dropped == 0)
                || (lag.local_events > 0 && lag.local_dropped >= lag.local_events)),
        "invalid benchmark lag state"
    );
    anyhow::ensure!(
        unique > 0 || duplicates == 0,
        "invalid benchmark duplicate count"
    );
    Ok(())
}

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
            StatusV1::from_value(value)?;
        }
        ("diagnostic_status", 2) => {
            DiagnosticStatusV2::from_value(value)?;
        }
        ("diagnostic_status", 3) => {
            DiagnosticStatusV3::from_value(value)?;
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
                    && valid_peer_id(&dto.peer)
                    && dto.ipc_capabilities.len() <= 64
                    && dto
                        .ipc_capabilities
                        .iter()
                        .all(|item| valid_public_text(item, 64)),
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
        ("bench_send_started", 2) => {
            let dto: BenchSendStartedV2 =
                serde_json::from_value(value.clone()).context("malformed benchmark start")?;
            validate_bench_base(
                &dto.run_id,
                dto.duration_secs,
                Some(dto.planned),
                &dto.request_id,
            )?;
            anyhow::ensure!(
                dto.family == family
                    && dto.schema_version == 2
                    && (1..=10_000).contains(&dto.rate)
                    && (106..=MAX_V2_MESSAGE_BODY_BYTES).contains(&dto.payload_bytes)
                    && u64::from(dto.rate).checked_mul(dto.duration_secs) == Some(dto.planned)
                    && !dto.delivery_acknowledged,
                "invalid benchmark start"
            );
        }
        ("bench_send_progress", 2) => {
            let dto: BenchSendProgressV2 =
                serde_json::from_value(value.clone()).context("malformed benchmark progress")?;
            validate_bench_base(
                &dto.run_id,
                dto.duration_secs,
                Some(dto.planned),
                &dto.request_id,
            )?;
            validate_send_metrics(
                (dto.rate, dto.duration_secs, dto.payload_bytes, dto.planned),
                (
                    dto.attempted,
                    dto.queued,
                    dto.failed,
                    dto.incomplete,
                    dto.schedule_missed,
                ),
                (dto.queued_body_bytes, dto.queued_envelope_bytes),
                (
                    dto.elapsed_ms,
                    dto.achieved_messages_per_second,
                    dto.achieved_body_bytes_per_second,
                ),
                false,
            )?;
            anyhow::ensure!(
                dto.family == family
                    && dto.schema_version == 2
                    && (1..=10_000).contains(&dto.rate)
                    && (106..=MAX_V2_MESSAGE_BODY_BYTES).contains(&dto.payload_bytes)
                    && dto.failed == 0
                    && dto.incomplete == 0
                    && !dto.delivery_acknowledged,
                "invalid benchmark progress"
            );
        }
        ("bench_send_summary", 2) => {
            let dto: BenchSendSummaryV2 =
                serde_json::from_value(value.clone()).context("malformed benchmark summary")?;
            validate_bench_base(
                &dto.run_id,
                dto.duration_secs,
                Some(dto.planned),
                &dto.request_id,
            )?;
            validate_send_metrics(
                (dto.rate, dto.duration_secs, dto.payload_bytes, dto.planned),
                (
                    dto.attempted,
                    dto.queued,
                    dto.failed,
                    dto.incomplete,
                    dto.schedule_missed,
                ),
                (dto.queued_body_bytes, dto.queued_envelope_bytes),
                (
                    dto.elapsed_ms,
                    dto.achieved_messages_per_second,
                    dto.achieved_body_bytes_per_second,
                ),
                dto.accounting_complete,
            )?;
            anyhow::ensure!(
                dto.family == family
                    && dto.schema_version == 2
                    && (1..=10_000).contains(&dto.rate)
                    && (106..=MAX_V2_MESSAGE_BODY_BYTES).contains(&dto.payload_bytes)
                    && !dto.delivery_acknowledged
                    && dto.accounting_complete
                    && matches!(
                        dto.completion_reason.as_str(),
                        "deadline" | "interrupted" | "send_failed" | "daemon_stopped"
                    ),
                "invalid benchmark summary"
            );
            let coherent_completion = match dto.completion_reason.as_str() {
                "send_failed" => {
                    dto.accounting_complete
                        && dto.failed == 1
                        && dto.incomplete == 0
                        && dto.first_error.as_deref()
                            == Some(contracts::BENCHMARK_SEND_FAILED_MESSAGE)
                        && dto.first_error.as_deref().is_some_and(|text| {
                            valid_public_text(text, contracts::MAX_PUBLIC_MESSAGE_BYTES)
                        })
                }
                "deadline" => {
                    dto.failed == 0
                        && dto.attempted.checked_add(dto.schedule_missed) == Some(dto.planned)
                        && dto
                            .duration_secs
                            .checked_mul(1_000)
                            .is_some_and(|deadline_ms| dto.elapsed_ms >= deadline_ms)
                        && dto.first_error.is_none()
                }
                "interrupted" | "daemon_stopped" => dto.failed == 0 && dto.first_error.is_none(),
                _ => false,
            };
            anyhow::ensure!(coherent_completion, "invalid benchmark completion state");
        }
        ("bench_receive_started", 1) => {
            let dto: BenchReceiveStartedV1 = serde_json::from_value(value.clone())
                .context("malformed receive benchmark start")?;
            validate_bench_base(
                &dto.run_id,
                dto.duration_secs,
                dto.expected,
                &dto.request_id,
            )?;
            anyhow::ensure!(
                dto.family == family && dto.schema_version == 1,
                "invalid receive benchmark start"
            );
        }
        ("bench_receive_progress", 1) => {
            let dto: BenchReceiveProgressV1 = serde_json::from_value(value.clone())
                .context("malformed receive benchmark progress")?;
            validate_bench_base(&dto.run_id, 1, dto.expected, &dto.request_id)?;
            validate_bench_metrics(
                (
                    dto.expected,
                    dto.unique,
                    dto.missing,
                    dto.highest_sequence,
                    dto.body_bytes,
                    dto.duplicates,
                ),
                (
                    dto.elapsed_ms,
                    dto.achieved_messages_per_second,
                    dto.achieved_body_bytes_per_second,
                ),
                (&dto.latency, 4_096),
                &dto.lag,
            )?;
            anyhow::ensure!(
                dto.family == family
                    && dto.schema_version == 1
                    && dto.out_of_order <= dto.unique.saturating_sub(1),
                "invalid receive benchmark progress"
            );
            let _ = (
                dto.schema_version,
                dto.elapsed_ms,
                dto.duplicates,
                dto.body_bytes,
                dto.malformed_messages,
            );
        }
        ("bench_receive_summary", 1) => {
            let dto: BenchReceiveSummaryV1 = serde_json::from_value(value.clone())
                .context("malformed receive benchmark summary")?;
            validate_bench_base(&dto.run_id, 1, dto.expected, &dto.request_id)?;
            validate_bench_metrics(
                (
                    dto.expected,
                    dto.unique,
                    dto.missing,
                    dto.highest_sequence,
                    dto.body_bytes,
                    dto.duplicates,
                ),
                (
                    dto.elapsed_ms,
                    dto.achieved_messages_per_second,
                    dto.achieved_body_bytes_per_second,
                ),
                (&dto.latency, 1_000_000),
                &dto.lag,
            )?;
            let coherent_missing_sample = coherent_missing_sequence_sample(
                dto.expected,
                dto.unique,
                dto.missing,
                dto.highest_sequence,
                &dto.missing_sequence_sample,
            );
            let complete = dto.expected.is_some_and(|count| count == dto.unique);
            anyhow::ensure!(
                dto.family == family
                    && dto.schema_version == 1
                    && matches!(
                        dto.completion_reason.as_str(),
                        "deadline" | "interrupted" | "daemon_stopped"
                    )
                    && dto.complete == complete
                    && dto.measurement_valid
                        == (complete && !dto.lag.incomplete && dto.malformed_messages == 0)
                    && coherent_missing_sample
                    && dto.out_of_order <= dto.unique.saturating_sub(1),
                "invalid receive benchmark summary"
            );
            let _ = (
                dto.schema_version,
                dto.elapsed_ms,
                dto.duplicates,
                dto.body_bytes,
                dto.peer_up,
                dto.peer_down,
                dto.ignored_messages,
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

impl StatusV1 {
    pub(crate) fn from_value(value: &serde_json::Value) -> Result<Self> {
        let status: Self =
            serde_json::from_value(value.clone()).context("daemon returned malformed status")?;
        anyhow::ensure!(
            status.kind == "status" && status.schema_version == contracts::SCHEMA_VERSION,
            "daemon returned unsupported status"
        );
        anyhow::ensure!(
            contracts::valid_request_id(&status.request_id),
            "daemon status request ID is invalid"
        );
        anyhow::ensure!(
            status.running
                && valid_peer_id(&status.peer)
                && valid_content_digest(&status.topic)
                && status.max_attachment_bytes > 0
                && status
                    .alias
                    .as_deref()
                    .is_none_or(|value| valid_public_text(value, 63))
                && status
                    .captured_hostname
                    .as_deref()
                    .is_none_or(|value| valid_public_text(value, 253))
                && status
                    .custom_alias
                    .as_deref()
                    .is_none_or(|value| valid_public_text(value, 63))
                && status
                    .direct_replay_error
                    .as_deref()
                    .is_none_or(|value| valid_public_text(
                        value,
                        contracts::MAX_PUBLIC_MESSAGE_BYTES
                    )),
            "daemon status values are invalid"
        );
        anyhow::ensure!(
            status.attachment_storage.tags <= status.attachment_storage.tag_capacity
                && status.attachment_storage.tagged_blobs <= status.attachment_storage.tags
                && status.attachment_storage.over_quota
                    == (status.attachment_storage.tagged_bytes
                        > status.attachment_storage.quota_bytes)
                && status.attachment_storage.below_min_free
                    == (status.attachment_storage.available_bytes
                        < status.attachment_storage.min_free_bytes)
                && status.attachment_storage.pressure
                    == (status.attachment_storage.over_quota
                        || status.attachment_storage.below_min_free),
            "daemon attachment status is invalid"
        );
        anyhow::ensure!(
            status.ipc_capabilities.len() <= 64
                && status
                    .ipc_capabilities
                    .iter()
                    .all(|capability| capability.len() <= 64),
            "daemon capabilities are invalid"
        );
        Ok(status)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DiagnosticStatusV2 {
    #[serde(rename = "type")]
    pub(crate) kind: String,
    pub(crate) schema_version: u8,
    pub(crate) request_id: String,
    pub(crate) records_accepted: u64,
    pub(crate) records_dropped: u64,
    pub(crate) records_retained: usize,
    pub(crate) stdout_queue_occupancy: usize,
    pub(crate) stdout_queue_capacity: usize,
    pub(crate) stdout_queue_high_watermark: usize,
    pub(crate) diagnostic_queue_occupancy: usize,
    pub(crate) diagnostic_queue_capacity: usize,
    pub(crate) diagnostic_queue_high_watermark: usize,
    pub(crate) records_sampled: u64,
    pub(crate) records_suppressed: u64,
    pub(crate) queue_drops: u64,
    pub(crate) contention_drops: u64,
    pub(crate) records_written: u64,
    pub(crate) write_failures: u64,
    pub(crate) writer_panics: u64,
    pub(crate) writer_records_lost: u64,
    pub(crate) writer_healthy: bool,
    pub(crate) writer_terminal: bool,
    pub(crate) process_panics: u64,
}

impl DiagnosticStatusV2 {
    pub(crate) fn from_value(value: &serde_json::Value) -> Result<Self> {
        let status: Self = serde_json::from_value(value.clone())
            .context("daemon returned malformed diagnostic status")?;
        anyhow::ensure!(status.valid(2), "daemon diagnostic status is invalid");
        Ok(status)
    }

    fn valid(&self, schema_version: u8) -> bool {
        self.kind == "diagnostic_status"
            && self.schema_version == schema_version
            && contracts::valid_request_id(&self.request_id)
            && self.records_retained == 0
            && self.stdout_queue_capacity > 0
            && self.stdout_queue_occupancy <= self.stdout_queue_capacity
            && self.stdout_queue_high_watermark <= self.stdout_queue_capacity
            && self.diagnostic_queue_occupancy <= self.diagnostic_queue_capacity
            && self.diagnostic_queue_high_watermark <= self.diagnostic_queue_capacity
            && self.records_accepted >= self.records_written
            && self.records_dropped
                == self
                    .queue_drops
                    .saturating_add(self.contention_drops)
                    .saturating_add(self.writer_records_lost)
            && self.writer_healthy != self.writer_terminal
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DiagnosticStatusV3 {
    #[serde(flatten)]
    pub(crate) v2: DiagnosticStatusV2,
    pub(crate) admission_rejections: u64,
}

impl DiagnosticStatusV3 {
    pub(crate) fn from_value(value: &serde_json::Value) -> Result<Self> {
        let status: Self = serde_json::from_value(value.clone())
            .context("daemon returned malformed diagnostic status")?;
        anyhow::ensure!(status.v2.valid(3), "daemon diagnostic status is invalid");
        Ok(status)
    }
}

pub(crate) fn negotiated_diagnostic_request(status: &StatusV1) -> Result<(IpcRequest, u64)> {
    if status
        .ipc_capabilities
        .iter()
        .any(|capability| capability == DIAGNOSTIC_STATUS_V3_CAPABILITY)
    {
        Ok((IpcRequest::DiagnosticsV3, 3))
    } else if status
        .ipc_capabilities
        .iter()
        .any(|capability| capability == DIAGNOSTIC_STATUS_V2_CAPABILITY)
    {
        Ok((IpcRequest::Diagnostics, 2))
    } else {
        anyhow::bail!("daemon does not advertise a compatible diagnostic status capability")
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum IpcRequest {
    Send {
        operation_id: String,
        body: String,
    },
    PrivateSend {
        operation_id: String,
        to: String,
        body: String,
    },
    BenchSend {
        config: BenchConfig,
    },
    Subscribe,
    Status,
    Diagnostics,
    DiagnosticsV3,
    Peers,
    Offers,
    OffersRemove {
        operation_id: String,
        offer_id: String,
        direction: Option<String>,
        provider: Option<String>,
    },
    OffersPrune {
        operation_id: String,
        /// Explicit effective age. The daemon resolves and owns the cutoff.
        older_than_secs: u64,
        direction: Option<String>,
        dry_run: bool,
        max_delete: usize,
    },
    Share {
        operation_id: String,
        source_digest: String,
        path: PathBuf,
    },
    Download {
        operation_id: String,
        offer: String,
        output: PathBuf,
    },
    /// Export the verified offered blob without interpreting it. Used by the
    /// local web bridge with a server-selected temporary output path.
    WebDownload {
        operation_id: String,
        offer: String,
        output: PathBuf,
    },
    Stop,
}

/// Every IPC command is wrapped in this strict transport contract. Schema 1 is
/// intentionally fail-closed: pre-contract clients/daemons must upgrade rather
/// than silently interpreting a partial request.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct IpcRequestFrame {
    pub(crate) schema_version: u8,
    pub(crate) request_id: String,
    pub(crate) request: IpcRequest,
}

impl IpcRequest {
    fn error_expectation(&self) -> (contracts::ErrorOperationKind, Option<&str>) {
        match self {
            Self::Send { operation_id, .. } => {
                (contracts::ErrorOperationKind::Send, Some(operation_id))
            }
            Self::PrivateSend { operation_id, .. } => (
                contracts::ErrorOperationKind::PrivateSend,
                Some(operation_id),
            ),
            Self::BenchSend { .. } => (contracts::ErrorOperationKind::Benchmark, None),
            Self::Subscribe => (contracts::ErrorOperationKind::Feed, None),
            Self::Offers => (contracts::ErrorOperationKind::Offers, None),
            Self::OffersRemove { operation_id, .. } => {
                (contracts::ErrorOperationKind::Remove, Some(operation_id))
            }
            Self::OffersPrune { operation_id, .. } => {
                (contracts::ErrorOperationKind::Prune, Some(operation_id))
            }
            Self::Share { operation_id, .. } => {
                (contracts::ErrorOperationKind::Share, Some(operation_id))
            }
            Self::Download { operation_id, .. } => {
                (contracts::ErrorOperationKind::Download, Some(operation_id))
            }
            Self::WebDownload { operation_id, .. } => (
                contracts::ErrorOperationKind::WebDownload,
                Some(operation_id),
            ),
            Self::Status | Self::Diagnostics | Self::DiagnosticsV3 | Self::Peers | Self::Stop => {
                (contracts::ErrorOperationKind::General, None)
            }
        }
    }
}

impl IpcRequestFrame {
    pub(crate) fn new(request_id: String, request: IpcRequest) -> Self {
        Self {
            schema_version: contracts::SCHEMA_VERSION,
            request_id,
            request,
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            self.schema_version == contracts::SCHEMA_VERSION,
            "unsupported local IPC request schema version"
        );
        anyhow::ensure!(
            contracts::valid_request_id(&self.request_id),
            "invalid local IPC request ID"
        );
        Ok(())
    }
}

#[derive(Deserialize)]
struct ResponseMetadata {
    #[serde(rename = "type")]
    kind: String,
    schema_version: u8,
    request_id: Option<String>,
    #[serde(flatten)]
    _payload: std::collections::HashMap<String, serde_json::Value>,
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
    let metadata: ResponseMetadata =
        serde_json::from_slice(frame).context("daemon returned a malformed response envelope")?;
    anyhow::ensure!(
        metadata.schema_version > 0,
        "daemon returned an invalid response schema version"
    );
    anyhow::ensure!(!metadata.kind.is_empty(), "daemon response type is empty");
    let value: serde_json::Value =
        serde_json::from_slice(frame).context("invalid response from local daemon")?;
    if metadata.kind == "error" {
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
        metadata.request_id.as_deref() == Some(expected_request_id),
        "daemon response request ID does not match the request"
    );
    validate_success_payload_for_context(&value, expected_topic, live_now_ms)?;
    Ok(value)
}

pub(crate) async fn read_frame<S>(stream: &mut S, maximum: usize) -> Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut frame = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        let read = stream.read(&mut byte).await.context("read daemon socket")?;
        anyhow::ensure!(read != 0, "daemon socket closed before a complete response");
        if byte[0] == b'\n' {
            break;
        }
        anyhow::ensure!(
            frame.len() < maximum,
            "local IPC frame exceeds {maximum} bytes"
        );
        frame.push(byte[0]);
    }
    Ok(frame)
}

pub(crate) async fn write_value<S>(stream: &mut S, value: &serde_json::Value) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let mut encoded = serde_json::to_vec(value)?;
    anyhow::ensure!(
        encoded.len() <= MAX_IPC_EVENT_SIZE,
        "local IPC event exceeds {MAX_IPC_EVENT_SIZE} bytes"
    );
    encoded.push(b'\n');
    stream
        .write_all(&encoded)
        .await
        .context("write daemon socket")?;
    Ok(())
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
        let (kind, operation_id) = request.error_expectation();
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
            StatusV1::from_value(&value)?;
        }
        "diagnostic_status" => match expected_schema_version {
            Some(2) => {
                DiagnosticStatusV2::from_value(&value)?;
            }
            Some(3) => {
                DiagnosticStatusV3::from_value(&value)?;
            }
            _ => anyhow::bail!("diagnostic status validation requires schema version 2 or 3"),
        },
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
    let frame = IpcRequestFrame::new(request_id.to_owned(), request.clone());
    let mut encoded = serde_json::to_vec(&frame)?;
    anyhow::ensure!(
        encoded.len() <= MAX_IPC_REQUEST_SIZE,
        "local IPC request is too large"
    );
    encoded.push(b'\n');
    stream.write_all(&encoded).await?;
    Ok(())
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
        Self::new_correlated_for_operation(stream, request_id, contracts::ErrorOperationKind::Feed)
    }

    pub(crate) fn new_correlated_for_operation(
        stream: S,
        request_id: String,
        error_operation: contracts::ErrorOperationKind,
    ) -> Self {
        Self {
            reader: BufReader::new(stream),
            frame: Vec::new(),
            request_id: Some(request_id),
            expected_topic: None,
            error_operation,
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

    pub(crate) fn get_mut(&mut self) -> &mut S {
        self.reader.get_mut()
    }

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
            "type":"attachment_offer", "schema_version":2, "request_id":request_id,
            "from":"4".repeat(64), "message_id":operation_id, "timestamp_ms":1,
            "offer_id":operation_id.to_ascii_uppercase(), "kind":"file",
            "name":"safe.txt", "size":4, "ticket":"malformed", "offer":"malformed"
        });
        let valid = serde_json::json!({
            "type":"message", "schema_version":2, "request_id":request_id,
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
                operation_id: "0123456789abcdef0123456789abcdef".into(),
                body: "a\nb".into(),
            },
            "11111111111111111111111111111111",
        )
        .await
        .unwrap();
        assert_eq!(bytes, b"{\"schema_version\":1,\"request_id\":\"11111111111111111111111111111111\",\"request\":{\"command\":\"send\",\"operation_id\":\"0123456789abcdef0123456789abcdef\",\"body\":\"a\\nb\"}}\n");
        assert!(write_request(
            &mut bytes,
            &IpcRequest::Send {
                operation_id: "0123456789abcdef0123456789abcdef".into(),
                body: "x".repeat(MAX_IPC_REQUEST_SIZE),
            }
        )
        .await
        .is_err());
    }

    #[tokio::test]
    async fn web_download_is_a_distinct_raw_export_command() {
        let mut bytes = Vec::new();
        write_request(
            &mut bytes,
            &IpcRequest::WebDownload {
                operation_id: "0123456789abcdef0123456789abcdef".into(),
                offer: "signed-offer".into(),
                output: PathBuf::from("server-selected.blob"),
            },
        )
        .await
        .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["request"]["command"], "web_download");
        assert_eq!(value["request"]["offer"], "signed-offer");
        assert_eq!(value["request"]["output"], "server-selected.blob");
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
            (
                AttachmentOperationKind::WebDownload,
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
                AttachmentOperationKind::WebDownload,
            ] {
                if wrong_kind != kind
                    && !(code == "download_failed"
                        && matches!(
                            wrong_kind,
                            AttachmentOperationKind::Download
                                | AttachmentOperationKind::WebDownload
                        ))
                {
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
            AttachmentOperationKind::WebDownload,
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
                operation_id: "fedcba9876543210fedcba9876543210".into(),
                offer_id: "0123456789abcdef0123456789abcdef".into(),
                direction: Some("outgoing".into()),
                provider: None,
            },
        )
        .await
        .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["request"]["command"], "offers_remove");
        let prune = IpcRequest::OffersPrune {
            operation_id: "fedcba9876543210fedcba9876543210".into(),
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
        assert_eq!(value["schema_version"], 1);
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
                operation_id: "0123456789abcdef0123456789abcdef".into(),
                to: "peer".into(),
                body: "private text".into(),
            },
        )
        .await
        .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["schema_version"], 1);
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
        let valid = br#"{"schema_version":1,"request_id":"11111111111111111111111111111111","request":{"command":"status"}}"#;
        let frame: IpcRequestFrame = serde_json::from_slice(valid).unwrap();
        frame.validate().unwrap();
        for malformed in [
            br#"{"request_id":"11111111111111111111111111111111","request":{"command":"status"}}"#.as_slice(),
            br#"{"schema_version":1,"request_id":"11111111111111111111111111111111","request":{"command":"status"},"extra":true}"#.as_slice(),
            br#"{"schema_version":1,"schema_version":1,"request_id":"11111111111111111111111111111111","request":{"command":"status"}}"#.as_slice(),
            br#"{"schema_version":1,"request_id":1,"request":{"command":"status"}}"#.as_slice(),
        ] {
            assert!(serde_json::from_slice::<IpcRequestFrame>(malformed).is_err());
        }
        for unsupported in [
            br#"{"schema_version":2,"request_id":"11111111111111111111111111111111","request":{"command":"status"}}"#.as_slice(),
            br#"{"schema_version":1,"request_id":"UPPER000000000000000000000000000","request":{"command":"status"}}"#.as_slice(),
        ] {
            let frame: IpcRequestFrame = serde_json::from_slice(unsupported).unwrap();
            assert!(frame.validate().is_err());
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
                operation_id: operation.into(),
                body: "x".into(),
            },
            IpcRequest::PrivateSend {
                operation_id: operation.into(),
                to: "2".repeat(64),
                body: "x".into(),
            },
            IpcRequest::Share {
                operation_id: operation.into(),
                source_digest: "3".repeat(64),
                path: PathBuf::from("x"),
            },
            IpcRequest::OffersRemove {
                operation_id: operation.into(),
                offer_id: "4".repeat(32),
                direction: None,
                provider: None,
            },
            IpcRequest::OffersPrune {
                operation_id: operation.into(),
                older_than_secs: 1,
                direction: None,
                dry_run: false,
                max_delete: 1,
            },
            IpcRequest::Download {
                operation_id: operation.into(),
                offer: "x".into(),
                output: PathBuf::from("x"),
            },
            IpcRequest::WebDownload {
                operation_id: operation.into(),
                offer: "x".into(),
                output: PathBuf::from("x"),
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
        let valid = br#"{"type":"stopping","schema_version":1,"request_id":"11111111111111111111111111111111","outcome":"accepted"}"#;
        assert!(decode_response(valid, id).is_ok());
        assert!(decode_response(br#"{"type":"stopping","type":"stopping","schema_version":1,"request_id":"11111111111111111111111111111111","outcome":"accepted"}"#, id).is_err());
        assert!(decode_response(br#"{"type":"stopping","schema_version":1,"request_id":"22222222222222222222222222222222","outcome":"accepted"}"#, id).is_err());
        assert!(decode_response(
            br#"{"type":"stopping","request_id":"11111111111111111111111111111111","outcome":"accepted"}"#,
            id
        )
        .is_err());
    }

    #[test]
    fn status_dto_is_exact_and_rejects_unknown_missing_and_wrong_version() {
        let mut status = StatusV1 {
            kind: "status".into(),
            schema_version: 1,
            request_id: "11111111111111111111111111111111".into(),
            running: true,
            peer: "2".repeat(64),
            topic: "3".repeat(64),
            advertises_self: true,
            has_invite: true,
            bootstrap_peer_count: 1,
            self_advertised: true,
            neighbors: 1,
            endpoint_online: true,
            topic_joined: true,
            alias: Some("node".into()),
            alias_enabled: true,
            captured_hostname: Some("node".into()),
            custom_alias: None,
            advertised_aliases: 1,
            ipc_capabilities: vec!["typed_contracts_v1".into()],
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
            attachment_storage: AttachmentStorageStatusV1 {
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
        let value = serde_json::to_value(&status).unwrap();
        validate_success_payload(&value).unwrap();
        let mut v1_with_v2_metrics = value.clone();
        v1_with_v2_metrics["diagnostic_records_accepted"] = 1.into();
        assert!(validate_success_payload(&v1_with_v2_metrics).is_err());
        // This is the exact strict diagnostic_status_v2 shape released in v0.1.19.
        let diagnostics_v2 = serde_json::json!({
            "type":"diagnostic_status", "schema_version":2,
            "request_id":"11111111111111111111111111111111",
            "records_accepted":2, "records_dropped":1, "records_retained":0,
            "stdout_queue_occupancy":0, "stdout_queue_capacity":256,
            "stdout_queue_high_watermark":2,
            "diagnostic_queue_occupancy":0, "diagnostic_queue_capacity":128,
            "diagnostic_queue_high_watermark":1,
            "records_sampled":1, "records_suppressed":1,
            "queue_drops":1, "contention_drops":0,
            "records_written":2, "write_failures":0, "writer_panics":0,
            "writer_records_lost":0, "writer_healthy":true,
            "writer_terminal":false, "process_panics":0
        });
        DiagnosticStatusV2::from_value(&diagnostics_v2).unwrap();
        assert!(validate_success_payload(&diagnostics_v2).is_ok());
        let mut v2_with_v3_metric = diagnostics_v2.clone();
        v2_with_v3_metric["admission_rejections"] = 3.into();
        assert!(DiagnosticStatusV2::from_value(&v2_with_v3_metric).is_err());

        let mut diagnostics_v3 = diagnostics_v2.clone();
        diagnostics_v3["schema_version"] = 3.into();
        diagnostics_v3["admission_rejections"] = 3.into();
        DiagnosticStatusV3::from_value(&diagnostics_v3).unwrap();
        assert!(validate_success_payload(&diagnostics_v3).is_ok());
        let mut v3_missing_metric = diagnostics_v3.clone();
        v3_missing_metric
            .as_object_mut()
            .unwrap()
            .remove("admission_rejections");
        assert!(DiagnosticStatusV3::from_value(&v3_missing_metric).is_err());
        let mut v3_unknown = diagnostics_v3.clone();
        v3_unknown["private_cause"] = "secret".into();
        assert!(DiagnosticStatusV3::from_value(&v3_unknown).is_err());

        let mut malformed_diagnostics = diagnostics_v2;
        malformed_diagnostics["records_retained"] = 257.into();
        assert!(DiagnosticStatusV2::from_value(&malformed_diagnostics).is_err());

        status.ipc_capabilities = vec![DIAGNOSTIC_STATUS_V2_CAPABILITY.into()];
        let (request, version) = negotiated_diagnostic_request(&status).unwrap();
        assert!(matches!(request, IpcRequest::Diagnostics));
        assert_eq!(version, 2);
        status
            .ipc_capabilities
            .push(DIAGNOSTIC_STATUS_V3_CAPABILITY.into());
        let (request, version) = negotiated_diagnostic_request(&status).unwrap();
        assert!(matches!(request, IpcRequest::DiagnosticsV3));
        assert_eq!(version, 3);
        status.ipc_capabilities.clear();
        assert!(negotiated_diagnostic_request(&status).is_err());

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
        let base_send_progress = serde_json::json!({
            "type":"bench_send_progress", "schema_version":2, "request_id":request_id,
            "run_id":operation_id, "rate":10, "duration_secs":1, "payload_bytes":128,
            "planned":10, "attempted":2, "queued":2, "failed":0, "incomplete":0,
            "schedule_missed":0, "queued_body_bytes":256, "queued_envelope_bytes":512,
            "elapsed_ms":200, "achieved_messages_per_second":10.0,
            "achieved_body_bytes_per_second":1280.0, "delivery_acknowledged":false
        });
        let latency = serde_json::json!({
            "observations":1,"samples":1,"sampled":false,"clock_invalid":0,
            "p50_ms":1,"p95_ms":1,"p99_ms":1
        });
        let lag = serde_json::json!({
            "local_events":0,"local_dropped":0,"gossip_events":0,"incomplete":false
        });
        let cutoff_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
            - 1_000;
        let fixtures = vec![
            serde_json::json!({"type":"connected","schema_version":1,"request_id":request_id,"peer":peer,"endpoint_online":true,"topic_joined":true,"alias":"node","ipc_capabilities":["typed_contracts_v1"]}),
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
            serde_json::json!({"type":"bench_send_started","schema_version":2,"request_id":request_id,"run_id":operation_id,"rate":10,"duration_secs":1,"payload_bytes":128,"planned":10,"delivery_acknowledged":false}),
            base_send_progress.clone(),
            {
                let mut value = base_send_progress.clone();
                value["type"] = "bench_send_summary".into();
                value["accounting_complete"] = true.into();
                value["completion_reason"] = "interrupted".into();
                value["schedule_missed"] = 1.into();
                value["first_error"] = serde_json::Value::Null;
                value
            },
            serde_json::json!({"type":"bench_receive_started","schema_version":1,"request_id":request_id,"run_id":operation_id,"duration_secs":1,"expected":10}),
            serde_json::json!({"type":"bench_receive_progress","schema_version":1,"request_id":request_id,"run_id":operation_id,"elapsed_ms":1,"expected":10,"unique":1,"missing":9,"duplicates":0,"out_of_order":0,"highest_sequence":0,"body_bytes":128,"achieved_messages_per_second":1000.0,"achieved_body_bytes_per_second":128000.0,"latency":latency,"lag":lag,"malformed_messages":0}),
            serde_json::json!({"type":"bench_receive_summary","schema_version":1,"request_id":request_id,"run_id":operation_id,"completion_reason":"deadline","elapsed_ms":1,"expected":1,"complete":true,"measurement_valid":true,"unique":1,"missing":0,"missing_sequence_sample":[],"duplicates":0,"out_of_order":0,"highest_sequence":0,"body_bytes":128,"achieved_messages_per_second":1000.0,"achieved_body_bytes_per_second":128000.0,"latency":latency,"lag":lag,"peer_up":0,"peer_down":0,"ignored_messages":0,"malformed_messages":0}),
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

        let mut failed_summary = base_send_progress;
        failed_summary["type"] = "bench_send_summary".into();
        failed_summary["accounting_complete"] = true.into();
        failed_summary["completion_reason"] = "send_failed".into();
        failed_summary["attempted"] = 2.into();
        failed_summary["queued"] = 1.into();
        failed_summary["failed"] = 1.into();
        failed_summary["schedule_missed"] = 1.into();
        failed_summary["queued_body_bytes"] = 128.into();
        failed_summary["queued_envelope_bytes"] = 256.into();
        failed_summary["achieved_messages_per_second"] = 5.0.into();
        failed_summary["achieved_body_bytes_per_second"] = 640.0.into();
        failed_summary["first_error"] = contracts::BENCHMARK_SEND_FAILED_MESSAGE.into();
        validate_success_payload(&failed_summary).unwrap();
        for unsafe_error in [
            "/home/alice/private/benchmark.log",
            "submission failed\t/private/path",
            "submission failed\nforged record",
            "submission failed\u{001b}[31m",
            "x",
        ] {
            let mut malformed = failed_summary.clone();
            malformed["first_error"] = unsafe_error.into();
            assert!(
                validate_success_payload(&malformed).is_err(),
                "unsafe benchmark error accepted: {unsafe_error:?}"
            );
        }
        let mut oversized = failed_summary.clone();
        oversized["first_error"] = "x".repeat(contracts::MAX_PUBLIC_MESSAGE_BYTES + 1).into();
        assert!(validate_success_payload(&oversized).is_err());

        for malformed in [
            {
                let mut value = failed_summary.clone();
                value["failed"] = 0.into();
                value["queued"] = 2.into();
                value
            },
            {
                let mut value = failed_summary.clone();
                value["first_error"] = serde_json::Value::Null;
                value
            },
            {
                let mut value = failed_summary.clone();
                value["completion_reason"] = "deadline".into();
                value
            },
            {
                let mut value = failed_summary.clone();
                value["attempted"] = 1.into();
                value
            },
        ] {
            assert!(validate_success_payload(&malformed).is_err());
        }

        let mut completed_summary = failed_summary;
        completed_summary["completion_reason"] = "deadline".into();
        completed_summary["first_error"] = serde_json::Value::Null;
        completed_summary["queued"] = 2.into();
        completed_summary["failed"] = 0.into();
        completed_summary["queued_body_bytes"] = 256.into();
        completed_summary["queued_envelope_bytes"] = 512.into();
        completed_summary["elapsed_ms"] = 1000.into();
        completed_summary["achieved_messages_per_second"] = 2.0.into();
        completed_summary["achieved_body_bytes_per_second"] = 256.0.into();
        completed_summary["schedule_missed"] = 8.into();
        validate_success_payload(&completed_summary).unwrap();
    }

    #[test]
    fn benchmark_metric_validation_fails_closed_on_adversarial_boundaries() {
        let request_id = "11111111111111111111111111111111";
        let run_id = "22222222222222222222222222222222";
        let send = serde_json::json!({
            "type":"bench_send_summary", "schema_version":2, "request_id":request_id,
            "run_id":run_id, "rate":10, "duration_secs":1, "payload_bytes":128,
            "planned":10, "attempted":10, "queued":10, "failed":0, "incomplete":0,
            "schedule_missed":0, "queued_body_bytes":1280, "queued_envelope_bytes":2560,
            "elapsed_ms":1000, "achieved_messages_per_second":10.0,
            "achieved_body_bytes_per_second":1280.0, "delivery_acknowledged":false,
            "accounting_complete":true, "completion_reason":"deadline", "first_error":null
        });
        validate_success_payload(&send).unwrap();
        let mut early_progress = send.clone();
        early_progress["type"] = "bench_send_progress".into();
        early_progress
            .as_object_mut()
            .unwrap()
            .remove("completion_reason");
        early_progress
            .as_object_mut()
            .unwrap()
            .remove("first_error");
        early_progress
            .as_object_mut()
            .unwrap()
            .remove("accounting_complete");
        early_progress["elapsed_ms"] = 100.into();
        early_progress["attempted"] = 1.into();
        early_progress["queued"] = 1.into();
        early_progress["schedule_missed"] = 5.into();
        early_progress["queued_body_bytes"] = 128.into();
        early_progress["queued_envelope_bytes"] = 256.into();
        early_progress["achieved_messages_per_second"] = 10.0.into();
        early_progress["achieved_body_bytes_per_second"] = 1280.0.into();
        assert!(validate_success_payload(&early_progress).is_err());

        for (field, value) in [
            ("queued_body_bytes", serde_json::json!(0)),
            ("queued_body_bytes", serde_json::json!(1279)),
            ("queued_envelope_bytes", serde_json::json!(1280)),
            ("queued_envelope_bytes", serde_json::json!(40961)),
            ("achieved_messages_per_second", serde_json::json!(-0.1)),
            ("achieved_body_bytes_per_second", serde_json::json!(-1.0)),
            ("achieved_messages_per_second", serde_json::json!(9.0)),
            ("schedule_missed", serde_json::json!(u64::MAX)),
            ("attempted", serde_json::json!(u64::MAX)),
            ("planned", serde_json::json!(u64::MAX)),
            ("incomplete", serde_json::json!(2)),
            ("accounting_complete", serde_json::json!(false)),
        ] {
            let mut malformed = send.clone();
            malformed[field] = value;
            assert!(
                validate_success_payload(&malformed).is_err(),
                "adversarial send field {field} was accepted"
            );
        }

        let latency = serde_json::json!({
            "observations":1,"samples":1,"sampled":false,"clock_invalid":0,
            "p50_ms":1,"p95_ms":1,"p99_ms":1
        });
        let receive = serde_json::json!({
            "type":"bench_receive_summary", "schema_version":1, "request_id":request_id,
            "run_id":run_id, "completion_reason":"deadline", "elapsed_ms":1000,
            "expected":2, "complete":false, "measurement_valid":false,
            "unique":1, "missing":1, "missing_sequence_sample":[1],
            "duplicates":0, "out_of_order":0, "highest_sequence":0,
            "body_bytes":128, "achieved_messages_per_second":1.0,
            "achieved_body_bytes_per_second":128.0, "latency":latency,
            "lag":{"local_events":0,"local_dropped":0,"gossip_events":0,"incomplete":false},
            "peer_up":0,"peer_down":0,"ignored_messages":0,"malformed_messages":0
        });
        validate_success_payload(&receive).unwrap();
        let contradictions = [
            ("zero body for a unique message", {
                let mut v = receive.clone();
                v["body_bytes"] = 0.into();
                v
            }),
            ("negative message rate", {
                let mut v = receive.clone();
                v["achieved_messages_per_second"] = (-1.0).into();
                v
            }),
            ("incoherent body rate", {
                let mut v = receive.clone();
                v["achieved_body_bytes_per_second"] = 127.0.into();
                v
            }),
            ("unique exceeds expected", {
                let mut v = receive.clone();
                v["unique"] = 3.into();
                v
            }),
            ("positive unique without highest", {
                let mut v = receive.clone();
                v["highest_sequence"] = serde_json::Value::Null;
                v
            }),
            ("highest is listed as missing", {
                let mut v = receive.clone();
                v["missing_sequence_sample"] = serde_json::json!([0]);
                v
            }),
            ("missing sample has wrong cardinality", {
                let mut v = receive.clone();
                v["missing_sequence_sample"] = serde_json::json!([]);
                v
            }),
            ("validity contradicts incomplete delivery", {
                let mut v = receive.clone();
                v["measurement_valid"] = true.into();
                v
            }),
            ("latency count overflow", {
                let mut v = receive.clone();
                v["latency"]["observations"] = u64::MAX.into();
                v
            }),
            ("positive observations without retained samples", {
                let mut v = receive.clone();
                v["latency"]["samples"] = 0.into();
                v["latency"]["sampled"] = true.into();
                v["latency"]["p50_ms"] = serde_json::Value::Null;
                v["latency"]["p95_ms"] = serde_json::Value::Null;
                v["latency"]["p99_ms"] = serde_json::Value::Null;
                v
            }),
            ("partial null percentiles", {
                let mut v = receive.clone();
                v["latency"]["p95_ms"] = serde_json::Value::Null;
                v
            }),
            ("percentiles out of order", {
                let mut v = receive.clone();
                v["latency"]["p95_ms"] = 0.into();
                v
            }),
            ("one-sample percentiles disagree", {
                let mut v = receive.clone();
                v["latency"]["p95_ms"] = 2.into();
                v["latency"]["p99_ms"] = 2.into();
                v
            }),
            ("local drop sum below event count", {
                let mut v = receive.clone();
                v["lag"]["local_events"] = 2.into();
                v["lag"]["local_dropped"] = 1.into();
                v["lag"]["incomplete"] = true.into();
                v
            }),
            ("out of order before a second unique", {
                let mut v = receive.clone();
                v["out_of_order"] = 1.into();
                v
            }),
            ("duplicate before any unique", {
                let mut v = receive.clone();
                v["unique"] = 0.into();
                v["missing"] = 2.into();
                v["missing_sequence_sample"] = serde_json::json!([0, 1]);
                v["highest_sequence"] = serde_json::Value::Null;
                v["body_bytes"] = 0.into();
                v["achieved_messages_per_second"] = 0.0.into();
                v["achieved_body_bytes_per_second"] = 0.0.into();
                v["duplicates"] = 1.into();
                v["latency"] = serde_json::json!({
                    "observations":0,"samples":0,"sampled":false,"clock_invalid":0,
                    "p50_ms":null,"p95_ms":null,"p99_ms":null
                });
                v
            }),
            ("highest range cannot contain unique count", {
                let mut v = receive.clone();
                v["unique"] = 2.into();
                v["missing"] = 0.into();
                v["missing_sequence_sample"] = serde_json::json!([]);
                v["complete"] = true.into();
                v["measurement_valid"] = true.into();
                v["body_bytes"] = 256.into();
                v["achieved_messages_per_second"] = 2.0.into();
                v["achieved_body_bytes_per_second"] = 256.0.into();
                v["latency"]["observations"] = 2.into();
                v["latency"]["samples"] = 2.into();
                v
            }),
            ("sample capacity overflow", {
                let mut v = receive.clone();
                v["latency"]["samples"] = 1_000_001.into();
                v
            }),
            ("body byte overflow boundary", {
                let mut v = receive.clone();
                v["body_bytes"] = u64::MAX.into();
                v
            }),
        ];
        for (name, malformed) in contradictions {
            assert!(
                validate_success_payload(&malformed).is_err(),
                "receive contradiction accepted: {name}"
            );
        }
    }

    #[test]
    fn benchmark_numeric_validation_never_panics_at_machine_boundaries() {
        let request_id = "11111111111111111111111111111111";
        let run_id = "22222222222222222222222222222222";
        let send = serde_json::json!({
            "type":"bench_send_progress", "schema_version":2, "request_id":request_id,
            "run_id":run_id, "rate":1, "duration_secs":1, "payload_bytes":128,
            "planned":1, "attempted":1, "queued":1, "failed":0, "incomplete":0,
            "schedule_missed":0, "queued_body_bytes":128, "queued_envelope_bytes":256,
            "elapsed_ms":1000, "achieved_messages_per_second":1.0,
            "achieved_body_bytes_per_second":128.0, "delivery_acknowledged":false
        });
        let receive = serde_json::json!({
            "type":"bench_receive_summary", "schema_version":1, "request_id":request_id,
            "run_id":run_id, "completion_reason":"deadline", "elapsed_ms":1000,
            "expected":1, "complete":true, "measurement_valid":true,
            "unique":1, "missing":0, "missing_sequence_sample":[],
            "duplicates":0, "out_of_order":0, "highest_sequence":0,
            "body_bytes":128, "achieved_messages_per_second":1.0,
            "achieved_body_bytes_per_second":128.0,
            "latency":{"observations":1,"samples":1,"sampled":false,"clock_invalid":0,
                "p50_ms":1,"p95_ms":1,"p99_ms":1},
            "lag":{"local_events":0,"local_dropped":0,"gossip_events":0,"incomplete":false},
            "peer_up":0,"peer_down":0,"ignored_messages":0,"malformed_messages":0
        });

        let mut malformed = Vec::new();
        for rate in [0_u32, u32::MAX] {
            let mut value = send.clone();
            value["rate"] = rate.into();
            malformed.push(value);
        }
        for (field, boundary) in [
            ("elapsed_ms", u64::MAX),
            ("attempted", u64::MAX),
            ("queued", u64::MAX),
            ("queued_body_bytes", u64::MAX),
            ("queued_envelope_bytes", u64::MAX),
        ] {
            let mut value = send.clone();
            value[field] = boundary.into();
            malformed.push(value);
        }
        let mut huge_samples = receive.clone();
        huge_samples["latency"]["samples"] = usize::MAX.into();
        malformed.push(huge_samples);
        let mut latency_sum_overflow = receive;
        latency_sum_overflow["unique"] = u64::MAX.into();
        latency_sum_overflow["latency"]["observations"] = u64::MAX.into();
        latency_sum_overflow["latency"]["clock_invalid"] = 1.into();
        malformed.push(latency_sum_overflow);

        for value in malformed {
            let result = std::panic::catch_unwind(|| validate_success_payload(&value));
            assert!(result.is_ok(), "numeric boundary panicked: {value}");
            assert!(
                result.unwrap().is_err(),
                "numeric boundary was accepted: {value}"
            );
        }
    }

    #[test]
    fn missing_sequence_sample_feasibility_matches_small_exhaustive_model() {
        for expected in 1_u64..=9 {
            let universe = 1_u64 << expected;
            for unique in 0..=expected {
                for highest in std::iter::once(None).chain((0..expected).map(Some)) {
                    for missing_mask in 0..universe {
                        let sample = (0..expected)
                            .filter(|sequence| missing_mask & (1 << sequence) != 0)
                            .collect::<Vec<_>>();
                        let complement = (0..expected)
                            .filter(|sequence| missing_mask & (1 << sequence) == 0)
                            .collect::<Vec<_>>();
                        let feasible = sample.len() as u64 == expected - unique
                            && complement.last().copied() == highest;
                        assert_eq!(
                            coherent_missing_sequence_sample(
                                Some(expected),
                                unique,
                                Some(expected - unique),
                                highest,
                                &sample,
                            ),
                            feasible,
                            "expected={expected} unique={unique} highest={highest:?} sample={sample:?}"
                        );
                    }
                }
            }
        }

        // Exhaust all observed sets that still force truncation in a 104-item
        // universe. Their generated first-100 missing prefixes must stay valid.
        let expected = 104_u64;
        for observed_mask in 0_u16..(1 << 10) {
            let observed = (0_u64..10)
                .filter(|sequence| observed_mask & (1_u16 << sequence) != 0)
                .collect::<Vec<_>>();
            if observed.len() >= 4 {
                continue;
            }
            let sample = (0..expected)
                .filter(|sequence| !observed.contains(sequence))
                .take(100)
                .collect::<Vec<_>>();
            assert!(coherent_missing_sequence_sample(
                Some(expected),
                observed.len() as u64,
                Some(expected - observed.len() as u64),
                observed.last().copied(),
                &sample,
            ));
        }
    }

    #[test]
    fn truncated_missing_sequence_samples_enforce_sound_prefix_constraints() {
        let valid = (0_u64..100).collect::<Vec<_>>();
        assert!(coherent_missing_sequence_sample(
            Some(105),
            1,
            Some(104),
            Some(104),
            &valid,
        ));
        let mut skipped_prefix_gap = valid.clone();
        skipped_prefix_gap[50..].rotate_left(1);
        skipped_prefix_gap[99] = 100;
        skipped_prefix_gap.sort_unstable();
        assert!(!coherent_missing_sequence_sample(
            Some(105),
            1,
            Some(104),
            Some(104),
            &skipped_prefix_gap,
        ));

        let complete_tail = (100_u64..200).collect::<Vec<_>>();
        assert!(coherent_missing_sequence_sample(
            Some(200),
            100,
            Some(100),
            Some(99),
            &complete_tail,
        ));
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
            IpcRequest::Send { body, .. } if body == "broadcast"
        ));
    }
}
