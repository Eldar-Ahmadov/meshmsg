//! Shared bounded newline-delimited local daemon protocol. Platform connection
//! ownership checks remain in node::connect_daemon for both CLI and web clients.
use crate::{
    contracts::{self, ErrorEnvelopeV1},
    node::{connect_daemon, LocalClientStream},
};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
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
pub(crate) const ATTACHMENT_LIFECYCLE_CAPABILITY: &str = "attachment_lifecycle_v1";
pub(crate) type LifecycleErrorV1 = ErrorEnvelopeV1;

pub(crate) fn valid_operation_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn valid_content_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LifecycleSuccessV1 {
    #[serde(rename = "type")]
    family: String,
    schema_version: u8,
    request_id: String,
    dry_run: bool,
    selected_tags: usize,
    removed_tags: usize,
    released_bytes: u64,
    limited: bool,
    cutoff_ms: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DownloadStartedV1 {
    #[serde(rename = "type")]
    family: String,
    schema_version: u8,
    request_id: String,
    output: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DownloadProgressV1 {
    #[serde(rename = "type")]
    family: String,
    schema_version: u8,
    request_id: String,
    received_bytes: u64,
    total_bytes: u64,
    output: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DownloadCompleteV1 {
    #[serde(rename = "type")]
    family: String,
    schema_version: u8,
    request_id: String,
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
struct BenchSendStartedV1 {
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
struct BenchSendProgressV1 {
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
struct BenchSendSummaryV1 {
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
    schedule_missed: u64,
    queued_body_bytes: u64,
    queued_envelope_bytes: u64,
    elapsed_ms: u64,
    achieved_messages_per_second: f64,
    achieved_body_bytes_per_second: f64,
    delivery_acknowledged: bool,
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

impl DownloadCompleteV1 {
    pub(crate) fn from_value(value: &serde_json::Value) -> Result<Self> {
        let dto: Self = serde_json::from_value(value.clone())
            .context("malformed download-complete response")?;
        anyhow::ensure!(
            valid_family(
                &dto.family,
                "download_complete",
                dto.schema_version,
                &dto.request_id
            ) && dto.schema_version == 1
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

    pub(crate) fn output(&self) -> &Path {
        &self.output
    }
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

fn validate_bench_metrics(
    expected: Option<u64>,
    unique: u64,
    missing: Option<u64>,
    highest: Option<u64>,
    latency: &BenchLatencyV1,
    lag: &BenchLagV1,
    rates: (f64, f64),
) -> Result<()> {
    anyhow::ensure!(
        rates.0.is_finite() && rates.0 >= 0.0 && rates.1.is_finite() && rates.1 >= 0.0,
        "invalid benchmark rates"
    );
    anyhow::ensure!(
        expected.map(|count| count.saturating_sub(unique)) == missing,
        "invalid benchmark missing count"
    );
    anyhow::ensure!(
        highest.is_none_or(|value| expected.is_none_or(|count| value < count)),
        "invalid benchmark highest sequence"
    );
    anyhow::ensure!(
        latency.samples <= 4096 && latency.samples as u64 <= latency.observations,
        "invalid benchmark latency counts"
    );
    anyhow::ensure!(
        lag.incomplete == (lag.local_events > 0 || lag.gossip_events > 0),
        "invalid benchmark lag state"
    );
    let _ = (
        latency.sampled,
        latency.clock_invalid,
        latency.p50_ms,
        latency.p95_ms,
        latency.p99_ms,
        lag.local_dropped,
    );
    Ok(())
}

pub(crate) fn validate_success_payload(value: &serde_json::Value) -> Result<()> {
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
                    && !dto.body.is_empty()
                    && dto.body.len() <= 4096,
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
            anyhow::ensure!(
                valid_family(&dto.family, family, dto.schema_version, &dto.request_id)
                    && valid_peer_id(&dto.from)
                    && valid_operation_id(&dto.message_id)
                    && valid_operation_id(&dto.offer_id)
                    && dto.timestamp_ms != 0
                    && matches!(dto.kind.as_str(), "file" | "directory_tar_v1")
                    && valid_public_text(&dto.name, 255)
                    && !dto.ticket.is_empty()
                    && !dto.offer.is_empty(),
                "invalid attachment offer"
            );
            let _ = dto.size;
        }
        ("attachment_shared", 3) => {
            let dto: AttachmentSharedV3 =
                serde_json::from_value(value.clone()).context("malformed attachment share")?;
            anyhow::ensure!(
                valid_family(&dto.family, family, dto.schema_version, &dto.request_id)
                    && valid_operation_id(&dto.operation_id)
                    && dto.message_id == dto.operation_id
                    && dto.offer_id == dto.operation_id
                    && valid_content_digest(&dto.source_digest)
                    && valid_peer_id(&dto.from)
                    && dto.timestamp_ms != 0
                    && matches!(dto.kind.as_str(), "file" | "directory_tar_v1")
                    && valid_public_text(&dto.name, 255)
                    && !dto.ticket.is_empty()
                    && !dto.offer.is_empty()
                    && !dto.delivery_acknowledged,
                "invalid attachment share"
            );
            let _ = dto.size;
        }
        ("offers", 1) => {
            let dto: OffersV1 =
                serde_json::from_value(value.clone()).context("malformed offers response")?;
            dto.validate()?;
        }
        ("offer_removed" | "offers_pruned", 1) => {
            let dto: LifecycleSuccessV1 =
                serde_json::from_value(value.clone()).context("malformed lifecycle response")?;
            anyhow::ensure!(
                valid_family(&dto.family, family, dto.schema_version, &dto.request_id)
                    && dto.removed_tags <= dto.selected_tags
                    && (!dto.dry_run || dto.removed_tags == 0),
                "invalid lifecycle response"
            );
            let _ = (dto.released_bytes, dto.limited, dto.cutoff_ms);
        }
        ("download_started", 1) => {
            let dto: DownloadStartedV1 = serde_json::from_value(value.clone())
                .context("malformed download-started event")?;
            anyhow::ensure!(
                valid_family(&dto.family, family, dto.schema_version, &dto.request_id)
                    && !dto.output.as_os_str().is_empty(),
                "invalid download-started event"
            );
        }
        ("download_progress", 1) => {
            let dto: DownloadProgressV1 = serde_json::from_value(value.clone())
                .context("malformed download-progress event")?;
            anyhow::ensure!(
                valid_family(&dto.family, family, dto.schema_version, &dto.request_id)
                    && !dto.output.as_os_str().is_empty()
                    && dto.total_bytes > 0
                    && dto.received_bytes <= dto.total_bytes,
                "invalid download-progress event"
            );
        }
        ("download_complete", 1) => {
            DownloadCompleteV1::from_value(value)?;
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
        ("bench_send_started", 1) => {
            let dto: BenchSendStartedV1 =
                serde_json::from_value(value.clone()).context("malformed benchmark start")?;
            validate_bench_base(
                &dto.run_id,
                dto.duration_secs,
                Some(dto.planned),
                &dto.request_id,
            )?;
            anyhow::ensure!(
                dto.family == family
                    && dto.schema_version == 1
                    && (1..=10_000).contains(&dto.rate)
                    && dto.payload_bytes > 0
                    && !dto.delivery_acknowledged,
                "invalid benchmark start"
            );
        }
        ("bench_send_progress", 1) => {
            let dto: BenchSendProgressV1 =
                serde_json::from_value(value.clone()).context("malformed benchmark progress")?;
            validate_bench_base(
                &dto.run_id,
                dto.duration_secs,
                Some(dto.planned),
                &dto.request_id,
            )?;
            anyhow::ensure!(
                dto.family == family
                    && (1..=10_000).contains(&dto.rate)
                    && dto.payload_bytes > 0
                    && dto.queued <= dto.attempted
                    && dto.failed <= dto.attempted
                    && dto.attempted <= dto.planned
                    && dto.queued_body_bytes <= dto.queued.saturating_mul(dto.payload_bytes as u64)
                    && dto.achieved_messages_per_second.is_finite()
                    && dto.achieved_body_bytes_per_second.is_finite()
                    && !dto.delivery_acknowledged,
                "invalid benchmark progress"
            );
            let _ = (
                dto.schema_version,
                dto.schedule_missed,
                dto.queued_envelope_bytes,
                dto.elapsed_ms,
            );
        }
        ("bench_send_summary", 1) => {
            let dto: BenchSendSummaryV1 =
                serde_json::from_value(value.clone()).context("malformed benchmark summary")?;
            validate_bench_base(
                &dto.run_id,
                dto.duration_secs,
                Some(dto.planned),
                &dto.request_id,
            )?;
            anyhow::ensure!(
                dto.family == family
                    && (1..=10_000).contains(&dto.rate)
                    && dto.payload_bytes > 0
                    && dto.queued <= dto.attempted
                    && dto.failed <= dto.attempted
                    && dto.attempted <= dto.planned
                    && dto.achieved_messages_per_second.is_finite()
                    && dto.achieved_body_bytes_per_second.is_finite()
                    && !dto.delivery_acknowledged
                    && matches!(
                        dto.completion_reason.as_str(),
                        "deadline" | "interrupted" | "send_failed" | "daemon_stopped"
                    ),
                "invalid benchmark summary"
            );
            anyhow::ensure!(
                dto.first_error
                    .as_deref()
                    .is_none_or(|text| text.len() <= contracts::MAX_PUBLIC_MESSAGE_BYTES),
                "invalid benchmark error"
            );
            let _ = (
                dto.schema_version,
                dto.schedule_missed,
                dto.queued_body_bytes,
                dto.queued_envelope_bytes,
                dto.elapsed_ms,
            );
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
                dto.expected,
                dto.unique,
                dto.missing,
                dto.highest_sequence,
                &dto.latency,
                &dto.lag,
                (
                    dto.achieved_messages_per_second,
                    dto.achieved_body_bytes_per_second,
                ),
            )?;
            anyhow::ensure!(
                dto.family == family && dto.out_of_order <= dto.unique,
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
                dto.expected,
                dto.unique,
                dto.missing,
                dto.highest_sequence,
                &dto.latency,
                &dto.lag,
                (
                    dto.achieved_messages_per_second,
                    dto.achieved_body_bytes_per_second,
                ),
            )?;
            anyhow::ensure!(
                dto.family == family
                    && matches!(
                        dto.completion_reason.as_str(),
                        "deadline" | "interrupted" | "daemon_stopped"
                    )
                    && dto.complete == dto.expected.is_some_and(|count| count == dto.unique)
                    && (!dto.measurement_valid
                        || (dto.complete && !dto.lag.incomplete && dto.malformed_messages == 0))
                    && dto.missing_sequence_sample.len() <= 128
                    && dto.out_of_order <= dto.unique,
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
                && !self.body.is_empty()
                && self.body.len() <= 4096
                && !self.delivery_acknowledged,
            "invalid queued response values"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OfferItemV1 {
    direction: String,
    offer_id: String,
    #[serde(default)]
    provider: Option<String>,
    name: String,
    kind: String,
    hash: String,
    format: String,
    status: String,
    #[serde(default)]
    size: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OffersV1 {
    #[serde(rename = "type")]
    kind: String,
    schema_version: u8,
    request_id: String,
    blobs: Vec<OfferItemV1>,
    truncated: bool,
    has_more: bool,
    item_errors: usize,
}

impl OffersV1 {
    fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            self.kind == "offers" && self.schema_version == 1,
            "invalid offers response version"
        );
        anyhow::ensure!(
            contracts::valid_request_id(&self.request_id),
            "invalid offers request ID"
        );
        anyhow::ensure!(
            self.blobs.len() <= 1024 && self.truncated == self.has_more,
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
        anyhow::ensure!(self.item_errors <= 1024, "invalid offer item error count");
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
    Peers,
    Offers,
    OffersRemove {
        offer_id: String,
        direction: Option<String>,
        provider: Option<String>,
    },
    OffersPrune {
        older_than_secs: Option<u64>,
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
        offer: String,
        output: PathBuf,
    },
    /// Export the verified offered blob without interpreting it. Used by the
    /// local web bridge with a server-selected temporary output path.
    WebDownload {
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

fn decode_response(frame: &[u8], expected_request_id: &str) -> Result<serde_json::Value> {
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
    validate_success_payload(&value)?;
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
    decode_response(&frame, request_id)
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

pub(crate) fn daemon_error_message(value: &serde_json::Value) -> String {
    diagnostic_string(value.get("message"), "unknown error")
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
}

impl<S: AsyncRead + Unpin> SubscriptionReader<S> {
    #[cfg(test)]
    pub(crate) fn new(stream: S) -> Self {
        Self {
            reader: BufReader::new(stream),
            frame: Vec::new(),
            request_id: None,
        }
    }

    pub(crate) fn new_correlated(stream: S, request_id: String) -> Self {
        Self {
            reader: BufReader::new(stream),
            frame: Vec::new(),
            request_id: Some(request_id),
        }
    }

    pub(crate) fn get_mut(&mut self) -> &mut S {
        self.reader.get_mut()
    }

    /// Reads one event while retaining any bytes consumed if this future is
    /// cancelled by a competing `select!` branch.
    pub(crate) async fn read(&mut self) -> Result<Option<serde_json::Value>> {
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
        let value = match &self.request_id {
            Some(request_id) => {
                decode_response(&self.frame, request_id).context("invalid daemon event")
            }
            None => serde_json::from_slice(&self.frame).context("invalid daemon event"),
        }?;
        self.frame.clear();
        Ok(Some(value))
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
    write_request_with_id(&mut stream, &IpcRequest::Subscribe, request_id).await?;
    Ok(SubscriptionReader::new_correlated(
        stream,
        request_id.to_owned(),
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
        error.offer_id = Some("0123456789abcdef0123456789abcdef".into());
        let value = error.clone().into_value();
        assert_eq!(LifecycleErrorV1::from_value(&value).unwrap(), error);
        for malformed in [
            serde_json::json!({"type":"error","schema_version":2,"code":"attachment_storage_busy","message":"busy","outcome":"not_started","retryable":true}),
            serde_json::json!({"type":"error","schema_version":1,"code":"attachment_storage_busy","message":"busy","outcome":"started","retryable":true}),
            serde_json::json!({"type":"error","schema_version":1,"code":"attachment_storage_busy","message":"busy","outcome":"not_started","retryable":true,"extra":1}),
        ] {
            assert!(LifecycleErrorV1::from_value(&malformed).is_err());
        }
    }

    #[tokio::test]
    async fn attachment_lifecycle_requests_are_strict_and_versioned_by_response_contract() {
        let mut bytes = Vec::new();
        write_request(
            &mut bytes,
            &IpcRequest::OffersRemove {
                offer_id: "0123456789abcdef0123456789abcdef".into(),
                direction: Some("outgoing".into()),
                provider: None,
            },
        )
        .await
        .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["request"]["command"], "offers_remove");
        assert!(serde_json::from_slice::<IpcRequest>(
            br#"{"command":"offers_prune","older_than_secs":0,"direction":null,"dry_run":true,"max_delete":1,"extra":false}"#
        ).is_err());
        validate_response(
            &serde_json::json!({"type":"offers_pruned","schema_version":1}),
            "offers_pruned",
            Some(1),
        )
        .unwrap();
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
        let status = StatusV1 {
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
        let value = serde_json::to_value(status).unwrap();
        validate_success_payload(&value).unwrap();
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
        let peer = "4".repeat(64);
        let base_send_progress = serde_json::json!({
            "type":"bench_send_progress", "schema_version":1, "request_id":request_id,
            "run_id":operation_id, "rate":10, "duration_secs":1, "payload_bytes":128,
            "planned":10, "attempted":2, "queued":2, "failed":0,
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
        let fixtures = vec![
            serde_json::json!({"type":"connected","schema_version":1,"request_id":request_id,"peer":peer,"endpoint_online":true,"topic_joined":true,"alias":"node","ipc_capabilities":["typed_contracts_v1"]}),
            serde_json::json!({"type":"message","schema_version":2,"request_id":request_id,"from":peer,"message_id":operation_id,"timestamp_ms":1,"body":"hello"}),
            serde_json::json!({"type":"private_message","schema_version":1,"request_id":request_id,"private":true,"from":peer,"message_id":operation_id,"timestamp_ms":1,"body":"secret","acceptance_acknowledged":true,"durable":false,"read":false}),
            serde_json::json!({"type":"queued","schema_version":3,"request_id":request_id,"operation_id":operation_id,"from":peer,"message_id":operation_id,"timestamp_ms":1,"body":"hello","delivery_acknowledged":false}),
            serde_json::json!({"type":"private_accepted","schema_version":3,"request_id":request_id,"operation_id":operation_id,"to":peer,"message_id":operation_id,"timestamp_ms":1,"body_bytes":6,"acceptance_acknowledged":true,"duplicate_accepted":false,"durable":false,"read":false}),
            serde_json::json!({"type":"attachment_offer","schema_version":2,"request_id":request_id,"from":peer,"message_id":operation_id,"timestamp_ms":1,"offer_id":operation_id,"kind":"file","name":"safe.txt","size":4,"ticket":"ticket","offer":"offer"}),
            serde_json::json!({"type":"attachment_shared","schema_version":3,"request_id":request_id,"operation_id":operation_id,"from":peer,"message_id":operation_id,"timestamp_ms":1,"offer_id":operation_id,"source_digest":digest,"kind":"file","name":"safe.txt","size":4,"ticket":"ticket","offer":"offer","delivery_acknowledged":false}),
            serde_json::json!({"type":"offers","schema_version":1,"request_id":request_id,"blobs":[{"direction":"outgoing","offer_id":operation_id,"name":"safe.txt","kind":"file","hash":digest,"format":"raw","status":"complete","size":4}],"truncated":false,"has_more":false,"item_errors":0}),
            serde_json::json!({"type":"offer_removed","schema_version":1,"request_id":request_id,"dry_run":false,"selected_tags":1,"removed_tags":1,"released_bytes":4,"limited":false,"cutoff_ms":null}),
            serde_json::json!({"type":"offers_pruned","schema_version":1,"request_id":request_id,"dry_run":true,"selected_tags":1,"removed_tags":0,"released_bytes":4,"limited":false,"cutoff_ms":1}),
            serde_json::json!({"type":"download_started","schema_version":1,"request_id":request_id,"output":"/tmp/file"}),
            serde_json::json!({"type":"download_progress","schema_version":1,"request_id":request_id,"received_bytes":2,"total_bytes":4,"output":"/tmp/file"}),
            serde_json::json!({"type":"download_complete","schema_version":1,"request_id":request_id,"offer_id":operation_id,"kind":"file","name":"safe.txt","size":4,"from":peer,"output":"/tmp/file","installed":true,"pinned":true,"destination_synced":true,"cleanup_complete":true,"warnings":[]}),
            serde_json::json!({"type":"stopping","schema_version":1,"request_id":request_id,"outcome":"accepted"}),
            serde_json::json!({"type":"peer_up","schema_version":1,"request_id":request_id,"peer":peer}),
            serde_json::json!({"type":"peer_down","schema_version":1,"request_id":request_id,"peer":peer}),
            serde_json::json!({"type":"lagged","schema_version":1,"request_id":request_id,"source":"local","dropped":2,"message":"listener missed events"}),
            serde_json::json!({"type":"bench_send_started","schema_version":1,"request_id":request_id,"run_id":operation_id,"rate":10,"duration_secs":1,"payload_bytes":128,"planned":10,"delivery_acknowledged":false}),
            base_send_progress.clone(),
            {
                let mut value = base_send_progress.clone();
                value["type"] = "bench_send_summary".into();
                value["completion_reason"] = "deadline".into();
                value["first_error"] = serde_json::Value::Null;
                value
            },
            serde_json::json!({"type":"bench_receive_started","schema_version":1,"request_id":request_id,"run_id":operation_id,"duration_secs":1,"expected":10}),
            serde_json::json!({"type":"bench_receive_progress","schema_version":1,"request_id":request_id,"run_id":operation_id,"elapsed_ms":1,"expected":10,"unique":1,"missing":9,"duplicates":0,"out_of_order":0,"highest_sequence":0,"body_bytes":128,"achieved_messages_per_second":1.0,"achieved_body_bytes_per_second":128.0,"latency":latency,"lag":lag,"malformed_messages":0}),
            serde_json::json!({"type":"bench_receive_summary","schema_version":1,"request_id":request_id,"run_id":operation_id,"completion_reason":"deadline","elapsed_ms":1,"expected":1,"complete":true,"measurement_valid":true,"unique":1,"missing":0,"missing_sequence_sample":[],"duplicates":0,"out_of_order":0,"highest_sequence":0,"body_bytes":128,"achieved_messages_per_second":1.0,"achieved_body_bytes_per_second":128.0,"latency":latency,"lag":lag,"peer_up":0,"peer_down":0,"ignored_messages":0,"malformed_messages":0}),
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
            IpcRequest::Send { body, .. } if body == "broadcast"
        ));
    }
}
