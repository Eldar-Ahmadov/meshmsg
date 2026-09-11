//! Stable, versioned contracts shared by CLI JSON, local IPC, HTTP, and SSE.
//!
//! IDs are deliberately distinct: a request ID correlates one transport request,
//! while an operation ID identifies a retry-safe mutation across requests.
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    mpsc::{sync_channel, SyncSender, TrySendError},
    Mutex, OnceLock, TryLockError,
};

pub(crate) const SCHEMA_VERSION: u8 = 1;
pub(crate) const API_CONTRACT_CAPABILITY: &str = "typed_contracts_v1";
pub(crate) const MAX_PUBLIC_MESSAGE_BYTES: usize = 1024;
pub(crate) const BENCHMARK_SEND_FAILED_MESSAGE: &str = "Message submission failed.";

pub(crate) fn new_request_id() -> String {
    data_encoding::HEXLOWER.encode(&rand::random::<[u8; 16]>())
}

/// Canonical lexical form shared by request, operation, wire-message, and
/// attachment-offer IDs: exactly 128 bits encoded as lowercase hexadecimal.
pub(crate) fn valid_operation_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn valid_request_id(value: &str) -> bool {
    valid_operation_id(value)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ErrorOperationKind {
    General,
    Send,
    PrivateSend,
    Share,
    Offers,
    Remove,
    Prune,
    Download,
    WebDownload,
    Benchmark,
    Feed,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ErrorCodeSpec {
    pub(crate) message: &'static str,
    /// Admitted `(outcome, retryable)` pairs. Keeping the pair together prevents
    /// validators from accidentally accepting a valid outcome with the wrong retry policy.
    pub(crate) semantics: &'static [(&'static str, bool)],
    pub(crate) operations: &'static [ErrorOperationKind],
    pub(crate) request_id: FieldRule,
    pub(crate) operation_id: FieldRule,
    pub(crate) offer_id: FieldRule,
    pub(crate) removal_counts: FieldRule,
    pub(crate) suppression_count: FieldRule,
    pub(crate) lifecycle_context: FieldRule,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FieldRule {
    Forbidden,
    Optional,
    Required,
}

const ALL_OPERATIONS: &[ErrorOperationKind] = &[
    ErrorOperationKind::General,
    ErrorOperationKind::Send,
    ErrorOperationKind::PrivateSend,
    ErrorOperationKind::Share,
    ErrorOperationKind::Offers,
    ErrorOperationKind::Remove,
    ErrorOperationKind::Prune,
    ErrorOperationKind::Download,
    ErrorOperationKind::WebDownload,
    ErrorOperationKind::Benchmark,
    ErrorOperationKind::Feed,
];
const MUTATIONS: &[ErrorOperationKind] = &[
    ErrorOperationKind::Send,
    ErrorOperationKind::PrivateSend,
    ErrorOperationKind::Share,
    ErrorOperationKind::Remove,
    ErrorOperationKind::Prune,
    ErrorOperationKind::Download,
    ErrorOperationKind::WebDownload,
];
const ATTACHMENT_MUTATIONS: &[ErrorOperationKind] = &[
    ErrorOperationKind::Share,
    ErrorOperationKind::Remove,
    ErrorOperationKind::Prune,
    ErrorOperationKind::Download,
    ErrorOperationKind::WebDownload,
];
const REMOVE_PRUNE: &[ErrorOperationKind] =
    &[ErrorOperationKind::Remove, ErrorOperationKind::Prune];
const DOWNLOADS: &[ErrorOperationKind] = &[
    ErrorOperationKind::Download,
    ErrorOperationKind::WebDownload,
];
const NS_FALSE: &[(&str, bool)] = &[("not_started", false)];
const NS_TRUE: &[(&str, bool)] = &[("not_started", true)];
const UNKNOWN_TRUE: &[(&str, bool)] = &[("unknown", true)];
const PARTIAL_OR_UNKNOWN_TRUE: &[(&str, bool)] = &[("partial", true), ("unknown", true)];
const NS_OR_UNKNOWN_TRUE: &[(&str, bool)] = &[("not_started", true), ("unknown", true)];
const TIMEOUT_TRUE: &[(&str, bool)] =
    &[("not_started", true), ("unknown", true), ("partial", true)];

macro_rules! error_spec {
    ($code:expr, $sem:expr, $ops:expr) => {{
        ErrorCodeSpec {
            message: stable_message($code),
            semantics: $sem,
            operations: $ops,
            request_id: FieldRule::Optional,
            operation_id: FieldRule::Optional,
            offer_id: FieldRule::Forbidden,
            removal_counts: FieldRule::Forbidden,
            suppression_count: FieldRule::Forbidden,
            lifecycle_context: FieldRule::Forbidden,
        }
    }};
}

pub(crate) fn error_code_spec(code: &str) -> Option<ErrorCodeSpec> {
    let mut spec = match code {
        "daemon_offline" => error_spec!(code, NS_OR_UNKNOWN_TRUE, ALL_OPERATIONS),
        "daemon_disconnected" => error_spec!(code, PARTIAL_OR_UNKNOWN_TRUE, ALL_OPERATIONS),
        "daemon_unavailable" | "capacity_or_offline" => error_spec!(code, NS_TRUE, ALL_OPERATIONS),
        "daemon_stopping" => error_spec!(
            code,
            &[("not_started", true), ("unknown", true)],
            ALL_OPERATIONS
        ),
        "command_timeout" => error_spec!(code, TIMEOUT_TRUE, ALL_OPERATIONS),
        "attachment_command_timeout" | "attachment_storage_shutdown" => {
            error_spec!(code, UNKNOWN_TRUE, ATTACHMENT_MUTATIONS)
        }
        "ipc_capacity" => error_spec!(code, NS_TRUE, ALL_OPERATIONS),
        "operation_capacity" => error_spec!(code, NS_TRUE, MUTATIONS),
        "attachment_storage_busy" => error_spec!(code, NS_TRUE, ATTACHMENT_MUTATIONS),
        "operation_id_conflict" => error_spec!(code, NS_FALSE, MUTATIONS),
        "invalid_operation_id" => error_spec!(code, NS_FALSE, MUTATIONS),
        "invalid_source_digest" => error_spec!(code, NS_FALSE, &[ErrorOperationKind::Share]),
        "invalid_attachment_offer" => error_spec!(
            code,
            NS_FALSE,
            &[
                ErrorOperationKind::General,
                ErrorOperationKind::Feed,
                ErrorOperationKind::Download,
                ErrorOperationKind::WebDownload
            ]
        ),
        "invalid_offer_selector" => error_spec!(code, NS_FALSE, &[ErrorOperationKind::Remove]),
        "invalid_prune_request" => error_spec!(code, NS_FALSE, &[ErrorOperationKind::Prune]),
        "share_failed" => error_spec!(code, UNKNOWN_TRUE, &[ErrorOperationKind::Share]),
        "download_failed" => error_spec!(code, NS_OR_UNKNOWN_TRUE, DOWNLOADS),
        "offers_failed" => error_spec!(code, UNKNOWN_TRUE, &[ErrorOperationKind::Offers]),
        "offers_busy" => error_spec!(code, NS_TRUE, &[ErrorOperationKind::Offers]),
        "attachment_lifecycle_internal" => error_spec!(code, UNKNOWN_TRUE, REMOVE_PRUNE),
        "send_failed" => error_spec!(
            code,
            &[("unknown", true), ("partial", false)],
            &[ErrorOperationKind::Send, ErrorOperationKind::Benchmark]
        ),
        "private_send_failed" => {
            error_spec!(code, UNKNOWN_TRUE, &[ErrorOperationKind::PrivateSend])
        }
        "recipient_unresolved" | "private_message_conflict" => {
            error_spec!(code, NS_FALSE, &[ErrorOperationKind::PrivateSend])
        }
        "invalid_request" | "unsupported_schema" => error_spec!(code, NS_FALSE, ALL_OPERATIONS),
        "invalid_message" => error_spec!(
            code,
            NS_FALSE,
            &[ErrorOperationKind::Send, ErrorOperationKind::Feed]
        ),
        "invalid_benchmark" => error_spec!(code, NS_FALSE, &[ErrorOperationKind::Benchmark]),
        "initial_frame_timeout" => error_spec!(code, NS_TRUE, ALL_OPERATIONS),
        "private_send_busy" | "private_recipient_busy" => {
            error_spec!(code, NS_TRUE, &[ErrorOperationKind::PrivateSend])
        }
        "benchmark_busy" => error_spec!(code, NS_TRUE, &[ErrorOperationKind::Benchmark]),
        "private_replay_unavailable" => {
            error_spec!(code, NS_TRUE, &[ErrorOperationKind::PrivateSend])
        }
        "private_delivery_unknown" => {
            error_spec!(
                code,
                &[("unknown", false)],
                &[ErrorOperationKind::PrivateSend]
            )
        }
        "attachment_quota_exceeded" | "attachment_tag_capacity" => error_spec!(
            code,
            NS_FALSE,
            &[
                ErrorOperationKind::Share,
                ErrorOperationKind::Download,
                ErrorOperationKind::WebDownload
            ]
        ),
        "attachment_min_free_space" => error_spec!(
            code,
            NS_TRUE,
            &[
                ErrorOperationKind::Share,
                ErrorOperationKind::Download,
                ErrorOperationKind::WebDownload
            ]
        ),
        "attachment_removal_partial" => error_spec!(code, PARTIAL_OR_UNKNOWN_TRUE, REMOVE_PRUNE),
        "share_operation_capacity" => error_spec!(code, NS_TRUE, &[ErrorOperationKind::Share]),
        "download_operation_capacity" | "download_staging_unavailable" => {
            error_spec!(code, NS_TRUE, DOWNLOADS)
        }
        "invalid_daemon_response" => error_spec!(
            code,
            &[("unknown", true), ("partial", false)],
            ALL_OPERATIONS
        ),
        "request_rejected" | "command_failed" => error_spec!(code, NS_FALSE, ALL_OPERATIONS),
        "feed_error" => error_spec!(code, UNKNOWN_TRUE, &[ErrorOperationKind::Feed]),
        "startup_failed" => error_spec!(code, NS_TRUE, &[ErrorOperationKind::General]),
        "internal_contract_error" => error_spec!(
            code,
            &[("unknown", false)],
            &[ErrorOperationKind::General, ErrorOperationKind::Feed]
        ),
        "request_forbidden"
        | "not_found"
        | "payload_too_large"
        | "unsupported_media_type"
        | "invalid_range"
        | "idempotency_unsupported" => error_spec!(code, NS_FALSE, ALL_OPERATIONS),
        "request_throttled" => error_spec!(code, NS_TRUE, ALL_OPERATIONS),
        "send_throttled" => error_spec!(code, NS_TRUE, &[ErrorOperationKind::Send]),
        "request_timeout" => error_spec!(code, NS_OR_UNKNOWN_TRUE, ALL_OPERATIONS),
        "request_failed" => error_spec!(
            code,
            &[("not_started", false), ("unknown", true)],
            ALL_OPERATIONS
        ),
        "send_outcome_unknown" => error_spec!(code, UNKNOWN_TRUE, &[ErrorOperationKind::Send]),
        "share_outcome_unknown" => error_spec!(code, UNKNOWN_TRUE, &[ErrorOperationKind::Share]),
        _ => return None,
    };
    if code == "invalid_offer_selector" || code == "attachment_removal_partial" {
        spec.offer_id = FieldRule::Optional;
    }
    if code == "attachment_removal_partial" {
        spec.removal_counts = FieldRule::Required;
        spec.lifecycle_context = FieldRule::Required;
    }
    if code == "internal_contract_error" {
        spec.suppression_count = FieldRule::Optional;
    }
    Some(spec)
}

pub(crate) fn known_error_code(code: &str) -> bool {
    error_code_spec(code).is_some()
}

fn stable_message(code: &str) -> &'static str {
    match code {
        "daemon_offline" => "Daemon is offline.",
        "command_timeout" | "attachment_command_timeout" => {
            "The request timed out; reconcile before retrying."
        }
        "daemon_stopping" | "attachment_storage_shutdown" => {
            "The daemon is shutting down or unavailable."
        }
        "ipc_capacity" | "operation_capacity" | "attachment_storage_busy" => {
            "Local capacity is currently unavailable."
        }
        "operation_id_conflict" => "The operation ID is bound to different input.",
        "invalid_operation_id" => "The operation ID is invalid.",
        "invalid_source_digest" => "The source digest is invalid.",
        "share_failed" => "Attachment sharing failed.",
        "download_failed" => "Attachment download failed.",
        "send_failed" | "private_send_failed" => "Message submission failed.",
        "recipient_unresolved" => "The recipient could not be resolved.",
        "invalid_request" | "unsupported_schema" => {
            "The request contract is invalid or unsupported."
        }
        "initial_frame_timeout" => "The initial local request timed out.",
        "invalid_message" => "The message is invalid.",
        "private_send_busy" | "private_recipient_busy" | "benchmark_busy" => {
            "The requested operation is currently busy."
        }
        "private_message_conflict" => "The message ID is bound to different content.",
        "private_replay_unavailable" => "Recipient replay protection is unavailable.",
        "invalid_benchmark" => "The benchmark configuration is invalid.",
        "attachment_quota_exceeded" => "The attachment storage quota is exceeded.",
        "attachment_min_free_space" => "The attachment free-space reserve is unavailable.",
        "attachment_tag_capacity" => "The attachment pin capacity is exhausted.",
        "attachment_removal_partial" => "Attachment removal completed only partially.",
        "share_operation_capacity" => "Attachment sharing capacity is unavailable.",
        "download_operation_capacity" => "Attachment download capacity is unavailable.",
        "download_staging_unavailable" => "Attachment download staging is unavailable.",
        "invalid_daemon_response" => "The daemon returned an invalid response.",
        "daemon_disconnected" => "The daemon disconnected; the event feed has a gap.",
        "request_rejected" => "The request was rejected.",
        "feed_error" => "The event feed failed.",
        "command_failed" => "The command failed.",
        "startup_failed" => "Daemon startup failed.",
        "internal_contract_error" => "An internal contract error occurred.",
        "request_forbidden" => "The request is forbidden.",
        "not_found" => "The requested resource was not found.",
        "request_throttled" | "send_throttled" => "The request was throttled.",
        "request_timeout" => "The HTTP request timed out.",
        "payload_too_large" => "The request payload is too large.",
        "unsupported_media_type" => "The request media type is unsupported.",
        "invalid_range" => "The requested byte range is invalid.",
        "capacity_or_offline" | "daemon_unavailable" => "The service is unavailable.",
        "request_failed" => "The request failed.",
        "idempotency_unsupported" => "Retry-safe mutations are unsupported by the daemon.",
        "send_outcome_unknown" => "The message outcome is unknown.",
        "share_outcome_unknown" => "The attachment sharing outcome is unknown.",
        "invalid_attachment_offer" | "invalid_offer_selector" | "invalid_prune_request" => {
            "The attachment request is invalid."
        }
        "offers_busy" => "Attachment listing is currently busy.",
        "offers_failed" | "attachment_lifecycle_internal" => {
            "The attachment lifecycle operation failed."
        }
        "private_delivery_unknown" => "The private-message outcome is unknown.",
        _ => "Request failed.",
    }
}

#[cfg(test)]
pub(crate) fn sanitize_message(message: &str) -> String {
    let mut result = String::with_capacity(message.len().min(MAX_PUBLIC_MESSAGE_BYTES));
    for character in message.chars() {
        if result.len() >= MAX_PUBLIC_MESSAGE_BYTES {
            break;
        }
        let replacement = if character.is_control() {
            '\u{fffd}'
        } else {
            character
        };
        if result.len() + replacement.len_utf8() > MAX_PUBLIC_MESSAGE_BYTES {
            break;
        }
        result.push(replacement);
    }
    if result.is_empty() {
        "Request failed.".to_owned()
    } else {
        result
    }
}

fn valid_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn validate_field_rule(rule: FieldRule, present: bool, name: &str) -> Result<()> {
    anyhow::ensure!(
        match rule {
            FieldRule::Forbidden => !present,
            FieldRule::Optional => true,
            FieldRule::Required => present,
        },
        "error {name} applicability is invalid"
    );
    Ok(())
}

const PRIVATE_DIAGNOSTIC_BYTES: usize = 2048;
const PRIVATE_DIAGNOSTIC_QUEUE: usize = 128;
static PRIVATE_DIAGNOSTIC_TX: OnceLock<SyncSender<String>> = OnceLock::new();
static PRIVATE_DIAGNOSTIC_DROPPED: AtomicU64 = AtomicU64::new(0);
static PRIVATE_DIAGNOSTIC_ACCEPTED: AtomicU64 = AtomicU64::new(0);
static PRIVATE_DIAGNOSTIC_OUTPUT: AtomicBool = AtomicBool::new(true);
static PRIVATE_DIAGNOSTIC_EVIDENCE: OnceLock<Mutex<std::collections::VecDeque<String>>> =
    OnceLock::new();

pub(crate) fn set_private_diagnostic_output(enabled: bool) {
    PRIVATE_DIAGNOSTIC_OUTPUT.store(enabled, Ordering::Relaxed);
    if enabled {
        let _ = PRIVATE_DIAGNOSTIC_TX.get_or_init(|| {
            let (tx, rx) = sync_channel::<String>(PRIVATE_DIAGNOSTIC_QUEUE);
            std::thread::Builder::new()
                .name("meshmsg-diagnostics".into())
                .spawn(move || {
                    while let Ok(record) = rx.recv() {
                        eprintln!("{record}");
                    }
                })
                .expect("spawn bounded diagnostic worker during startup");
            tx
        });
    }
}

pub(crate) fn diagnostic_metrics() -> (u64, u64, usize) {
    let retained = PRIVATE_DIAGNOSTIC_EVIDENCE
        .get()
        .and_then(|records| records.try_lock().ok())
        .map_or(0, |records| records.len());
    (
        PRIVATE_DIAGNOSTIC_ACCEPTED.load(Ordering::Relaxed),
        PRIVATE_DIAGNOSTIC_DROPPED.load(Ordering::Relaxed),
        retained,
    )
}

/// Retain the private cause before constructing fixed public output. Admission is
/// bounded and nonblocking; a dedicated worker owns the potentially blocking sink.
pub(crate) fn log_private_diagnostic(context: &str, code: &str, diagnostic: &str) {
    let diagnostic = sanitize_message_to(diagnostic, PRIVATE_DIAGNOSTIC_BYTES);
    if diagnostic.is_empty() {
        return;
    }
    let record = format!("meshmsg {context} diagnostic [{code}]: {diagnostic}");
    let evidence = PRIVATE_DIAGNOSTIC_EVIDENCE.get_or_init(Default::default);
    match evidence.try_lock() {
        Ok(mut evidence) => {
            if evidence.len() == 256 {
                evidence.pop_front();
            }
            evidence.push_back(record.clone());
            PRIVATE_DIAGNOSTIC_ACCEPTED.fetch_add(1, Ordering::Relaxed);
        }
        Err(TryLockError::Poisoned(poisoned)) => {
            let mut records = poisoned.into_inner();
            if records.len() == 256 {
                records.pop_front();
            }
            records.push_back(record.clone());
            drop(records);
            evidence.clear_poison();
            PRIVATE_DIAGNOSTIC_ACCEPTED.fetch_add(1, Ordering::Relaxed);
        }
        Err(TryLockError::WouldBlock) => {
            PRIVATE_DIAGNOSTIC_DROPPED.fetch_add(1, Ordering::Relaxed);
        }
    }
    if !PRIVATE_DIAGNOSTIC_OUTPUT.load(Ordering::Relaxed) {
        return;
    }
    let Some(tx) = PRIVATE_DIAGNOSTIC_TX.get() else {
        PRIVATE_DIAGNOSTIC_DROPPED.fetch_add(1, Ordering::Relaxed);
        return;
    };
    if let Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) = tx.try_send(record) {
        PRIVATE_DIAGNOSTIC_DROPPED.fetch_add(1, Ordering::Relaxed);
    }
}

fn sanitize_message_to(message: &str, maximum: usize) -> String {
    let mut result = String::with_capacity(message.len().min(maximum));
    for character in message.chars() {
        let replacement = if character.is_control() {
            '\u{fffd}'
        } else {
            character
        };
        if result.len() + replacement.len_utf8() > maximum {
            break;
        }
        result.push(replacement);
    }
    result
}

#[cfg(test)]
pub(crate) fn private_diagnostic_evidence_contains(needle: &str) -> bool {
    PRIVATE_DIAGNOSTIC_EVIDENCE
        .get_or_init(Default::default)
        .lock()
        .is_ok_and(|records| records.iter().any(|record| record.contains(needle)))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ErrorEnvelopeV1 {
    #[serde(rename = "type")]
    pub(crate) kind: String,
    pub(crate) schema_version: u8,
    pub(crate) code: String,
    pub(crate) message: String,
    pub(crate) retryable: bool,
    pub(crate) outcome: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) operation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) offer_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) selected_tags: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) removed_tags: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) quota_bytes_released: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) suppressed_since_last: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) direction: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) older_than_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) maximum: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) dry_run: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) cutoff_ms: Option<u64>,
}

#[derive(Debug)]
pub(crate) struct ContractFailure(pub(crate) ErrorEnvelopeV1);

impl std::fmt::Display for ContractFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "request failed [{}; {}]",
            self.0.code, self.0.outcome
        )
    }
}

impl std::error::Error for ContractFailure {}

impl ErrorEnvelopeV1 {
    pub(crate) fn try_new(
        code: impl Into<String>,
        diagnostic: impl AsRef<str>,
        outcome: impl Into<String>,
        retryable: bool,
    ) -> Result<Self> {
        let code = code.into();
        let diagnostic = diagnostic.as_ref();
        log_private_diagnostic("error_envelope", &code, diagnostic);
        let spec =
            error_code_spec(&code).context("error envelope producer used an unknown code")?;
        let outcome = outcome.into();
        anyhow::ensure!(
            spec.semantics.contains(&(outcome.as_str(), retryable)),
            "error envelope producer used noncanonical outcome/retryability"
        );
        let message = spec.message.to_owned();
        Ok(Self {
            kind: "error".into(),
            schema_version: SCHEMA_VERSION,
            code,
            message,
            retryable,
            outcome,
            request_id: None,
            operation_id: None,
            offer_id: None,
            selected_tags: None,
            removed_tags: None,
            quota_bytes_released: None,
            suppressed_since_last: None,
            direction: None,
            provider: None,
            older_than_secs: None,
            maximum: None,
            dry_run: None,
            cutoff_ms: None,
        })
    }

    /// Infallible boundary for existing producers: invalid producer semantics
    /// become an explicit internal contract failure, never a different form of
    /// the requested public code.
    pub(crate) fn new(
        code: impl Into<String>,
        diagnostic: impl AsRef<str>,
        outcome: impl Into<String>,
        retryable: bool,
    ) -> Self {
        let code = code.into();
        let outcome = outcome.into();
        Self::try_new(&code, diagnostic.as_ref(), &outcome, retryable).unwrap_or_else(|failure| {
            log_private_diagnostic("invalid_error_producer", &code, &failure.to_string());
            Self {
                kind: "error".into(),
                schema_version: SCHEMA_VERSION,
                code: "internal_contract_error".into(),
                message: stable_message("internal_contract_error").into(),
                retryable: false,
                outcome: "unknown".into(),
                request_id: None,
                operation_id: None,
                offer_id: None,
                selected_tags: None,
                removed_tags: None,
                quota_bytes_released: None,
                suppressed_since_last: None,
                direction: None,
                provider: None,
                older_than_secs: None,
                maximum: None,
                dry_run: None,
                cutoff_ms: None,
            }
        })
    }

    pub(crate) fn validate(&self) -> Result<()> {
        anyhow::ensure!(self.kind == "error", "error type is invalid");
        anyhow::ensure!(
            self.schema_version == SCHEMA_VERSION,
            "unsupported error schema version"
        );
        let spec = error_code_spec(&self.code)
            .filter(|_| valid_token(&self.code))
            .context("error code is invalid or unknown")?;
        anyhow::ensure!(
            self.message == spec.message,
            "error message is not the fixed public text for its code"
        );
        anyhow::ensure!(
            spec.semantics
                .contains(&(self.outcome.as_str(), self.retryable)),
            "error outcome/retryability is not canonical for its code"
        );
        anyhow::ensure!(
            !self.message.is_empty()
                && self.message.len() <= MAX_PUBLIC_MESSAGE_BYTES
                && !self.message.chars().any(char::is_control),
            "error message is invalid"
        );
        anyhow::ensure!(
            matches!(self.outcome.as_str(), "not_started" | "unknown" | "partial"),
            "error outcome is invalid"
        );
        if let Some(id) = &self.request_id {
            anyhow::ensure!(valid_request_id(id), "error request ID is invalid");
        }
        if let Some(id) = &self.operation_id {
            anyhow::ensure!(
                crate::ipc::valid_operation_id(id),
                "error operation ID is invalid"
            );
        }
        if let Some(id) = &self.offer_id {
            anyhow::ensure!(
                crate::ipc::valid_operation_id(id),
                "error offer ID is invalid"
            );
        }
        anyhow::ensure!(
            matches!(
                (
                    self.selected_tags,
                    self.removed_tags,
                    self.quota_bytes_released,
                ),
                (None, None, None) | (Some(_), Some(_), Some(_))
            ) && self.removed_tags.unwrap_or(0) <= self.selected_tags.unwrap_or(0),
            "error removal counts are invalid"
        );
        validate_field_rule(spec.request_id, self.request_id.is_some(), "request ID")?;
        validate_field_rule(
            spec.operation_id,
            self.operation_id.is_some(),
            "operation ID",
        )?;
        validate_field_rule(spec.offer_id, self.offer_id.is_some(), "offer ID")?;
        validate_field_rule(
            spec.removal_counts,
            self.selected_tags.is_some(),
            "removal counts",
        )?;
        validate_field_rule(
            spec.suppression_count,
            self.suppressed_since_last.is_some(),
            "suppression accounting",
        )?;
        let lifecycle_fields = [self.maximum.is_some(), self.dry_run.is_some()];
        anyhow::ensure!(
            lifecycle_fields[0] == lifecycle_fields[1],
            "error lifecycle context is incomplete"
        );
        anyhow::ensure!(
            lifecycle_fields[0]
                || (self.direction.is_none()
                    && self.provider.is_none()
                    && self.older_than_secs.is_none()
                    && self.cutoff_ms.is_none()),
            "error included inapplicable lifecycle selectors"
        );
        validate_field_rule(
            spec.lifecycle_context,
            lifecycle_fields[0],
            "lifecycle context",
        )?;
        anyhow::ensure!(
            self.direction
                .as_deref()
                .is_none_or(|value| matches!(value, "incoming" | "outgoing")),
            "error lifecycle direction is invalid"
        );
        anyhow::ensure!(
            self.provider
                .as_deref()
                .is_none_or(|value| value.len() == 64
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))),
            "error lifecycle provider is invalid"
        );
        Ok(())
    }

    pub(crate) fn validate_for_operation(
        &self,
        operation: ErrorOperationKind,
        expected_operation_id: Option<&str>,
    ) -> Result<()> {
        self.validate()?;
        let spec = error_code_spec(&self.code).expect("validated code has a specification");
        anyhow::ensure!(
            spec.operations.contains(&operation),
            "error code is not applicable to this operation kind"
        );
        let operation_required = !matches!(
            operation,
            ErrorOperationKind::General
                | ErrorOperationKind::Offers
                | ErrorOperationKind::Feed
                | ErrorOperationKind::Benchmark
        );
        anyhow::ensure!(
            operation_required == expected_operation_id.is_some(),
            "strict consumer omitted its expected operation identity"
        );
        anyhow::ensure!(
            self.operation_id.as_deref() == expected_operation_id,
            "error operation ID is missing, mismatched, or inapplicable"
        );
        Ok(())
    }

    pub(crate) fn from_value(value: &serde_json::Value) -> Result<Self> {
        let error: Self = serde_json::from_value(value.clone())
            .context("peer returned a malformed error envelope")?;
        error.validate()?;
        Ok(error)
    }

    pub(crate) fn into_value(self) -> serde_json::Value {
        serde_json::to_value(self).expect("error envelope serialization cannot fail")
    }
}

/// Add the mandatory common response metadata. Existing family versions are
/// retained; previously unversioned families become version 1.
pub(crate) fn correlate(mut value: serde_json::Value, request_id: &str) -> serde_json::Value {
    let Some(object) = value.as_object_mut() else {
        let mut error = ErrorEnvelopeV1::new(
            "internal_contract_error",
            "Internal response contract failure.",
            "unknown",
            false,
        );
        error.request_id = Some(request_id.to_owned());
        return error.into_value();
    };
    object
        .entry("schema_version")
        .or_insert_with(|| SCHEMA_VERSION.into());
    object.insert("request_id".into(), request_id.into());
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    const ERROR_CODES: &[&str] = &[
        "daemon_offline",
        "daemon_disconnected",
        "daemon_unavailable",
        "daemon_stopping",
        "command_timeout",
        "attachment_command_timeout",
        "attachment_storage_shutdown",
        "ipc_capacity",
        "operation_capacity",
        "attachment_storage_busy",
        "operation_id_conflict",
        "invalid_operation_id",
        "invalid_source_digest",
        "invalid_attachment_offer",
        "invalid_offer_selector",
        "invalid_prune_request",
        "share_failed",
        "download_failed",
        "offers_failed",
        "offers_busy",
        "attachment_lifecycle_internal",
        "send_failed",
        "private_send_failed",
        "recipient_unresolved",
        "invalid_request",
        "unsupported_schema",
        "initial_frame_timeout",
        "invalid_message",
        "private_send_busy",
        "private_recipient_busy",
        "benchmark_busy",
        "private_message_conflict",
        "private_replay_unavailable",
        "private_delivery_unknown",
        "invalid_benchmark",
        "attachment_quota_exceeded",
        "attachment_min_free_space",
        "attachment_tag_capacity",
        "attachment_removal_partial",
        "share_operation_capacity",
        "download_operation_capacity",
        "download_staging_unavailable",
        "invalid_daemon_response",
        "request_rejected",
        "feed_error",
        "command_failed",
        "startup_failed",
        "internal_contract_error",
        "request_forbidden",
        "not_found",
        "request_throttled",
        "request_timeout",
        "payload_too_large",
        "unsupported_media_type",
        "invalid_range",
        "capacity_or_offline",
        "request_failed",
        "idempotency_unsupported",
        "send_throttled",
        "send_outcome_unknown",
        "share_outcome_unknown",
    ];

    #[test]
    fn diagnostic_admission_is_nonblocking_counted_and_poison_safe() {
        let evidence = PRIVATE_DIAGNOSTIC_EVIDENCE.get_or_init(Default::default);
        let guard = evidence
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let dropped_before = diagnostic_metrics().1;
        let writer = std::thread::spawn(|| {
            log_private_diagnostic("contention-test", "internal_contract_error", "contended");
        });
        writer.join().unwrap();
        assert!(diagnostic_metrics().1 > dropped_before);
        drop(guard);

        let poisoner = std::thread::spawn(|| {
            let _guard = PRIVATE_DIAGNOSTIC_EVIDENCE
                .get_or_init(Default::default)
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            panic!("intentional diagnostic mutex poison");
        });
        assert!(poisoner.join().is_err());
        let accepted_before = diagnostic_metrics().0;
        log_private_diagnostic(
            "poison-test",
            "internal_contract_error",
            "recovered evidence",
        );
        assert!(diagnostic_metrics().0 > accepted_before);
        assert!(private_diagnostic_evidence_contains("recovered evidence"));
    }

    #[test]
    fn every_error_code_has_exhaustive_canonical_semantics_and_applicability() {
        let operations = [
            ErrorOperationKind::General,
            ErrorOperationKind::Send,
            ErrorOperationKind::PrivateSend,
            ErrorOperationKind::Share,
            ErrorOperationKind::Offers,
            ErrorOperationKind::Remove,
            ErrorOperationKind::Prune,
            ErrorOperationKind::Download,
            ErrorOperationKind::WebDownload,
            ErrorOperationKind::Benchmark,
            ErrorOperationKind::Feed,
        ];
        for code in ERROR_CODES {
            let spec = error_code_spec(code).unwrap_or_else(|| panic!("missing spec for {code}"));
            assert!(!spec.semantics.is_empty() && !spec.operations.is_empty());
            for &(outcome, retryable) in spec.semantics {
                let mut error =
                    ErrorEnvelopeV1::new(*code, "private /tmp/cause", outcome, retryable);
                if spec.removal_counts == FieldRule::Required {
                    error.selected_tags = Some(2);
                    error.removed_tags = Some(1);
                    error.quota_bytes_released = Some(7);
                    error.maximum = Some(2);
                    error.dry_run = Some(false);
                }
                assert!(
                    ErrorEnvelopeV1::from_value(&error.clone().into_value()).is_ok(),
                    "canonical {code}/{outcome}/{retryable} rejected"
                );
                let mut wrong_retry = error.clone();
                wrong_retry.retryable = !retryable;
                assert!(
                    wrong_retry.validate().is_err(),
                    "wrong retryability admitted for {code}"
                );
                let mut wrong_message = error.clone();
                wrong_message.message.push('!');
                assert!(
                    wrong_message.validate().is_err(),
                    "wrong public message admitted for {code}"
                );
                for operation in operations {
                    let mut candidate = error.clone();
                    candidate.operation_id = (!matches!(
                        operation,
                        ErrorOperationKind::General
                            | ErrorOperationKind::Offers
                            | ErrorOperationKind::Benchmark
                            | ErrorOperationKind::Feed
                    ))
                    .then(|| "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into());
                    assert_eq!(
                        candidate
                            .validate_for_operation(operation, candidate.operation_id.as_deref())
                            .is_ok(),
                        spec.operations.contains(&operation),
                        "{code} applicability for {operation:?}"
                    );
                }
            }
        }
        assert_eq!(
            ERROR_CODES.len(),
            61,
            "update the exhaustive code table when adding a code"
        );
    }

    #[test]
    fn independent_mutation_consumer_error_matrix_matches_contract() {
        use ErrorOperationKind::{Download, PrivateSend, Prune, Remove, Send, Share, WebDownload};
        let all = &[
            Send,
            PrivateSend,
            Share,
            Remove,
            Prune,
            Download,
            WebDownload,
        ];
        let attachment = &[Share, Remove, Prune, Download, WebDownload];
        let downloads = &[Download, WebDownload];
        type ExpectedError = (
            &'static str,
            &'static str,
            &'static [(&'static str, bool)],
            &'static [ErrorOperationKind],
        );
        let expected: Vec<ExpectedError> = vec![
            (
                "daemon_offline",
                "Daemon is offline.",
                &[("not_started", true), ("unknown", true)],
                all,
            ),
            (
                "daemon_disconnected",
                "The daemon disconnected; the event feed has a gap.",
                &[("partial", true), ("unknown", true)],
                all,
            ),
            (
                "daemon_unavailable",
                "The service is unavailable.",
                &[("not_started", true)],
                all,
            ),
            (
                "capacity_or_offline",
                "The service is unavailable.",
                &[("not_started", true)],
                all,
            ),
            (
                "daemon_stopping",
                "The daemon is shutting down or unavailable.",
                &[("not_started", true), ("unknown", true)],
                all,
            ),
            (
                "command_timeout",
                "The request timed out; reconcile before retrying.",
                &[("not_started", true), ("unknown", true), ("partial", true)],
                all,
            ),
            (
                "ipc_capacity",
                "Local capacity is currently unavailable.",
                &[("not_started", true)],
                all,
            ),
            (
                "operation_capacity",
                "Local capacity is currently unavailable.",
                &[("not_started", true)],
                all,
            ),
            (
                "operation_id_conflict",
                "The operation ID is bound to different input.",
                &[("not_started", false)],
                all,
            ),
            (
                "invalid_operation_id",
                "The operation ID is invalid.",
                &[("not_started", false)],
                all,
            ),
            (
                "invalid_request",
                "The request contract is invalid or unsupported.",
                &[("not_started", false)],
                all,
            ),
            (
                "unsupported_schema",
                "The request contract is invalid or unsupported.",
                &[("not_started", false)],
                all,
            ),
            (
                "initial_frame_timeout",
                "The initial local request timed out.",
                &[("not_started", true)],
                all,
            ),
            (
                "invalid_daemon_response",
                "The daemon returned an invalid response.",
                &[("unknown", true), ("partial", false)],
                all,
            ),
            (
                "request_rejected",
                "The request was rejected.",
                &[("not_started", false)],
                all,
            ),
            (
                "command_failed",
                "The command failed.",
                &[("not_started", false)],
                all,
            ),
            (
                "request_forbidden",
                "The request is forbidden.",
                &[("not_started", false)],
                all,
            ),
            (
                "not_found",
                "The requested resource was not found.",
                &[("not_started", false)],
                all,
            ),
            (
                "payload_too_large",
                "The request payload is too large.",
                &[("not_started", false)],
                all,
            ),
            (
                "unsupported_media_type",
                "The request media type is unsupported.",
                &[("not_started", false)],
                all,
            ),
            (
                "invalid_range",
                "The requested byte range is invalid.",
                &[("not_started", false)],
                all,
            ),
            (
                "idempotency_unsupported",
                "Retry-safe mutations are unsupported by the daemon.",
                &[("not_started", false)],
                all,
            ),
            (
                "request_throttled",
                "The request was throttled.",
                &[("not_started", true)],
                all,
            ),
            (
                "request_timeout",
                "The HTTP request timed out.",
                &[("not_started", true), ("unknown", true)],
                all,
            ),
            (
                "request_failed",
                "The request failed.",
                &[("not_started", false), ("unknown", true)],
                all,
            ),
            (
                "attachment_command_timeout",
                "The request timed out; reconcile before retrying.",
                &[("unknown", true)],
                attachment,
            ),
            (
                "attachment_storage_shutdown",
                "The daemon is shutting down or unavailable.",
                &[("unknown", true)],
                attachment,
            ),
            (
                "attachment_storage_busy",
                "Local capacity is currently unavailable.",
                &[("not_started", true)],
                attachment,
            ),
            (
                "invalid_source_digest",
                "The source digest is invalid.",
                &[("not_started", false)],
                &[Share],
            ),
            (
                "invalid_attachment_offer",
                "The attachment request is invalid.",
                &[("not_started", false)],
                downloads,
            ),
            (
                "invalid_offer_selector",
                "The attachment request is invalid.",
                &[("not_started", false)],
                &[Remove],
            ),
            (
                "invalid_prune_request",
                "The attachment request is invalid.",
                &[("not_started", false)],
                &[Prune],
            ),
            (
                "share_failed",
                "Attachment sharing failed.",
                &[("unknown", true)],
                &[Share],
            ),
            (
                "download_failed",
                "Attachment download failed.",
                &[("not_started", true), ("unknown", true)],
                downloads,
            ),
            (
                "attachment_lifecycle_internal",
                "The attachment lifecycle operation failed.",
                &[("unknown", true)],
                &[Remove, Prune],
            ),
            (
                "send_failed",
                "Message submission failed.",
                &[("unknown", true), ("partial", false)],
                &[Send],
            ),
            (
                "private_send_failed",
                "Message submission failed.",
                &[("unknown", true)],
                &[PrivateSend],
            ),
            (
                "recipient_unresolved",
                "The recipient could not be resolved.",
                &[("not_started", false)],
                &[PrivateSend],
            ),
            (
                "private_message_conflict",
                "The message ID is bound to different content.",
                &[("not_started", false)],
                &[PrivateSend],
            ),
            (
                "invalid_message",
                "The message is invalid.",
                &[("not_started", false)],
                &[Send],
            ),
            (
                "private_send_busy",
                "The requested operation is currently busy.",
                &[("not_started", true)],
                &[PrivateSend],
            ),
            (
                "private_recipient_busy",
                "The requested operation is currently busy.",
                &[("not_started", true)],
                &[PrivateSend],
            ),
            (
                "private_replay_unavailable",
                "Recipient replay protection is unavailable.",
                &[("not_started", true)],
                &[PrivateSend],
            ),
            (
                "private_delivery_unknown",
                "The private-message outcome is unknown.",
                &[("unknown", false)],
                &[PrivateSend],
            ),
            (
                "attachment_quota_exceeded",
                "The attachment storage quota is exceeded.",
                &[("not_started", false)],
                &[Share, Download, WebDownload],
            ),
            (
                "attachment_min_free_space",
                "The attachment free-space reserve is unavailable.",
                &[("not_started", true)],
                &[Share, Download, WebDownload],
            ),
            (
                "attachment_tag_capacity",
                "The attachment pin capacity is exhausted.",
                &[("not_started", false)],
                &[Share, Download, WebDownload],
            ),
            (
                "attachment_removal_partial",
                "Attachment removal completed only partially.",
                &[("partial", true), ("unknown", true)],
                &[Remove, Prune],
            ),
            (
                "share_operation_capacity",
                "Attachment sharing capacity is unavailable.",
                &[("not_started", true)],
                &[Share],
            ),
            (
                "download_operation_capacity",
                "Attachment download capacity is unavailable.",
                &[("not_started", true)],
                downloads,
            ),
            (
                "download_staging_unavailable",
                "Attachment download staging is unavailable.",
                &[("not_started", true)],
                downloads,
            ),
            (
                "send_throttled",
                "The request was throttled.",
                &[("not_started", true)],
                &[Send],
            ),
            (
                "send_outcome_unknown",
                "The message outcome is unknown.",
                &[("unknown", true)],
                &[Send],
            ),
            (
                "share_outcome_unknown",
                "The attachment sharing outcome is unknown.",
                &[("unknown", true)],
                &[Share],
            ),
        ];
        for (code, message, semantics, operations) in &expected {
            let actual = error_code_spec(code).unwrap();
            assert_eq!(actual.message, *message, "{code} message");
            assert_eq!(actual.semantics, *semantics, "{code} semantics");
            for operation in all {
                assert_eq!(
                    actual.operations.contains(operation),
                    operations.contains(operation),
                    "{code}/{operation:?} applicability"
                );
            }
        }
        for code in ERROR_CODES {
            let actual = error_code_spec(code).unwrap();
            if actual
                .operations
                .iter()
                .any(|operation| all.contains(operation))
            {
                assert!(
                    expected.iter().any(|entry| entry.0 == *code),
                    "mutation-applicable code missing from independent matrix: {code}"
                );
            }
        }
    }

    #[test]
    fn error_contract_is_strict_bounded_and_keeps_ids_distinct() {
        let mut error =
            ErrorEnvelopeV1::new("daemon_offline", "bad\n\u{1b}[31m", "not_started", true);
        error.request_id = Some("11111111111111111111111111111111".into());
        error.operation_id = Some("22222222222222222222222222222222".into());
        error.validate().unwrap();
        assert_ne!(error.request_id, error.operation_id);
        assert!(!error.message.contains('\n'));
        assert_eq!(sanitize_message("safe\tfield\nnext"), "safe�field�next");
        assert!(!error.message.contains("bad"));
        assert!(ErrorEnvelopeV1::try_new("daemon_offline", "cause", "unknown", false).is_err());
        let fallback = ErrorEnvelopeV1::new("daemon_offline", "cause", "unknown", false);
        assert_eq!(fallback.code, "internal_contract_error");
        assert_eq!(
            (fallback.outcome.as_str(), fallback.retryable),
            ("unknown", false)
        );
        let value = error.into_value();
        assert!(ErrorEnvelopeV1::from_value(&value).is_ok());
        for malformed in [
            serde_json::json!({"type":"error","schema_version":2,"code":"daemon_offline","message":"bad","retryable":true,"outcome":"not_started"}),
            serde_json::json!({"type":"error","schema_version":1,"code":"BAD","message":"bad","retryable":true,"outcome":"not_started"}),
            serde_json::json!({"type":"error","schema_version":1,"code":"daemon_offline","message":"bad","retryable":true,"outcome":"done"}),
            serde_json::json!({"type":"error","schema_version":1,"code":"daemon_offline","message":"bad","retryable":true,"outcome":"not_started","extra":1}),
            serde_json::json!({"type":"error","schema_version":1,"code":"unknown_future_code","message":"Request failed.","retryable":true,"outcome":"not_started"}),
            serde_json::json!({"type":"error","schema_version":1,"code":"daemon_offline","message":"/home/user/private.sock\tdiagnostic","retryable":true,"outcome":"not_started"}),
        ] {
            assert!(ErrorEnvelopeV1::from_value(&malformed).is_err());
        }
    }
}
