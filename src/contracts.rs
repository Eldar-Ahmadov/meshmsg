//! Stable, versioned contracts shared by CLI JSON, local IPC, HTTP, and SSE.
//!
//! IDs are deliberately distinct: a request ID correlates one transport request,
//! while an operation ID identifies a retry-safe mutation across requests.
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

pub(crate) const SCHEMA_VERSION: u8 = 1;
pub(crate) const API_CONTRACT_CAPABILITY: &str = "typed_contracts_v1";
pub(crate) const MAX_PUBLIC_MESSAGE_BYTES: usize = 1024;
pub(crate) const BENCHMARK_SEND_FAILED_MESSAGE: &str = "Message submission failed.";

pub(crate) fn new_request_id() -> String {
    data_encoding::HEXLOWER.encode(&rand::random::<[u8; 16]>())
}

pub(crate) fn valid_request_id(value: &str) -> bool {
    crate::ipc::valid_operation_id(value)
}

pub(crate) fn known_error_code(code: &str) -> bool {
    matches!(
        code,
        "daemon_offline"
            | "daemon_disconnected"
            | "daemon_unavailable"
            | "daemon_stopping"
            | "command_timeout"
            | "attachment_command_timeout"
            | "attachment_storage_shutdown"
            | "ipc_capacity"
            | "operation_capacity"
            | "attachment_storage_busy"
            | "operation_id_conflict"
            | "invalid_operation_id"
            | "invalid_source_digest"
            | "invalid_attachment_offer"
            | "invalid_offer_selector"
            | "invalid_prune_request"
            | "share_failed"
            | "download_failed"
            | "offers_failed"
            | "offers_busy"
            | "attachment_lifecycle_internal"
            | "send_failed"
            | "private_send_failed"
            | "recipient_unresolved"
            | "invalid_request"
            | "unsupported_schema"
            | "initial_frame_timeout"
            | "invalid_message"
            | "private_send_busy"
            | "private_recipient_busy"
            | "benchmark_busy"
            | "private_message_conflict"
            | "private_replay_unavailable"
            | "private_delivery_unknown"
            | "invalid_benchmark"
            | "attachment_quota_exceeded"
            | "attachment_min_free_space"
            | "attachment_tag_capacity"
            | "attachment_removal_partial"
            | "share_operation_capacity"
            | "download_operation_capacity"
            | "invalid_daemon_response"
            | "request_rejected"
            | "feed_error"
            | "command_failed"
            | "startup_failed"
            | "internal_contract_error"
            | "request_forbidden"
            | "not_found"
            | "request_throttled"
            | "request_timeout"
            | "payload_too_large"
            | "unsupported_media_type"
            | "invalid_range"
            | "capacity_or_offline"
            | "request_failed"
            | "idempotency_unsupported"
            | "send_throttled"
            | "send_outcome_unknown"
            | "share_outcome_unknown"
    )
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
    pub(crate) fn new(
        code: impl Into<String>,
        message: impl AsRef<str>,
        outcome: impl Into<String>,
        retryable: bool,
    ) -> Self {
        let code = code.into();
        let _ = message;
        let message = sanitize_message(stable_message(&code));
        Self {
            kind: "error".into(),
            schema_version: SCHEMA_VERSION,
            code,
            message,
            retryable,
            outcome: outcome.into(),
            request_id: None,
            operation_id: None,
            offer_id: None,
            selected_tags: None,
            removed_tags: None,
            quota_bytes_released: None,
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        anyhow::ensure!(self.kind == "error", "error type is invalid");
        anyhow::ensure!(
            self.schema_version == SCHEMA_VERSION,
            "unsupported error schema version"
        );
        anyhow::ensure!(
            valid_token(&self.code) && known_error_code(&self.code),
            "error code is invalid or unknown"
        );
        anyhow::ensure!(
            self.message == stable_message(&self.code),
            "error message is not the fixed public text for its code"
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
            true,
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
