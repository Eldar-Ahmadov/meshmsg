//! Typed local failure envelope for the strict protocol-v4 error boundary.
//!
//! Failures travel through `anyhow` chains as [`ContractFailure`] values and
//! become a protocol frame only at the CLI boundary. Diagnostic text is local
//! presentation and never part of the wire contract.
use meshmsg_protocol::{
    ErrorCode, OperationId, Outcome, ProtocolError, RequestId, Response, ResponseFrame,
};
use std::fmt;

pub(crate) fn new_request_id() -> RequestId {
    RequestId::new_random()
}

pub(crate) fn valid_operation_id(value: &str) -> bool {
    value.parse::<OperationId>().is_ok()
}

pub(crate) fn valid_request_id(value: &str) -> bool {
    value.parse::<RequestId>().is_ok()
}

/// An authoritative protocol error, optionally correlated with its request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ContractFailure {
    pub(crate) request_id: Option<RequestId>,
    pub(crate) error: ProtocolError,
}

impl ContractFailure {
    pub(crate) fn new(request_id: Option<RequestId>, error: ProtocolError) -> Self {
        Self { request_id, error }
    }

    /// A failure detected locally before any daemon operation exists.
    pub(crate) fn local(code: ErrorCode, outcome: Outcome) -> Self {
        Self::new(None, ProtocolError::new(None, code, outcome))
    }

    /// The single JSON frame printed for a failed CLI command.
    pub(crate) fn into_frame(self) -> ResponseFrame {
        ResponseFrame::new(
            Some(self.request_id.unwrap_or_else(new_request_id)),
            Response::Error(self.error),
        )
    }
}

impl fmt::Display for ContractFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} [{}; {}; {}]",
            self.error.message(),
            self.error.code,
            outcome_name(self.error.outcome),
            self.error.retry_advice().message()
        )
    }
}

impl std::error::Error for ContractFailure {}

pub(crate) fn outcome_name(value: Outcome) -> &'static str {
    match value {
        Outcome::NotStarted => "not_started",
        Outcome::Partial => "partial",
        Outcome::Unknown => "unknown",
    }
}

pub(crate) fn protocol_error_response(
    code: ErrorCode,
    outcome: Outcome,
    operation_id: Option<OperationId>,
) -> Response {
    Response::Error(ProtocolError::new(operation_id, code, outcome))
}
