//! Typed local failure envelope for the strict protocol-v5 error boundary.
//!
//! Failures travel through `anyhow` chains as [`ContractFailure`] values and
//! become a protocol frame only at the CLI boundary. Diagnostic text is local
//! presentation and never part of the wire contract.
use meshmsg_protocol::{ErrorCode, Outcome, ProtocolError, RequestId, Response, ResponseFrame};
use std::fmt;

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
            Some(self.request_id.unwrap_or_else(RequestId::new_random)),
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
            self.error.outcome,
            self.error.retry_advice().message()
        )
    }
}

impl std::error::Error for ContractFailure {}
