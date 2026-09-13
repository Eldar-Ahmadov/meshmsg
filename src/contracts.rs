//! Small adapter helpers around the strict protocol-v3 boundary.
use anyhow::{Context, Result};
use meshmsg_protocol::{ErrorCode, OperationId, Outcome, ProtocolError};

pub(crate) fn new_request_id() -> String {
    meshmsg_protocol::RequestId::new_random().into_string()
}

pub(crate) fn valid_operation_id(value: &str) -> bool {
    value.parse::<OperationId>().is_ok()
}

pub(crate) fn valid_request_id(value: &str) -> bool {
    value.parse::<meshmsg_protocol::RequestId>().is_ok()
}

/// In-process adapter between operation workers and the strict protocol DTO.
/// Diagnostics and presentation fields never cross IPC.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProtocolErrorAdapter {
    pub(crate) code: String,
    pub(crate) outcome: String,
    pub(crate) request_id: Option<String>,
    pub(crate) operation_id: Option<String>,
    pub(crate) message: String,
    pub(crate) retryable: bool,
}

impl ProtocolErrorAdapter {
    pub(crate) fn try_new(
        code: impl Into<String>,
        _diagnostic: impl AsRef<str>,
        outcome: impl Into<String>,
        _retryable: bool,
    ) -> Result<Self> {
        let code = code.into();
        let outcome = outcome.into();
        let typed = protocol_error(
            error_code(&code)?,
            crate::contracts::outcome(&outcome)?,
            None,
        )?;
        Ok(Self::from_typed(None, typed))
    }
    pub(crate) fn new(
        code: impl Into<String>,
        diagnostic: impl AsRef<str>,
        outcome: impl Into<String>,
        retryable: bool,
    ) -> Self {
        Self::try_new(code, diagnostic, outcome, retryable).unwrap_or_else(|_| {
            Self::from_typed(
                None,
                ProtocolError::new(None, ErrorCode::InternalContractError, Outcome::Unknown),
            )
        })
    }
    pub(crate) fn from_typed(request_id: Option<String>, error: ProtocolError) -> Self {
        Self {
            code: error.code.to_string(),
            outcome: outcome_name(error.outcome).into(),
            request_id,
            operation_id: error.operation_id.as_ref().map(ToString::to_string),
            message: error.message().into(),
            retryable: error.retryable(),
        }
    }
    pub(crate) fn typed(&self) -> Result<ProtocolError> {
        protocol_error(
            error_code(&self.code)?,
            outcome(&self.outcome)?,
            self.operation_id.as_deref(),
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ContractFailure(pub(crate) ProtocolErrorAdapter);

impl std::fmt::Display for ContractFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{} [{}; {}; {}]",
            self.0.message,
            self.0.code,
            self.0.outcome,
            if self.0.retryable {
                "retryable"
            } else {
                "do not retry unchanged"
            }
        )
    }
}
impl std::error::Error for ContractFailure {}

pub(crate) fn error_code(name: &str) -> Result<ErrorCode> {
    serde_json::from_value(serde_json::Value::String(name.to_owned()))
        .context("unknown protocol error code")
}

pub(crate) fn outcome(name: &str) -> Result<Outcome> {
    serde_json::from_value(serde_json::Value::String(name.to_owned()))
        .context("unknown protocol outcome")
}

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
) -> meshmsg_protocol::Response {
    meshmsg_protocol::Response::Error(ProtocolError::new(operation_id, code, outcome))
}

pub(crate) fn protocol_error(
    code: ErrorCode,
    outcome: Outcome,
    operation_id: Option<&str>,
) -> Result<ProtocolError> {
    Ok(ProtocolError::new(
        operation_id.map(str::parse).transpose()?,
        code,
        outcome,
    ))
}
