//! Small adapter helpers around the strict protocol-v2 boundary.
use anyhow::{Context, Result};
use meshmsg_protocol::{ErrorCode, OperationId, Outcome, ProtocolError};

pub(crate) const SCHEMA_VERSION: u8 = 1;
pub(crate) const MAX_PUBLIC_MESSAGE_BYTES: usize = 1024;

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
    pub(crate) fn validate(&self) -> Result<()> {
        self.typed()?;
        if let Some(id) = &self.request_id {
            anyhow::ensure!(valid_request_id(id), "invalid error request ID");
        }
        Ok(())
    }
    #[cfg(feature = "web")]
    pub(crate) fn validate_operation_id(&self, operation_id: Option<&str>) -> Result<()> {
        self.validate()?;
        anyhow::ensure!(
            self.operation_id.as_deref() == operation_id,
            "error operation ID does not match request"
        );
        Ok(())
    }
    pub(crate) fn from_value(value: &serde_json::Value) -> Result<Self> {
        let request_id = value
            .get("request_id")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        let operation_id = value
            .get("operation_id")
            .and_then(serde_json::Value::as_str);
        let typed = protocol_error(
            serde_json::from_value(value.get("code").cloned().context("missing error code")?)?,
            serde_json::from_value(
                value
                    .get("outcome")
                    .cloned()
                    .context("missing error outcome")?,
            )?,
            operation_id,
        )?;
        let result = Self::from_typed(request_id, typed);
        let allowed = [
            "protocol_version",
            "schema_version",
            "request_id",
            "type",
            "operation_id",
            "code",
            "outcome",
        ];
        anyhow::ensure!(
            value
                .as_object()
                .is_some_and(|object| object.keys().all(|key| allowed.contains(&key.as_str()))),
            "malformed protocol error"
        );
        result.validate()?;
        Ok(result)
    }
    #[cfg(feature = "web")]
    pub(crate) fn into_value(self) -> serde_json::Value {
        let typed = self.typed().expect("typed protocol error producer");
        let request_id = self
            .request_id
            .map(|id| id.parse().expect("validated protocol request ID"));
        meshmsg_protocol::DaemonFrame::Response(meshmsg_protocol::ResponseFrame::new(
            request_id,
            meshmsg_protocol::Response::Error(typed),
        ))
        .into_payload_value()
        .expect("canonical protocol error serialization")
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

#[cfg(feature = "web")]
pub(crate) fn known_error_code(name: &str) -> bool {
    error_code(name).is_ok()
}

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

/// Produce the historical JSON presentation shape for CLI/HTTP adapters. The
/// daemon wire boundary removes `message` and `retryable`; those values are
/// always derived locally from the typed enums.
pub(crate) fn present_error(request_id: Option<&str>, error: &ProtocolError) -> serde_json::Value {
    let mut value = serde_json::json!({
        "type": "error",
        "schema_version": SCHEMA_VERSION,
        "code": error.code,
        "message": error.message(),
        "outcome": error.outcome,
        "retryable": error.retryable(),
    });
    if let Some(request_id) = request_id {
        value["request_id"] = request_id.into();
    }
    if let Some(operation_id) = &error.operation_id {
        value["operation_id"] = operation_id.to_string().into();
    }
    value
}
