pub(crate) fn invalid_local_message(
    operation_id: &meshmsg_protocol::OperationId,
    diagnostic: anyhow::Error,
) -> anyhow::Error {
    let error = meshmsg_protocol::ProtocolError::new(
        Some(operation_id.clone()),
        meshmsg_protocol::ErrorCode::InvalidMessage,
        meshmsg_protocol::Outcome::NotStarted,
    );
    let failure = crate::contracts::ContractFailure::new(
        Some(meshmsg_protocol::RequestId::new_random()),
        error,
    );
    anyhow::Error::new(failure).context(diagnostic)
}
