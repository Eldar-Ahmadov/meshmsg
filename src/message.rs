use anyhow::Result;

/// Conservative limit for newly produced broadcast text. It leaves deterministic
/// headroom for EnvelopeV2 metadata and signatures inside the 4096-byte frame.
pub(crate) const MAX_BROADCAST_BODY_BYTES: usize = 3900;
/// Direct/private messages use a separate bounded transport and retain their
/// 4096-byte body contract.
pub(crate) const MAX_PRIVATE_BODY_BYTES: usize = 4096;

pub(crate) fn validate_broadcast_body(body: &str) -> Result<()> {
    validate_nonempty_bounded(body, MAX_BROADCAST_BODY_BYTES, "broadcast message")
}

pub(crate) fn validate_private_body(body: &str) -> Result<()> {
    validate_nonempty_bounded(body, MAX_PRIVATE_BODY_BYTES, "private message")
}

pub(crate) fn invalid_local_message(
    operation_id: &str,
    diagnostic: anyhow::Error,
) -> anyhow::Error {
    let error = meshmsg_protocol::ProtocolError::new(
        Some(operation_id.parse().expect("validated operation ID")),
        meshmsg_protocol::ErrorCode::InvalidMessage,
        meshmsg_protocol::Outcome::NotStarted,
    );
    let envelope = crate::contracts::ProtocolErrorAdapter::from_typed(
        Some(crate::contracts::new_request_id()),
        error,
    );
    anyhow::Error::new(crate::contracts::ContractFailure(envelope)).context(diagnostic)
}

fn validate_nonempty_bounded(body: &str, maximum: usize, operation: &str) -> Result<()> {
    anyhow::ensure!(!body.is_empty(), "{operation} body cannot be empty");
    anyhow::ensure!(
        body.len() <= maximum,
        "{operation} body exceeds {maximum} UTF-8 bytes"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_body_boundaries_are_byte_based() {
        validate_broadcast_body(" ").unwrap();
        validate_broadcast_body(&"a".repeat(MAX_BROADCAST_BODY_BYTES)).unwrap();
        assert!(validate_broadcast_body("").is_err());
        assert!(
            validate_broadcast_body(&"a".repeat(MAX_BROADCAST_BODY_BYTES + 1))
                .unwrap_err()
                .to_string()
                .contains("broadcast message")
        );

        validate_private_body(&"a".repeat(MAX_PRIVATE_BODY_BYTES)).unwrap();
        assert!(validate_private_body("").is_err());
        assert!(
            validate_private_body(&"a".repeat(MAX_PRIVATE_BODY_BYTES + 1))
                .unwrap_err()
                .to_string()
                .contains("private message")
        );

        let exact_multibyte = "界".repeat(MAX_BROADCAST_BODY_BYTES / "界".len());
        assert_eq!(exact_multibyte.len(), MAX_BROADCAST_BODY_BYTES);
        validate_broadcast_body(&exact_multibyte).unwrap();
        assert!(validate_broadcast_body(&(exact_multibyte + "界")).is_err());
    }
}
