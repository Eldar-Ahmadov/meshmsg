use crate::{
    alias::AliasConfig,
    config::State,
    contracts,
    invite::configured_details,
    ipc::{send_request_checked, subscribe},
    output,
};
use anyhow::{Context, Result};
use meshmsg_protocol::{OfferId, OperationId, Request, RequestId};
use std::path::{Path, PathBuf};
use tokio::sync::mpsc;

pub(crate) async fn send_once(
    dir: &Path,
    operation_id: OperationId,
    to: Option<&str>,
    body: &str,
    json: bool,
) -> Result<()> {
    let request = if let Some(to) = to {
        Request::PrivateSend {
            operation_id: operation_id.clone(),
            to: to.parse()?,
            body: meshmsg_protocol::PrivateBody::new(body)?,
        }
    } else {
        Request::Send {
            operation_id: operation_id.clone(),
            body: meshmsg_protocol::BroadcastBody::new(body)?,
        }
    };
    let value = send_request_checked(dir, &request)
        .await
        .with_context(|| format!("operation {operation_id}"))?;
    output::response(json, &value)?;
    Ok(())
}

fn caller_path(path: &Path) -> Result<PathBuf> {
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .context("read current directory")?
            .join(path)
    };
    meshmsg_protocol::validate_ipc_path(&path).map_err(anyhow::Error::msg)?;
    Ok(path)
}

pub(crate) async fn share(
    dir: &Path,
    operation_id: Option<OperationId>,
    path: &Path,
    json: bool,
) -> Result<()> {
    let operation_id = operation_id.unwrap_or_else(OperationId::new_random);
    let path = caller_path(path)?;
    let frame = send_request_checked(
        dir,
        &Request::Share {
            operation_id: operation_id.clone(),
            path,
        },
    )
    .await
    .with_context(|| format!("operation {operation_id}"))?;
    output::response(json, &frame)?;
    Ok(())
}

pub(crate) async fn peers(dir: &Path, json: bool) -> Result<()> {
    let value = send_request_checked(dir, &Request::Peers)
        .await
        .context("request peer directory; the daemon may need to be upgraded and restarted")?;
    output::response(json, &value)?;
    Ok(())
}

pub(crate) async fn offers(dir: &Path, json: bool) -> Result<()> {
    let value = send_request_checked(dir, &Request::Offers).await?;
    output::response(json, &value)?;
    Ok(())
}

pub(crate) async fn offers_remove(
    dir: &Path,
    operation_id: Option<OperationId>,
    offer_id: OfferId,
    direction: Option<meshmsg_protocol::OfferDirection>,
    provider: Option<&str>,
    json: bool,
) -> Result<()> {
    let operation_id = operation_id.unwrap_or_else(OperationId::new_random);
    let frame = send_request_checked(
        dir,
        &Request::OffersRemove {
            operation_id,
            offer_id,
            direction,
            provider: provider.map(str::parse).transpose()?,
        },
    )
    .await?;
    output::response(json, &frame)?;
    Ok(())
}

pub(crate) async fn offers_prune(
    dir: &Path,
    operation_id: Option<OperationId>,
    older_than_secs: Option<u64>,
    direction: Option<meshmsg_protocol::OfferDirection>,
    dry_run: bool,
    max_delete: usize,
    json: bool,
) -> Result<()> {
    let frame = send_request_checked(
        dir,
        &Request::OffersPrune {
            operation_id: operation_id.unwrap_or_else(OperationId::new_random),
            older_than_secs,
            direction,
            dry_run,
            max_delete,
        },
    )
    .await?;
    output::response(json, &frame)?;
    Ok(())
}

/// An input that cannot even be framed as an offer token gets the same typed
/// rejection the daemon returns for any input that is not a signed offer.
fn invalid_attachment_offer(
    operation_id: &OperationId,
    diagnostic: meshmsg_protocol::TextError,
) -> anyhow::Error {
    let error = meshmsg_protocol::ProtocolError::new(
        Some(operation_id.clone()),
        meshmsg_protocol::ErrorCode::InvalidAttachmentOffer,
        meshmsg_protocol::Outcome::NotStarted,
    );
    anyhow::Error::new(contracts::ContractFailure::new(
        Some(RequestId::new_random()),
        error,
    ))
    .context(diagnostic)
}

pub(crate) async fn download(
    dir: &Path,
    operation_id: Option<OperationId>,
    offer: &str,
    output_path: &Path,
    json: bool,
) -> Result<()> {
    let operation_id = operation_id.unwrap_or_else(OperationId::new_random);
    let output = caller_path(output_path)?;
    let offer = offer
        .parse()
        .map_err(|error| invalid_attachment_offer(&operation_id, error))?;
    let frame = send_request_checked(
        dir,
        &Request::Download {
            operation_id,
            offer,
            output,
        },
    )
    .await?;
    output::response(json, &frame)?;
    Ok(())
}

pub(crate) async fn listen(dir: &Path, json: bool) -> Result<()> {
    let mut reader = subscribe(dir).await?;
    loop {
        tokio::select! {
            value = reader.read() => match value? {
                Some(frame) => output::event(json, &frame)?,
                None => anyhow::bail!("local daemon stopped; restart it with `meshmsg daemon`"),
            },
            _ = tokio::signal::ctrl_c() => break,
        }
    }
    Ok(())
}

fn invalid_chat_input(diagnostic: &'static str) -> anyhow::Error {
    let operation_id = OperationId::new_random();
    crate::message::invalid_local_message(&operation_id, anyhow::anyhow!(diagnostic))
}

// LF is the only delimiter. Bound allocation even for an unterminated record;
// two extra bytes allow an exact-limit body followed by CRLF.
fn read_message_line(
    input: &mut impl std::io::BufRead,
    maximum: usize,
) -> std::result::Result<Option<String>, &'static str> {
    let read_limit = maximum
        .checked_add(2)
        .and_then(|value| u64::try_from(value).ok())
        .expect("message input bound is representable");
    let mut bytes = Vec::with_capacity(maximum.min(8 * 1024));
    let mut bounded = std::io::Read::take(input, read_limit);
    if std::io::BufRead::read_until(&mut bounded, b'\n', &mut bytes)
        .map_err(|_| "failed to read message input")?
        == 0
    {
        return Ok(None);
    }
    if bytes.ends_with(b"\n") {
        bytes.pop();
        if bytes.ends_with(b"\r") {
            bytes.pop();
        }
    }
    if bytes.len() > maximum {
        return Err("message exceeds the UTF-8 byte limit");
    }
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| "message is not valid UTF-8")
}

fn stdin_message_lines(
    maximum: usize,
) -> mpsc::Receiver<std::result::Result<String, &'static str>> {
    let (tx, rx) = mpsc::channel(1);
    // Use a detached OS thread, not Tokio's blocking pool: an open stdin must
    // not prevent runtime shutdown after Ctrl-C or a send failure.
    std::thread::spawn(move || {
        let mut input = std::io::stdin().lock();
        loop {
            let value = match read_message_line(&mut input, maximum) {
                Ok(Some(body)) => Ok(body),
                Ok(None) => break,
                Err(error) => Err(error),
            };
            let failed = value.is_err();
            if tx.blocking_send(value).is_err() || failed {
                break;
            }
        }
    });
    rx
}

fn stream_send_failure(
    error: anyhow::Error,
    operation_id: &OperationId,
    private: bool,
) -> anyhow::Error {
    // Preserve authoritative daemon errors, including their exact correlation.
    if error.downcast_ref::<contracts::ContractFailure>().is_some() {
        return error.context(format!("operation {operation_id}"));
    }
    // A lost/malformed IPC reply or interruption cannot prove non-execution.
    let failure = meshmsg_protocol::ProtocolError::new(
        Some(operation_id.clone()),
        if private {
            meshmsg_protocol::ErrorCode::PrivateSendFailed
        } else {
            meshmsg_protocol::ErrorCode::SendFailed
        },
        meshmsg_protocol::Outcome::Unknown,
    );
    anyhow::Error::new(contracts::ContractFailure::new(
        Some(RequestId::new_random()),
        failure,
    ))
    .context(error)
    .context(format!("operation {operation_id}"))
}

pub(crate) async fn send_stream(dir: &Path, to: Option<&str>, json: bool) -> Result<()> {
    // Reject invalid recipient syntax before reading any input.
    if let Some(to) = to {
        let _: meshmsg_protocol::Recipient = to.parse()?;
    }
    let maximum = if to.is_some() {
        meshmsg_protocol::MAX_PRIVATE_BODY_BYTES
    } else {
        meshmsg_protocol::MAX_BROADCAST_BODY_BYTES
    };
    let mut rx = stdin_message_lines(maximum);
    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);
    loop {
        let line = tokio::select! {
            biased;
            signal = &mut shutdown => {
                signal.context("listen for Ctrl-C")?;
                return Ok(());
            }
            line = rx.recv() => match line {
                Some(Ok(body)) if body.is_empty() => continue,
                Some(line) => line,
                None => return Ok(()),
            },
        };
        let operation_id = OperationId::new_random();
        let body = line.map_err(|diagnostic| {
            crate::message::invalid_local_message(&operation_id, anyhow::anyhow!(diagnostic))
                .context(format!("operation {operation_id}"))
        })?;
        // One outstanding operation, no retries. Cancelling an in-flight send
        // reports its ID and unknown outcome rather than silently losing it.
        let result = tokio::select! {
            biased;
            result = send_once(dir, operation_id.clone(), to, &body, json) => result,
            signal = &mut shutdown => match signal {
                Ok(()) => Err(anyhow::anyhow!("send interrupted; outcome may be unknown")),
                Err(error) => Err(error.into()),
            },
        };
        result.map_err(|error| stream_send_failure(error, &operation_id, to.is_some()))?;
    }
}

pub(crate) async fn chat(dir: &Path, json: bool) -> Result<()> {
    let mut reader = subscribe(dir).await?;
    let mut rx = stdin_message_lines(meshmsg_protocol::MAX_BROADCAST_BODY_BYTES);
    loop {
        tokio::select! {
            line = rx.recv() => match line {
                Some(Ok(body)) => {
                    if body.is_empty() {
                        continue;
                    }
                    crate::message::validate_broadcast_body(&body)?;
                    send_request_checked(
                        dir,
                        &Request::Send {
                            operation_id: OperationId::new_random(),
                            body: meshmsg_protocol::BroadcastBody::new(body)?,
                        },
                    )
                    .await?;
                }
                Some(Err(error)) => return Err(invalid_chat_input(error)),
                None => break,
            },
            value = reader.read() => match value? {
                Some(frame) => output::event(json, &frame)?,
                None => anyhow::bail!("local daemon stopped; restart it with `meshmsg daemon`"),
            },
            _ = tokio::signal::ctrl_c() => break,
        }
    }
    Ok(())
}

pub(crate) async fn status(dir: &Path, json: bool) -> Result<()> {
    let frame = send_request_checked(dir, &Request::Status).await?;
    output::status(json, &frame)
}

pub(crate) async fn stop(dir: &Path, json: bool) -> Result<()> {
    let value = send_request_checked(dir, &Request::Stop).await?;
    output::response(json, &value)?;
    Ok(())
}

pub(crate) async fn doctor(dir: &Path, json: bool) -> Result<()> {
    let (state, secret) = State::load_for_doctor(dir)?;
    state.validate_for_identity(secret.public())?;
    let alias_config = AliasConfig::load_for_identity(dir, secret.public())?;
    let (has_invite, bootstrap_peer_count, self_advertised) =
        configured_details(state.invite.as_deref(), secret.public())?;
    let value = serde_json::json!({
        "type":"doctor", "request_id":RequestId::new_random().into_string(),
        "ok":true, "peer":secret.public().to_string(), "topic":state.topic,
        "advertises_self":state.advertise_self, "has_invite":has_invite,
        "bootstrap_peer_count":bootstrap_peer_count, "self_advertised":self_advertised,
        "alias":alias_config.effective(), "alias_enabled":alias_config.enabled(),
        "captured_hostname":alias_config.hostname(), "custom_alias":alias_config.custom()
    });
    output::doctor(json, &value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::invite::Invite;
    use iroh::SecretKey;
    use iroh_gossip::proto::TopicId;

    #[test]
    fn message_lines_preserve_content_and_strip_only_delimiters() {
        let mut input = std::io::Cursor::new("\n\r\n hello \r\n界\u{2028}x\nlast\r");
        for expected in ["", "", " hello ", "界\u{2028}x", "last\r"] {
            assert_eq!(
                read_message_line(&mut input, 32).unwrap().as_deref(),
                Some(expected)
            );
        }
        assert_eq!(read_message_line(&mut input, 32).unwrap(), None);
    }

    #[test]
    fn message_lines_enforce_byte_limits_without_unbounded_reads() {
        for maximum in [
            meshmsg_protocol::MAX_PRIVATE_BODY_BYTES,
            meshmsg_protocol::MAX_BROADCAST_BODY_BYTES,
        ] {
            for ending in ["", "\n", "\r\n"] {
                let body = "a".repeat(maximum);
                let mut input = std::io::Cursor::new(format!("{body}{ending}"));
                assert_eq!(read_message_line(&mut input, maximum).unwrap(), Some(body));
                assert_eq!(read_message_line(&mut input, maximum).unwrap(), None);

                let mut input =
                    std::io::Cursor::new(format!("{}{ending}", "a".repeat(maximum + 1)));
                assert!(read_message_line(&mut input, maximum).is_err());
                assert!(input.position() <= (maximum + 2) as u64);
            }
            let mut input = std::io::Cursor::new(vec![b'x'; maximum * 10]);
            assert!(read_message_line(&mut input, maximum).is_err());
            assert_eq!(input.position(), (maximum + 2) as u64);
        }
        assert!(read_message_line(&mut std::io::Cursor::new("界\n"), 2).is_err());
        assert!(read_message_line(&mut std::io::Cursor::new(b"\xff\n"), 10).is_err());
        assert!(read_message_line(&mut std::io::Cursor::new(b"a\r"), 1).is_err());
    }

    #[test]
    fn message_lines_propagate_read_failures() {
        struct Broken;
        impl std::io::Read for Broken {
            fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("broken input"))
            }
        }
        let mut input = std::io::BufReader::new(Broken);
        assert_eq!(
            read_message_line(&mut input, 10),
            Err("failed to read message input")
        );
    }

    #[test]
    fn stream_failures_preserve_identity_and_ambiguous_outcomes() {
        use meshmsg_protocol::{ErrorCode, Outcome, ProtocolError};
        let operation_id = OperationId::new_random();
        for (private, code) in [
            (false, ErrorCode::SendFailed),
            (true, ErrorCode::PrivateSendFailed),
        ] {
            let error = stream_send_failure(anyhow::anyhow!("lost reply"), &operation_id, private);
            let failure = error
                .downcast_ref::<contracts::ContractFailure>()
                .expect("stream failure is typed");
            assert_eq!(failure.error.operation_id.as_ref(), Some(&operation_id));
            assert_eq!(failure.error.outcome, Outcome::Unknown);
            assert_eq!(failure.error.code, code);
        }
        let original = contracts::ContractFailure::new(
            Some(RequestId::new_random()),
            ProtocolError::new(
                Some(operation_id.clone()),
                ErrorCode::PrivateRecipientBusy,
                Outcome::NotStarted,
            ),
        );
        let error = stream_send_failure(anyhow::Error::new(original.clone()), &operation_id, true);
        assert_eq!(
            error.downcast_ref::<contracts::ContractFailure>(),
            Some(&original)
        );
    }

    #[test]
    fn invalid_chat_input_uses_the_canonical_message_error_contract() {
        let error = invalid_chat_input("chat message exceeds the broadcast UTF-8 byte limit");
        let failure = error
            .downcast_ref::<crate::contracts::ContractFailure>()
            .expect("chat input failure must retain its typed contract");
        assert_eq!(
            failure.error.code,
            meshmsg_protocol::ErrorCode::InvalidMessage
        );
        assert_eq!(failure.error.outcome, meshmsg_protocol::Outcome::NotStarted);
        assert!(failure.error.operation_id.is_some());
        assert!(failure.request_id.is_some());
    }

    #[test]
    fn caller_share_path_preserves_representation_and_rejects_oversize_before_ipc() {
        let current = std::env::current_dir().unwrap();
        let relative = Path::new("./directory/../file.txt");
        assert_eq!(caller_path(relative).unwrap(), current.join(relative));
        let absolute = current.join("./directory/../file.txt");
        assert_eq!(caller_path(&absolute).unwrap(), absolute);

        let prefix = current.to_str().unwrap();
        let separator = std::path::MAIN_SEPARATOR;
        let exact = PathBuf::from(format!(
            "{prefix}{separator}{}",
            "x".repeat(meshmsg_protocol::MAX_IPC_PATH_BYTES - prefix.len() - 1)
        ));
        let oversized = PathBuf::from(format!("{}x", exact.display()));
        assert_eq!(
            exact.as_os_str().as_encoded_bytes().len(),
            meshmsg_protocol::MAX_IPC_PATH_BYTES
        );
        assert!(caller_path(&exact).is_ok());
        let error = caller_path(&oversized).unwrap_err().to_string();
        assert!(error.contains("at most 32768 bytes"));
    }

    #[tokio::test]
    async fn doctor_rejects_unpublishable_advertising_state() {
        let dir = std::env::temp_dir().join(format!(
            "meshmsg-doctor-capacity-test-{}",
            rand::random::<u64>()
        ));
        let invite = Invite {
            topic: TopicId::from_bytes([8; 32]),
            bootstrap_peers: (0..crate::invite::MAX_BOOTSTRAP_PEERS)
                .map(|_| iroh::EndpointAddr::new(SecretKey::generate().public()))
                .collect(),
        };
        State::from_invite(invite.to_string(), &invite, true)
            .save_new(&dir, false)
            .unwrap();

        let error = doctor(&dir, true).await.unwrap_err();

        assert!(error.to_string().contains("cannot advertise self"));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
