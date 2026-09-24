use crate::{
    alias::AliasConfig,
    attachment::{
        self,
        runtime::{download_request_context, MAX_PRUNE_TAGS},
    },
    config::State,
    contracts,
    invite::configured_details,
    ipc::{self, send_request_checked, subscribe, IpcRequest},
    output,
};
use anyhow::{Context, Result};
use iroh_gossip::proto::TopicId;
use std::path::{Path, PathBuf};
use tokio::sync::mpsc;

fn parse_operation_id(value: Option<String>) -> Result<meshmsg_protocol::OperationId> {
    value.map_or_else(
        || Ok(meshmsg_protocol::OperationId::new_random()),
        |value| value.parse().map_err(anyhow::Error::from),
    )
}

pub(crate) async fn send_once(
    dir: &Path,
    operation_id: meshmsg_protocol::OperationId,
    to: Option<&str>,
    body: &str,
    json: bool,
) -> Result<()> {
    let value = if let Some(to) = to {
        let value = send_request_checked(
            dir,
            &IpcRequest::PrivateSend {
                operation_id: operation_id.clone(),
                to: to.parse()?,
                body: meshmsg_protocol::PrivateBody::new(body)?,
            },
        )
        .await
        .with_context(|| format!("operation {operation_id}"))?;
        match &value.response {
            meshmsg_protocol::Response::PrivateAccepted(accepted) => anyhow::ensure!(
                accepted.body_bytes == body.len(),
                "private-send acceptance metadata does not match the request"
            ),
            _ => unreachable!("checked response family"),
        }
        value
    } else {
        let value = send_request_checked(
            dir,
            &IpcRequest::Send {
                operation_id: operation_id.clone(),
                body: meshmsg_protocol::BroadcastBody::new(body)?,
            },
        )
        .await
        .with_context(|| format!("operation {operation_id}"))?;
        value
    };
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
    operation_id: Option<String>,
    path: &Path,
    json: bool,
) -> Result<()> {
    let operation_id = parse_operation_id(operation_id)?;
    let path = caller_path(path)?;
    let status = send_request_checked(dir, &IpcRequest::Status).await?;
    let maximum = match &status.response {
        meshmsg_protocol::Response::Status(status) => status.max_attachment_bytes,
        _ => unreachable!("checked response family"),
    };
    let digest_path = path.clone();
    let source_digest =
        tokio::task::spawn_blocking(move || attachment::share_source_digest(&digest_path, maximum))
            .await
            .context("attachment digest task failed")??;
    let frame = send_lifecycle_request(
        dir,
        &IpcRequest::Share {
            operation_id: operation_id.clone(),
            source_digest: source_digest.parse()?,
            path,
        },
    )
    .await
    .with_context(|| format!("operation {operation_id}"))?;
    let meshmsg_protocol::Response::AttachmentShared(shared) = &frame.response else {
        unreachable!("checked attachment-shared family")
    };
    anyhow::ensure!(
        shared.source_digest.as_str() == source_digest,
        "daemon returned mismatched share operation metadata"
    );
    output::response(json, &frame)?;
    Ok(())
}

pub(crate) async fn peers(dir: &Path, json: bool) -> Result<()> {
    let value = send_request_checked(dir, &IpcRequest::Peers)
        .await
        .context("request peer directory; the daemon may need to be upgraded and restarted")?;
    output::response(json, &value)?;
    Ok(())
}

pub(crate) async fn offers(dir: &Path, json: bool) -> Result<()> {
    let value = send_request_checked(dir, &IpcRequest::Offers).await?;
    output::response(json, &value)?;
    Ok(())
}

async fn send_lifecycle_request(
    dir: &Path,
    request: &IpcRequest,
) -> Result<meshmsg_protocol::ResponseFrame> {
    send_request_checked(dir, request).await
}

pub(crate) async fn offers_remove(
    dir: &Path,
    operation_id: Option<String>,
    offer_id: &str,
    direction: Option<&str>,
    provider: Option<&str>,
    json: bool,
) -> Result<()> {
    let operation_id = parse_operation_id(operation_id)?;
    let frame = send_lifecycle_request(
        dir,
        &IpcRequest::OffersRemove {
            operation_id: operation_id.clone(),
            offer_id: offer_id.parse()?,
            direction: direction.map(str::parse).transpose()?,
            provider: provider.map(str::parse).transpose()?,
        },
    )
    .await?;
    let meshmsg_protocol::Response::OfferRemoved(result) = &frame.response else {
        unreachable!("checked lifecycle family")
    };
    anyhow::ensure!(
        result.offer_id.to_string() == offer_id
            && result
                .direction
                .as_ref()
                .map(ToString::to_string)
                .as_deref()
                == direction
            && result.provider.as_ref().map(ToString::to_string).as_deref() == provider
            && result.maximum == MAX_PRUNE_TAGS,
        "lifecycle response does not match its request"
    );
    output::response(json, &frame)?;
    Ok(())
}

pub(crate) async fn offers_prune(
    dir: &Path,
    operation_id: Option<String>,
    older_than_secs: Option<u64>,
    direction: Option<&str>,
    dry_run: bool,
    max_delete: usize,
    json: bool,
) -> Result<()> {
    let operation_id = parse_operation_id(operation_id)?;
    let status = send_request_checked(dir, &IpcRequest::Status).await?;
    let retention = match &status.response {
        meshmsg_protocol::Response::Status(status) => status.attachment_retention_secs,
        _ => unreachable!("checked response family"),
    };
    let effective_age = older_than_secs.unwrap_or(retention);
    let frame = send_lifecycle_request(
        dir,
        &IpcRequest::OffersPrune {
            operation_id: operation_id.clone(),
            older_than_secs: effective_age,
            direction: direction.map(str::parse).transpose()?,
            dry_run,
            max_delete,
        },
    )
    .await?;
    let meshmsg_protocol::Response::OffersPruned(result) = &frame.response else {
        unreachable!("checked lifecycle family")
    };
    anyhow::ensure!(
        result.older_than_secs == effective_age
            && result
                .direction
                .as_ref()
                .map(ToString::to_string)
                .as_deref()
                == direction
            && result.dry_run == dry_run
            && result.maximum == max_delete,
        "lifecycle response does not match its request"
    );
    output::response(json, &frame)?;
    Ok(())
}

pub(crate) async fn download(
    dir: &Path,
    operation_id: Option<String>,
    offer: &str,
    output_path: &Path,
    json: bool,
) -> Result<()> {
    let operation_id = parse_operation_id(operation_id)?;
    let requested_output = caller_path(output_path)?;
    let status = send_request_checked(dir, &IpcRequest::Status).await?;
    let status = match &status.response {
        meshmsg_protocol::Response::Status(status) => status,
        _ => unreachable!("checked response family"),
    };
    let topic_bytes = status.topic.to_bytes();
    let expected = download_request_context(
        &operation_id,
        offer,
        &requested_output,
        TopicId::from_bytes(topic_bytes),
    )
    .context("validate submitted attachment offer")?;
    let frame = send_lifecycle_request(
        dir,
        &IpcRequest::Download {
            operation_id: operation_id.clone(),
            offer: offer.to_owned(),
            output: requested_output.clone(),
            mode: meshmsg_protocol::DownloadMode::Install,
        },
    )
    .await?;
    let meshmsg_protocol::Response::DownloadComplete(result) = &frame.response else {
        unreachable!("checked download family")
    };
    result
        .validate_for_request(&expected)
        .map_err(anyhow::Error::msg)?;
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
    let operation_id = ipc::new_operation_id();
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
    operation_id: &meshmsg_protocol::OperationId,
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
    anyhow::Error::new(contracts::ContractFailure(
        contracts::ProtocolErrorAdapter::from_typed(Some(contracts::new_request_id()), failure),
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
        crate::message::MAX_PRIVATE_BODY_BYTES
    } else {
        crate::message::MAX_BROADCAST_BODY_BYTES
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
        let operation_id = ipc::new_operation_id();
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
    let mut rx = stdin_message_lines(crate::message::MAX_BROADCAST_BODY_BYTES);
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
                        &IpcRequest::Send {
                            operation_id: ipc::new_operation_id(),
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
    let frame = send_request_checked(dir, &IpcRequest::Status).await?;
    output::status(json, &frame)
}

pub(crate) async fn stop(dir: &Path, json: bool) -> Result<()> {
    let value = send_request_checked(dir, &IpcRequest::Stop).await?;
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
        "type":"doctor", "request_id":contracts::new_request_id(),
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
            crate::message::MAX_PRIVATE_BODY_BYTES,
            crate::message::MAX_BROADCAST_BODY_BYTES,
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
        let operation_id = ipc::new_operation_id();
        for private in [false, true] {
            let error = stream_send_failure(anyhow::anyhow!("lost reply"), &operation_id, private);
            let failure = &error
                .downcast_ref::<contracts::ContractFailure>()
                .unwrap()
                .0;
            assert_eq!(failure.operation_id.as_deref(), Some(operation_id.as_str()));
            assert_eq!(failure.outcome, "unknown");
            assert_eq!(
                failure.code,
                if private {
                    "private_send_failed"
                } else {
                    "send_failed"
                }
            );
        }
        let original = contracts::ProtocolErrorAdapter::from_typed(
            Some(contracts::new_request_id()),
            meshmsg_protocol::ProtocolError::new(
                Some(operation_id.clone()),
                meshmsg_protocol::ErrorCode::PrivateRecipientBusy,
                meshmsg_protocol::Outcome::NotStarted,
            ),
        );
        let error = stream_send_failure(
            anyhow::Error::new(contracts::ContractFailure(original.clone())),
            &operation_id,
            true,
        );
        assert_eq!(
            error
                .downcast_ref::<contracts::ContractFailure>()
                .unwrap()
                .0,
            original
        );
    }

    #[test]
    fn invalid_chat_input_uses_the_canonical_message_error_contract() {
        let error = invalid_chat_input("chat message exceeds the broadcast UTF-8 byte limit");
        let failure = error
            .downcast_ref::<crate::contracts::ContractFailure>()
            .expect("chat input failure must retain its typed contract");
        assert_eq!(failure.0.code, "invalid_message");
        assert_eq!(failure.0.outcome, "not_started");
        assert!(failure
            .0
            .operation_id
            .as_deref()
            .is_some_and(crate::contracts::valid_operation_id));
        assert!(failure
            .0
            .request_id
            .as_deref()
            .is_some_and(crate::contracts::valid_request_id));
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
