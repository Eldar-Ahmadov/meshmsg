use super::{protocol, storage, tags, transfer};
use anyhow::Result;
use iroh_blobs::api::Store;
use std::{path::PathBuf, sync::Arc};
use tokio::sync::{broadcast, OwnedSemaphorePermit, Semaphore};

pub(crate) use storage::{AttachmentStorage, RemovalSpec, MAX_PRUNE_TAGS};
pub(crate) use transfer::{DownloadResources, ShareResources};

/// The operation whose storage failure is being reported.
#[derive(Clone, Copy)]
enum StorageOperation {
    Share,
    Download,
    OffersRemove,
    OffersPrune,
}

impl StorageOperation {
    /// Code and outcome for storage failures that carry no typed protocol code.
    fn fallback(self) -> (meshmsg_protocol::ErrorCode, meshmsg_protocol::Outcome) {
        use meshmsg_protocol::{ErrorCode, Outcome};
        match self {
            Self::Share => (ErrorCode::ShareFailed, Outcome::Unknown),
            Self::Download => (ErrorCode::DownloadFailed, Outcome::NotStarted),
            Self::OffersRemove | Self::OffersPrune => {
                (ErrorCode::AttachmentLifecycleInternal, Outcome::Unknown)
            }
        }
    }
}

fn storage_operation_error(
    operation: StorageOperation,
    error: &anyhow::Error,
    operation_id: &meshmsg_protocol::OperationId,
) -> meshmsg_protocol::Response {
    // Typed admission failures always bind to NotStarted; everything else is
    // the operation's fallback.
    let (code, outcome) = match error
        .chain()
        .find_map(|cause| cause.downcast_ref::<storage::AttachmentFailure>())
    {
        Some(failure) => (failure.code(), meshmsg_protocol::Outcome::NotStarted),
        None => operation.fallback(),
    };
    meshmsg_protocol::Response::Error(meshmsg_protocol::ProtocolError::new(
        Some(*operation_id),
        code,
        outcome,
    ))
}

pub(crate) fn try_admit_transfer(limit: &Arc<Semaphore>) -> Result<OwnedSemaphorePermit, ()> {
    limit.clone().try_acquire_owned().map_err(|_| ())
}

pub(crate) fn try_admit_offer_listing(
    limit: &Arc<Semaphore>,
) -> Result<OwnedSemaphorePermit, meshmsg_protocol::ProtocolError> {
    limit.clone().try_acquire_owned().map_err(|_| {
        meshmsg_protocol::ProtocolError::new(
            None,
            meshmsg_protocol::ErrorCode::OffersBusy,
            meshmsg_protocol::Outcome::NotStarted,
        )
    })
}

pub(crate) async fn list_offers_request(store: Store) -> meshmsg_protocol::Response {
    match tags::list_pinned_blobs(&store).await {
        Ok((blobs, truncated, item_errors)) => {
            meshmsg_protocol::Response::Offers(meshmsg_protocol::OffersList {
                blobs,
                truncated,
                item_errors,
            })
        }
        Err(_error) => meshmsg_protocol::Response::Error(meshmsg_protocol::ProtocolError::new(
            None,
            meshmsg_protocol::ErrorCode::OffersFailed,
            meshmsg_protocol::Outcome::Unknown,
        )),
    }
}

pub(crate) async fn remove_offer_request(
    storage: AttachmentStorage,
    operation_id: &meshmsg_protocol::OperationId,
    offer_id: &meshmsg_protocol::OfferId,
    direction: Option<meshmsg_protocol::OfferDirection>,
    provider: Option<&meshmsg_protocol::PeerId>,
) -> meshmsg_protocol::Response {
    match storage
        .remove_at_cutoff(
            RemovalSpec {
                operation_id,
                offer_id: Some(offer_id),
                direction,
                provider,
                older_than_secs: None,
                maximum: MAX_PRUNE_TAGS,
                dry_run: false,
            },
            None,
        )
        .await
    {
        Ok(value) => value,
        Err(error) => storage_operation_error(StorageOperation::OffersRemove, &error, operation_id),
    }
}

pub(crate) async fn prune_offers_request(
    storage: AttachmentStorage,
    operation_id: &meshmsg_protocol::OperationId,
    older_than_secs: u64,
    cutoff_ms: u64,
    direction: Option<meshmsg_protocol::OfferDirection>,
    dry_run: bool,
    max_delete: usize,
) -> meshmsg_protocol::Response {
    match storage
        .remove_at_cutoff(
            RemovalSpec {
                operation_id,
                offer_id: None,
                direction,
                provider: None,
                older_than_secs: Some(older_than_secs),
                maximum: max_delete,
                dry_run,
            },
            Some(cutoff_ms),
        )
        .await
    {
        Ok(value) => value,
        Err(error) => storage_operation_error(StorageOperation::OffersPrune, &error, operation_id),
    }
}

pub(crate) async fn share_request(
    resources: ShareResources,
    operation_id: meshmsg_protocol::OperationId,
    path: PathBuf,
    max_attachment_bytes: u64,
) -> meshmsg_protocol::Response {
    let gate = resources.storage.gate.clone();
    match gate.acquire_owned().await {
        Ok(_permit) => {
            match transfer::share_attachment(resources, operation_id, path, max_attachment_bytes)
                .await
            {
                Ok(value) => value,
                Err(error) => {
                    storage_operation_error(StorageOperation::Share, &error, &operation_id)
                }
            }
        }
        Err(_) => meshmsg_protocol::Response::Error(meshmsg_protocol::ProtocolError::new(
            Some(operation_id),
            meshmsg_protocol::ErrorCode::DaemonStopping,
            meshmsg_protocol::Outcome::Unknown,
        )),
    }
}

/// A download's authenticated offer and the blob ticket it carries.
pub(crate) type SignedOffer = (super::AttachmentOffer, iroh_blobs::ticket::BlobTicket);

/// Only a signed offer for this daemon's topic is accepted. The daemon calls
/// this before transfer admission, so any other input is a stable
/// `invalid_attachment_offer` rather than a load-dependent busy result, and is
/// rejected before storage admission, events, or network work.
pub(crate) fn parse_download_offer(
    operation_id: meshmsg_protocol::OperationId,
    offer: &meshmsg_protocol::AttachmentToken,
    topic: iroh_gossip::proto::TopicId,
) -> Result<SignedOffer, meshmsg_protocol::ProtocolError> {
    protocol::parse_signed_offer_token(offer.as_str(), topic).map_err(|_| {
        meshmsg_protocol::ProtocolError::new(
            Some(operation_id),
            meshmsg_protocol::ErrorCode::InvalidAttachmentOffer,
            meshmsg_protocol::Outcome::NotStarted,
        )
    })
}

pub(crate) async fn download_request(
    resources: DownloadResources,
    events: broadcast::Sender<meshmsg_protocol::Event>,
    operation_id: meshmsg_protocol::OperationId,
    (offer, ticket): SignedOffer,
    output: PathBuf,
    max_attachment_bytes: u64,
) -> meshmsg_protocol::Response {
    let gate = resources.storage.gate.clone();
    match gate.acquire_owned().await {
        Ok(_permit) => {
            let _ = events.send(meshmsg_protocol::Event::DownloadStarted {
                operation_id,
                output: output.clone(),
            });
            match transfer::download_attachment(
                resources,
                events,
                &operation_id,
                offer,
                ticket,
                output,
                max_attachment_bytes,
            )
            .await
            {
                Ok(value) => value,
                Err(error) => {
                    storage_operation_error(StorageOperation::Download, &error, &operation_id)
                }
            }
        }
        Err(_) => meshmsg_protocol::Response::Error(meshmsg_protocol::ProtocolError::new(
            Some(operation_id),
            meshmsg_protocol::ErrorCode::DaemonStopping,
            meshmsg_protocol::Outcome::Unknown,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::{EndpointAddr, SecretKey};
    use iroh_blobs::{ticket::BlobTicket, BlobFormat};
    use iroh_gossip::proto::TopicId;

    fn test_topic() -> TopicId {
        TopicId::from_bytes([7; 32])
    }
    #[test]
    fn concurrent_offer_listing_returns_same_request_advice() {
        let limit = Arc::new(Semaphore::new(1));
        let active_listing = try_admit_offer_listing(&limit).unwrap();
        let busy = try_admit_offer_listing(&limit).unwrap_err();
        assert_eq!(busy.code, meshmsg_protocol::ErrorCode::OffersBusy);
        assert_eq!(busy.message(), "Attachment listing is currently busy.");
        assert_eq!(busy.outcome, meshmsg_protocol::Outcome::NotStarted);
        assert_eq!(
            busy.retry_advice(),
            meshmsg_protocol::RetryAdvice::RetrySameRequest
        );
        drop(active_listing);
        assert!(try_admit_offer_listing(&limit).is_ok());
    }

    #[test]
    fn inputs_other_than_a_signed_offer_for_this_topic_are_rejected() {
        let provider = SecretKey::generate();
        let ticket = BlobTicket::new(
            EndpointAddr::new(provider.public()),
            iroh_blobs::Hash::new(b"content"),
            BlobFormat::Raw,
        );
        let offer_id = meshmsg_protocol::OperationId::new_random();
        let signed_offer = |topic| {
            let signed = protocol::encode_signed_offer(
                &provider,
                topic,
                &offer_id,
                crate::attachment::AttachmentOffer {
                    offer_id: offer_id.to_string(),
                    kind: crate::attachment::AttachmentKind::File,
                    name: "report.txt".to_owned(),
                    size: 7,
                    ticket: ticket.to_string(),
                },
                42,
            )
            .unwrap();
            data_encoding::BASE64URL_NOPAD.encode(&signed.encoded)
        };
        let parse = |token: String| {
            let operation_id = meshmsg_protocol::OperationId::new_random();
            let token = meshmsg_protocol::AttachmentToken::new(token).unwrap();
            (
                operation_id,
                parse_download_offer(operation_id, &token, test_topic()),
            )
        };

        for (label, token) in [
            ("raw blob ticket", ticket.to_string()),
            ("arbitrary text", "not-a-signed-offer".to_owned()),
            (
                "signed offer for another topic",
                signed_offer(TopicId::from_bytes([8; 32])),
            ),
        ] {
            let (operation_id, result) = parse(token);
            let error = result.expect_err(label);
            assert_eq!(
                error.code,
                meshmsg_protocol::ErrorCode::InvalidAttachmentOffer,
                "{label}"
            );
            assert_eq!(error.outcome, meshmsg_protocol::Outcome::NotStarted);
            assert_eq!(error.operation_id.as_ref(), Some(&operation_id));
        }

        let (_, result) = parse(signed_offer(test_topic()));
        let (offer, parsed_ticket) = result.expect("signed offer for this topic");
        assert_eq!(offer.name, "report.txt");
        assert_eq!(parsed_ticket, ticket);
    }
}

#[cfg(test)]
mod classification_tests {
    use super::*;
    use meshmsg_protocol::{ErrorCode, OperationId, Outcome, Response};

    fn classify(operation: StorageOperation, error: &anyhow::Error) -> (ErrorCode, Outcome) {
        let operation_id: OperationId = "22222222222222222222222222222222".parse().unwrap();
        let Response::Error(error) = storage_operation_error(operation, error, &operation_id)
        else {
            panic!("storage failures are always protocol errors");
        };
        assert_eq!(error.operation_id.as_ref(), Some(&operation_id));
        (error.code, error.outcome)
    }

    #[test]
    fn typed_storage_failures_keep_their_code_even_when_wrapped() {
        let typed = storage::AttachmentFailure::error(ErrorCode::AttachmentQuotaExceeded, "quota");
        assert_eq!(
            classify(StorageOperation::Share, &typed),
            (ErrorCode::AttachmentQuotaExceeded, Outcome::NotStarted)
        );
        let wrapped = typed.context("while pinning");
        assert_eq!(
            classify(StorageOperation::OffersPrune, &wrapped),
            (ErrorCode::AttachmentQuotaExceeded, Outcome::NotStarted)
        );
    }

    #[test]
    fn message_text_never_selects_a_protocol_code() {
        // A diagnostic that merely spells a code must fall back to the operation.
        let spoofed = anyhow::anyhow!("attachment_quota_exceeded: not a typed failure");
        assert_eq!(
            classify(StorageOperation::Share, &spoofed),
            (ErrorCode::ShareFailed, Outcome::Unknown)
        );
        assert_eq!(
            classify(StorageOperation::Download, &spoofed),
            (ErrorCode::DownloadFailed, Outcome::NotStarted)
        );
        assert_eq!(
            classify(StorageOperation::OffersRemove, &spoofed),
            (ErrorCode::AttachmentLifecycleInternal, Outcome::Unknown)
        );
    }
}
