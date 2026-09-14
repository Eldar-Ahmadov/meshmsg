use super::{storage, tags, transfer};
use crate::contracts;
use anyhow::Result;
use iroh_blobs::api::Store;
use std::{path::PathBuf, sync::Arc};
use tokio::sync::{broadcast, OwnedSemaphorePermit, Semaphore};

pub(crate) use storage::{AttachmentStorage, MAX_PRUNE_TAGS};
pub(crate) use transfer::{download_request_context, DownloadResources, ShareResources};

fn storage_operation_error(
    default_code: &str,
    error: &anyhow::Error,
    share: bool,
    operation_id: Option<&meshmsg_protocol::OperationId>,
    _offer_id: Option<&str>,
) -> meshmsg_protocol::Response {
    let has_code = |expected: &str| {
        error
            .chain()
            .any(|cause| cause.to_string().starts_with(expected))
    };
    let (code, outcome) = if has_code("attachment_quota_exceeded:") {
        (
            meshmsg_protocol::ErrorCode::AttachmentQuotaExceeded,
            meshmsg_protocol::Outcome::NotStarted,
        )
    } else if has_code("attachment_min_free_space:") {
        (
            meshmsg_protocol::ErrorCode::AttachmentMinFreeSpace,
            meshmsg_protocol::Outcome::NotStarted,
        )
    } else if has_code("attachment_tag_capacity:") {
        (
            meshmsg_protocol::ErrorCode::AttachmentTagCapacity,
            meshmsg_protocol::Outcome::NotStarted,
        )
    } else if has_code("attachment_storage_busy:") {
        (
            meshmsg_protocol::ErrorCode::AttachmentStorageBusy,
            meshmsg_protocol::Outcome::NotStarted,
        )
    } else {
        let code = match default_code {
            "share_failed" => meshmsg_protocol::ErrorCode::ShareFailed,
            "download_failed" => meshmsg_protocol::ErrorCode::DownloadFailed,
            value if value.starts_with("offers_") => {
                meshmsg_protocol::ErrorCode::AttachmentLifecycleInternal
            }
            _ => unreachable!("storage error code is canonical"),
        };
        (
            code,
            if share || default_code.starts_with("offers_") {
                meshmsg_protocol::Outcome::Unknown
            } else {
                meshmsg_protocol::Outcome::NotStarted
            },
        )
    };
    meshmsg_protocol::Response::Error(meshmsg_protocol::ProtocolError::new(
        operation_id.cloned(),
        code,
        outcome,
    ))
}

pub(crate) fn try_admit_transfer(
    limit: &Arc<Semaphore>,
    _busy_code: &'static str,
    _busy_message: &'static str,
) -> Result<OwnedSemaphorePermit, ()> {
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
        Err(_error) => contracts::protocol_error_response(
            meshmsg_protocol::ErrorCode::OffersFailed,
            meshmsg_protocol::Outcome::Unknown,
            None,
        ),
    }
}

pub(crate) async fn remove_offer_request(
    storage: AttachmentStorage,
    operation_id: &meshmsg_protocol::OperationId,
    offer_id: &meshmsg_protocol::OfferId,
    direction: Option<meshmsg_protocol::OfferDirection>,
    provider: Option<&meshmsg_protocol::PeerId>,
) -> meshmsg_protocol::Response {
    let direction = direction.map(|value| match value {
        meshmsg_protocol::OfferDirection::Incoming => "incoming",
        meshmsg_protocol::OfferDirection::Outgoing => "outgoing",
    });
    match storage
        .remove_at_cutoff(
            operation_id,
            Some(offer_id.as_str()),
            direction,
            provider.map(meshmsg_protocol::PeerId::as_str),
            None,
            None,
            MAX_PRUNE_TAGS,
            false,
        )
        .await
    {
        Ok(value) => value,
        Err(error) => storage_operation_error(
            "offers_remove_failed",
            &error,
            false,
            Some(operation_id),
            None,
        ),
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
    let direction = direction.map(|value| match value {
        meshmsg_protocol::OfferDirection::Incoming => "incoming",
        meshmsg_protocol::OfferDirection::Outgoing => "outgoing",
    });
    match storage
        .remove_at_cutoff(
            operation_id,
            None,
            direction,
            None,
            Some(older_than_secs),
            Some(cutoff_ms),
            max_delete,
            dry_run,
        )
        .await
    {
        Ok(value) => value,
        Err(error) => storage_operation_error(
            "offers_prune_failed",
            &error,
            false,
            Some(operation_id),
            None,
        ),
    }
}

pub(crate) async fn share_request(
    resources: ShareResources,
    operation_id: meshmsg_protocol::OperationId,
    source_digest: meshmsg_protocol::ContentDigest,
    path: PathBuf,
    max_attachment_bytes: u64,
) -> meshmsg_protocol::Response {
    let gate = resources.storage.gate.clone();
    match gate.acquire_owned().await {
        Ok(_permit) => match transfer::share_attachment(
            resources,
            operation_id.clone(),
            source_digest,
            path,
            max_attachment_bytes,
        )
        .await
        {
            Ok(value) => value,
            Err(error) => {
                storage_operation_error("share_failed", &error, true, Some(&operation_id), None)
            }
        },
        Err(_) => meshmsg_protocol::Response::Error(meshmsg_protocol::ProtocolError::new(
            Some(operation_id),
            meshmsg_protocol::ErrorCode::AttachmentStorageShutdown,
            meshmsg_protocol::Outcome::Unknown,
        )),
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn download_request(
    resources: DownloadResources,
    events: broadcast::Sender<meshmsg_protocol::Event>,
    operation_id: meshmsg_protocol::OperationId,
    offer: meshmsg_protocol::AttachmentToken,
    output: PathBuf,
    max_attachment_bytes: u64,
    _mode: meshmsg_protocol::DownloadMode,
) -> meshmsg_protocol::Response {
    if transfer::validate_raw_ticket_request_name(offer.as_str(), &output, resources.topic).is_err()
    {
        return meshmsg_protocol::Response::Error(meshmsg_protocol::ProtocolError::new(
            Some(operation_id.clone()),
            meshmsg_protocol::ErrorCode::InvalidAttachmentOffer,
            meshmsg_protocol::Outcome::NotStarted,
        ));
    }
    let gate = resources.storage.gate.clone();
    match gate.acquire_owned().await {
        Ok(_permit) => {
            let _ = events.send(meshmsg_protocol::Event::DownloadStarted {
                operation_id: operation_id.clone(),
                output: output.clone(),
            });
            match transfer::download_attachment(
                resources,
                events,
                &operation_id,
                offer.into_string(),
                output,
                max_attachment_bytes,
            )
            .await
            {
                Ok(value) => value,
                Err(error) => storage_operation_error(
                    "download_failed",
                    &error,
                    false,
                    Some(&operation_id),
                    None,
                ),
            }
        }
        Err(_) => meshmsg_protocol::Response::Error(meshmsg_protocol::ProtocolError::new(
            Some(operation_id),
            meshmsg_protocol::ErrorCode::AttachmentStorageShutdown,
            meshmsg_protocol::Outcome::Unknown,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attachment::DEFAULT_MAX_ATTACHMENT_BYTES;
    use iroh::{
        address_lookup::memory::MemoryLookup, endpoint::presets, Endpoint, EndpointAddr, SecretKey,
    };
    use iroh_blobs::{
        store::fs::{options::Options as FsStoreOptions, FsStore},
        ticket::BlobTicket,
        BlobFormat,
    };
    use iroh_gossip::proto::TopicId;

    fn test_topic() -> TopicId {
        TopicId::from_bytes([7; 32])
    }
    fn response_error(response: &meshmsg_protocol::Response) -> &meshmsg_protocol::ProtocolError {
        match response {
            meshmsg_protocol::Response::Error(error) => error,
            _ => panic!("expected protocol error"),
        }
    }
    async fn lifecycle_test_store(label: &str) -> (PathBuf, PathBuf, Store) {
        let root =
            std::env::temp_dir().join(format!("meshmsg-runtime-{label}-{}", rand::random::<u64>()));
        let state = root.join("state");
        let blob_root = root.join("blobs");
        std::fs::create_dir_all(&state).unwrap();
        let store: Store =
            FsStore::load_with_opts(blob_root.join("blobs.db"), FsStoreOptions::new(&blob_root))
                .await
                .unwrap()
                .into();
        (root, state, store)
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

    #[tokio::test]
    async fn raw_ticket_output_name_is_rejected_before_download_side_effects() {
        let (root, state, store) = lifecycle_test_store("invalid-raw-name").await;
        let storage = AttachmentStorage::open(store.clone(), root.join("blobs"), &state, 100, 0, 0)
            .await
            .unwrap();
        // A storage-gate failure would win if validation happened after storage
        // admission, making this a sentinel for pre-work rejection ordering.
        storage.gate.close();
        let secret = SecretKey::generate();
        let endpoint = Endpoint::builder(presets::N0)
            .secret_key(secret)
            .bind()
            .await
            .unwrap();
        let provider = SecretKey::generate().public();
        let ticket = BlobTicket::new(
            EndpointAddr::new(provider),
            iroh_blobs::Hash::new(b"raw ticket"),
            BlobFormat::Raw,
        );
        let output = root.join(format!("bad:{}", rand::random::<u64>()));
        let (events, mut event_rx) = broadcast::channel(4);
        let operation_id = meshmsg_protocol::OperationId::new_random();
        let response = download_request(
            DownloadResources {
                downloader: store.downloader(&endpoint),
                endpoint: endpoint.clone(),
                lookup: MemoryLookup::new(),
                store: store.clone(),
                storage: storage.clone(),
                topic: test_topic(),
            },
            events,
            operation_id.clone(),
            meshmsg_protocol::AttachmentToken::new(ticket.to_string()).unwrap(),
            output.clone(),
            DEFAULT_MAX_ATTACHMENT_BYTES,
            meshmsg_protocol::DownloadMode::Install,
        )
        .await;

        let error = response_error(&response);
        assert_eq!(
            error.code,
            meshmsg_protocol::ErrorCode::InvalidAttachmentOffer
        );
        assert_eq!(error.outcome, meshmsg_protocol::Outcome::NotStarted);
        assert_eq!(error.operation_id.as_ref(), Some(&operation_id));
        assert!(event_rx.try_recv().is_err(), "download event was emitted");
        assert!(!output.exists(), "invalid output was touched");
        assert_eq!(storage.status().tags, 0, "attachment storage was mutated");

        endpoint.close().await;
        drop(storage);
        drop(store);
        let _ = std::fs::remove_dir_all(root);
    }
}
