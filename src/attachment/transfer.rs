use super::{
    protocol,
    storage::AttachmentStorage,
    tags::{
        inbound_blob_tag, outbound_blob_tag, parse_pinned_blob_tag, protocol_attachment_kind,
        PinnedBlobTag,
    },
    AttachmentKind, AttachmentOffer,
};
use crate::{attachment, ids::id_string};
use anyhow::{Context, Result};
use data_encoding::BASE64URL_NOPAD;
use futures_util::StreamExt;
use iroh::{address_lookup::memory::MemoryLookup, Endpoint, SecretKey};
use iroh_blobs::{
    api::{
        downloader::{DownloadProgressItem, Downloader},
        Store,
    },
    get::request::get_verified_size,
    ticket::BlobTicket,
    BlobFormat,
};
use iroh_gossip::{api::GossipSender, proto::TopicId};
use std::{
    io::Read as _,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::broadcast;

const ENDPOINT_ONLINE_TIMEOUT: Duration = Duration::from_secs(30);
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(60 * 60);
const DOWNLOAD_PROGRESS_STEP: u64 = 8 * 1024 * 1024;

fn unix_timestamp_ms() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64)
}

fn hash_file(path: &Path) -> Result<iroh_blobs::Hash> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(iroh_blobs::Hash::from_bytes(*hasher.finalize().as_bytes()))
}

pub(crate) struct ShareResources {
    pub(crate) store: Store,
    pub(crate) storage: AttachmentStorage,
    pub(crate) endpoint: Endpoint,
    pub(crate) secret: SecretKey,
    pub(crate) topic: TopicId,
    pub(crate) sender: GossipSender,
    pub(crate) state_dir: PathBuf,
}

pub(super) async fn share_attachment(
    resources: ShareResources,
    operation_id: meshmsg_protocol::OperationId,
    source_digest: meshmsg_protocol::ContentDigest,
    path: PathBuf,
    max_attachment_bytes: u64,
) -> Result<meshmsg_protocol::Response> {
    let ShareResources {
        store,
        storage,
        endpoint,
        secret,
        topic,
        sender,
        state_dir,
    } = resources;
    storage.preflight_free_space(0).await?;
    let metadata = tokio::fs::symlink_metadata(&path)
        .await
        .with_context(|| format!("inspect shared path {}", path.display()))?;
    anyhow::ensure!(
        !metadata.file_type().is_symlink(),
        "symbolic links cannot be shared"
    );
    let directory = metadata.is_dir();
    anyhow::ensure!(
        directory || metadata.is_file(),
        "shared path must be a regular file or directory"
    );
    let name = attachment::file_name(&path, directory)?;
    let staging = attachment::staging_file_near(
        &state_dir.join("attachment-stage"),
        if directory { ".tar" } else { ".blob" },
    )?;
    let source = path.clone();
    let expected_digest = source_digest.to_string();
    let staged = tokio::task::spawn_blocking(move || {
        let staged = attachment::StagedFile::new(staging);
        let size = if directory {
            attachment::create_deterministic_tar(&source, staged.path(), max_attachment_bytes)?
        } else {
            attachment::copy_bounded(&source, staged.path(), max_attachment_bytes)?
        };
        let actual_digest =
            attachment::staged_share_digest(staged.path(), directory, max_attachment_bytes)?;
        anyhow::ensure!(
            actual_digest == expected_digest,
            "shared source digest does not match the staged content"
        );
        Ok::<_, anyhow::Error>((size, staged))
    })
    .await
    .context("attachment staging task failed")??;
    let (size, staged) = staged;
    storage.preflight_free_space(size).await?;
    let staged_path = staged.path().to_owned();
    let content_hash = tokio::task::spawn_blocking(move || hash_file(&staged_path))
        .await
        .context("attachment hash task failed")??;
    let offer_id = operation_id.to_string();
    let kind = if directory {
        AttachmentKind::DirectoryTarV1
    } else {
        AttachmentKind::File
    };
    let imported = store
        .blobs()
        .add_path(staged.path())
        .temp_tag()
        .await
        .context("import attachment with a temporary pin")?;
    drop(staged);
    anyhow::ensure!(
        imported.format() == BlobFormat::Raw && imported.hash() == content_hash,
        "attachment_lifecycle_internal: imported attachment identity is unsupported or changed"
    );

    let publish_result = async {
        let ticket = BlobTicket::new(endpoint.addr(), imported.hash(), imported.format());
        let offer = AttachmentOffer {
            offer_id,
            kind,
            name,
            size,
            ticket: ticket.to_string(),
        };
        let timestamp_ms = unix_timestamp_ms()?;
        let signed =
            protocol::encode_signed_offer(&secret, topic, &operation_id, offer, timestamp_ms)?;
        let timestamp_ms = signed.timestamp_ms;
        let encoded = signed.encoded;
        let message_id = signed.message_id;
        let offer = signed.offer;
        let tag_name = outbound_blob_tag(&offer.offer_id, offer.kind, &offer.name);
        storage
            .commit_pin(
                &tag_name,
                PinnedBlobTag {
                    direction: "outgoing",
                    offer_id: offer.offer_id.clone(),
                    provider: None,
                    name: offer.name.clone(),
                    kind: offer.kind,
                },
                imported.hash_and_format(),
                size,
                &|_| Ok(()),
            )
            .await
            .context("commit attachment pin before publication")?;
        // From this point an error cannot prove that no peer observed the offer.
        // Retain the committed pin for retry and remote availability.
        sender
            .broadcast(encoded.clone())
            .await
            .context("broadcast attachment offer after durable pin")?;
        Ok(meshmsg_protocol::Response::AttachmentShared(
            meshmsg_protocol::AttachmentShared {
                operation_id: operation_id.clone(),
                from: signed
                    .from
                    .to_string()
                    .parse()
                    .expect("public key is canonical"),
                message_id: id_string(&message_id)
                    .parse()
                    .expect("message ID is canonical"),
                timestamp_ms,
                offer_id: offer.offer_id.parse().expect("validated offer ID"),
                source_digest,
                kind: protocol_attachment_kind(offer.kind),
                name: meshmsg_protocol::AttachmentName::new(offer.name)
                    .expect("validated attachment name"),
                size: offer.size,
                ticket: meshmsg_protocol::AttachmentToken::new(offer.ticket)
                    .expect("validated attachment ticket"),
                offer: meshmsg_protocol::AttachmentToken::new(BASE64URL_NOPAD.encode(&encoded))
                    .expect("bounded signed offer"),
                delivery_acknowledged: false,
            },
        ))
    }
    .await;

    publish_result
}

fn raw_ticket_offer_id(ticket: &BlobTicket) -> String {
    use sha2::{Digest, Sha256};

    let mut digest = Sha256::new();
    digest.update(b"meshmsg-raw-ticket-pin-v1\0");
    digest.update(ticket.addr().id.to_string().as_bytes());
    digest.update(b"\0");
    digest.update(ticket.hash().to_string().as_bytes());
    digest.update(b"\0raw");
    id_string(
        &digest.finalize()[..16]
            .try_into()
            .expect("fixed digest prefix"),
    )
}

fn raw_ticket_blob_tag(ticket: &BlobTicket) -> String {
    inbound_blob_tag(
        ticket.addr().id,
        &raw_ticket_offer_id(ticket),
        AttachmentKind::File,
        "raw-ticket.blob",
    )
}

fn raw_ticket_attachment_name(output: &Path) -> Result<meshmsg_protocol::AttachmentName> {
    let name = output
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("attachment");
    meshmsg_protocol::AttachmentName::new(name.to_owned()).map_err(anyhow::Error::from)
}

pub(super) fn validate_raw_ticket_request_name(
    token: &str,
    output: &Path,
    topic: TopicId,
) -> Result<()> {
    if protocol::parse_signed_offer_token(token, topic).is_ok() {
        return Ok(());
    }
    let ticket: BlobTicket = token.parse()?;
    anyhow::ensure!(
        ticket.format() == BlobFormat::Raw,
        "only raw blob tickets are supported"
    );
    raw_ticket_attachment_name(output)?;
    Ok(())
}

pub(crate) fn download_request_context(
    operation_id: &meshmsg_protocol::OperationId,
    token: &str,
    output: &Path,
    topic: TopicId,
) -> Result<crate::ipc::DownloadRequestContext> {
    let (offer_id, provider, kind, name, declared_size) =
        match protocol::parse_signed_offer_token(token, topic) {
            Ok((offer, ticket)) => (
                offer.offer_id,
                ticket.addr().id.to_string(),
                match offer.kind {
                    AttachmentKind::File => "file".to_owned(),
                    AttachmentKind::DirectoryTarV1 => "directory_tar_v1".to_owned(),
                },
                offer.name,
                Some(offer.size),
            ),
            Err(signed_error) => {
                let ticket: BlobTicket = token.parse().map_err(|_| signed_error)?;
                anyhow::ensure!(
                    ticket.format() == BlobFormat::Raw,
                    "only raw blob tickets are supported"
                );
                (
                    raw_ticket_offer_id(&ticket),
                    ticket.addr().id.to_string(),
                    "file".to_owned(),
                    raw_ticket_attachment_name(output)?.into_string(),
                    None,
                )
            }
        };
    Ok(crate::ipc::DownloadRequestContext {
        operation_id: operation_id.clone(),
        token_digest: crate::ipc::download_token_digest(token),
        offer_id: offer_id.parse()?,
        provider: provider.parse()?,
        kind: kind
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid attachment kind"))?,
        name: meshmsg_protocol::AttachmentName::new(name)?,
        declared_size,
        output: output.to_path_buf(),
        mode: meshmsg_protocol::DownloadMode::Install,
    })
}

fn validate_declared_attachment_size(declared_size: Option<u64>, actual_size: u64) -> Result<()> {
    if let Some(declared_size) = declared_size {
        anyhow::ensure!(
            actual_size == declared_size,
            "provider size does not match the signed offer"
        );
    }
    Ok(())
}

pub(crate) struct DownloadResources {
    pub(crate) store: Store,
    pub(crate) storage: AttachmentStorage,
    pub(crate) topic: TopicId,
    pub(crate) downloader: Downloader,
    pub(crate) endpoint: Endpoint,
    pub(crate) lookup: MemoryLookup,
}

#[derive(Debug)]
struct DownloadCommitOutcome {
    destination_synced: bool,
    cleanup_complete: bool,
    warnings: Vec<String>,
}

fn bounded_download_warning(value: impl AsRef<str>) -> String {
    let mut warning = String::new();
    for character in value.as_ref().chars() {
        let character = if character.is_control() {
            ' '
        } else {
            character
        };
        if warning.len() + character.len_utf8() > meshmsg_protocol::MAX_PUBLIC_TEXT_BYTES {
            break;
        }
        warning.push(character);
    }
    if warning.is_empty() {
        warning.push_str("download durability warning");
    }
    warning
}

fn push_download_warning(warnings: &mut Vec<String>, value: impl AsRef<str>) {
    if warnings.len() < meshmsg_protocol::MAX_WARNINGS {
        warnings.push(bounded_download_warning(value));
    }
}

struct DownloadCommit<'a> {
    store: &'a Store,
    tag_name: &'a [u8],
    hash_and_format: iroh_blobs::HashAndFormat,
    staging: attachment::StagedFile,
    output: &'a Path,
    kind: AttachmentKind,
    max_attachment_bytes: u64,
    pin_already_committed: bool,
}

/// Commits the local half of a download. The named blob pin is made durable
/// before the no-clobber destination operation. Once installation succeeds,
/// subsequent sync/cleanup errors are partial-success metadata, never a false
/// `download_failed` result that would make a safe retry impossible.
async fn commit_download(
    commit: DownloadCommit<'_>,
    fault: &(dyn Fn(&'static str) -> Result<()> + Sync),
) -> Result<DownloadCommitOutcome> {
    let DownloadCommit {
        store,
        tag_name,
        hash_and_format,
        staging,
        output,
        kind,
        max_attachment_bytes,
        pin_already_committed,
    } = commit;
    if !pin_already_committed {
        fault("blob_tag_persist")?;
        store.tags().set(tag_name, hash_and_format).await?;
        fault("after_blob_tag_persist")?;
        fault("blob_tag_sync")?;
        store.sync_db().await?;
        fault("after_blob_tag_sync")?;
    }

    fault("destination_install")?;
    let directory = kind == AttachmentKind::DirectoryTarV1;
    let output_for_task = output.to_owned();
    let staging = tokio::task::spawn_blocking(move || {
        if directory {
            attachment::extract_staged_tar_no_clobber(
                &staging,
                &output_for_task,
                max_attachment_bytes,
            )?;
        } else {
            attachment::link_file_no_clobber(staging.path(), &output_for_task)?;
        }
        Ok::<_, anyhow::Error>(staging)
    })
    .await
    .context("install task failed")??;

    // The destination now exists. Do not return Err below this line: no-clobber
    // makes a retry unsuitable, so accurately report any durability/cleanup
    // degradation as a successful installation with warnings.
    let mut warnings = Vec::new();
    if let Err(error) = fault("after_destination_install") {
        push_download_warning(
            &mut warnings,
            format!("interrupted after destination installation: {error}"),
        );
    }
    let content_synced = match fault("destination_sync") {
        Ok(()) => {
            let output_for_task = output.to_owned();
            match tokio::task::spawn_blocking(move || {
                attachment::sync_installed_destination(&output_for_task, directory)
            })
            .await
            {
                Ok(Ok(())) => true,
                Ok(Err(error)) => {
                    push_download_warning(
                        &mut warnings,
                        format!("installed content sync failed: {error}"),
                    );
                    false
                }
                Err(error) => {
                    push_download_warning(
                        &mut warnings,
                        format!("installed content sync task failed: {error}"),
                    );
                    false
                }
            }
        }
        Err(error) => {
            push_download_warning(
                &mut warnings,
                format!("installed content sync failed: {error}"),
            );
            false
        }
    };
    let parent_synced = match fault("parent_sync") {
        Ok(()) => {
            let output_for_task = output.to_owned();
            match tokio::task::spawn_blocking(move || {
                attachment::sync_output_parent(&output_for_task)
            })
            .await
            {
                Ok(Ok(())) => true,
                Ok(Err(error)) => {
                    push_download_warning(
                        &mut warnings,
                        format!("installed output parent sync failed: {error}"),
                    );
                    false
                }
                Err(error) => {
                    push_download_warning(
                        &mut warnings,
                        format!("installed output parent sync task failed: {error}"),
                    );
                    false
                }
            }
        }
        Err(error) => {
            push_download_warning(
                &mut warnings,
                format!("installed output parent sync failed: {error}"),
            );
            false
        }
    };
    let destination_synced = content_synced && parent_synced;
    if let Err(error) = fault("after_destination_sync") {
        push_download_warning(
            &mut warnings,
            format!("interrupted after destination sync: {error}"),
        );
    }

    let cleanup_complete = match fault("staging_cleanup") {
        Ok(()) => match tokio::task::spawn_blocking(move || staging.cleanup()).await {
            Ok(Ok(())) => match fault("after_staging_cleanup") {
                Ok(()) => true,
                Err(error) => {
                    push_download_warning(
                        &mut warnings,
                        format!("interrupted after staging cleanup: {error}"),
                    );
                    true
                }
            },
            Ok(Err(error)) => {
                push_download_warning(
                    &mut warnings,
                    format!("installed output staging cleanup failed: {error}"),
                );
                false
            }
            Err(error) => {
                push_download_warning(
                    &mut warnings,
                    format!("installed output cleanup task failed: {error}"),
                );
                false
            }
        },
        Err(error) => {
            push_download_warning(
                &mut warnings,
                format!("installed output staging cleanup failed: {error}"),
            );
            // Dropping the guard makes a final best-effort cleanup attempt.
            drop(staging);
            false
        }
    };

    Ok(DownloadCommitOutcome {
        destination_synced,
        cleanup_complete,
        warnings,
    })
}

pub(super) async fn download_attachment(
    resources: DownloadResources,
    events: broadcast::Sender<meshmsg_protocol::Event>,
    operation_id: &meshmsg_protocol::OperationId,
    offer_token: String,
    output: PathBuf,
    max_attachment_bytes: u64,
) -> Result<meshmsg_protocol::Response> {
    let DownloadResources {
        store,
        storage,
        topic,
        downloader,
        endpoint,
        lookup,
    } = resources;
    let token_digest = crate::ipc::download_token_digest(&offer_token);
    let parsed_signed = protocol::parse_signed_offer_token(&offer_token, topic);
    let (offer, ticket, declared_size, raw_ticket) = match parsed_signed {
        Ok((offer, ticket)) => {
            let declared_size = Some(offer.size);
            (offer, ticket, declared_size, false)
        }
        Err(signed_error) => {
            let ticket: BlobTicket = offer_token.parse().map_err(|_| signed_error)?;
            anyhow::ensure!(
                ticket.format() == BlobFormat::Raw,
                "only raw blob tickets are supported"
            );
            let name = raw_ticket_attachment_name(&output)?.into_string();
            (
                AttachmentOffer {
                    offer_id: raw_ticket_offer_id(&ticket),
                    kind: AttachmentKind::File,
                    name,
                    size: 0,
                    ticket: ticket.to_string(),
                },
                ticket,
                None,
                true,
            )
        }
    };
    // All names transitively derived from IPC input are validated before any
    // filesystem, blob-store, or network work starts.
    let response_name = meshmsg_protocol::AttachmentName::new(offer.name.clone())?;
    storage.preflight_free_space(0).await?;
    anyhow::ensure!(
        !output.exists(),
        "output already exists: {}",
        output.display()
    );
    // Validate the existing durability boundary before network or store work.
    let staging_path = attachment::staging_file_near(&output, ".download")?;
    anyhow::ensure!(
        ticket.format() == BlobFormat::Raw,
        "only raw attachment blob formats are supported by lifecycle storage"
    );
    if let Some(declared_size) = declared_size {
        anyhow::ensure!(
            declared_size <= max_attachment_bytes,
            "attachment exceeds the configured size limit of {max_attachment_bytes} bytes"
        );
    }
    lookup.add_endpoint_info(ticket.addr().clone());
    // Protect complete or partial content from periodic GC until installation
    // and creation of the durable inbound pin have both completed.
    let _download_pin = store
        .tags()
        .temp_tag(ticket.hash_and_format())
        .await
        .context("temporarily pin attachment download")?;
    let existing_size = match store.blobs().status(ticket.hash()).await? {
        iroh_blobs::api::proto::BlobStatus::Complete { size } => Some(size),
        _ => None,
    };
    let size = if let Some(size) = existing_size {
        size
    } else {
        let connection = tokio::time::timeout(
            ENDPOINT_ONLINE_TIMEOUT,
            endpoint.connect(ticket.addr().clone(), iroh_blobs::ALPN),
        )
        .await
        .context("attachment size check timed out")?
        .context("connect to attachment provider")?;
        let (verified_size, _) = tokio::time::timeout(
            ENDPOINT_ONLINE_TIMEOUT,
            get_verified_size(&connection, &ticket.hash()),
        )
        .await
        .context("attachment size check timed out")?
        .context("verify attachment size")?;
        anyhow::ensure!(
            verified_size <= max_attachment_bytes,
            "attachment exceeds the configured size limit of {max_attachment_bytes} bytes"
        );
        validate_declared_attachment_size(declared_size, verified_size)?;
        storage.preflight_free_space(verified_size).await?;
        let download = downloader.download(ticket.hash_and_format(), Some(ticket.addr().id));
        let mut progress = download
            .stream()
            .await
            .context("start attachment download")?;
        let transfer = async {
            let mut next_report = DOWNLOAD_PROGRESS_STEP;
            while let Some(item) = progress.next().await {
                match item {
                    DownloadProgressItem::Error(error) => {
                        anyhow::bail!("attachment download failed: {error}")
                    }
                    DownloadProgressItem::DownloadError => {
                        anyhow::bail!("attachment download failed")
                    }
                    DownloadProgressItem::Progress(received_bytes)
                        if verified_size > 0
                            && (received_bytes >= next_report
                                || received_bytes == verified_size) =>
                    {
                        let _ = events.send(meshmsg_protocol::Event::DownloadProgress {
                            operation_id: operation_id.clone(),
                            received_bytes: received_bytes.min(verified_size),
                            total_bytes: verified_size,
                            output: output.clone(),
                        });
                        next_report = received_bytes
                            .saturating_div(DOWNLOAD_PROGRESS_STEP)
                            .saturating_add(1)
                            .saturating_mul(DOWNLOAD_PROGRESS_STEP);
                    }
                    _ => {}
                }
            }
            Ok::<(), anyhow::Error>(())
        };
        tokio::time::timeout(TRANSFER_TIMEOUT, transfer)
            .await
            .context("attachment download timed out")??;
        match store.blobs().status(ticket.hash()).await? {
            iroh_blobs::api::proto::BlobStatus::Complete { size } => size,
            _ => anyhow::bail!("download did not produce a complete blob"),
        }
    };
    if size == 0 {
        let _ = events.send(meshmsg_protocol::Event::DownloadProgress {
            operation_id: operation_id.clone(),
            received_bytes: 0,
            total_bytes: 0,
            output: output.clone(),
        });
    }
    anyhow::ensure!(
        size <= max_attachment_bytes,
        "download exceeds the configured size limit of {max_attachment_bytes} bytes"
    );
    validate_declared_attachment_size(declared_size, size)
        .context("validate downloaded attachment size")?;
    let staging = attachment::StagedFile::new(staging_path);
    let export_store = store.clone();
    let export_hash = ticket.hash();
    let staging = tokio::spawn(async move {
        export_store
            .blobs()
            .export(export_hash, staging.path())
            .await
            .context("export downloaded attachment")?;
        attachment::sync_staged_file(staging.path())?;
        Ok::<_, anyhow::Error>(staging)
    })
    .await
    .context("attachment export task failed")??;
    let tag_name = if raw_ticket {
        raw_ticket_blob_tag(&ticket)
    } else {
        inbound_blob_tag(ticket.addr().id, &offer.offer_id, offer.kind, &offer.name)
    };
    let parsed_tag = parse_pinned_blob_tag(tag_name.as_bytes())
        .context("generated attachment tag is invalid")?;
    let newly_created = storage
        .commit_pin(
            &tag_name,
            parsed_tag,
            ticket.hash_and_format(),
            size,
            &|_| Ok(()),
        )
        .await
        .context("commit downloaded attachment pin")?;
    let commit_result = commit_download(
        DownloadCommit {
            store: &store,
            tag_name: tag_name.as_bytes(),
            hash_and_format: ticket.hash_and_format(),
            staging,
            output: &output,
            kind: offer.kind,
            max_attachment_bytes,
            pin_already_committed: true,
        },
        &|_| Ok(()),
    )
    .await;
    let commit = match commit_result {
        Ok(commit) => commit,
        Err(error) => {
            storage
                .rollback_committed_pin(&tag_name, newly_created)
                .await
                .context("roll back pin after download installation failure")?;
            return Err(error);
        }
    };
    Ok(meshmsg_protocol::Response::DownloadComplete(
        meshmsg_protocol::DownloadResult {
            operation_id: operation_id.clone(),
            token_digest,
            offer_id: offer.offer_id.parse().expect("validated offer ID"),
            kind: protocol_attachment_kind(offer.kind),
            name: response_name,
            size,
            from: ticket
                .addr()
                .id
                .to_string()
                .parse()
                .expect("public key is canonical"),
            output,
            mode: meshmsg_protocol::DownloadMode::Install,
            installed: true,
            pinned: true,
            destination_synced: commit.destination_synced,
            cleanup_complete: commit.cleanup_complete,
            warnings: commit.warnings,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::super::tags;
    use super::*;
    use crate::attachment::DEFAULT_MAX_ATTACHMENT_BYTES;
    use crate::contracts;
    use iroh::SecretKey;
    use iroh_blobs::store::fs::{options::Options as FsStoreOptions, FsStore};
    #[test]
    fn arbitrary_download_warning_is_sanitized_to_protocol_bounds() {
        let warning = bounded_download_warning(format!("failure\n{}", "é".repeat(2_000)));
        assert!(!warning.is_empty());
        assert!(warning.len() <= meshmsg_protocol::MAX_PUBLIC_TEXT_BYTES);
        assert!(!warning.chars().any(char::is_control));
    }

    #[test]
    fn signed_zero_size_is_validated_but_raw_ticket_size_is_unspecified() {
        validate_declared_attachment_size(Some(0), 0).unwrap();
        assert!(validate_declared_attachment_size(Some(0), 1).is_err());
        validate_declared_attachment_size(None, 1).unwrap();
    }

    #[tokio::test]
    async fn download_commit_process_exit_child() {
        let Ok(root) = std::env::var("MESHMSG_COMMIT_CRASH_ROOT") else {
            return;
        };
        let phase = std::env::var("MESHMSG_COMMIT_CRASH_PHASE").unwrap();
        let root = PathBuf::from(root);
        std::fs::create_dir_all(&root).unwrap();
        let options = FsStoreOptions::new(&root.join("store"));
        let store: Store = FsStore::load_with_opts(root.join("blobs.db"), options)
            .await
            .unwrap()
            .into();
        let provider = SecretKey::from_bytes(&[9; 32]).public();
        let ticket = BlobTicket::new(
            iroh::EndpointAddr::new(provider),
            iroh_blobs::Hash::new(b"crash payload"),
            BlobFormat::Raw,
        );
        let tag = raw_ticket_blob_tag(&ticket);
        let staging = root.join(".meshmsg-part-1111111111111111.download");
        std::fs::write(&staging, b"crash payload").unwrap();
        let output = root.join("output");
        let _ = commit_download(
            DownloadCommit {
                store: &store,
                tag_name: tag.as_bytes(),
                hash_and_format: ticket.hash_and_format(),
                staging: attachment::StagedFile::new(staging),
                output: &output,
                kind: AttachmentKind::File,
                max_attachment_bytes: DEFAULT_MAX_ATTACHMENT_BYTES,
                pin_already_committed: false,
            },
            &|boundary| {
                if boundary == phase {
                    std::process::exit(86);
                }
                Ok(())
            },
        )
        .await;
        panic!("child did not exit at {phase}");
    }

    #[tokio::test]
    async fn process_exit_recovery_reopens_raw_pin_retries_without_duplicates_and_tracks_leftovers()
    {
        for phase in ["after_blob_tag_sync", "after_destination_install"] {
            let root = std::env::temp_dir().join(format!(
                "meshmsg-commit-process-exit-{phase}-{}",
                rand::random::<u64>()
            ));
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg("attachment::transfer::tests::download_commit_process_exit_child")
                .arg("--nocapture")
                .env("MESHMSG_COMMIT_CRASH_ROOT", &root)
                .env("MESHMSG_COMMIT_CRASH_PHASE", phase)
                .status()
                .unwrap();
            assert_eq!(status.code(), Some(86));

            let provider = SecretKey::from_bytes(&[9; 32]).public();
            let ticket = BlobTicket::new(
                iroh::EndpointAddr::new(provider),
                iroh_blobs::Hash::new(b"crash payload"),
                BlobFormat::Raw,
            );
            let offer_id = raw_ticket_offer_id(&ticket);
            assert!(contracts::valid_operation_id(&offer_id));
            assert_eq!(offer_id, raw_ticket_offer_id(&ticket));
            let tag = raw_ticket_blob_tag(&ticket);
            let options = FsStoreOptions::new(&root.join("store"));
            let store: Store = FsStore::load_with_opts(root.join("blobs.db"), options)
                .await
                .unwrap()
                .into();
            let (pins, _, item_errors) = tags::list_pinned_blobs(&store).await.unwrap();
            assert!(
                pins.is_empty(),
                "missing blob content must not be advertised"
            );
            assert_eq!(item_errors, 1);
            assert_eq!(
                store
                    .tags()
                    .get(tag.as_bytes())
                    .await
                    .unwrap()
                    .unwrap()
                    .hash_and_format(),
                ticket.hash_and_format()
            );
            let output = root.join("output");
            let staging = root.join(".meshmsg-part-1111111111111111.download");
            assert_eq!(output.exists(), phase == "after_destination_install");
            assert!(staging.exists(), "abrupt exit should bypass cleanup guards");
            // Arbitrary output scopes are not scanned by state startup cleanup.
            assert_eq!(attachment::cleanup_stale_state_staging(&root).unwrap(), 0);
            assert!(staging.exists());

            if phase == "after_blob_tag_sync" {
                let outcome = commit_download(
                    DownloadCommit {
                        store: &store,
                        tag_name: tag.as_bytes(),
                        hash_and_format: ticket.hash_and_format(),
                        staging: attachment::StagedFile::new(staging.clone()),
                        output: &output,
                        kind: AttachmentKind::File,
                        max_attachment_bytes: DEFAULT_MAX_ATTACHMENT_BYTES,
                        pin_already_committed: false,
                    },
                    &|_| Ok(()),
                )
                .await
                .unwrap();
                assert!(outcome.destination_synced);
                assert!(outcome.cleanup_complete);
                assert_eq!(
                    store
                        .tags()
                        .get(tag.as_bytes())
                        .await
                        .unwrap()
                        .unwrap()
                        .hash_and_format(),
                    ticket.hash_and_format(),
                    "raw retry changed the permanent pin"
                );
                assert_eq!(std::fs::read(&output).unwrap(), b"crash payload");
                assert!(!staging.exists());
            }
            drop(store);
            let _ = std::fs::remove_dir_all(root);
        }
    }

    #[tokio::test]
    async fn download_commit_fault_boundaries_preserve_retry_and_partial_success_semantics() {
        for boundary in [
            "blob_tag_persist",
            "after_blob_tag_persist",
            "blob_tag_sync",
            "after_blob_tag_sync",
            "destination_install",
        ] {
            let root = std::env::temp_dir().join(format!(
                "meshmsg-download-commit-{boundary}-{}",
                rand::random::<u64>()
            ));
            std::fs::create_dir_all(&root).unwrap();
            let options = FsStoreOptions::new(&root.join("store"));
            let store: Store = FsStore::load_with_opts(root.join("blobs.db"), options)
                .await
                .unwrap()
                .into();
            let hash_and_format = iroh_blobs::HashAndFormat::raw(iroh_blobs::Hash::new(b"blob"));
            let provider = SecretKey::generate().public();
            let provider_text = provider.to_string();
            let tag = inbound_blob_tag(
                provider,
                "0123456789abcdef0123456789abcdef",
                AttachmentKind::File,
                "retry.txt",
            );
            let output = root.join("output");
            let staging = root.join("first.download");
            std::fs::write(&staging, b"blob").unwrap();
            let injected = |current| {
                if current == boundary {
                    anyhow::bail!("injected {boundary} failure")
                }
                Ok(())
            };

            let error = commit_download(
                DownloadCommit {
                    store: &store,
                    tag_name: tag.as_bytes(),
                    hash_and_format,
                    staging: attachment::StagedFile::new(staging.clone()),
                    output: &output,
                    kind: AttachmentKind::File,
                    max_attachment_bytes: DEFAULT_MAX_ATTACHMENT_BYTES,
                    pin_already_committed: false,
                },
                &injected,
            )
            .await
            .unwrap_err();
            assert!(error.to_string().contains("injected"));
            assert!(
                !output.exists(),
                "{boundary} installed an output on failure"
            );
            assert!(
                !staging.exists(),
                "{boundary} leaked its failed staging file"
            );
            assert_eq!(
                store.tags().get(tag.as_bytes()).await.unwrap().is_some(),
                boundary != "blob_tag_persist",
                "unexpected pin state at {boundary}"
            );

            // Retrying repeats the idempotent tag set/sync and then installs to
            // the still-unused destination. This also recovers an uncertain
            // tag sync and a durable pin left by an install failure.
            let retry_staging = root.join("retry.download");
            std::fs::write(&retry_staging, b"blob").unwrap();
            let outcome = commit_download(
                DownloadCommit {
                    store: &store,
                    tag_name: tag.as_bytes(),
                    hash_and_format,
                    staging: attachment::StagedFile::new(retry_staging),
                    output: &output,
                    kind: AttachmentKind::File,
                    max_attachment_bytes: DEFAULT_MAX_ATTACHMENT_BYTES,
                    pin_already_committed: false,
                },
                &|_| Ok(()),
            )
            .await
            .unwrap();
            assert!(outcome.destination_synced);
            assert!(outcome.cleanup_complete);
            assert!(outcome.warnings.is_empty());
            assert_eq!(std::fs::read(&output).unwrap(), b"blob");
            store.sync_db().await.unwrap();
            let parsed = parse_pinned_blob_tag(tag.as_bytes()).unwrap();
            assert_eq!(parsed.direction, "incoming");
            assert_eq!(parsed.provider.as_deref(), Some(provider_text.as_str()));
            assert_eq!(
                store
                    .tags()
                    .get(tag.as_bytes())
                    .await
                    .unwrap()
                    .unwrap()
                    .hash_and_format(),
                hash_and_format
            );
            drop(store);
            let _ = std::fs::remove_dir_all(root);
        }

        for boundary in [
            "after_destination_install",
            "destination_sync",
            "parent_sync",
            "after_destination_sync",
            "staging_cleanup",
            "after_staging_cleanup",
        ] {
            let root = std::env::temp_dir().join(format!(
                "meshmsg-download-partial-{boundary}-{}",
                rand::random::<u64>()
            ));
            std::fs::create_dir_all(&root).unwrap();
            let options = FsStoreOptions::new(&root.join("store"));
            let store: Store = FsStore::load_with_opts(root.join("blobs.db"), options)
                .await
                .unwrap()
                .into();
            let hash_and_format = iroh_blobs::HashAndFormat::raw(iroh_blobs::Hash::new(b"blob"));
            let provider = SecretKey::generate().public();
            let provider_text = provider.to_string();
            let tag = inbound_blob_tag(
                provider,
                "fedcba9876543210fedcba9876543210",
                AttachmentKind::File,
                "partial.txt",
            );
            let output = root.join("output");
            let staging = root.join("part.download");
            std::fs::write(&staging, b"blob").unwrap();
            let injected = |current| {
                if current == boundary {
                    anyhow::bail!("injected {boundary} failure")
                }
                Ok(())
            };

            let outcome = commit_download(
                DownloadCommit {
                    store: &store,
                    tag_name: tag.as_bytes(),
                    hash_and_format,
                    staging: attachment::StagedFile::new(staging.clone()),
                    output: &output,
                    kind: AttachmentKind::File,
                    max_attachment_bytes: DEFAULT_MAX_ATTACHMENT_BYTES,
                    pin_already_committed: false,
                },
                &injected,
            )
            .await
            .unwrap();
            assert_eq!(std::fs::read(&output).unwrap(), b"blob");
            assert_eq!(
                outcome.destination_synced,
                !matches!(boundary, "destination_sync" | "parent_sync")
            );
            assert_eq!(outcome.cleanup_complete, boundary != "staging_cleanup");
            assert_eq!(outcome.warnings.len(), 1);
            assert!(!staging.exists(), "drop recovery did not remove staging");
            let parsed = parse_pinned_blob_tag(tag.as_bytes()).unwrap();
            assert_eq!(parsed.direction, "incoming");
            assert_eq!(parsed.provider.as_deref(), Some(provider_text.as_str()));
            assert_eq!(
                store
                    .tags()
                    .get(tag.as_bytes())
                    .await
                    .unwrap()
                    .unwrap()
                    .hash_and_format(),
                hash_and_format
            );
            drop(store);
            let _ = std::fs::remove_dir_all(root);
        }
    }

    #[tokio::test]
    async fn signed_directory_commit_reports_after_install_fault_without_false_failure() {
        let root = std::env::temp_dir().join(format!(
            "meshmsg-signed-directory-commit-{}",
            rand::random::<u64>()
        ));
        let source = root.join("source");
        std::fs::create_dir_all(source.join("nested")).unwrap();
        std::fs::write(source.join("nested/file.txt"), b"directory payload").unwrap();
        let archive = root.join("directory.download");
        attachment::create_deterministic_tar(&source, &archive, DEFAULT_MAX_ATTACHMENT_BYTES)
            .unwrap();
        let bytes = std::fs::read(&archive).unwrap();
        let hash_and_format = iroh_blobs::HashAndFormat::raw(iroh_blobs::Hash::new(&bytes));
        let provider = SecretKey::generate().public();
        let offer_id = "abcdefabcdefabcdefabcdefabcdefab";
        let tag = inbound_blob_tag(
            provider,
            offer_id,
            AttachmentKind::DirectoryTarV1,
            "source.tar",
        );
        let options = FsStoreOptions::new(&root.join("store"));
        let store: Store = FsStore::load_with_opts(root.join("blobs.db"), options)
            .await
            .unwrap()
            .into();
        let output = root.join("installed");
        let outcome = commit_download(
            DownloadCommit {
                store: &store,
                tag_name: tag.as_bytes(),
                hash_and_format,
                staging: attachment::StagedFile::new(archive),
                output: &output,
                kind: AttachmentKind::DirectoryTarV1,
                max_attachment_bytes: DEFAULT_MAX_ATTACHMENT_BYTES,
                pin_already_committed: false,
            },
            &|boundary| {
                if boundary == "after_destination_install" {
                    anyhow::bail!("simulated interruption")
                }
                Ok(())
            },
        )
        .await
        .unwrap();
        assert!(outcome.destination_synced);
        assert!(outcome.cleanup_complete);
        assert_eq!(outcome.warnings.len(), 1);
        assert_eq!(
            std::fs::read(output.join("nested/file.txt")).unwrap(),
            b"directory payload"
        );
        let parsed = parse_pinned_blob_tag(tag.as_bytes()).unwrap();
        assert_eq!(parsed.direction, "incoming");
        assert_eq!(parsed.offer_id, offer_id);
        assert_eq!(
            store
                .tags()
                .get(tag.as_bytes())
                .await
                .unwrap()
                .unwrap()
                .hash_and_format(),
            hash_and_format
        );
        drop(store);
        let _ = std::fs::remove_dir_all(root);
    }

    async fn lifecycle_test_store(label: &str) -> (PathBuf, PathBuf, Store) {
        let root = std::env::temp_dir().join(format!(
            "meshmsg-transfer-{label}-{}",
            rand::random::<u64>()
        ));
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
    #[tokio::test]
    async fn download_install_failure_rolls_back_new_pin_and_index_reservation() {
        let (root, state, store) = lifecycle_test_store("install-rollback").await;
        let storage = AttachmentStorage::open(store.clone(), root.join("blobs"), &state, 100, 0, 0)
            .await
            .unwrap();
        let tag_name = outbound_blob_tag(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            AttachmentKind::File,
            "x",
        );
        let imported = store.blobs().add_slice(b"x").await.unwrap();
        let hash_and_format = imported.hash_and_format();
        let created = storage
            .commit_pin(
                &tag_name,
                parse_pinned_blob_tag(tag_name.as_bytes()).unwrap(),
                hash_and_format,
                1,
                &|_| Ok(()),
            )
            .await
            .unwrap();
        assert!(created);
        let staging = root.join("staging");
        let output = root.join("existing");
        std::fs::write(&staging, b"x").unwrap();
        std::fs::write(&output, b"keep").unwrap();
        let error = commit_download(
            DownloadCommit {
                store: &store,
                tag_name: tag_name.as_bytes(),
                hash_and_format,
                staging: attachment::StagedFile::new(staging),
                output: &output,
                kind: AttachmentKind::File,
                max_attachment_bytes: DEFAULT_MAX_ATTACHMENT_BYTES,
                pin_already_committed: true,
            },
            &|_| Ok(()),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("already exists"));
        storage
            .rollback_committed_pin(&tag_name, created)
            .await
            .unwrap();
        assert_eq!(storage.status().tags, 0);
        assert!(storage.reservations_empty());
        assert!(store
            .tags()
            .get(tag_name.as_bytes())
            .await
            .unwrap()
            .is_none());
        drop(store);
        let _ = std::fs::remove_dir_all(root);
    }
}
