use super::AttachmentKind;
use crate::{
    attachment, contracts,
    ipc::{MAX_OFFER_LIST_ENTRIES, MAX_OFFER_LIST_SCANNED},
};
use anyhow::{Context, Result};
use data_encoding::BASE64URL_NOPAD;
use futures_util::StreamExt;
use iroh::PublicKey;
use iroh_blobs::{api::Store, BlobFormat};

const MAX_ENCODED_TAG_NAME_BYTES: usize = 134;
const MAX_ENCODED_PUBLIC_KEY_BYTES: usize = 64;
pub(super) const BLOB_TAG_PREFIX: &[u8] = b"meshmsg/";
const OUTBOUND_BLOB_TAG_PREFIX: &str = "meshmsg/out/v1/";
const INBOUND_BLOB_TAG_PREFIX: &str = "meshmsg/in/v1/";
pub(super) const MAX_ATTACHMENT_INDEX_TAG_BYTES: usize = INBOUND_BLOB_TAG_PREFIX.len()
    + MAX_ENCODED_PUBLIC_KEY_BYTES
    + 1
    + 32
    + 1
    + "directory_tar_v1".len()
    + 1
    + MAX_ENCODED_TAG_NAME_BYTES;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PinnedBlobTag {
    pub(super) direction: &'static str,
    pub(super) offer_id: String,
    pub(super) provider: Option<String>,
    pub(super) name: String,
    pub(super) kind: AttachmentKind,
}

fn attachment_kind_name(kind: AttachmentKind) -> &'static str {
    match kind {
        AttachmentKind::File => "file",
        AttachmentKind::DirectoryTarV1 => "directory_tar_v1",
    }
}

fn parse_attachment_kind(value: &str) -> Option<AttachmentKind> {
    match value {
        "file" => Some(AttachmentKind::File),
        "directory_tar_v1" => Some(AttachmentKind::DirectoryTarV1),
        _ => None,
    }
}

pub(super) fn protocol_attachment_kind(kind: AttachmentKind) -> meshmsg_protocol::AttachmentKind {
    match kind {
        AttachmentKind::File => meshmsg_protocol::AttachmentKind::File,
        AttachmentKind::DirectoryTarV1 => meshmsg_protocol::AttachmentKind::DirectoryTarV1,
    }
}

fn decode_tag_name(value: &str) -> Option<String> {
    // A valid display name is at most 100 UTF-8 bytes. Reject oversized input
    // before the decoder allocates in proportion to untrusted tag metadata.
    if value.len() > MAX_ENCODED_TAG_NAME_BYTES {
        return None;
    }
    let decoded = BASE64URL_NOPAD.decode(value.as_bytes()).ok()?;
    let name = String::from_utf8(decoded).ok()?;
    attachment::validate_display_name(&name).ok()?;
    Some(name)
}

fn encode_tag_name(value: &str) -> String {
    BASE64URL_NOPAD.encode(value.as_bytes())
}

pub(super) fn outbound_blob_tag(offer_id: &str, kind: AttachmentKind, name: &str) -> String {
    assert!(
        contracts::valid_operation_id(offer_id),
        "invalid attachment offer ID before tag generation"
    );
    attachment::validate_display_name(name).expect("invalid attachment name before tag generation");
    format!(
        "{OUTBOUND_BLOB_TAG_PREFIX}{offer_id}/{}/{}",
        attachment_kind_name(kind),
        encode_tag_name(name)
    )
}

pub(super) fn inbound_blob_tag(
    provider: PublicKey,
    offer_id: &str,
    kind: AttachmentKind,
    name: &str,
) -> String {
    assert!(
        contracts::valid_operation_id(offer_id),
        "invalid attachment offer ID before tag generation"
    );
    attachment::validate_display_name(name).expect("invalid attachment name before tag generation");
    format!(
        "{INBOUND_BLOB_TAG_PREFIX}{provider}/{offer_id}/{}/{}",
        attachment_kind_name(kind),
        encode_tag_name(name)
    )
}

pub(super) fn parse_pinned_blob_tag(name: &[u8]) -> Option<PinnedBlobTag> {
    let name = std::str::from_utf8(name).ok()?;
    let (direction, provider, remainder) =
        if let Some(remainder) = name.strip_prefix(OUTBOUND_BLOB_TAG_PREFIX) {
            ("outgoing", None, remainder)
        } else {
            let remainder = name.strip_prefix(INBOUND_BLOB_TAG_PREFIX)?;
            let (provider, remainder) = remainder.split_once('/')?;
            if provider.len() > MAX_ENCODED_PUBLIC_KEY_BYTES {
                return None;
            }
            let canonical_provider = provider.parse::<PublicKey>().ok()?.to_string();
            if canonical_provider != provider {
                return None;
            }
            ("incoming", Some(canonical_provider), remainder)
        };
    let mut parts = remainder.split('/');
    let offer_id = parts.next()?;
    let kind = parse_attachment_kind(parts.next()?)?;
    let name = decode_tag_name(parts.next()?)?;
    if parts.next().is_some() || !contracts::valid_operation_id(offer_id) {
        return None;
    }
    Some(PinnedBlobTag {
        direction,
        offer_id: offer_id.to_owned(),
        provider,
        name,
        kind,
    })
}

pub(super) async fn list_pinned_blobs(
    store: &Store,
) -> Result<(Vec<meshmsg_protocol::OfferListItem>, bool, usize)> {
    let mut tags = store
        .tags()
        .list_prefix(BLOB_TAG_PREFIX)
        .await
        .context("list attachment blob tags")?;
    // Validate at most 4096 records plus one presence-only lookahead. Continuing
    // after filling the public page accounts malformed/unavailable omitted items
    // without allocating an unbounded response.
    let mut blobs = Vec::new();
    let mut scanned = 0_usize;
    let mut item_errors = 0_usize;
    let mut truncated = false;
    while scanned < MAX_OFFER_LIST_SCANNED {
        let Some(item) = tags.next().await else { break };
        scanned += 1;
        let tag = match item {
            Ok(tag) => tag,
            Err(_) => {
                item_errors += 1;
                continue;
            }
        };
        let Some(parsed) = parse_pinned_blob_tag(tag.name.as_ref()) else {
            item_errors += 1;
            continue;
        };
        let size = match (tag.format, store.blobs().status(tag.hash).await) {
            (BlobFormat::Raw, Ok(iroh_blobs::api::proto::BlobStatus::Complete { size })) => size,
            (_, Ok(_)) => {
                item_errors += 1;
                continue;
            }
            (_, Err(_)) => {
                item_errors += 1;
                continue;
            }
        };
        if blobs.len() == MAX_OFFER_LIST_ENTRIES {
            truncated = true;
        } else {
            blobs.push(meshmsg_protocol::OfferListItem {
                direction: parsed.direction.parse()?,
                offer_id: parsed.offer_id.parse()?,
                provider: parsed.provider.map(|value| value.parse()).transpose()?,
                name: meshmsg_protocol::AttachmentName::new(parsed.name)?,
                kind: match parsed.kind {
                    AttachmentKind::File => meshmsg_protocol::AttachmentKind::File,
                    AttachmentKind::DirectoryTarV1 => {
                        meshmsg_protocol::AttachmentKind::DirectoryTarV1
                    }
                },
                hash: tag.hash.to_string().parse()?,
                format: "raw".into(),
                status: "complete".into(),
                size: Some(size),
            });
        }
    }
    if scanned == MAX_OFFER_LIST_SCANNED {
        truncated |= tags.next().await.is_some();
    }
    truncated |= item_errors != 0;
    Ok((blobs, truncated, item_errors))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attachment::AttachmentKind;
    use crate::ipc::{MAX_IPC_EVENT_SIZE, MAX_OFFER_LIST_ENTRIES, MAX_OFFER_LIST_SCANNED};
    use iroh::SecretKey;
    use iroh_blobs::store::fs::{options::Options as FsStoreOptions, FsStore};
    #[test]
    fn pinned_blob_tags_preserve_names_and_kinds() {
        let id = "0123456789abcdef0123456789abcdef";
        let provider = SecretKey::generate().public();
        let name = "résumé 2026.pdf";
        assert_eq!(
            parse_pinned_blob_tag(outbound_blob_tag(id, AttachmentKind::File, name).as_bytes()),
            Some(PinnedBlobTag {
                direction: "outgoing",
                offer_id: id.to_owned(),
                provider: None,
                name: name.to_owned(),
                kind: AttachmentKind::File,
            })
        );
        assert_eq!(
            parse_pinned_blob_tag(
                inbound_blob_tag(provider, id, AttachmentKind::DirectoryTarV1, "results.tar")
                    .as_bytes()
            ),
            Some(PinnedBlobTag {
                direction: "incoming",
                offer_id: id.to_owned(),
                provider: Some(provider.to_string()),
                name: "results.tar".to_owned(),
                kind: AttachmentKind::DirectoryTarV1,
            })
        );
    }

    #[test]
    fn malformed_pinned_blob_tags_are_ignored() {
        for invalid in [
            "meshmsg/out/v1/",
            "meshmsg/out/v1/0123456789ABCDEF0123456789ABCDEF/file/bmFtZQ",
            "meshmsg/out/v1/0123456789abcdef0123456789abcdef/unknown/bmFtZQ",
            "meshmsg/out/v1/0123456789abcdef0123456789abcdef/file/not+base64",
            "meshmsg/in/v1//0123456789abcdef0123456789abcdef/file/bmFtZQ",
            "meshmsg/in/v1/provider/0123456789abcdef0123456789abcdef/file/bmFtZQ/extra",
            "meshmsg/out/v2/0123456789abcdef0123456789abcdef/file/bmFtZQ",
            "other/out/v1/0123456789abcdef0123456789abcdef",
        ] {
            assert_eq!(parse_pinned_blob_tag(invalid.as_bytes()), None, "{invalid}");
        }
        assert_eq!(parse_pinned_blob_tag(&[0xff]), None);
        let provider = SecretKey::generate().public().to_string();
        let canonical = format!(
            "{INBOUND_BLOB_TAG_PREFIX}{provider}/0123456789abcdef0123456789abcdef/file/bmFtZQ"
        );
        let uppercase_provider = canonical.replacen(&provider, &provider.to_ascii_uppercase(), 1);
        let padded_provider = canonical.replacen(&provider, &format!("{provider}="), 1);
        assert!(parse_pinned_blob_tag(canonical.as_bytes()).is_some());
        assert_eq!(parse_pinned_blob_tag(uppercase_provider.as_bytes()), None);
        assert_eq!(parse_pinned_blob_tag(padded_provider.as_bytes()), None);
        assert_eq!(
            [canonical, uppercase_provider, padded_provider]
                .iter()
                .filter(|tag| parse_pinned_blob_tag(tag.as_bytes()).is_some())
                .count(),
            1,
            "noncanonical provider encodings consumed duplicate logical slots"
        );

        let oversized_name = format!(
            "meshmsg/out/v1/0123456789abcdef0123456789abcdef/file/{}",
            "A".repeat(MAX_ATTACHMENT_INDEX_TAG_BYTES + 1)
        );
        assert_eq!(parse_pinned_blob_tag(oversized_name.as_bytes()), None);
        let oversized_provider = format!(
            "meshmsg/in/v1/{}/0123456789abcdef0123456789abcdef/file/bmFtZQ",
            "a".repeat(MAX_ENCODED_PUBLIC_KEY_BYTES + 1)
        );
        assert_eq!(parse_pinned_blob_tag(oversized_provider.as_bytes()), None);
    }

    #[tokio::test]
    async fn actual_blob_store_listing_caps_valid_ordered_tags() {
        let dir =
            std::env::temp_dir().join(format!("meshmsg-offers-test-{}", rand::random::<u64>()));
        let options = FsStoreOptions::new(&dir);
        let store: Store = FsStore::load_with_opts(dir.join("blobs.db"), options)
            .await
            .unwrap()
            .into();
        let source = dir.join("listing-source");
        std::fs::write(&source, b"listing test").unwrap();
        let imported = store.blobs().add_path(&source).temp_tag().await.unwrap();
        let hash = imported.hash();
        for index in (0..=MAX_OFFER_LIST_ENTRIES).rev() {
            let tag = outbound_blob_tag(
                &format!("{index:032x}"),
                AttachmentKind::File,
                &format!("file-{index}"),
            );
            store
                .tags()
                .set(tag.as_bytes(), iroh_blobs::HashAndFormat::raw(hash))
                .await
                .unwrap();
        }
        // A malformed tag is ignored by the real parser and does not consume the valid cap.
        store
            .tags()
            .set(
                b"meshmsg/out/v1/not-an-offer/file/bmFtZQ",
                iroh_blobs::HashAndFormat::raw(hash),
            )
            .await
            .unwrap();

        let (blobs, truncated, item_errors) = list_pinned_blobs(&store).await.unwrap();
        assert_eq!(blobs.len(), MAX_OFFER_LIST_ENTRIES);
        assert!(truncated);
        assert_eq!(item_errors, 1);
        assert_eq!(blobs[0].offer_id.to_string(), format!("{:032x}", 0));
        assert_eq!(
            blobs.last().unwrap().offer_id.to_string(),
            format!("{:032x}", MAX_OFFER_LIST_ENTRIES - 1)
        );
        let frame = meshmsg_protocol::ResponseFrame::new(
            Some(meshmsg_protocol::RequestId::new_random()),
            meshmsg_protocol::Response::Offers(meshmsg_protocol::OffersList {
                blobs,
                truncated,
                item_errors,
            }),
        );
        let encoded = serde_json::to_vec(&frame).unwrap();
        assert!(
            encoded.len() <= MAX_IPC_EVENT_SIZE,
            "maximum canonical offer-list response exceeds IPC frame"
        );
        drop(store);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn real_store_offer_scan_bounds_4095_4096_4097_and_caps_item_errors() {
        for count in [4095_usize, 4096, 4097] {
            let dir = std::env::temp_dir().join(format!(
                "meshmsg-offer-scan-{count}-{}",
                rand::random::<u64>()
            ));
            let options = FsStoreOptions::new(&dir);
            let store: Store = FsStore::load_with_opts(dir.join("blobs.db"), options)
                .await
                .unwrap()
                .into();
            for index in 0..count {
                let malformed = format!("meshmsg/out/v1/A{index:031x}/file/eA");
                store
                    .tags()
                    .set(
                        malformed.as_bytes(),
                        iroh_blobs::HashAndFormat::raw(iroh_blobs::Hash::new(b"missing")),
                    )
                    .await
                    .unwrap();
            }
            store.sync_db().await.unwrap();
            let (listed, truncated, item_errors) = list_pinned_blobs(&store).await.unwrap();
            assert!(listed.is_empty());
            assert!(truncated);
            assert_eq!(item_errors, count.min(MAX_OFFER_LIST_SCANNED));
            drop(store);
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}
