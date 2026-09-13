use super::{protocol, AttachmentKind, AttachmentOffer};
use crate::attachment;
use crate::{
    contracts,
    ids::id_string,
    ipc::{LifecycleRequestContext, MAX_OFFER_LIST_ENTRIES, MAX_OFFER_LIST_SCANNED},
};
use anyhow::{Context, Result};
use data_encoding::BASE64URL_NOPAD;
use futures_util::StreamExt;
use iroh::{address_lookup::memory::MemoryLookup, Endpoint, PublicKey, SecretKey};
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
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    io::Read as _,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant as StdInstant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{broadcast, OwnedSemaphorePermit, Semaphore};

const ENDPOINT_ONLINE_TIMEOUT: Duration = Duration::from_secs(30);
pub(crate) const TRANSFER_TIMEOUT: Duration = Duration::from_secs(60 * 60);
pub(crate) const MAX_ATTACHMENT_TAG_SCAN: usize = MAX_ATTACHMENT_TAGS * 2 + 1;
pub(crate) const MAX_PRUNE_TAGS: usize = meshmsg_protocol::MAX_LIFECYCLE_ITEMS;
pub(crate) const MAX_ATTACHMENT_TAGS: usize = 8_192;
pub(crate) const MAX_ATTACHMENT_INDEX_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const ATTACHMENT_INDEX_NAME: &str = "attachment-retention-v1.json";
pub(crate) const DOWNLOAD_PROGRESS_STEP: u64 = 8 * 1024 * 1024;
pub(crate) const MAX_ENCODED_TAG_NAME_BYTES: usize = 134;
pub(crate) const MAX_ENCODED_PUBLIC_KEY_BYTES: usize = 64;
const BLOB_TAG_PREFIX: &[u8] = b"meshmsg/";
const OUTBOUND_BLOB_TAG_PREFIX: &str = "meshmsg/out/v1/";
pub(crate) const INBOUND_BLOB_TAG_PREFIX: &str = "meshmsg/in/v1/";
pub(crate) const MAX_ATTACHMENT_INDEX_TAG_BYTES: usize = INBOUND_BLOB_TAG_PREFIX.len()
    + MAX_ENCODED_PUBLIC_KEY_BYTES
    + 1
    + 32
    + 1
    + "directory_tar_v1".len()
    + 1
    + MAX_ENCODED_TAG_NAME_BYTES;

fn unix_timestamp_ms() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PinnedBlobTag {
    pub(crate) direction: &'static str,
    pub(crate) offer_id: String,
    pub(crate) provider: Option<String>,
    pub(crate) name: String,
    pub(crate) kind: AttachmentKind,
}

pub(crate) fn attachment_kind_name(kind: AttachmentKind) -> &'static str {
    match kind {
        AttachmentKind::File => "file",
        AttachmentKind::DirectoryTarV1 => "directory_tar_v1",
    }
}

pub(crate) fn parse_attachment_kind(value: &str) -> Option<AttachmentKind> {
    match value {
        "file" => Some(AttachmentKind::File),
        "directory_tar_v1" => Some(AttachmentKind::DirectoryTarV1),
        _ => None,
    }
}

fn protocol_attachment_kind(kind: AttachmentKind) -> meshmsg_protocol::AttachmentKind {
    match kind {
        AttachmentKind::File => meshmsg_protocol::AttachmentKind::File,
        AttachmentKind::DirectoryTarV1 => meshmsg_protocol::AttachmentKind::DirectoryTarV1,
    }
}

pub(crate) fn decode_tag_name(value: &str) -> Option<String> {
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

pub(crate) fn encode_tag_name(value: &str) -> String {
    BASE64URL_NOPAD.encode(value.as_bytes())
}

pub(crate) fn outbound_blob_tag(offer_id: &str, kind: AttachmentKind, name: &str) -> String {
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

pub(crate) fn inbound_blob_tag(
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

pub(crate) fn parse_pinned_blob_tag(name: &[u8]) -> Option<PinnedBlobTag> {
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

pub(crate) async fn list_pinned_blobs(
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
    let mut has_more = false;
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
            has_more = true;
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
        has_more |= tags.next().await.is_some();
    }
    has_more |= item_errors != 0;
    Ok((blobs, has_more, item_errors))
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AttachmentRetentionIndex {
    pub(crate) schema_version: u8,
    #[serde(deserialize_with = "deserialize_attachment_index_entries")]
    pub(crate) created_at_ms: BTreeMap<String, u64>,
}

#[derive(Deserialize)]
struct AttachmentIndexVersionProbe {
    schema_version: u64,
}

fn deserialize_attachment_index_entries<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct EntriesVisitor;
    impl<'de> serde::de::Visitor<'de> for EntriesVisitor {
        type Value = BTreeMap<String, u64>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                formatter,
                "at most {MAX_ATTACHMENT_TAGS} bounded attachment index entries"
            )
        }

        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut access: A,
        ) -> Result<Self::Value, A::Error> {
            let mut entries = BTreeMap::new();
            while let Some(key) = access
                .next_key::<crate::persistent::BoundedString<MAX_ATTACHMENT_INDEX_TAG_BYTES>>()?
            {
                if entries.len() == MAX_ATTACHMENT_TAGS {
                    return Err(serde::de::Error::invalid_length(entries.len() + 1, &self));
                }
                let value = access.next_value::<u64>()?;
                if entries.insert(key.into_string(), value).is_some() {
                    return Err(serde::de::Error::custom(
                        "duplicate attachment retention index key",
                    ));
                }
            }
            Ok(entries)
        }
    }
    deserializer.deserialize_map(EntriesVisitor)
}

impl Default for AttachmentRetentionIndex {
    fn default() -> Self {
        Self {
            schema_version: 1,
            created_at_ms: BTreeMap::new(),
        }
    }
}

#[derive(Clone)]
pub(crate) struct AttachmentStorage {
    store: Store,
    blob_root: PathBuf,
    state_dir: PathBuf,
    pub(crate) state: Arc<Mutex<AttachmentStorageState>>,
    pub(crate) gate: Arc<Semaphore>,
    quota_bytes: u64,
    min_free_bytes: u64,
    retention_secs: u64,
}

pub(crate) struct AttachmentStorageState {
    pub(crate) index: AttachmentRetentionIndex,
    pub(crate) tags: BTreeMap<String, StorageTag>,
    pub(crate) reservations: HashSet<String>,
    pub(crate) gc_protections: HashMap<iroh_blobs::HashAndFormat, GcProtection>,
    pub(crate) accounting_healthy: bool,
    pub(crate) status: meshmsg_protocol::AttachmentStorageStatus,
}

pub(crate) struct GcProtection {
    pub(crate) _tag: iroh_blobs::api::TempTag,
    pub(crate) deadline: GcProtectionDeadline,
}

#[derive(Clone, Copy)]
pub(crate) enum GcProtectionDeadline {
    InFlight,
    Until(StdInstant),
}

pub(crate) struct RemovalGcGuard {
    pub(crate) state: Arc<Mutex<AttachmentStorageState>>,
    records: Vec<(iroh_blobs::HashAndFormat, Option<GcProtectionDeadline>)>,
    finished: bool,
}

impl RemovalGcGuard {
    fn restore_before_deletion(&mut self) {
        let mut state = self
            .state
            .lock()
            .expect("attachment storage state poisoned");
        for (value, previous) in &self.records {
            match previous {
                Some(deadline) => {
                    if let Some(protection) = state.gc_protections.get_mut(value) {
                        protection.deadline = *deadline;
                    }
                }
                None => {
                    state.gc_protections.remove(value);
                }
            }
        }
        self.finished = true;
    }

    fn finish(mut self, possibly_unpinned: &HashSet<iroh_blobs::HashAndFormat>) {
        let expires_at = StdInstant::now() + TRANSFER_TIMEOUT;
        let mut state = self
            .state
            .lock()
            .expect("attachment storage state poisoned");
        for (value, previous) in &self.records {
            if possibly_unpinned.contains(value) {
                if let Some(protection) = state.gc_protections.get_mut(value) {
                    protection.deadline = GcProtectionDeadline::Until(expires_at);
                }
            } else {
                match previous {
                    Some(deadline) => {
                        if let Some(protection) = state.gc_protections.get_mut(value) {
                            protection.deadline = *deadline;
                        }
                    }
                    None => {
                        state.gc_protections.remove(value);
                    }
                }
            }
        }
        drop(state);
        self.finished = true;
    }
}

impl Drop for RemovalGcGuard {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        let expires_at = StdInstant::now() + TRANSFER_TIMEOUT;
        let mut state = self
            .state
            .lock()
            .expect("attachment storage state poisoned");
        for (value, _) in &self.records {
            if let Some(protection) = state.gc_protections.get_mut(value) {
                protection.deadline = GcProtectionDeadline::Until(expires_at);
            }
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct StorageTag {
    name: String,
    parsed: PinnedBlobTag,
    hash_and_format: iroh_blobs::HashAndFormat,
    size: u64,
}

pub(crate) struct RemovalSpec<'a> {
    pub(crate) operation_id: &'a str,
    pub(crate) offer_id: Option<&'a str>,
    pub(crate) direction: Option<&'a str>,
    pub(crate) provider: Option<&'a str>,
    pub(crate) older_than_secs: Option<u64>,
    pub(crate) maximum: usize,
    pub(crate) dry_run: bool,
}

impl AttachmentStorage {
    pub(crate) async fn open(
        store: Store,
        blob_root: PathBuf,
        state_dir: &Path,
        quota_bytes: u64,
        min_free_bytes: u64,
        retention_secs: u64,
    ) -> Result<Self> {
        let state_dir = state_dir.to_owned();
        let index_dir = state_dir.clone();
        let mut index = tokio::task::spawn_blocking(move || load_attachment_index(&index_dir))
            .await
            .context("attachment index load task failed")??;
        let live = collect_storage_tags_bounded(&store).await?;
        anyhow::ensure!(
            live.len() <= MAX_ATTACHMENT_TAGS,
            "attachment tag capacity exceeded: {} pins found, maximum is {MAX_ATTACHMENT_TAGS}; remove pins with a compatible older daemon or restore from backup",
            live.len()
        );
        let now = unix_timestamp_ms()?;
        let tags = live
            .into_iter()
            .map(|tag| (tag.name.clone(), tag))
            .collect::<BTreeMap<_, _>>();
        index
            .created_at_ms
            .retain(|name, _| tags.contains_key(name));
        for name in tags.keys() {
            index.created_at_ms.entry(name.clone()).or_insert(now);
        }
        let persist_dir = state_dir.clone();
        let persist_index = clone_attachment_index(&index);
        tokio::task::spawn_blocking(move || persist_attachment_index(&persist_dir, &persist_index))
            .await
            .context("attachment index reconciliation task failed")??;
        let available_bytes = available_space_off_loop(blob_root.clone()).await?;
        let status = storage_status(
            tags.values(),
            quota_bytes,
            available_bytes,
            min_free_bytes,
            now,
        );
        Ok(Self {
            store,
            blob_root,
            state_dir,
            state: Arc::new(Mutex::new(AttachmentStorageState {
                index,
                tags,
                reservations: HashSet::new(),
                gc_protections: HashMap::new(),
                accounting_healthy: true,
                status,
            })),
            gate: Arc::new(Semaphore::new(1)),
            quota_bytes,
            min_free_bytes,
            retention_secs,
        })
    }

    pub(crate) fn status(&self) -> meshmsg_protocol::AttachmentStorageStatus {
        self.state
            .lock()
            .expect("attachment storage state poisoned")
            .status
            .clone()
    }

    pub(crate) async fn refresh_free_space(&self) -> Result<()> {
        let available = available_space_off_loop(self.blob_root.clone()).await?;
        let now = unix_timestamp_ms()?;
        let mut state = self
            .state
            .lock()
            .expect("attachment storage state poisoned");
        let monotonic_now = StdInstant::now();
        state.gc_protections.retain(|_, protection| {
            matches!(protection.deadline, GcProtectionDeadline::InFlight)
                || matches!(
                    protection.deadline,
                    GcProtectionDeadline::Until(deadline) if deadline > monotonic_now
                )
        });
        state.status = storage_status(
            state.tags.values(),
            self.quota_bytes,
            available,
            self.min_free_bytes,
            now,
        );
        Ok(())
    }

    pub(crate) async fn preflight_free_space(&self, additional_bytes: u64) -> Result<()> {
        let available = available_space_off_loop(self.blob_root.clone()).await?;
        let required = self
            .min_free_bytes
            .checked_add(additional_bytes)
            .context("attachment free-space requirement overflow")?;
        {
            let now = unix_timestamp_ms()?;
            let mut state = self
                .state
                .lock()
                .expect("attachment storage state poisoned");
            state.status = storage_status(
                state.tags.values(),
                self.quota_bytes,
                available,
                self.min_free_bytes,
                now,
            );
        }
        anyhow::ensure!(
            available >= required,
            "attachment_min_free_space: attachment needs {additional_bytes} bytes while preserving {} free bytes ({} available)",
            self.min_free_bytes, available
        );
        Ok(())
    }

    pub(crate) fn admit_pin(
        &self,
        tag_name: &str,
        hash_and_format: iroh_blobs::HashAndFormat,
        size: u64,
    ) -> Result<()> {
        anyhow::ensure!(
            hash_and_format.format == BlobFormat::Raw,
            "attachment_lifecycle_internal: unsupported hash_seq attachment format"
        );
        let state = self
            .state
            .lock()
            .expect("attachment storage state poisoned");
        anyhow::ensure!(
            state.accounting_healthy,
            "attachment_lifecycle_internal: attachment accounting requires reconciliation"
        );
        if let Some(existing) = state.tags.get(tag_name) {
            anyhow::ensure!(
                existing.hash_and_format == hash_and_format,
                "attachment_lifecycle_internal: attachment tag is bound to different content"
            );
            return Ok(());
        }
        anyhow::ensure!(
            state.tags.len() + state.reservations.len() < MAX_ATTACHMENT_TAGS,
            "attachment_tag_capacity: attachment pin capacity of {MAX_ATTACHMENT_TAGS} reached"
        );
        let used = state.status.tagged_bytes;
        let deduplicated = state
            .tags
            .values()
            .any(|tag| tag.hash_and_format == hash_and_format);
        let additional = if deduplicated { 0 } else { size };
        anyhow::ensure!(
            used.checked_add(additional).is_some_and(|total| total <= self.quota_bytes),
            "attachment_quota_exceeded: pinning this blob would exceed the {}-byte attachment quota ({} used, {} additional)",
            self.quota_bytes, used, additional
        );
        Ok(())
    }

    pub(crate) async fn commit_pin(
        &self,
        tag_name: &str,
        parsed: PinnedBlobTag,
        hash_and_format: iroh_blobs::HashAndFormat,
        size: u64,
        fault: &(dyn Fn(&'static str) -> Result<()> + Sync),
    ) -> Result<bool> {
        let authoritative_size = complete_blob_size(&self.store, hash_and_format).await?;
        anyhow::ensure!(
            authoritative_size == size,
            "attachment_lifecycle_internal: complete blob size {authoritative_size} differs from expected {size}"
        );
        self.admit_pin(tag_name, hash_and_format, authoritative_size)?;
        {
            let mut state = self
                .state
                .lock()
                .expect("attachment storage state poisoned");
            if state.tags.contains_key(tag_name) {
                return Ok(false);
            }
            anyhow::ensure!(
                state.reservations.insert(tag_name.to_owned()),
                "attachment_lifecycle_internal: duplicate attachment reservation"
            );
        }
        let result = async {
            fault("before_attachment_tag_set")?;
            self.store
                .tags()
                .set(tag_name.as_bytes(), hash_and_format)
                .await?;
            fault("after_attachment_tag_set")?;
            self.store.sync_db().await?;
            fault("after_attachment_tag_sync")?;
            let now = unix_timestamp_ms()?;
            let index = {
                let mut state = self
                    .state
                    .lock()
                    .expect("attachment storage state poisoned");
                state.tags.insert(
                    tag_name.to_owned(),
                    StorageTag {
                        name: tag_name.to_owned(),
                        parsed,
                        hash_and_format,
                        size: authoritative_size,
                    },
                );
                state.index.created_at_ms.insert(tag_name.to_owned(), now);
                state.reservations.remove(tag_name);
                let available = state.status.available_bytes;
                state.status = storage_status(
                    state.tags.values(),
                    self.quota_bytes,
                    available,
                    self.min_free_bytes,
                    now,
                );
                clone_attachment_index(&state.index)
            };
            fault("before_attachment_index_persist")?;
            persist_attachment_index_off_loop(self.state_dir.clone(), index).await?;
            fault("after_attachment_index_persist")?;
            self.recalculate_cached_status().await?;
            Ok::<(), anyhow::Error>(())
        }
        .await;
        if let Err(error) = result {
            let rollback = self.rollback_new_pin(tag_name, fault).await;
            return match rollback {
                Ok(()) => Err(error),
                Err(rollback_error) => Err(error.context(format!(
                    "attachment pin rollback failed and was reconciled: {rollback_error:#}"
                ))),
            };
        }
        Ok(true)
    }

    pub(crate) async fn rollback_new_pin(
        &self,
        tag_name: &str,
        fault: &(dyn Fn(&'static str) -> Result<()> + Sync),
    ) -> Result<()> {
        let rollback = async {
            fault("before_attachment_tag_rollback")?;
            self.store.tags().delete(tag_name.as_bytes()).await?;
            self.store.sync_db().await?;
            fault("after_attachment_tag_rollback")?;
            let index = {
                let mut state = self
                    .state
                    .lock()
                    .expect("attachment storage state poisoned");
                state.tags.remove(tag_name);
                state.reservations.remove(tag_name);
                state.index.created_at_ms.remove(tag_name);
                let available = state.status.available_bytes;
                state.status = storage_status(
                    state.tags.values(),
                    self.quota_bytes,
                    available,
                    self.min_free_bytes,
                    unix_timestamp_ms()?,
                );
                clone_attachment_index(&state.index)
            };
            persist_attachment_index_off_loop(self.state_dir.clone(), index).await?;
            self.recalculate_cached_status().await?;
            Ok::<(), anyhow::Error>(())
        }
        .await;
        if rollback.is_err() {
            self.reconcile()
                .await
                .context("reconcile after attachment rollback failure")?;
        }
        rollback
    }

    pub(crate) async fn rollback_committed_pin(
        &self,
        tag_name: &str,
        newly_created: bool,
    ) -> Result<()> {
        if newly_created {
            self.rollback_new_pin(tag_name, &|_| Ok(())).await
        } else {
            Ok(())
        }
    }

    pub(crate) async fn recalculate_cached_status(&self) -> Result<()> {
        let available = available_space_off_loop(self.blob_root.clone()).await?;
        let now = unix_timestamp_ms()?;
        let mut state = self
            .state
            .lock()
            .expect("attachment storage state poisoned");
        state.status = storage_status(
            state.tags.values(),
            self.quota_bytes,
            available,
            self.min_free_bytes,
            now,
        );
        Ok(())
    }

    pub(crate) async fn reconcile(&self) -> Result<()> {
        self.state
            .lock()
            .expect("attachment storage state poisoned")
            .accounting_healthy = false;
        let tags = collect_storage_tags_bounded(&self.store)
            .await?
            .into_iter()
            .map(|tag| (tag.name.clone(), tag))
            .collect::<BTreeMap<_, _>>();
        anyhow::ensure!(
            tags.len() <= MAX_ATTACHMENT_TAGS,
            "attachment tag capacity exceeded during reconciliation"
        );
        let now = unix_timestamp_ms()?;
        let index = {
            let mut state = self
                .state
                .lock()
                .expect("attachment storage state poisoned");
            state
                .index
                .created_at_ms
                .retain(|name, _| tags.contains_key(name));
            for name in tags.keys() {
                state.index.created_at_ms.entry(name.clone()).or_insert(now);
            }
            state.tags = tags;
            state.reservations.clear();
            let available = state.status.available_bytes;
            state.status = storage_status(
                state.tags.values(),
                self.quota_bytes,
                available,
                self.min_free_bytes,
                now,
            );
            state.accounting_healthy = true;
            clone_attachment_index(&state.index)
        };
        persist_attachment_index_off_loop(self.state_dir.clone(), index).await?;
        self.recalculate_cached_status().await
    }

    pub(crate) async fn automatic_retention_pass(
        &self,
    ) -> Result<Option<meshmsg_protocol::Response>> {
        if self.retention_secs == 0 {
            return Ok(None);
        }
        let operation_id = crate::ipc::new_operation_id();
        self.remove(
            &operation_id,
            None,
            None,
            None,
            Some(self.retention_secs),
            MAX_PRUNE_TAGS,
            false,
        )
        .await
        .map(Some)
    }

    pub(crate) async fn protect_removed_blobs_from_gc(
        &self,
        values: impl IntoIterator<Item = iroh_blobs::HashAndFormat>,
    ) -> Result<RemovalGcGuard> {
        let values = values.into_iter().collect::<HashSet<_>>();
        let mut guard = RemovalGcGuard {
            state: self.state.clone(),
            records: Vec::with_capacity(values.len()),
            finished: false,
        };
        for value in values {
            // The named pin still exists while this await runs. Once acquired,
            // lookup and transition to InFlight happen under one state lock.
            let temporary = match self.store.tags().temp_tag(value).await {
                Ok(temporary) => temporary,
                Err(error) => {
                    guard.restore_before_deletion();
                    return Err(anyhow::Error::new(error)
                        .context("protect attachment blob from GC before pin removal"));
                }
            };
            let now = StdInstant::now();
            let mut state = self
                .state
                .lock()
                .expect("attachment storage state poisoned");
            state.gc_protections.retain(|_, protection| {
                matches!(protection.deadline, GcProtectionDeadline::InFlight)
                    || matches!(
                        protection.deadline,
                        GcProtectionDeadline::Until(deadline) if deadline > now
                    )
            });
            if !state.gc_protections.contains_key(&value)
                && state.gc_protections.len() >= MAX_ATTACHMENT_TAGS
            {
                drop(state);
                drop(temporary);
                guard.restore_before_deletion();
                anyhow::bail!(
                    "attachment_storage_busy: active-transfer GC protection capacity reached"
                );
            }
            let previous = match state.gc_protections.entry(value) {
                std::collections::hash_map::Entry::Occupied(mut entry) => {
                    let previous = entry.get().deadline;
                    entry.get_mut().deadline = GcProtectionDeadline::InFlight;
                    Some(previous)
                }
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(GcProtection {
                        _tag: temporary,
                        deadline: GcProtectionDeadline::InFlight,
                    });
                    guard.records.push((value, None));
                    continue;
                }
            };
            drop(state);
            drop(temporary);
            guard.records.push((value, previous));
        }
        Ok(guard)
    }

    #[allow(clippy::too_many_arguments)] // Internal selector wrapper used outside strict IPC.
    pub(crate) async fn remove(
        &self,
        operation_id: &str,
        offer_id: Option<&str>,
        direction: Option<&str>,
        provider: Option<&str>,
        older_than_secs: Option<u64>,
        maximum: usize,
        dry_run: bool,
    ) -> Result<meshmsg_protocol::Response> {
        let cutoff_ms = match older_than_secs {
            Some(age) => Some(crate::ipc::prune_cutoff_upper_bound(
                unix_timestamp_ms()?,
                age,
            )),
            None if offer_id.is_none() => Some(unix_timestamp_ms()?),
            None => None,
        };
        self.remove_at_cutoff(
            operation_id,
            offer_id,
            direction,
            provider,
            older_than_secs,
            cutoff_ms,
            maximum,
            dry_run,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)] // Mirrors the complete lifecycle selector contract.
    pub(crate) async fn remove_at_cutoff(
        &self,
        operation_id: &str,
        offer_id: Option<&str>,
        direction: Option<&str>,
        provider: Option<&str>,
        older_than_secs: Option<u64>,
        cutoff_ms: Option<u64>,
        maximum: usize,
        dry_run: bool,
    ) -> Result<meshmsg_protocol::Response> {
        self.remove_with_fault_at_cutoff(
            RemovalSpec {
                operation_id,
                offer_id,
                direction,
                provider,
                older_than_secs,
                maximum,
                dry_run,
            },
            cutoff_ms,
            &|_| Ok(()),
        )
        .await
    }

    #[cfg(test)]
    pub(crate) async fn remove_with_fault(
        &self,
        spec: RemovalSpec<'_>,
        fault: &(dyn Fn(&'static str) -> Result<()> + Sync),
    ) -> Result<meshmsg_protocol::Response> {
        let cutoff_ms = match spec.older_than_secs {
            Some(age) => Some(crate::ipc::prune_cutoff_upper_bound(
                unix_timestamp_ms()?,
                age,
            )),
            None if spec.offer_id.is_none() => Some(unix_timestamp_ms()?),
            None => None,
        };
        self.remove_with_fault_at_cutoff(spec, cutoff_ms, fault)
            .await
    }

    pub(crate) async fn remove_with_fault_at_cutoff(
        &self,
        spec: RemovalSpec<'_>,
        cutoff_ms: Option<u64>,
        fault: &(dyn Fn(&'static str) -> Result<()> + Sync),
    ) -> Result<meshmsg_protocol::Response> {
        let RemovalSpec {
            operation_id,
            offer_id,
            direction,
            provider,
            older_than_secs,
            maximum,
            dry_run,
        } = spec;
        let _permit = self.gate.clone().try_acquire_owned().map_err(|_| {
            anyhow::anyhow!(
                "attachment_storage_busy: an attachment transfer or lifecycle operation is active"
            )
        })?;
        let now = unix_timestamp_ms()?;
        anyhow::ensure!(
            offer_id.is_some() == cutoff_ms.is_none(),
            "invalid internal lifecycle cutoff context"
        );
        let cutoff = cutoff_ms;
        let lifecycle_context = match (offer_id, older_than_secs) {
            (Some(offer_id), None) => LifecycleRequestContext::Remove {
                operation_id,
                offer_id,
                direction,
                provider,
                maximum,
            },
            (None, older_than_secs) => {
                let _ = cutoff.context("prune cutoff missing")?;
                LifecycleRequestContext::Prune {
                    operation_id,
                    older_than_secs: older_than_secs.unwrap_or(0),
                    direction,
                    dry_run,
                    maximum,
                }
            }
            _ => anyhow::bail!("invalid internal lifecycle request context"),
        };
        let (before, mut selected, tags) = {
            let state = self
                .state
                .lock()
                .expect("attachment storage state poisoned");
            let mut selected = state
                .tags
                .values()
                .filter(|tag| {
                    offer_id.is_none_or(|id| tag.parsed.offer_id == id)
                        && direction.is_none_or(|value| tag.parsed.direction == value)
                        && provider
                            .is_none_or(|value| tag.parsed.provider.as_deref() == Some(value))
                        && cutoff.is_none_or(|boundary| {
                            state
                                .index
                                .created_at_ms
                                .get(&tag.name)
                                .copied()
                                .unwrap_or(now)
                                <= boundary
                        })
                })
                .map(|tag| {
                    (
                        state
                            .index
                            .created_at_ms
                            .get(&tag.name)
                            .copied()
                            .unwrap_or(now),
                        tag.name.clone(),
                    )
                })
                .collect::<Vec<_>>();
            selected.sort();
            (state.status.tagged_bytes, selected, state.tags.clone())
        };
        let limited = selected.len() > maximum;
        selected.truncate(maximum);
        let selected_names = selected
            .into_iter()
            .map(|(_, name)| name)
            .collect::<Vec<_>>();
        let selected_set = selected_names.iter().cloned().collect::<HashSet<_>>();
        let projected = tags
            .values()
            .filter(|tag| !selected_set.contains(&tag.name));
        let projected_usage = unique_storage_usage(projected).0;
        if dry_run {
            return lifecycle_response(
                &lifecycle_context,
                selected_names.len(),
                0,
                before.saturating_sub(projected_usage),
                limited,
                cutoff,
            );
        }
        let protection = self
            .protect_removed_blobs_from_gc(
                selected_names
                    .iter()
                    .filter_map(|name| tags.get(name).map(|tag| tag.hash_and_format)),
            )
            .await?;
        let mut removed = Vec::new();
        let mut failures = 0_usize;
        let mut possibly_unpinned = HashSet::new();
        for name in &selected_names {
            if fault("attachment_tag_delete").is_err() {
                failures += 1;
                continue;
            }
            if let Some(tag) = tags.get(name) {
                // Once deletion is attempted, an error or zero count cannot
                // prove that a durable pin remains. Retain the conservative guard.
                possibly_unpinned.insert(tag.hash_and_format);
            }
            match self.store.tags().delete(name.as_bytes()).await {
                Ok(count) if count != 0 => removed.push(name.clone()),
                Ok(_) => {}
                Err(_) => failures += 1,
            }
        }
        let sync_error = match fault("attachment_removal_sync") {
            Ok(()) => self
                .store
                .sync_db()
                .await
                .err()
                .map(|error| error.to_string()),
            Err(error) => Some(error.to_string()),
        };
        if failures != 0 || sync_error.is_some() {
            // Keep every guard nonexpiring through failure reconciliation, then
            // start grace only for values whose deletion may have taken effect.
            let _ = self.reconcile().await;
            protection.finish(&possibly_unpinned);
            let _ = sync_error;
            return Ok(meshmsg_protocol::Response::Error(
                meshmsg_protocol::ProtocolError::new(
                    Some(
                        lifecycle_context
                            .operation_id()
                            .parse()
                            .expect("validated operation ID"),
                    ),
                    meshmsg_protocol::ErrorCode::AttachmentRemovalPartial,
                    if removed.is_empty() {
                        meshmsg_protocol::Outcome::Unknown
                    } else {
                        meshmsg_protocol::Outcome::Partial
                    },
                ),
            ));
        }
        // Successful deletion is now database-durable. Start a complete grace
        // interval from this boundary, not from pre-deletion guard acquisition.
        protection.finish(&possibly_unpinned);
        let index = {
            let mut state = self
                .state
                .lock()
                .expect("attachment storage state poisoned");
            for name in &removed {
                state.tags.remove(name);
                state.index.created_at_ms.remove(name);
            }
            clone_attachment_index(&state.index)
        };
        if fault("attachment_removal_index_persist").is_err()
            || persist_attachment_index_off_loop(self.state_dir.clone(), index)
                .await
                .is_err()
        {
            self.recalculate_cached_status().await?;
            return Ok(meshmsg_protocol::Response::Error(
                meshmsg_protocol::ProtocolError::new(
                    Some(
                        lifecycle_context
                            .operation_id()
                            .parse()
                            .expect("validated operation ID"),
                    ),
                    meshmsg_protocol::ErrorCode::AttachmentRemovalPartial,
                    if removed.is_empty() {
                        meshmsg_protocol::Outcome::Unknown
                    } else {
                        meshmsg_protocol::Outcome::Partial
                    },
                ),
            ));
        }
        self.recalculate_cached_status().await?;
        lifecycle_response(
            &lifecycle_context,
            selected_names.len(),
            removed.len(),
            before.saturating_sub(self.status().tagged_bytes),
            limited,
            cutoff,
        )
    }
}

fn lifecycle_response(
    context: &LifecycleRequestContext<'_>,
    selected_tags: usize,
    removed_tags: usize,
    released_bytes: u64,
    limited: bool,
    cutoff_ms: Option<u64>,
) -> Result<meshmsg_protocol::Response> {
    let (offer_id, direction, provider, older_than_secs, maximum, dry_run, removed) = match context
    {
        LifecycleRequestContext::Remove {
            offer_id,
            direction,
            provider,
            maximum,
            ..
        } => (
            Some((*offer_id).parse()?),
            direction.map(str::parse).transpose()?,
            provider.map(str::parse).transpose()?,
            None,
            *maximum,
            false,
            true,
        ),
        LifecycleRequestContext::Prune {
            older_than_secs,
            direction,
            dry_run,
            maximum,
            ..
        } => (
            None,
            direction.map(str::parse).transpose()?,
            None,
            Some(*older_than_secs),
            *maximum,
            *dry_run,
            false,
        ),
    };
    let result = meshmsg_protocol::LifecycleResult {
        operation_id: context.operation_id().parse()?,
        offer_id,
        direction,
        provider,
        older_than_secs,
        maximum,
        dry_run,
        selected_tags,
        removed_tags,
        released_bytes,
        limited,
        cutoff_ms,
    };
    let response = if removed {
        meshmsg_protocol::Response::OfferRemoved(result)
    } else {
        meshmsg_protocol::Response::OffersPruned(result)
    };
    // Canonical construction validates the same invariants enforced while decoding.
    response.validate().map_err(anyhow::Error::msg)?;
    Ok(response)
}

fn clone_attachment_index(index: &AttachmentRetentionIndex) -> AttachmentRetentionIndex {
    AttachmentRetentionIndex {
        schema_version: index.schema_version,
        created_at_ms: index.created_at_ms.clone(),
    }
}

pub(crate) fn load_attachment_index(state_dir: &Path) -> Result<AttachmentRetentionIndex> {
    let path = state_dir.join(ATTACHMENT_INDEX_NAME);
    let Some(bytes) = crate::persistent::read_optional_file_bounded(
        &path,
        "attachment retention index",
        MAX_ATTACHMENT_INDEX_BYTES,
    )?
    else {
        return Ok(AttachmentRetentionIndex::default());
    };
    let probe: AttachmentIndexVersionProbe = crate::persistent::parse_json_bounded_strings(
        &bytes,
        "attachment retention index",
        MAX_ATTACHMENT_INDEX_TAG_BYTES,
    )?;
    if probe.schema_version != 1 {
        return Err(crate::persistent::PersistentError::unsupported_version(
            "attachment retention index",
            probe.schema_version,
        )
        .into());
    }
    let index: AttachmentRetentionIndex = crate::persistent::parse_json_bounded_strings(
        &bytes,
        "attachment retention index",
        MAX_ATTACHMENT_INDEX_TAG_BYTES,
    )?;
    if index.schema_version != 1 {
        return Err(crate::persistent::PersistentError::unsupported_version(
            "attachment retention index",
            u64::from(index.schema_version),
        )
        .into());
    }
    Ok(index)
}

pub(crate) fn persist_attachment_index(
    state_dir: &Path,
    index: &AttachmentRetentionIndex,
) -> Result<()> {
    let encoded = serde_json::to_vec_pretty(index)?;
    anyhow::ensure!(
        encoded.len() <= MAX_ATTACHMENT_INDEX_BYTES,
        "attachment retention index exceeds its size bound"
    );
    crate::config::atomic_write(state_dir, ATTACHMENT_INDEX_NAME, &encoded, 0o600)
        .context("persist attachment retention index")
}

async fn persist_attachment_index_off_loop(
    state_dir: PathBuf,
    index: AttachmentRetentionIndex,
) -> Result<()> {
    tokio::task::spawn_blocking(move || persist_attachment_index(&state_dir, &index))
        .await
        .context("attachment index persistence task failed")?
}

async fn available_space_off_loop(path: PathBuf) -> Result<u64> {
    tokio::task::spawn_blocking(move || {
        fs2::available_space(path).context("query attachment store free space")
    })
    .await
    .context("attachment free-space task failed")?
}

async fn complete_blob_size(
    store: &Store,
    hash_and_format: iroh_blobs::HashAndFormat,
) -> Result<u64> {
    anyhow::ensure!(
        hash_and_format.format == BlobFormat::Raw,
        "attachment_lifecycle_internal: unsupported hash_seq attachment format"
    );
    match store.blobs().status(hash_and_format.hash).await {
        Ok(iroh_blobs::api::proto::BlobStatus::Complete { size }) => Ok(size),
        Ok(iroh_blobs::api::proto::BlobStatus::Partial { size }) => anyhow::bail!(
            "attachment_lifecycle_internal: attachment blob is incomplete (reported size {size:?})"
        ),
        Ok(iroh_blobs::api::proto::BlobStatus::NotFound) => {
            anyhow::bail!("attachment_lifecycle_internal: attachment blob is missing")
        }
        Err(error) => Err(anyhow::Error::new(error)
            .context("attachment_lifecycle_internal: query attachment blob completeness")),
    }
}

async fn collect_storage_tags_bounded(store: &Store) -> Result<Vec<StorageTag>> {
    let mut stream = store
        .tags()
        .list_prefix(BLOB_TAG_PREFIX)
        .await
        .context("list attachment tags for storage reconciliation")?;
    let mut result = Vec::new();
    let mut scanned = 0_usize;
    while let Some(item) = stream.next().await {
        scanned += 1;
        anyhow::ensure!(
            scanned <= MAX_ATTACHMENT_TAG_SCAN,
            "attachment reserved-prefix scan exceeded {MAX_ATTACHMENT_TAG_SCAN} entries"
        );
        let tag = item.context("read attachment tag for storage reconciliation")?;
        let Some(parsed) = parse_pinned_blob_tag(tag.name.as_ref()) else {
            continue;
        };
        anyhow::ensure!(
            result.len() < MAX_ATTACHMENT_TAGS,
            "attachment tag capacity exceeded: more than {MAX_ATTACHMENT_TAGS} pins"
        );
        anyhow::ensure!(
            tag.format == BlobFormat::Raw,
            "unsupported hash_seq format in meshmsg attachment tag"
        );
        let name = std::str::from_utf8(tag.name.as_ref())
            .context("attachment tag is not UTF-8")?
            .to_owned();
        let hash_and_format = iroh_blobs::HashAndFormat {
            hash: tag.hash,
            format: tag.format,
        };
        let size = complete_blob_size(store, hash_and_format)
            .await
            .with_context(|| format!("validate complete attachment blob for tag {name}"))?;
        result.push(StorageTag {
            name,
            parsed,
            hash_and_format,
            size,
        });
    }
    Ok(result)
}

fn unique_storage_usage<'a>(tags: impl IntoIterator<Item = &'a StorageTag>) -> (u64, usize) {
    let mut values = HashSet::new();
    let mut bytes = 0_u64;
    for tag in tags {
        if values.insert(tag.hash_and_format) {
            bytes = bytes.saturating_add(tag.size);
        }
    }
    (bytes, values.len())
}

fn storage_status<'a>(
    tags: impl IntoIterator<Item = &'a StorageTag>,
    quota_bytes: u64,
    available_bytes: u64,
    min_free_bytes: u64,
    sampled_at_ms: u64,
) -> meshmsg_protocol::AttachmentStorageStatus {
    let tags = tags.into_iter().collect::<Vec<_>>();
    let (tagged_bytes, tagged_blobs) = unique_storage_usage(tags.iter().copied());
    let over_quota = tagged_bytes > quota_bytes;
    let below_min_free = available_bytes < min_free_bytes;
    meshmsg_protocol::AttachmentStorageStatus {
        tagged_bytes,
        tagged_blobs,
        tags: tags.len(),
        tag_capacity: MAX_ATTACHMENT_TAGS,
        quota_bytes,
        available_bytes,
        min_free_bytes,
        pressure: over_quota || below_min_free,
        over_quota,
        below_min_free,
        sampled_at_ms,
    }
}

pub(crate) fn hash_file(path: &Path) -> Result<iroh_blobs::Hash> {
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

pub(crate) fn storage_operation_error(
    default_code: &str,
    error: &anyhow::Error,
    share: bool,
    operation_id: Option<&str>,
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
        operation_id.map(|value| value.parse().expect("validated operation ID")),
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

pub(crate) struct ShareResources {
    pub(crate) store: Store,
    pub(crate) storage: AttachmentStorage,
    pub(crate) endpoint: Endpoint,
    pub(crate) secret: SecretKey,
    pub(crate) topic: TopicId,
    pub(crate) sender: GossipSender,
    pub(crate) state_dir: PathBuf,
}

pub(crate) async fn share_attachment(
    resources: ShareResources,
    operation_id: String,
    source_digest: String,
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
    let expected_digest = source_digest.clone();
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
    let offer_id = operation_id;
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
        let signed = protocol::encode_signed_offer(&secret, topic, offer, timestamp_ms)?;
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
                operation_id: offer.offer_id.parse().expect("validated operation ID"),
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
                source_digest: source_digest.parse().expect("validated source digest"),
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

pub(crate) fn raw_ticket_offer_id(ticket: &BlobTicket) -> String {
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

pub(crate) fn raw_ticket_blob_tag(ticket: &BlobTicket) -> String {
    inbound_blob_tag(
        ticket.addr().id,
        &raw_ticket_offer_id(ticket),
        AttachmentKind::File,
        "raw-ticket.blob",
    )
}

pub(crate) fn download_request_context(
    operation_id: &str,
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
                    output
                        .file_name()
                        .and_then(|value| value.to_str())
                        .unwrap_or("attachment")
                        .to_owned(),
                    None,
                )
            }
        };
    Ok(crate::ipc::DownloadRequestContext {
        operation_id: operation_id.parse()?,
        token_digest: crate::ipc::download_token_digest(token).parse()?,
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

pub(crate) fn validate_declared_attachment_size(
    declared_size: Option<u64>,
    actual_size: u64,
) -> Result<()> {
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
pub(crate) struct DownloadCommitOutcome {
    pub(crate) destination_synced: bool,
    pub(crate) cleanup_complete: bool,
    pub(crate) warnings: Vec<String>,
}

pub(crate) struct DownloadCommit<'a> {
    pub(crate) store: &'a Store,
    pub(crate) tag_name: &'a [u8],
    pub(crate) hash_and_format: iroh_blobs::HashAndFormat,
    pub(crate) staging: attachment::StagedFile,
    pub(crate) output: &'a Path,
    pub(crate) kind: AttachmentKind,
    pub(crate) max_attachment_bytes: u64,
    pub(crate) pin_already_committed: bool,
}

/// Commits the local half of a download. The named blob pin is made durable
/// before the no-clobber destination operation. Once installation succeeds,
/// subsequent sync/cleanup errors are partial-success metadata, never a false
/// `download_failed` result that would make a safe retry impossible.
pub(crate) async fn commit_download(
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
        warnings.push(format!(
            "interrupted after destination installation: {error}"
        ));
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
                    warnings.push(format!("installed content sync failed: {error}"));
                    false
                }
                Err(error) => {
                    warnings.push(format!("installed content sync task failed: {error}"));
                    false
                }
            }
        }
        Err(error) => {
            warnings.push(format!("installed content sync failed: {error}"));
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
                    warnings.push(format!("installed output parent sync failed: {error}"));
                    false
                }
                Err(error) => {
                    warnings.push(format!("installed output parent sync task failed: {error}"));
                    false
                }
            }
        }
        Err(error) => {
            warnings.push(format!("installed output parent sync failed: {error}"));
            false
        }
    };
    let destination_synced = content_synced && parent_synced;
    if let Err(error) = fault("after_destination_sync") {
        warnings.push(format!("interrupted after destination sync: {error}"));
    }

    let cleanup_complete = match fault("staging_cleanup") {
        Ok(()) => match tokio::task::spawn_blocking(move || staging.cleanup()).await {
            Ok(Ok(())) => match fault("after_staging_cleanup") {
                Ok(()) => true,
                Err(error) => {
                    warnings.push(format!("interrupted after staging cleanup: {error}"));
                    true
                }
            },
            Ok(Err(error)) => {
                warnings.push(format!("installed output staging cleanup failed: {error}"));
                false
            }
            Err(error) => {
                warnings.push(format!("installed output cleanup task failed: {error}"));
                false
            }
        },
        Err(error) => {
            warnings.push(format!("installed output staging cleanup failed: {error}"));
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

pub(crate) async fn download_attachment(
    resources: DownloadResources,
    events: broadcast::Sender<meshmsg_protocol::Event>,
    operation_id: &str,
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
    storage.preflight_free_space(0).await?;
    let token_digest = crate::ipc::download_token_digest(&offer_token);
    anyhow::ensure!(
        !output.exists(),
        "output already exists: {}",
        output.display()
    );
    // Validate the existing durability boundary before network or store work.
    let staging_path = attachment::staging_file_near(&output, ".download")?;
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
            let name = output
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or("attachment")
                .to_owned();
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
                            operation_id: operation_id.parse().expect("validated operation ID"),
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
            operation_id: operation_id.parse().expect("validated operation ID"),
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
            operation_id: operation_id.parse().expect("validated operation ID"),
            token_digest: token_digest.parse().expect("generated digest is canonical"),
            offer_id: offer.offer_id.parse().expect("validated offer ID"),
            kind: protocol_attachment_kind(offer.kind),
            name: meshmsg_protocol::AttachmentName::new(offer.name)
                .expect("validated attachment name"),
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

pub(crate) async fn list_offers_request(store: Store) -> meshmsg_protocol::Response {
    match list_pinned_blobs(&store).await {
        Ok((blobs, has_more, item_errors)) => {
            meshmsg_protocol::Response::Offers(meshmsg_protocol::OffersList {
                blobs,
                truncated: has_more || item_errors != 0,
                has_more,
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
    operation_id: &str,
    offer_id: &str,
    direction: Option<&str>,
    provider: Option<&str>,
) -> meshmsg_protocol::Response {
    let valid_direction = direction.is_none_or(|value| matches!(value, "incoming" | "outgoing"));
    let valid_provider = provider.is_none_or(|value| {
        value
            .parse::<PublicKey>()
            .is_ok_and(|key| key.to_string() == value)
    });
    if !valid_provider {
        return meshmsg_protocol::Response::Error(meshmsg_protocol::ProtocolError::new(
            Some(operation_id.parse().expect("validated operation ID")),
            meshmsg_protocol::ErrorCode::InvalidOfferSelector,
            meshmsg_protocol::Outcome::NotStarted,
        ));
    }
    if !contracts::valid_operation_id(offer_id) || !valid_direction {
        return meshmsg_protocol::Response::Error(meshmsg_protocol::ProtocolError::new(
            Some(operation_id.parse().expect("validated operation ID")),
            meshmsg_protocol::ErrorCode::InvalidOfferSelector,
            meshmsg_protocol::Outcome::NotStarted,
        ));
    }
    match storage
        .remove_at_cutoff(
            operation_id,
            Some(offer_id),
            direction,
            provider,
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
    operation_id: &str,
    older_than_secs: u64,
    cutoff_ms: u64,
    direction: Option<&str>,
    dry_run: bool,
    max_delete: usize,
) -> meshmsg_protocol::Response {
    if !direction.is_none_or(|value| matches!(value, "incoming" | "outgoing"))
        || !(1..=MAX_PRUNE_TAGS).contains(&max_delete)
    {
        return meshmsg_protocol::Response::Error(meshmsg_protocol::ProtocolError::new(
            Some(operation_id.parse().expect("validated operation ID")),
            meshmsg_protocol::ErrorCode::InvalidPruneRequest,
            meshmsg_protocol::Outcome::NotStarted,
        ));
    }
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
    operation_id: String,
    source_digest: String,
    path: PathBuf,
    max_attachment_bytes: u64,
) -> meshmsg_protocol::Response {
    let gate = resources.storage.gate.clone();
    match gate.acquire_owned().await {
        Ok(_permit) => match share_attachment(
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
            Some(operation_id.parse().expect("validated operation ID")),
            meshmsg_protocol::ErrorCode::AttachmentStorageShutdown,
            meshmsg_protocol::Outcome::Unknown,
        )),
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn download_request(
    resources: DownloadResources,
    events: broadcast::Sender<meshmsg_protocol::Event>,
    operation_id: String,
    offer: String,
    output: PathBuf,
    max_attachment_bytes: u64,
    _mode: meshmsg_protocol::DownloadMode,
) -> meshmsg_protocol::Response {
    let gate = resources.storage.gate.clone();
    match gate.acquire_owned().await {
        Ok(_permit) => {
            let _ = events.send(meshmsg_protocol::Event::DownloadStarted {
                operation_id: operation_id.parse().expect("validated operation ID"),
                output: output.clone(),
            });
            match download_attachment(
                resources,
                events,
                &operation_id,
                offer,
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
            Some(operation_id.parse().expect("validated operation ID")),
            meshmsg_protocol::ErrorCode::AttachmentStorageShutdown,
            meshmsg_protocol::Outcome::Unknown,
        )),
    }
}
