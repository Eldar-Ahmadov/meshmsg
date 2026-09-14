use super::tags::{
    parse_pinned_blob_tag, PinnedBlobTag, BLOB_TAG_PREFIX, MAX_ATTACHMENT_INDEX_TAG_BYTES,
};
use crate::ipc::LifecycleRequestContext;
use anyhow::{Context, Result};
use futures_util::StreamExt;
use iroh_blobs::{api::Store, BlobFormat};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant as StdInstant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Semaphore;

const TRANSFER_TIMEOUT: Duration = Duration::from_secs(60 * 60);
const MAX_ATTACHMENT_TAGS: usize = 8_192;
const MAX_ATTACHMENT_TAG_SCAN: usize = MAX_ATTACHMENT_TAGS * 2 + 1;
const MAX_ATTACHMENT_INDEX_BYTES: usize = 8 * 1024 * 1024;
const ATTACHMENT_INDEX_NAME: &str = "attachment-retention-v1.json";
pub(crate) const MAX_PRUNE_TAGS: usize = meshmsg_protocol::MAX_LIFECYCLE_ITEMS;

fn unix_timestamp_ms() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64)
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttachmentRetentionIndex {
    schema_version: u8,
    #[serde(deserialize_with = "deserialize_attachment_index_entries")]
    created_at_ms: BTreeMap<String, u64>,
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
    state: Arc<Mutex<AttachmentStorageState>>,
    pub(crate) gate: Arc<Semaphore>,
    quota_bytes: u64,
    min_free_bytes: u64,
    retention_secs: u64,
}

struct AttachmentStorageState {
    index: AttachmentRetentionIndex,
    tags: BTreeMap<String, StorageTag>,
    reservations: HashSet<String>,
    gc_protections: HashMap<iroh_blobs::HashAndFormat, GcProtection>,
    accounting_healthy: bool,
    status: meshmsg_protocol::AttachmentStorageStatus,
}

struct GcProtection {
    _tag: iroh_blobs::api::TempTag,
    deadline: GcProtectionDeadline,
}

#[derive(Clone, Copy)]
enum GcProtectionDeadline {
    InFlight,
    Until(StdInstant),
}

struct RemovalGcGuard {
    state: Arc<Mutex<AttachmentStorageState>>,
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
struct StorageTag {
    name: String,
    parsed: PinnedBlobTag,
    hash_and_format: iroh_blobs::HashAndFormat,
    size: u64,
}

struct RemovalSpec<'a> {
    operation_id: &'a meshmsg_protocol::OperationId,
    offer_id: Option<&'a str>,
    direction: Option<&'a str>,
    provider: Option<&'a str>,
    older_than_secs: Option<u64>,
    maximum: usize,
    dry_run: bool,
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
        let index_result = tokio::task::spawn_blocking(move || load_attachment_index(&index_dir))
            .await
            .context("attachment index load task failed")?;
        let live = collect_storage_tags_bounded(&store).await?;
        anyhow::ensure!(
            live.len() <= MAX_ATTACHMENT_TAGS,
            "attachment tag capacity exceeded: {} pins found, maximum is {MAX_ATTACHMENT_TAGS}; remove pins with a compatible older daemon or restore from backup",
            live.len()
        );
        let mut index = match index_result {
            Ok(index) => index,
            Err(error)
                if error
                    .downcast_ref::<crate::persistent::PersistentError>()
                    .is_some_and(|error| {
                        error.kind() == crate::persistent::PersistentErrorKind::Missing
                    }) =>
            {
                anyhow::ensure!(
                    live.is_empty(),
                    "attachment retention index is missing while managed attachment pins exist; restore attachment-retention-v1.json from current state or remove the pins with a compatible older daemon"
                );
                AttachmentRetentionIndex::default()
            }
            Err(error) => return Err(error),
        };
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

    #[cfg(test)]
    pub(super) fn reservations_empty(&self) -> bool {
        self.state
            .lock()
            .expect("attachment storage state poisoned")
            .reservations
            .is_empty()
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

    pub(super) async fn preflight_free_space(&self, additional_bytes: u64) -> Result<()> {
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

    fn admit_pin(
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

    pub(super) async fn commit_pin(
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

    async fn rollback_new_pin(
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

    pub(super) async fn rollback_committed_pin(
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

    async fn recalculate_cached_status(&self) -> Result<()> {
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

    async fn reconcile(&self) -> Result<()> {
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

    async fn protect_removed_blobs_from_gc(
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
    async fn remove(
        &self,
        operation_id: &meshmsg_protocol::OperationId,
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
    pub(super) async fn remove_at_cutoff(
        &self,
        operation_id: &meshmsg_protocol::OperationId,
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
    async fn remove_with_fault(
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

    async fn remove_with_fault_at_cutoff(
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
                    Some(lifecycle_context.operation_id().clone()),
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
                    Some(lifecycle_context.operation_id().clone()),
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
    let response = match context {
        LifecycleRequestContext::Remove {
            offer_id,
            direction,
            provider,
            maximum,
            ..
        } => {
            anyhow::ensure!(cutoff_ms.is_none(), "remove unexpectedly resolved a cutoff");
            meshmsg_protocol::Response::OfferRemoved(meshmsg_protocol::OfferRemoved {
                operation_id: context.operation_id().clone(),
                offer_id: (*offer_id).parse()?,
                direction: direction.map(str::parse).transpose()?,
                provider: provider.map(str::parse).transpose()?,
                maximum: *maximum,
                selected_tags,
                removed_tags,
                released_bytes,
                limited,
            })
        }
        LifecycleRequestContext::Prune {
            older_than_secs,
            direction,
            dry_run,
            maximum,
            ..
        } => meshmsg_protocol::Response::OffersPruned(meshmsg_protocol::OffersPruned {
            operation_id: context.operation_id().clone(),
            direction: direction.map(str::parse).transpose()?,
            older_than_secs: *older_than_secs,
            maximum: *maximum,
            dry_run: *dry_run,
            selected_tags,
            removed_tags,
            released_bytes,
            limited,
            cutoff_ms: cutoff_ms.context("prune response is missing its resolved cutoff")?,
        }),
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

fn load_attachment_index(state_dir: &Path) -> Result<AttachmentRetentionIndex> {
    let path = state_dir.join(ATTACHMENT_INDEX_NAME);
    let bytes = crate::persistent::read_file_bounded(
        &path,
        "attachment retention index",
        MAX_ATTACHMENT_INDEX_BYTES,
    )?;
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

fn persist_attachment_index(state_dir: &Path, index: &AttachmentRetentionIndex) -> Result<()> {
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

#[cfg(test)]
mod tests {
    use super::super::{
        tags::{self, *},
        AttachmentKind,
    };
    use super::*;
    use iroh_blobs::{
        protocol::ChunkRangesExt,
        store::{
            fs::{options::Options as FsStoreOptions, FsStore},
            GcConfig,
        },
    };
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::Ordering;
    use tokio::io::AsyncReadExt;

    static TEST_OPERATION_ID: std::sync::LazyLock<meshmsg_protocol::OperationId> =
        std::sync::LazyLock::new(|| "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".parse().unwrap());

    fn response_error(response: &meshmsg_protocol::Response) -> &meshmsg_protocol::ProtocolError {
        match response {
            meshmsg_protocol::Response::Error(error) => error,
            _ => panic!("expected protocol error"),
        }
    }

    struct LifecycleCounts {
        selected_tags: usize,
        removed_tags: usize,
        released_bytes: u64,
        limited: bool,
    }

    fn lifecycle_result(response: &meshmsg_protocol::Response) -> LifecycleCounts {
        let (selected_tags, removed_tags, released_bytes, limited) = match response {
            meshmsg_protocol::Response::OfferRemoved(value) => (
                value.selected_tags,
                value.removed_tags,
                value.released_bytes,
                value.limited,
            ),
            meshmsg_protocol::Response::OffersPruned(value) => (
                value.selected_tags,
                value.removed_tags,
                value.released_bytes,
                value.limited,
            ),
            _ => panic!("expected lifecycle response"),
        };
        LifecycleCounts {
            selected_tags,
            removed_tags,
            released_bytes,
            limited,
        }
    }

    fn encoded_bao(data: &[u8], ranges: &bao_tree::ChunkRanges) -> (iroh_blobs::Hash, Vec<u8>) {
        use bao_tree::io::outboard::PreOrderMemOutboard;
        let outboard = PreOrderMemOutboard::create(data, iroh_blobs::store::IROH_BLOCK_SIZE);
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&(data.len() as u64).to_le_bytes());
        bao_tree::io::sync::encode_ranges_validated(data, &outboard, ranges, &mut encoded).unwrap();
        (outboard.root.into(), encoded)
    }

    async fn lifecycle_test_store(label: &str) -> (PathBuf, PathBuf, Store) {
        let root =
            std::env::temp_dir().join(format!("meshmsg-storage-{label}-{}", rand::random::<u64>()));
        let state = root.join("state");
        let blob_root = root.join("blobs");
        std::fs::create_dir_all(&state).unwrap();
        let store: Store =
            FsStore::load_with_opts(blob_root.join("blobs.db"), FsStoreOptions::new(&blob_root))
                .await
                .unwrap()
                .into();
        persist_attachment_index(&state, &AttachmentRetentionIndex::default()).unwrap();
        (root, state, store)
    }

    #[tokio::test]
    async fn missing_attachment_index_initializes_only_an_empty_fresh_store() {
        let (root, state, store) = lifecycle_test_store("missing-index-empty").await;
        std::fs::remove_file(state.join(ATTACHMENT_INDEX_NAME)).unwrap();

        let storage = AttachmentStorage::open(store.clone(), root.join("blobs"), &state, 100, 0, 0)
            .await
            .unwrap();
        assert_eq!(storage.status().tags, 0);
        assert!(state.join(ATTACHMENT_INDEX_NAME).is_file());

        drop(storage);
        drop(store);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn managed_pins_without_attachment_index_fail_closed() {
        let (root, state, store) = lifecycle_test_store("missing-index-pins").await;
        std::fs::remove_file(state.join(ATTACHMENT_INDEX_NAME)).unwrap();
        let tag = outbound_blob_tag(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            AttachmentKind::File,
            "existing.bin",
        );
        pin_test_blob(&store, &root, b"existing", &[tag]).await;

        let error = AttachmentStorage::open(store.clone(), root.join("blobs"), &state, 100, 0, 0)
            .await
            .err()
            .expect("managed pins without a current index must fail closed");
        let message = format!("{error:#}");
        assert!(message.contains("attachment retention index is missing"));
        assert!(message.contains("restore attachment-retention-v1.json"));
        assert!(!state.join(ATTACHMENT_INDEX_NAME).exists());

        drop(store);
        let _ = std::fs::remove_dir_all(root);
    }

    async fn pin_test_blob(store: &Store, root: &Path, bytes: &[u8], tags: &[String]) {
        let path = root.join(format!("source-{}", rand::random::<u64>()));
        std::fs::write(&path, bytes).unwrap();
        let imported = store.blobs().add_path(&path).temp_tag().await.unwrap();
        for tag in tags {
            store
                .tags()
                .set(tag.as_bytes(), imported.hash_and_format())
                .await
                .unwrap();
        }
        store.sync_db().await.unwrap();
    }

    #[tokio::test]
    async fn incomplete_and_missing_pins_fail_closed_then_restart_accounts_completion() {
        let (root, state, store) = lifecycle_test_store("incomplete-reconcile").await;
        let data = vec![9_u8; 64 * 1024];
        let partial_ranges = bao_tree::ChunkRanges::chunks(0..1);
        let (hash, partial) = encoded_bao(&data, &partial_ranges);
        store
            .blobs()
            .import_bao_bytes(hash, partial_ranges, partial)
            .await
            .unwrap();
        assert!(matches!(
            store.blobs().status(hash).await.unwrap(),
            iroh_blobs::api::proto::BlobStatus::Partial { .. }
        ));
        let partial_tag = outbound_blob_tag(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1",
            AttachmentKind::File,
            "partial",
        );
        store
            .tags()
            .set(partial_tag.as_bytes(), iroh_blobs::HashAndFormat::raw(hash))
            .await
            .unwrap();
        store.sync_db().await.unwrap();
        let (listed, truncated, item_errors) = tags::list_pinned_blobs(&store).await.unwrap();
        assert!(listed.is_empty());
        assert!(truncated);
        assert_eq!(item_errors, 1, "partial blob must be an item error");
        let error = AttachmentStorage::open(
            store.clone(),
            root.join("blobs"),
            &state,
            data.len() as u64,
            0,
            0,
        )
        .await
        .err()
        .expect("partial tagged blob must fail closed");
        assert!(format!("{error:#}").contains("incomplete"));

        let all = bao_tree::ChunkRanges::all();
        let (_, complete) = encoded_bao(&data, &all);
        store
            .blobs()
            .import_bao_bytes(hash, all, complete)
            .await
            .unwrap();
        let storage = AttachmentStorage::open(
            store.clone(),
            root.join("blobs"),
            &state,
            data.len() as u64,
            0,
            0,
        )
        .await
        .unwrap();
        assert_eq!(storage.status().tagged_bytes, data.len() as u64);
        assert!(storage
            .admit_pin(
                "meshmsg/out/v1/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb1/file/eA",
                iroh_blobs::HashAndFormat::raw(iroh_blobs::Hash::new(b"x")),
                1,
            )
            .is_err());
        drop(storage);
        let restarted = AttachmentStorage::open(
            store.clone(),
            root.join("blobs"),
            &state,
            data.len() as u64,
            0,
            0,
        )
        .await
        .unwrap();
        assert_eq!(restarted.status().tagged_bytes, data.len() as u64);
        drop(restarted);

        store.tags().delete(partial_tag.as_bytes()).await.unwrap();
        let missing_hash = iroh_blobs::Hash::new(b"not stored");
        let missing_tag = outbound_blob_tag(
            "ccccccccccccccccccccccccccccccc1",
            AttachmentKind::File,
            "missing",
        );
        store
            .tags()
            .set(
                missing_tag.as_bytes(),
                iroh_blobs::HashAndFormat::raw(missing_hash),
            )
            .await
            .unwrap();
        store.sync_db().await.unwrap();
        let error = AttachmentStorage::open(store.clone(), root.join("blobs"), &state, 100, 0, 0)
            .await
            .err()
            .expect("missing tagged blob must fail closed");
        assert!(format!("{error:#}").contains("missing"));
        drop(store);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn concurrent_partial_completion_is_atomically_charged_without_restart() {
        let (root, state, store) = lifecycle_test_store("concurrent-completion").await;
        let data = vec![7_u8; 96 * 1024];
        let partial_ranges = bao_tree::ChunkRanges::chunks(0..1);
        let (hash, partial) = encoded_bao(&data, &partial_ranges);
        store
            .blobs()
            .import_bao_bytes(hash, partial_ranges, partial)
            .await
            .unwrap();
        let storage = AttachmentStorage::open(
            store.clone(),
            root.join("blobs"),
            &state,
            data.len() as u64,
            0,
            0,
        )
        .await
        .unwrap();
        let tag = outbound_blob_tag(
            "ddddddddddddddddddddddddddddddd1",
            AttachmentKind::File,
            "concurrent",
        );
        let parsed = parse_pinned_blob_tag(tag.as_bytes()).unwrap();
        let hash_and_format = iroh_blobs::HashAndFormat::raw(hash);
        let error = storage
            .commit_pin(
                &tag,
                parsed.clone(),
                hash_and_format,
                data.len() as u64,
                &|_| Ok(()),
            )
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("incomplete"));
        assert_eq!(storage.status().tagged_bytes, 0);
        assert!(storage.state.lock().unwrap().reservations.is_empty());

        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let complete_store = store.clone();
        let complete_data = data.clone();
        let complete_barrier = barrier.clone();
        let completion = tokio::spawn(async move {
            complete_barrier.wait().await;
            let all = bao_tree::ChunkRanges::all();
            let (_, encoded) = encoded_bao(&complete_data, &all);
            complete_store
                .blobs()
                .import_bao_bytes(hash, all, encoded)
                .await
                .unwrap();
        });
        barrier.wait().await;
        completion.await.unwrap();
        let observed_during_commit = std::sync::atomic::AtomicU64::new(0);
        assert!(storage
            .commit_pin(
                &tag,
                parsed,
                hash_and_format,
                data.len() as u64,
                &|boundary| {
                    if boundary == "before_attachment_index_persist" {
                        observed_during_commit
                            .store(storage.status().tagged_bytes, Ordering::SeqCst);
                    }
                    Ok(())
                }
            )
            .await
            .unwrap());
        assert_eq!(
            observed_during_commit.load(Ordering::SeqCst),
            data.len() as u64,
            "cached quota must update atomically before index persistence"
        );
        assert_eq!(storage.status().tagged_bytes, data.len() as u64);
        assert_eq!(storage.status().tagged_blobs, 1);
        assert!(storage
            .admit_pin(
                "meshmsg/out/v1/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeee1/file/eA",
                iroh_blobs::HashAndFormat::raw(iroh_blobs::Hash::new(b"boundary")),
                1,
            )
            .is_err());
        drop(store);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn removal_gc_guard_is_inflight_through_delete_sync_and_gets_full_post_commit_grace() {
        let (root, state, store) = lifecycle_test_store("gc-guard-stalls").await;
        let tag = outbound_blob_tag(
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            AttachmentKind::File,
            "stall",
        );
        pin_test_blob(&store, &root, b"guarded", std::slice::from_ref(&tag)).await;
        let hash_and_format = iroh_blobs::HashAndFormat::raw(iroh_blobs::Hash::new(b"guarded"));
        let storage = AttachmentStorage::open(store.clone(), root.join("blobs"), &state, 100, 0, 0)
            .await
            .unwrap();
        // Force an expiry-boundary replacement. Refresh may remove this expired
        // entry before begin, but begin must atomically install InFlight either way.
        let expired = store.tags().temp_tag(hash_and_format).await.unwrap();
        storage.state.lock().unwrap().gc_protections.insert(
            hash_and_format,
            GcProtection {
                _tag: expired,
                deadline: GcProtectionDeadline::Until(StdInstant::now()),
            },
        );

        let delete_entered = Arc::new(std::sync::Barrier::new(2));
        let delete_release = Arc::new(std::sync::Barrier::new(2));
        let sync_entered = Arc::new(std::sync::Barrier::new(2));
        let sync_release = Arc::new(std::sync::Barrier::new(2));
        let task_storage = storage.clone();
        let task_delete_entered = delete_entered.clone();
        let task_delete_release = delete_release.clone();
        let task_sync_entered = sync_entered.clone();
        let task_sync_release = sync_release.clone();
        let removal = tokio::spawn(async move {
            let fault = move |boundary| {
                if boundary == "attachment_tag_delete" {
                    task_delete_entered.wait();
                    task_delete_release.wait();
                } else if boundary == "attachment_removal_sync" {
                    task_sync_entered.wait();
                    task_sync_release.wait();
                }
                Ok(())
            };
            task_storage
                .remove_with_fault(
                    RemovalSpec {
                        operation_id: &TEST_OPERATION_ID,
                        offer_id: Some("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"),
                        direction: None,
                        provider: None,
                        older_than_secs: None,
                        maximum: 1,
                        dry_run: false,
                    },
                    &fault,
                )
                .await
        });

        tokio::task::spawn_blocking(move || delete_entered.wait())
            .await
            .unwrap();
        storage.refresh_free_space().await.unwrap();
        assert!(matches!(
            storage
                .state
                .lock()
                .unwrap()
                .gc_protections
                .get(&hash_and_format)
                .map(|entry| entry.deadline),
            Some(GcProtectionDeadline::InFlight)
        ));
        tokio::task::spawn_blocking(move || delete_release.wait())
            .await
            .unwrap();

        tokio::task::spawn_blocking(move || sync_entered.wait())
            .await
            .unwrap();
        storage.refresh_free_space().await.unwrap();
        assert!(matches!(
            storage
                .state
                .lock()
                .unwrap()
                .gc_protections
                .get(&hash_and_format)
                .map(|entry| entry.deadline),
            Some(GcProtectionDeadline::InFlight)
        ));
        let sync_finished_at = StdInstant::now();
        tokio::task::spawn_blocking(move || sync_release.wait())
            .await
            .unwrap();
        removal.await.unwrap().unwrap();
        let deadline = match storage
            .state
            .lock()
            .unwrap()
            .gc_protections
            .get(&hash_and_format)
            .map(|entry| entry.deadline)
        {
            Some(GcProtectionDeadline::Until(deadline)) => deadline,
            _ => panic!("successful removal did not finalize its GC guard"),
        };
        assert!(deadline >= sync_finished_at + TRANSFER_TIMEOUT);
        drop(store);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn removal_gc_guard_restores_prior_state_when_deletion_never_starts() {
        let (root, state, store) = lifecycle_test_store("gc-guard-rollback").await;
        let tags = [
            outbound_blob_tag(
                "11111111111111111111111111111112",
                AttachmentKind::File,
                "prior",
            ),
            outbound_blob_tag(
                "22222222222222222222222222222223",
                AttachmentKind::File,
                "new",
            ),
        ];
        pin_test_blob(&store, &root, b"prior", std::slice::from_ref(&tags[0])).await;
        pin_test_blob(&store, &root, b"new", std::slice::from_ref(&tags[1])).await;
        let prior_hash = iroh_blobs::HashAndFormat::raw(iroh_blobs::Hash::new(b"prior"));
        let new_hash = iroh_blobs::HashAndFormat::raw(iroh_blobs::Hash::new(b"new"));
        let storage = AttachmentStorage::open(store.clone(), root.join("blobs"), &state, 100, 0, 0)
            .await
            .unwrap();
        let prior_deadline = StdInstant::now() + Duration::from_secs(300);
        let prior_temp = store.tags().temp_tag(prior_hash).await.unwrap();
        storage.state.lock().unwrap().gc_protections.insert(
            prior_hash,
            GcProtection {
                _tag: prior_temp,
                deadline: GcProtectionDeadline::Until(prior_deadline),
            },
        );
        let result = storage
            .remove_with_fault(
                RemovalSpec {
                    operation_id: &TEST_OPERATION_ID,
                    offer_id: None,
                    direction: None,
                    provider: None,
                    older_than_secs: None,
                    maximum: 2,
                    dry_run: false,
                },
                &|boundary| {
                    if boundary == "attachment_tag_delete" {
                        anyhow::bail!("stopped before deletion")
                    }
                    Ok(())
                },
            )
            .await
            .unwrap();
        assert!(matches!(result, meshmsg_protocol::Response::Error(_)));
        {
            let state = storage.state.lock().unwrap();
            assert!(matches!(
                state
                    .gc_protections
                    .get(&prior_hash)
                    .map(|entry| entry.deadline),
                Some(GcProtectionDeadline::Until(deadline)) if deadline == prior_deadline
            ));
            assert!(!state.gc_protections.contains_key(&new_hash));
        }
        assert_eq!(storage.status().tags, 2);

        let failed_sync_started = StdInstant::now();
        let result = storage
            .remove_with_fault(
                RemovalSpec {
                    operation_id: &TEST_OPERATION_ID,
                    offer_id: None,
                    direction: None,
                    provider: None,
                    older_than_secs: None,
                    maximum: 2,
                    dry_run: false,
                },
                &|boundary| {
                    if boundary == "attachment_removal_sync" {
                        anyhow::bail!("injected sync failure")
                    }
                    Ok(())
                },
            )
            .await
            .unwrap();
        let error = response_error(&result);
        assert_eq!(
            error.code,
            meshmsg_protocol::ErrorCode::AttachmentRemovalPartial
        );
        let state = storage.state.lock().unwrap();
        for value in [prior_hash, new_hash] {
            assert!(matches!(
                state
                    .gc_protections
                    .get(&value)
                    .map(|entry| entry.deadline),
                Some(GcProtectionDeadline::Until(deadline))
                    if deadline >= failed_sync_started + TRANSFER_TIMEOUT
            ));
        }
        drop(state);
        drop(store);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn active_provider_read_survives_concurrent_pin_removal_and_observed_gc() {
        let root =
            std::env::temp_dir().join(format!("meshmsg-active-read-gc-{}", rand::random::<u64>()));
        let state = root.join("state");
        let blob_root = root.join("blobs");
        std::fs::create_dir_all(&state).unwrap();
        let gc_rounds = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let gc_armed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let gc_barrier = Arc::new(tokio::sync::Barrier::new(2));
        let callback_rounds = gc_rounds.clone();
        let callback_armed = gc_armed.clone();
        let callback_barrier = gc_barrier.clone();
        let mut options = FsStoreOptions::new(&blob_root);
        options.gc = Some(GcConfig {
            interval: Duration::from_millis(20),
            add_protected: Some(Arc::new(move |_| {
                let rounds = callback_rounds.clone();
                let armed = callback_armed.clone();
                let barrier = callback_barrier.clone();
                Box::pin(async move {
                    rounds.fetch_add(1, Ordering::SeqCst);
                    if armed.load(Ordering::SeqCst) {
                        barrier.wait().await;
                    }
                    iroh_blobs::store::ProtectOutcome::Continue
                })
            })),
        });
        let store: Store = FsStore::load_with_opts(blob_root.join("blobs.db"), options)
            .await
            .unwrap()
            .into();
        persist_attachment_index(&state, &AttachmentRetentionIndex::default()).unwrap();
        let data = vec![5_u8; 2 * 1024 * 1024];
        let tag = outbound_blob_tag(
            "fffffffffffffffffffffffffffffff1",
            AttachmentKind::File,
            "active",
        );
        pin_test_blob(&store, &root, &data, std::slice::from_ref(&tag)).await;
        let hash = iroh_blobs::Hash::new(&data);
        let storage = AttachmentStorage::open(
            store.clone(),
            blob_root.clone(),
            &state,
            data.len() as u64,
            0,
            0,
        )
        .await
        .unwrap();

        let mut reader = store.blobs().reader(hash);
        let mut prefix = vec![0_u8; 16 * 1024];
        reader.read_exact(&mut prefix).await.unwrap();
        assert_eq!(prefix, data[..prefix.len()]);
        storage
            .remove(
                &TEST_OPERATION_ID,
                Some("fffffffffffffffffffffffffffffff1"),
                None,
                None,
                None,
                1,
                false,
            )
            .await
            .unwrap();
        assert_eq!(storage.status().tags, 0);
        assert!(storage
            .state
            .lock()
            .unwrap()
            .gc_protections
            .contains_key(&iroh_blobs::HashAndFormat::raw(hash)));

        gc_armed.store(true, Ordering::SeqCst);
        tokio::time::timeout(Duration::from_secs(5), gc_barrier.wait())
            .await
            .expect("GC did not reach its post-removal protection barrier");
        gc_armed.store(false, Ordering::SeqCst);
        let completed_round = gc_rounds.load(Ordering::SeqCst);
        tokio::time::timeout(Duration::from_secs(5), async {
            while gc_rounds.load(Ordering::SeqCst) <= completed_round {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("GC did not complete the post-removal cycle");
        assert!(matches!(
            store.blobs().status(hash).await.unwrap(),
            iroh_blobs::api::proto::BlobStatus::Complete { .. }
        ));
        let mut suffix = Vec::new();
        reader.read_to_end(&mut suffix).await.unwrap();
        assert_eq!(suffix, data[prefix.len()..]);
        drop(store);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn attachment_storage_deduplicates_quota_and_releases_only_last_reference() {
        let (root, state, store) = lifecycle_test_store("dedup").await;
        let first = outbound_blob_tag(
            "00000000000000000000000000000001",
            AttachmentKind::File,
            "same.bin",
        );
        let second = outbound_blob_tag(
            "00000000000000000000000000000002",
            AttachmentKind::File,
            "same.bin",
        );
        pin_test_blob(&store, &root, b"same bytes", &[first, second]).await;
        let storage = AttachmentStorage::open(store.clone(), root.join("blobs"), &state, 10, 0, 60)
            .await
            .unwrap();
        let status = storage.status();
        assert_eq!(status.tagged_bytes, 10);
        assert_eq!(status.tagged_blobs, 1);
        assert_eq!(status.tags, 2);
        storage
            .admit_pin(
                "meshmsg/out/v1/new/file/bmV3",
                iroh_blobs::HashAndFormat::raw(iroh_blobs::Hash::new(b"same bytes")),
                u64::MAX,
            )
            .unwrap();
        assert!(storage
            .admit_pin(
                "meshmsg/out/v1/other/file/b3RoZXI",
                iroh_blobs::HashAndFormat::raw(iroh_blobs::Hash::new(b"other")),
                1,
            )
            .unwrap_err()
            .to_string()
            .starts_with("attachment_quota_exceeded:"));

        let removed = storage
            .remove(
                &TEST_OPERATION_ID,
                Some("00000000000000000000000000000001"),
                None,
                None,
                None,
                512,
                false,
            )
            .await
            .unwrap();
        assert_eq!(lifecycle_result(&removed).removed_tags, 1);
        assert_eq!(lifecycle_result(&removed).released_bytes, 0);
        let removed = storage
            .remove(
                &TEST_OPERATION_ID,
                Some("00000000000000000000000000000002"),
                None,
                None,
                None,
                512,
                false,
            )
            .await
            .unwrap();
        assert_eq!(lifecycle_result(&removed).released_bytes, 10);
        assert_eq!(storage.status().tagged_bytes, 0);
        storage
            .admit_pin(
                "meshmsg/out/v1/x/file/eA",
                iroh_blobs::HashAndFormat::raw(iroh_blobs::Hash::new(b"x")),
                10,
            )
            .unwrap();
        drop(store);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn attachment_index_read_is_bounded_versioned_and_permission_safe() {
        let state = std::env::temp_dir().join(format!(
            "meshmsg-attachment-index-test-{}",
            rand::random::<u64>()
        ));
        crate::config::prepare_state_dir(&state).unwrap();
        let path = state.join(ATTACHMENT_INDEX_NAME);
        let missing = load_attachment_index(&state).unwrap_err();
        assert_eq!(
            missing
                .downcast_ref::<crate::persistent::PersistentError>()
                .unwrap()
                .kind(),
            crate::persistent::PersistentErrorKind::Missing
        );

        persist_attachment_index(&state, &AttachmentRetentionIndex::default()).unwrap();
        let mut exact = std::fs::read(&path).unwrap();
        exact.resize(MAX_ATTACHMENT_INDEX_BYTES, b' ');
        std::fs::write(&path, &exact).unwrap();
        assert!(load_attachment_index(&state)
            .unwrap()
            .created_at_ms
            .is_empty());

        std::fs::write(&path, vec![b' '; MAX_ATTACHMENT_INDEX_BYTES + 1]).unwrap();
        assert!(load_attachment_index(&state)
            .unwrap_err()
            .to_string()
            .contains("exceeds its size limit"));
        std::fs::write(&path, b"{\"schema_version\":1").unwrap();
        assert!(load_attachment_index(&state)
            .unwrap_err()
            .to_string()
            .contains("could not parse attachment retention index"));
        std::fs::write(&path, br#"{"schema_version":256,"created_at_ms":{}}"#).unwrap();
        assert!(load_attachment_index(&state)
            .unwrap_err()
            .to_string()
            .contains("unsupported attachment retention index schema version 256"));
        std::fs::write(
            &path,
            format!(
                "{{\"schema_version\":1,\"created_at_ms\":{{\"{}\":1}}}}",
                "x".repeat(MAX_ATTACHMENT_INDEX_TAG_BYTES + 1)
            ),
        )
        .unwrap();
        assert!(load_attachment_index(&state).is_err());

        for (exact, oversized) in [
            (
                r"\u0078".repeat(MAX_ATTACHMENT_INDEX_TAG_BYTES),
                r"\u0078".repeat(MAX_ATTACHMENT_INDEX_TAG_BYTES + 1),
            ),
            (
                r"\\".repeat(MAX_ATTACHMENT_INDEX_TAG_BYTES),
                r"\\".repeat(MAX_ATTACHMENT_INDEX_TAG_BYTES + 1),
            ),
        ] {
            std::fs::write(
                &path,
                format!("{{\"schema_version\":1,\"created_at_ms\":{{\"{exact}\":1}}}}"),
            )
            .unwrap();
            let loaded = load_attachment_index(&state).unwrap();
            assert_eq!(
                loaded.created_at_ms.keys().next().unwrap().len(),
                MAX_ATTACHMENT_INDEX_TAG_BYTES
            );
            std::fs::write(
                &path,
                format!("{{\"schema_version\":1,\"created_at_ms\":{{\"{oversized}\":1}}}}"),
            )
            .unwrap();
            assert!(load_attachment_index(&state).is_err());
        }

        let mut compact = BTreeMap::new();
        for index in 0..MAX_ATTACHMENT_TAGS {
            compact.insert(format!("k{index:04x}"), index as u64);
        }
        let boundary = serde_json::to_vec(&serde_json::json!({
            "schema_version":1,
            "created_at_ms":compact,
        }))
        .unwrap();
        assert!(boundary.len() < MAX_ATTACHMENT_INDEX_BYTES);
        std::fs::write(&path, &boundary).unwrap();
        assert_eq!(
            load_attachment_index(&state).unwrap().created_at_ms.len(),
            MAX_ATTACHMENT_TAGS
        );
        let insertion = boundary.len() - 2;
        let mut amplified = boundary;
        amplified.splice(insertion..insertion, b",\"overflow\":1".iter().copied());
        std::fs::write(&path, amplified).unwrap();
        assert!(load_attachment_index(&state).is_err());

        persist_attachment_index(&state, &AttachmentRetentionIndex::default()).unwrap();
        #[cfg(unix)]
        {
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            std::fs::remove_file(&path).unwrap();
            std::os::unix::fs::symlink(state.join("missing"), &path).unwrap();
            assert!(load_attachment_index(&state).is_err());
        }
        std::fs::remove_dir_all(state).unwrap();
    }

    #[tokio::test]
    async fn attachment_prune_is_oldest_first_bounded_dry_run_and_persistent() {
        let (root, state, store) = lifecycle_test_store("prune").await;
        let tags = (1..=3)
            .map(|id| {
                outbound_blob_tag(
                    &format!("{id:032x}"),
                    AttachmentKind::File,
                    &format!("{id}.bin"),
                )
            })
            .collect::<Vec<_>>();
        for (id, tag) in tags.iter().enumerate() {
            pin_test_blob(&store, &root, &[id as u8], std::slice::from_ref(tag)).await;
        }
        let storage =
            AttachmentStorage::open(store.clone(), root.join("blobs"), &state, 100, 0, 60)
                .await
                .unwrap();
        let now = unix_timestamp_ms().unwrap();
        {
            let mut lifecycle = storage.state.lock().unwrap();
            lifecycle
                .index
                .created_at_ms
                .insert(tags[0].clone(), now - 20_000);
            lifecycle
                .index
                .created_at_ms
                .insert(tags[1].clone(), now - 10_000);
            lifecycle.index.created_at_ms.insert(tags[2].clone(), now);
            persist_attachment_index(&state, &lifecycle.index).unwrap();
        }
        let dry = storage
            .remove(&TEST_OPERATION_ID, None, None, None, Some(10), 1, true)
            .await
            .unwrap();
        assert_eq!(lifecycle_result(&dry).selected_tags, 1);
        assert_eq!(lifecycle_result(&dry).removed_tags, 0);
        assert!(lifecycle_result(&dry).limited);
        assert_eq!(storage.status().tags, 3);
        let pruned = storage
            .remove(&TEST_OPERATION_ID, None, None, None, Some(10), 2, false)
            .await
            .unwrap();
        assert_eq!(
            lifecycle_result(&pruned).removed_tags,
            2,
            "the exact cutoff is inclusive"
        );
        assert_eq!(storage.status().tags, 1);
        let held = storage.gate.clone().acquire_owned().await.unwrap();
        let busy = storage
            .remove(&TEST_OPERATION_ID, None, None, None, Some(0), 1, false)
            .await
            .unwrap_err();
        assert!(busy.to_string().starts_with("attachment_storage_busy:"));
        drop(held);

        drop(storage);
        // Crash recovery reconciles stale metadata against authoritative pins.
        let mut persisted: AttachmentRetentionIndex =
            serde_json::from_slice(&std::fs::read(state.join(ATTACHMENT_INDEX_NAME)).unwrap())
                .unwrap();
        persisted
            .created_at_ms
            .insert("meshmsg/out/v1/stale/file/c3RhbGU".into(), 1);
        persist_attachment_index(&state, &persisted).unwrap();
        let reopened =
            AttachmentStorage::open(store.clone(), root.join("blobs"), &state, 100, 0, 60)
                .await
                .unwrap();
        assert_eq!(reopened.state.lock().unwrap().index.created_at_ms.len(), 1);
        drop(store);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn startup_reconciliation_bounds_reserved_prefix_and_ignores_foreign_tags() {
        let (root, state, store) = lifecycle_test_store("startup-bound").await;
        let imported = store.blobs().add_slice(b"present").await.unwrap();
        let hash = imported.hash;
        for id in 0..=MAX_ATTACHMENT_TAGS {
            let tag = outbound_blob_tag(&format!("{id:032x}"), AttachmentKind::File, "x");
            store
                .tags()
                .set(tag.as_bytes(), iroh_blobs::HashAndFormat::raw(hash))
                .await
                .unwrap();
        }
        for id in 0..100 {
            store
                .tags()
                .set(
                    format!("foreign/{id:04}").as_bytes(),
                    iroh_blobs::HashAndFormat::hash_seq(hash),
                )
                .await
                .unwrap();
        }
        store.sync_db().await.unwrap();
        let error =
            AttachmentStorage::open(store.clone(), root.join("blobs"), &state, u64::MAX, 0, 0)
                .await
                .err()
                .unwrap();
        assert!(error.to_string().contains("tag capacity exceeded"));
        drop(store);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn foreign_tags_are_preserved_and_hash_seq_meshmsg_tags_fail_closed() {
        let (root, state, store) = lifecycle_test_store("foreign-format").await;
        let imported = store.blobs().add_slice(b"foreign").await.unwrap();
        let hash = imported.hash;
        store
            .tags()
            .set(b"foreign/keep", iroh_blobs::HashAndFormat::hash_seq(hash))
            .await
            .unwrap();
        let valid = outbound_blob_tag(
            "11111111111111111111111111111111",
            AttachmentKind::File,
            "x",
        );
        store
            .tags()
            .set(valid.as_bytes(), iroh_blobs::HashAndFormat::raw(hash))
            .await
            .unwrap();
        store.sync_db().await.unwrap();
        let storage = AttachmentStorage::open(store.clone(), root.join("blobs"), &state, 100, 0, 0)
            .await
            .unwrap();
        assert!(storage
            .admit_pin(
                "meshmsg/out/v1/new/file/eA",
                iroh_blobs::HashAndFormat::hash_seq(hash),
                0,
            )
            .unwrap_err()
            .to_string()
            .contains("hash_seq"));
        storage
            .remove(
                &TEST_OPERATION_ID,
                Some("11111111111111111111111111111111"),
                None,
                None,
                None,
                1,
                false,
            )
            .await
            .unwrap();
        assert!(store.tags().get(b"foreign/keep").await.unwrap().is_some());
        let unsupported = outbound_blob_tag(
            "22222222222222222222222222222222",
            AttachmentKind::File,
            "x",
        );
        store
            .tags()
            .set(
                unsupported.as_bytes(),
                iroh_blobs::HashAndFormat::hash_seq(hash),
            )
            .await
            .unwrap();
        store.sync_db().await.unwrap();
        let (listed, truncated, item_errors) = tags::list_pinned_blobs(&store).await.unwrap();
        assert!(listed.is_empty());
        assert!(truncated);
        assert_eq!(item_errors, 1);
        drop(storage);
        let error = AttachmentStorage::open(store.clone(), root.join("blobs"), &state, 100, 0, 0)
            .await
            .err()
            .unwrap();
        assert!(error.to_string().contains("unsupported hash_seq"));
        drop(store);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn pin_transaction_faults_rollback_reservations_and_restart_without_phantoms() {
        for boundary in [
            "before_attachment_tag_set",
            "after_attachment_tag_set",
            "after_attachment_tag_sync",
            "before_attachment_index_persist",
            "after_attachment_index_persist",
        ] {
            let (root, state, store) = lifecycle_test_store(boundary).await;
            let storage =
                AttachmentStorage::open(store.clone(), root.join("blobs"), &state, 100, 0, 0)
                    .await
                    .unwrap();
            let imported = store.blobs().add_slice(b"x").await.unwrap();
            let tag_name = outbound_blob_tag(
                "33333333333333333333333333333333",
                AttachmentKind::File,
                "x",
            );
            let parsed = parse_pinned_blob_tag(tag_name.as_bytes()).unwrap();
            let error = storage
                .commit_pin(
                    &tag_name,
                    parsed,
                    imported.hash_and_format(),
                    1,
                    &|current| {
                        if current == boundary {
                            anyhow::bail!("injected {boundary}")
                        } else {
                            Ok(())
                        }
                    },
                )
                .await
                .unwrap_err();
            assert!(error.to_string().contains("injected"));
            assert_eq!(storage.status().tags, 0, "cache phantom at {boundary}");
            assert!(storage.state.lock().unwrap().reservations.is_empty());
            assert!(store
                .tags()
                .get(tag_name.as_bytes())
                .await
                .unwrap()
                .is_none());
            drop(storage);
            let reopened =
                AttachmentStorage::open(store.clone(), root.join("blobs"), &state, 100, 0, 0)
                    .await
                    .unwrap();
            assert_eq!(reopened.status().tags, 0, "restart phantom at {boundary}");
            drop(store);
            let _ = std::fs::remove_dir_all(root);
        }
    }

    #[tokio::test]
    async fn attachment_pin_process_exit_child() {
        let Ok(root) = std::env::var("MESHMSG_ATTACHMENT_PIN_CRASH_ROOT") else {
            return;
        };
        let phase = std::env::var("MESHMSG_ATTACHMENT_PIN_CRASH_PHASE").unwrap();
        let root = PathBuf::from(root);
        let state = root.join("state");
        let blob_root = root.join("blobs");
        std::fs::create_dir_all(&state).unwrap();
        let store: Store =
            FsStore::load_with_opts(blob_root.join("blobs.db"), FsStoreOptions::new(&blob_root))
                .await
                .unwrap()
                .into();
        let storage = AttachmentStorage::open(store.clone(), blob_root, &state, 100, 0, 0)
            .await
            .unwrap();
        let imported = store.blobs().add_slice(b"x").await.unwrap();
        let tag_name = outbound_blob_tag(
            "dddddddddddddddddddddddddddddddd",
            AttachmentKind::File,
            "x",
        );
        let _ = storage
            .commit_pin(
                &tag_name,
                parse_pinned_blob_tag(tag_name.as_bytes()).unwrap(),
                imported.hash_and_format(),
                1,
                &|current| {
                    if current == phase {
                        std::process::exit(87);
                    }
                    Ok(())
                },
            )
            .await;
        panic!("child did not exit at {phase}");
    }

    #[tokio::test]
    async fn crash_boundaries_reconcile_tag_and_index_without_phantom_reservations() {
        for phase in [
            "after_attachment_tag_sync",
            "after_attachment_index_persist",
        ] {
            let root = std::env::temp_dir().join(format!(
                "meshmsg-pin-crash-{phase}-{}",
                rand::random::<u64>()
            ));
            let result = std::process::Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg("attachment::storage::tests::attachment_pin_process_exit_child")
                .arg("--nocapture")
                .env("MESHMSG_ATTACHMENT_PIN_CRASH_ROOT", &root)
                .env("MESHMSG_ATTACHMENT_PIN_CRASH_PHASE", phase)
                .status()
                .unwrap();
            assert_eq!(result.code(), Some(87));
            let state = root.join("state");
            let blob_root = root.join("blobs");
            let store: Store = FsStore::load_with_opts(
                blob_root.join("blobs.db"),
                FsStoreOptions::new(&blob_root),
            )
            .await
            .unwrap()
            .into();
            let storage = AttachmentStorage::open(store.clone(), blob_root, &state, 100, 0, 0)
                .await
                .unwrap();
            assert_eq!(storage.status().tags, 1);
            {
                let lifecycle = storage.state.lock().unwrap();
                assert_eq!(lifecycle.index.created_at_ms.len(), 1);
                assert!(lifecycle.reservations.is_empty());
            }
            storage
                .remove(
                    &TEST_OPERATION_ID,
                    Some("dddddddddddddddddddddddddddddddd"),
                    None,
                    None,
                    None,
                    1,
                    false,
                )
                .await
                .unwrap();
            assert_eq!(storage.status().tags, 0);
            drop(store);
            let _ = std::fs::remove_dir_all(root);
        }
    }

    #[tokio::test]
    async fn rollback_failure_reconciles_authoritative_tag_and_remove_recovers_capacity() {
        let (root, state, store) = lifecycle_test_store("rollback-reconcile").await;
        let storage = AttachmentStorage::open(store.clone(), root.join("blobs"), &state, 1, 0, 0)
            .await
            .unwrap();
        let tag_name = outbound_blob_tag(
            "44444444444444444444444444444444",
            AttachmentKind::File,
            "x",
        );
        let parsed = parse_pinned_blob_tag(tag_name.as_bytes()).unwrap();
        let imported = store.blobs().add_slice(b"x").await.unwrap();
        let error = storage
            .commit_pin(
                &tag_name,
                parsed,
                imported.hash_and_format(),
                1,
                &|current| match current {
                    "after_attachment_tag_set" | "before_attachment_tag_rollback" => {
                        anyhow::bail!("injected rollback fault")
                    }
                    _ => Ok(()),
                },
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("rollback failed"));
        assert_eq!(storage.status().tags, 1, "authoritative tag was hidden");
        assert!(storage.state.lock().unwrap().reservations.is_empty());
        storage
            .remove(
                &TEST_OPERATION_ID,
                Some("44444444444444444444444444444444"),
                None,
                None,
                None,
                1,
                false,
            )
            .await
            .unwrap();
        assert_eq!(storage.status().tags, 0);
        drop(store);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn removal_sync_index_and_partial_delete_faults_reconcile_and_restart() {
        for boundary in [
            "attachment_removal_sync",
            "attachment_removal_index_persist",
        ] {
            let (root, state, store) = lifecycle_test_store(boundary).await;
            let tag = outbound_blob_tag(
                "66666666666666666666666666666666",
                AttachmentKind::File,
                "x",
            );
            pin_test_blob(&store, &root, b"x", std::slice::from_ref(&tag)).await;
            let storage =
                AttachmentStorage::open(store.clone(), root.join("blobs"), &state, 100, 0, 0)
                    .await
                    .unwrap();
            let value = storage
                .remove_with_fault(
                    RemovalSpec {
                        operation_id: &TEST_OPERATION_ID,
                        offer_id: Some("66666666666666666666666666666666"),
                        direction: None,
                        provider: None,
                        older_than_secs: None,
                        maximum: 1,
                        dry_run: false,
                    },
                    &|current| {
                        if current == boundary {
                            anyhow::bail!("injected {boundary}")
                        } else {
                            Ok(())
                        }
                    },
                )
                .await
                .unwrap();
            let error = response_error(&value);
            assert_eq!(
                error.code,
                meshmsg_protocol::ErrorCode::AttachmentRemovalPartial
            );
            assert_eq!(storage.status().tags, 0);
            drop(storage);
            let reopened =
                AttachmentStorage::open(store.clone(), root.join("blobs"), &state, 100, 0, 0)
                    .await
                    .unwrap();
            assert_eq!(reopened.status().tags, 0);
            drop(store);
            let _ = std::fs::remove_dir_all(root);
        }

        let (root, state, store) = lifecycle_test_store("partial-delete").await;
        let tags = [
            outbound_blob_tag(
                "77777777777777777777777777777777",
                AttachmentKind::File,
                "a",
            ),
            outbound_blob_tag(
                "88888888888888888888888888888888",
                AttachmentKind::File,
                "b",
            ),
        ];
        for tag in &tags {
            pin_test_blob(&store, &root, tag.as_bytes(), std::slice::from_ref(tag)).await;
        }
        let storage =
            AttachmentStorage::open(store.clone(), root.join("blobs"), &state, 1000, 0, 0)
                .await
                .unwrap();
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let value = storage
            .remove_with_fault(
                RemovalSpec {
                    operation_id: &TEST_OPERATION_ID,
                    offer_id: None,
                    direction: None,
                    provider: None,
                    older_than_secs: None,
                    maximum: 2,
                    dry_run: false,
                },
                &|current| {
                    if current == "attachment_tag_delete"
                        && calls.fetch_add(1, Ordering::SeqCst) == 0
                    {
                        anyhow::bail!("first delete failed")
                    }
                    Ok(())
                },
            )
            .await
            .unwrap();
        let error = response_error(&value);
        assert_eq!(error.outcome, meshmsg_protocol::Outcome::Partial);
        assert_eq!(storage.status().tags, 1);
        drop(store);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn automatic_retention_is_opt_in_and_removal_failures_are_retryable() {
        let (root, state, store) = lifecycle_test_store("automatic-retention").await;
        let tag = outbound_blob_tag(
            "55555555555555555555555555555555",
            AttachmentKind::File,
            "x",
        );
        pin_test_blob(&store, &root, b"x", std::slice::from_ref(&tag)).await;
        let disabled =
            AttachmentStorage::open(store.clone(), root.join("blobs"), &state, 100, 0, 0)
                .await
                .unwrap();
        assert!(disabled.automatic_retention_pass().await.unwrap().is_none());
        drop(disabled);
        let enabled = AttachmentStorage::open(store.clone(), root.join("blobs"), &state, 100, 0, 1)
            .await
            .unwrap();
        {
            let mut lifecycle = enabled.state.lock().unwrap();
            lifecycle
                .index
                .created_at_ms
                .insert(tag.clone(), unix_timestamp_ms().unwrap() - 2_000);
            persist_attachment_index(&state, &lifecycle.index).unwrap();
        }
        let partial = enabled
            .remove_with_fault(
                RemovalSpec {
                    operation_id: &TEST_OPERATION_ID,
                    offer_id: None,
                    direction: None,
                    provider: None,
                    older_than_secs: Some(1),
                    maximum: 1,
                    dry_run: false,
                },
                &|boundary| {
                    if boundary == "attachment_tag_delete" {
                        anyhow::bail!("delete fault")
                    } else {
                        Ok(())
                    }
                },
            )
            .await
            .unwrap();
        let error = response_error(&partial);
        assert_eq!(
            error.code,
            meshmsg_protocol::ErrorCode::AttachmentRemovalPartial
        );
        assert_eq!(error.outcome, meshmsg_protocol::Outcome::Unknown);
        assert_eq!(enabled.status().tags, 1);
        let automatic = enabled.automatic_retention_pass().await.unwrap().unwrap();
        assert_eq!(lifecycle_result(&automatic).removed_tags, 1);
        assert_eq!(enabled.status().tags, 0);
        drop(store);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn cached_attachment_status_is_constant_work_and_responsive() {
        let (root, state, store) = lifecycle_test_store("cached-status").await;
        let storage = AttachmentStorage::open(store.clone(), root.join("blobs"), &state, 2, 0, 0)
            .await
            .unwrap();
        let sampled_at = storage.status().sampled_at_ms;
        let started = StdInstant::now();
        for _ in 0..10_000 {
            assert_eq!(storage.status().sampled_at_ms, sampled_at);
        }
        assert!(started.elapsed() < Duration::from_secs(1));
        drop(store);
        let _ = std::fs::remove_dir_all(root);
    }
}
