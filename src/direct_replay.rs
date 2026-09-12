use crate::{config::atomic_write, persistent};
use anyhow::{Context, Result};
use iroh::PublicKey;
use iroh_gossip::proto::TopicId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs,
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    str::FromStr,
    thread,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{mpsc, oneshot, watch};

const SNAPSHOT_VERSION: u8 = 2;
const WAL_VERSION: u8 = 2;
pub(crate) const REPLAY_QUEUE_CAPACITY: usize = 64;
pub(crate) const MAX_REPLAY_ENTRIES: usize = 8_192;
pub(crate) const MAX_REPLAY_ENTRIES_PER_SENDER: usize = 512;
const MAX_REPLAY_SENDERS: usize = MAX_REPLAY_ENTRIES;
pub(crate) const GLOBAL_RATE_PER_SECOND: f64 = 128.0;
pub(crate) const GLOBAL_RATE_BURST: f64 = 256.0;
pub(crate) const SENDER_RATE_PER_SECOND: f64 = 8.0;
pub(crate) const SENDER_RATE_BURST: f64 = 16.0;
const COMPACT_AFTER_RECORDS: usize = 256;
const MAX_WAL_BYTES: u64 = 8 * 1024 * 1024;
const MAX_SNAPSHOT_BYTES: usize = 4 * 1024 * 1024;
const MAX_WAL_RECORD_BYTES: usize = 512;
const SNAPSHOT_DOMAIN: &[u8] = b"meshmsg-direct-replay-snapshot-v2";
const WAL_DOMAIN: &[u8] = b"meshmsg-direct-replay-wal-v2";
const TERMINAL_HEALTH_ERROR: &str = "direct replay persistence worker failed";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReplayDecision {
    Accepted,
    DuplicateAccepted,
    Conflict,
    DeliveryOutcomeUnknown,
    Busy,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReplayHealth {
    pub(crate) available: bool,
    pub(crate) error: Option<String>,
}

impl ReplayHealth {
    fn healthy() -> Self {
        Self {
            available: true,
            error: None,
        }
    }

    fn failed() -> Self {
        Self {
            available: false,
            error: Some(TERMINAL_HEALTH_ERROR.to_owned()),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ReplayClient {
    requests: mpsc::Sender<WorkerRequest>,
}

#[derive(Debug)]
pub(crate) struct ReplayWorker {
    requests: Option<mpsc::Sender<WorkerRequest>>,
    health: watch::Receiver<ReplayHealth>,
    thread: Option<thread::JoinHandle<Result<()>>>,
}

impl ReplayClient {
    pub(crate) async fn admit(
        &self,
        sender: PublicKey,
        id: [u8; 16],
        fingerprint: [u8; 32],
        expires_at_ms: u64,
        delivery: Option<Box<dyn FnOnce() + Send + 'static>>,
    ) -> Result<ReplayDecision> {
        let (reply, response) = oneshot::channel();
        let request = WorkerRequest::Admit {
            sender,
            id,
            fingerprint,
            expires_at_ms,
            delivery,
            reply,
        };
        match self.requests.try_send(request) {
            // Once admitted to the worker queue, a dropped response cannot prove
            // whether persistence or volatile delivery began.
            Ok(()) => Ok(response
                .await
                .unwrap_or(ReplayDecision::DeliveryOutcomeUnknown)),
            Err(mpsc::error::TrySendError::Full(_)) => Ok(ReplayDecision::Busy),
            Err(mpsc::error::TrySendError::Closed(_)) => Ok(ReplayDecision::Unavailable),
        }
    }
}

impl ReplayWorker {
    pub(crate) fn health(&self) -> ReplayHealth {
        self.health.borrow().clone()
    }

    pub(crate) async fn shutdown(&mut self) -> Result<()> {
        let mut shutdown_result = Ok(());
        if let Some(requests) = self.requests.take() {
            let (reply, response) = oneshot::channel();
            // Shutdown happens after the protocol router has stopped admission.
            // Queueing behind prior requests drains their transactions in order.
            if requests
                .send(WorkerRequest::Shutdown { reply })
                .await
                .is_ok()
            {
                shutdown_result = response.await.unwrap_or_else(|_| {
                    Err(anyhow::anyhow!(
                        "direct replay persistence worker dropped shutdown response"
                    ))
                });
            } else {
                shutdown_result = Err(anyhow::anyhow!(
                    "direct replay persistence worker stopped before shutdown"
                ));
            }
        }
        let Some(handle) = self.thread.take() else {
            return shutdown_result;
        };
        let worker_result = tokio::task::spawn_blocking(move || handle.join())
            .await
            .context("join direct replay persistence worker task")?
            .map_err(|_| anyhow::anyhow!("direct replay persistence worker panicked"))?;
        shutdown_result.and(worker_result)
    }
}

impl Drop for ReplayWorker {
    fn drop(&mut self) {
        if let Some(requests) = self.requests.take() {
            let (reply, _response) = oneshot::channel();
            let _ = requests.try_send(WorkerRequest::Shutdown { reply });
        }
        // Joining in Drop could block an async runtime worker. Normal daemon paths
        // call shutdown(); process teardown remains safe because each accepted ID is
        // synced before its response, independently of compaction.
    }
}

enum WorkerRequest {
    Admit {
        sender: PublicKey,
        id: [u8; 16],
        fingerprint: [u8; 32],
        expires_at_ms: u64,
        delivery: Option<Box<dyn FnOnce() + Send + 'static>>,
        reply: oneshot::Sender<ReplayDecision>,
    },
    Shutdown {
        reply: oneshot::Sender<Result<()>>,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum PersistedState {
    LegacyUnknown,
    Recorded,
    DeliveryConfirmed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplayEntry {
    #[serde(deserialize_with = "persistent::string_64")]
    sender: String,
    #[serde(deserialize_with = "persistent::string_32")]
    id: String,
    #[serde(deserialize_with = "persistent::string_64")]
    fingerprint: String,
    expires_at_ms: u64,
    state: PersistedState,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotPayload {
    version: u8,
    #[serde(deserialize_with = "persistent::string_64")]
    recipient: String,
    #[serde(deserialize_with = "persistent::string_64")]
    topic: String,
    #[serde(deserialize_with = "deserialize_replay_entries")]
    entries: Vec<ReplayEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotFile {
    payload: SnapshotPayload,
    #[serde(deserialize_with = "persistent::string_64")]
    checksum: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WalHeader {
    version: u8,
    #[serde(deserialize_with = "persistent::string_64")]
    recipient: String,
    #[serde(deserialize_with = "persistent::string_64")]
    topic: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WalRecord {
    entry: ReplayEntry,
    #[serde(deserialize_with = "persistent::string_64")]
    checksum: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyReplayState {
    version: u8,
    #[serde(deserialize_with = "persistent::string_64")]
    recipient: String,
    #[serde(deserialize_with = "persistent::string_64")]
    topic: String,
    #[serde(deserialize_with = "deserialize_legacy_replay_entries")]
    entries: Vec<LegacyReplayEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyReplayEntry {
    #[serde(deserialize_with = "persistent::string_64")]
    sender: String,
    #[serde(deserialize_with = "persistent::string_32")]
    id: String,
    expires_at_ms: u64,
}

#[derive(Deserialize)]
struct SnapshotVersionProbe {
    payload: SnapshotPayloadVersionProbe,
}

#[derive(Deserialize)]
struct SnapshotPayloadVersionProbe {
    version: u64,
}

#[derive(Deserialize)]
struct ReplayVersionProbe {
    version: u64,
}

fn deserialize_replay_entries<'de, D>(deserializer: D) -> Result<Vec<ReplayEntry>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct EntriesVisitor;
    impl<'de> serde::de::Visitor<'de> for EntriesVisitor {
        type Value = Vec<ReplayEntry>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(formatter, "at most {MAX_REPLAY_ENTRIES} replay entries")
        }

        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut access: A,
        ) -> Result<Self::Value, A::Error> {
            let mut entries = Vec::new();
            while entries.len() < MAX_REPLAY_ENTRIES {
                let Some(entry) = access.next_element::<ReplayEntry>()? else {
                    return Ok(entries);
                };
                entries.push(entry);
            }
            if access.next_element::<serde::de::IgnoredAny>()?.is_some() {
                return Err(serde::de::Error::invalid_length(
                    MAX_REPLAY_ENTRIES + 1,
                    &self,
                ));
            }
            Ok(entries)
        }
    }
    deserializer.deserialize_seq(EntriesVisitor)
}

fn deserialize_legacy_replay_entries<'de, D>(
    deserializer: D,
) -> Result<Vec<LegacyReplayEntry>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct EntriesVisitor;
    impl<'de> serde::de::Visitor<'de> for EntriesVisitor {
        type Value = Vec<LegacyReplayEntry>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                formatter,
                "at most {MAX_REPLAY_ENTRIES} legacy replay entries"
            )
        }

        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut access: A,
        ) -> Result<Self::Value, A::Error> {
            let mut entries = Vec::new();
            while entries.len() < MAX_REPLAY_ENTRIES {
                let Some(entry) = access.next_element::<LegacyReplayEntry>()? else {
                    return Ok(entries);
                };
                entries.push(entry);
            }
            if access.next_element::<serde::de::IgnoredAny>()?.is_some() {
                return Err(serde::de::Error::invalid_length(
                    MAX_REPLAY_ENTRIES + 1,
                    &self,
                ));
            }
            Ok(entries)
        }
    }
    deserializer.deserialize_seq(EntriesVisitor)
}

#[derive(Debug, Clone)]
struct TokenBucket {
    tokens: f64,
    updated: Instant,
}

impl TokenBucket {
    fn full(burst: f64, now: Instant) -> Self {
        Self {
            tokens: burst,
            updated: now,
        }
    }

    fn available(&self, now: Instant, rate: f64, burst: f64) -> bool {
        (self.tokens + now.duration_since(self.updated).as_secs_f64() * rate).min(burst) >= 1.0
    }

    fn take(&mut self, now: Instant, rate: f64, burst: f64) {
        self.tokens =
            (self.tokens + now.duration_since(self.updated).as_secs_f64() * rate).min(burst) - 1.0;
        self.updated = now;
    }
}

#[derive(Debug)]
struct SenderState {
    live_ids: usize,
    rate: TokenBucket,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReplayMetadata {
    fingerprint: [u8; 32],
    expires_at_ms: u64,
    state: PersistedState,
}

type ReplayEntries = HashMap<(PublicKey, [u8; 16]), ReplayMetadata>;

struct Admission {
    sender: PublicKey,
    id: [u8; 16],
    fingerprint: [u8; 32],
    expires_at_ms: u64,
    delivery: Option<Box<dyn FnOnce() + Send + 'static>>,
}

#[derive(Debug)]
struct AdmissionFailure {
    outcome: ReplayDecision,
    error: anyhow::Error,
}

impl AdmissionFailure {
    fn unavailable(error: impl Into<anyhow::Error>) -> Self {
        Self {
            outcome: ReplayDecision::Unavailable,
            error: error.into(),
        }
    }

    fn unknown(error: impl Into<anyhow::Error>) -> Self {
        Self {
            outcome: ReplayDecision::DeliveryOutcomeUnknown,
            error: error.into(),
        }
    }
}

#[derive(Debug)]
struct ReplayStore {
    recipient: PublicKey,
    topic: TopicId,
    snapshot_path: PathBuf,
    wal_path: PathBuf,
    entries: ReplayEntries,
    senders: HashMap<PublicKey, SenderState>,
    global_rate: TokenBucket,
    wal_records: usize,
}

pub(crate) fn start(
    state_dir: &Path,
    recipient: PublicKey,
    topic: TopicId,
) -> Result<(ReplayClient, ReplayWorker)> {
    let mut path_hasher = Sha256::new();
    path_hasher.update(recipient.as_bytes());
    path_hasher.update(topic.as_bytes());
    let suffix = data_encoding::HEXLOWER.encode(&path_hasher.finalize());
    let snapshot_path = state_dir.join(format!("direct-replay-v2-{suffix}.snapshot.json"));
    let wal_path = state_dir.join(format!("direct-replay-v2-{suffix}.wal"));
    let legacy_path = state_dir.join(format!("direct-replay-v1-{suffix}.json"));
    start_paths(snapshot_path, wal_path, legacy_path, recipient, topic)
}

fn start_paths(
    snapshot_path: PathBuf,
    wal_path: PathBuf,
    legacy_path: PathBuf,
    recipient: PublicKey,
    topic: TopicId,
) -> Result<(ReplayClient, ReplayWorker)> {
    let (requests, receiver) = mpsc::channel(REPLAY_QUEUE_CAPACITY);
    let (health_tx, health) = watch::channel(ReplayHealth::healthy());
    let worker_health = health.clone();
    let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
    let thread = thread::Builder::new()
        .name("meshmsg-direct-replay".to_owned())
        .spawn(move || {
            let store = ReplayStore::load(snapshot_path, wal_path, legacy_path, recipient, topic);
            match store {
                Ok(mut store) => {
                    let _ = started_tx.send(Ok(()));
                    let panic_health = health_tx.clone();
                    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        store.run(receiver, health_tx)
                    })) {
                        Ok(result) => {
                            if result.is_err() {
                                let _ = panic_health.send(ReplayHealth::failed());
                            }
                            result
                        }
                        Err(_) => {
                            let _ = panic_health.send(ReplayHealth::failed());
                            Err(anyhow::anyhow!("{TERMINAL_HEALTH_ERROR}: worker panicked"))
                        }
                    }
                }
                Err(error) => {
                    let message = format!("{error:#}");
                    let _ = started_tx.send(Err(message.clone()));
                    Err(anyhow::anyhow!(message))
                }
            }
        })
        .context("spawn direct replay persistence worker")?;
    if let Err(message) = started_rx
        .recv()
        .context("direct replay persistence worker did not initialize")?
    {
        let _ = thread.join();
        anyhow::bail!(message);
    }
    Ok((
        ReplayClient {
            requests: requests.clone(),
        },
        ReplayWorker {
            requests: Some(requests),
            health: worker_health,
            thread: Some(thread),
        },
    ))
}

impl ReplayStore {
    fn load(
        snapshot_path: PathBuf,
        wal_path: PathBuf,
        legacy_path: PathBuf,
        recipient: PublicKey,
        topic: TopicId,
    ) -> Result<Self> {
        let now_wall = wall_ms()?;
        let now_mono = Instant::now();
        let (mut entries, snapshot_present) =
            match load_snapshot(&snapshot_path, recipient, topic, now_wall)? {
                Some(entries) => (entries, true),
                None => (
                    load_legacy(&legacy_path, recipient, topic, now_wall)?.unwrap_or_default(),
                    false,
                ),
            };
        let (wal_records, wal_present) =
            load_wal(&wal_path, recipient, topic, now_wall, &mut entries)?;
        anyhow::ensure!(
            entries.len() <= MAX_REPLAY_ENTRIES,
            "direct replay state capacity exceeded"
        );
        let mut senders = HashMap::new();
        for (sender, _) in entries.keys() {
            let state = senders.entry(*sender).or_insert_with(|| SenderState {
                live_ids: 0,
                rate: TokenBucket::full(SENDER_RATE_BURST, now_mono),
            });
            // A v1 migration may contain more entries than the new per-sender
            // quota. Preserve those live replay IDs and reject further IDs from
            // that sender until expiry instead of making the daemon unavailable.
            state.live_ids += 1;
        }
        anyhow::ensure!(
            senders.len() <= MAX_REPLAY_SENDERS,
            "direct replay sender capacity exceeded"
        );
        let mut store = Self {
            recipient,
            topic,
            snapshot_path,
            wal_path,
            entries,
            senders,
            global_rate: TokenBucket::full(GLOBAL_RATE_BURST, now_mono),
            wal_records,
        };
        if !snapshot_present || !wal_present {
            store.compact(now_wall)?;
        }
        Ok(store)
    }

    fn run(
        &mut self,
        mut receiver: mpsc::Receiver<WorkerRequest>,
        health: watch::Sender<ReplayHealth>,
    ) -> Result<()> {
        while let Some(request) = receiver.blocking_recv() {
            match request {
                WorkerRequest::Admit {
                    sender,
                    id,
                    fingerprint,
                    expires_at_ms,
                    delivery,
                    reply,
                } => {
                    let admission = Admission {
                        sender,
                        id,
                        fingerprint,
                        expires_at_ms,
                        delivery,
                    };
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        let now = wall_ms().map_err(AdmissionFailure::unavailable)?;
                        self.admit_transaction(admission, now, Instant::now())
                    }));
                    let result = match result {
                        Ok(result) => result,
                        Err(_) => Err(AdmissionFailure::unknown(anyhow::anyhow!(
                            "direct replay transaction panicked"
                        ))),
                    };
                    match result {
                        Ok(decision) => {
                            let _ = reply.send(decision);
                        }
                        Err(failure) => {
                            // Publish terminal health before answering and drain
                            // queued callers as unavailable. If an append started,
                            // its disk outcome is unknown; pre-append failures are
                            // safely unavailable/not-started.
                            let _ = health.send(ReplayHealth::failed());
                            let _ = reply.send(failure.outcome);
                            receiver.close();
                            while let Ok(queued) = receiver.try_recv() {
                                match queued {
                                    WorkerRequest::Admit { reply, .. } => {
                                        let _ = reply.send(ReplayDecision::Unavailable);
                                    }
                                    WorkerRequest::Shutdown { reply } => {
                                        let _ =
                                            reply.send(Err(anyhow::anyhow!(TERMINAL_HEALTH_ERROR)));
                                    }
                                }
                            }
                            return Err(failure.error.context(TERMINAL_HEALTH_ERROR));
                        }
                    }
                }
                WorkerRequest::Shutdown { reply } => {
                    receiver.close();
                    while let Ok(queued) = receiver.try_recv() {
                        match queued {
                            WorkerRequest::Admit { reply, .. } => {
                                let _ = reply.send(ReplayDecision::Unavailable);
                            }
                            WorkerRequest::Shutdown { reply } => {
                                let _ = reply.send(Ok(()));
                            }
                        }
                    }
                    let result = self.compact(wall_ms()?);
                    if result.is_err() {
                        let _ = health.send(ReplayHealth::failed());
                    }
                    let response = result.as_ref().map(|_| ()).map_err(|error| {
                        anyhow::anyhow!("compact direct replay state on shutdown: {error:#}")
                    });
                    let _ = reply.send(response);
                    return result;
                }
            }
        }
        // Every completed admission is already represented in a synced WAL.
        // Compact on an unexpected owner drop and publish any terminal failure.
        let result = self.compact(wall_ms()?);
        if result.is_err() {
            let _ = health.send(ReplayHealth::failed());
        }
        result
    }

    fn admit_transaction(
        &mut self,
        admission: Admission,
        now_wall: u64,
        now_mono: Instant,
    ) -> std::result::Result<ReplayDecision, AdmissionFailure> {
        let Admission {
            sender,
            id,
            fingerprint,
            expires_at_ms,
            delivery,
        } = admission;
        self.expire(now_wall);
        let key = (sender, id);
        if let Some(metadata) = self.entries.get(&key) {
            if metadata.fingerprint != fingerprint {
                return Ok(ReplayDecision::Conflict);
            }
            return Ok(match metadata.state {
                PersistedState::LegacyUnknown => ReplayDecision::Conflict,
                PersistedState::Recorded => ReplayDecision::DeliveryOutcomeUnknown,
                PersistedState::DeliveryConfirmed => ReplayDecision::DuplicateAccepted,
            });
        }
        if delivery.is_none()
            || self.entries.len() >= MAX_REPLAY_ENTRIES
            || (!self.senders.contains_key(&sender) && self.senders.len() >= MAX_REPLAY_SENDERS)
        {
            return Ok(ReplayDecision::Busy);
        }
        let sender_allowed = self.senders.get(&sender).is_none_or(|state| {
            state.live_ids < MAX_REPLAY_ENTRIES_PER_SENDER
                && state
                    .rate
                    .available(now_mono, SENDER_RATE_PER_SECOND, SENDER_RATE_BURST)
        });
        if !sender_allowed
            || !self
                .global_rate
                .available(now_mono, GLOBAL_RATE_PER_SECOND, GLOBAL_RATE_BURST)
        {
            return Ok(ReplayDecision::Busy);
        }
        if expires_at_ms <= now_wall {
            return Ok(ReplayDecision::Busy);
        }
        if self.wal_records >= COMPACT_AFTER_RECORDS {
            let _ = self.compact(now_wall);
        }

        let mut metadata = ReplayMetadata {
            fingerprint,
            expires_at_ms,
            state: PersistedState::Recorded,
        };
        let recorded = wal_record(self.recipient, self.topic, sender, id, metadata)
            .map_err(AdmissionFailure::unavailable)?;
        let confirmation_reserve = MAX_WAL_RECORD_BYTES as u64 + 1;
        let mut wal = open_wal_transaction(&self.wal_path, self.recipient, self.topic)
            .map_err(AdmissionFailure::unavailable)?;
        if !append_wal(&mut wal, &self.wal_path, &recorded, confirmation_reserve)
            .map_err(AdmissionFailure::unknown)?
        {
            drop(wal);
            if self.compact(now_wall).is_err() {
                return Ok(ReplayDecision::Busy);
            }
            wal = open_wal_transaction(&self.wal_path, self.recipient, self.topic)
                .map_err(AdmissionFailure::unavailable)?;
            if !append_wal(&mut wal, &self.wal_path, &recorded, confirmation_reserve)
                .map_err(AdmissionFailure::unknown)?
            {
                return Ok(ReplayDecision::Busy);
            }
        }
        self.entries.insert(key, metadata);
        let sender_state = self.senders.entry(sender).or_insert_with(|| SenderState {
            live_ids: 0,
            rate: TokenBucket::full(SENDER_RATE_BURST, now_mono),
        });
        sender_state.live_ids += 1;
        sender_state
            .rate
            .take(now_mono, SENDER_RATE_PER_SECOND, SENDER_RATE_BURST);
        self.global_rate
            .take(now_mono, GLOBAL_RATE_PER_SECOND, GLOBAL_RATE_BURST);
        self.wal_records += 1;
        test_crash_point("after_record_sync");

        delivery.expect("new replay admission has delivery capacity")();
        test_crash_point("after_delivery_before_transition");

        metadata.state = PersistedState::DeliveryConfirmed;
        let confirmed = wal_record(self.recipient, self.topic, sender, id, metadata)
            .map_err(AdmissionFailure::unknown)?;
        if !append_wal(&mut wal, &self.wal_path, &confirmed, 0)
            .map_err(AdmissionFailure::unknown)?
        {
            return Err(AdmissionFailure::unknown(anyhow::anyhow!(
                "reserved direct replay WAL capacity was lost"
            )));
        }
        self.entries.insert(key, metadata);
        self.wal_records += 1;
        test_crash_point("after_delivery_transition_sync");

        if self.wal_records >= COMPACT_AFTER_RECORDS {
            // Both transaction records are durable before best-effort maintenance.
            let _ = self.compact(now_wall);
        }
        Ok(ReplayDecision::Accepted)
    }

    #[cfg(test)]
    fn admit(
        &mut self,
        sender: PublicKey,
        id: [u8; 16],
        expires_at_ms: u64,
        delivery_capacity: bool,
        now_wall: u64,
        now_mono: Instant,
    ) -> Result<ReplayDecision> {
        self.admit_transaction(
            Admission {
                sender,
                id,
                fingerprint: [id[0]; 32],
                expires_at_ms,
                delivery: delivery_capacity
                    .then(|| Box::new(|| {}) as Box<dyn FnOnce() + Send + 'static>),
            },
            now_wall,
            now_mono,
        )
        .map_err(|failure| failure.error)
    }

    fn expire(&mut self, now_wall: u64) {
        let expired: Vec<_> = self
            .entries
            .iter()
            .filter_map(|(key, metadata)| (metadata.expires_at_ms <= now_wall).then_some(*key))
            .collect();
        for (sender, id) in expired {
            self.entries.remove(&(sender, id));
            if let Some(state) = self.senders.get_mut(&sender) {
                state.live_ids -= 1;
                if state.live_ids == 0 {
                    self.senders.remove(&sender);
                }
            }
        }
    }

    fn compact(&mut self, now_wall: u64) -> Result<()> {
        self.expire(now_wall);
        let mut entries: Vec<_> = self
            .entries
            .iter()
            .map(|((sender, id), metadata)| replay_entry(*sender, *id, *metadata))
            .collect();
        entries.sort_unstable_by(|left, right| {
            (&left.sender, &left.id).cmp(&(&right.sender, &right.id))
        });
        let payload = SnapshotPayload {
            version: SNAPSHOT_VERSION,
            recipient: self.recipient.to_string(),
            topic: self.topic.to_string(),
            entries,
        };
        let checksum = snapshot_checksum(&payload)?;
        let snapshot = serde_json::to_vec(&SnapshotFile { payload, checksum })?;
        anyhow::ensure!(
            snapshot.len() <= MAX_SNAPSHOT_BYTES,
            "direct replay snapshot exceeds size limit"
        );
        let snapshot_dir = self
            .snapshot_path
            .parent()
            .context("direct replay snapshot has no parent")?;
        let snapshot_name = file_name(&self.snapshot_path)?;
        atomic_write(snapshot_dir, snapshot_name, &snapshot, 0o600)
            .context("commit direct replay snapshot")?;
        // Snapshot replacement and its parent-directory sync happen first. If the
        // process exits before this WAL replacement, recovery merely replays
        // duplicate records over the newer snapshot.
        let header = wal_header_bytes(self.recipient, self.topic)?;
        let wal_dir = self
            .wal_path
            .parent()
            .context("direct replay WAL has no parent")?;
        let wal_name = file_name(&self.wal_path)?;
        atomic_write(wal_dir, wal_name, &header, 0o600).context("reset direct replay WAL")?;
        self.wal_records = 0;
        Ok(())
    }
}

fn load_snapshot(
    path: &Path,
    recipient: PublicKey,
    topic: TopicId,
    now: u64,
) -> Result<Option<ReplayEntries>> {
    let Some(bytes) =
        persistent::read_optional_file_bounded(path, "direct replay snapshot", MAX_SNAPSHOT_BYTES)?
    else {
        return Ok(None);
    };
    let probe: SnapshotVersionProbe =
        persistent::parse_json_bounded_strings(&bytes, "direct replay snapshot", 64)?;
    if probe.payload.version != u64::from(SNAPSHOT_VERSION) {
        return Err(persistent::PersistentError::unsupported_version(
            "direct replay snapshot",
            probe.payload.version,
        )
        .into());
    }
    let file: SnapshotFile =
        persistent::parse_json_bounded_strings(&bytes, "direct replay snapshot", 64)?;
    validate_binding(
        &file.payload.recipient,
        &file.payload.topic,
        recipient,
        topic,
    )?;
    if file.checksum != snapshot_checksum(&file.payload)? {
        return Err(persistent::PersistentError::corrupt(
            "direct replay snapshot",
            "checksum mismatch",
        )
        .into());
    }
    entries_from_records(file.payload.entries, now).map(Some)
}

fn load_legacy(
    path: &Path,
    recipient: PublicKey,
    topic: TopicId,
    now: u64,
) -> Result<Option<ReplayEntries>> {
    let Some(bytes) = persistent::read_optional_file_bounded(
        path,
        "legacy direct replay state",
        MAX_SNAPSHOT_BYTES,
    )?
    else {
        return Ok(None);
    };
    let probe: ReplayVersionProbe =
        persistent::parse_json_bounded_strings(&bytes, "legacy direct replay state", 64)?;
    if probe.version != 1 {
        return Err(persistent::PersistentError::unsupported_version(
            "legacy direct replay state",
            probe.version,
        )
        .into());
    }
    let state: LegacyReplayState =
        persistent::parse_json_bounded_strings(&bytes, "legacy direct replay state", 64)?;
    validate_binding(&state.recipient, &state.topic, recipient, topic)?;
    anyhow::ensure!(
        state.entries.len() <= MAX_REPLAY_ENTRIES,
        "legacy direct replay state capacity exceeded"
    );
    let mut entries = HashMap::new();
    for entry in state.entries {
        let key = parse_sender_and_id(&entry.sender, &entry.id)?;
        if entry.expires_at_ms > now {
            anyhow::ensure!(
                entries
                    .insert(
                        key,
                        ReplayMetadata {
                            fingerprint: [0; 32],
                            expires_at_ms: entry.expires_at_ms,
                            state: PersistedState::LegacyUnknown,
                        },
                    )
                    .is_none(),
                "duplicate legacy direct replay entry"
            );
        }
    }
    Ok(Some(entries))
}

fn entries_from_records(records: Vec<ReplayEntry>, now: u64) -> Result<ReplayEntries> {
    anyhow::ensure!(
        records.len() <= MAX_REPLAY_ENTRIES,
        "direct replay state capacity exceeded"
    );
    let mut entries = HashMap::new();
    for record in records {
        let (key, metadata) = parse_entry(&record)?;
        if metadata.expires_at_ms > now {
            anyhow::ensure!(
                entries.insert(key, metadata).is_none(),
                "duplicate direct replay snapshot entry"
            );
        }
    }
    Ok(entries)
}

fn load_wal(
    path: &Path,
    recipient: PublicKey,
    topic: TopicId,
    now: u64,
    entries: &mut ReplayEntries,
) -> Result<(usize, bool)> {
    let mut file = match persistent::open_read_write(path, "direct replay WAL") {
        Ok(file) => file,
        Err(error) if error.kind() == persistent::PersistentErrorKind::Missing => {
            let parent = path.parent().context("direct replay WAL has no parent")?;
            atomic_write(
                parent,
                file_name(path)?,
                &wal_header_bytes(recipient, topic)?,
                0o600,
            )?;
            return Ok((0, false));
        }
        Err(error) => return Err(error.into()),
    };
    let metadata = file
        .metadata()
        .context("inspect direct replay WAL handle")?;
    if metadata.len() > MAX_WAL_BYTES {
        return Err(persistent::PersistentError::too_large(
            "direct replay WAL",
            MAX_WAL_BYTES as usize,
        )
        .into());
    }
    let bytes = persistent::read_bounded(
        &mut file,
        "direct replay WAL",
        MAX_WAL_BYTES as usize,
        metadata.len() as usize,
    )?;
    let Some(header_end) = bytes.iter().position(|byte| *byte == b'\n') else {
        return Err(persistent::PersistentError::corrupt(
            "direct replay WAL",
            "header is torn or missing",
        )
        .into());
    };
    let probe: ReplayVersionProbe = persistent::parse_json_bounded_strings(
        &bytes[..header_end],
        "direct replay WAL header",
        64,
    )?;
    if probe.version != u64::from(WAL_VERSION) {
        return Err(persistent::PersistentError::unsupported_version(
            "direct replay WAL",
            probe.version,
        )
        .into());
    }
    let header: WalHeader = persistent::parse_json_bounded_strings(
        &bytes[..header_end],
        "direct replay WAL header",
        64,
    )?;
    validate_binding(&header.recipient, &header.topic, recipient, topic)?;
    let mut offset = header_end + 1;
    let mut records = 0usize;
    while offset < bytes.len() {
        let Some(relative_end) = bytes[offset..].iter().position(|byte| *byte == b'\n') else {
            // Only one bounded non-newline-terminated append can be torn. A larger
            // tail could contain multiple/corrupt records and must remain untouched.
            let tail_len = bytes.len() - offset;
            if tail_len > MAX_WAL_RECORD_BYTES {
                return Err(persistent::PersistentError::corrupt(
                    "direct replay WAL",
                    "unterminated tail exceeds record limit",
                )
                .into());
            }
            file.set_len(offset as u64)
                .context("truncate torn direct replay WAL tail")?;
            file.seek(SeekFrom::Start(offset as u64))?;
            file.sync_all().context("sync repaired direct replay WAL")?;
            break;
        };
        let end = offset + relative_end;
        anyhow::ensure!(
            end - offset <= MAX_WAL_RECORD_BYTES,
            "direct replay WAL record is too large"
        );
        let record: WalRecord = persistent::parse_json_bounded_strings(
            &bytes[offset..end],
            "direct replay WAL record",
            64,
        )
        .with_context(|| format!("parse direct replay WAL record {records}"))?;
        let (key, metadata) = parse_entry(&record.entry)?;
        if record.checksum != wal_checksum(recipient, topic, key.0, key.1, metadata) {
            return Err(persistent::PersistentError::corrupt(
                "direct replay WAL",
                format!("record {records} checksum mismatch"),
            )
            .into());
        }
        if metadata.expires_at_ms > now {
            merge_wal_metadata(entries, key, metadata)?;
        }
        records += 1;
        anyhow::ensure!(
            entries.len() <= MAX_REPLAY_ENTRIES,
            "direct replay state capacity exceeded"
        );
        offset = end + 1;
    }
    Ok((records, true))
}

struct WalTransaction {
    file: fs::File,
    expected_len: u64,
    expected_header: Vec<u8>,
}

fn open_wal_transaction(
    path: &Path,
    recipient: PublicKey,
    topic: TopicId,
) -> Result<WalTransaction> {
    let mut file = persistent::open_read_append(path, "direct replay WAL")?;
    anyhow::ensure!(
        persistent::opened_file_is_current_path(&file, path, "direct replay WAL")?,
        "direct replay WAL was replaced while opening transaction"
    );
    let metadata = file
        .metadata()
        .context("inspect direct replay WAL transaction handle")?;
    anyhow::ensure!(
        metadata.len() <= MAX_WAL_BYTES,
        "direct replay WAL is too large"
    );
    file.seek(SeekFrom::Start(0))?;
    let mut prefix = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_WAL_RECORD_BYTES as u64 + 1)
        .read_to_end(&mut prefix)
        .context("read direct replay WAL transaction header")?;
    let header_end = prefix
        .iter()
        .position(|byte| *byte == b'\n')
        .context("direct replay WAL header is torn or missing")?;
    let probe: ReplayVersionProbe = persistent::parse_json_bounded_strings(
        &prefix[..header_end],
        "direct replay WAL header",
        64,
    )?;
    anyhow::ensure!(
        probe.version == u64::from(WAL_VERSION),
        "unsupported direct replay WAL version"
    );
    let header: WalHeader = persistent::parse_json_bounded_strings(
        &prefix[..header_end],
        "direct replay WAL header",
        64,
    )?;
    validate_binding(&header.recipient, &header.topic, recipient, topic)?;
    anyhow::ensure!(
        persistent::opened_file_is_current_path(&file, path, "direct replay WAL")?,
        "direct replay WAL was replaced while validating transaction"
    );
    Ok(WalTransaction {
        file,
        expected_len: metadata.len(),
        expected_header: prefix[..=header_end].to_vec(),
    })
}

fn validate_wal_transaction(wal: &mut WalTransaction, path: &Path) -> Result<()> {
    anyhow::ensure!(
        persistent::opened_file_is_current_path(&wal.file, path, "direct replay WAL")?,
        "direct replay WAL was replaced during transaction"
    );
    let size = wal
        .file
        .metadata()
        .context("inspect direct replay WAL transaction continuity")?
        .len();
    anyhow::ensure!(
        size == wal.expected_len,
        "direct replay WAL length continuity was lost"
    );
    wal.file.seek(SeekFrom::Start(0))?;
    let mut header = vec![0_u8; wal.expected_header.len()];
    wal.file
        .read_exact(&mut header)
        .context("re-read direct replay WAL transaction header")?;
    anyhow::ensure!(
        header == wal.expected_header,
        "direct replay WAL header continuity was lost"
    );
    Ok(())
}

fn append_wal(
    wal: &mut WalTransaction,
    path: &Path,
    record: &WalRecord,
    reserved_bytes: u64,
) -> Result<bool> {
    append_wal_with_hook(wal, path, record, reserved_bytes, || {})
}

fn append_wal_with_hook(
    wal: &mut WalTransaction,
    path: &Path,
    record: &WalRecord,
    reserved_bytes: u64,
    before_write: impl FnOnce(),
) -> Result<bool> {
    let mut bytes = serde_json::to_vec(record)?;
    anyhow::ensure!(
        bytes.len() <= MAX_WAL_RECORD_BYTES,
        "direct replay WAL record exceeds size limit"
    );
    bytes.push(b'\n');
    validate_wal_transaction(wal, path)?;
    let required = (bytes.len() as u64).saturating_add(reserved_bytes);
    if wal.expected_len.saturating_add(required) > MAX_WAL_BYTES {
        return Ok(false);
    }
    before_write();
    wal.file
        .write_all(&bytes)
        .context("append direct replay WAL")?;
    wal.file
        .sync_all()
        .context("sync direct replay WAL append")?;
    wal.expected_len = wal.expected_len.saturating_add(bytes.len() as u64);
    validate_wal_transaction(wal, path)?;
    Ok(true)
}

fn wal_header_bytes(recipient: PublicKey, topic: TopicId) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec(&WalHeader {
        version: WAL_VERSION,
        recipient: recipient.to_string(),
        topic: topic.to_string(),
    })?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn snapshot_checksum(payload: &SnapshotPayload) -> Result<String> {
    let bytes = serde_json::to_vec(payload)?;
    let mut hasher = Sha256::new();
    hasher.update(SNAPSHOT_DOMAIN);
    hasher.update(&bytes);
    Ok(data_encoding::HEXLOWER.encode(&hasher.finalize()))
}

fn replay_entry(sender: PublicKey, id: [u8; 16], metadata: ReplayMetadata) -> ReplayEntry {
    ReplayEntry {
        sender: sender.to_string(),
        id: id_string(&id),
        fingerprint: data_encoding::HEXLOWER.encode(&metadata.fingerprint),
        expires_at_ms: metadata.expires_at_ms,
        state: metadata.state,
    }
}

fn wal_record(
    recipient: PublicKey,
    topic: TopicId,
    sender: PublicKey,
    id: [u8; 16],
    metadata: ReplayMetadata,
) -> Result<WalRecord> {
    let entry = replay_entry(sender, id, metadata);
    Ok(WalRecord {
        checksum: wal_checksum(recipient, topic, sender, id, metadata),
        entry,
    })
}

fn wal_checksum(
    recipient: PublicKey,
    topic: TopicId,
    sender: PublicKey,
    id: [u8; 16],
    metadata: ReplayMetadata,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(WAL_DOMAIN);
    hasher.update(recipient.as_bytes());
    hasher.update(topic.as_bytes());
    hasher.update(sender.as_bytes());
    hasher.update(id);
    hasher.update(metadata.fingerprint);
    hasher.update(metadata.expires_at_ms.to_le_bytes());
    hasher.update([match metadata.state {
        PersistedState::LegacyUnknown => 0,
        PersistedState::Recorded => 1,
        PersistedState::DeliveryConfirmed => 2,
    }]);
    data_encoding::HEXLOWER.encode(&hasher.finalize())
}

fn parse_sender_and_id(sender: &str, id: &str) -> Result<(PublicKey, [u8; 16])> {
    let sender_key = PublicKey::from_str(sender).context("invalid direct replay sender")?;
    anyhow::ensure!(
        sender_key.to_string() == sender,
        "noncanonical direct replay sender"
    );
    let bytes = data_encoding::HEXLOWER
        .decode(id.as_bytes())
        .context("invalid direct replay ID")?;
    let id_bytes = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid direct replay ID length"))?;
    anyhow::ensure!(id_string(&id_bytes) == id, "noncanonical direct replay ID");
    Ok((sender_key, id_bytes))
}

fn parse_entry(entry: &ReplayEntry) -> Result<((PublicKey, [u8; 16]), ReplayMetadata)> {
    let key = parse_sender_and_id(&entry.sender, &entry.id)?;
    let fingerprint: [u8; 32] = data_encoding::HEXLOWER
        .decode(entry.fingerprint.as_bytes())
        .context("invalid direct replay fingerprint")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid direct replay fingerprint length"))?;
    anyhow::ensure!(
        data_encoding::HEXLOWER.encode(&fingerprint) == entry.fingerprint,
        "noncanonical direct replay fingerprint"
    );
    Ok((
        key,
        ReplayMetadata {
            fingerprint,
            expires_at_ms: entry.expires_at_ms,
            state: entry.state,
        },
    ))
}

fn merge_wal_metadata(
    entries: &mut ReplayEntries,
    key: (PublicKey, [u8; 16]),
    incoming: ReplayMetadata,
) -> Result<()> {
    let Some(current) = entries.get_mut(&key) else {
        entries.insert(key, incoming);
        return Ok(());
    };
    anyhow::ensure!(
        current.fingerprint == incoming.fingerprint
            && current.expires_at_ms == incoming.expires_at_ms,
        "conflicting duplicate direct replay WAL entry"
    );
    match (current.state, incoming.state) {
        (PersistedState::Recorded, PersistedState::DeliveryConfirmed) => {
            current.state = PersistedState::DeliveryConfirmed;
        }
        // An old WAL can be replayed over a newer compact snapshot if the
        // process exited between snapshot commit and WAL reset. Never regress.
        (PersistedState::DeliveryConfirmed, PersistedState::Recorded)
        | (PersistedState::LegacyUnknown, PersistedState::LegacyUnknown)
        | (PersistedState::Recorded, PersistedState::Recorded)
        | (PersistedState::DeliveryConfirmed, PersistedState::DeliveryConfirmed) => {}
        _ => anyhow::bail!("invalid direct replay state transition"),
    }
    Ok(())
}

fn validate_binding(
    stored_recipient: &str,
    stored_topic: &str,
    recipient: PublicKey,
    topic: TopicId,
) -> Result<()> {
    anyhow::ensure!(
        stored_recipient == recipient.to_string(),
        "direct replay state recipient mismatch"
    );
    anyhow::ensure!(
        stored_topic == topic.to_string(),
        "direct replay state topic mismatch"
    );
    Ok(())
}

#[cfg(test)]
fn test_crash_point(point: &str) {
    if std::env::var("MESHMSG_DIRECT_REPLAY_CRASH_POINT").as_deref() == Ok(point) {
        std::process::exit(match point {
            "after_record_sync" => 88,
            "after_delivery_before_transition" => 89,
            "after_delivery_transition_sync" => 90,
            _ => 99,
        });
    }
}

#[cfg(not(test))]
fn test_crash_point(_point: &str) {}

fn wall_ms() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64)
}

fn file_name(path: &Path) -> Result<&str> {
    path.file_name()
        .and_then(|name| name.to_str())
        .context("invalid direct replay state filename")
}

fn id_string(id: &[u8; 16]) -> String {
    data_encoding::HEXLOWER.encode(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_paths() -> (PathBuf, PathBuf, PathBuf, PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "meshmsg-direct-replay-worker-test-{}",
            rand::random::<u64>()
        ));
        fs::create_dir_all(&dir).unwrap();
        (
            dir.join("snapshot.json"),
            dir.join("replay.wal"),
            dir.join("legacy.json"),
            dir,
        )
    }

    fn loaded_store(
        snapshot: PathBuf,
        wal: PathBuf,
        legacy: PathBuf,
        recipient: PublicKey,
        topic: TopicId,
    ) -> ReplayStore {
        ReplayStore::load(snapshot, wal, legacy, recipient, topic).unwrap()
    }

    fn delivery(available: bool) -> Option<Box<dyn FnOnce() + Send + 'static>> {
        available.then(|| Box::new(|| {}) as Box<dyn FnOnce() + Send + 'static>)
    }

    fn fingerprint(id: [u8; 16]) -> [u8; 32] {
        [id[0]; 32]
    }

    #[test]
    fn legacy_whole_map_state_migrates_without_losing_live_ids() {
        let recipient = iroh::SecretKey::generate().public();
        let sender = iroh::SecretKey::generate().public();
        let topic = TopicId::from_bytes([30; 32]);
        let (snapshot, wal, legacy, dir) = test_paths();
        let expires_at_ms = wall_ms().unwrap() + 60_000;
        let legacy_state = LegacyReplayState {
            version: 1,
            recipient: recipient.to_string(),
            topic: topic.to_string(),
            entries: vec![LegacyReplayEntry {
                sender: sender.to_string(),
                id: id_string(&[3; 16]),
                expires_at_ms,
            }],
        };
        fs::write(&legacy, serde_json::to_vec(&legacy_state).unwrap()).unwrap();
        let store = loaded_store(snapshot.clone(), wal.clone(), legacy, recipient, topic);
        assert_eq!(
            store.entries.get(&(sender, [3; 16])).unwrap().state,
            PersistedState::LegacyUnknown
        );
        assert!(snapshot.is_file());
        assert!(wal.is_file());
        drop(store);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn replay_versions_are_probed_as_u64_before_specific_decode() {
        let recipient = iroh::SecretKey::generate().public();
        let topic = TopicId::from_bytes([29; 32]);
        let (snapshot, wal, legacy, dir) = test_paths();
        fs::write(
            &snapshot,
            format!(
                "{{\"payload\":{{\"version\":256,\"recipient\":\"{recipient}\",\"topic\":\"{topic}\",\"entries\":[]}},\"checksum\":\"{}\"}}",
                "0".repeat(64)
            ),
        )
        .unwrap();
        let error = ReplayStore::load(
            snapshot.clone(),
            wal.clone(),
            legacy.clone(),
            recipient,
            topic,
        )
        .unwrap_err();
        assert!(error.to_string().contains("schema version 256"));
        fs::remove_file(&snapshot).unwrap();

        fs::write(
            &legacy,
            format!(
                "{{\"version\":256,\"recipient\":\"{recipient}\",\"topic\":\"{topic}\",\"entries\":[]}}"
            ),
        )
        .unwrap();
        let error = ReplayStore::load(
            snapshot.clone(),
            wal.clone(),
            legacy.clone(),
            recipient,
            topic,
        )
        .unwrap_err();
        assert!(error.to_string().contains("schema version 256"));
        fs::remove_file(&legacy).unwrap();

        fs::write(
            &wal,
            format!("{{\"version\":256,\"recipient\":\"{recipient}\",\"topic\":\"{topic}\"}}\n"),
        )
        .unwrap();
        let error = ReplayStore::load(snapshot, wal, legacy, recipient, topic).unwrap_err();
        assert!(error.to_string().contains("schema version 256"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn replay_entry_visitors_bound_compact_collections_and_strings() {
        let sender = iroh::SecretKey::generate().public().to_string();
        let topic = TopicId::from_bytes([28; 32]).to_string();
        let entry = format!(
            "{{\"sender\":\"{sender}\",\"id\":\"{}\",\"fingerprint\":\"{}\",\"expires_at_ms\":1,\"state\":\"recorded\"}}",
            "0".repeat(32),
            "0".repeat(64)
        );
        let snapshot = |count: usize, sender_value: &str| {
            let item = entry.replace(&sender, sender_value);
            format!(
                "{{\"payload\":{{\"version\":2,\"recipient\":\"{sender}\",\"topic\":\"{topic}\",\"entries\":[{}]}},\"checksum\":\"{}\"}}",
                std::iter::repeat_n(item.as_str(), count).collect::<Vec<_>>().join(","),
                "0".repeat(64)
            )
        };
        let boundary = snapshot(MAX_REPLAY_ENTRIES, &sender);
        assert!(boundary.len() < MAX_SNAPSHOT_BYTES);
        let parsed: SnapshotFile = persistent::parse_json_bounded_strings(
            boundary.as_bytes(),
            "direct replay snapshot",
            64,
        )
        .unwrap();
        assert_eq!(parsed.payload.entries.len(), MAX_REPLAY_ENTRIES);

        let amplified = snapshot(MAX_REPLAY_ENTRIES + 1, &sender);
        assert!(amplified.len() < MAX_SNAPSHOT_BYTES);
        assert!(persistent::parse_json_bounded_strings::<SnapshotFile>(
            amplified.as_bytes(),
            "direct replay snapshot",
            64,
        )
        .is_err());
        for (exact, oversized) in [
            (r"\u0061".repeat(64), r"\u0061".repeat(65)),
            (r"\\".repeat(64), r"\\".repeat(65)),
            (r"\uD83D\uDE00".repeat(16), r"\uD83D\uDE00".repeat(17)),
        ] {
            persistent::parse_json_bounded_strings::<SnapshotFile>(
                snapshot(1, &exact).as_bytes(),
                "direct replay snapshot",
                64,
            )
            .unwrap();
            assert!(persistent::parse_json_bounded_strings::<SnapshotFile>(
                snapshot(1, &oversized).as_bytes(),
                "direct replay snapshot",
                64,
            )
            .is_err());
        }

        let legacy_entry = format!(
            "{{\"sender\":\"{sender}\",\"id\":\"{}\",\"expires_at_ms\":1}}",
            "0".repeat(32)
        );
        let legacy = format!(
            "{{\"version\":1,\"recipient\":\"{sender}\",\"topic\":\"{topic}\",\"entries\":[{}]}}",
            std::iter::repeat_n(legacy_entry.as_str(), MAX_REPLAY_ENTRIES + 1)
                .collect::<Vec<_>>()
                .join(",")
        );
        assert!(legacy.len() < MAX_SNAPSHOT_BYTES);
        assert!(persistent::parse_json_bounded_strings::<LegacyReplayState>(
            legacy.as_bytes(),
            "legacy direct replay state",
            64,
        )
        .is_err());
        let escaped_legacy = |sender_value: &str| {
            format!(
                "{{\"version\":1,\"recipient\":\"{sender}\",\"topic\":\"{topic}\",\"entries\":[{{\"sender\":\"{sender_value}\",\"id\":\"{}\",\"expires_at_ms\":1}}]}}",
                "0".repeat(32)
            )
        };
        persistent::parse_json_bounded_strings::<LegacyReplayState>(
            escaped_legacy(&r"\u0061".repeat(64)).as_bytes(),
            "legacy direct replay state",
            64,
        )
        .unwrap();
        assert!(persistent::parse_json_bounded_strings::<LegacyReplayState>(
            escaped_legacy(&r"\u0061".repeat(65)).as_bytes(),
            "legacy direct replay state",
            64,
        )
        .is_err());
    }

    #[cfg(unix)]
    #[test]
    fn replay_optional_files_and_wal_append_reject_dangling_links() {
        use std::os::unix::fs::symlink;
        for role in ["snapshot", "legacy", "wal"] {
            let recipient = iroh::SecretKey::generate().public();
            let topic = TopicId::from_bytes([27; 32]);
            let (snapshot, wal, legacy, dir) = test_paths();
            let path = match role {
                "snapshot" => &snapshot,
                "legacy" => &legacy,
                _ => &wal,
            };
            symlink(dir.join("missing-target"), path).unwrap();
            assert!(ReplayStore::load(snapshot, wal, legacy, recipient, topic).is_err());
            fs::remove_dir_all(dir).unwrap();
        }

        let (_snapshot, wal, _legacy, dir) = test_paths();
        let target = dir.join("redirected");
        fs::write(&target, b"unchanged").unwrap();
        symlink(&target, &wal).unwrap();
        let recipient = iroh::SecretKey::generate().public();
        let topic = TopicId::from_bytes([26; 32]);
        assert!(open_wal_transaction(&wal, recipient, topic).is_err());
        assert_eq!(fs::read(target).unwrap(), b"unchanged");
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn wal_append_detects_path_replacement_after_checked_open() {
        let (_snapshot, wal, _legacy, dir) = test_paths();
        let saved = dir.join("opened-wal");
        let replacement = b"replacement WAL";
        let recipient = iroh::SecretKey::generate().public();
        let topic = TopicId::from_bytes([25; 32]);
        atomic_write(
            &dir,
            file_name(&wal).unwrap(),
            &wal_header_bytes(recipient, topic).unwrap(),
            0o600,
        )
        .unwrap();
        let record = wal_record(
            recipient,
            topic,
            recipient,
            [2; 16],
            ReplayMetadata {
                fingerprint: [2; 32],
                expires_at_ms: 2,
                state: PersistedState::Recorded,
            },
        )
        .unwrap();
        let mut transaction = open_wal_transaction(&wal, recipient, topic).unwrap();
        let error = append_wal_with_hook(&mut transaction, &wal, &record, 0, || {
            fs::rename(&wal, &saved).unwrap();
            fs::write(&wal, replacement).unwrap();
        })
        .unwrap_err();
        assert!(error.to_string().contains("replaced during transaction"));
        assert_eq!(fs::read(&wal).unwrap(), replacement);
        assert!(
            fs::metadata(&saved).unwrap().len()
                > wal_header_bytes(recipient, topic).unwrap().len() as u64
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn wal_append_detects_symlink_replacement_after_checked_open() {
        use std::os::unix::fs::symlink;
        let (_snapshot, wal, _legacy, dir) = test_paths();
        let saved = dir.join("opened-wal");
        let target = dir.join("redirect-target");
        fs::write(&target, b"unchanged").unwrap();
        let recipient = iroh::SecretKey::generate().public();
        let topic = TopicId::from_bytes([24; 32]);
        atomic_write(
            &dir,
            file_name(&wal).unwrap(),
            &wal_header_bytes(recipient, topic).unwrap(),
            0o600,
        )
        .unwrap();
        let record = wal_record(
            recipient,
            topic,
            recipient,
            [3; 16],
            ReplayMetadata {
                fingerprint: [3; 32],
                expires_at_ms: 3,
                state: PersistedState::Recorded,
            },
        )
        .unwrap();
        let mut transaction = open_wal_transaction(&wal, recipient, topic).unwrap();
        assert!(
            append_wal_with_hook(&mut transaction, &wal, &record, 0, || {
                fs::rename(&wal, &saved).unwrap();
                symlink(&target, &wal).unwrap();
            })
            .is_err()
        );
        assert_eq!(fs::read(target).unwrap(), b"unchanged");
        assert!(
            fs::metadata(saved).unwrap().len()
                > wal_header_bytes(recipient, topic).unwrap().len() as u64
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn transaction_rejects_every_wal_replacement_between_record_and_confirmation() {
        use std::os::unix::fs::symlink;

        for kind in [
            "empty",
            "valid_new_file",
            "malformed",
            "symlink",
            "directory",
        ] {
            let recipient = iroh::SecretKey::generate().public();
            let sender = iroh::SecretKey::generate().public();
            let topic = TopicId::from_bytes([23; 32]);
            let (snapshot, wal, legacy, dir) = test_paths();
            let mut store = loaded_store(snapshot, wal.clone(), legacy.clone(), recipient, topic);
            let saved = dir.join("recorded-generation.wal");
            let target = dir.join("replacement-target");
            fs::write(&target, b"target remains unchanged").unwrap();
            let replacement_bytes = match kind {
                "empty" => Some(Vec::new()),
                "valid_new_file" => Some(wal_header_bytes(recipient, topic).unwrap()),
                "malformed" => Some(b"not a WAL\n".to_vec()),
                "symlink" | "directory" => None,
                _ => unreachable!(),
            };
            let wal_for_delivery = wal.clone();
            let saved_for_delivery = saved.clone();
            let target_for_delivery = target.clone();
            let replacement_for_delivery = replacement_bytes.clone();
            let delivery = Box::new(move || {
                fs::rename(&wal_for_delivery, &saved_for_delivery).unwrap();
                match kind {
                    "symlink" => symlink(&target_for_delivery, &wal_for_delivery).unwrap(),
                    "directory" => fs::create_dir(&wal_for_delivery).unwrap(),
                    _ => fs::write(&wal_for_delivery, replacement_for_delivery.unwrap()).unwrap(),
                }
            });
            let now = wall_ms().unwrap();
            let failure = store
                .admit_transaction(
                    Admission {
                        sender,
                        id: [4; 16],
                        fingerprint: [4; 32],
                        expires_at_ms: now + 60_000,
                        delivery: Some(delivery),
                    },
                    now,
                    Instant::now(),
                )
                .unwrap_err();
            assert_eq!(failure.outcome, ReplayDecision::DeliveryOutcomeUnknown);
            let recorded_generation = fs::read(&saved).unwrap();
            assert!(String::from_utf8_lossy(&recorded_generation).contains("\"recorded\""));
            assert!(
                !String::from_utf8_lossy(&recorded_generation).contains("\"delivery_confirmed\"")
            );
            match kind {
                "symlink" => {
                    assert!(fs::symlink_metadata(&wal).unwrap().file_type().is_symlink());
                    assert_eq!(fs::read(&target).unwrap(), b"target remains unchanged");
                    fs::remove_file(&wal).unwrap();
                }
                "directory" => {
                    assert!(wal.is_dir());
                    fs::remove_dir(&wal).unwrap();
                }
                _ => assert_eq!(fs::read(&wal).unwrap(), replacement_bytes.unwrap()),
            }
            if wal.exists() {
                fs::remove_file(&wal).unwrap();
            }
            fs::rename(&saved, &wal).unwrap();
            drop(store);
            let mut restarted =
                loaded_store(dir.join("snapshot.json"), wal, legacy, recipient, topic);
            assert_eq!(
                restarted
                    .admit(sender, [4; 16], now + 60_000, true, now, Instant::now())
                    .unwrap(),
                ReplayDecision::DeliveryOutcomeUnknown
            );
            drop(restarted);
            fs::remove_dir_all(dir).unwrap();
        }
    }

    #[test]
    fn transaction_rejects_in_place_header_discontinuity_before_confirmation() {
        let recipient = iroh::SecretKey::generate().public();
        let sender = iroh::SecretKey::generate().public();
        let topic = TopicId::from_bytes([21; 32]);
        let (snapshot, wal, legacy, dir) = test_paths();
        let mut store = loaded_store(snapshot, wal.clone(), legacy, recipient, topic);
        let wal_for_delivery = wal.clone();
        let delivery = Box::new(move || {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .open(&wal_for_delivery)
                .unwrap();
            file.seek(SeekFrom::Start(0)).unwrap();
            file.write_all(b"!").unwrap();
            file.sync_all().unwrap();
        });
        let now = wall_ms().unwrap();
        let failure = store
            .admit_transaction(
                Admission {
                    sender,
                    id: [6; 16],
                    fingerprint: [6; 32],
                    expires_at_ms: now + 60_000,
                    delivery: Some(delivery),
                },
                now,
                Instant::now(),
            )
            .unwrap_err();
        assert_eq!(failure.outcome, ReplayDecision::DeliveryOutcomeUnknown);
        let bytes = fs::read(&wal).unwrap();
        assert!(String::from_utf8_lossy(&bytes).contains("\"recorded\""));
        assert!(!String::from_utf8_lossy(&bytes).contains("\"delivery_confirmed\""));
        drop(store);
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_wal_append_rejects_reparse_points() {
        use std::os::windows::fs::symlink_file;
        let (_snapshot, wal, _legacy, dir) = test_paths();
        let target = dir.join("redirected");
        fs::write(&target, b"unchanged").unwrap();
        symlink_file(&target, &wal).unwrap();
        let recipient = iroh::SecretKey::generate().public();
        let topic = TopicId::from_bytes([26; 32]);
        assert!(open_wal_transaction(&wal, recipient, topic).is_err());
        assert_eq!(fs::read(target).unwrap(), b"unchanged");
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_transaction_rejects_reparse_replacement_between_appends() {
        use std::os::windows::fs::symlink_file;

        let recipient = iroh::SecretKey::generate().public();
        let sender = iroh::SecretKey::generate().public();
        let topic = TopicId::from_bytes([22; 32]);
        let (snapshot, wal, legacy, dir) = test_paths();
        let mut store = loaded_store(snapshot, wal.clone(), legacy, recipient, topic);
        let saved = dir.join("recorded-generation.wal");
        let target = dir.join("replacement-target");
        fs::write(&target, b"unchanged").unwrap();
        let wal_for_delivery = wal.clone();
        let delivery = Box::new(move || {
            fs::rename(&wal_for_delivery, &saved).unwrap();
            symlink_file(&target, &wal_for_delivery).unwrap();
        });
        let now = wall_ms().unwrap();
        let failure = store
            .admit_transaction(
                Admission {
                    sender,
                    id: [5; 16],
                    fingerprint: [5; 32],
                    expires_at_ms: now + 60_000,
                    delivery: Some(delivery),
                },
                now,
                Instant::now(),
            )
            .unwrap_err();
        assert_eq!(failure.outcome, ReplayDecision::DeliveryOutcomeUnknown);
        drop(store);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn wal_torn_tail_is_truncated_but_complete_corruption_fails_closed() {
        let recipient = iroh::SecretKey::generate().public();
        let sender = iroh::SecretKey::generate().public();
        let topic = TopicId::from_bytes([31; 32]);
        let (snapshot, wal, legacy, dir) = test_paths();
        let now = wall_ms().unwrap();
        let mut store = loaded_store(
            snapshot.clone(),
            wal.clone(),
            legacy.clone(),
            recipient,
            topic,
        );
        assert_eq!(
            store
                .admit(sender, [1; 16], now + 60_000, true, now, Instant::now())
                .unwrap(),
            ReplayDecision::Accepted
        );
        drop(store);
        let valid_len = fs::metadata(&wal).unwrap().len();
        fs::OpenOptions::new()
            .append(true)
            .open(&wal)
            .unwrap()
            .write_all(b"{\"entry\":")
            .unwrap();
        let recovered = loaded_store(
            snapshot.clone(),
            wal.clone(),
            legacy.clone(),
            recipient,
            topic,
        );
        assert!(recovered.entries.contains_key(&(sender, [1; 16])));
        assert_eq!(fs::metadata(&wal).unwrap().len(), valid_len);
        drop(recovered);

        fs::OpenOptions::new()
            .append(true)
            .open(&wal)
            .unwrap()
            .write_all(&vec![b'x'; MAX_WAL_RECORD_BYTES])
            .unwrap();
        let recovered = loaded_store(
            snapshot.clone(),
            wal.clone(),
            legacy.clone(),
            recipient,
            topic,
        );
        assert!(recovered.entries.contains_key(&(sender, [1; 16])));
        assert_eq!(fs::metadata(&wal).unwrap().len(), valid_len);
        drop(recovered);

        fs::OpenOptions::new()
            .append(true)
            .open(&wal)
            .unwrap()
            .write_all(&vec![b'x'; MAX_WAL_RECORD_BYTES + 1])
            .unwrap();
        let oversized_tail = fs::read(&wal).unwrap();
        assert!(ReplayStore::load(
            snapshot.clone(),
            wal.clone(),
            legacy.clone(),
            recipient,
            topic
        )
        .unwrap_err()
        .to_string()
        .contains("unterminated tail exceeds record limit"));
        assert_eq!(fs::read(&wal).unwrap(), oversized_tail);
        fs::OpenOptions::new()
            .write(true)
            .open(&wal)
            .unwrap()
            .set_len(valid_len)
            .unwrap();

        fs::OpenOptions::new()
            .append(true)
            .open(&wal)
            .unwrap()
            .write_all(b"{}\n")
            .unwrap();
        assert!(ReplayStore::load(snapshot, wal, legacy, recipient, topic)
            .unwrap_err()
            .to_string()
            .contains("parse direct replay WAL record"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn compaction_recovers_before_and_after_wal_reset_and_detects_snapshot_corruption() {
        let recipient = iroh::SecretKey::generate().public();
        let sender = iroh::SecretKey::generate().public();
        let topic = TopicId::from_bytes([32; 32]);
        let (snapshot, wal, legacy, dir) = test_paths();
        let now = wall_ms().unwrap();
        let mut store = loaded_store(
            snapshot.clone(),
            wal.clone(),
            legacy.clone(),
            recipient,
            topic,
        );
        store
            .admit(sender, [2; 16], now + 60_000, true, now, Instant::now())
            .unwrap();
        let old_wal = fs::read(&wal).unwrap();
        store.compact(now).unwrap();
        let compacted_wal = fs::read(&wal).unwrap();
        // Crash after snapshot replacement but before WAL reset: duplicate replay
        // of the old WAL is harmless and still restores the exact live set.
        fs::write(&wal, &old_wal).unwrap();
        let recovered = loaded_store(
            snapshot.clone(),
            wal.clone(),
            legacy.clone(),
            recipient,
            topic,
        );
        assert_eq!(recovered.entries.len(), 1);
        drop(recovered);
        fs::write(&wal, compacted_wal).unwrap();
        let mut bytes = fs::read(&snapshot).unwrap();
        let index = bytes.len() / 2;
        bytes[index] ^= 1;
        fs::write(&snapshot, bytes).unwrap();
        assert!(ReplayStore::load(snapshot, wal, legacy, recipient, topic).is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn per_sender_and_global_limits_never_evict_live_ids() {
        let recipient = iroh::SecretKey::generate().public();
        let abusive = iroh::SecretKey::generate().public();
        let honest = iroh::SecretKey::generate().public();
        let topic = TopicId::from_bytes([33; 32]);
        let (snapshot, wal, legacy, dir) = test_paths();
        let now_wall = wall_ms().unwrap();
        let now_mono = Instant::now();
        let mut store = loaded_store(snapshot, wal, legacy, recipient, topic);
        // Isolate quota behavior from token timing in this structural test.
        store.senders.insert(
            abusive,
            SenderState {
                live_ids: MAX_REPLAY_ENTRIES_PER_SENDER,
                rate: TokenBucket::full(SENDER_RATE_BURST, now_mono),
            },
        );
        for index in 0..MAX_REPLAY_ENTRIES_PER_SENDER {
            let id = (index as u128).to_le_bytes();
            store.entries.insert(
                (abusive, id),
                ReplayMetadata {
                    fingerprint: [id[0]; 32],
                    expires_at_ms: now_wall + 60_000,
                    state: PersistedState::DeliveryConfirmed,
                },
            );
        }
        assert_eq!(
            store
                .admit(
                    abusive,
                    [255; 16],
                    now_wall + 60_000,
                    true,
                    now_wall,
                    now_mono,
                )
                .unwrap(),
            ReplayDecision::Busy
        );
        assert_eq!(store.entries.len(), MAX_REPLAY_ENTRIES_PER_SENDER);
        assert_eq!(
            store
                .admit(honest, [7; 16], now_wall + 60_000, true, now_wall, now_mono,)
                .unwrap(),
            ReplayDecision::Accepted
        );
        assert!(store.entries.contains_key(&(abusive, [0; 16])));
        // Global pressure is also fail-closed and cannot displace either sender's
        // accepted ID. Artificially fill the remaining structural slots without
        // disk writes so the boundary remains a fast unit test.
        let retained_honest = (honest, [7; 16]);
        for index in store.entries.len()..MAX_REPLAY_ENTRIES {
            let synthetic = iroh::SecretKey::generate().public();
            let id = (index as u128).to_le_bytes();
            store.entries.insert(
                (synthetic, id),
                ReplayMetadata {
                    fingerprint: [id[0]; 32],
                    expires_at_ms: now_wall + 60_000,
                    state: PersistedState::DeliveryConfirmed,
                },
            );
        }
        assert_eq!(
            store
                .admit(honest, [8; 16], now_wall + 60_000, true, now_wall, now_mono,)
                .unwrap(),
            ReplayDecision::Busy
        );
        assert!(store.entries.contains_key(&(abusive, [0; 16])));
        assert!(store.entries.contains_key(&retained_honest));
        assert_eq!(
            store
                .admit(
                    honest,
                    [7; 16],
                    now_wall + 60_000,
                    false,
                    now_wall,
                    now_mono,
                )
                .unwrap(),
            ReplayDecision::DuplicateAccepted
        );
        // The advertised global quota must fit the durable snapshot format.
        store.compact(now_wall).unwrap();
        assert_eq!(store.entries.len(), MAX_REPLAY_ENTRIES);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn append_failure_does_not_admit_and_compaction_failure_keeps_synced_wal_authoritative() {
        let recipient = iroh::SecretKey::generate().public();
        let sender = iroh::SecretKey::generate().public();
        let topic = TopicId::from_bytes([37; 32]);
        let (snapshot, wal, legacy, dir) = test_paths();
        let now = wall_ms().unwrap();
        let mut store = loaded_store(
            snapshot.clone(),
            wal.clone(),
            legacy.clone(),
            recipient,
            topic,
        );
        let wal_saved = dir.join("wal.saved");
        fs::rename(&wal, &wal_saved).unwrap();
        fs::create_dir(&wal).unwrap();
        assert!(store
            .admit(sender, [1; 16], now + 60_000, true, now, Instant::now())
            .is_err());
        assert!(!store.entries.contains_key(&(sender, [1; 16])));
        fs::remove_dir(&wal).unwrap();
        fs::rename(&wal_saved, &wal).unwrap();

        // Force maintenance on the next successful append, then make only the
        // snapshot replacement fail. The append remains a valid acceptance and
        // recovery from the pre-compaction snapshot plus WAL includes it.
        let snapshot_saved = fs::read(&snapshot).unwrap();
        fs::remove_file(&snapshot).unwrap();
        fs::create_dir(&snapshot).unwrap();
        store.wal_records = COMPACT_AFTER_RECORDS;
        assert_eq!(
            store
                .admit(sender, [2; 16], now + 60_000, true, now, Instant::now())
                .unwrap(),
            ReplayDecision::Accepted
        );
        drop(store);
        fs::remove_dir(&snapshot).unwrap();
        fs::write(&snapshot, snapshot_saved).unwrap();
        let recovered = loaded_store(snapshot, wal, legacy, recipient, topic);
        assert!(recovered.entries.contains_key(&(sender, [2; 16])));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rate_limits_are_bounded_and_refill_without_mutating_replay_state() {
        let recipient = iroh::SecretKey::generate().public();
        let sender = iroh::SecretKey::generate().public();
        let topic = TopicId::from_bytes([34; 32]);
        let (snapshot, wal, legacy, dir) = test_paths();
        let now_wall = wall_ms().unwrap();
        let start = Instant::now();
        let mut store = loaded_store(snapshot, wal, legacy, recipient, topic);
        for index in 0..SENDER_RATE_BURST as usize {
            assert_eq!(
                store
                    .admit(
                        sender,
                        (index as u128).to_le_bytes(),
                        now_wall + 60_000,
                        true,
                        now_wall,
                        start,
                    )
                    .unwrap(),
                ReplayDecision::Accepted
            );
        }
        let before = store.entries.len();
        assert_eq!(
            store
                .admit(sender, [99; 16], now_wall + 60_000, true, now_wall, start,)
                .unwrap(),
            ReplayDecision::Busy
        );
        assert_eq!(store.entries.len(), before);
        assert_eq!(
            store
                .admit(
                    sender,
                    [99; 16],
                    now_wall + 60_000,
                    true,
                    now_wall,
                    start + std::time::Duration::from_millis(125),
                )
                .unwrap(),
            ReplayDecision::Accepted
        );

        let other = iroh::SecretKey::generate().public();
        let global_start = start + std::time::Duration::from_secs(1);
        store.global_rate = TokenBucket {
            tokens: 0.0,
            updated: global_start,
        };
        let before_global_rejection = store.entries.len();
        assert_eq!(
            store
                .admit(
                    other,
                    [100; 16],
                    now_wall + 60_000,
                    true,
                    now_wall,
                    global_start,
                )
                .unwrap(),
            ReplayDecision::Busy
        );
        assert_eq!(store.entries.len(), before_global_rejection);
        assert_eq!(
            store
                .admit(
                    other,
                    [100; 16],
                    now_wall + 60_000,
                    true,
                    now_wall,
                    global_start + std::time::Duration::from_millis(8),
                )
                .unwrap(),
            ReplayDecision::Accepted
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn bounded_request_queue_returns_busy_without_waiting() {
        let (requests, mut receiver) = mpsc::channel(REPLAY_QUEUE_CAPACITY);
        let client = ReplayClient { requests };
        let sender = iroh::SecretKey::generate().public();
        let expires = wall_ms().unwrap() + 60_000;
        let mut waiting = Vec::new();
        for index in 0..REPLAY_QUEUE_CAPACITY {
            let client = client.clone();
            waiting.push(tokio::spawn(async move {
                let id = (index as u128).to_le_bytes();
                client
                    .admit(sender, id, fingerprint(id), expires, delivery(true))
                    .await
            }));
        }
        while receiver.len() < REPLAY_QUEUE_CAPACITY {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            client
                .admit(
                    sender,
                    [255; 16],
                    fingerprint([255; 16]),
                    expires,
                    delivery(true),
                )
                .await
                .unwrap(),
            ReplayDecision::Busy
        );
        receiver.close();
        for task in waiting {
            task.abort();
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_protocol_wait_cannot_cancel_committed_delivery() {
        let recipient = iroh::SecretKey::generate().public();
        let sender = iroh::SecretKey::generate().public();
        let topic = TopicId::from_bytes([38; 32]);
        let (snapshot, wal, legacy, dir) = test_paths();
        let (client, mut worker) = start_paths(snapshot, wal, legacy, recipient, topic).unwrap();
        let (delivered_tx, delivered_rx) = std::sync::mpsc::sync_channel(1);
        let (reply, response) = oneshot::channel();
        let submitted = client
            .requests
            .send(WorkerRequest::Admit {
                sender,
                id: [8; 16],
                fingerprint: fingerprint([8; 16]),
                expires_at_ms: wall_ms().unwrap() + 60_000,
                delivery: Some(Box::new(move || delivered_tx.send(()).unwrap())),
                reply,
            })
            .await;
        assert!(submitted.is_ok());
        drop(response); // model connection timeout/cancellation after submission
        delivered_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        worker.shutdown().await.unwrap();
        fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn terminal_worker_failure_updates_health_drains_queue_and_shutdown_reports_error() {
        let recipient = iroh::SecretKey::generate().public();
        let sender = iroh::SecretKey::generate().public();
        let topic = TopicId::from_bytes([40; 32]);
        let (snapshot, wal, legacy, dir) = test_paths();
        let (client, mut worker) =
            start_paths(snapshot, wal.clone(), legacy, recipient, topic).unwrap();
        let expires = wall_ms().unwrap() + 60_000;
        let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
        let (first_reply, first_response) = oneshot::channel();
        assert!(client
            .requests
            .send(WorkerRequest::Admit {
                sender,
                id: [10; 16],
                fingerprint: fingerprint([10; 16]),
                expires_at_ms: expires,
                delivery: Some(Box::new(move || {
                    entered_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                })),
                reply: first_reply,
            })
            .await
            .is_ok());
        entered_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();

        let saved_wal = dir.join("saved.wal");
        fs::rename(&wal, &saved_wal).unwrap();
        fs::create_dir(&wal).unwrap();
        let mut queued = Vec::new();
        for value in [11_u8, 12_u8] {
            let (reply, response) = oneshot::channel();
            assert!(client
                .requests
                .send(WorkerRequest::Admit {
                    sender,
                    id: [value; 16],
                    fingerprint: fingerprint([value; 16]),
                    expires_at_ms: expires,
                    delivery: delivery(true),
                    reply,
                })
                .await
                .is_ok());
            queued.push(response);
        }
        release_tx.send(()).unwrap();
        assert_eq!(
            first_response.await.unwrap(),
            ReplayDecision::DeliveryOutcomeUnknown
        );
        for response in queued {
            assert_eq!(response.await.unwrap(), ReplayDecision::Unavailable);
        }
        assert_eq!(worker.health(), ReplayHealth::failed());
        assert_eq!(
            client
                .admit(
                    sender,
                    [13; 16],
                    fingerprint([13; 16]),
                    expires,
                    delivery(true),
                )
                .await
                .unwrap(),
            ReplayDecision::Unavailable
        );
        assert!(worker.shutdown().await.is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn panicking_delivery_reports_unknown_and_terminal_health() {
        let recipient = iroh::SecretKey::generate().public();
        let sender = iroh::SecretKey::generate().public();
        let topic = TopicId::from_bytes([43; 32]);
        let (snapshot, wal, legacy, dir) = test_paths();
        let (client, mut worker) = start_paths(snapshot, wal, legacy, recipient, topic).unwrap();
        assert_eq!(
            client
                .admit(
                    sender,
                    [14; 16],
                    fingerprint([14; 16]),
                    wall_ms().unwrap() + 60_000,
                    Some(Box::new(|| panic!("injected delivery panic"))),
                )
                .await
                .unwrap(),
            ReplayDecision::DeliveryOutcomeUnknown
        );
        assert_eq!(worker.health(), ReplayHealth::failed());
        assert_eq!(
            client
                .admit(
                    sender,
                    [15; 16],
                    fingerprint([15; 16]),
                    wall_ms().unwrap() + 60_000,
                    delivery(true),
                )
                .await
                .unwrap(),
            ReplayDecision::Unavailable
        );
        assert!(worker.shutdown().await.is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn replay_transaction_process_exit_child() {
        let Ok(root) = std::env::var("MESHMSG_DIRECT_REPLAY_CRASH_ROOT") else {
            return;
        };
        let root = PathBuf::from(root);
        fs::create_dir_all(&root).unwrap();
        let recipient = iroh::SecretKey::from_bytes(&[41; 32]).public();
        let sender = iroh::SecretKey::from_bytes(&[42; 32]).public();
        let topic = TopicId::from_bytes([36; 32]);
        let marker = root.join("delivered.marker");
        let (client, _worker) = start_paths(
            root.join("snapshot.json"),
            root.join("replay.wal"),
            root.join("legacy.json"),
            recipient,
            topic,
        )
        .unwrap();
        let result = client
            .admit(
                sender,
                [6; 16],
                fingerprint([6; 16]),
                wall_ms().unwrap() + 60_000,
                Some(Box::new(move || {
                    let mut file = fs::File::create(marker).unwrap();
                    file.write_all(b"queued").unwrap();
                    file.sync_all().unwrap();
                })),
            )
            .await
            .unwrap();
        panic!("crash failpoint did not exit; result was {result:?}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn process_exit_boundaries_recover_truthful_delivery_state_without_redelivery() {
        for (point, code, expected_marker, expected_replay) in [
            (
                "after_record_sync",
                88,
                false,
                ReplayDecision::DeliveryOutcomeUnknown,
            ),
            (
                "after_delivery_before_transition",
                89,
                true,
                ReplayDecision::DeliveryOutcomeUnknown,
            ),
            (
                "after_delivery_transition_sync",
                90,
                true,
                ReplayDecision::DuplicateAccepted,
            ),
        ] {
            let (_, _, _, root) = test_paths();
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg("direct_replay::tests::replay_transaction_process_exit_child")
                .arg("--nocapture")
                .env("MESHMSG_DIRECT_REPLAY_CRASH_ROOT", &root)
                .env("MESHMSG_DIRECT_REPLAY_CRASH_POINT", point)
                .status()
                .unwrap();
            assert_eq!(status.code(), Some(code), "wrong exit at {point}");
            assert_eq!(root.join("delivered.marker").exists(), expected_marker);

            let recipient = iroh::SecretKey::from_bytes(&[41; 32]).public();
            let sender = iroh::SecretKey::from_bytes(&[42; 32]).public();
            let topic = TopicId::from_bytes([36; 32]);
            let (client, mut worker) = start_paths(
                root.join("snapshot.json"),
                root.join("replay.wal"),
                root.join("legacy.json"),
                recipient,
                topic,
            )
            .unwrap();
            let second_marker = root.join("redelivered.marker");
            assert_eq!(
                client
                    .admit(
                        sender,
                        [6; 16],
                        fingerprint([6; 16]),
                        wall_ms().unwrap() + 60_000,
                        Some(Box::new(move || fs::write(second_marker, b"bad").unwrap())),
                    )
                    .await
                    .unwrap(),
                expected_replay
            );
            assert!(!root.join("redelivered.marker").exists());
            assert_eq!(
                client
                    .admit(
                        sender,
                        [6; 16],
                        [99; 32],
                        wall_ms().unwrap() + 60_000,
                        delivery(false),
                    )
                    .await
                    .unwrap(),
                ReplayDecision::Conflict
            );
            worker.shutdown().await.unwrap();
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_and_restart_fingerprint_conflicts_are_deterministic() {
        let recipient = iroh::SecretKey::generate().public();
        let sender = iroh::SecretKey::generate().public();
        let topic = TopicId::from_bytes([39; 32]);
        let (snapshot, wal, legacy, dir) = test_paths();
        let (client, mut worker) = start_paths(
            snapshot.clone(),
            wal.clone(),
            legacy.clone(),
            recipient,
            topic,
        )
        .unwrap();
        let expires = wall_ms().unwrap() + 60_000;
        let first = {
            let client = client.clone();
            tokio::spawn(async move {
                client
                    .admit(sender, [9; 16], [1; 32], expires, delivery(true))
                    .await
                    .unwrap()
            })
        };
        let conflicting = {
            let client = client.clone();
            tokio::spawn(async move {
                client
                    .admit(sender, [9; 16], [2; 32], expires, delivery(true))
                    .await
                    .unwrap()
            })
        };
        let outcomes = [first.await.unwrap(), conflicting.await.unwrap()];
        assert!(outcomes.contains(&ReplayDecision::Accepted));
        assert!(outcomes.contains(&ReplayDecision::Conflict));
        let accepted_fingerprint = if outcomes[0] == ReplayDecision::Accepted {
            [1; 32]
        } else {
            [2; 32]
        };
        worker.shutdown().await.unwrap();

        let (restarted, mut restarted_worker) =
            start_paths(snapshot, wal, legacy, recipient, topic).unwrap();
        assert_eq!(
            restarted
                .admit(
                    sender,
                    [9; 16],
                    accepted_fingerprint,
                    expires,
                    delivery(false),
                )
                .await
                .unwrap(),
            ReplayDecision::DuplicateAccepted
        );
        assert_eq!(
            restarted
                .admit(sender, [9; 16], [3; 32], expires, delivery(false),)
                .await
                .unwrap(),
            ReplayDecision::Conflict
        );
        restarted_worker.shutdown().await.unwrap();
        fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn worker_persists_concurrent_requests_restarts_and_shuts_down_cleanly() {
        let recipient = iroh::SecretKey::generate().public();
        let sender = iroh::SecretKey::generate().public();
        let topic = TopicId::from_bytes([35; 32]);
        let (snapshot, wal, legacy, dir) = test_paths();
        let (client, mut worker) = start_paths(
            snapshot.clone(),
            wal.clone(),
            legacy.clone(),
            recipient,
            topic,
        )
        .unwrap();
        let expires = wall_ms().unwrap() + 60_000;
        let mut tasks = Vec::new();
        for index in 0..SENDER_RATE_BURST as usize {
            let client = client.clone();
            tasks.push(tokio::spawn(async move {
                let id = (index as u128).to_le_bytes();
                client
                    .admit(sender, id, fingerprint(id), expires, delivery(true))
                    .await
                    .unwrap()
            }));
        }
        for task in tasks {
            assert_eq!(task.await.unwrap(), ReplayDecision::Accepted);
        }
        worker.shutdown().await.unwrap();
        let (restarted, mut restarted_worker) =
            start_paths(snapshot, wal, legacy, recipient, topic).unwrap();
        assert_eq!(
            restarted
                .admit(
                    sender,
                    [0; 16],
                    fingerprint([0; 16]),
                    expires,
                    delivery(false),
                )
                .await
                .unwrap(),
            ReplayDecision::DuplicateAccepted
        );
        restarted_worker.shutdown().await.unwrap();
        fs::remove_dir_all(dir).unwrap();
    }
}
