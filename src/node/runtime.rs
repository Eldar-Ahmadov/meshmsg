use super::{
    bootstrap::{start, RunningNode},
    commands::DaemonCommand,
    common::{OPERATION_CACHE_CAPACITY, OPERATION_CACHE_TTL},
    operation_cache::OperationCache,
    supervisor::{BackgroundTasks, JoinedTask},
};

use crate::{
    alias::AliasConfig,
    attachment::{
        protocol::{offer_event as attachment_offer_event, validate_offer_binding},
        runtime::*,
    },
    cli::DaemonOptions,
    clock::unix_timestamp_ms,
    config::{State, StateLock},
    direct,
    gossip::EventHandler as GossipEventHandler,
    ids::peer_id,
    invite::Invite,
    ipc::{
        bind_local_endpoint,
        server::{
            subscription_startup_events, LocalClientSession, Server as IpcServer,
            EVENT_CAPACITY as IPC_EVENT_CAPACITY,
        },
    },
    presence::{self, Directory, PresenceSourceLimiter},
};
use anyhow::{Context, Result};
use futures_util::TryStreamExt;
use iroh_gossip::{api::Event, proto::TopicId};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::sync::{broadcast, mpsc, Semaphore};

const NEIGHBOR_PRESENCE_ANNOUNCE_TIMEOUT: Duration = Duration::from_secs(10);
const STARTUP_TIMEOUT: Duration = Duration::from_secs(45);
const ENDPOINT_ONLINE_TIMEOUT: Duration = Duration::from_secs(30);
/// Re-issue the gossip join after connectivity loss. `join_peers` only queues a
/// connection attempt, so repeating it also covers attempts made while the
/// network interface is still unavailable.
const REJOIN_INTERVAL: Duration = Duration::from_secs(5);
/// Every live peer re-announces presence each `ANNOUNCE_INTERVAL`. If the
/// broadcast topic has neighbors but no presence record has arrived for this
/// long, the separate presence swarm is treated as partitioned from the mesh.
const PRESENCE_STALE_AFTER: Duration = Duration::from_secs(90);
/// Minimum spacing between presence repair joins while the swarm stays silent.
const PRESENCE_REPAIR_INTERVAL: Duration = Duration::from_secs(90);
const ATTACHMENT_RETENTION_CHECK_INTERVAL: Duration = Duration::from_secs(60 * 60);
const ATTACHMENT_SPACE_REFRESH_INTERVAL: Duration = Duration::from_secs(30);
fn shutdown_signals() -> Result<mpsc::Receiver<()>> {
    let (sender, receiver) = mpsc::channel(1);
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .context("install SIGTERM handler")?;
        let mut interrupt =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                .context("install SIGINT handler")?;
        tokio::spawn(async move {
            tokio::select! {
                _ = terminate.recv() => {}
                _ = interrupt.recv() => {}
            }
            let _ = sender.send(()).await;
        });
    }
    #[cfg(windows)]
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            let _ = sender.send(()).await;
        }
    });
    Ok(receiver)
}

/// Tracks liveness of the presence gossip swarm independently of its own
/// neighbor bookkeeping, which can report stale neighbors indefinitely after
/// suspend/resume or network changes while the broadcast swarm recovers.
struct PresenceHealth {
    last_received: tokio::time::Instant,
    last_repair: Option<tokio::time::Instant>,
}

impl PresenceHealth {
    fn new(now: tokio::time::Instant) -> Self {
        Self {
            last_received: now,
            last_repair: None,
        }
    }

    fn received(&mut self, now: tokio::time::Instant) {
        self.last_received = now;
        self.last_repair = None;
    }

    /// Returns true (and records the attempt) when a repair join is due.
    fn take_repair(&mut self, broadcast_joined: bool, now: tokio::time::Instant) -> bool {
        let stale = now.duration_since(self.last_received) >= PRESENCE_STALE_AFTER;
        let spaced = self
            .last_repair
            .is_none_or(|last| now.duration_since(last) >= PRESENCE_REPAIR_INTERVAL);
        let due = broadcast_joined && stale && spaced;
        if due {
            self.last_repair = Some(now);
        }
        due
    }
}

fn presence_join_candidates(
    bootstrap: &[iroh::PublicKey],
    broadcast_neighbors: impl IntoIterator<Item = iroh::PublicKey>,
    me: iroh::PublicKey,
) -> Vec<iroh::PublicKey> {
    let mut candidates = bootstrap.to_vec();
    for peer in broadcast_neighbors {
        if !candidates.contains(&peer) {
            candidates.push(peer);
        }
    }
    candidates.retain(|peer| *peer != me);
    candidates
}

/// The long-lived state of a running daemon. Only the daemon loop task
/// touches it, so nothing here needs a lock.
pub(super) struct Daemon {
    pub(super) dir: PathBuf,
    pub(super) node: RunningNode,
    pub(super) topic: TopicId,
    pub(super) peer: meshmsg_protocol::PeerId,
    pub(super) state: State,
    pub(super) alias_config: AliasConfig,
    pub(super) has_invite: bool,
    pub(super) bootstrap_peer_count: usize,
    pub(super) self_advertised: bool,
    pub(super) max_attachment_bytes: u64,
    pub(super) attachment_retention_secs: u64,
    pub(super) attachment_storage: AttachmentStorage,
    pub(super) transfer_limit: Arc<Semaphore>,
    pub(super) offer_list_limit: Arc<Semaphore>,
    pub(super) direct_sender: direct::DirectSender,
    pub(super) operation_cache: OperationCache,
    pub(super) tasks: BackgroundTasks,
    pub(super) directory: Directory,
    pub(super) event_tx: broadcast::Sender<meshmsg_protocol::Event>,
    presence_sources: PresenceSourceLimiter,
    presence_health: PresenceHealth,
    gossip_events: GossipEventHandler,
    /// Daemon-lifetime state: consumed before starting the sole reconnect
    /// announcement so neither send failure nor later churn can retry it.
    neighbor_announcement_pending: bool,
    neighbor_presence_tasks: tokio::task::JoinSet<()>,
}

impl Daemon {
    /// `invite` is the parsed invite of `state`, and `node` runs its topic.
    pub(super) async fn new(
        dir: &Path,
        node: RunningNode,
        state: State,
        alias_config: AliasConfig,
        invite: Option<&Invite>,
        options: DaemonOptions,
    ) -> Result<Self> {
        let topic = state.topic_id();
        let (has_invite, bootstrap_peer_count, self_advertised) =
            crate::invite::configured_details(invite, node.endpoint.id());
        let blob_root = dir.join("blobs-v1").join(node.secret.public().to_string());
        let attachment_storage = AttachmentStorage::open(
            node.blob_store.clone(),
            blob_root,
            dir,
            options.max_attachment_storage_bytes,
            options.min_attachment_free_bytes,
            options.attachment_retention_secs,
        )
        .await
        .context("initialize attachment lifecycle state")?;
        let mut directory = Directory::new(node.presence_lookup.clone());
        for address in &node.bootstrap_addrs {
            if directory.pin(address.clone()).is_ok() {
                // Invite validation already bounds bootstrap addresses; invalid direct
                // addresses simply remain unavailable for private messaging.
            }
        }
        if presence::validate_endpoint_addr(&node.endpoint.addr(), node.endpoint.id()).is_ok() {
            directory.pin(node.endpoint.addr())?;
        }
        Ok(Self {
            dir: dir.to_path_buf(),
            topic,
            peer: peer_id(node.endpoint.id()),
            state,
            alias_config,
            has_invite,
            bootstrap_peer_count,
            self_advertised,
            max_attachment_bytes: options.max_attachment_bytes,
            attachment_retention_secs: options.attachment_retention_secs,
            attachment_storage,
            transfer_limit: Arc::new(Semaphore::new(2)),
            offer_list_limit: Arc::new(Semaphore::new(1)),
            direct_sender: direct::DirectSender::new(
                node.endpoint.clone(),
                node.secret.clone(),
                topic,
            ),
            // Deliberately daemon-lifetime scoped: the cache is bounded, memory-only, and
            // cleared by restart, so callers never infer durable command history.
            operation_cache: OperationCache::new(OPERATION_CACHE_CAPACITY, OPERATION_CACHE_TTL),
            tasks: BackgroundTasks::default(),
            directory,
            event_tx: broadcast::channel(IPC_EVENT_CAPACITY).0,
            presence_sources: PresenceSourceLimiter::default(),
            presence_health: PresenceHealth::new(tokio::time::Instant::now()),
            gossip_events: GossipEventHandler::default(),
            neighbor_announcement_pending: true,
            neighbor_presence_tasks: tokio::task::JoinSet::new(),
            node,
        })
    }

    /// Expiration is authoritative in the daemon: every caller publishes
    /// pending expiries before it reads or changes the directory.
    pub(super) fn expire_peers(&mut self) {
        for transition in self.directory.cleanup() {
            let _ = self.event_tx.send(transition);
        }
    }

    /// Per-client state for a newly admitted local connection.
    fn client_session(
        &mut self,
        commands: mpsc::Sender<DaemonCommand>,
    ) -> Result<LocalClientSession> {
        // Emit expiries before capturing the new subscriber's snapshot so
        // queued events are strictly later than that snapshot.
        self.expire_peers();
        let generated_at_ms = unix_timestamp_ms()?;
        let connectivity = presence::local_connectivity(&self.node.endpoint, &self.node.receiver);
        let (connected, startup_peers) = subscription_startup_events(
            connectivity,
            &self.directory,
            self.peer,
            self.alias_config.effective(),
            generated_at_ms,
        )?;
        Ok(LocalClientSession {
            commands,
            events: self.event_tx.subscribe(),
            connected,
            startup_peers: Some(startup_peers),
        })
    }

    fn on_broadcast_event(&mut self, value: Event) -> Result<()> {
        let now_ms = unix_timestamp_ms()?;
        let events = self
            .gossip_events
            .handle(value, self.topic, now_ms, |envelope| {
                let offer = validate_offer_binding(
                    envelope.from,
                    envelope.message_id,
                    envelope.timestamp_ms,
                    envelope.body,
                )?;
                Ok(attachment_offer_event(
                    envelope.from,
                    envelope.timestamp_ms,
                    envelope.encoded,
                    offer,
                ))
            });
        for event in events {
            let _ = self.event_tx.send(event);
        }
        Ok(())
    }

    fn on_presence_event(&mut self, event: Event) {
        match event {
            Event::Received(message) => {
                // Rate-limit the authenticated transport hop, not the signed
                // presence identity, which an invite holder can rotate cheaply.
                if self.presence_sources.allow(message.delivered_from) {
                    // Never let receive-time cleanup swallow an expiry. The
                    // explicit cleanup transition is emitted first.
                    self.expire_peers();
                    if let Ok(transition) = self.directory.receive(&message.content, self.topic) {
                        self.presence_health.received(tokio::time::Instant::now());
                        if let Some(transition) = transition {
                            let _ = self.event_tx.send(transition);
                        }
                    }
                }
            }
            Event::NeighborDown(source) => self.presence_sources.remove(source),
            Event::NeighborUp(_) => self.on_presence_neighbor_up(),
            Event::Lagged => {}
        }
    }

    /// Announces presence to the first presence neighbor of this daemon's
    /// lifetime; later neighbors rely on the periodic announcement.
    fn on_presence_neighbor_up(&mut self) {
        if !std::mem::take(&mut self.neighbor_announcement_pending) {
            return;
        }
        // Exactly one bounded task can be created in this daemon lifetime.
        let sender = self.node.presence_sender.clone();
        let secret = self.node.secret.clone();
        let topic = self.topic;
        let alias = self.alias_config.effective().map(str::to_owned);
        let endpoint = self.node.endpoint.addr();
        self.neighbor_presence_tasks.spawn(async move {
            let _ = tokio::time::timeout(
                NEIGHBOR_PRESENCE_ANNOUNCE_TIMEOUT,
                presence::announce(&sender, &secret, topic, alias.as_deref(), endpoint),
            )
            .await;
        });
    }

    async fn announce_presence(&self) {
        presence::announce(
            &self.node.presence_sender,
            &self.node.secret,
            self.topic,
            self.alias_config.effective(),
            self.node.endpoint.addr(),
        )
        .await;
    }

    fn refresh_attachment_space(&mut self) {
        let storage = self.attachment_storage.clone();
        self.tasks
            .try_spawn_space_refresh(async move { storage.refresh_free_space().await });
    }

    fn run_attachment_retention(&mut self) {
        let storage = self.attachment_storage.clone();
        self.tasks
            .spawn_retention(async move { storage.automatic_retention_pass().await });
    }

    async fn rejoin(&mut self) -> Result<()> {
        let node = &self.node;
        if !node.bootstrap_peers.is_empty() && !node.receiver.is_joined() {
            node.sender
                .join_peers(node.bootstrap_peers.clone())
                .await
                .context("retry gossip bootstrap peers after connectivity loss")?;
        }
        // The presence swarm is separate from the broadcast swarm, so it
        // can stay partitioned (or hold stale neighbors) while broadcast
        // traffic still flows. Live broadcast neighbors are reachable
        // members of the same topic: use them as additional contacts.
        let presence_lost = !node.presence_receiver.is_joined();
        if presence_lost
            || self
                .presence_health
                .take_repair(node.receiver.is_joined(), tokio::time::Instant::now())
        {
            let candidates = presence_join_candidates(
                &node.bootstrap_peers,
                node.receiver.neighbors(),
                node.endpoint.id(),
            );
            if !candidates.is_empty() {
                node.presence_sender
                    .join_peers(candidates)
                    .await
                    .context("retry presence peers after connectivity loss")?;
            }
        }
        Ok(())
    }

    pub(super) fn complete_task(&mut self, joined: JoinedTask) {
        self.tasks
            .complete(joined, &mut self.operation_cache, &self.event_tx);
    }
}

pub(crate) async fn run_daemon(dir: &Path, options: DaemonOptions) -> Result<()> {
    anyhow::ensure!(
        options.max_attachment_bytes > 0,
        "maximum attachment size must be greater than zero"
    );
    anyhow::ensure!(
        options.max_attachment_storage_bytes > 0,
        "maximum attachment storage must be greater than zero"
    );
    // Install service-manager/console signal handling before startup becomes visible.
    let mut shutdown = shutdown_signals()?;
    // Claim local ownership before reading the identity, starting networking, or mutating state.
    let state_lock = StateLock::acquire(dir)?;
    // Loading under the lock validates the state for this identity and yields
    // the one parsed copy of its invite.
    let (mut state, secret, mut invite) = State::load_locked(dir, &state_lock)?;
    let topic = state.topic_id();
    let alias_config = AliasConfig::load_for_identity(dir, secret.public())?;
    let startup = tokio::select! {
        result = tokio::time::timeout(STARTUP_TIMEOUT, start(topic, invite.as_ref(), secret, dir)) => result,
        _ = shutdown.recv() => return Ok(()),
    };
    let node = match startup {
        Ok(Ok(node)) => node,
        Ok(Err(error)) => {
            return Err(error)
                .context("start gossip topic; verify the invite and bootstrap-peer reachability");
        }
        Err(_) => {
            anyhow::bail!(
                "startup timed out after {}s while joining the gossip topic; verify that at least one configured bootstrap peer is reachable",
                STARTUP_TIMEOUT.as_secs()
            );
        }
    };
    let online = tokio::select! {
        result = tokio::time::timeout(ENDPOINT_ONLINE_TIMEOUT, node.endpoint.online()) => result,
        _ = shutdown.recv() => {
            node.router.shutdown().await?;
            return Ok(());
        }
    };
    if online.is_err() {
        node.router.shutdown().await?;
        anyhow::bail!(
            "endpoint did not become online within {}s; check internet, DNS, firewall, and relay access",
            ENDPOINT_ONLINE_TIMEOUT.as_secs()
        );
    }

    if state.advertise_self {
        let advertised = invite.get_or_insert(Invite {
            topic,
            bootstrap_peers: Vec::new(),
        });
        advertised.upsert_bootstrap_peer(node.endpoint.addr())?;
        state.invite = Some(advertised.to_string());
        state.save(dir, &state_lock)?;
    }

    let mut daemon = Daemon::new(dir, node, state, alias_config, invite.as_ref(), options).await?;
    // Expose IPC only after networking is ready, so clients never connect to a
    // socket whose daemon is still blocked during bootstrap.
    let (mut listener, _endpoint_guard) = bind_local_endpoint(dir, &state_lock).await?;
    eprintln!("daemon running as {}", daemon.peer);

    let (command_tx, mut command_rx) = mpsc::channel(32);
    let mut ipc_server = IpcServer::new();
    let mut presence = tokio::time::interval(presence::ANNOUNCE_INTERVAL);
    presence.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut presence_cleanup = tokio::time::interval(presence::CLEANUP_INTERVAL);
    presence_cleanup.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut rejoin = tokio::time::interval(REJOIN_INTERVAL);
    rejoin.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut retention_check = tokio::time::interval(ATTACHMENT_RETENTION_CHECK_INTERVAL);
    retention_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Do not run a retention pass immediately at startup.
    retention_check.tick().await;
    let mut attachment_space_refresh = tokio::time::interval(ATTACHMENT_SPACE_REFRESH_INTERVAL);
    attachment_space_refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    attachment_space_refresh.tick().await;

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let stream = accepted?;
                // Admission is the first operation after the platform listener's
                // accept/authentication. The session state—cleanup, time lookup,
                // snapshot construction, and subscription—is prepared only while
                // this client owns a connection permit.
                let _admitted = ipc_server
                    .admit(stream, || daemon.client_session(command_tx.clone()))
                    .await?;
            }
            command = command_rx.recv() => match command {
                Some(DaemonCommand::Execute { request, reply }) => {
                    daemon.execute(request, reply).await?;
                }
                Some(DaemonCommand::Stop) | None => break,
            },
            incoming = daemon.node.receiver.try_next() => match incoming? {
                Some(event) => daemon.on_broadcast_event(event)?,
                None => break,
            },
            incoming = daemon.node.presence_receiver.try_next() => match incoming? {
                Some(event) => daemon.on_presence_event(event),
                None => break,
            },
            incoming = daemon.node.direct_incoming.recv() => {
                if let Some(event) = incoming {
                    let _ = daemon.event_tx.send(event);
                }
            },
            _ = presence.tick() => daemon.announce_presence().await,
            _ = presence_cleanup.tick() => {
                daemon.expire_peers();
                daemon.presence_sources.cleanup();
            },
            _ = attachment_space_refresh.tick() => daemon.refresh_attachment_space(),
            _ = retention_check.tick(), if daemon.attachment_retention_secs != 0 => {
                daemon.run_attachment_retention();
            }
            _ = rejoin.tick() => daemon.rejoin().await?,
            _ = ipc_server.join_next(), if ipc_server.has_sessions() => {},
            joined = daemon.tasks.join_next(), if !daemon.tasks.is_empty() => {
                if let Some(joined) = joined {
                    daemon.complete_task(joined);
                }
            },
            _ = shutdown.recv() => break,
        }
    }

    // Stop admission and command submission first. Closing the event channel
    // lets subscriptions finish naturally; cancelling work releases any pending
    // command replies. Give handlers a short drain window before force-aborting.
    ipc_server.close_admission();
    command_rx.close();
    daemon.transfer_limit.close();
    daemon.attachment_storage.gate.close();
    daemon.offer_list_limit.close();
    daemon.direct_sender.close();
    daemon
        .tasks
        .abort_and_drain(&mut daemon.operation_cache, &daemon.event_tx)
        .await;
    // Keep the event sender alive until supervised cancellation has completed
    // operation waiters. Subscriptions can then close naturally while command
    // handlers retain their existing bounded response-drain grace.
    drop(daemon.event_tx);
    daemon.neighbor_presence_tasks.abort_all();
    while daemon.neighbor_presence_tasks.join_next().await.is_some() {}
    ipc_server.shutdown().await;
    daemon.node.router.shutdown().await?;
    Ok(())
}

#[cfg(test)]
impl Daemon {
    /// A daemon on a fresh single-node topic in its own temporary state directory.
    pub(super) async fn start_for_test() -> Self {
        let dir =
            std::env::temp_dir().join(format!("meshmsg-daemon-test-{}", rand::random::<u64>()));
        let mut alias = AliasConfig::prepare(false).unwrap();
        State::new_topic()
            .save_new_with_alias(&dir, false, &mut alias)
            .unwrap();
        let (state, secret) = State::load_for_doctor(&dir).unwrap();
        let alias_config = AliasConfig::load_for_identity(&dir, secret.public()).unwrap();
        let node = start(state.topic_id(), None, secret, &dir).await.unwrap();
        let options = DaemonOptions {
            max_attachment_bytes: 1024,
            max_attachment_storage_bytes: 1024,
            min_attachment_free_bytes: 0,
            attachment_retention_secs: 0,
        };
        Self::new(&dir, node, state, alias_config, None, options)
            .await
            .unwrap()
    }

    pub(super) async fn stop_for_test(self) {
        self.node.router.shutdown().await.unwrap();
        let dir = self.dir.clone();
        drop(self);
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn only_the_first_presence_neighbor_starts_one_announcement_per_daemon_lifetime() {
        let mut daemon = Daemon::start_for_test().await;
        assert!(daemon.neighbor_presence_tasks.is_empty());
        for _ in 0..1_000 {
            daemon.on_presence_neighbor_up();
        }
        assert_eq!(daemon.neighbor_presence_tasks.len(), 1);

        // However that announcement ended, later churn never retries it.
        while daemon.neighbor_presence_tasks.join_next().await.is_some() {}
        for _ in 0..1_000 {
            daemon.on_presence_neighbor_up();
        }
        assert!(daemon.neighbor_presence_tasks.is_empty());
        daemon.stop_for_test().await;
    }

    #[test]
    fn presence_repair_requires_live_broadcast_and_silent_presence() {
        let start = tokio::time::Instant::now();
        let mut health = PresenceHealth::new(start);
        assert!(!health.take_repair(true, start + Duration::from_secs(89)));
        let stale = start + PRESENCE_STALE_AFTER;
        assert!(!health.take_repair(false, stale));
        assert!(health.take_repair(true, stale));
        // Repairs are spaced while presence stays silent.
        assert!(!health.take_repair(true, stale + Duration::from_secs(5)));
        assert!(health.take_repair(true, stale + PRESENCE_REPAIR_INTERVAL));
        // Any accepted record resets staleness and spacing.
        let fresh = stale + PRESENCE_REPAIR_INTERVAL + Duration::from_secs(1);
        health.received(fresh);
        assert!(!health.take_repair(true, fresh + Duration::from_secs(60)));
        assert!(health.take_repair(true, fresh + PRESENCE_STALE_AFTER));
    }

    #[test]
    fn presence_join_candidates_merge_bootstrap_and_broadcast_neighbors() {
        let me = iroh::SecretKey::generate().public();
        let a = iroh::SecretKey::generate().public();
        let b = iroh::SecretKey::generate().public();
        assert_eq!(
            presence_join_candidates(&[a, me], [a, b, me], me),
            vec![a, b]
        );
        assert!(presence_join_candidates(&[], [], me).is_empty());
    }
}
