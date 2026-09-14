use super::{
    bootstrap::start,
    commands::{self, CommandAction, ExecutionContext},
    common::{unix_timestamp_ms, OPERATION_CACHE_CAPACITY, OPERATION_CACHE_TTL},
    operation_cache::OperationCache,
    supervisor::{self, AttachmentTaskCompletion, AttachmentTaskMetadata},
};

use crate::{
    alias::AliasConfig,
    attachment::{
        protocol::{offer_event as attachment_offer_event, validate_offer_binding},
        runtime::*,
    },
    config::{State, StateLock},
    direct,
    gossip::EventHandler as GossipEventHandler,
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
use iroh::{EndpointAddr, SecretKey};
use iroh_gossip::{
    api::{Event, GossipSender},
    proto::TopicId,
};
use std::{
    collections::HashMap,
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::{broadcast, mpsc, Semaphore};

const NEIGHBOR_PRESENCE_ANNOUNCE_TIMEOUT: Duration = Duration::from_secs(10);

fn on_neighbor_up<T>(
    is_presence_neighbor: bool,
    available: &mut bool,
    announce: impl FnOnce() -> T,
) -> Option<T> {
    (is_presence_neighbor && std::mem::take(available)).then(announce)
}

const STARTUP_TIMEOUT: Duration = Duration::from_secs(45);
const ENDPOINT_ONLINE_TIMEOUT: Duration = Duration::from_secs(30);
/// Re-issue the gossip join after connectivity loss. `join_peers` only queues a
/// connection attempt, so repeating it also covers attempts made while the
/// network interface is still unavailable.
const REJOIN_INTERVAL: Duration = Duration::from_secs(5);
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

fn spawn_neighbor_presence_announcement(
    tasks: &mut tokio::task::JoinSet<()>,
    sender: GossipSender,
    secret: SecretKey,
    topic: TopicId,
    alias: Option<String>,
    endpoint: EndpointAddr,
) {
    tasks.spawn(async move {
        let _ = tokio::time::timeout(
            NEIGHBOR_PRESENCE_ANNOUNCE_TIMEOUT,
            presence::announce(&sender, &secret, topic, alias.as_deref(), endpoint),
        )
        .await;
    });
}

pub(super) async fn run_daemon(
    dir: &Path,
    max_attachment_bytes: u64,
    max_attachment_storage_bytes: u64,
    min_attachment_free_bytes: u64,
    attachment_retention_secs: u64,
) -> Result<()> {
    anyhow::ensure!(
        max_attachment_bytes > 0,
        "maximum attachment size must be greater than zero"
    );
    anyhow::ensure!(
        max_attachment_storage_bytes > 0,
        "maximum attachment storage must be greater than zero"
    );
    // Install service-manager/console signal handling before startup becomes visible.
    let mut shutdown = shutdown_signals()?;
    // Claim local ownership before reading the identity, starting networking, or mutating state.
    let state_lock = StateLock::acquire(dir)?;
    let (mut state, secret) = State::load_locked(dir, &state_lock)?;
    state.validate_for_identity(secret.public())?;
    let alias_config = AliasConfig::load_for_identity(dir, secret.public())?;
    let startup = tokio::select! {
        result = tokio::time::timeout(STARTUP_TIMEOUT, start(&state, secret, dir)) => result,
        _ = shutdown.recv() => return Ok(()),
    };
    let mut node = match startup {
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
            node.direct_replay.shutdown().await?;
            return Ok(());
        }
    };
    if online.is_err() {
        node.router.shutdown().await?;
        node.direct_replay.shutdown().await?;
        anyhow::bail!(
            "endpoint did not become online within {}s; check internet, DNS, firewall, and relay access",
            ENDPOINT_ONLINE_TIMEOUT.as_secs()
        );
    }

    if state.advertise_self {
        let mut invite = match &state.invite {
            Some(token) => token.parse::<Invite>()?,
            None => Invite {
                topic: state.topic_id()?,
                bootstrap_peers: Vec::new(),
            },
        };
        invite.upsert_bootstrap_peer(node.endpoint.addr())?;
        state.invite = Some(invite.to_string());
        state.save(dir, &state_lock)?;
    }

    let (has_invite, bootstrap_peer_count, self_advertised) =
        crate::invite::configured_details(state.invite.as_deref(), node.endpoint.id())?;
    let blob_root = dir.join("blobs-v1").join(node.secret.public().to_string());
    let attachment_storage = AttachmentStorage::open(
        node.blob_store.clone(),
        blob_root,
        dir,
        max_attachment_storage_bytes,
        min_attachment_free_bytes,
        attachment_retention_secs,
    )
    .await
    .context("initialize attachment lifecycle state")?;
    // Expose IPC only after networking is ready, so clients never connect to a
    // socket whose daemon is still blocked during bootstrap.
    let (mut listener, _endpoint_guard) = bind_local_endpoint(dir, &state_lock).await?;
    let peer = node.endpoint.id().to_string();
    eprintln!("daemon running as {peer}");

    let (command_tx, mut command_rx) = mpsc::channel(32);
    let (event_tx, _) = broadcast::channel(IPC_EVENT_CAPACITY);
    let transfer_limit = Arc::new(Semaphore::new(2));
    let offer_list_limit = Arc::new(Semaphore::new(1));
    let direct_sender = direct::DirectSender::new(
        node.endpoint.clone(),
        node.secret.clone(),
        state.topic_id()?,
    );
    // Deliberately daemon-lifetime scoped: status advertises the bounded TTL and
    // restart semantics so callers never infer durable command history.
    let operation_cache = Arc::new(Mutex::new(OperationCache::new(
        OPERATION_CACHE_CAPACITY,
        OPERATION_CACHE_TTL,
    )));
    let topic = state.topic_id()?;
    let mut directory = Directory::new(node.presence_lookup.clone());
    let directory_epoch = data_encoding::HEXLOWER.encode(&rand::random::<[u8; 16]>());
    let mut directory_revision = 0_u64;
    for address in &node.bootstrap_addrs {
        if directory.pin(address.clone()).is_ok() {
            // Invite validation already bounds bootstrap addresses; invalid direct
            // addresses simply remain unavailable for private messaging.
        }
    }
    if presence::validate_endpoint_addr(&node.endpoint.addr(), node.endpoint.id()).is_ok() {
        directory.pin(node.endpoint.addr())?;
    }
    let mut presence = tokio::time::interval(presence::ANNOUNCE_INTERVAL);
    presence.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut presence_cleanup = tokio::time::interval(presence::CLEANUP_INTERVAL);
    presence_cleanup.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut presence_sources = PresenceSourceLimiter::default();
    // Daemon-lifetime state: consume this before starting the sole reconnect
    // announcement so neither send failure nor later churn can retry it.
    let mut first_neighbor_presence_announcement = true;
    let mut neighbor_presence_tasks = tokio::task::JoinSet::new();
    let mut gossip_events = GossipEventHandler::default();
    let mut ipc_server = IpcServer::new();
    let mut transfer_tasks = tokio::task::JoinSet::new();
    let mut offer_list_tasks = tokio::task::JoinSet::new();
    let mut attachment_task_metadata = HashMap::new();
    let mut attachment_space_refresh_active = false;
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
                // accept/authentication. Everything in this closure—including
                // cleanup, time lookup, snapshot construction, and subscription—
                // runs only while this client owns a connection permit.
                let _admitted = ipc_server.admit(stream, || {
                        // Expiration is authoritative in the daemon. Emit it before
                        // capturing the new subscriber's snapshot so queued events
                        // are strictly later than that snapshot.
                        presence::emit_transitions(directory.cleanup(), &event_tx, &directory_epoch, &mut directory_revision);
                        let generated_at_ms = unix_timestamp_ms()?;
                        let connectivity = presence::local_connectivity(
                            &node.endpoint,
                            &node.receiver,
                        );
                        let (connected, startup_peers) = subscription_startup_events(
                            connectivity,
                            &directory,
                            &peer,
                            alias_config.effective(),
                            generated_at_ms,
                            &directory_epoch,
                            directory_revision,
                        )?;
                        Ok(LocalClientSession::new(
                            command_tx.clone(),
                            event_tx.subscribe(),
                            connected,
                            Some(startup_peers),
                        ))
                    },
                ).await?;
            }
            command = command_rx.recv() => {
                let action = commands::execute(
                    command,
                    ExecutionContext {
                        node: &node,
                        state: &state,
                        alias_config: &alias_config,
                        has_invite,
                        bootstrap_peer_count,
                        self_advertised,
                        max_attachment_bytes,
                        attachment_retention_secs,
                        attachment_storage: &attachment_storage,
                        direct_sender: &direct_sender,
                        operation_cache: &operation_cache,
                        directory: &mut directory,
                        event_tx: &event_tx,
                        directory_epoch: &directory_epoch,
                        directory_revision: &mut directory_revision,
                        peer: &peer,
                        offer_list_limit: &offer_list_limit,
                        transfer_limit: &transfer_limit,
                        transfer_tasks: &mut transfer_tasks,
                        offer_list_tasks: &mut offer_list_tasks,
                        attachment_task_metadata: &mut attachment_task_metadata,
                        dir,
                        topic,
                    },
                ).await?;
                if action == CommandAction::Stop {
                    break;
                }
            },
            incoming = node.receiver.try_next() => match incoming? {
                Some(value) => {
                    let now_ms = unix_timestamp_ms()?;
                    let values = gossip_events.handle(value, topic, now_ms, |envelope| {
                        let offer = validate_offer_binding(
                            envelope.from,
                            envelope.message_id,
                            envelope.timestamp_ms,
                            envelope.body,
                        )?;
                        Ok(attachment_offer_event(
                            envelope.from,
                            envelope.message_id,
                            envelope.timestamp_ms,
                            envelope.encoded,
                            offer,
                        ))
                    });
                    for event in values {
                        let _ = event_tx.send(event);
                    }
                }
                None => break,
            },
            incoming = node.presence_receiver.try_next() => match incoming? {
                Some(Event::Received(message)) => {
                    // Rate-limit the authenticated transport hop, not the signed
                    // presence identity, which an invite holder can rotate cheaply.
                    if presence_sources.allow(message.delivered_from) {
                        // Never let receive-time cleanup swallow an expiry. The
                        // explicit cleanup transition is emitted first.
                        presence::emit_transitions(directory.cleanup(), &event_tx, &directory_epoch, &mut directory_revision);
                        if let Ok(Some(transition)) = directory.receive(&message.content, topic) {
                            presence::emit_transitions([transition], &event_tx, &directory_epoch, &mut directory_revision);
                        }
                    }
                }
                Some(Event::NeighborDown(source)) => presence_sources.remove(source),
                Some(Event::NeighborUp(_)) => {
                    let _ = on_neighbor_up(
                        true,
                        &mut first_neighbor_presence_announcement,
                        || {
                            // Exactly one bounded task can be created in this daemon lifetime.
                            spawn_neighbor_presence_announcement(
                                &mut neighbor_presence_tasks,
                                node.presence_sender.clone(),
                                node.secret.clone(),
                                topic,
                                alias_config.effective().map(str::to_owned),
                                node.endpoint.addr(),
                            );
                        },
                    );
                }
                Some(Event::Lagged) => {}
                None => break,
            },
            incoming = node.direct_incoming.recv() => {
                if let Some(event) = incoming {
                    let _ = event_tx.send(event);
                }
            },
            _ = presence.tick() => {
                presence::announce(
                    &node.presence_sender,
                    &node.secret,
                    topic,
                    alias_config.effective(),
                    node.endpoint.addr(),
                ).await;
            },
            _ = presence_cleanup.tick() => {
                presence::emit_transitions(directory.cleanup(), &event_tx, &directory_epoch, &mut directory_revision);
                presence_sources.cleanup();
            },
            _ = attachment_space_refresh.tick() => {
                let storage = attachment_storage.clone();
                supervisor::try_spawn_attachment_space_refresh(
                    &mut attachment_space_refresh_active,
                    &mut offer_list_tasks,
                    &mut attachment_task_metadata,
                    async move { storage.refresh_free_space().await },
                );
            }
            _ = retention_check.tick(), if attachment_retention_secs != 0 => {
                let storage = attachment_storage.clone();
                supervisor::spawn_attachment_task(
                    &mut offer_list_tasks,
                    &mut attachment_task_metadata,
                    AttachmentTaskMetadata {
                        kind: "automatic attachment retention",
                        unexpected_operation: None,
                        space_refresh: false,
                    },
                    async move {
                        AttachmentTaskCompletion::Retention(
                            storage.automatic_retention_pass().await,
                        )
                    },
                );
            }
            _ = rejoin.tick(), if !node.bootstrap_peers.is_empty() => {
                if !node.receiver.is_joined() {
                    node.sender
                        .join_peers(node.bootstrap_peers.clone())
                        .await
                        .context("retry gossip bootstrap peers after connectivity loss")?;
                }
                if !node.presence_receiver.is_joined() {
                    node.presence_sender
                        .join_peers(node.bootstrap_peers.clone())
                        .await
                        .context("retry presence bootstrap peers after connectivity loss")?;
                }
            },
            _ = ipc_server.join_next(), if ipc_server.has_sessions() => {},
            completed = transfer_tasks.join_next_with_id(), if !transfer_tasks.is_empty() => {
                if let Some(completed) = completed {
                    supervisor::complete_attachment_task(
                        completed,
                        &mut attachment_task_metadata,
                        &operation_cache,
                        &event_tx,
                        &mut attachment_space_refresh_active,
                    );
                }
            },
            completed = offer_list_tasks.join_next_with_id(), if !offer_list_tasks.is_empty() => {
                if let Some(completed) = completed {
                    supervisor::complete_attachment_task(
                        completed,
                        &mut attachment_task_metadata,
                        &operation_cache,
                        &event_tx,
                        &mut attachment_space_refresh_active,
                    );
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
    transfer_limit.close();
    attachment_storage.gate.close();
    offer_list_limit.close();
    direct_sender.close();
    supervisor::abort_and_drain_attachment_tasks(
        &mut transfer_tasks,
        &mut offer_list_tasks,
        &mut attachment_task_metadata,
        &operation_cache,
        &event_tx,
        &mut attachment_space_refresh_active,
    )
    .await;
    // Keep the event sender alive until supervised cancellation has completed
    // operation waiters. Subscriptions can then close naturally while command
    // handlers retain their existing bounded response-drain grace.
    drop(event_tx);
    neighbor_presence_tasks.abort_all();
    while neighbor_presence_tasks.join_next().await.is_some() {}
    ipc_server.shutdown().await;
    node.router.shutdown().await?;
    node.direct_replay.shutdown().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broadcast_neighbor_never_triggers_presence_work() {
        let mut available = true;
        let mut announcements = 0;
        for _ in 0..10_000 {
            assert_eq!(
                on_neighbor_up(false, &mut available, || announcements += 1),
                None
            );
        }
        assert_eq!(announcements, 0);
        assert!(available);
    }

    #[test]
    fn first_presence_neighbor_triggers_one_announcement() {
        let mut available = true;
        let mut announcements = 0;
        assert_eq!(
            on_neighbor_up(true, &mut available, || announcements += 1),
            Some(())
        );
        assert_eq!(announcements, 1);
        assert!(!available);
    }

    #[test]
    fn repeated_presence_neighbors_trigger_no_additional_announcements() {
        let mut available = true;
        let mut announcements = 0;
        let _ = on_neighbor_up(true, &mut available, || announcements += 1);
        for _ in 0..10_000 {
            assert_eq!(
                on_neighbor_up(true, &mut available, || announcements += 1),
                None
            );
        }
        assert_eq!(announcements, 1);
    }

    #[test]
    fn failed_first_presence_announcement_is_not_retried_by_churn() {
        let mut available = true;
        let mut attempts = 0;
        let failed = on_neighbor_up(true, &mut available, || {
            attempts += 1;
            Err::<(), ()>(())
        });
        assert!(matches!(failed, Some(Err(()))));
        for is_presence in [false, true].into_iter().cycle().take(10_000) {
            assert_eq!(
                on_neighbor_up(is_presence, &mut available, || {
                    attempts += 1;
                    Ok::<(), ()>(())
                }),
                None
            );
        }
        assert_eq!(attempts, 1);
    }
}
