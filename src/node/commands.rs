//! Typed daemon commands and their execution policy.

use super::{
    bootstrap::RunningNode,
    operation_cache::OperationCache,
    supervisor::{
        spawn_attachment_task, AttachmentTaskCompletion, AttachmentTaskMetadata, OperationEventKind,
    },
};
use crate::{
    alias::AliasConfig,
    attachment::runtime::*,
    clock::{unix_timestamp_ms, unix_timestamp_ms_saturating},
    config::State,
    direct, gossip,
    presence::{self, Directory},
};
use anyhow::Result;
use iroh_gossip::proto::TopicId;
use meshmsg_protocol::Request;
use std::{
    collections::HashMap,
    path::Path,
    sync::{Arc, Mutex},
    time::{Instant as StdInstant, SystemTime},
};
use tokio::sync::{broadcast, oneshot, Semaphore};

pub(crate) enum DaemonCommand {
    Execute {
        request: Request,
        reply: oneshot::Sender<meshmsg_protocol::Response>,
    },
    Stop,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CommandAction {
    Continue,
    Stop,
}

pub(super) struct ExecutionContext<'a> {
    pub(super) node: &'a RunningNode,
    pub(super) state: &'a State,
    pub(super) alias_config: &'a AliasConfig,
    pub(super) has_invite: bool,
    pub(super) bootstrap_peer_count: usize,
    pub(super) self_advertised: bool,
    pub(super) max_attachment_bytes: u64,
    pub(super) attachment_retention_secs: u64,
    pub(super) attachment_storage: &'a AttachmentStorage,
    pub(super) direct_sender: &'a direct::DirectSender,
    pub(super) operation_cache: &'a Arc<Mutex<OperationCache>>,
    pub(super) directory: &'a mut Directory,
    pub(super) event_tx: &'a broadcast::Sender<meshmsg_protocol::Event>,
    pub(super) peer: meshmsg_protocol::PeerId,
    pub(super) offer_list_limit: &'a Arc<Semaphore>,
    pub(super) transfer_limit: &'a Arc<Semaphore>,
    pub(super) transfer_tasks: &'a mut tokio::task::JoinSet<AttachmentTaskCompletion>,
    pub(super) offer_list_tasks: &'a mut tokio::task::JoinSet<AttachmentTaskCompletion>,
    pub(super) attachment_task_metadata: &'a mut HashMap<tokio::task::Id, AttachmentTaskMetadata>,
    pub(super) dir: &'a Path,
    pub(super) topic: TopicId,
}

pub(super) fn operation_fingerprint(kind: &str, fields: &[&[u8]]) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let mut digest = Sha256::new();
    digest.update(b"meshmsg-operation-v1\0");
    digest.update(kind.as_bytes());
    for field in fields {
        digest.update((field.len() as u64).to_le_bytes());
        digest.update(field);
    }
    digest.finalize().into()
}

pub(super) fn optional_text_fingerprint(value: Option<&str>) -> Vec<u8> {
    match value {
        Some(value) => [b"some\0".as_slice(), value.as_bytes()].concat(),
        None => b"none".to_vec(),
    }
}

pub(super) async fn execute(
    command: Option<DaemonCommand>,
    context: ExecutionContext<'_>,
) -> Result<CommandAction> {
    let ExecutionContext {
        node,
        state,
        alias_config,
        has_invite,
        bootstrap_peer_count,
        self_advertised,
        max_attachment_bytes,
        attachment_retention_secs,
        attachment_storage,
        direct_sender,
        operation_cache,
        directory,
        event_tx,
        peer,
        offer_list_limit,
        transfer_limit,
        transfer_tasks,
        offer_list_tasks,
        attachment_task_metadata,
        dir,
        topic,
    } = context;
    match command {
        Some(DaemonCommand::Execute {
            request: Request::Send { operation_id, body },
            reply,
        }) => {
            let fingerprint = operation_fingerprint("send", &[body.as_bytes()]);
            if !operation_cache
                .lock()
                .expect("operation cache poisoned")
                .admit(operation_id, fingerprint, reply, StdInstant::now())
            {
                return Ok(CommandAction::Continue);
            }
            let response = match unix_timestamp_ms() {
                Ok(timestamp_ms) => match gossip::Envelope::encode_message_with_id_at(
                    &node.secret,
                    topic,
                    body.clone().into_string(),
                    operation_id.to_bytes(),
                    timestamp_ms,
                ) {
                    Ok(envelope) => match node.sender.broadcast(envelope).await {
                        Ok(()) => meshmsg_protocol::Response::Queued(gossip::queued_event(
                            peer,
                            operation_id,
                            body,
                            timestamp_ms,
                        )),
                        Err(_error) => {
                            meshmsg_protocol::Response::Error(meshmsg_protocol::ProtocolError::new(
                                Some(operation_id),
                                meshmsg_protocol::ErrorCode::SendFailed,
                                meshmsg_protocol::Outcome::Unknown,
                            ))
                        }
                    },
                    Err(_error) => {
                        meshmsg_protocol::Response::Error(meshmsg_protocol::ProtocolError::new(
                            Some(operation_id),
                            meshmsg_protocol::ErrorCode::InvalidMessage,
                            meshmsg_protocol::Outcome::NotStarted,
                        ))
                    }
                },
                Err(_error) => {
                    meshmsg_protocol::Response::Error(meshmsg_protocol::ProtocolError::new(
                        Some(operation_id),
                        meshmsg_protocol::ErrorCode::InvalidMessage,
                        meshmsg_protocol::Outcome::NotStarted,
                    ))
                }
            };
            let response = operation_cache
                .lock()
                .expect("operation cache poisoned")
                .complete(&operation_id, response, StdInstant::now());
            if let meshmsg_protocol::Response::Queued(queued) = response {
                let _ = event_tx.send(meshmsg_protocol::Event::Queued(queued));
            }
        }
        Some(DaemonCommand::Execute {
            request:
                Request::PrivateSend {
                    operation_id,
                    to,
                    body,
                },
            reply,
        }) => {
            let fingerprint =
                operation_fingerprint("private_send", &[to.as_str().as_bytes(), body.as_bytes()]);
            if !operation_cache
                .lock()
                .expect("operation cache poisoned")
                .admit(operation_id, fingerprint, reply, StdInstant::now())
            {
                return Ok(CommandAction::Continue);
            }
            presence::emit_transitions(directory.cleanup(), event_tx);
            let address = match directory.resolve(to.as_str()) {
                Ok(address) => address,
                Err(_error) => {
                    operation_cache
                        .lock()
                        .expect("operation cache poisoned")
                        .complete(
                            &operation_id,
                            meshmsg_protocol::Response::Error(
                                meshmsg_protocol::ProtocolError::new(
                                    Some(operation_id),
                                    meshmsg_protocol::ErrorCode::RecipientUnresolved,
                                    meshmsg_protocol::Outcome::NotStarted,
                                ),
                            ),
                            StdInstant::now(),
                        );
                    return Ok(CommandAction::Continue);
                }
            };
            let permit = match direct_sender.try_reserve(operation_id) {
                Ok(permit) => permit,
                Err(error) => {
                    operation_cache
                        .lock()
                        .expect("operation cache poisoned")
                        .complete(
                            &operation_id,
                            meshmsg_protocol::Response::Error(error),
                            StdInstant::now(),
                        );
                    return Ok(CommandAction::Continue);
                }
            };
            spawn_attachment_task(
                transfer_tasks,
                attachment_task_metadata,
                AttachmentTaskMetadata {
                    kind: "private send",
                    unexpected_operation: Some((
                        operation_id,
                        meshmsg_protocol::ErrorCode::PrivateSendFailed,
                    )),
                    space_refresh: false,
                },
                async move {
                    let response = permit.send(address, body.into_string(), operation_id).await;
                    AttachmentTaskCompletion::Operation {
                        operation_id,
                        response,
                        event: OperationEventKind::None,
                    }
                },
            );
        }
        Some(DaemonCommand::Execute {
            request: Request::Status,
            reply,
        }) => {
            let connectivity = presence::local_connectivity(&node.endpoint, &node.receiver);
            let neighbors = node.receiver.neighbors().count();
            let status = meshmsg_protocol::Status {
                peer,
                topic: state.topic,
                advertises_self: state.advertise_self,
                has_invite,
                bootstrap_peer_count,
                self_advertised,
                neighbors,
                endpoint_online: connectivity.endpoint_online,
                topic_joined: connectivity.topic_joined,
                alias: alias_config.effective().map(str::parse).transpose()?,
                alias_enabled: alias_config.enabled(),
                captured_hostname: alias_config.hostname().map(str::to_owned),
                custom_alias: alias_config.custom().map(str::to_owned),
                advertised_aliases: directory.advertised_aliases(),
                max_attachment_bytes,
                attachment_storage: attachment_storage.status(),
                attachment_retention_secs,
            };
            status.validate().map_err(anyhow::Error::msg)?;
            let _ = reply.send(meshmsg_protocol::Response::Status(status));
        }
        Some(DaemonCommand::Execute {
            request: Request::Peers,
            reply,
        }) => {
            presence::emit_transitions(directory.cleanup(), event_tx);
            let generated_at_ms = unix_timestamp_ms()?;
            let _ = reply.send(meshmsg_protocol::Response::PeersSnapshot(
                directory.snapshot(
                    presence::local_connectivity(&node.endpoint, &node.receiver),
                    peer,
                    alias_config.effective(),
                    generated_at_ms,
                ),
            ));
        }
        Some(DaemonCommand::Execute {
            request: Request::Offers,
            reply,
        }) => {
            let permit = match try_admit_offer_listing(offer_list_limit) {
                Ok(permit) => permit,
                Err(error) => {
                    let _ = reply.send(meshmsg_protocol::Response::Error(error));
                    return Ok(CommandAction::Continue);
                }
            };
            let store = node.blob_store.clone();
            spawn_attachment_task(
                offer_list_tasks,
                attachment_task_metadata,
                AttachmentTaskMetadata {
                    kind: "attachment offer listing",
                    unexpected_operation: None,
                    space_refresh: false,
                },
                async move {
                    let _permit = permit;
                    AttachmentTaskCompletion::OfferList {
                        reply,
                        response: list_offers_request(store).await,
                    }
                },
            );
        }
        Some(DaemonCommand::Execute {
            request:
                Request::OffersRemove {
                    operation_id,
                    offer_id,
                    direction,
                    provider,
                },
            reply,
        }) => {
            let direction_fingerprint =
                optional_text_fingerprint(direction.map(|value| value.to_string()).as_deref());
            let provider_fingerprint =
                optional_text_fingerprint(provider.map(|value| value.to_string()).as_deref());
            let fingerprint = operation_fingerprint(
                "offers_remove",
                &[
                    offer_id.to_string().as_bytes(),
                    &direction_fingerprint,
                    &provider_fingerprint,
                ],
            );
            if !operation_cache
                .lock()
                .expect("operation cache poisoned")
                .admit(operation_id, fingerprint, reply, StdInstant::now())
            {
                return Ok(CommandAction::Continue);
            }
            let storage = attachment_storage.clone();
            spawn_attachment_task(
                offer_list_tasks,
                attachment_task_metadata,
                AttachmentTaskMetadata {
                    kind: "attachment offer removal",
                    unexpected_operation: Some((
                        operation_id,
                        meshmsg_protocol::ErrorCode::AttachmentLifecycleInternal,
                    )),
                    space_refresh: false,
                },
                async move {
                    let response = remove_offer_request(
                        storage,
                        &operation_id,
                        &offer_id,
                        direction,
                        provider.as_ref(),
                    )
                    .await;
                    AttachmentTaskCompletion::Operation {
                        operation_id,
                        response,
                        event: OperationEventKind::None,
                    }
                },
            );
        }
        Some(DaemonCommand::Execute {
            request:
                Request::OffersPrune {
                    operation_id,
                    older_than_secs,
                    direction,
                    dry_run,
                    max_delete,
                },
            reply,
        }) => {
            // The fingerprint binds the age as submitted, so an omitted age and
            // an explicit one never share an operation ID.
            let age_fingerprint = match older_than_secs {
                Some(age) => [b"some\0".as_slice(), &age.to_le_bytes()].concat(),
                None => b"none".to_vec(),
            };
            let direction_fingerprint =
                optional_text_fingerprint(direction.map(|value| value.to_string()).as_deref());
            let dry_run_fingerprint = [u8::from(dry_run)];
            let maximum_fingerprint = max_delete.to_le_bytes();
            let fingerprint = operation_fingerprint(
                "offers_prune",
                &[
                    &age_fingerprint,
                    &direction_fingerprint,
                    &dry_run_fingerprint,
                    &maximum_fingerprint,
                ],
            );
            if !operation_cache
                .lock()
                .expect("operation cache poisoned")
                .admit(operation_id, fingerprint, reply, StdInstant::now())
            {
                return Ok(CommandAction::Continue);
            }
            // Resolved once by the admitted owner. Retries replay the cached
            // terminal response, so neither the default age nor the cutoff is
            // derived a second time.
            let age = older_than_secs.unwrap_or(attachment_retention_secs);
            let cutoff = crate::attachment::prune_cutoff_upper_bound(
                unix_timestamp_ms_saturating(SystemTime::now()),
                age,
            );
            let storage = attachment_storage.clone();
            spawn_attachment_task(
                offer_list_tasks,
                attachment_task_metadata,
                AttachmentTaskMetadata {
                    kind: "attachment offer pruning",
                    unexpected_operation: Some((
                        operation_id,
                        meshmsg_protocol::ErrorCode::AttachmentLifecycleInternal,
                    )),
                    space_refresh: false,
                },
                async move {
                    let response = prune_offers_request(
                        storage,
                        &operation_id,
                        age,
                        cutoff,
                        direction,
                        dry_run,
                        max_delete,
                    )
                    .await;
                    AttachmentTaskCompletion::Operation {
                        operation_id,
                        response,
                        event: OperationEventKind::None,
                    }
                },
            );
        }
        Some(DaemonCommand::Execute {
            request: Request::Share { operation_id, path },
            reply,
        }) => {
            let fingerprint =
                operation_fingerprint("share", &[path.as_os_str().as_encoded_bytes()]);
            if !operation_cache
                .lock()
                .expect("operation cache poisoned")
                .admit(operation_id, fingerprint, reply, StdInstant::now())
            {
                return Ok(CommandAction::Continue);
            }
            let permit = match try_admit_transfer(transfer_limit) {
                Ok(permit) => permit,
                Err(_) => {
                    let error = meshmsg_protocol::ProtocolError::new(
                        Some(operation_id),
                        meshmsg_protocol::ErrorCode::AttachmentStorageBusy,
                        meshmsg_protocol::Outcome::NotStarted,
                    );
                    operation_cache
                        .lock()
                        .expect("operation cache poisoned")
                        .complete(
                            &operation_id,
                            meshmsg_protocol::Response::Error(error),
                            StdInstant::now(),
                        );
                    return Ok(CommandAction::Continue);
                }
            };
            let store = node.blob_store.clone();
            let storage = attachment_storage.clone();
            let endpoint = node.endpoint.clone();
            let secret = node.secret.clone();
            let sender = node.sender.clone();
            let state_dir = dir.to_path_buf();
            spawn_attachment_task(
                transfer_tasks,
                attachment_task_metadata,
                AttachmentTaskMetadata {
                    kind: "attachment share",
                    unexpected_operation: Some((
                        operation_id,
                        meshmsg_protocol::ErrorCode::ShareFailed,
                    )),
                    space_refresh: false,
                },
                async move {
                    let _permit = permit;
                    let response = share_request(
                        ShareResources {
                            store,
                            storage,
                            endpoint,
                            secret,
                            topic,
                            sender,
                            state_dir,
                        },
                        operation_id,
                        path,
                        max_attachment_bytes,
                    )
                    .await;
                    AttachmentTaskCompletion::Operation {
                        operation_id,
                        response,
                        event: OperationEventKind::AttachmentShared,
                    }
                },
            );
        }
        Some(DaemonCommand::Execute {
            request:
                Request::Download {
                    operation_id,
                    offer,
                    output,
                },
            reply,
        }) => {
            let fingerprint = operation_fingerprint(
                "download",
                &[
                    offer.as_str().as_bytes(),
                    output.as_os_str().as_encoded_bytes(),
                ],
            );
            if !operation_cache
                .lock()
                .expect("operation cache poisoned")
                .admit(operation_id, fingerprint, reply, StdInstant::now())
            {
                return Ok(CommandAction::Continue);
            }
            // Validate before transfer admission: an input that can never
            // succeed must not be reported as a transient busy condition.
            let offer = match parse_download_offer(operation_id, &offer, topic) {
                Ok(offer) => offer,
                Err(error) => {
                    operation_cache
                        .lock()
                        .expect("operation cache poisoned")
                        .complete(
                            &operation_id,
                            meshmsg_protocol::Response::Error(error),
                            StdInstant::now(),
                        );
                    return Ok(CommandAction::Continue);
                }
            };
            let permit = match try_admit_transfer(transfer_limit) {
                Ok(permit) => permit,
                Err(_) => {
                    let error = meshmsg_protocol::ProtocolError::new(
                        Some(operation_id),
                        meshmsg_protocol::ErrorCode::AttachmentStorageBusy,
                        meshmsg_protocol::Outcome::NotStarted,
                    );
                    operation_cache
                        .lock()
                        .expect("operation cache poisoned")
                        .complete(
                            &operation_id,
                            meshmsg_protocol::Response::Error(error),
                            StdInstant::now(),
                        );
                    return Ok(CommandAction::Continue);
                }
            };
            let store = node.blob_store.clone();
            let storage = attachment_storage.clone();
            let downloader = node.downloader.clone();
            let endpoint = node.endpoint.clone();
            let lookup = node.lookup.clone();
            let events = event_tx.clone();
            spawn_attachment_task(
                transfer_tasks,
                attachment_task_metadata,
                AttachmentTaskMetadata {
                    kind: "attachment download",
                    unexpected_operation: Some((
                        operation_id,
                        meshmsg_protocol::ErrorCode::DownloadFailed,
                    )),
                    space_refresh: false,
                },
                async move {
                    let _permit = permit;
                    let response = download_request(
                        DownloadResources {
                            store,
                            storage,
                            downloader,
                            endpoint,
                            lookup,
                        },
                        events,
                        operation_id,
                        offer,
                        output,
                        max_attachment_bytes,
                    )
                    .await;
                    AttachmentTaskCompletion::Operation {
                        operation_id,
                        response,
                        event: OperationEventKind::DownloadComplete,
                    }
                },
            );
        }
        Some(DaemonCommand::Execute {
            request: Request::Subscribe | Request::Stop,
            reply,
        }) => {
            let _ = reply.send(meshmsg_protocol::Response::Error(
                meshmsg_protocol::ProtocolError::new(
                    None,
                    meshmsg_protocol::ErrorCode::InvalidRequest,
                    meshmsg_protocol::Outcome::NotStarted,
                ),
            ));
        }
        Some(DaemonCommand::Stop) | None => return Ok(CommandAction::Stop),
    }
    Ok(CommandAction::Continue)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::State,
        ipc::{
            read_frame,
            server::{handle_local_client, LocalClientSession, LocalIpcTimeouts},
            write_request, MAX_IPC_EVENT_SIZE,
        },
        node::{
            bootstrap,
            common::{OPERATION_CACHE_CAPACITY, OPERATION_CACHE_TTL},
        },
    };
    use iroh::{EndpointAddr, SecretKey};
    use tokio::sync::mpsc;

    fn connected_fixture() -> meshmsg_protocol::Event {
        meshmsg_protocol::Event::Connected(meshmsg_protocol::Connected {
            peer: "2".repeat(64).parse().unwrap(),
            endpoint_online: true,
            topic_joined: true,
            alias: None,
        })
    }

    #[tokio::test]
    async fn private_send_saturation_preserves_operation_id_through_full_ipc_path() {
        let dir = std::env::temp_dir().join(format!(
            "meshmsg-command-dispatch-test-{}",
            rand::random::<u64>()
        ));
        let initial_state = State::new_topic();
        let mut initial_alias = AliasConfig::prepare(false).unwrap();
        initial_state
            .save_new_with_alias(&dir, false, &mut initial_alias)
            .unwrap();
        let (state, secret) = State::load_for_doctor(&dir).unwrap();
        let alias_config = AliasConfig::load_for_identity(&dir, secret.public()).unwrap();
        let topic = state.topic_id();
        let node = bootstrap::start(topic, None, secret, &dir).await.unwrap();
        let blob_root = dir.join("blobs-v1").join(node.secret.public().to_string());
        let attachment_storage =
            AttachmentStorage::open(node.blob_store.clone(), blob_root, &dir, 1024, 0, 0)
                .await
                .unwrap();

        let direct_sender =
            direct::DirectSender::new(node.endpoint.clone(), node.secret.clone(), topic);
        let mut held = Vec::new();
        for _ in 0..direct::SEND_CONCURRENCY {
            held.push(
                direct_sender
                    .try_reserve(meshmsg_protocol::OperationId::new_random())
                    .unwrap(),
            );
        }
        let recipient = SecretKey::generate().public();
        let mut directory = Directory::new(node.presence_lookup.clone());
        directory
            .pin(EndpointAddr::new(recipient).with_ip_addr("127.0.0.1:7777".parse().unwrap()))
            .unwrap();

        let (mut client, server) = tokio::io::duplex(4096);
        let (commands, mut command_rx) = mpsc::channel(1);
        let (events, receiver) = broadcast::channel(2);
        let client_task = tokio::spawn(handle_local_client(
            server,
            LocalClientSession {
                commands,
                events: receiver,
                connected: connected_fixture(),
                startup_peers: None,
            },
            LocalIpcTimeouts::default(),
        ));
        let operation_id = meshmsg_protocol::OperationId::new_random();
        let request = Request::PrivateSend {
            operation_id,
            to: recipient.to_string().parse().unwrap(),
            body: meshmsg_protocol::PrivateBody::new("saturated").unwrap(),
        };
        write_request(
            &mut client,
            &request,
            meshmsg_protocol::RequestId::new_random(),
        )
        .await
        .unwrap();

        let operation_cache = Arc::new(Mutex::new(OperationCache::new(
            OPERATION_CACHE_CAPACITY,
            OPERATION_CACHE_TTL,
        )));
        let offer_list_limit = Arc::new(Semaphore::new(1));
        let transfer_limit = Arc::new(Semaphore::new(2));
        let mut transfer_tasks = tokio::task::JoinSet::new();
        let mut offer_list_tasks = tokio::task::JoinSet::new();
        let mut attachment_task_metadata = HashMap::new();
        let peer = crate::ids::peer_id(node.endpoint.id());
        let action = execute(
            command_rx.recv().await,
            ExecutionContext {
                node: &node,
                state: &state,
                alias_config: &alias_config,
                has_invite: false,
                bootstrap_peer_count: 0,
                self_advertised: false,
                max_attachment_bytes: 1024,
                attachment_retention_secs: 0,
                attachment_storage: &attachment_storage,
                direct_sender: &direct_sender,
                operation_cache: &operation_cache,
                directory: &mut directory,
                event_tx: &events,
                peer,
                offer_list_limit: &offer_list_limit,
                transfer_limit: &transfer_limit,
                transfer_tasks: &mut transfer_tasks,
                offer_list_tasks: &mut offer_list_tasks,
                attachment_task_metadata: &mut attachment_task_metadata,
                dir: &dir,
                topic,
            },
        )
        .await
        .unwrap();
        assert_eq!(action, CommandAction::Continue);
        assert!(transfer_tasks.is_empty());

        let frame = read_frame(&mut client, MAX_IPC_EVENT_SIZE).await.unwrap();
        let frame: meshmsg_protocol::ResponseFrame = serde_json::from_slice(&frame).unwrap();
        assert!(request.validate_response(&frame.response).is_ok());
        let meshmsg_protocol::Response::Error(error) = frame.response else {
            panic!("expected private-send saturation error")
        };
        assert_eq!(error.code, meshmsg_protocol::ErrorCode::PrivateSendBusy);
        assert_eq!(error.outcome, meshmsg_protocol::Outcome::NotStarted);
        assert_eq!(error.operation_id.as_ref(), Some(&operation_id));

        client_task.await.unwrap().unwrap();
        drop(held);
        drop(direct_sender);
        drop(attachment_storage);
        node.router.shutdown().await.unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn prune_without_an_age_resolves_the_configured_retention_in_the_daemon() {
        use crate::node::supervisor::complete_attachment_task;

        let dir = std::env::temp_dir().join(format!(
            "meshmsg-prune-default-age-test-{}",
            rand::random::<u64>()
        ));
        let initial_state = State::new_topic();
        let mut initial_alias = AliasConfig::prepare(false).unwrap();
        initial_state
            .save_new_with_alias(&dir, false, &mut initial_alias)
            .unwrap();
        let (state, secret) = State::load_for_doctor(&dir).unwrap();
        let alias_config = AliasConfig::load_for_identity(&dir, secret.public()).unwrap();
        let topic = state.topic_id();
        let node = bootstrap::start(topic, None, secret, &dir).await.unwrap();
        let blob_root = dir.join("blobs-v1").join(node.secret.public().to_string());
        let attachment_storage =
            AttachmentStorage::open(node.blob_store.clone(), blob_root, &dir, 1024, 0, 0)
                .await
                .unwrap();
        let direct_sender =
            direct::DirectSender::new(node.endpoint.clone(), node.secret.clone(), topic);
        let mut directory = Directory::new(node.presence_lookup.clone());
        let (events, _receiver) = broadcast::channel(2);
        let operation_cache = Arc::new(Mutex::new(OperationCache::new(
            OPERATION_CACHE_CAPACITY,
            OPERATION_CACHE_TTL,
        )));
        let offer_list_limit = Arc::new(Semaphore::new(1));
        let transfer_limit = Arc::new(Semaphore::new(2));
        let mut transfer_tasks = tokio::task::JoinSet::new();
        let mut offer_list_tasks = tokio::task::JoinSet::new();
        let mut attachment_task_metadata = HashMap::new();
        let mut space_refresh_active = false;
        let peer = crate::ids::peer_id(node.endpoint.id());

        let default_age = meshmsg_protocol::OperationId::new_random();
        let disabled_retention = meshmsg_protocol::OperationId::new_random();
        // (operation, submitted age, configured retention, expected effective age)
        let cases = [
            (&default_age, None, 7, Some(7)),
            // An explicit age equal to the default is still different input.
            (&default_age, Some(7), 7, None),
            // An exact retry replays the original resolution, even if the
            // configured retention were to differ.
            (&default_age, None, 9, Some(7)),
            (&disabled_retention, None, 0, Some(0)),
        ];
        let mut first_resolution = None;
        for (operation_id, older_than_secs, attachment_retention_secs, expected_age) in cases {
            let (reply, response) = oneshot::channel();
            let before_ms = unix_timestamp_ms().unwrap();
            let action = execute(
                Some(DaemonCommand::Execute {
                    request: Request::OffersPrune {
                        operation_id: *operation_id,
                        older_than_secs,
                        direction: None,
                        dry_run: true,
                        max_delete: 1,
                    },
                    reply,
                }),
                ExecutionContext {
                    node: &node,
                    state: &state,
                    alias_config: &alias_config,
                    has_invite: false,
                    bootstrap_peer_count: 0,
                    self_advertised: false,
                    max_attachment_bytes: 1024,
                    attachment_retention_secs,
                    attachment_storage: &attachment_storage,
                    direct_sender: &direct_sender,
                    operation_cache: &operation_cache,
                    directory: &mut directory,
                    event_tx: &events,
                    peer,
                    offer_list_limit: &offer_list_limit,
                    transfer_limit: &transfer_limit,
                    transfer_tasks: &mut transfer_tasks,
                    offer_list_tasks: &mut offer_list_tasks,
                    attachment_task_metadata: &mut attachment_task_metadata,
                    dir: &dir,
                    topic,
                },
            )
            .await
            .unwrap();
            assert_eq!(action, CommandAction::Continue);
            if let Some(completed) = offer_list_tasks.join_next_with_id().await {
                complete_attachment_task(
                    completed,
                    &mut attachment_task_metadata,
                    &operation_cache,
                    &events,
                    &mut space_refresh_active,
                );
            }
            match (response.await.unwrap(), expected_age) {
                (meshmsg_protocol::Response::OffersPruned(pruned), Some(age)) => {
                    assert_eq!(pruned.operation_id, *operation_id);
                    assert_eq!(pruned.older_than_secs, age);
                    assert!(pruned.dry_run);
                    assert_eq!(pruned.maximum, 1);
                    if attachment_retention_secs == age {
                        let newest = unix_timestamp_ms().unwrap() - age * 1000;
                        assert!(
                            (before_ms - age * 1000..=newest).contains(&pruned.cutoff_ms),
                            "cutoff was not derived from the effective age"
                        );
                        first_resolution.get_or_insert(pruned);
                    } else {
                        assert_eq!(Some(&pruned), first_resolution.as_ref());
                    }
                }
                (meshmsg_protocol::Response::Error(error), None) => {
                    assert_eq!(error.code, meshmsg_protocol::ErrorCode::OperationIdConflict);
                    assert_eq!(error.operation_id.as_ref(), Some(operation_id));
                }
                (response, _) => panic!("unexpected prune response: {response:?}"),
            }
        }
        // Two admitted operations ran; the exact retry replayed the first.
        assert_eq!(operation_cache.lock().unwrap().counts(), (0, 2));

        drop(direct_sender);
        drop(attachment_storage);
        node.router.shutdown().await.unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }
}
