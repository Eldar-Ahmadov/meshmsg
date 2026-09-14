//! Typed daemon commands and their execution policy.

use super::{
    bootstrap::RunningNode,
    common::{
        unix_timestamp_ms, unix_timestamp_ms_saturating, OPERATION_CACHE_CAPACITY,
        OPERATION_CACHE_TTL,
    },
    operation_cache::OperationCache,
    supervisor::{
        spawn_attachment_task, AttachmentTaskCompletion, AttachmentTaskMetadata, OperationEventKind,
    },
};
use crate::{
    alias::AliasConfig,
    attachment::runtime::*,
    config::State,
    contracts, direct, gossip,
    ipc::IpcRequest,
    presence::{self, Directory},
};
use anyhow::Result;
use iroh_gossip::proto::TopicId;
use std::{
    collections::HashMap,
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant as StdInstant, SystemTime},
};
use tokio::sync::{broadcast, oneshot, Semaphore};

pub(crate) enum DaemonCommand {
    Execute {
        request: ExecutableRequest,
        reply: oneshot::Sender<meshmsg_protocol::Response>,
    },
    Stop,
}

pub(crate) enum ExecutableRequest {
    Protocol(meshmsg_protocol::Request),
    Download {
        operation_id: meshmsg_protocol::OperationId,
        offer: meshmsg_protocol::AttachmentToken,
        output: std::path::PathBuf,
        mode: meshmsg_protocol::DownloadMode,
    },
}

impl TryFrom<meshmsg_protocol::Request> for ExecutableRequest {
    type Error = meshmsg_protocol::TextError;

    fn try_from(request: meshmsg_protocol::Request) -> Result<Self, Self::Error> {
        match request {
            meshmsg_protocol::Request::Download {
                operation_id,
                offer,
                output,
                mode,
            } => Ok(Self::Download {
                operation_id,
                offer: meshmsg_protocol::AttachmentToken::new(offer)?,
                output,
                mode,
            }),
            request => Ok(Self::Protocol(request)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CommandPolicy {
    pub(crate) deadline: Duration,
    pub(crate) timeout_code: meshmsg_protocol::ErrorCode,
    pub(crate) unavailable_code: meshmsg_protocol::ErrorCode,
}

#[derive(Clone, Copy)]
pub(crate) struct CommandTimeouts {
    pub(crate) ordinary: Duration,
    pub(crate) private: Duration,
    pub(crate) list: Duration,
    pub(crate) transfer: Duration,
}

impl CommandPolicy {
    pub(crate) fn for_request(
        request: &meshmsg_protocol::Request,
        timeouts: CommandTimeouts,
    ) -> Option<Self> {
        use meshmsg_protocol::{ErrorCode, Request};

        let (deadline, timeout_code, unavailable_code) = match request {
            Request::Send { .. } | Request::Status | Request::Peers => (
                timeouts.ordinary,
                ErrorCode::CommandTimeout,
                ErrorCode::DaemonStopping,
            ),
            Request::PrivateSend { .. } => (
                timeouts.private,
                ErrorCode::CommandTimeout,
                ErrorCode::DaemonStopping,
            ),
            Request::Offers => (
                timeouts.list,
                ErrorCode::CommandTimeout,
                ErrorCode::DaemonStopping,
            ),
            Request::OffersRemove { .. } | Request::OffersPrune { .. } => (
                timeouts.list,
                ErrorCode::AttachmentCommandTimeout,
                ErrorCode::AttachmentStorageShutdown,
            ),
            Request::Share { .. } | Request::Download { .. } => (
                timeouts.transfer,
                ErrorCode::AttachmentCommandTimeout,
                ErrorCode::AttachmentStorageShutdown,
            ),
            Request::Subscribe | Request::Stop => return None,
        };
        Some(Self {
            deadline,
            timeout_code,
            unavailable_code,
        })
    }
}

pub(crate) fn request_operation_id(
    request: &meshmsg_protocol::Request,
) -> Option<meshmsg_protocol::OperationId> {
    use meshmsg_protocol::Request;
    match request {
        Request::Send { operation_id, .. }
        | Request::PrivateSend { operation_id, .. }
        | Request::OffersRemove { operation_id, .. }
        | Request::OffersPrune { operation_id, .. }
        | Request::Share { operation_id, .. }
        | Request::Download { operation_id, .. } => Some(operation_id.clone()),
        Request::Subscribe | Request::Status | Request::Peers | Request::Offers | Request::Stop => {
            None
        }
    }
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
    pub(super) directory_epoch: &'a str,
    pub(super) directory_revision: &'a mut u64,
    pub(super) peer: &'a str,
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

fn direction_text(direction: meshmsg_protocol::OfferDirection) -> &'static str {
    match direction {
        meshmsg_protocol::OfferDirection::Incoming => "incoming",
        meshmsg_protocol::OfferDirection::Outgoing => "outgoing",
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
        directory_epoch,
        directory_revision,
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
            request: ExecutableRequest::Protocol(IpcRequest::Send { operation_id, body }),
            reply,
        }) => {
            let fingerprint = operation_fingerprint("send", &[body.as_bytes()]);
            if !operation_cache
                .lock()
                .expect("operation cache poisoned")
                .admit(operation_id.clone(), fingerprint, reply, StdInstant::now())
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
                            operation_id.to_bytes(),
                            body.into_string(),
                            timestamp_ms,
                        )),
                        Err(_error) => contracts::protocol_error_response(
                            meshmsg_protocol::ErrorCode::SendFailed,
                            meshmsg_protocol::Outcome::Unknown,
                            Some(operation_id.clone()),
                        ),
                    },
                    Err(_error) => contracts::protocol_error_response(
                        meshmsg_protocol::ErrorCode::InvalidMessage,
                        meshmsg_protocol::Outcome::NotStarted,
                        Some(operation_id.clone()),
                    ),
                },
                Err(_error) => contracts::protocol_error_response(
                    meshmsg_protocol::ErrorCode::InvalidMessage,
                    meshmsg_protocol::Outcome::NotStarted,
                    Some(operation_id.clone()),
                ),
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
                ExecutableRequest::Protocol(IpcRequest::PrivateSend {
                    operation_id,
                    to,
                    body,
                }),
            reply,
        }) => {
            let fingerprint =
                operation_fingerprint("private_send", &[to.as_str().as_bytes(), body.as_bytes()]);
            if !operation_cache
                .lock()
                .expect("operation cache poisoned")
                .admit(operation_id.clone(), fingerprint, reply, StdInstant::now())
            {
                return Ok(CommandAction::Continue);
            }
            presence::emit_transitions(
                directory.cleanup(),
                event_tx,
                directory_epoch,
                directory_revision,
            );
            let address = match directory.resolve(to.as_str()) {
                Ok(address) => address,
                Err(_error) => {
                    operation_cache
                        .lock()
                        .expect("operation cache poisoned")
                        .complete(
                            &operation_id,
                            contracts::protocol_error_response(
                                meshmsg_protocol::ErrorCode::RecipientUnresolved,
                                meshmsg_protocol::Outcome::NotStarted,
                                Some(operation_id.clone()),
                            ),
                            StdInstant::now(),
                        );
                    return Ok(CommandAction::Continue);
                }
            };
            let permit = match direct_sender.try_reserve(operation_id.clone()) {
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
            let task_operation_id = operation_id.clone();
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
                    let response = permit
                        .send(address, body.into_string(), task_operation_id.to_bytes())
                        .await;
                    AttachmentTaskCompletion::Operation {
                        operation_id: task_operation_id,
                        response,
                        event: OperationEventKind::None,
                    }
                },
            );
        }
        Some(DaemonCommand::Execute {
            request: ExecutableRequest::Protocol(IpcRequest::Status),
            reply,
        }) => {
            let connectivity = presence::local_connectivity(&node.endpoint, &node.receiver);
            let neighbors = node.receiver.neighbors().count();
            let replay_status = direct::replay_status(&node.direct_replay);
            let status = meshmsg_protocol::Status {
                running: true,
                peer: peer.parse()?,
                topic: state.topic.parse()?,
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
                operation_cache_capacity: OPERATION_CACHE_CAPACITY,
                operation_cache_ttl_ms: OPERATION_CACHE_TTL.as_millis() as u64,
                operation_cache_persistent: false,
                direct_replay_available: replay_status.available,
                direct_replay_error: replay_status.error,
                direct_replay_capacity: replay_status.capacity,
                direct_replay_per_sender_capacity: replay_status.per_sender_capacity,
                direct_replay_queue_capacity: replay_status.queue_capacity,
                direct_replay_global_rate_per_second: replay_status.global_rate_per_second,
                direct_replay_global_rate_burst: replay_status.global_rate_burst,
                direct_replay_sender_rate_per_second: replay_status.sender_rate_per_second,
                direct_replay_sender_rate_burst: replay_status.sender_rate_burst,
                max_attachment_bytes,
                attachment_storage: attachment_storage.status(),
                attachment_retention_secs,
            };
            status.validate().map_err(anyhow::Error::msg)?;
            let _ = reply.send(meshmsg_protocol::Response::Status(status));
        }
        Some(DaemonCommand::Execute {
            request: ExecutableRequest::Protocol(IpcRequest::Peers),
            reply,
        }) => {
            presence::emit_transitions(
                directory.cleanup(),
                event_tx,
                directory_epoch,
                directory_revision,
            );
            let generated_at_ms = unix_timestamp_ms()?;
            let _ = reply.send(meshmsg_protocol::Response::PeersSnapshot(
                presence::snapshot(
                    (&node.endpoint, &node.receiver),
                    directory,
                    peer,
                    alias_config.effective(),
                    generated_at_ms,
                    directory_epoch,
                    *directory_revision,
                ),
            ));
        }
        Some(DaemonCommand::Execute {
            request: ExecutableRequest::Protocol(IpcRequest::Offers),
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
                ExecutableRequest::Protocol(IpcRequest::OffersRemove {
                    operation_id,
                    offer_id,
                    direction,
                    provider,
                }),
            reply,
        }) => {
            let direction_fingerprint = optional_text_fingerprint(direction.map(direction_text));
            let provider_fingerprint =
                optional_text_fingerprint(provider.as_ref().map(|value| value.as_str()));
            let fingerprint = operation_fingerprint(
                "offers_remove",
                &[
                    offer_id.as_str().as_bytes(),
                    &direction_fingerprint,
                    &provider_fingerprint,
                ],
            );
            if !operation_cache
                .lock()
                .expect("operation cache poisoned")
                .admit(operation_id.clone(), fingerprint, reply, StdInstant::now())
            {
                return Ok(CommandAction::Continue);
            }
            let storage = attachment_storage.clone();
            let task_operation_id = operation_id.clone();
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
                        &task_operation_id,
                        &offer_id,
                        direction,
                        provider.as_ref(),
                    )
                    .await;
                    AttachmentTaskCompletion::Operation {
                        operation_id: task_operation_id,
                        response,
                        event: OperationEventKind::None,
                    }
                },
            );
        }
        Some(DaemonCommand::Execute {
            request:
                ExecutableRequest::Protocol(IpcRequest::OffersPrune {
                    operation_id,
                    older_than_secs,
                    direction,
                    dry_run,
                    max_delete,
                }),
            reply,
        }) => {
            let age_fingerprint = older_than_secs.to_le_bytes();
            let direction_fingerprint = optional_text_fingerprint(direction.map(direction_text));
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
                .admit(operation_id.clone(), fingerprint, reply, StdInstant::now())
            {
                return Ok(CommandAction::Continue);
            }
            let resolution = operation_cache
                .lock()
                .expect("operation cache poisoned")
                .resolve_prune(
                    &operation_id,
                    older_than_secs,
                    unix_timestamp_ms_saturating(SystemTime::now()),
                );
            let age = resolution.older_than_secs;
            let cutoff = resolution.cutoff_ms;
            let storage = attachment_storage.clone();
            let task_operation_id = operation_id.clone();
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
                        &task_operation_id,
                        age,
                        cutoff,
                        direction,
                        dry_run,
                        max_delete,
                    )
                    .await;
                    AttachmentTaskCompletion::Operation {
                        operation_id: task_operation_id,
                        response,
                        event: OperationEventKind::None,
                    }
                },
            );
        }
        Some(DaemonCommand::Execute {
            request:
                ExecutableRequest::Protocol(IpcRequest::Share {
                    operation_id,
                    source_digest,
                    path,
                }),
            reply,
        }) => {
            let fingerprint = operation_fingerprint(
                "share",
                &[
                    path.as_os_str().as_encoded_bytes(),
                    source_digest.as_bytes(),
                ],
            );
            if !operation_cache
                .lock()
                .expect("operation cache poisoned")
                .admit(operation_id.clone(), fingerprint, reply, StdInstant::now())
            {
                return Ok(CommandAction::Continue);
            }
            let permit = match try_admit_transfer(
                transfer_limit,
                "share_busy",
                "attachment transfer capacity reached",
            ) {
                Ok(permit) => permit,
                Err(_) => {
                    let error = meshmsg_protocol::ProtocolError::new(
                        Some(operation_id.clone()),
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
            let task_operation_id = operation_id.clone();
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
                        task_operation_id.clone(),
                        source_digest,
                        path,
                        max_attachment_bytes,
                    )
                    .await;
                    AttachmentTaskCompletion::Operation {
                        operation_id: task_operation_id,
                        response,
                        event: OperationEventKind::AttachmentShared,
                    }
                },
            );
        }
        Some(DaemonCommand::Execute {
            request:
                ExecutableRequest::Download {
                    operation_id,
                    offer,
                    output,
                    mode,
                },
            reply,
        }) => {
            let mode_name = match mode {
                meshmsg_protocol::DownloadMode::Install => "install",
            };
            let fingerprint = operation_fingerprint(
                "download",
                &[
                    offer.as_str().as_bytes(),
                    output.as_os_str().as_encoded_bytes(),
                    mode_name.as_bytes(),
                ],
            );
            if !operation_cache
                .lock()
                .expect("operation cache poisoned")
                .admit(operation_id.clone(), fingerprint, reply, StdInstant::now())
            {
                return Ok(CommandAction::Continue);
            }
            let permit = match try_admit_transfer(
                transfer_limit,
                "download_busy",
                "attachment transfer capacity reached",
            ) {
                Ok(permit) => permit,
                Err(_) => {
                    let error = meshmsg_protocol::ProtocolError::new(
                        Some(operation_id.clone()),
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
            let task_operation_id = operation_id.clone();
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
                            topic,
                            downloader,
                            endpoint,
                            lookup,
                        },
                        events,
                        task_operation_id.clone(),
                        offer,
                        output,
                        max_attachment_bytes,
                        mode,
                    )
                    .await;
                    AttachmentTaskCompletion::Operation {
                        operation_id: task_operation_id,
                        response,
                        event: OperationEventKind::DownloadComplete,
                    }
                },
            );
        }
        Some(DaemonCommand::Execute {
            request:
                ExecutableRequest::Protocol(
                    IpcRequest::Subscribe | IpcRequest::Stop | IpcRequest::Download { .. },
                ),
            reply,
        }) => {
            let _ = reply.send(contracts::protocol_error_response(
                meshmsg_protocol::ErrorCode::InvalidRequest,
                meshmsg_protocol::Outcome::NotStarted,
                None,
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
        ipc::{read_frame, server::handle_local_client, write_request, MAX_IPC_EVENT_SIZE},
        node::bootstrap,
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
        let topic = state.topic_id().unwrap();
        let mut node = bootstrap::start(&state, secret, &dir).await.unwrap();
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
            commands,
            receiver,
            connected_fixture(),
            None,
        ));
        let operation_id = meshmsg_protocol::OperationId::new_random();
        let request = IpcRequest::PrivateSend {
            operation_id: operation_id.clone(),
            to: recipient.to_string().parse().unwrap(),
            body: meshmsg_protocol::PrivateBody::new("saturated").unwrap(),
        };
        write_request(&mut client, &request).await.unwrap();

        let operation_cache = Arc::new(Mutex::new(OperationCache::new(
            OPERATION_CACHE_CAPACITY,
            OPERATION_CACHE_TTL,
        )));
        let offer_list_limit = Arc::new(Semaphore::new(1));
        let transfer_limit = Arc::new(Semaphore::new(2));
        let mut transfer_tasks = tokio::task::JoinSet::new();
        let mut offer_list_tasks = tokio::task::JoinSet::new();
        let mut attachment_task_metadata = HashMap::new();
        let mut directory_revision = 0;
        let peer = node.endpoint.id().to_string();
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
                directory_epoch: "command-dispatch-test-epoch",
                directory_revision: &mut directory_revision,
                peer: &peer,
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
        node.direct_replay.shutdown().await.unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn download_is_typed_once_when_it_becomes_executable() {
        let operation_id = meshmsg_protocol::OperationId::new_random();
        let output = std::env::temp_dir().join("meshmsg-typed-download");
        let executable = ExecutableRequest::try_from(IpcRequest::Download {
            operation_id: operation_id.clone(),
            offer: String::from("typed-on-admission"),
            output: output.clone(),
            mode: meshmsg_protocol::DownloadMode::Install,
        })
        .unwrap();
        let ExecutableRequest::Download {
            operation_id: actual_id,
            offer,
            output: actual_output,
            mode,
        } = executable
        else {
            panic!("download did not become a typed executable request")
        };
        assert_eq!(actual_id, operation_id);
        assert_eq!(offer.as_str(), "typed-on-admission");
        assert_eq!(actual_output, output);
        assert_eq!(mode, meshmsg_protocol::DownloadMode::Install);
    }

    #[test]
    fn command_policy_covers_each_request_family_and_preserves_correlation() {
        use meshmsg_protocol::{ErrorCode, OfferDirection, Request};

        let timeouts = CommandTimeouts {
            ordinary: Duration::from_millis(40),
            private: Duration::from_millis(60),
            list: Duration::from_millis(70),
            transfer: Duration::from_millis(80),
        };
        let operation_id = meshmsg_protocol::OperationId::new_random();
        let requests = [
            (
                Request::Send {
                    operation_id: operation_id.clone(),
                    body: meshmsg_protocol::BroadcastBody::new("broadcast").unwrap(),
                },
                timeouts.ordinary,
                ErrorCode::CommandTimeout,
                ErrorCode::DaemonStopping,
            ),
            (
                Request::PrivateSend {
                    operation_id: operation_id.clone(),
                    to: "peer".parse().unwrap(),
                    body: meshmsg_protocol::PrivateBody::new("private").unwrap(),
                },
                timeouts.private,
                ErrorCode::CommandTimeout,
                ErrorCode::DaemonStopping,
            ),
            (
                Request::Status,
                timeouts.ordinary,
                ErrorCode::CommandTimeout,
                ErrorCode::DaemonStopping,
            ),
            (
                Request::Peers,
                timeouts.ordinary,
                ErrorCode::CommandTimeout,
                ErrorCode::DaemonStopping,
            ),
            (
                Request::Offers,
                timeouts.list,
                ErrorCode::CommandTimeout,
                ErrorCode::DaemonStopping,
            ),
            (
                Request::OffersRemove {
                    operation_id: operation_id.clone(),
                    offer_id: meshmsg_protocol::OfferId::new_random(),
                    direction: Some(OfferDirection::Incoming),
                    provider: Some(meshmsg_protocol::PeerId::new_random()),
                },
                timeouts.list,
                ErrorCode::AttachmentCommandTimeout,
                ErrorCode::AttachmentStorageShutdown,
            ),
            (
                Request::OffersPrune {
                    operation_id: operation_id.clone(),
                    older_than_secs: 7,
                    direction: Some(OfferDirection::Outgoing),
                    dry_run: true,
                    max_delete: 3,
                },
                timeouts.list,
                ErrorCode::AttachmentCommandTimeout,
                ErrorCode::AttachmentStorageShutdown,
            ),
            (
                Request::Share {
                    operation_id: operation_id.clone(),
                    source_digest: meshmsg_protocol::ContentDigest::new_random(),
                    path: std::env::temp_dir().join("meshmsg-policy-share"),
                },
                timeouts.transfer,
                ErrorCode::AttachmentCommandTimeout,
                ErrorCode::AttachmentStorageShutdown,
            ),
            (
                Request::Download {
                    operation_id: operation_id.clone(),
                    offer: "typed-token".into(),
                    output: std::env::temp_dir().join("meshmsg-policy-download"),
                    mode: meshmsg_protocol::DownloadMode::Install,
                },
                timeouts.transfer,
                ErrorCode::AttachmentCommandTimeout,
                ErrorCode::AttachmentStorageShutdown,
            ),
        ];

        for (request, deadline, timeout_code, unavailable_code) in requests {
            let policy = CommandPolicy::for_request(&request, timeouts).unwrap();
            assert_eq!(policy.deadline, deadline);
            assert_eq!(policy.timeout_code, timeout_code);
            assert_eq!(policy.unavailable_code, unavailable_code);
            assert_eq!(
                request_operation_id(&request).as_ref(),
                matches!(
                    request,
                    Request::Send { .. }
                        | Request::PrivateSend { .. }
                        | Request::OffersRemove { .. }
                        | Request::OffersPrune { .. }
                        | Request::Share { .. }
                        | Request::Download { .. }
                )
                .then_some(&operation_id)
            );
        }
        assert!(CommandPolicy::for_request(&Request::Subscribe, timeouts).is_none());
        assert!(CommandPolicy::for_request(&Request::Stop, timeouts).is_none());
    }
}
