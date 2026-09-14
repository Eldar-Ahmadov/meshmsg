//! Supervision for daemon-owned attachment background tasks.

use super::operation_cache::OperationCache;
use crate::contracts;
use anyhow::Result;
use std::{
    collections::HashMap,
    future::Future,
    sync::{Arc, Mutex},
    time::Instant as StdInstant,
};
use tokio::sync::{broadcast, oneshot};

pub(super) enum OperationEventKind {
    None,
    AttachmentShared,
    DownloadComplete,
}

pub(super) enum AttachmentTaskCompletion {
    Operation {
        operation_id: meshmsg_protocol::OperationId,
        response: meshmsg_protocol::Response,
        event: OperationEventKind,
    },
    OfferList {
        reply: oneshot::Sender<meshmsg_protocol::Response>,
        response: meshmsg_protocol::Response,
    },
    SpaceRefresh(Result<()>),
    Retention(Result<Option<meshmsg_protocol::Response>>),
}

pub(super) struct AttachmentTaskMetadata {
    pub(super) kind: &'static str,
    pub(super) unexpected_operation:
        Option<(meshmsg_protocol::OperationId, meshmsg_protocol::ErrorCode)>,
    pub(super) space_refresh: bool,
}

pub(super) fn spawn_attachment_task<F>(
    tasks: &mut tokio::task::JoinSet<AttachmentTaskCompletion>,
    metadata: &mut HashMap<tokio::task::Id, AttachmentTaskMetadata>,
    task_metadata: AttachmentTaskMetadata,
    task: F,
) -> tokio::task::AbortHandle
where
    F: Future<Output = AttachmentTaskCompletion> + Send + 'static,
{
    let handle = tasks.spawn(task);
    metadata.insert(handle.id(), task_metadata);
    handle
}

pub(super) fn try_spawn_attachment_space_refresh<F>(
    active: &mut bool,
    tasks: &mut tokio::task::JoinSet<AttachmentTaskCompletion>,
    metadata: &mut HashMap<tokio::task::Id, AttachmentTaskMetadata>,
    task: F,
) -> bool
where
    F: Future<Output = Result<()>> + Send + 'static,
{
    if *active {
        return false;
    }
    *active = true;
    spawn_attachment_task(
        tasks,
        metadata,
        AttachmentTaskMetadata {
            kind: "attachment free-space refresh",
            unexpected_operation: None,
            space_refresh: true,
        },
        async move { AttachmentTaskCompletion::SpaceRefresh(task.await) },
    );
    true
}

pub(super) fn complete_attachment_task(
    completed: Result<(tokio::task::Id, AttachmentTaskCompletion), tokio::task::JoinError>,
    metadata: &mut HashMap<tokio::task::Id, AttachmentTaskMetadata>,
    operation_cache: &Arc<Mutex<OperationCache>>,
    events: &broadcast::Sender<meshmsg_protocol::Event>,
    space_refresh_active: &mut bool,
) {
    let task_id = match &completed {
        Ok((task_id, _)) => *task_id,
        Err(error) => error.id(),
    };
    let Some(task_metadata) = metadata.remove(&task_id) else {
        eprintln!("untracked background attachment task {task_id} completed");
        return;
    };
    if task_metadata.space_refresh {
        *space_refresh_active = false;
    }

    match completed {
        Ok((
            _,
            AttachmentTaskCompletion::Operation {
                operation_id,
                response,
                event,
            },
        )) => {
            let response = operation_cache
                .lock()
                .expect("operation cache poisoned")
                .complete(&operation_id, response, StdInstant::now());
            let event = match (event, response) {
                (
                    OperationEventKind::AttachmentShared,
                    meshmsg_protocol::Response::AttachmentShared(value),
                ) => Some(meshmsg_protocol::Event::AttachmentShared(value)),
                (
                    OperationEventKind::DownloadComplete,
                    meshmsg_protocol::Response::DownloadComplete(value),
                ) => Some(meshmsg_protocol::Event::DownloadComplete(value)),
                _ => None,
            };
            if let Some(event) = event {
                let _ = events.send(event);
            }
        }
        Ok((_, AttachmentTaskCompletion::OfferList { reply, response })) => {
            let _ = reply.send(response);
        }
        Ok((_, AttachmentTaskCompletion::SpaceRefresh(Err(error)))) => {
            eprintln!("{} failed: {error:#}", task_metadata.kind);
        }
        Ok((_, AttachmentTaskCompletion::Retention(Err(error)))) => {
            eprintln!("{} failed: {error:#}", task_metadata.kind);
        }
        Ok((
            _,
            AttachmentTaskCompletion::Retention(Ok(Some(meshmsg_protocol::Response::Error(error)))),
        )) => {
            eprintln!(
                "{} completed with {} ({:?})",
                task_metadata.kind,
                error.code.message(),
                error.outcome
            );
        }
        Ok((
            _,
            AttachmentTaskCompletion::SpaceRefresh(Ok(()))
            | AttachmentTaskCompletion::Retention(Ok(_)),
        )) => {}
        Err(error) => {
            eprintln!("{} exited unexpectedly: {error}", task_metadata.kind);
            if let Some((operation_id, code)) = task_metadata.unexpected_operation {
                let response = contracts::protocol_error_response(
                    code,
                    meshmsg_protocol::Outcome::Unknown,
                    Some(operation_id.clone()),
                );
                operation_cache
                    .lock()
                    .expect("operation cache poisoned")
                    .complete(&operation_id, response, StdInstant::now());
            }
        }
    }
}

pub(super) async fn abort_and_drain_attachment_tasks(
    transfer_tasks: &mut tokio::task::JoinSet<AttachmentTaskCompletion>,
    offer_list_tasks: &mut tokio::task::JoinSet<AttachmentTaskCompletion>,
    metadata: &mut HashMap<tokio::task::Id, AttachmentTaskMetadata>,
    operation_cache: &Arc<Mutex<OperationCache>>,
    events: &broadcast::Sender<meshmsg_protocol::Event>,
    space_refresh_active: &mut bool,
) {
    // Abort both classes before draining either so shutdown does not allow the
    // second class to continue while the first is being supervised.
    transfer_tasks.abort_all();
    offer_list_tasks.abort_all();
    while let Some(completed) = transfer_tasks.join_next_with_id().await {
        complete_attachment_task(
            completed,
            metadata,
            operation_cache,
            events,
            space_refresh_active,
        );
    }
    while let Some(completed) = offer_list_tasks.join_next_with_id().await {
        complete_attachment_task(
            completed,
            metadata,
            operation_cache,
            events,
            space_refresh_active,
        );
    }
    if !metadata.is_empty() {
        eprintln!(
            "{} background attachment task metadata entries remained after shutdown drain",
            metadata.len()
        );
        for (_, task_metadata) in metadata.drain() {
            if task_metadata.space_refresh {
                *space_refresh_active = false;
            }
            if let Some((operation_id, code)) = task_metadata.unexpected_operation {
                let response = contracts::protocol_error_response(
                    code,
                    meshmsg_protocol::Outcome::Unknown,
                    Some(operation_id.clone()),
                );
                operation_cache
                    .lock()
                    .expect("operation cache poisoned")
                    .complete(&operation_id, response, StdInstant::now());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ipc::{
            read_frame, server::handle_local_client, write_request, IpcRequest, MAX_IPC_EVENT_SIZE,
        },
        node::{commands::operation_fingerprint, DaemonCommand, ExecutableRequest},
    };
    use iroh::SecretKey;
    use std::{sync::atomic::Ordering, time::Duration};
    use tokio::sync::mpsc;

    fn connected_fixture() -> meshmsg_protocol::Event {
        meshmsg_protocol::Event::Connected(meshmsg_protocol::Connected {
            peer: "2".repeat(64).parse().unwrap(),
            endpoint_online: true,
            topic_joined: true,
            alias: None,
        })
    }

    fn response_error(response: &meshmsg_protocol::Response) -> &meshmsg_protocol::ProtocolError {
        match response {
            meshmsg_protocol::Response::Error(error) => error,
            _ => panic!("expected protocol error"),
        }
    }

    #[tokio::test]
    async fn panicked_attachment_task_completes_operation_with_terminal_unknown_error() {
        let operation_id = meshmsg_protocol::OperationId::new_random();
        let fingerprint = operation_fingerprint("share", &[b"panic"]);
        let cache = Arc::new(Mutex::new(OperationCache::new(4, Duration::from_secs(10))));
        let (reply, response) = oneshot::channel();
        assert!(cache.lock().unwrap().admit(
            operation_id.clone(),
            fingerprint,
            reply,
            StdInstant::now(),
        ));
        let (events, _) = broadcast::channel(1);
        let mut tasks = tokio::task::JoinSet::new();
        let mut metadata = HashMap::new();
        let mut refresh_active = false;
        spawn_attachment_task(
            &mut tasks,
            &mut metadata,
            AttachmentTaskMetadata {
                kind: "panicking test attachment share",
                unexpected_operation: Some((
                    operation_id.clone(),
                    meshmsg_protocol::ErrorCode::ShareFailed,
                )),
                space_refresh: false,
            },
            async move {
                panic!("injected attachment task panic");
                #[allow(unreachable_code)]
                AttachmentTaskCompletion::SpaceRefresh(Ok(()))
            },
        );

        complete_attachment_task(
            tasks.join_next_with_id().await.unwrap(),
            &mut metadata,
            &cache,
            &events,
            &mut refresh_active,
        );
        let response = response
            .await
            .expect("operation waiter received terminal result");
        let error = response_error(&response);
        assert_eq!(error.code, meshmsg_protocol::ErrorCode::ShareFailed);
        assert_eq!(error.outcome, meshmsg_protocol::Outcome::Unknown);
        assert_eq!(error.operation_id.as_ref(), Some(&operation_id));

        let (retry, retry_response) = oneshot::channel();
        assert!(!cache.lock().unwrap().admit(
            operation_id.clone(),
            fingerprint,
            retry,
            StdInstant::now(),
        ));
        assert_eq!(retry_response.await.unwrap(), response);
        assert!(metadata.is_empty());
    }

    #[tokio::test]
    async fn cancelled_attachment_task_also_completes_operation() {
        let operation_id = meshmsg_protocol::OperationId::new_random();
        let cache = Arc::new(Mutex::new(OperationCache::new(2, Duration::from_secs(10))));
        let (reply, response) = oneshot::channel();
        assert!(cache.lock().unwrap().admit(
            operation_id.clone(),
            operation_fingerprint("download", &[b"cancel"]),
            reply,
            StdInstant::now(),
        ));
        let (events, _) = broadcast::channel(1);
        let mut tasks = tokio::task::JoinSet::new();
        let mut metadata = HashMap::new();
        let mut refresh_active = false;
        let handle = spawn_attachment_task(
            &mut tasks,
            &mut metadata,
            AttachmentTaskMetadata {
                kind: "cancelled test attachment download",
                unexpected_operation: Some((
                    operation_id.clone(),
                    meshmsg_protocol::ErrorCode::DownloadFailed,
                )),
                space_refresh: false,
            },
            std::future::pending::<AttachmentTaskCompletion>(),
        );
        handle.abort();

        complete_attachment_task(
            tasks.join_next_with_id().await.unwrap(),
            &mut metadata,
            &cache,
            &events,
            &mut refresh_active,
        );
        let response = response
            .await
            .expect("cancelled operation received terminal result");
        let error = response_error(&response);
        assert_eq!(error.code, meshmsg_protocol::ErrorCode::DownloadFailed);
        assert_eq!(error.outcome, meshmsg_protocol::Outcome::Unknown);
        assert_eq!(error.operation_id.as_ref(), Some(&operation_id));
    }

    #[tokio::test]
    async fn shutdown_of_admitted_operation_returns_correlated_terminal_and_completes_cache() {
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
            to: SecretKey::generate().public().to_string().parse().unwrap(),
            body: meshmsg_protocol::PrivateBody::new("shutdown in flight").unwrap(),
        };
        write_request(&mut client, &request).await.unwrap();
        let DaemonCommand::Execute {
            request:
                ExecutableRequest::Protocol(IpcRequest::PrivateSend {
                    operation_id: command_operation_id,
                    to,
                    body,
                }),
            reply,
        } = command_rx.recv().await.unwrap()
        else {
            panic!("expected private-send command")
        };
        let fingerprint =
            operation_fingerprint("private_send", &[to.as_str().as_bytes(), body.as_bytes()]);
        let cache = Arc::new(Mutex::new(OperationCache::new(4, Duration::from_secs(10))));
        assert!(cache.lock().unwrap().admit(
            command_operation_id.clone(),
            fingerprint,
            reply,
            StdInstant::now(),
        ));

        let mut transfer_tasks = tokio::task::JoinSet::new();
        let mut offer_list_tasks = tokio::task::JoinSet::new();
        let mut metadata = HashMap::new();
        let mut refresh_active = false;
        spawn_attachment_task(
            &mut transfer_tasks,
            &mut metadata,
            AttachmentTaskMetadata {
                kind: "shutdown test private send",
                unexpected_operation: Some((
                    command_operation_id.clone(),
                    meshmsg_protocol::ErrorCode::PrivateSendFailed,
                )),
                space_refresh: false,
            },
            std::future::pending::<AttachmentTaskCompletion>(),
        );
        abort_and_drain_attachment_tasks(
            &mut transfer_tasks,
            &mut offer_list_tasks,
            &mut metadata,
            &cache,
            &events,
            &mut refresh_active,
        )
        .await;

        let frame = read_frame(&mut client, MAX_IPC_EVENT_SIZE).await.unwrap();
        let frame: meshmsg_protocol::ResponseFrame = serde_json::from_slice(&frame).unwrap();
        let meshmsg_protocol::Response::Error(error) = &frame.response else {
            panic!("expected supervised shutdown error")
        };
        assert_eq!(error.code, meshmsg_protocol::ErrorCode::PrivateSendFailed);
        assert_eq!(error.outcome, meshmsg_protocol::Outcome::Unknown);
        assert_eq!(error.operation_id.as_ref(), Some(&operation_id));
        crate::ipc::validate_error_for_request(error, &request).unwrap();
        client_task.await.unwrap().unwrap();

        let (retry, retry_response) = oneshot::channel();
        assert!(!cache.lock().unwrap().admit(
            operation_id.clone(),
            fingerprint,
            retry,
            StdInstant::now(),
        ));
        assert_eq!(retry_response.await.unwrap(), frame.response);
        let cache = cache.lock().unwrap();
        assert_eq!(cache.counts(), (0, 1));
        assert!(metadata.is_empty());
    }

    #[tokio::test]
    async fn attachment_space_refresh_never_overlaps_and_reopens_after_completion() {
        let cache = Arc::new(Mutex::new(OperationCache::new(1, Duration::from_secs(10))));
        let (events, _) = broadcast::channel(1);
        let mut tasks = tokio::task::JoinSet::new();
        let mut metadata = HashMap::new();
        let mut active = false;
        let (release, wait) = oneshot::channel();
        let running = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let first_running = running.clone();
        assert!(try_spawn_attachment_space_refresh(
            &mut active,
            &mut tasks,
            &mut metadata,
            async move {
                first_running.fetch_add(1, Ordering::SeqCst);
                wait.await.unwrap();
                first_running.fetch_sub(1, Ordering::SeqCst);
                Ok(())
            },
        ));
        assert!(!try_spawn_attachment_space_refresh(
            &mut active,
            &mut tasks,
            &mut metadata,
            async { panic!("overlapping refresh was spawned") },
        ));
        tokio::task::yield_now().await;
        assert_eq!(running.load(Ordering::SeqCst), 1);
        assert_eq!(tasks.len(), 1);
        assert_eq!(metadata.len(), 1);

        release.send(()).unwrap();
        complete_attachment_task(
            tasks.join_next_with_id().await.unwrap(),
            &mut metadata,
            &cache,
            &events,
            &mut active,
        );
        assert!(!active);
        assert_eq!(running.load(Ordering::SeqCst), 0);
        assert!(try_spawn_attachment_space_refresh(
            &mut active,
            &mut tasks,
            &mut metadata,
            async { Ok(()) },
        ));
        complete_attachment_task(
            tasks.join_next_with_id().await.unwrap(),
            &mut metadata,
            &cache,
            &events,
            &mut active,
        );
        assert!(!active);
        assert!(metadata.is_empty());
    }
}
