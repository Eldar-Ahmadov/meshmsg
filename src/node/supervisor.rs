//! Supervision for daemon-owned background tasks.

use super::operation_cache::OperationCache;
use anyhow::Result;
use std::{collections::HashMap, future::Future};
use tokio::{
    sync::{broadcast, oneshot},
    task::{Id, JoinError, JoinSet},
};

pub(super) enum TaskOutput {
    Operation {
        operation_id: meshmsg_protocol::OperationId,
        response: meshmsg_protocol::Response,
    },
    OfferList {
        reply: oneshot::Sender<meshmsg_protocol::Response>,
        response: meshmsg_protocol::Response,
    },
    SpaceRefresh(Result<()>),
    Retention(Result<Option<meshmsg_protocol::Response>>),
}

pub(super) type JoinedTask = Result<(Id, TaskOutput), JoinError>;

struct TaskMetadata {
    kind: &'static str,
    /// The operation this task owns, and the code that completes it if the
    /// task panics or is aborted before returning a response.
    operation: Option<(meshmsg_protocol::OperationId, meshmsg_protocol::ErrorCode)>,
}

/// Every background task the daemon loop supervises. Concurrency is bounded
/// where each task is admitted (semaphores, the storage gate, the single
/// free-space refresh), not by this set.
#[derive(Default)]
pub(super) struct BackgroundTasks {
    tasks: JoinSet<TaskOutput>,
    metadata: HashMap<Id, TaskMetadata>,
    space_refresh: Option<Id>,
}

impl BackgroundTasks {
    fn spawn<F>(&mut self, metadata: TaskMetadata, task: F) -> Id
    where
        F: Future<Output = TaskOutput> + Send + 'static,
    {
        let id = self.tasks.spawn(task).id();
        self.metadata.insert(id, metadata);
        id
    }

    /// Runs an admitted operation to its terminal response. If the task exits
    /// without one, the operation completes with `unexpected_exit` and an
    /// unknown outcome.
    pub(super) fn spawn_operation<F>(
        &mut self,
        kind: &'static str,
        operation_id: meshmsg_protocol::OperationId,
        unexpected_exit: meshmsg_protocol::ErrorCode,
        task: F,
    ) where
        F: Future<Output = meshmsg_protocol::Response> + Send + 'static,
    {
        self.spawn(
            TaskMetadata {
                kind,
                operation: Some((operation_id, unexpected_exit)),
            },
            async move {
                TaskOutput::Operation {
                    operation_id,
                    response: task.await,
                }
            },
        );
    }

    pub(super) fn spawn_offer_list<F>(
        &mut self,
        reply: oneshot::Sender<meshmsg_protocol::Response>,
        task: F,
    ) where
        F: Future<Output = meshmsg_protocol::Response> + Send + 'static,
    {
        self.spawn(
            TaskMetadata {
                kind: "attachment offer listing",
                operation: None,
            },
            async move {
                TaskOutput::OfferList {
                    reply,
                    response: task.await,
                }
            },
        );
    }

    /// Starts a free-space refresh unless the previous one is still running.
    pub(super) fn try_spawn_space_refresh<F>(&mut self, task: F) -> bool
    where
        F: Future<Output = Result<()>> + Send + 'static,
    {
        if self.space_refresh.is_some() {
            return false;
        }
        self.space_refresh = Some(self.spawn(
            TaskMetadata {
                kind: "attachment free-space refresh",
                operation: None,
            },
            async move { TaskOutput::SpaceRefresh(task.await) },
        ));
        true
    }

    pub(super) fn spawn_retention<F>(&mut self, task: F)
    where
        F: Future<Output = Result<Option<meshmsg_protocol::Response>>> + Send + 'static,
    {
        self.spawn(
            TaskMetadata {
                kind: "automatic attachment retention",
                operation: None,
            },
            async move { TaskOutput::Retention(task.await) },
        );
    }

    pub(super) fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    pub(super) async fn join_next(&mut self) -> Option<JoinedTask> {
        self.tasks.join_next_with_id().await
    }

    pub(super) fn complete(
        &mut self,
        joined: JoinedTask,
        operation_cache: &mut OperationCache,
        events: &broadcast::Sender<meshmsg_protocol::Event>,
    ) {
        let task_id = match &joined {
            Ok((task_id, _)) => *task_id,
            Err(error) => error.id(),
        };
        if self.space_refresh == Some(task_id) {
            self.space_refresh = None;
        }
        let Some(metadata) = self.metadata.remove(&task_id) else {
            eprintln!("untracked background attachment task {task_id} completed");
            return;
        };

        match joined {
            Ok((
                _,
                TaskOutput::Operation {
                    operation_id,
                    response,
                },
            )) => operation_cache.finish(operation_id, response, events),
            Ok((_, TaskOutput::OfferList { reply, response })) => {
                let _ = reply.send(response);
            }
            Ok((_, TaskOutput::SpaceRefresh(Err(error)) | TaskOutput::Retention(Err(error)))) => {
                eprintln!("{} failed: {error:#}", metadata.kind);
            }
            Ok((_, TaskOutput::Retention(Ok(Some(meshmsg_protocol::Response::Error(error)))))) => {
                eprintln!(
                    "{} completed with {} ({:?})",
                    metadata.kind,
                    error.code.message(),
                    error.outcome
                );
            }
            Ok((_, TaskOutput::SpaceRefresh(Ok(())) | TaskOutput::Retention(Ok(_)))) => {}
            Err(error) => {
                eprintln!("{} exited unexpectedly: {error}", metadata.kind);
                fail_operation(metadata, operation_cache, events);
            }
        }
    }

    pub(super) async fn abort_and_drain(
        &mut self,
        operation_cache: &mut OperationCache,
        events: &broadcast::Sender<meshmsg_protocol::Event>,
    ) {
        self.tasks.abort_all();
        while let Some(joined) = self.join_next().await {
            self.complete(joined, operation_cache, events);
        }
        if !self.metadata.is_empty() {
            eprintln!(
                "{} background attachment task metadata entries remained after shutdown drain",
                self.metadata.len()
            );
            self.space_refresh = None;
            for (_, metadata) in self.metadata.drain() {
                fail_operation(metadata, operation_cache, events);
            }
        }
    }
}

fn fail_operation(
    metadata: TaskMetadata,
    operation_cache: &mut OperationCache,
    events: &broadcast::Sender<meshmsg_protocol::Event>,
) {
    if let Some((operation_id, code)) = metadata.operation {
        let response = meshmsg_protocol::Response::Error(meshmsg_protocol::ProtocolError::new(
            Some(operation_id),
            code,
            meshmsg_protocol::Outcome::Unknown,
        ));
        operation_cache.finish(operation_id, response, events);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ipc::{
            read_frame,
            server::{handle_local_client, LocalClientSession, LocalIpcTimeouts},
            write_request, MAX_IPC_EVENT_SIZE,
        },
        node::{operation_cache::request_fingerprint, DaemonCommand},
    };
    use iroh::SecretKey;
    use meshmsg_protocol::Request;
    use std::{
        sync::{atomic::Ordering, Arc},
        time::{Duration, Instant as StdInstant},
    };
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
        let fingerprint = [1; 32];
        let mut cache = OperationCache::new(4, Duration::from_secs(10));
        let (reply, response) = oneshot::channel();
        assert!(cache.admit(operation_id, fingerprint, reply, StdInstant::now()));
        let (events, _) = broadcast::channel(1);
        let mut tasks = BackgroundTasks::default();
        tasks.spawn_operation(
            "panicking test attachment share",
            operation_id,
            meshmsg_protocol::ErrorCode::ShareFailed,
            async { panic!("injected attachment task panic") },
        );

        let joined = tasks.join_next().await.unwrap();
        tasks.complete(joined, &mut cache, &events);
        let response = response
            .await
            .expect("operation waiter received terminal result");
        let error = response_error(&response);
        assert_eq!(error.code, meshmsg_protocol::ErrorCode::ShareFailed);
        assert_eq!(error.outcome, meshmsg_protocol::Outcome::Unknown);
        assert_eq!(error.operation_id.as_ref(), Some(&operation_id));

        let (retry, retry_response) = oneshot::channel();
        assert!(!cache.admit(operation_id, fingerprint, retry, StdInstant::now()));
        assert_eq!(retry_response.await.unwrap(), response);
        assert!(tasks.metadata.is_empty());
    }

    #[tokio::test]
    async fn cancelled_attachment_task_also_completes_operation() {
        let operation_id = meshmsg_protocol::OperationId::new_random();
        let mut cache = OperationCache::new(2, Duration::from_secs(10));
        let (reply, response) = oneshot::channel();
        assert!(cache.admit(operation_id, [2; 32], reply, StdInstant::now()));
        let (events, _) = broadcast::channel(1);
        let mut tasks = BackgroundTasks::default();
        tasks.spawn_operation(
            "cancelled test attachment download",
            operation_id,
            meshmsg_protocol::ErrorCode::DownloadFailed,
            std::future::pending(),
        );
        tasks.tasks.abort_all();

        let joined = tasks.join_next().await.unwrap();
        tasks.complete(joined, &mut cache, &events);
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
            to: SecretKey::generate().public().to_string().parse().unwrap(),
            body: meshmsg_protocol::PrivateBody::new("shutdown in flight").unwrap(),
        };
        write_request(
            &mut client,
            &request,
            meshmsg_protocol::RequestId::new_random(),
        )
        .await
        .unwrap();
        let DaemonCommand::Execute {
            request: received,
            reply,
        } = command_rx.recv().await.unwrap()
        else {
            panic!("expected private-send command")
        };
        assert_eq!(received, request);
        let fingerprint = request_fingerprint(&received).unwrap();
        let mut cache = OperationCache::new(4, Duration::from_secs(10));
        assert!(cache.admit(operation_id, fingerprint, reply, StdInstant::now()));

        let mut tasks = BackgroundTasks::default();
        tasks.spawn_operation(
            "shutdown test private send",
            operation_id,
            meshmsg_protocol::ErrorCode::PrivateSendFailed,
            std::future::pending(),
        );
        tasks.abort_and_drain(&mut cache, &events).await;

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
        assert!(!cache.admit(operation_id, fingerprint, retry, StdInstant::now()));
        assert_eq!(retry_response.await.unwrap(), frame.response);
        assert_eq!(cache.counts(), (0, 1));
        assert!(tasks.metadata.is_empty());
    }

    #[tokio::test]
    async fn attachment_space_refresh_never_overlaps_and_reopens_after_completion() {
        let mut cache = OperationCache::new(1, Duration::from_secs(10));
        let (events, _) = broadcast::channel(1);
        let mut tasks = BackgroundTasks::default();
        let (release, wait) = oneshot::channel();
        let running = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let first_running = running.clone();
        assert!(tasks.try_spawn_space_refresh(async move {
            first_running.fetch_add(1, Ordering::SeqCst);
            wait.await.unwrap();
            first_running.fetch_sub(1, Ordering::SeqCst);
            Ok(())
        }));
        assert!(!tasks.try_spawn_space_refresh(async { panic!("overlapping refresh was spawned") }));
        tokio::task::yield_now().await;
        assert_eq!(running.load(Ordering::SeqCst), 1);
        assert_eq!(tasks.tasks.len(), 1);
        assert_eq!(tasks.metadata.len(), 1);

        release.send(()).unwrap();
        let joined = tasks.join_next().await.unwrap();
        tasks.complete(joined, &mut cache, &events);
        assert!(tasks.space_refresh.is_none());
        assert_eq!(running.load(Ordering::SeqCst), 0);
        // A failed or panicked refresh reopens the slot as well.
        assert!(tasks.try_spawn_space_refresh(async { panic!("injected refresh panic") }));
        let joined = tasks.join_next().await.unwrap();
        tasks.complete(joined, &mut cache, &events);
        assert!(tasks.try_spawn_space_refresh(async { Ok(()) }));
        let joined = tasks.join_next().await.unwrap();
        tasks.complete(joined, &mut cache, &events);
        assert!(tasks.space_refresh.is_none());
        assert!(tasks.metadata.is_empty());
    }
}
