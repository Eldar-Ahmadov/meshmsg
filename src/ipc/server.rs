//! Local IPC admission, sessions, deadlines, and subscriptions.

use super::{IpcRequest, IpcRequestFrame, SubscriptionStream};
use crate::{
    node::{
        request_operation_id, CommandPolicy, CommandTimeouts, DaemonCommand, ExecutableRequest,
    },
    presence::{self, Directory},
};
use anyhow::{Context, Result};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::AsyncWrite,
    sync::{broadcast, mpsc, oneshot, OwnedSemaphorePermit, Semaphore},
};

/// At the maximum broadcast size, the shared subscriber ring retains at most
/// 4 MiB of broadcast bodies before lagging slow readers.
const EVENT_BROADCAST_BUDGET_BYTES: usize = 4 * 1024 * 1024;
pub(crate) const EVENT_CAPACITY: usize =
    EVENT_BROADCAST_BUDGET_BYTES / meshmsg_protocol::MAX_SIGNED_BROADCAST_ENVELOPE_BYTES;
const _: () = assert!(EVENT_CAPACITY > 0);

/// Bounds all accepted local IPC connections, including long-lived subscriptions.
const CONNECTION_CAPACITY: usize = 64;
const INITIAL_FRAME_TIMEOUT: Duration = Duration::from_secs(8);
const RESPONSE_WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const ORDINARY_COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
const PRIVATE_COMMAND_TIMEOUT: Duration = Duration::from_secs(35);
const LIST_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const TRANSFER_COMMAND_TIMEOUT: Duration = Duration::from_secs(60 * 60 + 10);
const SHUTDOWN_GRACE: Duration = Duration::from_secs(2);
const REJECTION_WRITE_TIMEOUT: Duration = Duration::from_millis(250);

#[derive(Clone, Copy)]
struct LocalIpcTimeouts {
    initial_frame: Duration,
    response_write: Duration,
    ordinary_command: Duration,
    private_command: Duration,
    list_command: Duration,
    transfer_command: Duration,
    rejection_write: Duration,
}

impl LocalIpcTimeouts {
    fn command_timeouts(self) -> CommandTimeouts {
        CommandTimeouts {
            ordinary: self.ordinary_command,
            private: self.private_command,
            list: self.list_command,
            transfer: self.transfer_command,
        }
    }
}

impl Default for LocalIpcTimeouts {
    fn default() -> Self {
        Self {
            initial_frame: INITIAL_FRAME_TIMEOUT,
            response_write: RESPONSE_WRITE_TIMEOUT,
            ordinary_command: ORDINARY_COMMAND_TIMEOUT,
            private_command: PRIVATE_COMMAND_TIMEOUT,
            list_command: LIST_COMMAND_TIMEOUT,
            transfer_command: TRANSFER_COMMAND_TIMEOUT,
            rejection_write: REJECTION_WRITE_TIMEOUT,
        }
    }
}

async fn write_local_frame<S, F>(stream: &mut S, frame: &F, deadline: Duration) -> Result<()>
where
    S: AsyncWrite + Unpin,
    F: serde::Serialize + ?Sized,
{
    tokio::time::timeout(
        deadline,
        meshmsg_protocol::write_json(stream, frame, meshmsg_protocol::FrameLimit::Event),
    )
    .await
    .context("timed out writing local IPC frame")?
    .map_err(anyhow::Error::from)
}

async fn write_local_response<S>(
    stream: &mut S,
    request_id: Option<meshmsg_protocol::RequestId>,
    response: meshmsg_protocol::Response,
    deadline: Duration,
) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let frame = meshmsg_protocol::ResponseFrame::try_new(request_id, response)
        .map_err(anyhow::Error::msg)
        .context("invalid local IPC response")?;
    write_local_frame(stream, &frame, deadline).await
}

async fn write_local_event<S>(
    stream: &mut S,
    request_id: meshmsg_protocol::RequestId,
    event: meshmsg_protocol::Event,
    deadline: Duration,
) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let frame = meshmsg_protocol::EventFrame::try_new(request_id, event)
        .map_err(anyhow::Error::msg)
        .context("invalid local IPC event")?;
    write_local_frame(stream, &frame, deadline).await
}

async fn command_response<F>(
    operation: F,
    policy: CommandPolicy,
    operation_id: Option<meshmsg_protocol::OperationId>,
) -> meshmsg_protocol::Response
where
    F: std::future::Future<Output = Result<meshmsg_protocol::Response>>,
{
    let (code, value) = match tokio::time::timeout(policy.deadline, operation).await {
        Ok(Ok(value)) => return value,
        Ok(Err(_)) => (policy.unavailable_code, meshmsg_protocol::Outcome::Unknown),
        Err(_) => (policy.timeout_code, meshmsg_protocol::Outcome::Unknown),
    };
    meshmsg_protocol::Response::Error(meshmsg_protocol::ProtocolError::new(
        operation_id,
        code,
        value,
    ))
}

async fn send_command(
    commands: &mpsc::Sender<DaemonCommand>,
    command: DaemonCommand,
    response: oneshot::Receiver<meshmsg_protocol::Response>,
) -> Result<meshmsg_protocol::Response> {
    commands.send(command).await?;
    Ok(response.await?)
}

#[cfg(test)]
pub(crate) async fn handle_local_client<S>(
    stream: S,
    commands: mpsc::Sender<DaemonCommand>,
    events: broadcast::Receiver<meshmsg_protocol::Event>,
    connected: meshmsg_protocol::Event,
    startup_peers: Option<meshmsg_protocol::Event>,
) -> Result<()>
where
    S: SubscriptionStream,
{
    handle_local_client_with_timeouts(
        stream,
        commands,
        events,
        connected,
        startup_peers,
        LocalIpcTimeouts::default(),
    )
    .await
}

async fn handle_local_client_with_timeouts<S>(
    stream: S,
    commands: mpsc::Sender<DaemonCommand>,
    events: broadcast::Receiver<meshmsg_protocol::Event>,
    connected: meshmsg_protocol::Event,
    startup_peers: Option<meshmsg_protocol::Event>,
    timeouts: LocalIpcTimeouts,
) -> Result<()>
where
    S: SubscriptionStream,
{
    handle_local_client_inner(stream, commands, events, connected, startup_peers, timeouts).await
}

async fn handle_local_client_inner<S>(
    stream: S,
    commands: mpsc::Sender<DaemonCommand>,
    mut events: broadcast::Receiver<meshmsg_protocol::Event>,
    connected: meshmsg_protocol::Event,
    startup_peers: Option<meshmsg_protocol::Event>,
    timeouts: LocalIpcTimeouts,
) -> Result<()>
where
    S: SubscriptionStream,
{
    let mut stream = meshmsg_protocol::FrameReader::new(stream);
    let frame = match tokio::time::timeout(
        timeouts.initial_frame,
        stream.read_frame(meshmsg_protocol::FrameLimit::Request),
    )
    .await
    {
        Ok(result) => result?,
        Err(_) => {
            let _ = write_local_response(
                &mut stream,
                None,
                meshmsg_protocol::Response::Error(meshmsg_protocol::ProtocolError::new(
                    None,
                    meshmsg_protocol::ErrorCode::InitialFrameTimeout,
                    meshmsg_protocol::Outcome::NotStarted,
                )),
                timeouts.response_write,
            )
            .await;
            return Ok(());
        }
    };
    let request_frame: IpcRequestFrame = match serde_json::from_slice(&frame) {
        Ok(frame) => frame,
        Err(_) => {
            let _ = write_local_response(
                &mut stream,
                None,
                meshmsg_protocol::Response::Error(meshmsg_protocol::ProtocolError::new(
                    None,
                    meshmsg_protocol::ErrorCode::InvalidRequest,
                    meshmsg_protocol::Outcome::NotStarted,
                )),
                timeouts.response_write,
            )
            .await;
            return Ok(());
        }
    };
    let request_id = request_frame.request_id;
    let request = request_frame.request;
    match request {
        IpcRequest::Subscribe => {
            write_local_event(
                &mut stream,
                request_id.clone(),
                connected,
                timeouts.response_write,
            )
            .await?;
            if let Some(snapshot) = startup_peers {
                write_local_event(
                    &mut stream,
                    request_id.clone(),
                    snapshot,
                    timeouts.response_write,
                )
                .await?;
            }
            let mut read_closed = false;
            loop {
                let mut disconnect = [0_u8; 1];
                tokio::select! {
                    read = stream.read(&mut disconnect), if !read_closed => {
                        anyhow::ensure!(read? == 0, "unexpected data after subscribe");
                        read_closed = true;
                        if stream.get_ref().subscription_closed_after_eof()? {
                            break;
                        }
                    }
                    // EOF stays readable forever. Avoid a busy loop while still
                    // reclaiming quiet subscriptions after a full close.
                    _ = tokio::time::sleep(Duration::from_millis(250)), if read_closed => {
                        if stream.get_ref().subscription_closed_after_eof()? {
                            break;
                        }
                    }
                    value = events.recv() => match value {
                        Ok(value) => write_local_event(
                            &mut stream,
                            request_id.clone(),
                            value,
                            timeouts.response_write,
                        ).await?,
                        Err(broadcast::error::RecvError::Lagged(count)) => {
                            write_local_event(
                                &mut stream,
                                request_id.clone(),
                                meshmsg_protocol::Event::Lagged {
                                    source: meshmsg_protocol::EventSource::Local,
                                    dropped: count,
                                    message: format!("local listener missed {count} events"),
                                },
                                timeouts.response_write,
                            )
                            .await?;
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
            }
        }
        request @ (IpcRequest::Send { .. }
        | IpcRequest::PrivateSend { .. }
        | IpcRequest::Status
        | IpcRequest::Peers
        | IpcRequest::Offers
        | IpcRequest::OffersRemove { .. }
        | IpcRequest::OffersPrune { .. }
        | IpcRequest::Share { .. }
        | IpcRequest::Download { .. }) => {
            let policy = CommandPolicy::for_request(&request, timeouts.command_timeouts())
                .expect("executable requests have a command policy");
            let operation_id = request_operation_id(&request);
            let request = ExecutableRequest::try_from(request)
                .expect("validated IPC request has a bounded attachment token");
            let (reply, response) = oneshot::channel();
            let value = command_response(
                send_command(
                    &commands,
                    DaemonCommand::Execute { request, reply },
                    response,
                ),
                policy,
                operation_id,
            )
            .await;
            write_local_response(
                &mut stream,
                Some(request_id),
                value,
                timeouts.response_write,
            )
            .await?;
        }
        IpcRequest::Stop => {
            // Reserve bounded queue capacity before acknowledging. Once `send`
            // succeeds the daemon will stop even if the client disappears before
            // reading the acknowledgement; before it succeeds, report not_started.
            let response = match tokio::time::timeout(timeouts.ordinary_command, commands.reserve())
                .await
            {
                Ok(Ok(permit)) => {
                    permit.send(DaemonCommand::Stop);
                    meshmsg_protocol::Response::Stopping {}
                }
                Ok(Err(_)) => {
                    meshmsg_protocol::Response::Error(meshmsg_protocol::ProtocolError::new(
                        None,
                        meshmsg_protocol::ErrorCode::DaemonStopping,
                        meshmsg_protocol::Outcome::NotStarted,
                    ))
                }
                Err(_) => meshmsg_protocol::Response::Error(meshmsg_protocol::ProtocolError::new(
                    None,
                    meshmsg_protocol::ErrorCode::CommandTimeout,
                    meshmsg_protocol::Outcome::NotStarted,
                )),
            };
            write_local_response(
                &mut stream,
                Some(request_id),
                response,
                timeouts.response_write,
            )
            .await?;
        }
    }
    Ok(())
}

async fn reject_local_client_at_capacity<S>(mut stream: S, write_timeout: Duration)
where
    S: AsyncWrite + Unpin,
{
    let _ = write_local_response(
        &mut stream,
        None,
        meshmsg_protocol::Response::Error(meshmsg_protocol::ProtocolError::new(
            None,
            meshmsg_protocol::ErrorCode::IpcCapacity,
            meshmsg_protocol::Outcome::NotStarted,
        )),
        write_timeout,
    )
    .await;
}

pub(crate) fn subscription_startup_events(
    connectivity: presence::LocalConnectivity,
    directory: &Directory,
    peer: &str,
    alias: Option<&str>,
    generated_at_ms: u64,
    directory_epoch: &str,
    directory_revision: u64,
) -> Result<(meshmsg_protocol::Event, meshmsg_protocol::Event)> {
    let connected = meshmsg_protocol::Event::Connected(meshmsg_protocol::Connected {
        peer: peer.parse()?,
        endpoint_online: connectivity.endpoint_online,
        topic_joined: connectivity.topic_joined,
        alias: alias.map(str::parse).transpose()?,
    });
    let snapshot = presence::snapshot_with_connectivity(
        connectivity,
        directory,
        peer,
        alias,
        generated_at_ms,
        directory_epoch,
        directory_revision,
    );
    Ok((connected, meshmsg_protocol::Event::PeersSnapshot(snapshot)))
}

pub(crate) struct LocalClientSession {
    commands: mpsc::Sender<DaemonCommand>,
    events: broadcast::Receiver<meshmsg_protocol::Event>,
    connected: meshmsg_protocol::Event,
    startup_peers: Option<meshmsg_protocol::Event>,
}

impl LocalClientSession {
    pub(crate) fn new(
        commands: mpsc::Sender<DaemonCommand>,
        events: broadcast::Receiver<meshmsg_protocol::Event>,
        connected: meshmsg_protocol::Event,
        startup_peers: Option<meshmsg_protocol::Event>,
    ) -> Self {
        Self {
            commands,
            events,
            connected,
            startup_peers,
        }
    }
}

async fn handle_admitted_local_client<S>(
    stream: S,
    session: LocalClientSession,
    timeouts: LocalIpcTimeouts,
    permit: OwnedSemaphorePermit,
) -> Result<()>
where
    S: SubscriptionStream,
{
    let _permit = permit;
    handle_local_client_with_timeouts(
        stream,
        session.commands,
        session.events,
        session.connected,
        session.startup_peers,
        timeouts,
    )
    .await
}

/// Admit immediately after the platform listener has accepted/authenticated the
/// stream. The preparation closure is deliberately invoked only after a permit
/// is owned, so saturated clients cannot trigger snapshots, subscriptions, or
/// other per-client state work.
async fn admit_local_client<S, F>(
    stream: S,
    connection_limit: &Arc<Semaphore>,
    tasks: &mut tokio::task::JoinSet<Result<()>>,
    timeouts: LocalIpcTimeouts,
    prepare: F,
) -> Result<bool>
where
    S: SubscriptionStream + Send + 'static,
    F: FnOnce() -> Result<LocalClientSession>,
{
    let permit = match connection_limit.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            // Accept before rejecting so cooperative clients receive an
            // explicit retryable result instead of an opaque connect error.
            reject_local_client_at_capacity(stream, timeouts.rejection_write).await;
            return Ok(false);
        }
    };
    let session = prepare()?;
    tasks.spawn(
        async move { handle_admitted_local_client(stream, session, timeouts, permit).await },
    );
    Ok(true)
}

async fn drain_local_client_tasks(tasks: &mut tokio::task::JoinSet<Result<()>>, grace: Duration) {
    let deadline = tokio::time::Instant::now() + grace;
    while !tasks.is_empty() {
        match tokio::time::timeout_at(deadline, tasks.join_next()).await {
            Ok(Some(result)) => report_session_completion(result),
            Ok(None) => return,
            Err(_) => break,
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
}

fn report_session_completion(completed: std::result::Result<Result<()>, tokio::task::JoinError>) {
    match completed {
        Ok(Ok(())) => {}
        Ok(Err(error)) => eprintln!("local IPC task failed: {error:#}"),
        Err(error) => eprintln!("local IPC task exited unexpectedly: {error}"),
    }
}

/// Owns local-client admission and all spawned session handlers. The daemon
/// retains the listener and decides when accepts are polled in its central loop.
pub(crate) struct Server {
    connection_limit: Arc<Semaphore>,
    tasks: tokio::task::JoinSet<Result<()>>,
}

impl Server {
    pub(crate) fn new() -> Self {
        Self {
            connection_limit: Arc::new(Semaphore::new(CONNECTION_CAPACITY)),
            tasks: tokio::task::JoinSet::new(),
        }
    }

    pub(crate) async fn admit<S, F>(&mut self, stream: S, prepare: F) -> Result<bool>
    where
        S: SubscriptionStream + Send + 'static,
        F: FnOnce() -> Result<LocalClientSession>,
    {
        admit_local_client(
            stream,
            &self.connection_limit,
            &mut self.tasks,
            LocalIpcTimeouts::default(),
            prepare,
        )
        .await
    }

    pub(crate) fn has_sessions(&self) -> bool {
        !self.tasks.is_empty()
    }

    pub(crate) async fn join_next(&mut self) {
        if let Some(completed) = self.tasks.join_next().await {
            report_session_completion(completed);
        }
    }

    pub(crate) fn close_admission(&self) {
        self.connection_limit.close();
    }

    pub(crate) async fn shutdown(&mut self) {
        drain_local_client_tasks(&mut self.tasks, SHUTDOWN_GRACE).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::StateLock,
        contracts,
        ipc::{
            bind_local_endpoint, connect_daemon, read_frame, write_request, write_request_with_id,
            LocalClientStream, LocalListener, MAX_IPC_EVENT_SIZE,
        },
    };
    use iroh::{address_lookup::memory::MemoryLookup, SecretKey};
    use std::{
        path::{Path, PathBuf},
        sync::atomic::Ordering,
    };
    use tokio::io::{AsyncWrite, AsyncWriteExt};
    #[cfg(unix)]
    use tokio::net::UnixStream;

    fn connected_fixture() -> meshmsg_protocol::Event {
        meshmsg_protocol::Event::Connected(meshmsg_protocol::Connected {
            peer: "2".repeat(64).parse().unwrap(),
            endpoint_online: true,
            topic_joined: true,
            alias: None,
        })
    }

    fn peer_discovered_fixture(revision: u64) -> meshmsg_protocol::Event {
        meshmsg_protocol::Event::PeerDiscovered(meshmsg_protocol::PeerTransition {
            directory_epoch: "4".repeat(32).parse().unwrap(),
            directory_revision: revision,
            peer: meshmsg_protocol::RemotePeer {
                public_key: "3".repeat(64).parse().unwrap(),
                alias: None,
                online: true,
                last_seen_ms: 1,
                expires_at_ms: 2,
            },
        })
    }

    #[tokio::test]
    async fn local_daemon_interoperates_with_v4_and_rejects_other_protocol_versions() {
        let exercise = |request: Vec<u8>| async move {
            let (mut client, server) = tokio::io::duplex(4096);
            let (commands, mut command_rx) = mpsc::channel(1);
            let (events, _) = broadcast::channel(1);
            let task = tokio::spawn(handle_local_client(
                server,
                commands,
                events.subscribe(),
                connected_fixture(),
                None,
            ));
            client.write_all(&request).await.unwrap();
            let frame = read_frame(&mut client, MAX_IPC_EVENT_SIZE).await.unwrap();
            let value: serde_json::Value = serde_json::from_slice(&frame).unwrap();
            let typed: meshmsg_protocol::ResponseFrame = serde_json::from_slice(&frame).unwrap();
            assert_eq!(typed.protocol_version, meshmsg_protocol::ProtocolVersion);
            drop(client);
            let _ = command_rx.recv().await;
            task.await.unwrap().unwrap();
            value
        };

        let mut request = Vec::new();
        write_request_with_id(
            &mut request,
            &IpcRequest::Stop,
            "11111111111111111111111111111111",
        )
        .await
        .unwrap();
        let response = exercise(request).await;
        assert_eq!(response["type"], "stopping");
        assert_eq!(response["request_id"], "11111111111111111111111111111111");
        let response_dto: meshmsg_protocol::ResponseFrame =
            serde_json::from_value(response.clone()).unwrap();
        assert!(matches!(
            response_dto.response,
            meshmsg_protocol::Response::Stopping {}
        ));
        let mut unsupported_response = response.clone();
        unsupported_response["protocol_version"] = 2.into();
        assert!(
            serde_json::from_value::<meshmsg_protocol::ResponseFrame>(unsupported_response)
                .is_err()
        );

        // Decode a frame produced by the real subscription path directly through
        // the public typed event frame.
        let (mut client, server) = tokio::io::duplex(4096);
        let (commands, _command_rx) = mpsc::channel(1);
        let (events, _) = broadcast::channel(1);
        let subscriber = tokio::spawn(handle_local_client(
            server,
            commands,
            events.subscribe(),
            connected_fixture(),
            None,
        ));
        write_request_with_id(
            &mut client,
            &IpcRequest::Subscribe,
            "33333333333333333333333333333333",
        )
        .await
        .unwrap();
        let connected = read_frame(&mut client, MAX_IPC_EVENT_SIZE).await.unwrap();
        let event_dto: meshmsg_protocol::EventFrame = serde_json::from_slice(&connected).unwrap();
        assert!(matches!(
            event_dto.event,
            meshmsg_protocol::Event::Connected(_)
        ));
        let mut unsupported_event: serde_json::Value = serde_json::from_slice(&connected).unwrap();
        unsupported_event["protocol_version"] = 2.into();
        assert!(serde_json::from_value::<meshmsg_protocol::EventFrame>(unsupported_event).is_err());
        drop(client);
        subscriber.await.unwrap().unwrap();

        for version in [1, 2] {
            let request = format!(
                "{{\"protocol_version\":{version},\"request_id\":\"22222222222222222222222222222222\",\"request\":{{\"command\":\"stop\"}}}}\n"
            )
            .into_bytes();
            let response = exercise(request).await;
            assert_eq!(response["type"], "error");
            assert_eq!(response["code"], "invalid_request");
            assert!(response.get("request_id").is_none());
            let response_dto: meshmsg_protocol::ResponseFrame =
                serde_json::from_value(response).unwrap();
            assert!(matches!(
                response_dto.response,
                meshmsg_protocol::Response::Error(_)
            ));
        }

        // A failed typed decode is terminal. Even recognizable envelope fields
        // are not reparsed to recover correlation or classify the rejection.
        let oversized_send = serde_json::json!({
            "protocol_version": meshmsg_protocol::PROTOCOL_VERSION,
            "request_id": "44444444444444444444444444444444",
            "request": {
                "command": "send",
                "operation_id": "55555555555555555555555555555555",
                "body": "x".repeat(crate::message::MAX_BROADCAST_BODY_BYTES + 1),
            }
        });
        let mut request = serde_json::to_vec(&oversized_send).unwrap();
        request.push(b'\n');
        let response = exercise(request).await;
        assert_eq!(response["code"], "invalid_request");
        assert!(response.get("request_id").is_none());
        assert!(response.get("operation_id").is_none());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_subscriber_receives_events_after_write_half_close() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let (commands, _command_rx) = mpsc::channel(1);
        let (events, receiver) = broadcast::channel(1);
        let mut task = tokio::spawn(handle_local_client(
            server,
            commands,
            receiver,
            connected_fixture(),
            None,
        ));
        write_request(&mut client, &IpcRequest::Subscribe)
            .await
            .unwrap();
        client.shutdown().await.unwrap();
        let connected = tokio::time::timeout(
            Duration::from_secs(1),
            read_frame(&mut client, MAX_IPC_EVENT_SIZE),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&connected).unwrap()["type"],
            "connected"
        );
        // Stay quiet across multiple closure polls before publishing an event.
        assert!(tokio::time::timeout(Duration::from_millis(600), &mut task)
            .await
            .is_err());
        events.send(peer_discovered_fixture(1)).unwrap();
        let received = tokio::time::timeout(
            Duration::from_secs(1),
            read_frame(&mut client, MAX_IPC_EVENT_SIZE),
        )
        .await
        .unwrap()
        .unwrap();
        let received: serde_json::Value = serde_json::from_slice(&received).unwrap();
        assert_eq!(received["type"], "peer_discovered");
        assert_eq!(received["peer"]["public_key"], "3".repeat(64));
        assert_eq!(received["protocol_version"], 4);
        assert!(contracts::valid_request_id(
            received["request_id"].as_str().unwrap()
        ));
        drop(client);
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(events.receiver_count(), 0);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn coalesced_subscribe_trailing_bytes_are_preserved_and_close_session() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let (commands, _command_rx) = mpsc::channel(1);
        let (events, receiver) = broadcast::channel(1);
        let task = tokio::spawn(handle_local_client(
            server,
            commands,
            receiver,
            connected_fixture(),
            None,
        ));
        let mut coalesced = Vec::new();
        write_request(&mut coalesced, &IpcRequest::Subscribe)
            .await
            .unwrap();
        coalesced.extend_from_slice(b"trailing");
        client.write_all(&coalesced).await.unwrap();
        client.shutdown().await.unwrap();

        let connected = read_frame(&mut client, MAX_IPC_EVENT_SIZE).await.unwrap();
        let connected: meshmsg_protocol::EventFrame = serde_json::from_slice(&connected).unwrap();
        assert!(matches!(
            connected.event,
            meshmsg_protocol::Event::Connected(_)
        ));
        let error = tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("server discarded buffered trailing bytes")
            .unwrap()
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("unexpected data after subscribe"));
        assert_eq!(events.receiver_count(), 0);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_subscriber_exits_when_client_closes_on_a_quiet_topic() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let (commands, _command_rx) = mpsc::channel(1);
        let (events, receiver) = broadcast::channel(1);
        let task = tokio::spawn(handle_local_client(
            server,
            commands,
            receiver,
            connected_fixture(),
            None,
        ));
        write_request(&mut client, &IpcRequest::Subscribe)
            .await
            .unwrap();
        read_frame(&mut client, MAX_IPC_EVENT_SIZE).await.unwrap();
        drop(client);
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(events.receiver_count(), 0);
    }

    #[tokio::test]
    async fn subscriber_gets_connected_then_atomic_startup_snapshot() {
        let (mut client, server) = tokio::io::duplex(MAX_IPC_EVENT_SIZE);
        let (commands, _command_rx) = mpsc::channel(1);
        let (events, receiver) = broadcast::channel(1);
        let startup = meshmsg_protocol::Event::PeersSnapshot(meshmsg_protocol::PeerSnapshot {
            generated_at_ms: 1,
            directory_epoch: "4".repeat(32).parse().unwrap(),
            directory_revision: 1,
            self_peer: meshmsg_protocol::SelfPeer {
                public_key: "2".repeat(64).parse().unwrap(),
                alias: None,
                online: true,
            },
            peers: vec![],
        });
        let task = tokio::spawn(handle_local_client(
            server,
            commands,
            receiver,
            connected_fixture(),
            Some(startup.clone()),
        ));
        write_request(&mut client, &IpcRequest::Subscribe)
            .await
            .unwrap();
        let mut client = meshmsg_protocol::FrameReader::new(client);
        let connected = client
            .read_frame(meshmsg_protocol::FrameLimit::Event)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&connected).unwrap()["type"],
            "connected"
        );
        let snapshot = client
            .read_frame(meshmsg_protocol::FrameLimit::Event)
            .await
            .unwrap();
        let snapshot: serde_json::Value = serde_json::from_slice(&snapshot).unwrap();
        assert_eq!(snapshot["type"], "peers_snapshot");
        assert_eq!(snapshot["peers"], serde_json::json!([]));
        assert!(contracts::valid_request_id(
            snapshot["request_id"].as_str().unwrap()
        ));

        drop(events);
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn newly_admitted_subscriber_uses_current_connectivity_for_both_snapshots() {
        let connectivity = Arc::new(std::sync::atomic::AtomicBool::new(true));
        connectivity.store(false, Ordering::SeqCst);
        let directory = Directory::new(MemoryLookup::new());
        let peer = SecretKey::generate().public().to_string();
        let (mut client, server) = tokio::io::duplex(4096);
        let (commands, _command_rx) = mpsc::channel(1);
        let (events, _) = broadcast::channel(1);
        let limit = Arc::new(Semaphore::new(1));
        let mut tasks = tokio::task::JoinSet::new();
        let current = connectivity.clone();
        assert!(admit_local_client(
            server,
            &limit,
            &mut tasks,
            LocalIpcTimeouts::default(),
            || {
                let connectivity = presence::LocalConnectivity {
                    endpoint_online: current.load(Ordering::SeqCst),
                    topic_joined: true,
                };
                let (connected, startup_peers) = subscription_startup_events(
                    connectivity,
                    &directory,
                    &peer,
                    None,
                    1,
                    "4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a",
                    0,
                )?;
                Ok(LocalClientSession {
                    commands,
                    events: events.subscribe(),
                    connected,
                    startup_peers: Some(startup_peers),
                })
            },
        )
        .await
        .unwrap());

        write_request(&mut client, &IpcRequest::Subscribe)
            .await
            .unwrap();
        let mut client = meshmsg_protocol::FrameReader::new(client);
        let connected: meshmsg_protocol::EventFrame = client
            .read_json(meshmsg_protocol::FrameLimit::Event)
            .await
            .unwrap();
        let snapshot: meshmsg_protocol::EventFrame = client
            .read_json(meshmsg_protocol::FrameLimit::Event)
            .await
            .unwrap();
        let meshmsg_protocol::Event::Connected(connected) = connected.event else {
            panic!("expected connected event")
        };
        let meshmsg_protocol::Event::PeersSnapshot(snapshot) = snapshot.event else {
            panic!("expected peer snapshot")
        };
        assert!(!connected.endpoint_online);
        assert!(connected.topic_joined);
        assert!(!snapshot.self_peer.online);

        drop(client);
        tasks.join_next().await.unwrap().unwrap().unwrap();
        assert_eq!(limit.available_permits(), 1);
    }

    #[tokio::test]
    async fn slow_subscriber_receives_lag_event() {
        let (mut client, server) = tokio::io::duplex(MAX_IPC_EVENT_SIZE);
        let (commands, _command_rx) = mpsc::channel(1);
        let (events, receiver) = broadcast::channel(1);
        events.send(peer_discovered_fixture(1)).unwrap();
        events.send(peer_discovered_fixture(2)).unwrap();
        let task = tokio::spawn(handle_local_client(
            server,
            commands,
            receiver,
            connected_fixture(),
            None,
        ));
        write_request(&mut client, &IpcRequest::Subscribe)
            .await
            .unwrap();
        let mut client = meshmsg_protocol::FrameReader::new(client);
        let _connected = client
            .read_frame(meshmsg_protocol::FrameLimit::Event)
            .await
            .unwrap();
        let lagged = client
            .read_frame(meshmsg_protocol::FrameLimit::Event)
            .await
            .unwrap();
        let lagged: serde_json::Value = serde_json::from_slice(&lagged).unwrap();
        assert_eq!(lagged["type"], "lagged");
        assert_eq!(lagged["source"], "local");
        assert_eq!(lagged["dropped"], 1);

        drop(events);
        task.await.unwrap().unwrap();
    }

    fn short_ipc_timeouts() -> LocalIpcTimeouts {
        LocalIpcTimeouts {
            initial_frame: Duration::from_millis(40),
            response_write: Duration::from_millis(100),
            ordinary_command: Duration::from_millis(40),
            private_command: Duration::from_millis(60),
            list_command: Duration::from_millis(60),
            transfer_command: Duration::from_millis(80),
            rejection_write: Duration::from_millis(20),
        }
    }

    #[cfg(any(unix, windows))]
    #[allow(clippy::too_many_arguments)]
    async fn accept_and_admit_test_client(
        listener: &mut LocalListener,
        dir: &Path,
        limit: &Arc<Semaphore>,
        tasks: &mut tokio::task::JoinSet<Result<()>>,
        commands: &mpsc::Sender<DaemonCommand>,
        events: &broadcast::Sender<meshmsg_protocol::Event>,
        preparations: &Arc<std::sync::atomic::AtomicUsize>,
        timeouts: LocalIpcTimeouts,
    ) -> (LocalClientStream, bool) {
        // Named pipes require the server connect future to be polled while the
        // client opens; Unix sockets exercise the same production listener API.
        let (server, client) = tokio::join!(listener.accept(), connect_daemon(dir));
        let admitted = admit_local_client(server.unwrap(), limit, tasks, timeouts, || {
            preparations.fetch_add(1, Ordering::SeqCst);
            Ok(LocalClientSession {
                commands: commands.clone(),
                events: events.subscribe(),
                connected: connected_fixture(),
                startup_peers: None,
            })
        })
        .await
        .unwrap();
        (client.unwrap(), admitted)
    }

    #[cfg(any(unix, windows))]
    #[tokio::test]
    async fn platform_listener_enforces_capacity_skips_saturated_preparation_and_recovers() {
        let dir =
            std::env::temp_dir().join(format!("meshmsg-ipc-capacity-{}", rand::random::<u64>()));
        let state_lock = StateLock::acquire(&dir).unwrap();
        let (mut listener, guard) = bind_local_endpoint(&dir, &state_lock).await.unwrap();
        let limit = Arc::new(Semaphore::new(CONNECTION_CAPACITY));
        let (commands, mut command_rx) = mpsc::channel(1);
        let (events, _) = broadcast::channel(1);
        let preparations = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut tasks = tokio::task::JoinSet::new();
        let mut timeouts = short_ipc_timeouts();
        timeouts.initial_frame = Duration::from_secs(5);
        let mut clients = Vec::new();

        for _ in 0..CONNECTION_CAPACITY {
            let (client, admitted) = accept_and_admit_test_client(
                &mut listener,
                &dir,
                &limit,
                &mut tasks,
                &commands,
                &events,
                &preparations,
                timeouts,
            )
            .await;
            assert!(admitted);
            clients.push(client);
        }
        assert_eq!(limit.available_permits(), 0);

        let (mut rejected, admitted) = accept_and_admit_test_client(
            &mut listener,
            &dir,
            &limit,
            &mut tasks,
            &commands,
            &events,
            &preparations,
            timeouts,
        )
        .await;
        assert!(!admitted);
        assert_eq!(
            preparations.load(Ordering::SeqCst),
            CONNECTION_CAPACITY,
            "saturated client unexpectedly ran per-client preparation"
        );
        let frame = read_frame(&mut rejected, MAX_IPC_EVENT_SIZE).await.unwrap();
        let rejection: meshmsg_protocol::ResponseFrame = serde_json::from_slice(&frame).unwrap();
        assert_eq!(
            rejection.protocol_version,
            meshmsg_protocol::ProtocolVersion
        );
        let meshmsg_protocol::Response::Error(error) = rejection.response else {
            panic!("expected capacity error")
        };
        assert_eq!(error.code, meshmsg_protocol::ErrorCode::IpcCapacity);
        assert_eq!(error.outcome, meshmsg_protocol::Outcome::NotStarted);
        assert_eq!(
            error.retry_advice(),
            meshmsg_protocol::RetryAdvice::RetrySameRequest
        );
        assert!(rejection.request_id.is_none());
        assert_eq!(tasks.len(), CONNECTION_CAPACITY);

        let operation: meshmsg_protocol::OperationId =
            "11111111111111111111111111111111".parse().unwrap();
        let mutations = vec![
            IpcRequest::Send {
                operation_id: operation.clone(),
                body: meshmsg_protocol::BroadcastBody::new("x").unwrap(),
            },
            IpcRequest::PrivateSend {
                operation_id: operation.clone(),
                to: "2".repeat(64).parse().unwrap(),
                body: meshmsg_protocol::PrivateBody::new("x").unwrap(),
            },
            IpcRequest::Share {
                operation_id: operation.clone(),
                source_digest: "3".repeat(64).parse().unwrap(),
                path: PathBuf::from("x"),
            },
            IpcRequest::OffersRemove {
                operation_id: operation.clone(),
                offer_id: "4".repeat(32).parse().unwrap(),
                direction: None,
                provider: None,
            },
            IpcRequest::OffersPrune {
                operation_id: operation.clone(),
                older_than_secs: 1,
                direction: None,
                dry_run: false,
                max_delete: 1,
            },
            IpcRequest::Download {
                operation_id: operation,
                offer: "x".into(),
                output: PathBuf::from("x"),
                mode: meshmsg_protocol::DownloadMode::Install,
            },
        ];
        for mutation in mutations {
            let (mut client, admitted) = accept_and_admit_test_client(
                &mut listener,
                &dir,
                &limit,
                &mut tasks,
                &commands,
                &events,
                &preparations,
                timeouts,
            )
            .await;
            assert!(!admitted);
            let frame = read_frame(&mut client, MAX_IPC_EVENT_SIZE).await.unwrap();
            let frame: meshmsg_protocol::ResponseFrame = serde_json::from_slice(&frame).unwrap();
            let meshmsg_protocol::Response::Error(transport) = frame.response else {
                panic!("expected transport error")
            };
            crate::ipc::validate_error_for_request(&transport, &mutation).unwrap();
        }

        tokio::time::timeout(Duration::from_secs(7), async {
            while !tasks.is_empty() {
                tasks.join_next().await.unwrap().unwrap().unwrap();
            }
        })
        .await
        .unwrap();
        assert_eq!(limit.available_permits(), CONNECTION_CAPACITY);
        let timeout_frame = read_frame(&mut clients[0], MAX_IPC_EVENT_SIZE)
            .await
            .unwrap();
        let timeout_error: meshmsg_protocol::ResponseFrame =
            serde_json::from_slice(&timeout_frame).unwrap();
        let meshmsg_protocol::Response::Error(error) = timeout_error.response else {
            panic!("expected initial-frame timeout error")
        };
        assert_eq!(error.code, meshmsg_protocol::ErrorCode::InitialFrameTimeout);
        assert_eq!(error.outcome, meshmsg_protocol::Outcome::NotStarted);
        assert_eq!(
            error.retry_advice(),
            meshmsg_protocol::RetryAdvice::RetrySameRequest
        );
        assert!(timeout_error.request_id.is_none());

        let (mut recovered, admitted) = accept_and_admit_test_client(
            &mut listener,
            &dir,
            &limit,
            &mut tasks,
            &commands,
            &events,
            &preparations,
            short_ipc_timeouts(),
        )
        .await;
        assert!(admitted);
        assert_eq!(preparations.load(Ordering::SeqCst), CONNECTION_CAPACITY + 1);
        write_request(&mut recovered, &IpcRequest::Status)
            .await
            .unwrap();
        let DaemonCommand::Execute {
            request: ExecutableRequest::Protocol(IpcRequest::Status),
            reply,
        } = command_rx.recv().await.unwrap()
        else {
            panic!("expected recovered status command")
        };
        reply.send(meshmsg_protocol::Response::Stopping {}).unwrap();
        read_frame(&mut recovered, MAX_IPC_EVENT_SIZE)
            .await
            .unwrap();
        tasks.join_next().await.unwrap().unwrap().unwrap();

        drop(clients);
        drop(rejected);
        drop(recovered);
        drop(listener);
        guard.release_for_test();
        drop(state_lock);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn stop_acknowledges_only_after_command_admission() {
        let (mut client, server) = tokio::io::duplex(1024);
        let (commands, mut command_rx) = mpsc::channel(1);
        let (_events, receiver) = broadcast::channel(1);
        let task = tokio::spawn(handle_local_client_with_timeouts(
            server,
            commands,
            receiver,
            connected_fixture(),
            None,
            short_ipc_timeouts(),
        ));
        write_request(&mut client, &IpcRequest::Stop).await.unwrap();
        assert!(matches!(command_rx.recv().await, Some(DaemonCommand::Stop)));
        let response = read_frame(&mut client, MAX_IPC_EVENT_SIZE).await.unwrap();
        let response: serde_json::Value = serde_json::from_slice(&response).unwrap();
        assert_eq!(response["type"], "stopping");
        assert!(response.get("outcome").is_none());
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn saturated_stop_queue_returns_not_started_without_false_success() {
        let (mut client, server) = tokio::io::duplex(1024);
        let (commands, mut command_rx) = mpsc::channel(1);
        commands.send(DaemonCommand::Stop).await.unwrap();
        let (_events, receiver) = broadcast::channel(1);
        let task = tokio::spawn(handle_local_client_with_timeouts(
            server,
            commands,
            receiver,
            connected_fixture(),
            None,
            short_ipc_timeouts(),
        ));
        write_request(&mut client, &IpcRequest::Stop).await.unwrap();
        let response = read_frame(&mut client, MAX_IPC_EVENT_SIZE).await.unwrap();
        let response: serde_json::Value = serde_json::from_slice(&response).unwrap();
        assert_eq!(response["type"], "error");
        assert_eq!(response["code"], "command_timeout");
        assert_eq!(response["outcome"], "not_started");
        assert!(matches!(command_rx.try_recv(), Ok(DaemonCommand::Stop)));
        assert!(command_rx.try_recv().is_err());
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn closed_stop_channel_returns_not_started_without_false_success() {
        let (mut client, server) = tokio::io::duplex(1024);
        let (commands, command_rx) = mpsc::channel(1);
        drop(command_rx);
        let (_events, receiver) = broadcast::channel(1);
        let task = tokio::spawn(handle_local_client_with_timeouts(
            server,
            commands,
            receiver,
            connected_fixture(),
            None,
            short_ipc_timeouts(),
        ));
        write_request(&mut client, &IpcRequest::Stop).await.unwrap();
        let response = read_frame(&mut client, MAX_IPC_EVENT_SIZE).await.unwrap();
        let response: serde_json::Value = serde_json::from_slice(&response).unwrap();
        assert_eq!(response["type"], "error");
        assert_eq!(response["code"], "daemon_stopping");
        assert_eq!(response["outcome"], "not_started");
        task.await.unwrap().unwrap();
    }
    struct PendingWriter;

    impl AsyncWrite for PendingWriter {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::task::Poll::Pending
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn blocked_capacity_rejection_write_is_bounded() {
        tokio::time::timeout(
            Duration::from_millis(200),
            reject_local_client_at_capacity(PendingWriter, Duration::from_millis(20)),
        )
        .await
        .expect("capacity rejection write did not respect its bound");
    }

    #[tokio::test]
    async fn ordinary_command_deadline_returns_error_and_releases_handler() {
        let (mut client, server) = tokio::io::duplex(1024);
        let (commands, mut command_rx) = mpsc::channel(1);
        let (_events, receiver) = broadcast::channel(1);
        let task = tokio::spawn(handle_local_client_with_timeouts(
            server,
            commands,
            receiver,
            connected_fixture(),
            None,
            short_ipc_timeouts(),
        ));
        write_request(&mut client, &IpcRequest::Status)
            .await
            .unwrap();
        let pending = command_rx.recv().await.unwrap();
        let response = read_frame(&mut client, MAX_IPC_EVENT_SIZE).await.unwrap();
        let response: serde_json::Value = serde_json::from_slice(&response).unwrap();
        assert_eq!(response["code"], "command_timeout");
        assert!(response.get("message").is_none());
        assert!(response.get("retryable").is_none());
        drop(pending);
        task.await.unwrap().unwrap();
    }

    #[cfg(any(unix, windows))]
    #[tokio::test]
    async fn platform_listener_shutdown_drains_and_aborts_handlers() {
        let dir = std::env::temp_dir().join(format!("meshmsg-ipc-drain-{}", rand::random::<u64>()));
        let state_lock = StateLock::acquire(&dir).unwrap();
        let (mut listener, guard) = bind_local_endpoint(&dir, &state_lock).await.unwrap();
        let limit = Arc::new(Semaphore::new(2));
        let (commands, mut command_rx) = mpsc::channel(1);
        let (events, _) = broadcast::channel(1);
        let preparations = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut tasks = tokio::task::JoinSet::new();
        let mut long_timeouts = short_ipc_timeouts();
        long_timeouts.initial_frame = Duration::from_secs(60);

        let (mut subscriber, admitted) = accept_and_admit_test_client(
            &mut listener,
            &dir,
            &limit,
            &mut tasks,
            &commands,
            &events,
            &preparations,
            long_timeouts,
        )
        .await;
        assert!(admitted);
        write_request(&mut subscriber, &IpcRequest::Subscribe)
            .await
            .unwrap();
        read_frame(&mut subscriber, MAX_IPC_EVENT_SIZE)
            .await
            .unwrap();
        let (idle, admitted) = accept_and_admit_test_client(
            &mut listener,
            &dir,
            &limit,
            &mut tasks,
            &commands,
            &events,
            &preparations,
            long_timeouts,
        )
        .await;
        assert!(admitted);

        limit.close();
        command_rx.close();
        drop(events);
        drain_local_client_tasks(&mut tasks, Duration::from_millis(50)).await;
        assert!(tasks.is_empty());
        assert!(limit.clone().try_acquire_owned().is_err());
        assert_eq!(Arc::strong_count(&limit), 1);

        drop(idle);
        drop(subscriber);
        drop(listener);
        guard.release_for_test();
        drop(state_lock);
        std::fs::remove_dir_all(dir).unwrap();
    }

    fn response_error(response: &meshmsg_protocol::Response) -> &meshmsg_protocol::ProtocolError {
        match response {
            meshmsg_protocol::Response::Error(error) => error,
            _ => panic!("expected protocol error"),
        }
    }

    #[tokio::test]
    async fn lifecycle_timeout_and_shutdown_errors_have_typed_retry_advice() {
        let (sender, receiver) = oneshot::channel::<meshmsg_protocol::Response>();
        let policy = CommandPolicy {
            deadline: Duration::from_millis(1),
            timeout_code: meshmsg_protocol::ErrorCode::AttachmentCommandTimeout,
            unavailable_code: meshmsg_protocol::ErrorCode::AttachmentStorageShutdown,
        };
        let operation_id = meshmsg_protocol::OperationId::new_random();
        let timeout_value = command_response(
            async move { Ok(receiver.await?) },
            policy,
            Some(operation_id.clone()),
        )
        .await;
        let timeout = response_error(&timeout_value);
        assert_eq!(
            timeout.code,
            meshmsg_protocol::ErrorCode::AttachmentCommandTimeout
        );
        assert_eq!(timeout.outcome, meshmsg_protocol::Outcome::Unknown);
        assert_eq!(
            timeout.retry_advice(),
            meshmsg_protocol::RetryAdvice::SameOperationReconciliation
        );
        drop(sender);

        let shutdown_value = command_response(
            async { anyhow::bail!("closed") },
            policy,
            Some(operation_id),
        )
        .await;
        let shutdown = response_error(&shutdown_value);
        assert_eq!(
            shutdown.code,
            meshmsg_protocol::ErrorCode::AttachmentStorageShutdown
        );
        assert_eq!(shutdown.outcome, meshmsg_protocol::Outcome::Unknown);
    }
}
