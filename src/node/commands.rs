//! Typed daemon commands and their execution policy.

use super::{operation_cache::request_fingerprint, runtime::Daemon};
use crate::{
    attachment::runtime::*,
    clock::{unix_timestamp_ms, unix_timestamp_ms_saturating},
    gossip, presence,
};
use anyhow::Result;
use meshmsg_protocol::{
    AttachmentToken, BroadcastBody, ErrorCode, OfferDirection, OfferId, OperationId, Outcome,
    PeerId, PrivateBody, ProtocolError, Queued, Recipient, Request, Response,
};
use std::{
    path::PathBuf,
    time::{Instant as StdInstant, SystemTime},
};
use tokio::sync::oneshot;

pub(crate) enum DaemonCommand {
    Execute {
        request: Request,
        reply: oneshot::Sender<Response>,
    },
    Stop,
}

fn operation_error(operation_id: OperationId, code: ErrorCode, outcome: Outcome) -> Response {
    Response::Error(ProtocolError::new(Some(operation_id), code, outcome))
}

impl Daemon {
    pub(super) async fn execute(
        &mut self,
        request: Request,
        reply: oneshot::Sender<Response>,
    ) -> Result<()> {
        let Some(&operation_id) = request.operation_id() else {
            return self.answer(request, reply);
        };
        // Every mutation is bound to its operation ID here, before any of its
        // work: a retry joins the in-flight operation or replays its terminal
        // response, and the same ID with any other input is a conflict.
        let admitted = match request_fingerprint(&request) {
            Ok(fingerprint) => {
                self.operation_cache
                    .admit(operation_id, fingerprint, reply, StdInstant::now())
            }
            Err(_) => {
                let _ = reply.send(operation_error(
                    operation_id,
                    ErrorCode::InvalidRequest,
                    Outcome::NotStarted,
                ));
                false
            }
        };
        if !admitted {
            return Ok(());
        }
        match request {
            Request::Send { body, .. } => self.send(operation_id, body).await,
            Request::PrivateSend { to, body, .. } => self.private_send(operation_id, to, body),
            Request::OffersRemove {
                offer_id,
                direction,
                provider,
                ..
            } => self.offers_remove(operation_id, offer_id, direction, provider),
            Request::OffersPrune {
                older_than_secs,
                direction,
                dry_run,
                max_delete,
                ..
            } => self.offers_prune(
                operation_id,
                older_than_secs,
                direction,
                dry_run,
                max_delete,
            ),
            Request::Share { path, .. } => self.share(operation_id, path),
            Request::Download { offer, output, .. } => self.download(operation_id, offer, output),
            // Requests without an operation ID were answered above.
            Request::Subscribe
            | Request::Status
            | Request::Peers
            | Request::Offers
            | Request::Stop => {}
        }
        Ok(())
    }

    /// Answers a request that has no operation ID and therefore no cache entry.
    fn answer(&mut self, request: Request, reply: oneshot::Sender<Response>) -> Result<()> {
        match request {
            Request::Status => self.status(reply),
            Request::Peers => self.peers(reply),
            Request::Offers => {
                self.offers(reply);
                Ok(())
            }
            // The IPC session serves `Subscribe` and `Stop` itself; mutations
            // never reach this function.
            _ => {
                let _ = reply.send(Response::Error(ProtocolError::new(
                    None,
                    ErrorCode::InvalidRequest,
                    Outcome::NotStarted,
                )));
                Ok(())
            }
        }
    }

    /// Completes an admitted operation and publishes the event it announces.
    fn finish(&mut self, operation_id: OperationId, response: Response) {
        self.operation_cache
            .finish(operation_id, response, &self.event_tx);
    }

    async fn send(&mut self, operation_id: OperationId, body: BroadcastBody) {
        let response = match self.broadcast(operation_id, body).await {
            Ok(queued) => Response::Queued(queued),
            Err((code, outcome)) => operation_error(operation_id, code, outcome),
        };
        self.finish(operation_id, response);
    }

    async fn broadcast(
        &self,
        operation_id: OperationId,
        body: BroadcastBody,
    ) -> Result<Queued, (ErrorCode, Outcome)> {
        const INVALID: (ErrorCode, Outcome) = (ErrorCode::InvalidMessage, Outcome::NotStarted);
        let timestamp_ms = unix_timestamp_ms().map_err(|_| INVALID)?;
        let envelope = gossip::Envelope::encode_message_with_id_at(
            &self.node.secret,
            self.topic,
            body.clone().into_string(),
            operation_id.to_bytes(),
            timestamp_ms,
        )
        .map_err(|_| INVALID)?;
        self.node
            .sender
            .broadcast(envelope)
            .await
            .map_err(|_| (ErrorCode::SendFailed, Outcome::Unknown))?;
        Ok(gossip::queued_event(
            self.peer,
            operation_id,
            body,
            timestamp_ms,
        ))
    }

    fn private_send(&mut self, operation_id: OperationId, to: Recipient, body: PrivateBody) {
        self.expire_peers();
        let Ok(address) = self.directory.resolve(to.as_str()) else {
            let error = operation_error(
                operation_id,
                ErrorCode::RecipientUnresolved,
                Outcome::NotStarted,
            );
            return self.finish(operation_id, error);
        };
        let permit = match self.direct_sender.try_reserve(operation_id) {
            Ok(permit) => permit,
            Err(error) => return self.finish(operation_id, Response::Error(error)),
        };
        self.tasks.spawn_operation(
            "private send",
            operation_id,
            ErrorCode::PrivateSendFailed,
            async move { permit.send(address, body.into_string(), operation_id).await },
        );
    }

    fn status(&self, reply: oneshot::Sender<Response>) -> Result<()> {
        let node = &self.node;
        let connectivity = presence::local_connectivity(&node.endpoint, &node.receiver);
        let status = meshmsg_protocol::Status {
            peer: self.peer,
            topic: self.state.topic,
            advertises_self: self.state.advertise_self,
            has_invite: self.has_invite,
            bootstrap_peer_count: self.bootstrap_peer_count,
            self_advertised: self.self_advertised,
            neighbors: node.receiver.neighbors().count(),
            endpoint_online: connectivity.endpoint_online,
            topic_joined: connectivity.topic_joined,
            alias: self.alias_config.effective().map(str::parse).transpose()?,
            alias_enabled: self.alias_config.enabled(),
            captured_hostname: self.alias_config.hostname().map(str::to_owned),
            custom_alias: self.alias_config.custom().map(str::to_owned),
            advertised_aliases: self.directory.advertised_aliases(),
            max_attachment_bytes: self.max_attachment_bytes,
            attachment_storage: self.attachment_storage.status(),
            attachment_retention_secs: self.attachment_retention_secs,
        };
        status.validate().map_err(anyhow::Error::msg)?;
        let _ = reply.send(Response::Status(status));
        Ok(())
    }

    fn peers(&mut self, reply: oneshot::Sender<Response>) -> Result<()> {
        self.expire_peers();
        let generated_at_ms = unix_timestamp_ms()?;
        let _ = reply.send(Response::PeersSnapshot(self.directory.snapshot(
            presence::local_connectivity(&self.node.endpoint, &self.node.receiver),
            self.peer,
            self.alias_config.effective(),
            generated_at_ms,
        )));
        Ok(())
    }

    fn offers(&mut self, reply: oneshot::Sender<Response>) {
        let permit = match try_admit_offer_listing(&self.offer_list_limit) {
            Ok(permit) => permit,
            Err(error) => {
                let _ = reply.send(Response::Error(error));
                return;
            }
        };
        let store = self.node.blob_store.clone();
        self.tasks.spawn_offer_list(reply, async move {
            let _permit = permit;
            list_offers_request(store).await
        });
    }

    fn offers_remove(
        &mut self,
        operation_id: OperationId,
        offer_id: OfferId,
        direction: Option<OfferDirection>,
        provider: Option<PeerId>,
    ) {
        let storage = self.attachment_storage.clone();
        self.tasks.spawn_operation(
            "attachment offer removal",
            operation_id,
            ErrorCode::AttachmentLifecycleInternal,
            async move {
                remove_offer_request(storage, operation_id, offer_id, direction, provider).await
            },
        );
    }

    fn offers_prune(
        &mut self,
        operation_id: OperationId,
        older_than_secs: Option<u64>,
        direction: Option<OfferDirection>,
        dry_run: bool,
        max_delete: usize,
    ) {
        // Resolved once by the admitted owner. Retries replay the cached
        // terminal response, so neither the default age nor the cutoff is
        // derived a second time.
        let age = older_than_secs.unwrap_or(self.attachment_retention_secs);
        let cutoff = crate::attachment::prune_cutoff_upper_bound(
            unix_timestamp_ms_saturating(SystemTime::now()),
            age,
        );
        let storage = self.attachment_storage.clone();
        self.tasks.spawn_operation(
            "attachment offer pruning",
            operation_id,
            ErrorCode::AttachmentLifecycleInternal,
            async move {
                prune_offers_request(
                    storage,
                    operation_id,
                    age,
                    cutoff,
                    direction,
                    dry_run,
                    max_delete,
                )
                .await
            },
        );
    }

    /// Reserves one of the concurrent share/download slots, or completes the
    /// operation as busy.
    fn admit_transfer(
        &mut self,
        operation_id: OperationId,
    ) -> Option<tokio::sync::OwnedSemaphorePermit> {
        let permit = try_admit_transfer(&self.transfer_limit).ok();
        if permit.is_none() {
            let error = operation_error(
                operation_id,
                ErrorCode::AttachmentStorageBusy,
                Outcome::NotStarted,
            );
            self.finish(operation_id, error);
        }
        permit
    }

    fn share(&mut self, operation_id: OperationId, path: PathBuf) {
        let Some(permit) = self.admit_transfer(operation_id) else {
            return;
        };
        let resources = ShareResources {
            store: self.node.blob_store.clone(),
            storage: self.attachment_storage.clone(),
            endpoint: self.node.endpoint.clone(),
            secret: self.node.secret.clone(),
            topic: self.topic,
            sender: self.node.sender.clone(),
            state_dir: self.dir.clone(),
        };
        let max_attachment_bytes = self.max_attachment_bytes;
        self.tasks.spawn_operation(
            "attachment share",
            operation_id,
            ErrorCode::ShareFailed,
            async move {
                let _permit = permit;
                share_request(resources, operation_id, path, max_attachment_bytes).await
            },
        );
    }

    fn download(&mut self, operation_id: OperationId, offer: AttachmentToken, output: PathBuf) {
        // Validate before transfer admission: an input that can never
        // succeed must not be reported as a transient busy condition.
        let offer = match parse_download_offer(operation_id, &offer, self.topic) {
            Ok(offer) => offer,
            Err(error) => return self.finish(operation_id, Response::Error(error)),
        };
        let Some(permit) = self.admit_transfer(operation_id) else {
            return;
        };
        let resources = DownloadResources {
            store: self.node.blob_store.clone(),
            storage: self.attachment_storage.clone(),
            downloader: self.node.downloader.clone(),
            endpoint: self.node.endpoint.clone(),
            lookup: self.node.lookup.clone(),
        };
        let events = self.event_tx.clone();
        let max_attachment_bytes = self.max_attachment_bytes;
        self.tasks.spawn_operation(
            "attachment download",
            operation_id,
            ErrorCode::DownloadFailed,
            async move {
                let _permit = permit;
                download_request(
                    resources,
                    events,
                    operation_id,
                    offer,
                    output,
                    max_attachment_bytes,
                )
                .await
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        direct,
        ipc::{
            read_frame,
            server::{handle_local_client, LocalClientSession, LocalIpcTimeouts},
            write_request, MAX_IPC_EVENT_SIZE,
        },
    };
    use iroh::{EndpointAddr, SecretKey};
    use tokio::sync::mpsc;

    /// Executes one request the way the daemon loop does and returns its response.
    async fn execute(daemon: &mut Daemon, request: Request) -> Response {
        let (reply, mut response) = oneshot::channel();
        daemon.execute(request, reply).await.unwrap();
        loop {
            if let Ok(response) = response.try_recv() {
                return response;
            }
            let joined = daemon.tasks.join_next().await;
            daemon.complete_task(joined.expect("an unanswered request has a running task"));
        }
    }

    fn expect_error(response: Response, operation_id: OperationId) -> (ErrorCode, Outcome) {
        let Response::Error(error) = response else {
            panic!("expected a protocol error, got {response:?}")
        };
        assert_eq!(error.operation_id, Some(operation_id));
        (error.code, error.outcome)
    }

    #[tokio::test]
    async fn private_send_saturation_preserves_operation_id_through_full_ipc_path() {
        let mut daemon = Daemon::start_for_test().await;
        let mut held = Vec::new();
        for _ in 0..direct::SEND_CONCURRENCY {
            held.push(
                daemon
                    .direct_sender
                    .try_reserve(OperationId::new_random())
                    .unwrap(),
            );
        }
        let recipient = SecretKey::generate().public();
        daemon
            .directory
            .pin(EndpointAddr::new(recipient).with_ip_addr("127.0.0.1:7777".parse().unwrap()))
            .unwrap();

        let (mut client, server) = tokio::io::duplex(4096);
        let (commands, mut command_rx) = mpsc::channel(1);
        let client_task = tokio::spawn(handle_local_client(
            server,
            LocalClientSession {
                commands,
                events: daemon.event_tx.subscribe(),
                connected: meshmsg_protocol::Event::Connected(meshmsg_protocol::Connected {
                    peer: daemon.peer,
                    endpoint_online: true,
                    topic_joined: true,
                    alias: None,
                }),
                startup_peers: None,
            },
            LocalIpcTimeouts::default(),
        ));
        let operation_id = OperationId::new_random();
        let request = Request::PrivateSend {
            operation_id,
            to: recipient.to_string().parse().unwrap(),
            body: PrivateBody::new("saturated").unwrap(),
        };
        write_request(
            &mut client,
            &request,
            meshmsg_protocol::RequestId::new_random(),
        )
        .await
        .unwrap();

        let Some(DaemonCommand::Execute {
            request: received,
            reply,
        }) = command_rx.recv().await
        else {
            panic!("expected the private-send command")
        };
        daemon.execute(received, reply).await.unwrap();
        assert!(daemon.tasks.is_empty());

        let frame = read_frame(&mut client, MAX_IPC_EVENT_SIZE).await.unwrap();
        let frame: meshmsg_protocol::ResponseFrame = serde_json::from_slice(&frame).unwrap();
        assert!(request.validate_response(&frame.response).is_ok());
        assert_eq!(
            expect_error(frame.response, operation_id),
            (ErrorCode::PrivateSendBusy, Outcome::NotStarted)
        );

        client_task.await.unwrap().unwrap();
        drop(held);
        daemon.stop_for_test().await;
    }

    #[tokio::test]
    async fn prune_without_an_age_resolves_the_configured_retention_in_the_daemon() {
        let mut daemon = Daemon::start_for_test().await;
        let default_age = OperationId::new_random();
        let disabled_retention = OperationId::new_random();
        // (operation, submitted age, configured retention, expected effective age)
        let cases = [
            (default_age, None, 7, Some(7)),
            // An explicit age equal to the default is still different input.
            (default_age, Some(7), 7, None),
            // An exact retry replays the original resolution, even if the
            // configured retention were to differ.
            (default_age, None, 9, Some(7)),
            (disabled_retention, None, 0, Some(0)),
        ];
        let mut first_resolution = None;
        for (operation_id, older_than_secs, attachment_retention_secs, expected_age) in cases {
            daemon.attachment_retention_secs = attachment_retention_secs;
            let before_ms = unix_timestamp_ms().unwrap();
            let response = execute(
                &mut daemon,
                Request::OffersPrune {
                    operation_id,
                    older_than_secs,
                    direction: None,
                    dry_run: true,
                    max_delete: 1,
                },
            )
            .await;
            match (response, expected_age) {
                (Response::OffersPruned(pruned), Some(age)) => {
                    assert_eq!(pruned.operation_id, operation_id);
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
                (response, None) => assert_eq!(
                    expect_error(response, operation_id),
                    (ErrorCode::OperationIdConflict, Outcome::NotStarted)
                ),
                (response, _) => panic!("unexpected prune response: {response:?}"),
            }
        }
        // Two admitted operations ran; the exact retry replayed the first.
        assert_eq!(daemon.operation_cache.counts(), (0, 2));
        daemon.stop_for_test().await;
    }

    #[tokio::test]
    async fn invalid_download_offer_is_rejected_before_transfer_admission_and_replayed() {
        let mut daemon = Daemon::start_for_test().await;
        let mut events = daemon.event_tx.subscribe();
        let held = [
            try_admit_transfer(&daemon.transfer_limit).unwrap(),
            try_admit_transfer(&daemon.transfer_limit).unwrap(),
        ];

        // The limit really is saturated: a well-formed transfer is busy.
        let share = OperationId::new_random();
        let busy = execute(
            &mut daemon,
            Request::Share {
                operation_id: share,
                path: std::env::temp_dir().join("meshmsg-saturated-share"),
            },
        )
        .await;
        assert_eq!(
            expect_error(busy, share),
            (ErrorCode::AttachmentStorageBusy, Outcome::NotStarted)
        );

        // An offer that can never succeed is reported as such, not as busy,
        // and a retry of the same operation replays that result.
        let download = OperationId::new_random();
        let request = Request::Download {
            operation_id: download,
            offer: "not-a-signed-offer".parse().unwrap(),
            output: std::env::temp_dir().join("meshmsg-invalid-offer-output"),
        };
        for _attempt in ["first", "retry"] {
            let response = execute(&mut daemon, request.clone()).await;
            assert_eq!(
                expect_error(response, download),
                (ErrorCode::InvalidAttachmentOffer, Outcome::NotStarted)
            );
        }
        assert_eq!(daemon.operation_cache.counts(), (0, 2));
        assert!(daemon.tasks.is_empty());
        assert!(events.try_recv().is_err(), "a rejected transfer is silent");

        drop(held);
        daemon.stop_for_test().await;
    }
}
