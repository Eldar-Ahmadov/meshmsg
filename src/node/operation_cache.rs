use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, VecDeque},
    time::{Duration, Instant as StdInstant},
};
use tokio::sync::{broadcast, oneshot};

struct CompletedOperation {
    fingerprint: [u8; 32],
    response: meshmsg_protocol::Response,
    expires_at: StdInstant,
}

struct InFlightOperation {
    fingerprint: [u8; 32],
    waiters: Vec<oneshot::Sender<meshmsg_protocol::Response>>,
}

/// Binds an operation ID to everything its request submitted: the canonical
/// JSON form names the request kind and every field, keeps an omitted option
/// distinct from an explicit value, and spells IPC paths (absolute UTF-8)
/// exactly. The digest only lives in this daemon's memory, so its derivation
/// is not a format. Serialization fails only for a non-UTF-8 path, which a
/// request decoded from IPC cannot carry.
pub(super) fn request_fingerprint(
    request: &meshmsg_protocol::Request,
) -> serde_json::Result<[u8; 32]> {
    let mut digest = Sha256::new();
    digest.update(b"meshmsg-operation-v2\0");
    digest.update(serde_json::to_vec(request)?);
    Ok(digest.finalize().into())
}

pub(super) struct OperationCache {
    capacity: usize,
    ttl: Duration,
    completed: HashMap<meshmsg_protocol::OperationId, CompletedOperation>,
    order: VecDeque<meshmsg_protocol::OperationId>,
    in_flight: HashMap<meshmsg_protocol::OperationId, InFlightOperation>,
}

impl OperationCache {
    pub(super) fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            capacity,
            ttl,
            completed: HashMap::new(),
            order: VecDeque::new(),
            in_flight: HashMap::new(),
        }
    }

    fn prune(&mut self, now: StdInstant) {
        self.completed.retain(|_, entry| entry.expires_at > now);
        self.order.retain(|id| self.completed.contains_key(id));
    }

    fn error(
        operation_id: meshmsg_protocol::OperationId,
        code: meshmsg_protocol::ErrorCode,
    ) -> meshmsg_protocol::Response {
        meshmsg_protocol::Response::Error(meshmsg_protocol::ProtocolError::new(
            Some(operation_id),
            code,
            meshmsg_protocol::Outcome::NotStarted,
        ))
    }

    /// Returns true only for the first caller that must execute the operation.
    pub(super) fn admit(
        &mut self,
        operation_id: meshmsg_protocol::OperationId,
        fingerprint: [u8; 32],
        reply: oneshot::Sender<meshmsg_protocol::Response>,
        now: StdInstant,
    ) -> bool {
        self.prune(now);
        if let Some(entry) = self.completed.get(&operation_id) {
            let response = if entry.fingerprint == fingerprint {
                entry.response.clone()
            } else {
                Self::error(
                    operation_id,
                    meshmsg_protocol::ErrorCode::OperationIdConflict,
                )
            };
            let _ = reply.send(response);
            return false;
        }
        if let Some(entry) = self.in_flight.get_mut(&operation_id) {
            if entry.fingerprint == fingerprint {
                entry.waiters.push(reply);
            } else {
                let _ = reply.send(Self::error(
                    operation_id,
                    meshmsg_protocol::ErrorCode::OperationIdConflict,
                ));
            }
            return false;
        }
        while self.completed.len() + self.in_flight.len() >= self.capacity {
            let Some(oldest) = self.order.pop_front() else {
                let _ = reply.send(Self::error(
                    operation_id,
                    meshmsg_protocol::ErrorCode::OperationCapacity,
                ));
                return false;
            };
            self.completed.remove(&oldest);
        }
        self.in_flight.insert(
            operation_id,
            InFlightOperation {
                fingerprint,
                waiters: vec![reply],
            },
        );
        true
    }

    /// Answers every waiter of an in-flight operation and retains the response
    /// for retries. Returns it only for that first completion.
    fn complete(
        &mut self,
        operation_id: meshmsg_protocol::OperationId,
        response: meshmsg_protocol::Response,
        now: StdInstant,
    ) -> Option<meshmsg_protocol::Response> {
        let in_flight = self.in_flight.remove(&operation_id)?;
        for waiter in in_flight.waiters {
            let _ = waiter.send(response.clone());
        }
        self.completed.insert(
            operation_id,
            CompletedOperation {
                fingerprint: in_flight.fingerprint,
                response: response.clone(),
                expires_at: now + self.ttl,
            },
        );
        self.order.push_back(operation_id);
        Some(response)
    }

    /// Completes an admitted operation and publishes the event its response
    /// announces. Retries are answered by `admit` from the retained response,
    /// so each operation publishes at most once.
    pub(super) fn finish(
        &mut self,
        operation_id: meshmsg_protocol::OperationId,
        response: meshmsg_protocol::Response,
        events: &broadcast::Sender<meshmsg_protocol::Event>,
    ) {
        use meshmsg_protocol::{Event, Response};

        let event = match self.complete(operation_id, response, StdInstant::now()) {
            Some(Response::Queued(queued)) => Event::Queued(queued),
            Some(Response::AttachmentShared(shared)) => Event::AttachmentShared(shared),
            Some(Response::DownloadComplete(download)) => Event::DownloadComplete(download),
            // Errors and the remaining acknowledgements announce nothing.
            Some(
                Response::PrivateAccepted(_)
                | Response::OfferRemoved(_)
                | Response::OffersPruned(_)
                | Response::Status(_)
                | Response::PeersSnapshot(_)
                | Response::Offers(_)
                | Response::Stopping {}
                | Response::Error(_),
            )
            | None => return,
        };
        let _ = events.send(event);
    }

    #[cfg(test)]
    pub(super) fn counts(&self) -> (usize, usize) {
        (self.in_flight.len(), self.completed.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::unix_timestamp_ms_saturating;
    use meshmsg_protocol::{OfferDirection, OperationId, Request};
    use std::{path::PathBuf, time::UNIX_EPOCH};

    fn response_value(response: &meshmsg_protocol::Response) -> serde_json::Value {
        serde_json::to_value(response).unwrap()
    }

    fn response_error(response: &meshmsg_protocol::Response) -> &meshmsg_protocol::ProtocolError {
        match response {
            meshmsg_protocol::Response::Error(error) => error,
            _ => panic!("expected protocol error"),
        }
    }

    fn fingerprint(request: &Request) -> [u8; 32] {
        request_fingerprint(request).unwrap()
    }

    fn send(operation_id: OperationId, body: &str) -> [u8; 32] {
        fingerprint(&Request::Send {
            operation_id,
            body: meshmsg_protocol::BroadcastBody::new(body).unwrap(),
        })
    }

    fn download(operation_id: OperationId, offer: &str, output: &str) -> [u8; 32] {
        fingerprint(&Request::Download {
            operation_id,
            offer: offer.parse().unwrap(),
            output: PathBuf::from(output),
        })
    }

    fn prune(operation_id: OperationId, older_than_secs: Option<u64>) -> [u8; 32] {
        fingerprint(&Request::OffersPrune {
            operation_id,
            older_than_secs,
            direction: Some(OfferDirection::Outgoing),
            dry_run: false,
            max_delete: 1,
        })
    }

    /// IDs are global across kinds, and every submitted input is represented
    /// without Option ambiguity or path/token normalization.
    #[test]
    fn request_fingerprint_binds_the_kind_and_every_submitted_input() {
        let operation_id: OperationId = "11111111111111111111111111111111".parse().unwrap();
        let offer_id: meshmsg_protocol::OfferId =
            "22222222222222222222222222222222".parse().unwrap();
        let peer = |digit: &str| {
            digit
                .repeat(64)
                .parse::<meshmsg_protocol::PeerId>()
                .unwrap()
        };
        let private = |to: &str, body: &str| Request::PrivateSend {
            operation_id,
            to: to.parse().unwrap(),
            body: meshmsg_protocol::PrivateBody::new(body).unwrap(),
        };
        let remove = |offer_id, direction, provider| Request::OffersRemove {
            operation_id,
            offer_id,
            direction,
            provider,
        };
        let prune = |older_than_secs, direction, dry_run, max_delete| Request::OffersPrune {
            operation_id,
            older_than_secs,
            direction,
            dry_run,
            max_delete,
        };
        let share = |path: &str| Request::Share {
            operation_id,
            path: PathBuf::from(path),
        };
        let download = |offer: &str, output: &str| Request::Download {
            operation_id,
            offer: offer.parse().unwrap(),
            output: PathBuf::from(output),
        };
        // Each request differs from the first of its kind in exactly one input.
        let requests = [
            Request::Send {
                operation_id,
                body: meshmsg_protocol::BroadcastBody::new("one").unwrap(),
            },
            Request::Send {
                operation_id,
                body: meshmsg_protocol::BroadcastBody::new("two").unwrap(),
            },
            private("alice", "one"),
            private("bob", "one"),
            private("alice", "two"),
            remove(offer_id, None, None),
            remove(
                "33333333333333333333333333333333".parse().unwrap(),
                None,
                None,
            ),
            remove(offer_id, Some(OfferDirection::Incoming), None),
            remove(offer_id, Some(OfferDirection::Outgoing), None),
            remove(offer_id, None, Some(peer("4"))),
            remove(offer_id, None, Some(peer("5"))),
            prune(None, None, false, 1),
            // An omitted age and an explicit one never share an operation ID.
            prune(Some(0), None, false, 1),
            prune(Some(1), None, false, 1),
            prune(None, Some(OfferDirection::Incoming), false, 1),
            prune(None, None, true, 1),
            prune(None, None, false, 2),
            share("/tmp/one"),
            share("/tmp/two"),
            share("/tmp/./one"),
            download("token", "/tmp/one"),
            download("changed-token", "/tmp/one"),
            download("token", "/tmp/two"),
            download("token", "/tmp/one/"),
            // The same text under another kind is a different request.
            download("one", "/tmp/one"),
            share("/tmp/token"),
        ];
        let fingerprints: Vec<_> = requests.iter().map(fingerprint).collect();
        for (index, request) in requests.iter().enumerate() {
            assert_eq!(
                fingerprints[index],
                fingerprint(&request.clone()),
                "an identical request must join or replay: {request:?}"
            );
            for other in index + 1..requests.len() {
                assert_ne!(
                    fingerprints[index], fingerprints[other],
                    "changed input must conflict: {request:?} vs {:?}",
                    requests[other]
                );
            }
        }
    }

    #[tokio::test]
    async fn operation_cache_joins_conflicts_caches_terminal_outcomes_and_bounds_retention() {
        let now = StdInstant::now();
        let mut cache = OperationCache::new(2, Duration::from_secs(10));
        let id1: meshmsg_protocol::OperationId =
            "11111111111111111111111111111111".parse().unwrap();
        let id2: meshmsg_protocol::OperationId =
            "22222222222222222222222222222222".parse().unwrap();
        let id3: meshmsg_protocol::OperationId =
            "33333333333333333333333333333333".parse().unwrap();
        let fp1 = send(id1, "one");
        let different = send(id1, "different");

        let (reply1, response1) = oneshot::channel();
        assert!(cache.admit(id1, fp1, reply1, now));
        let (duplicate, duplicate_response) = oneshot::channel();
        assert!(!cache.admit(id1, fp1, duplicate, now));
        let (conflict, conflict_response) = oneshot::channel();
        assert!(!cache.admit(id1, different, conflict, now));
        assert_eq!(
            response_error(&conflict_response.await.unwrap()).code,
            meshmsg_protocol::ErrorCode::OperationIdConflict,
        );

        let terminal = meshmsg_protocol::Response::Error(meshmsg_protocol::ProtocolError::new(
            Some(id1),
            meshmsg_protocol::ErrorCode::SendFailed,
            meshmsg_protocol::Outcome::Unknown,
        ));
        let stored = cache.complete(id1, terminal, now).unwrap();
        assert_eq!(response_error(&stored).operation_id, Some(id1));
        assert_eq!(response1.await.unwrap(), stored);
        assert_eq!(duplicate_response.await.unwrap(), stored);
        let (cached, cached_response) = oneshot::channel();
        assert!(!cache.admit(id1, fp1, cached, now));
        assert_eq!(cached_response.await.unwrap(), stored);

        let partial = meshmsg_protocol::Response::Error(meshmsg_protocol::ProtocolError::new(
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".parse().unwrap()),
            meshmsg_protocol::ErrorCode::DownloadFailed,
            meshmsg_protocol::Outcome::Partial,
        ));
        let partial_id: meshmsg_protocol::OperationId =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".parse().unwrap();
        let partial_fp = download(partial_id, "token", "/tmp/output");
        let mut partial_cache = OperationCache::new(2, Duration::from_secs(10));
        let (partial_reply, partial_response) = oneshot::channel();
        assert!(partial_cache.admit(partial_id, partial_fp, partial_reply, now));
        let partial = partial_cache.complete(partial_id, partial, now).unwrap();
        assert_eq!(partial_response.await.unwrap(), partial);
        let (partial_retry, partial_retry_response) = oneshot::channel();
        assert!(!partial_cache.admit(partial_id, partial_fp, partial_retry, now));
        assert_eq!(partial_retry_response.await.unwrap(), partial);

        let removal_id: meshmsg_protocol::OperationId =
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".parse().unwrap();
        let removal_fp = fingerprint(&Request::OffersRemove {
            operation_id: removal_id,
            offer_id: "dddddddddddddddddddddddddddddddd".parse().unwrap(),
            direction: None,
            provider: None,
        });
        let (removal_reply, removal_response) = oneshot::channel();
        assert!(partial_cache.admit(removal_id, removal_fp, removal_reply, now));
        let removal = partial_cache
            .complete(
                removal_id,
                meshmsg_protocol::Response::Error(meshmsg_protocol::ProtocolError::new(
                    None,
                    meshmsg_protocol::ErrorCode::AttachmentRemovalPartial,
                    meshmsg_protocol::Outcome::Partial,
                )),
                now,
            )
            .unwrap();
        assert_eq!(removal_response.await.unwrap(), removal);
        let (removal_retry, removal_retry_response) = oneshot::channel();
        assert!(!partial_cache.admit(removal_id, removal_fp, removal_retry, now));
        assert_eq!(removal_retry_response.await.unwrap(), removal);

        let fp2 = send(id2, "two");
        let (reply2, _response2) = oneshot::channel();
        assert!(cache.admit(id2, fp2, reply2, now));
        cache.complete(
            id2,
            meshmsg_protocol::Response::Error(meshmsg_protocol::ProtocolError::new(
                Some(id2),
                meshmsg_protocol::ErrorCode::SendFailed,
                meshmsg_protocol::Outcome::Unknown,
            )),
            now,
        );
        let fp3 = send(id3, "three");
        let (reply3, _response3) = oneshot::channel();
        assert!(cache.admit(id3, fp3, reply3, now));
        assert!(
            !cache.completed.contains_key(&id1),
            "oldest terminal entry was not evicted"
        );

        let mut expired = OperationCache::new(2, Duration::from_millis(1));
        let (reply, _response) = oneshot::channel();
        assert!(expired.admit(id1, fp1, reply, now));
        expired.complete(
            id1,
            meshmsg_protocol::Response::Error(meshmsg_protocol::ProtocolError::new(
                Some(id1),
                meshmsg_protocol::ErrorCode::SendFailed,
                meshmsg_protocol::Outcome::Unknown,
            )),
            now,
        );
        let (retry, _retry_response) = oneshot::channel();
        assert!(expired.admit(id1, fp1, retry, now + Duration::from_millis(2)));

        // The cache is intentionally daemon-lifetime scoped. A fresh daemon
        // admits the same ID again; status/docs tell clients not to infer
        // restart-persistent idempotency.
        let mut restarted = OperationCache::new(2, Duration::from_secs(10));
        let (retry, _retry_response) = oneshot::channel();
        assert!(restarted.admit(id1, fp1, retry, now));
    }

    #[tokio::test]
    async fn finishing_an_operation_publishes_its_event_once_and_never_for_errors_or_replays() {
        let (events, mut published) = broadcast::channel(4);
        let mut cache = OperationCache::new(4, Duration::from_secs(60));
        let now = StdInstant::now();

        let queued_id = OperationId::new_random();
        let queued = crate::gossip::queued_event(
            meshmsg_protocol::PeerId::from_bytes([0x11; 32]),
            queued_id,
            meshmsg_protocol::BroadcastBody::new("hello").unwrap(),
            1_700_000_000_000,
        );
        let terminal = meshmsg_protocol::Response::Queued(queued.clone());
        let fp = send(queued_id, "hello");
        let (owner, owner_response) = oneshot::channel();
        assert!(cache.admit(queued_id, fp, owner, now));
        let (joined, joined_response) = oneshot::channel();
        assert!(!cache.admit(queued_id, fp, joined, now));
        cache.finish(queued_id, terminal.clone(), &events);
        assert_eq!(owner_response.await.unwrap(), terminal);
        assert_eq!(joined_response.await.unwrap(), terminal);
        assert_eq!(
            published.try_recv().unwrap(),
            meshmsg_protocol::Event::Queued(queued)
        );

        // A retry replays the response without announcing it again, and a
        // stray second completion is ignored.
        let (retry, retry_response) = oneshot::channel();
        assert!(!cache.admit(queued_id, fp, retry, now));
        assert_eq!(retry_response.await.unwrap(), terminal);
        cache.finish(queued_id, terminal, &events);
        assert!(published.try_recv().is_err());

        let failed_id = OperationId::new_random();
        let failed_fp = send(failed_id, "hello");
        let (failed, failed_response) = oneshot::channel();
        assert!(cache.admit(failed_id, failed_fp, failed, now));
        let error = OperationCache::error(failed_id, meshmsg_protocol::ErrorCode::SendFailed);
        cache.finish(failed_id, error.clone(), &events);
        assert_eq!(failed_response.await.unwrap(), error);
        assert!(published.try_recv().is_err());
        assert_eq!(cache.counts(), (0, 2));
    }

    #[tokio::test]
    async fn operation_capacity_is_pre_admission_and_same_id_can_be_retried() {
        let active_id: meshmsg_protocol::OperationId =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".parse().unwrap();
        let rejected_id: meshmsg_protocol::OperationId =
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".parse().unwrap();
        let active_fingerprint = send(active_id, "active");
        let rejected_fingerprint = send(rejected_id, "rejected");
        let now = StdInstant::now();
        let mut cache = OperationCache::new(1, Duration::from_secs(60));

        let (active, _active_response) = oneshot::channel();
        assert!(cache.admit(active_id, active_fingerprint, active, now));
        let (rejected, rejected_response) = oneshot::channel();
        assert!(!cache.admit(rejected_id, rejected_fingerprint, rejected, now));
        let rejection = rejected_response.await.unwrap();
        assert_eq!(
            response_error(&rejection).code,
            meshmsg_protocol::ErrorCode::OperationCapacity
        );
        assert_eq!(
            response_error(&rejection).retry_advice(),
            meshmsg_protocol::RetryAdvice::RetrySameRequest
        );
        assert_eq!(cache.counts(), (1, 0));

        cache.complete(
            active_id,
            meshmsg_protocol::Response::Error(meshmsg_protocol::ProtocolError::new(
                Some(active_id),
                meshmsg_protocol::ErrorCode::SendFailed,
                meshmsg_protocol::Outcome::Unknown,
            )),
            now,
        );
        let (retry, _retry_response) = oneshot::channel();
        assert!(cache.admit(rejected_id, rejected_fingerprint, retry, now));
    }

    #[tokio::test]
    async fn cached_not_started_failure_stays_bound_but_advises_a_new_operation() {
        let operation_id: meshmsg_protocol::OperationId =
            "cccccccccccccccccccccccccccccccc".parse().unwrap();
        let fingerprint = download(operation_id, "offer", "/tmp/output");
        let different = download(operation_id, "offer", "/tmp/other-output");
        let now = StdInstant::now();
        let mut cache = OperationCache::new(2, Duration::from_secs(60));

        let (owner, _owner_response) = oneshot::channel();
        assert!(cache.admit(operation_id, fingerprint, owner, now));
        let terminal = meshmsg_protocol::Response::Error(meshmsg_protocol::ProtocolError::new(
            Some(operation_id),
            meshmsg_protocol::ErrorCode::DownloadFailed,
            meshmsg_protocol::Outcome::NotStarted,
        ));
        cache.complete(operation_id, terminal.clone(), now);

        let (same, same_response) = oneshot::channel();
        assert!(!cache.admit(operation_id, fingerprint, same, now));
        let replay = same_response.await.unwrap();
        assert_eq!(replay, terminal);
        assert_eq!(
            response_error(&replay).retry_advice(),
            meshmsg_protocol::RetryAdvice::NewOperationAfterConditionsChange
        );

        let (changed, changed_response) = oneshot::channel();
        assert!(!cache.admit(operation_id, different, changed, now));
        assert_eq!(
            response_error(&changed_response.await.unwrap()).code,
            meshmsg_protocol::ErrorCode::OperationIdConflict
        );
        assert_eq!(cache.counts(), (0, 1));
    }

    #[test]
    fn lifecycle_partial_errors_are_compact_across_operation_cache() {
        let operation: meshmsg_protocol::OperationId =
            "11111111111111111111111111111111".parse().unwrap();
        let producer = meshmsg_protocol::ProtocolError::new(
            Some(operation),
            meshmsg_protocol::ErrorCode::AttachmentRemovalPartial,
            meshmsg_protocol::Outcome::Partial,
        );
        let mut cache = OperationCache::new(2, Duration::from_secs(60));
        let now = StdInstant::now();
        let (reply, _receiver) = oneshot::channel();
        assert!(cache.admit(operation, [7; 32], reply, now));
        let value = cache
            .complete(operation, meshmsg_protocol::Response::Error(producer), now)
            .unwrap();
        let error = response_error(&value);
        assert_eq!(error.operation_id.as_ref(), Some(&operation));
        assert_eq!(error.outcome, meshmsg_protocol::Outcome::Partial);
        let value = response_value(&value);
        assert!(value.get("selected_tags").is_none());
        assert!(value.get("retryable").is_none());
    }

    #[test]
    fn daemon_resolved_prune_cutoff_is_authoritative_near_ttl() {
        assert_eq!(
            unix_timestamp_ms_saturating(UNIX_EPOCH - Duration::from_millis(1)),
            0,
            "a backwards wall clock saturates instead of creating a future cutoff"
        );
        let operation: meshmsg_protocol::OperationId =
            "44444444444444444444444444444444".parse().unwrap();
        let now = StdInstant::now();
        let ttl = Duration::from_secs(600);
        let fingerprint = |age: u64| prune(operation, Some(age));
        let mut cache = OperationCache::new(4, ttl);
        let (first_reply, _first_receiver) = oneshot::channel();
        assert!(cache.admit(operation, fingerprint(60), first_reply, now));
        // The owner resolves the cutoff once at admission; the cached terminal
        // response is the only place it is retained.
        let cutoff_ms = crate::attachment::prune_cutoff_upper_bound(100_000, 60);
        assert_eq!(cutoff_ms, 40_000);
        let terminal = meshmsg_protocol::Response::OffersPruned(meshmsg_protocol::OffersPruned {
            operation_id: operation,
            direction: Some(meshmsg_protocol::OfferDirection::Outgoing),
            older_than_secs: 60,
            maximum: 1,
            dry_run: false,
            selected_tags: 0,
            removed_tags: 0,
            released_bytes: 0,
            limited: false,
            cutoff_ms,
        });
        cache.complete(operation, terminal.clone(), now);

        // A retry can arrive with a much later or backwards wall clock. Its
        // stable caller-intent fingerprint does not derive another cutoff.
        let (replay_reply, replay_receiver) = oneshot::channel();
        assert!(!cache.admit(
            operation,
            fingerprint(60),
            replay_reply,
            now + ttl - Duration::from_millis(1),
        ));
        let replayed = replay_receiver.blocking_recv().unwrap();
        assert_eq!(replayed, terminal);

        let (conflict_reply, conflict_receiver) = oneshot::channel();
        assert!(!cache.admit(
            operation,
            fingerprint(61),
            conflict_reply,
            now + Duration::from_secs(1),
        ));
        let conflict = conflict_receiver.blocking_recv().unwrap();
        assert_eq!(
            response_error(&conflict).code,
            meshmsg_protocol::ErrorCode::OperationIdConflict
        );
        assert_eq!(response_error(&conflict).operation_id, Some(operation));
    }
}
