use crate::contracts;
use std::{
    collections::{HashMap, VecDeque},
    time::{Duration, Instant as StdInstant},
};
use tokio::sync::oneshot;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct PruneResolution {
    pub(super) older_than_secs: u64,
    pub(super) cutoff_ms: u64,
}

struct CompletedOperation {
    fingerprint: [u8; 32],
    response: meshmsg_protocol::Response,
    expires_at: StdInstant,
    prune_resolution: Option<PruneResolution>,
}

struct InFlightOperation {
    fingerprint: [u8; 32],
    waiters: Vec<oneshot::Sender<meshmsg_protocol::Response>>,
    prune_resolution: Option<PruneResolution>,
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
        operation_id: &meshmsg_protocol::OperationId,
        code: meshmsg_protocol::ErrorCode,
    ) -> meshmsg_protocol::Response {
        contracts::protocol_error_response(
            code,
            meshmsg_protocol::Outcome::NotStarted,
            Some(operation_id.clone()),
        )
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
                if let (Some(resolution), meshmsg_protocol::Response::OffersPruned(result)) =
                    (entry.prune_resolution, &entry.response)
                {
                    debug_assert_eq!(result.older_than_secs, resolution.older_than_secs);
                    debug_assert_eq!(result.cutoff_ms, resolution.cutoff_ms);
                }
                entry.response.clone()
            } else {
                Self::error(
                    &operation_id,
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
                    &operation_id,
                    meshmsg_protocol::ErrorCode::OperationIdConflict,
                ));
            }
            return false;
        }
        while self.completed.len() + self.in_flight.len() >= self.capacity {
            let Some(oldest) = self.order.pop_front() else {
                let _ = reply.send(Self::error(
                    &operation_id,
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
                prune_resolution: None,
            },
        );
        true
    }

    /// Resolve a prune boundary only for the newly admitted owner and retain it
    /// with the cache entry so execution and terminal replay share one authority.
    pub(super) fn resolve_prune(
        &mut self,
        operation_id: &meshmsg_protocol::OperationId,
        older_than_secs: u64,
        now_ms: u64,
    ) -> PruneResolution {
        let entry = self
            .in_flight
            .get_mut(operation_id)
            .expect("newly admitted prune is in flight");
        let resolution = *entry.prune_resolution.get_or_insert(PruneResolution {
            older_than_secs,
            cutoff_ms: crate::ipc::prune_cutoff_upper_bound(now_ms, older_than_secs),
        });
        debug_assert_eq!(resolution.older_than_secs, older_than_secs);
        resolution
    }

    pub(super) fn complete(
        &mut self,
        operation_id: &meshmsg_protocol::OperationId,
        response: meshmsg_protocol::Response,
        now: StdInstant,
    ) -> meshmsg_protocol::Response {
        let Some(in_flight) = self.in_flight.remove(operation_id) else {
            return response;
        };
        for waiter in in_flight.waiters {
            let _ = waiter.send(response.clone());
        }
        self.completed.insert(
            operation_id.clone(),
            CompletedOperation {
                fingerprint: in_flight.fingerprint,
                response,
                expires_at: now + self.ttl,
                prune_resolution: in_flight.prune_resolution,
            },
        );
        self.order.push_back(operation_id.clone());
        self.completed
            .get(operation_id)
            .expect("completed operation was inserted")
            .response
            .clone()
    }
    #[cfg(test)]
    pub(super) fn counts(&self) -> (usize, usize) {
        (self.in_flight.len(), self.completed.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::{
        commands::{operation_fingerprint, optional_text_fingerprint},
        common::unix_timestamp_ms_saturating,
    };
    use std::time::UNIX_EPOCH;

    fn response_value(response: &meshmsg_protocol::Response) -> serde_json::Value {
        serde_json::to_value(response).unwrap()
    }

    fn response_error(response: &meshmsg_protocol::Response) -> &meshmsg_protocol::ProtocolError {
        match response {
            meshmsg_protocol::Response::Error(error) => error,
            _ => panic!("expected protocol error"),
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
        let fp1 = operation_fingerprint("send", &[b"one"]);
        let different = operation_fingerprint("send", &[b"different"]);

        // IDs are global across kinds and every lifecycle/download selector is
        // represented without Option ambiguity or path/token normalization.
        assert_ne!(fp1, operation_fingerprint("download", &[b"one"]));
        assert_ne!(
            operation_fingerprint(
                "offers_remove",
                &[
                    b"offer",
                    &optional_text_fingerprint(None),
                    &optional_text_fingerprint(None)
                ],
            ),
            operation_fingerprint(
                "offers_remove",
                &[
                    b"offer",
                    &optional_text_fingerprint(Some("incoming")),
                    &optional_text_fingerprint(None),
                ],
            )
        );
        assert_ne!(
            operation_fingerprint(
                "offers_prune",
                &[
                    &0_u64.to_le_bytes(),
                    &optional_text_fingerprint(None),
                    &[0],
                    &1_usize.to_le_bytes(),
                ],
            ),
            operation_fingerprint(
                "offers_prune",
                &[
                    &1_u64.to_le_bytes(),
                    &optional_text_fingerprint(None),
                    &[0],
                    &1_usize.to_le_bytes(),
                ],
            ),
            "changed prune age must conflict"
        );
        assert_ne!(
            operation_fingerprint("download", &[b"token", b"/tmp/one"]),
            operation_fingerprint("download", &[b"token", b"/tmp/two"]),
        );
        assert_ne!(
            operation_fingerprint("download", &[b"token", b"/tmp/one"]),
            operation_fingerprint("download", &[b"changed-token", b"/tmp/one"]),
        );
        assert_ne!(
            operation_fingerprint("download", &[b"token", b"/tmp/one", b"install"]),
            operation_fingerprint("download", &[b"token", b"/tmp/one", b"raw"]),
        );

        let (reply1, response1) = oneshot::channel();
        assert!(cache.admit(id1.clone(), fp1, reply1, now));
        let (duplicate, duplicate_response) = oneshot::channel();
        assert!(!cache.admit(id1.clone(), fp1, duplicate, now));
        let (conflict, conflict_response) = oneshot::channel();
        assert!(!cache.admit(id1.clone(), different, conflict, now));
        assert_eq!(
            response_error(&conflict_response.await.unwrap()).code,
            meshmsg_protocol::ErrorCode::OperationIdConflict,
        );

        let terminal = contracts::protocol_error_response(
            meshmsg_protocol::ErrorCode::SendFailed,
            meshmsg_protocol::Outcome::Unknown,
            Some(id1.clone()),
        );
        let stored = cache.complete(&id1, terminal, now);
        assert_eq!(
            response_error(&stored)
                .operation_id
                .as_ref()
                .unwrap()
                .as_str(),
            id1.as_str()
        );
        assert_eq!(response1.await.unwrap(), stored);
        assert_eq!(duplicate_response.await.unwrap(), stored);
        let (cached, cached_response) = oneshot::channel();
        assert!(!cache.admit(id1.clone(), fp1, cached, now));
        assert_eq!(cached_response.await.unwrap(), stored);

        let partial = contracts::protocol_error_response(
            meshmsg_protocol::ErrorCode::DownloadFailed,
            meshmsg_protocol::Outcome::Partial,
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".parse().unwrap()),
        );
        let partial_id: meshmsg_protocol::OperationId =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".parse().unwrap();
        let partial_fp = operation_fingerprint("download", &[b"token", b"output"]);
        let mut partial_cache = OperationCache::new(2, Duration::from_secs(10));
        let (partial_reply, partial_response) = oneshot::channel();
        assert!(partial_cache.admit(partial_id.clone(), partial_fp, partial_reply, now));
        let partial = partial_cache.complete(&partial_id, partial, now);
        assert_eq!(partial_response.await.unwrap(), partial);
        let (partial_retry, partial_retry_response) = oneshot::channel();
        assert!(!partial_cache.admit(partial_id.clone(), partial_fp, partial_retry, now));
        assert_eq!(partial_retry_response.await.unwrap(), partial);

        let removal_id: meshmsg_protocol::OperationId =
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".parse().unwrap();
        let removal_fp = operation_fingerprint("offers_remove", &[b"selector"]);
        let (removal_reply, removal_response) = oneshot::channel();
        assert!(partial_cache.admit(removal_id.clone(), removal_fp, removal_reply, now));
        let removal_error = contracts::ProtocolErrorAdapter::new(
            "attachment_removal_partial",
            "private",
            "partial",
        );
        let removal = partial_cache.complete(
            &removal_id,
            meshmsg_protocol::Response::Error(removal_error.typed().unwrap()),
            now,
        );
        assert_eq!(removal_response.await.unwrap(), removal);
        let (removal_retry, removal_retry_response) = oneshot::channel();
        assert!(!partial_cache.admit(removal_id.clone(), removal_fp, removal_retry, now));
        assert_eq!(removal_retry_response.await.unwrap(), removal);

        let fp2 = operation_fingerprint("send", &[b"two"]);
        let (reply2, _response2) = oneshot::channel();
        assert!(cache.admit(id2.clone(), fp2, reply2, now));
        cache.complete(
            &id2,
            contracts::protocol_error_response(
                meshmsg_protocol::ErrorCode::SendFailed,
                meshmsg_protocol::Outcome::Unknown,
                Some(id2.clone()),
            ),
            now,
        );
        let fp3 = operation_fingerprint("send", &[b"three"]);
        let (reply3, _response3) = oneshot::channel();
        assert!(cache.admit(id3.clone(), fp3, reply3, now));
        assert!(
            !cache.completed.contains_key(&id1),
            "oldest terminal entry was not evicted"
        );

        let mut expired = OperationCache::new(2, Duration::from_millis(1));
        let (reply, _response) = oneshot::channel();
        assert!(expired.admit(id1.clone(), fp1, reply, now));
        expired.complete(
            &id1,
            contracts::protocol_error_response(
                meshmsg_protocol::ErrorCode::SendFailed,
                meshmsg_protocol::Outcome::Unknown,
                Some(id1.clone()),
            ),
            now,
        );
        let (retry, _retry_response) = oneshot::channel();
        assert!(expired.admit(id1.clone(), fp1, retry, now + Duration::from_millis(2)));

        // The cache is intentionally daemon-lifetime scoped. A fresh daemon
        // admits the same ID again; status/docs tell clients not to infer
        // restart-persistent idempotency.
        let mut restarted = OperationCache::new(2, Duration::from_secs(10));
        let (retry, _retry_response) = oneshot::channel();
        assert!(restarted.admit(id1.clone(), fp1, retry, now));
    }

    #[tokio::test]
    async fn operation_capacity_is_pre_admission_and_same_id_can_be_retried() {
        let active_id: meshmsg_protocol::OperationId =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".parse().unwrap();
        let rejected_id: meshmsg_protocol::OperationId =
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".parse().unwrap();
        let active_fingerprint = operation_fingerprint("send", &[b"active"]);
        let rejected_fingerprint = operation_fingerprint("send", &[b"rejected"]);
        let now = StdInstant::now();
        let mut cache = OperationCache::new(1, Duration::from_secs(60));

        let (active, _active_response) = oneshot::channel();
        assert!(cache.admit(active_id.clone(), active_fingerprint, active, now));
        let (rejected, rejected_response) = oneshot::channel();
        assert!(!cache.admit(rejected_id.clone(), rejected_fingerprint, rejected, now));
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
            &active_id,
            contracts::protocol_error_response(
                meshmsg_protocol::ErrorCode::SendFailed,
                meshmsg_protocol::Outcome::Unknown,
                Some(active_id.clone()),
            ),
            now,
        );
        let (retry, _retry_response) = oneshot::channel();
        assert!(cache.admit(rejected_id, rejected_fingerprint, retry, now));
    }

    #[tokio::test]
    async fn cached_not_started_failure_stays_bound_but_advises_a_new_operation() {
        let operation_id: meshmsg_protocol::OperationId =
            "cccccccccccccccccccccccccccccccc".parse().unwrap();
        let fingerprint = operation_fingerprint("download", &[b"offer", b"output"]);
        let different = operation_fingerprint("download", &[b"offer", b"other-output"]);
        let now = StdInstant::now();
        let mut cache = OperationCache::new(2, Duration::from_secs(60));

        let (owner, _owner_response) = oneshot::channel();
        assert!(cache.admit(operation_id.clone(), fingerprint, owner, now));
        let terminal = contracts::protocol_error_response(
            meshmsg_protocol::ErrorCode::DownloadFailed,
            meshmsg_protocol::Outcome::NotStarted,
            Some(operation_id.clone()),
        );
        cache.complete(&operation_id, terminal.clone(), now);

        let (same, same_response) = oneshot::channel();
        assert!(!cache.admit(operation_id.clone(), fingerprint, same, now));
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
        let mut producer = contracts::ProtocolErrorAdapter::new(
            "attachment_removal_partial",
            "private store failure",
            "partial",
        );
        producer.operation_id = Some(operation.to_string());
        let mut cache = OperationCache::new(2, Duration::from_secs(60));
        let now = StdInstant::now();
        let (reply, _receiver) = oneshot::channel();
        assert!(cache.admit(operation.clone(), [7; 32], reply, now));
        let value = cache.complete(
            &operation,
            meshmsg_protocol::Response::Error(producer.typed().unwrap()),
            now,
        );
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
        let fingerprint = |age: u64| {
            operation_fingerprint(
                "offers_prune",
                &[
                    &age.to_le_bytes(),
                    &optional_text_fingerprint(Some("outgoing")),
                    &[0],
                    &1_usize.to_le_bytes(),
                ],
            )
        };
        let mut cache = OperationCache::new(4, ttl);
        let (first_reply, _first_receiver) = oneshot::channel();
        assert!(cache.admit(operation.clone(), fingerprint(60), first_reply, now));
        let resolution = cache.resolve_prune(&operation, 60, 100_000);
        assert_eq!(resolution.cutoff_ms, 40_000);
        let terminal = meshmsg_protocol::Response::OffersPruned(meshmsg_protocol::OffersPruned {
            operation_id: operation.parse().unwrap(),
            direction: Some(meshmsg_protocol::OfferDirection::Outgoing),
            older_than_secs: 60,
            maximum: 1,
            dry_run: false,
            selected_tags: 0,
            removed_tags: 0,
            released_bytes: 0,
            limited: false,
            cutoff_ms: 40_000,
        });
        cache.complete(&operation, terminal.clone(), now);
        assert_eq!(
            cache.completed.get(&operation).unwrap().prune_resolution,
            Some(resolution)
        );

        // A retry can arrive with a much later or backwards wall clock. Its
        // stable caller-intent fingerprint does not derive another cutoff.
        let (replay_reply, replay_receiver) = oneshot::channel();
        assert!(!cache.admit(
            operation.clone(),
            fingerprint(60),
            replay_reply,
            now + ttl - Duration::from_millis(1),
        ));
        let replayed = replay_receiver.blocking_recv().unwrap();
        assert_eq!(replayed, terminal);

        let (conflict_reply, conflict_receiver) = oneshot::channel();
        assert!(!cache.admit(
            operation.clone(),
            fingerprint(61),
            conflict_reply,
            now + Duration::from_secs(1),
        ));
        let conflict = conflict_receiver.blocking_recv().unwrap();
        assert_eq!(
            response_error(&conflict).code,
            meshmsg_protocol::ErrorCode::OperationIdConflict
        );
        assert_eq!(
            response_error(&conflict)
                .operation_id
                .as_ref()
                .unwrap()
                .as_str(),
            operation.as_str()
        );
    }
}
