//! In-memory replay suppression for authenticated direct messages.
//!
//! Nothing here is persisted: a recipient restart forgets every accepted ID,
//! after which a same-ID retry is delivered again as a new message.

use crate::gossip::TokenBucket;
use iroh::PublicKey;
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

const MAX_REPLAY_ENTRIES: usize = 8_192;
const MAX_REPLAY_ENTRIES_PER_SENDER: usize = 512;
const GLOBAL_RATE_PER_SECOND: u64 = 128;
const GLOBAL_RATE_BURST: u64 = 256;
const SENDER_RATE_PER_SECOND: u64 = 8;
const SENDER_RATE_BURST: u64 = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReplayDecision {
    /// A new ID was recorded; the caller must deliver the message.
    Accepted,
    DuplicateAccepted,
    Conflict,
    Busy,
}

#[derive(Debug)]
struct ReplayEntry {
    fingerprint: [u8; 32],
    expires_at_ms: u64,
}

#[derive(Debug)]
struct SenderState {
    live_ids: usize,
    rate: TokenBucket,
}

#[derive(Debug)]
pub(crate) struct ReplayStore {
    lifetime_ms: u64,
    /// Origin of the monotonic milliseconds fed to the rate buckets, so
    /// wall-clock steps affect neither refill nor burst.
    started: Instant,
    entries: HashMap<(PublicKey, [u8; 16]), ReplayEntry>,
    senders: HashMap<PublicKey, SenderState>,
    global_rate: TokenBucket,
}

impl ReplayStore {
    pub(crate) fn new(lifetime: Duration) -> Self {
        Self {
            lifetime_ms: lifetime.as_millis() as u64,
            started: Instant::now(),
            entries: HashMap::new(),
            senders: HashMap::new(),
            global_rate: TokenBucket::new(GLOBAL_RATE_PER_SECOND, GLOBAL_RATE_BURST, 0),
        }
    }

    /// Classifies `(sender, id)` and records it when it is new and admissible.
    ///
    /// Known IDs are answered before any capacity check, so an accepted message
    /// can always be re-acknowledged. Live IDs are never evicted under pressure:
    /// a new ID is `Busy` when `delivery_capacity` is false or a quota or rate
    /// is exhausted, and a `Busy` ID leaves no state behind.
    pub(crate) fn admit(
        &mut self,
        sender: PublicKey,
        id: [u8; 16],
        fingerprint: [u8; 32],
        delivery_capacity: bool,
        now_wall_ms: u64,
        now: Instant,
    ) -> ReplayDecision {
        self.expire(now_wall_ms);
        if let Some(entry) = self.entries.get(&(sender, id)) {
            return if entry.fingerprint == fingerprint {
                ReplayDecision::DuplicateAccepted
            } else {
                ReplayDecision::Conflict
            };
        }
        if !delivery_capacity || self.entries.len() >= MAX_REPLAY_ENTRIES {
            return ReplayDecision::Busy;
        }
        let now_ms = now.saturating_duration_since(self.started).as_millis() as u64;
        if let Some(state) = self.senders.get_mut(&sender) {
            state.rate.refill(now_ms);
            if state.live_ids >= MAX_REPLAY_ENTRIES_PER_SENDER || !state.rate.available() {
                return ReplayDecision::Busy;
            }
        }
        self.global_rate.refill(now_ms);
        if !self.global_rate.available() {
            return ReplayDecision::Busy;
        }
        let state = self.senders.entry(sender).or_insert_with(|| SenderState {
            live_ids: 0,
            rate: TokenBucket::new(SENDER_RATE_PER_SECOND, SENDER_RATE_BURST, now_ms),
        });
        state.live_ids += 1;
        state.rate.consume();
        self.global_rate.consume();
        self.entries.insert(
            (sender, id),
            ReplayEntry {
                fingerprint,
                expires_at_ms: now_wall_ms.saturating_add(self.lifetime_ms),
            },
        );
        ReplayDecision::Accepted
    }

    fn expire(&mut self, now_wall_ms: u64) {
        let senders = &mut self.senders;
        self.entries.retain(|(sender, _), entry| {
            if entry.expires_at_ms > now_wall_ms {
                return true;
            }
            if let Some(state) = senders.get_mut(sender) {
                state.live_ids -= 1;
                if state.live_ids == 0 {
                    senders.remove(sender);
                }
            }
            false
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIFETIME: Duration = Duration::from_secs(60);
    const NOW_WALL_MS: u64 = 1_700_000_000_000;

    fn key() -> PublicKey {
        iroh::SecretKey::generate().public()
    }

    fn id(index: usize) -> [u8; 16] {
        (index as u128).to_le_bytes()
    }

    /// Inserts a live entry directly, bypassing the rate limits under test elsewhere.
    fn insert_live(store: &mut ReplayStore, sender: PublicKey, id: [u8; 16]) {
        store.entries.insert(
            (sender, id),
            ReplayEntry {
                fingerprint: [id[0]; 32],
                expires_at_ms: NOW_WALL_MS + 60_000,
            },
        );
        store
            .senders
            .entry(sender)
            .or_insert_with(|| SenderState {
                live_ids: 0,
                rate: TokenBucket::new(SENDER_RATE_PER_SECOND, SENDER_RATE_BURST, 0),
            })
            .live_ids += 1;
    }

    #[test]
    fn exact_duplicates_and_conflicts_are_classified_without_capacity() {
        let mut store = ReplayStore::new(LIFETIME);
        let now = store.started;
        let sender = key();
        assert_eq!(
            store.admit(sender, [1; 16], [7; 32], true, NOW_WALL_MS, now),
            ReplayDecision::Accepted
        );
        // Neither classification needs delivery capacity or rate tokens.
        for _ in 0..(SENDER_RATE_BURST as usize * 2) {
            assert_eq!(
                store.admit(sender, [1; 16], [7; 32], false, NOW_WALL_MS, now),
                ReplayDecision::DuplicateAccepted
            );
            assert_eq!(
                store.admit(sender, [1; 16], [8; 32], false, NOW_WALL_MS, now),
                ReplayDecision::Conflict
            );
        }
        // The same ID from another sender is a separate key.
        assert_eq!(
            store.admit(key(), [1; 16], [8; 32], true, NOW_WALL_MS, now),
            ReplayDecision::Accepted
        );
        assert_eq!(store.entries.len(), 2);
    }

    #[test]
    fn missing_delivery_capacity_is_busy_and_records_nothing() {
        let mut store = ReplayStore::new(LIFETIME);
        let now = store.started;
        let sender = key();
        assert_eq!(
            store.admit(sender, [1; 16], [1; 32], false, NOW_WALL_MS, now),
            ReplayDecision::Busy
        );
        assert!(store.entries.is_empty() && store.senders.is_empty());
        assert_eq!(
            store.admit(sender, [1; 16], [1; 32], true, NOW_WALL_MS, now),
            ReplayDecision::Accepted
        );
    }

    #[test]
    fn per_sender_and_global_limits_never_evict_live_ids() {
        let mut store = ReplayStore::new(LIFETIME);
        let now = store.started;
        let abusive = key();
        let honest = key();
        // Isolate quota behavior from token timing in this structural test.
        for index in 0..MAX_REPLAY_ENTRIES_PER_SENDER {
            insert_live(&mut store, abusive, id(index));
        }
        assert_eq!(
            store.admit(abusive, [255; 16], [255; 32], true, NOW_WALL_MS, now),
            ReplayDecision::Busy
        );
        assert_eq!(store.entries.len(), MAX_REPLAY_ENTRIES_PER_SENDER);
        assert_eq!(
            store.admit(honest, [7; 16], [7; 32], true, NOW_WALL_MS, now),
            ReplayDecision::Accepted
        );
        assert!(store.entries.contains_key(&(abusive, [0; 16])));

        // Global pressure is also fail-closed and cannot displace either
        // sender's accepted ID.
        for index in store.entries.len()..MAX_REPLAY_ENTRIES {
            insert_live(&mut store, key(), id(index));
        }
        assert_eq!(
            store.admit(honest, [8; 16], [8; 32], true, NOW_WALL_MS, now),
            ReplayDecision::Busy
        );
        assert_eq!(
            store.admit(key(), [9; 16], [9; 32], true, NOW_WALL_MS, now),
            ReplayDecision::Busy
        );
        assert_eq!(store.entries.len(), MAX_REPLAY_ENTRIES);
        assert!(store.entries.contains_key(&(abusive, [0; 16])));
        assert_eq!(
            store.admit(honest, [7; 16], [7; 32], false, NOW_WALL_MS, now),
            ReplayDecision::DuplicateAccepted
        );
    }

    #[test]
    fn sender_rate_is_bounded_and_refills_without_mutating_replay_state() {
        let mut store = ReplayStore::new(LIFETIME);
        let start = store.started;
        let sender = key();
        for index in 0..SENDER_RATE_BURST as usize {
            assert_eq!(
                store.admit(sender, id(index), [0; 32], true, NOW_WALL_MS, start),
                ReplayDecision::Accepted
            );
        }
        let before = store.entries.len();
        // One sender token refills every 125 ms of monotonic time.
        for elapsed_ms in [0, 124] {
            let now = start + Duration::from_millis(elapsed_ms);
            assert_eq!(
                store.admit(sender, [99; 16], [0; 32], true, NOW_WALL_MS, now),
                ReplayDecision::Busy
            );
        }
        assert_eq!(store.entries.len(), before);
        let now = start + Duration::from_millis(125);
        assert_eq!(
            store.admit(sender, [99; 16], [0; 32], true, NOW_WALL_MS, now),
            ReplayDecision::Accepted
        );
        // Another sender is unaffected by this sender's exhausted bucket.
        assert_eq!(
            store.admit(key(), [99; 16], [0; 32], true, NOW_WALL_MS, now),
            ReplayDecision::Accepted
        );
    }

    #[test]
    fn global_rate_is_bounded_across_senders_and_refills() {
        let mut store = ReplayStore::new(LIFETIME);
        let start = store.started;
        // Every sender is new and so has a full bucket of its own.
        for index in 0..GLOBAL_RATE_BURST as usize {
            assert_eq!(
                store.admit(key(), id(index), [0; 32], true, NOW_WALL_MS, start),
                ReplayDecision::Accepted
            );
        }
        let other = key();
        // One global token refills every 7.8125 ms of monotonic time.
        for elapsed_ms in [0, 7] {
            let now = start + Duration::from_millis(elapsed_ms);
            assert_eq!(
                store.admit(other, [100; 16], [0; 32], true, NOW_WALL_MS, now),
                ReplayDecision::Busy
            );
        }
        assert_eq!(store.entries.len(), GLOBAL_RATE_BURST as usize);
        assert!(!store.senders.contains_key(&other));
        let now = start + Duration::from_millis(8);
        assert_eq!(
            store.admit(other, [100; 16], [0; 32], true, NOW_WALL_MS, now),
            ReplayDecision::Accepted
        );
    }

    #[test]
    fn entries_expire_after_the_lifetime_and_release_sender_quota() {
        let mut store = ReplayStore::new(LIFETIME);
        let now = store.started;
        let lifetime_ms = LIFETIME.as_millis() as u64;
        let sender = key();
        assert_eq!(
            store.admit(sender, [1; 16], [1; 32], true, NOW_WALL_MS, now),
            ReplayDecision::Accepted
        );
        assert_eq!(
            store.admit(
                sender,
                [1; 16],
                [1; 32],
                true,
                NOW_WALL_MS + lifetime_ms - 1,
                now,
            ),
            ReplayDecision::DuplicateAccepted
        );
        // At the lifetime boundary the ID is forgotten: the same ID, even with
        // different content, is a new message and the idle sender is dropped.
        assert_eq!(
            store.admit(
                sender,
                [2; 16],
                [2; 32],
                false,
                NOW_WALL_MS + lifetime_ms,
                now,
            ),
            ReplayDecision::Busy
        );
        assert!(store.entries.is_empty() && store.senders.is_empty());
        assert_eq!(
            store.admit(
                sender,
                [1; 16],
                [9; 32],
                true,
                NOW_WALL_MS + lifetime_ms,
                now,
            ),
            ReplayDecision::Accepted
        );
        assert_eq!(store.senders[&sender].live_ids, 1);
    }
}
