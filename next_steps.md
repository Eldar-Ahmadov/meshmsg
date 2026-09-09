# Production readiness review and next steps

## Overall assessment

This is a security-conscious, well-tested MVP. Strong areas include bounded frames and queues, strict deserialization, atomic state writes, owner-only IPC, no-follow/no-clobber attachment handling, signed presence and direct messages, restrictive web headers, and extensive regression tests.

It is reasonably robust for a **small, trusted, live-only mesh**, but the following should be addressed before describing it as production-ready.

## Highest-priority findings

### 1. Broadcast envelopes are not topic-bound or replay-safe — High

- [x] **Status: completed for EnvelopeV2 and replay protection.** Broadcasts now use a separate V2 Gossip protocol and sign `{domain, version, topic, sender, message_id, timestamp, kind, body}`. Receivers enforce freshness and exact bounded replay retention with transport-source, per-sender, and global admission limits; legacy topic-unbound signed attachment tokens fail closed.
- Relevant implementation and focused boundary/load tests are in `src/node.rs`; schema propagation is enforced in `src/web.rs` and the broadcast/attachment integration harnesses. This is intentionally wire-incompatible with pre-V2 peers.
- Client-generated operation IDs, terminal-outcome caching, and safe retries are completed separately under finding 4.

### 2. Local IPC accepts unlimited idle clients — High availability risk

- [x] **Status: completed.** Immediately after platform accept/authentication, the daemon acquires one of 64 IPC permits before peer cleanup, timestamp/snapshot construction, serialization, event subscription, or other per-client preparation. Excess clients receive a bounded `ipc_capacity` rejection; initial frames, response writes, and commands have deadlines.
- Handlers are tracked in a `JoinSet`; shutdown closes admission, drains, then aborts stragglers. Stop is acknowledged only after bounded command-queue admission, while timeout or closure reports `outcome:"not_started"`. Platform-gated tests cover real Unix sockets and equivalent Windows named-pipe paths; native Windows tests run in CI.

### 3. Download commit order can return failure after installing the output — High

- [x] **Status: completed.** Downloaded bytes are exported and synced, then the inbound blob tag is written and durably synced before the atomic no-clobber destination install. Every ordinary `download_failed` outcome therefore leaves the requested destination uninstalled and safely retryable. Raw-ticket pin IDs and tag names are deterministic from the raw ticket's provider and content hash, so failure/restart/retry does not accumulate permanent pins.
- Output parents must already exist. Files and extracted directory trees are synced, the destination is atomically installed, and the one changed existing parent is synced. Post-install sync/cleanup failures return explicit `download_complete` partial-success metadata (`installed:true`, `pinned:true`, `destination_synced`, `cleanup_complete`, and `warnings`) rather than a false failure.
- Before/after-boundary fault injection covers tag set/sync, file and signed-directory installation, destination and parent sync, and cleanup. A subprocess exits without destructors after durable pin and after install; reopening verifies the exact inbound tag/hash, raw retry idempotency, and precise crash leftovers. Daemon startup removes only strictly named regular share staging files in its owner-only state root; arbitrary output siblings are not scanned and are documented for manual cleanup.

### 4. Mutating operations have no end-to-end idempotency — High API reliability gap

- [x] **Status: completed with explicit bounded-cache semantics.** CLI and web callers generate or accept reusable lowercase 128-bit operation IDs for broadcast send, attachment share, and private send. IDs propagate through versioned HTTP/IPC DTOs and become the signed broadcast/private/offer wire IDs; incompatible old mutation clients and daemons fail closed through `idempotent_mutations_v1` negotiation.
- The daemon joins matching concurrent requests, replays matching terminal successes and failures, and rejects cross-kind or changed-input reuse with a structured `operation_id_conflict`. Shares bind both the exact submitted absolute source-path representation and a domain-separated content digest, detecting equal-size content changes. The HTTP bridge uses strict mutation DTOs, preserves authoritative daemon errors exactly, negotiates capability before sends, and retains upload fingerprints for a complete daemon TTL after completion/latest retry. The cache is bounded to 1,024 entries with a 10-minute terminal TTL; oldest terminal entries are evicted under pressure and in-flight entries are retained.
- The cache is intentionally memory-only. Status and documentation expose that restart, expiry, or eviction ends the sender-side retry guarantee. Browser drafts/file selections retain their ID after unknown outcomes, and private recipients separately persist wire replay IDs. Focused unit tests and `tests/integration-idempotency.sh` cover response loss, concurrent joins, conflicts, terminal failures, stable wire IDs, and restart semantics.

### 5. Direct-message replay persistence is an availability bottleneck

- [x] **Status: completed.** Direct protocol v2 and replay-state v2 persist only a domain-separated SHA-256 semantic-payload fingerprint plus sender, ID, expiration, and state—never the body. The dedicated blocking worker uses a bounded 64-request queue and owns all filesystem I/O. A new transaction syncs `recorded`, inserts the body into its pre-reserved volatile queue, then syncs `delivery_confirmed` before signed `Accepted`; exact confirmed retries return signed `DuplicateAccepted`, changed fingerprints return signed `Conflict`, and no replay redelivers.
- The crash interval is explicit rather than hidden: a recovered `recorded` entry returns signed `DeliveryOutcomeUnknown` forever until expiry because the body is unavailable and queue insertion cannot be proved. Failpoint subprocesses exit immediately after the first sync, after queue delivery but before transition, and after transition sync; recovery verifies unknown/unknown/duplicate-accepted respectively and no redelivery. Checksummed WAL/snapshot recovery, torn-tail truncation, transition validation, compaction ordering, v1 conservative migration, concurrent/restart conflicts, cancellation, and append/compaction faults are covered.
- Live IDs are never evicted. New IDs have an 8,192 global quota, 512 per sender, global 128/second burst 256 and per-sender 8/second burst 16 token buckets. Capacity pressure returns signed `Busy`. A terminal worker error publishes `direct_replay_available:false` plus a stable error in status, returns signed unavailable for a known pre-append failure or unknown for append/delivery ambiguity, and unavailable for queued/subsequent requests, and is reported again by shutdown. Rotating identities can still share/exhaust the global budget, so this is bounded isolation rather than Sybil resistance.

### 6. Persistent attachment storage is unbounded

- [x] **Status: completed.** `offers remove` and deterministic, bounded `offers prune` (including dry-run) use strict versioned IPC outcomes. One deny-unknown-fields lifecycle-error V1 DTO covers daemon/IPC/HTTP attachment busy, timeout, shutdown, partial, pressure, and internal failures with validated stable codes/outcomes/retryability and relevant IDs/counts. Removal is idempotent, selector-aware, database-synced, retry-safe after partial/unknown failures, and deletes only selected meshmsg tags.
- A daemon-enforced unique-blob byte quota, authoritative 8,192-pin metadata bound, and filesystem minimum-free reserve protect nonempty and zero-byte/deduplicated stores. Startup reconciliation is bounded to 16,385 reserved-prefix records, runs before the command loop with blocking file/free-space work delegated off-loop, rejects oversized stores, meshmsg `hash_seq` tags, and missing/partial reserved blobs, and ignores foreign-prefix tags. Runtime pin admission rechecks complete authoritative size before its serialized transaction; accounting is transactionally cached, uses full `HashAndFormat` identity, and makes status constant work without stale partial-to-complete usage.
- Tag/index reservations roll back on ordinary share/download tag, database, index, export, and pre-install failures; rollback uncertainty triggers bounded authoritative reconciliation, while crash boundaries conservatively recover durable tags without phantom reservations. Automatic retention is disabled by default and requires explicit nonzero opt-in. The exclusive storage gate prevents local transfer/lifecycle races; removal acquires bounded nonexpiring in-flight GC pins before named-tag deletion and starts the full one-hour grace only after deletion/database-sync completion; deterministic stall/refresh/rollback and read/GC barrier coverage proves guards cannot expire mid-commit and active provider reads survive a completed post-removal GC cycle. HTTP preserves actionable lifecycle fields while replacing private diagnostics with fixed public messages.

## API and consistency issues

### 7. The JSON, HTTP, and IPC contracts are only partially versioned

- Mutation successes and operation errors are now versioned, but status, connected events, several non-mutation errors, and several HTTP responses remain unversioned.
- HTTP errors have `outcome` but no stable `code`, version, request ID, or retryability field: `src/web.rs:385-389`.
- `--json` failures still produce plain text on stderr and nothing on stdout: `src/main.rs:21-24`.
- Standardize a versioned envelope, for example:

```json
{
  "type": "error",
  "schema_version": 1,
  "code": "daemon_offline",
  "message": "...",
  "retryable": true,
  "outcome": "not_started",
  "request_id": "..."
}
```

- Deserialize responses into strict typed DTOs. Most clients currently validate only `type` and version, then silently default malformed fields.

### 8. Validation rules have drifted across layers

- Signed offers accept uppercase hexadecimal IDs at `src/node.rs:335-340`, while persistent listing accepts lowercase only at `src/node.rs:1324-1328`. Such a downloaded pin becomes invisible to `offers`.
- Positional message/token/offer inputs bypass the limits applied to file/stdin forms: `src/cli.rs:238-275`.
- Offer files accept 1 MiB, but IPC requests are capped at 25,600 bytes: `src/ipc.rs:10`, making most of that advertised range unusable.
- Web and CLI accept 4,096-byte broadcast bodies even though the complete signed envelope—not the body—is capped at 4,096 bytes.
- Centralize canonical validators and expose authoritative limits in daemon capabilities/status.

### 9. There are redundant compatibility fields without a deprecation policy

- `socket` and `local_endpoint` always contain the same value: `src/node.rs:1955`, `src/node.rs:2113`.
- `truncated` and `has_more` are always set together: `src/node.rs:2151-2152`.
- Document these as compatibility aliases with a removal version, or retain one canonical field.

## Operations and maintainability

### 10. Observability is currently minimal and potentially blocking

- `tracing-subscriber` is initialized in `src/main.rs:36`, but there are no tracing calls; logging uses a few `eprintln!` statements.
- `event()` performs synchronous `println!` from the daemon event loop: `src/node.rs:2261-2265`, `src/node.rs:3467`.
- Under benchmark/message load, stdout backpressure can stall networking, status, and shutdown; JSON daemon logs can also grow extremely quickly.
- Use bounded nonblocking structured logging, sampling, and metrics for queue occupancy, dropped events, transfer counts, replay capacity, reconnects, and disk usage.

### 11. Health/readiness semantics are unclear

- `topic_joined` is false for a healthy lone first peer: `docs/usage.md:204`.
- Add explicit `ready`, `degraded`, and dependency details rather than making monitoring infer health from neighbor state.
- A lightweight web health endpoint would also help orchestration.

### 12. State needs an upgrade and migration story

- `config.json` has no top-level schema version: `src/config.rs:71-77`.
- `config.json` and `alias.json` are read without file-size bounds: `src/config.rs:139-141`, `src/alias.rs:63`.
- Add versioned migrations, bounded reads, backup/restore guidance, and crash/fault tests.
- Consider old-key cleanup after successful forced identity replacement.

### 13. No-clobber is not portable to all compiled Unix targets

- [x] **Status: completed with an explicit platform limitation.** Extracted-directory installation uses atomic no-replace primitives on Linux, Android, and Windows. Other targets fail closed with an actionable raw-tar alternative; the replacement-capable `fs::rename` fallback was removed. Documentation and a cfg-gated unsupported-target regression test make the limitation explicit.

### 14. Large modules increase audit and regression risk

- `src/node.rs` is about 5,000 lines and `src/web.rs` about 1,900 lines.
- Split wire formats, daemon loop, IPC transport, attachment service, benchmark service, CLI presentation, and platform-specific IPC into separate modules.
- This will also make typed API contracts easier to enforce.

## Deliberate product constraints to resolve

The documentation correctly discloses these, but they determine what “production” means:

- no durable/offline delivery or history;
- no application authentication or user attribution in the web UI;
- no invite revocation, membership ACL, or key rotation;
- plaintext broadcast messages and attachments;
- no end-to-end encrypted attachments.

These are acceptable for a trusted ephemeral tool, but blockers for a general production messenger.

## Validation performed

Passed locally for these completed findings:

- `cargo fmt --all -- --check`, `cargo clippy --locked --all-targets -- -D warnings`, and `cargo build --locked`;
- `cargo test --locked --all-targets`: 198 passed, including EnvelopeV2/replay, IPC capacity, bounded/oversized attachment reconciliation, missing/partial fail-closed accounting, concurrent completion and exact quota boundaries, cached status responsiveness, transactional pin/index rollback and crash boundaries, deterministic active-read/post-removal-GC safety, HTTP diagnostic sanitization, automatic-retention opt-in, lifecycle DTO compatibility rejection, partial delete/sync/index faults, format/foreign-tag safety, removal/prune boundaries, dry-run, deduplicated quota/reference accounting, lifecycle concurrency, operation-cache behavior, and direct-replay recovery/load coverage;
- `tests/integration-attachments.sh`: passed with raw/signed file and directory transfers, no-clobber/durability, pin/index restart recovery, remove/prune/dry-run, dedup retention, share and download quota/free-space rejection, quota recovery, concurrent local share/download/remove/prune exclusion, and a started remote download surviving provider-pin removal;
- `tests/integration-idempotency.sh` and `tests/integration-direct-messages.sh`: passed with response-loss retries, concurrent duplicate joins, stable private wire IDs, recipient WAL persistence across sender restart, duplicate classification, signed changed-body conflicts, authenticated direct delivery, and no replay redelivery;
- `tests/integration-web.py`, `tests/integration-web-peer.py`, and `node tests/web-ui.cjs`: passed with conflicts, terminal failures, restart semantics, and HTTP/browser propagation.

Native Windows execution was unavailable locally. A Windows cross-check was attempted but dependency build scripts stopped before meshmsg compilation because `ml64.exe`/`lib.exe` are unavailable; regular CI runs the platform-gated tests, Clippy, and build on Windows Server 2022. A musl cross-check was likewise blocked before meshmsg compilation by the absent `x86_64-linux-musl-gcc`. Unsupported-target directory-install behavior has cfg-gated test coverage but was not executed locally. The longer five-peer and version-compatibility scenarios were not rerun; native Windows execution remains CI-only. `cargo-audit` and `cargo-deny` were unavailable locally and remain CI checks.

## Recommended implementation order

1. [x] Versioned, topic-bound envelope plus operation IDs, including bounded concurrent/terminal outcome deduplication and documented nonpersistent retry scope.
2. [x] Bound and time out daemon IPC connections.
3. [x] Correct download transaction ordering.
4. Introduce stable typed API and error contracts.
5. [x] Add attachment lifecycle and quota controls.
6. Replace synchronous daemon logging with bounded nonblocking structured output.
7. Add fuzzing, slowloris/load tests, crash fault injection, and cross-platform no-clobber tests.
8. Pin the Rust toolchain and add signed provenance/SBOM. `SHA256SUMS` hosted beside the artifacts protects against corruption, not release-account compromise.
