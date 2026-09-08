# Production readiness review and next steps

## Overall assessment

This is a security-conscious, well-tested MVP. Strong areas include bounded frames and queues, strict deserialization, atomic state writes, owner-only IPC, no-follow/no-clobber attachment handling, signed presence and direct messages, restrictive web headers, and extensive regression tests.

It is reasonably robust for a **small, trusted, live-only mesh**, but the following should be addressed before describing it as production-ready.

## Highest-priority findings

### 1. Broadcast envelopes are not topic-bound or replay-safe — High

- [x] **Status: completed for EnvelopeV2 and replay protection.** Broadcasts now use a separate V2 Gossip protocol and sign `{domain, version, topic, sender, message_id, timestamp, kind, body}`. Receivers enforce freshness and exact bounded replay retention with transport-source, per-sender, and global admission limits; legacy topic-unbound signed attachment tokens fail closed.
- Relevant implementation and focused boundary/load tests are in `src/node.rs`; schema propagation is enforced in `src/web.rs` and the broadcast/attachment integration harnesses. This is intentionally wire-incompatible with pre-V2 peers.
- Client-generated operation IDs, terminal-outcome caching, and safe retries are **not** part of this completion and remain outstanding under finding 4.

### 2. Local IPC accepts unlimited idle clients — High availability risk

- [x] **Status: completed.** Immediately after platform accept/authentication, the daemon acquires one of 64 IPC permits before peer cleanup, timestamp/snapshot construction, serialization, event subscription, or other per-client preparation. Excess clients receive a bounded `ipc_capacity` rejection; initial frames, response writes, and commands have deadlines.
- Handlers are tracked in a `JoinSet`; shutdown closes admission, drains, then aborts stragglers. Stop is acknowledged only after bounded command-queue admission, while timeout or closure reports `outcome:"not_started"`. Platform-gated tests cover real Unix sockets and equivalent Windows named-pipe paths; native Windows tests run in CI.

### 3. Download commit order can return failure after installing the output — High

- Relevant code: `src/node.rs:1755-1782`
- The destination is installed before the durable inbound blob tag is written and synced.
- If tag persistence fails, the CLI reports `download_failed`, but the output already exists and retry is rejected by no-clobber semantics.
- Persist the pin before final installation, or return an explicit partial-success response such as `installed:true, pinned:false`.
- Add fault-injection tests around every commit boundary.

### 4. Mutating operations have no end-to-end idempotency — High API reliability gap

- The documented “outcome unknown; do not blindly retry” behavior affects send, share, and private-send.
- Add client-generated operation IDs and propagate them through HTTP → IPC → daemon → wire.
- Cache bounded terminal outcomes so reconnects can safely query or retry.
- Private messages already have wire IDs, but they are generated after each new request; callers cannot safely reuse one after losing the response.

### 5. Direct-message replay persistence is an availability bottleneck

- Relevant code: `src/direct.rs:144-163`, `src/direct.rs:839-891`
- Each accepted message serializes and atomically fsyncs the entire replay map while holding a synchronous mutex inside async protocol handling.
- The global 4,096-entry cache can be filled with roughly 6.5 accepted messages per second over its 10.5-minute lifetime, denying all private sends until entries expire.
- Use an append-only/WAL or embedded database on a dedicated blocking worker, plus global and per-sender rate limits and quotas.

### 6. Persistent attachment storage is unbounded

- Relevant documentation: `docs/attachments.md:68`
- Every successful share/download creates a permanent pin, but there is no remove command, total quota, retention policy, or storage-pressure reporting.
- Add `offers remove`, `offers prune`, a total-byte quota, minimum-free-space checks, retention controls, and usage metrics.

## API and consistency issues

### 7. The JSON, HTTP, and IPC contracts are only partially versioned

- Peer and attachment records use `schema_version`; status, queued sends, connected events, errors, and several HTTP responses do not.
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

- `src/attachment.rs:580-583` falls back to `fs::rename` outside Linux, Android, and Windows, which may replace a concurrently created empty directory.
- Either implement platform-specific no-replace primitives for macOS/BSD or explicitly reject unsupported targets.

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
- `cargo test --locked --all-targets`: 150 passed, including EnvelopeV2/replay boundaries and Unix production-listener IPC capacity, ordering, timeout, stop, and shutdown coverage;
- JavaScript syntax/UI checks, fake-daemon CLI and HTTP integrations, and the real-Iroh peer-directory integration.

Native Windows execution was unavailable locally because the MSVC tools were absent; regular CI now runs the platform-gated named-pipe tests, Clippy, and build on Windows Server 2022. The longer five-peer, attachment, direct-message, web-peer, and version-compatibility scenarios were not rerun locally for this review. `cargo-audit` and `cargo-deny` were unavailable locally and remain CI checks.

## Recommended implementation order

1. [ ] Versioned, topic-bound envelope plus operation IDs. **Partially complete:** the versioned/topic-bound/replay-protected envelope is implemented; client-generated operation IDs, end-to-end propagation, and cached terminal outcomes remain outstanding under finding 4.
2. [x] Bound and time out daemon IPC connections.
3. Correct download transaction ordering.
4. Introduce stable typed API and error contracts.
5. Add attachment lifecycle and quota controls.
6. Replace replay JSON rewrites and synchronous logging.
7. Add fuzzing, slowloris/load tests, crash fault injection, and cross-platform no-clobber tests.
8. Pin the Rust toolchain and add signed provenance/SBOM. `SHA256SUMS` hosted beside the artifacts protects against corruption, not release-account compromise.
