# Production-readiness follow-up

## Overall assessment

The hardening work recorded in `next_steps.md` is substantial and generally well designed, but `v0.1.18` should not yet be described as fully production-ready. The topic-bound broadcast protocol, bounded IPC admission, durable download ordering, direct-message replay persistence, attachment quotas/lifecycle controls, and broad typed-contract coverage are appropriate implementations with strong tests.

The producer/consumer validation findings 1 and 2 below are now addressed, and finding 5's missing integration gates are closed. Findings 4 and 7 in `next_steps.md` still overstate their broader closure, and several acknowledged operational and release-process gaps remain open.

## Findings

### 1. Empty broadcasts can occur despite being invalid to consumers — High

- [x] **Status: completed.** `src/message.rs` separates broadcast production (1–3900 UTF-8 bytes), direct/private sends (1–4096 bytes), and the released EnvelopeV2 receive/event compatibility contract (1–3928 bytes, the exact 4096-byte-frame capacity at a one-byte postcard timestamp). Broadcast positional, file, stdin, chat, browser, HTTP, IPC, daemon, and EnvelopeV2 production use the conservative broadcast limit; all three private CLI input forms retain 4096 bytes; wire decoding and strict CLI/web event consumers continue accepting valid v0.1.18-sized broadcast records.
- Empty or oversized local requests are rejected with canonical `invalid_message`/`outcome:"not_started"` before command, throttle, and operation-cache admission. CLI and HTTP errors preserve the supplied operation ID (or the CLI-generated ID), so it remains reusable with no wire/message-event/cache side effect. Blank `chat` lines are ignored before operation-ID allocation.
- Signed remote text semantics are checked after signature verification but before replay admission and fanout. Generated malformed message/queued candidates are withheld by a strict publication guard; a sampled, strict `internal_contract_error` diagnostic is correlated per subscriber and remains consumable by CLI and SSE feeds.
- Focused tests cover byte/UTF-8 producer boundaries and exact released-consumer capacity at the minimum and maximum encoded timestamp plus postcard varint/body-length metadata boundaries, crafted signed empty EnvelopeV2 rejection followed by same-ID valid reuse, and two live strict listeners surviving malformed message/queued candidates. Real integrations cover every empty CLI input form, raw IPC and HTTP rejection/ID reuse/no side effect, blank chat lines, SSE continuity/diagnostics, and mixed current↔v0.1.18 peer/client/daemon boundaries.

### 2. Attachment offer identity validation still drifts — High

- [x] **Status: completed.** AttachmentOffer EnvelopeV2 semantics are now fully checked after signature verification and before replay admission: the body must be a typed nonempty offer, its display name and kind must deserialize through the safe structural types, the offer ID must be canonical lowercase, the envelope message ID must equal it, and the canonical raw ticket provider must equal the signer. Topic and envelope kind are already signed and checked at the same boundary.
- The same ID equality is required by strict IPC and web attachment-event consumers, and signed download tokens reuse the complete validator. Local attachment publication also passes it before encoding.
- Crafted empty-body, uppercase-ID, mismatched-ID, and wrong-provider offers are rejected without replay-ID/token consumption; each case is followed by an accepted message with the same signer and message ID in focused receive-pipeline coverage.

### 3. End-to-end idempotency does not cover every mutating operation — Medium-high

`IpcRequest` carries operation IDs for `send`, `private_send`, and `share`, but not for `offers_remove`, `offers_prune`, `download`, or `web_download`: `src/ipc.rs:1360-1402`.

Removal is end-state idempotent, and downloads have strong no-clobber and reconciliation behavior. Prune is nevertheless not request-idempotent: after a successful prune whose response is lost, repeating the same command can select and remove the next eligible batch rather than replaying the original result.

The completed status under the broad heading “Mutating operations have no end-to-end idempotency” should therefore either be narrowed to the three covered mutations or extended to lifecycle/download operations. In particular, prune should use an operation ID and cached selection/result if `--max-delete` is intended as a per-request side-effect bound.

### 4. Typed contracts remain structurally strict but semantically incomplete — Medium

The contract work provides useful deny-unknown-fields DTOs, exact family versions, bounded fields, and request correlation. Some validators still accept semantically impossible or request-inconsistent records:

- `ErrorEnvelopeV1::validate` accepts arbitrary combinations of a known `code`, `retryable`, and `outcome`, and does not restrict optional IDs/counts to applicable codes: `src/contracts.rs:250-299`.
- Lifecycle success validation does not bind `dry_run`, `cutoff_ms`, selectors, or limits to the originating request: `src/ipc.rs:904-913` and `src/node.rs:5745-5766`.
- `DownloadCompleteV1` does not enforce consistency between `destination_synced`, `cleanup_complete`, and `warnings`: `src/ipc.rs:467-493`.
- `OffersV1` accepts up to 1,024 entries even though the producer and documentation cap listing at 512: `src/ipc.rs:1255-1266` and `src/node.rs:164`.

The main architectural source of drift is that producers often construct ad-hoc `serde_json::Value` objects while consumers deserialize separately defined DTOs. Shared serializable DTOs and request-aware validators would make incompatible producer output harder to create.

There are related documentation/diagnostic inconsistencies:

- The `daemon_offline` example in `docs/contracts.md:30-43` uses `"Command failed."`, but the validator requires `"Daemon is offline."` from `src/contracts.rs:87-90`.
- `ErrorEnvelopeV1::new` discards the supplied diagnostic at `src/contracts.rs:224-233`. Several call sites do not log that cause separately, so the statement that private causes remain available in local diagnostics is not consistently true.

### 5. Release gating is not yet one authoritative workflow — Medium

- [x] **Missing integration gates completed.** Linux CI and release validation now invoke the authoritative `tests/integration-idempotency.sh` and `tests/integration-v018-message-boundary.sh` scripts directly; the development checklist lists the same commands rather than duplicating their assertions.

The release workflow still does not require evidence that a tag's commit passed the main CI workflow. Its initial validation only checks that the tag matches the package version. Release jobs run extensive tests, but omit Clippy, dependency-policy checks, and installer syntax validation.

Remaining recommended changes:

- Reuse one authoritative verification workflow for branch and release checks.
- Require the release tag to identify an approved main-branch commit with successful CI.
- Keep toolchain, audit, and policy-tool versions pinned.

### 6. Persistent-state reads are not allocation-bounded and state lacks a migration plan — Medium

Several persistent files are fully allocated before validation:

- `config.json`: `src/config.rs:139-141`
- Secret text: `src/config.rs:285-297`
- `alias.json`: `src/alias.rs:52-64`
- Attachment index: `src/node.rs:3480-3488`; its size is checked only after `std::fs::read` has allocated the complete file.

A corrupt or unexpectedly large local state file can therefore cause excessive startup allocation. `config.json` also has no top-level schema version, making future compatible migrations difficult.

Use a common bounded-reader helper, add a top-level state schema version and explicit migrations, and document backup/restore and failed-migration behavior.

### 7. Synchronous daemon output remains an availability risk — Medium

The daemon still writes event output synchronously from its network event loop at `src/node.rs`; the presentation function ultimately calls `println!`. A blocked stdout pipe or slow log consumer can therefore stall networking, status processing, and shutdown. Generated-event contract rejection no longer writes stderr: its sampled subscriber diagnostic carries exact suppression-since-last accounting. Other error paths still use synchronous `eprintln!`, and there are no meaningful tracing calls despite initializing `tracing-subscriber`.

Replace this with bounded nonblocking structured logging, sampling, and explicit drop/accounting metrics. This remains a production blocker already acknowledged by the release notes and `next_steps.md`.

### 8. Health and attachment-listing operability remain incomplete — Medium

Status exposes useful raw fields, but there is no explicit `ready`/`degraded` model or lightweight health endpoint. Operators must infer health from fields such as `endpoint_online`, `topic_joined`, replay availability, and storage pressure.

Attachment storage permits up to 8,192 tags, while `offers` returns only the first 512 and has no cursor or pagination. When `has_more` is true, an operator cannot enumerate subsequent entries through the API. Add cursor-based pagination or another bounded full-inventory mechanism.

### 9. Module size and duplicated contract logic now present greater audit risk — Medium maintainability

The hardening work substantially increased already large modules:

- `src/node.rs`: 11,964 lines
- `src/web.rs`: 3,200 lines
- `src/ipc.rs`: 2,649 lines

There are duplicate ID validators, lifecycle DTOs, ad-hoc JSON producers, and response validators spread across these files. The remaining empty-message and offer-ID bugs demonstrate the resulting producer/consumer drift risk.

Split wire formats, typed DTOs, daemon command handling, attachment storage/transfers, benchmark handling, platform IPC, and CLI presentation into focused modules. Make shared contract types the serialization path, rather than validation-only mirrors.

### 10. Release provenance and stress validation remain open — Medium

The following items are correctly acknowledged as incomplete and remain necessary for stronger production claims:

- pinned Rust toolchain;
- fuzzing of postcard/JSON/wire parsers and state recovery;
- slowloris, sustained load, and backpressure tests;
- broader native cross-platform no-clobber/crash testing;
- signed release provenance and an SBOM.

The release-hosted `SHA256SUMS` protects against accidental corruption, not compromise of the release account or artifact-producing workflow.

## `next_steps.md` cleanup needed

Several statements in the existing review are stale or too broad:

- The positional input-limit bypass has been fixed.
- The `socket`/`local_endpoint` cleanup claim was historically stale: v0.1.18 already omitted both from public JSON status and `daemon_started` records. This continuation did not change JSON; it removed only the human renderer's leftover empty `local endpoint:` startup line, so startup now prints the useful peer line alone.
- The uppercase-offer impact has changed: current code generally rejects the event/download rather than creating an invisible persistent pin, but the mismatch can still terminate feeds and waste transfer work.
- The listed module sizes are substantially outdated.
- `truncated` and `has_more` remain redundant compatibility fields without a removal version.
- The 1 MiB offer input limit still conflicts with the approximately 25 KiB maximum IPC request frame.
- The idempotency finding should explicitly state that only send, private-send, and share use operation IDs.
- The typed-contract finding should remain partially open until producer/consumer and request-semantic validation are unified.

## Verification performed

At the clean `v0.1.18` tagged revision:

- `cargo fmt --all -- --check` passed.
- `cargo clippy --locked --all-targets -- -D warnings` passed.
- `cargo test --locked --all-targets` passed with 219 tests.
- `cargo build --locked` passed.
- Focused idempotency, CLI-error, web/UI, syntax, attachment, direct-message, peer, and compatibility checks passed.
- The empty-message side-effect/feed-termination issue was reproduced against the built binary.

Native Windows and musl execution and local `cargo-audit`/`cargo-deny` execution were unavailable during the audit; those remain CI responsibilities.

Findings 1, 2, and the finding 5 integration gates were subsequently verified with `cargo fmt --all -- --check`, 227 full Rust tests, Clippy with warnings denied, and a locked debug build. The CLI-error, fake/real web (including live SSE `internal_contract_error` continuity and suppression accounting), idempotency, five-peer, peer-directory, attachment, direct-message (including positional/file/stdin 3900/3901/4096/4097 private boundaries), published-version IPC, and pinned v0.1.18 mixed-boundary integration (old daemon production to a current daemon/client, and current daemon production to an old daemon/client) all passed; browser asset syntax and UI tests also passed. Crafted signed malformed text and attachment EnvelopeV2 cases are exercised in the focused receive pipeline because there is intentionally no public raw-envelope injection command. Native Windows and musl execution remain CI-only.

## Recommended order

1. Reject empty broadcasts before any side effect and prevent invalid internal events from reaching subscribers.
2. Canonicalize attachment IDs and bind offer IDs to envelope message IDs.
3. Add producer-to-consumer contract round-trip tests and request-aware semantic validation.
4. Decide and document the operation-ID boundary; add it to prune/download if request-level replay is required.
5. Reuse one authoritative CI/release verification workflow and require successful main-branch CI for release tags.
6. Introduce bounded state reads and a versioned migration policy.
7. Move daemon output off the event loop and add explicit readiness/degraded health.
8. Add attachment pagination, split large modules, pin the toolchain, and add fuzz/load/provenance coverage.
