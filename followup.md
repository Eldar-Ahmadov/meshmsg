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

- [x] **Status: completed.** AttachmentOffer EnvelopeV2 semantics are now fully checked after signature verification and before accepted-traffic or replay/rate admission (every frame still pays a separate bounded pre-verification attempt budget): the body must be a typed nonempty offer, its display name and kind must deserialize through the safe structural types, the offer ID uses the one shared canonical lowercase operation-ID validator, the envelope message ID must equal it, and the canonical raw ticket's provider/hash/format must match the signer and signed metadata. The configured signed topic, envelope kind, and nonzero timestamp are checked at the same boundary; live events enforce the normal freshness window, while saved signed download tokens intentionally remain portable after that window and revalidate every other signed relationship.
- Strict request-context-aware IPC and HTTP/SSE consumers decode the signed offer again and bind the configured topic plus every duplicated provider/message-ID/timestamp/kind/name/size/ticket field to it before fanout, download registration, or transfer work. Signed CLI/web downloads reuse the wire validator. Local publication validates the resulting envelope before persistent tag generation, and reserved tag parsing uses the shared lowercase validator.
- Crafted malformed-body, uppercase, mixed-case, mismatched envelope/offer ID, provider/topic/time, unsafe-name, non-raw-format, duplicate/replay, alternate-envelope-ID, and operation-ID-reuse cases prove rejection without accepted-traffic or replay/rate consumption. Dedicated token tests prove stale, future, and replay frames consume only the cheap verification budget and leave valid retries/unrelated traffic admissible. Contract-field mutation, generated-event guard, strict-subscription continuity, and real peer/web attachment coverage prove malformed offers cannot create download handles or terminate live feeds, while released valid V2 offers remain accepted.

### 3. End-to-end idempotency does not cover every mutating operation — Medium-high

- [x] **Status: completed.** `offers_remove`, `offers_prune`, `download`, and `web_download` now carry reusable client-generated lowercase 128-bit operation IDs from CLI/HTTP through strict IPC DTOs to the daemon, distinct from each attempt's request ID. A new `idempotent_attachment_operations_v1` capability is negotiated before CLI lifecycle/download submission and browser controls are exposed; mixed old/new components fail closed. Lifecycle and download success/progress families moved to strict schema version 2 with mandatory operation IDs, and all operation errors are ID-bound.
- The existing bounded 1,024-entry/10-minute memory-only operation cache now covers all seven operation kinds. Exact concurrent duplicates join; exact terminal successes, failures, and post-install partial successes replay; cross-kind or changed selectors, age/dry-run/limit, signed/raw token, exact output representation, path, digest, recipient, or content return `operation_id_conflict` before work. In-flight entries are retained under pressure and oldest terminal entries are evicted. Expiry, eviction, and daemon restart explicitly end replay guarantees.
- Prune's first execution owns the selected set and terminal result, so response-loss retries cannot delete a later batch and `--max-delete` is a per-operation side-effect bound. Remove still has safe absent end-state behavior but same-ID retries replay the authoritative original counts/result. Downloads replay before no-clobber and therefore do not repeat network/export/install work; cached warning-bearing partial success remains success. After replay state is lost, existing output fails closed without clobbering and requires reconciliation.
- Browser download admission now uses one locked operation registry that atomically binds immutable offer input, one owner task, and one output. Concurrent exact starts join and changed offers conflict; only the current owner can publish Ready/failure or remove output. Canonical download-applicable polled `not_started` failures rotate the next user attempt's ID; malformed/cross-kind errors do not. Unknown timeout/disconnect failures stop polling, retain the ID, and allow at most three total same-ID preparation attempts (the initial attempt plus two reconciliations) so daemon-cached late success can be recovered without an unbounded stale-failure loop. Local capacity or staging failures during reconciliation replay the retained unknown without consuming an attempt or rotating its ID. Start/pending/ready records repeat that ID, and ready URLs must be the exact unencoded same-origin download route.
- Focused contract/cache tests cover strict versions, code-applicable lifecycle errors, full request-aware completion binding, controlled concurrent web admission/ownership ordering, kind/input fingerprints, joins, terminal failures/partial success, pressure eviction, and synthetic expiry/restart. `tests/integration-idempotency.sh`, fake/real web, UI, attachment, CLI/IPC compatibility, and lifecycle suites cover real lost responses, unknown late-success reconciliation, polled rejection/ID rotation, prune selection stability/no additional deletion, authoritative remove replay, no extra download/install, changed-input conflicts, browser polling/retries, and negotiated fail-closed behavior. Ten-minute expiry and pressure eviction are deterministic unit evidence; integrations cover process restart rather than sleeping through production TTLs.

### 4. Typed contracts remain structurally strict but semantically incomplete — Medium

- [ ] **Status: substantially implemented; final review remains open.** `src/contracts.rs` now owns the canonical closed error-code specification: each code has exact public text, admitted outcome/retryability pairs, operation-kind applicability, and offer/removal/suppression field policy. The fallible constructor rejects invalid producer semantics; the legacy infallible boundary emits an explicit canonical `internal_contract_error` rather than silently rewriting the requested code. Strict decoders reject malformed combinations, and operation-aware consumers require the exact operation kind and operation ID. Table-driven tests cover every admitted code, every operation kind, each admitted pair, and wrong message/retryability/field combinations.
- Private constructor diagnostics are bounded to 2,048 UTF-8 bytes and retained in a 256-record in-process telemetry ring; human mode also offers them without blocking to a 128-record channel whose worker owns stderr. JSON mode suppresses that sink to retain empty stderr. Contended evidence admission and full/disconnected sink queues are nonblocking and counted, poisoned evidence state is recovered without panic, and accepted/dropped/retained metrics are exposed through separately negotiated strict `diagnostic_status` v1 while exact released-compatible status v1 remains unchanged. Tests demonstrate that a private path remains in local evidence while fixed public JSON does not contain it. Documentation no longer claims lossless or process-persistent diagnostics.
- Lifecycle success moved to shared serializable `LifecycleSuccessV3` plus one request-aware validator used by producer, generic IPC dispatch, and CLI consumption. Success and partial-error records repeat operation ID, selectors, effective age, dry-run, maximum, and cutoff context and enforce selection/truncation/count/byte invariants. Prune resolves its effective age and concrete cutoff before submission with `request_now.saturating_sub(age.saturating_mul(1000))`, transmits that required cutoff in strict IPC, and binds it into selection, operation fingerprint/cache identity, success, and partial errors. No daemon-side clock derivation remains, preserving millisecond crossings, long execution, near-TTL replay, and backward-clock behavior; changed cutoffs conflict. `attachment_lifecycle_v3` negotiation makes old schema-v2 daemons fail closed before mutation while preserving operation-cache fingerprints and replay behavior.
- `OffersV1` and `OfferItemV1` are now shared producer/consumer DTOs with the producer's documented 512-entry cap, equal `truncated`/`has_more`, item-error/truncation coherence, and the 4,096-record scan bound. Production validates missing/partial/unsupported/malformed items without panicking, continues bounded accounting after the public cap, and emits canonical `offers_failed` on list/DTO failure. Tests cover 512/513 public boundaries, real-store 4095/4096/4097 scan exhaustion/lookahead, capped malformed-item accounting, missing/partial/hash-seq status failures, and malformed completeness combinations.
- A focused production inventory replaced ad-hoc construction for error-cache, lifecycle-success, and offers-list output with shared constructors; download completion was already shared and request-bound. Broad unrelated event/benchmark refactoring remains under the module-splitting maintainability finding rather than being riskily mixed into this fix. `docs/contracts.md` has the canonical `daemon_offline` example and current diagnostic/lifecycle/listing semantics.
- Remaining review work is intentionally not resolved in this commit: prune retry ergonomics, final prune request-contract reconciliation, and corresponding documentation review must be completed before this finding can be marked closed.

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

- `src/node.rs`: 12,541 lines
- `src/web.rs`: 3,307 lines
- `src/ipc.rs`: 2,939 lines

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
- The idempotency finding was stale; all mutating lifecycle and download operations now use operation IDs and the new attachment-operation capability.
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

Finding 3 and its review follow-ups were subsequently verified with formatting, 234 full Rust tests, Clippy with warnings denied, locked debug and release builds, shell/Python/JavaScript syntax checks, and the complete CLI-error, fake/real web, UI, idempotency, five-peer, peer-directory, attachment, direct-message, IPC-version, and pinned-v0.1.18 compatibility integrations. The extended idempotency harness proves lost prune/download replies, stable prune selection and per-operation limits, authoritative remove replay, no second deletion/install, and CLI changed-selector/limit/output conflicts. Focused tests prove code-applicable lifecycle errors, exact partial-failure replay, full valid-but-wrong completion-field rejection, controlled concurrent browser admission and owner-only publication/cleanup ordering, bounded unknown reconciliation, synthetic cache/job expiry, pressure eviction, and daemon restart; fake/real web and UI integrations cover concurrent starts, late cached-success recovery, polled rejection ID rotation, timeout/disconnect handling, and process restart. Native Windows and musl execution remain CI-only.

The current finding 4 implementation was verified with 245 full Rust tests, including an independently enumerated mutation-consumer error matrix, malformed semantic combinations, real producer→operation-cache→normalizer→strict-consumer partial remove/prune paths, age-bound overflow-safe cutoff and replay-clock boundaries, status-v1 compatibility plus diagnostic-status versioning, offers 512/513 and real-store 4095/4096/4097 boundaries, and private-diagnostic/public-sanitization evidence. Formatting, Clippy with warnings denied, locked debug/release builds, shell/Python/JavaScript syntax checks, CLI errors, UI, idempotency, attachments/lifecycle, direct messages, IPC version compatibility, pinned-v0.1.18 boundaries, five-peer, peer-directory, and fake/real web integrations all passed. Native Windows and musl execution remain CI-only.

Findings 1, 2, and the finding 5 integration gates were subsequently verified with `cargo fmt --all -- --check`, 231 full Rust tests, Clippy with warnings denied, and a locked debug build. The CLI-error, isolated fake/real web (including live SSE `internal_contract_error` continuity, suppression accounting, and same-process daemon topic replacement with old-topic rejection and new-topic offer/share delivery), idempotency, five-peer, peer-directory, attachment, direct-message (including positional/file/stdin 3900/3901/4096/4097 private boundaries), published-version IPC, and pinned v0.1.18 mixed-boundary integration (old daemon production to a current daemon/client, and current daemon production to an old daemon/client) all passed; browser asset syntax and UI tests also passed. Crafted signed malformed text and attachment EnvelopeV2 cases are exercised in the focused receive pipeline because there is intentionally no public raw-envelope injection command. Native Windows and musl execution remain CI-only.

## Recommended order

1. Reject empty broadcasts before any side effect and prevent invalid internal events from reaching subscribers.
2. Canonicalize attachment IDs and bind offer IDs to envelope message IDs.
3. Add producer-to-consumer contract round-trip tests and request-aware semantic validation.
4. [x] Extend and document the operation-ID boundary through lifecycle and CLI/browser download operations.
5. Reuse one authoritative CI/release verification workflow and require successful main-branch CI for release tags.
6. Introduce bounded state reads and a versioned migration policy.
7. Move daemon output off the event loop and add explicit readiness/degraded health.
8. Add attachment pagination, split large modules, pin the toolchain, and add fuzz/load/provenance coverage.
