# Stable JSON and IPC contracts

This document is the **authoritative local IPC and protocol contract**. Other guides
explain workflows and link here; when an exact wire limit, invariant, or retry rule
matters, this document is normative.

Local IPC uses exactly protocol version 4. Responses and events are strict tagged
typed variants inside one canonical frame shape; there are no per-family schema
versions or compatibility mappings.

## Correlation and mutation identity

A `request_id` is exactly 32 lowercase hexadecimal characters. It identifies one CLI result or IPC request. IPC responses and every event on an IPC subscription echo that request's ID.

An `operation_id` has the same lexical representation but a different meaning: it
identifies a retry-safe mutation and may be reused only for an identical mutation.
It is never generated from, compared with, or substituted for `request_id`.
Transport retries used to reconcile one uncertain operation have different request IDs and the same operation ID. A fresh attempt after a terminal condition-dependent `not_started` result uses a new operation ID. `send`,
`private_send`, `share`, `offers_remove`, `offers_prune`, and `download` all
require an operation ID. Downloads require the sole typed mode `install`; the removed raw export mode is rejected. Attachment `offer_id` and signed
message IDs retain their separate documented operation identity; a download's
operation ID is not its offer ID.

## Protocol-v4 error boundary

Daemon IPC errors are compact typed frames:

```json
{
  "protocol_version": 4,
  "type": "error",
  "code": "daemon_offline",
  "outcome": "not_started",
  "request_id": "0123456789abcdef0123456789abcdef"
}
```

`code` and `outcome` are closed enums owned by `meshmsg-protocol`. Mutation errors
also carry the exact typed `operation_id`. Unknown enum values, versions, fields,
or malformed IDs fail closed at that crate boundary. Errors never transmit a
display message, retryable flag, retry-advice field, offer selector, generic lifecycle
accounting, or suppression counter. CLI adapters derive stable user-facing text and
a local typed `RetryAdvice` from `ErrorCode`, `Outcome`, and operation correlation;
automation branches on those wire enums rather than display text. Advice distinguishes
reconciling the same possibly-started operation, making a new operation after a cached
condition failure, retrying the same request after pre-admission/non-mutation failure,
and never retrying. Lifecycle counts remain only on typed lifecycle success records.

With `--json`, one-shot failures write exactly one error object to **stdout**, write
nothing to stderr, and exit 1. Success exits 0. Streaming client commands use stdout
NDJSON. Human one-shot failures use stderr. The daemon is different: it never mirrors
events to stdout, even with `--json`; clients receive events through authenticated,
bounded `subscribe` IPC (`meshmsg listen`). Daemon startup and fatal errors use
stderr. There is no process diagnostic queue, output telemetry, bounded terminal
writer, or custom process panic hook. Clap help/version still exit successfully.

## IPC

The exact bounded values are:

| Contract | Exact maximum/value | Checked fact |
| --- | ---: | --- |
| Local IPC protocol version | 4 | `protocol_version` |
| Signed broadcast envelope version | 3 | `signed_broadcast_envelope_version` |
| Signed broadcast envelope | 65,536 bytes | `max_signed_broadcast_envelope_bytes` |
| Broadcast body (minimum is one byte) | 65,358 bytes | `max_broadcast_body_bytes` |
| Private/direct body (minimum is one byte) | 4,096 bytes | — |
| Signed attachment token | 87,382 bytes | `max_signed_attachment_token_bytes` |
| Serialized IPC path | 32,768 bytes | `max_ipc_path_bytes` |
| Peer snapshot entries | 1,024 | `max_peers` |
| Public offer-list entries | 512 | `max_offers` |
| Offer tag inspections | 4,096 | `max_offer_scan` |
| Lifecycle selection | 512 tags | `max_lifecycle_items` |
| Request frame, excluding newline | 1,129,432 bytes | `max_request_frame_bytes` |
| Response or event frame, excluding newline | 5,045,212 bytes (about 5 MiB) | `max_event_frame_bytes` |

Offer scans use one additional presence-only lookahead after the inspected-record
maximum.

The frame limits are directional: clients send request frames under the request
limit; daemon responses and subscription events use the larger response/event
limit. A response is not constrained by the request limit. Empty, over-limit, and
unterminated frames fail closed; an over-limit or incomplete buffered stream is not
resynchronized and reused.

Each newline-delimited request is a strict nested envelope:

```json
{
  "protocol_version": 4,
  "request_id": "0123456789abcdef0123456789abcdef",
  "request": { "command": "status" }
}
```

The typed command union is: `send`, `private_send`, `subscribe`, `status`,
`peers`, `offers`, `offers_remove`, `offers_prune`, `share`, `download`, and `stop`. Unknown, missing, duplicate, or wrong-typed envelope or
command fields are rejected. Unsupported versions and malformed IDs fail closed.
One-shot responses and subscription records are decoded in context as `ResponseFrame`
and `EventFrame`, respectively. There is no generic daemon-frame decoder because
several response and event families intentionally share the same wire shape. Each
exact `type` tag is fully deserialized into a deny-unknown-fields typed variant with
semantic and bounded-value checks.
Broadcast producers, EnvelopeV3 receivers, and event consumers accept 1 through
65,358 UTF-8 bytes. This single conservative limit subtracts the 178-byte
worst-case postcard metadata/signature overhead (including maximum-width timestamp
and body-length varints) from the complete 65,536-byte signed-envelope bound.
Private/direct sends retain their separate 1 through 4,096-byte body and 6 KiB
transport-frame contract. The complete 65,536-byte broadcast envelope bound is
checked before decoding. Local rejection occurs
before throttle/operation-cache admission, has `code:"invalid_message"` and
`outcome:"not_started"`, and preserves the operation ID. Invalid signed remote text or attachment semantics are rejected before accepted-traffic
or replay/rate admission and fanout, while every frame still pays a separate bounded
pre-verification attempt budget. Attachment validation binds one canonical lowercase
operation/offer ID plus the configured signed topic, kind, provider, ticket hash/format,
name, size, and nonzero timestamp before download registration or transfer work. Live
IPC attachment events must remain inside the wire freshness window. Saved signed
download tokens deliberately do not expire by timestamp, but revalidate the nonzero time,
signature, configured topic, identity, and complete metadata before any network work.
Daemon-created message, queued, and attachment events cross the same typed event
boundary before publication. Subscription frames are decoded directly into the closed
typed event union; unknown families, protocol versions, unknown fields, malformed
IDs, and invalid event semantics fail the read and terminate that subscription. They
are not repaired into a synthetic error event, skipped, or followed by later frames
from the same subscription. This applies to every command response and subscription event, including
stop, attachment share/download metadata, and lifecycle/progress/loss/peer events.
Download progress permits `0/0` only for an empty blob; otherwise `total_bytes` is
positive and `received_bytes <= total_bytes`. A CLI download accepts completion only
when `output` has the exact retained OS-string/byte representation it submitted;
Path-equivalent dot components, repeated/trailing separators, and other lexical
rewrites are rejected. Listen/chat therefore never print an unrecognized daemon event.
Error objects are strictly decoded against the closed error contract. Status includes replay limits, mutation-cache semantics, attachment limits, and
attachment-storage pressure. Clients and the daemon are one protocol-v4 component
set, so commands are submitted directly without status capability probes.

CLI-only setup/state-file records are `initialized`, `joined`, `alias`, `invite`,
and `doctor`; they do not cross IPC. The exhaustive
IPC success/event families are:

- lifecycle response: unit `stopping` acknowledgement (no `outcome` field);
- state/directory: `status`, `connected`, `peers_snapshot`, and
  `peer_discovered`/`peer_updated`/`peer_expired`;
- messaging: `queued`, `private_accepted`, `message`, and `private_message`;
- attachment: `attachment_offer`, `attachment_shared`, `offers`, `offer_removed`,
  `offers_pruned`, `download_started`, `download_progress`, and `download_complete`
  (all lifecycle/download records carry their operation ID);
- loss indication: `lagged`.

Local filesystem paths are no longer present in status/daemon-started contracts.
Attachment commands that inherently select a caller-owned input/output path keep it
only on owner-authenticated IPC. Every request, response, and event `PathBuf` must
be an absolute UTF-8 path whose serialized value is at most 32,768 bytes; one byte
over fails typed validation. Checked frame derivation sums simultaneous worst-case
body/token/path input and, for output, body, two tokens, path, warnings, maximum
peer snapshot, and maximum offer listing before applying sixfold JSON escaping.
CLI share/download paths are made absolute without canonicalization and validated
before daemon contact or typed frame construction; fallible frame constructors
return bounded-path errors rather than panicking. A download request's `output` is
required and absolute, and every `download_started`, `download_progress`, and
`download_complete` record repeats that exact lexical path representation.

## Attachment limits and defaults

These are the canonical attachment runtime defaults and hard bounds. Byte values use
binary units.

| Attachment contract | Exact value |
| --- | ---: |
| Default maximum file/archive blob | 4,294,967,296 bytes (4 GiB) |
| Default retained unique-blob quota | 17,179,869,184 bytes (16 GiB) |
| Default minimum free-space reserve | 1,073,741,824 bytes (1 GiB) |
| Default automatic retention | 0 seconds (disabled) |
| Retention check interval when enabled | 3,600 seconds |
| Maximum tags selected per retention/lifecycle pass | 512 |
| Maximum tracked meshmsg attachment pins | 8,192 |
| Maximum reserved-prefix records examined at startup | 16,385 |
| Concurrent attachment operations admitted | 2 |
| Concurrent store mutations | 1 |
| Transfer timeout and post-removal GC grace | 3,600 seconds |
| Download progress step | 8,388,608 bytes (8 MiB) |
| Free-space refresh interval | 30 seconds |
| Maximum directory archive entries | 10,000 |
| Maximum directory archive depth | 64 components |

The byte-valued daemon options and environment variables override the first three
rows; values must be nonzero. Automatic retention remains opt-in: zero disables it.
The lifecycle maximum is also the upper bound for `max_delete` and the `maximum`
field in remove/prune results.

## Compatibility and migration

Protocol v4 is an intentional local-API compatibility boundary. It removes the
ambiguous generic `DaemonFrame` API in favor of context-specific `ResponseFrame` and
`EventFrame` decoding; removes the never-emitted `stopping` and `error` event
variants; replaces the string-valued stop outcome with a unit `stopping` response;
splits the option-heavy lifecycle result into strict `OfferRemoved` and
`OffersPruned` DTOs; and removes inactive legacy HTTP/web error codes. In v4 remove
responses omit prune-only `older_than_secs`, `dry_run`, and `cutoff_ms`, while prune
responses omit remove-only `offer_id` and `provider`; fields required by each family
are no longer nullable. The removed inactive error codes are `daemon_unavailable`,
`capacity_or_offline`, `invalid_operation_id`, `invalid_source_digest`,
`invalid_offer_selector`, `invalid_prune_request`, `unsupported_schema`,
`share_operation_capacity`, `download_operation_capacity`,
`download_staging_unavailable`, `invalid_daemon_response`, `request_rejected`,
`feed_error`, `startup_failed`, `request_forbidden`, `not_found`,
`payload_too_large`, `unsupported_media_type`, `invalid_range`,
`idempotency_unsupported`, `request_throttled`, `send_throttled`,
`request_timeout`, `request_failed`, `send_outcome_unknown`, and
`share_outcome_unknown`. Every code emitted by the daemon or current CLI adapters is
retained. Clients send only strict protocol-v4 IPC envelopes and require exact
correlated replies. Older clients and daemons are rejected before any
payload is consumed. There is no permissive downgrade, capability probe, or field
defaulting; operators must reinstall and restart the CLI and daemon together. Broadcast EnvelopeV3 and
`/meshmsg/broadcast-gossip/3` are intentional hard breaks: V2 envelopes, signed
attachment tokens, and Gossip peers are rejected without negotiation or fallback.
Current broadcasts are uniformly limited to 65,358 UTF-8 bytes inside a 65,536-byte
envelope.

## Operation retries and cache

| Cache contract | Exact value |
| --- | ---: |
| Completed plus in-flight operation capacity | 1,024 |
| Terminal-result TTL from completion | 600,000 ms (10 minutes) |
| Persistence | memory-only; cleared on daemon restart |

Matching concurrent requests join one execution. A terminal success, failure, or
post-install partial success is replayed for the terminal-result TTL;
oldest terminal entries can be evicted under pressure, while in-flight entries are
never evicted. IDs are global across operation kinds. Fingerprints bind kind and
exact inputs: message/recipient/body, share path/content digest, lifecycle selectors,
age/dry-run/limit, and download token, `DownloadMode::Install`, plus exact output OS representation. Changed
input returns `operation_id_conflict` without work. For prune, the cached terminal
record is the authoritative original selected set/result, so a retry cannot consume
the next batch and `max_delete` bounds one operation. For remove, an exact retry
replays the original counts rather than recomputing the already-achieved end state.
For download, replay occurs before the no-clobber check and prevents duplicate
network/export/install work. `download_complete` includes a domain-separated
SHA-256 digest of the exact submitted token; the shared request-aware validator binds operation ID, token identity, offer ID, provider, kind, name,
signed declared size when present, and exact output representation. A cached partial-success `download_complete` remains a
success; callers inspect durability warnings rather than retrying the installed
path. Once the memory-only entry expires, is evicted, or the daemon restarts, the
retry guarantee ends: a retry is a new execution and an existing output fails closed
without clobbering. Status exposes these bounds and `operation_cache_persistent:false`. Unit tests
exercise synthetic expiry and pressure eviction deterministically; integrations
exercise real response loss and daemon restart, not a ten-minute wall-clock wait.

## Offer listing

`offers` contains at most 512 entries. `truncated` reports an incomplete bounded
result. Every inspected reserved-prefix record that cannot become a public item—an
unreadable item, malformed meshmsg tag, unsupported format, missing or partial blob,
or per-item store failure—is omitted and increments `item_errors`; any nonzero
`item_errors` forces `truncated:true`. These errors are diagnosed privately, not
included as per-item wire details. Producer validation is bounded to 4,096 tag
records plus one presence-only lookahead, including records after the 512th public
item. A list/stream
failure returns canonical `offers_failed` rather than panicking. The current variant
has no cursor, so truncation is a bounded prefix rather than pagination.

## Lifecycle contract

Lifecycle successes and compact partial errors repeat the exact operation ID. The
`offer_removed` DTO contains its offer/direction/provider selectors, maximum, and
counts; the `offers_pruned` DTO contains its direction, required effective age,
dry-run mode, maximum, required daemon cutoff, and counts. Remove has no cutoff.
Canonical protocol-v4 lifecycle successes are, for example:

```json
{"protocol_version":4,"request_id":"0123456789abcdef0123456789abcdef","type":"offer_removed","operation_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","offer_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","direction":"outgoing","provider":null,"maximum":512,"selected_tags":1,"removed_tags":1,"released_bytes":1234,"limited":false}
```

```json
{"protocol_version":4,"request_id":"0123456789abcdef0123456789abcdef","type":"offers_pruned","operation_id":"cccccccccccccccccccccccccccccccc","direction":null,"older_than_secs":86400,"maximum":10,"dry_run":true,"selected_tags":10,"removed_tags":0,"released_bytes":1234,"limited":true,"cutoff_ms":1699913600000}
```

The remove record has no `older_than_secs`, `dry_run`, or `cutoff_ms`; the prune
record has no `offer_id` or `provider`. Required fields are not nullable unless shown
as such. The canonical prune request variant contains
`operation_id`, required `older_than_secs`, nullable `direction`, `dry_run`, and
`max_delete`; it never contains `cutoff_ms`. Strict deny-unknown-fields decoding
therefore rejects cutoff-only, age-plus-cutoff, future-cutoff, saturated-cutoff, and
selector/cutoff combinations instead of letting raw clients choose a boundary.

The operation fingerprint binds only stable caller intent: kind, effective age,
direction, dry-run, and maximum. For the first admitted owner, the daemon resolves
`cutoff_ms = daemon_now_ms.saturating_sub(
older_than_secs.saturating_mul(1000))`; multiplication and subtraction cannot
overflow, age zero uses admission time, and sufficiently large ages resolve to zero.
That resolution is retained as authoritative in the in-flight and completed cache
entry, drives selection, and is repeated in success or partial-error output.
Concurrent duplicates join it and terminal retries replay it without consulting the
clock. This preserves delayed execution, backward-clock behavior, and retries up to
the cache TTL while ensuring an identical CLI retry does not need a value from the
lost response. Changed age/selectors/mode/limit conflict; cutoff is not caller input.
Selection is bounded by `maximum`; `limited:true` requires a full selection;
successful non-dry-run removal has equal selected and removed counts; dry-run removes
zero; and an empty selection releases zero bytes. The same request-aware DTO
validator is used by production IPC dispatch and CLI consumption and binds the
required daemon-authoritative cutoff. The protocol-v4 lifecycle command is submitted directly and its strict response is
validated before consumption.

Attachment operation errors use the same compact boundary and retain exact
operation-ID correlation. Lifecycle selectors and counts exist only in typed requests
and lifecycle success variants; they are not repeated in generic errors.

Adding or changing fields requires a future protocol-version migration because typed
variants deny unknown fields. Unsupported protocol versions always fail closed.
