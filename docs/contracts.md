# Stable JSON and IPC contracts

Local IPC uses exactly protocol version 2. Responses and events are strict tagged
typed variants inside one canonical frame shape; there are no per-family schema
versions or compatibility mappings.

## Correlation and mutation identity

A `request_id` is exactly 32 lowercase hexadecimal characters. It identifies one CLI result or IPC request. IPC responses and every event on an IPC subscription echo that request's ID.

An `operation_id` has the same lexical representation but a different meaning: it
identifies a retry-safe mutation and may be reused only for an identical mutation.
It is never generated from, compared with, or substituted for `request_id`.
Different retries have different request IDs and the same operation ID. `send`,
`private_send`, `share`, `offers_remove`, `offers_prune`, and `download` all
require an operation ID. Downloads require the sole typed mode `install`; the removed raw export mode is rejected. Attachment `offer_id` and signed
message IDs retain their separate documented operation identity; a download's
operation ID is not its offer ID.

## Protocol-v2 error boundary

Daemon IPC errors are compact typed frames:

```json
{
  "protocol_version": 2,
  "type": "error",
  "code": "daemon_offline",
  "outcome": "not_started",
  "request_id": "0123456789abcdef0123456789abcdef"
}
```

`code` and `outcome` are closed enums owned by `meshmsg-protocol`. Mutation errors
also carry the exact typed `operation_id`. Unknown enum values, versions, fields,
or malformed IDs fail closed at that crate boundary. Errors never transmit a
display message, retryable flag, offer selector, generic lifecycle accounting, or
suppression counter. CLI adapters derive stable user-facing text and retry
guidance from `ErrorCode` and `Outcome`; automation branches on those enums rather
than display text. Lifecycle counts remain only on typed lifecycle success records.

With `--json`, one-shot failures write exactly one error object to **stdout**, write
nothing to stderr, and exit 1. Success exits 0. Streaming client commands use stdout
NDJSON. Human one-shot failures use stderr. The daemon is different: it never mirrors
events to stdout, even with `--json`; clients receive events through authenticated,
bounded `subscribe` IPC (`meshmsg listen`). Daemon startup and fatal errors use
stderr. There is no process diagnostic queue, output telemetry, bounded terminal
writer, or custom process panic hook. Clap help/version still exit successfully.

## IPC

Each newline-delimited request is a strict nested envelope:

```json
{
  "protocol_version": 2,
  "request_id": "0123456789abcdef0123456789abcdef",
  "request": { "command": "status" }
}
```

The typed command union is: `send`, `private_send`, `subscribe`, `status`,
`peers`, `offers`, `offers_remove`, `offers_prune`, `share`, `download`, and `stop`. Unknown, missing, duplicate, or wrong-typed envelope or
command fields are rejected. Unsupported versions and malformed IDs fail closed.
Responses are dispatched by the exact `type` tag and then fully deserialized into
a deny-unknown-fields typed variant with semantic and bounded-value checks.
New broadcast producers accept 1 through 3900 UTF-8 bytes. Private/direct sends
retain their separate 1 through 4096-byte body contract. EnvelopeV2 and event
consumers retain the released v0.1.18-compatible 1 through 3928-byte worst-case
range. That exact maximum occurs with a one-byte postcard timestamp; the complete
4096-byte envelope bound is still checked before decoding. Local rejection occurs
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
attachment-storage pressure. Clients and the daemon are one protocol-v2 component
set, so commands are submitted directly without status capability probes.

CLI-only setup/state-file records are `initialized`, `joined`, `alias`, `invite`,
and `doctor`; they do not cross IPC. The exhaustive
IPC success/event families are:

- lifecycle: `stopping`;
- state/directory: `status`, `connected`, `peers_snapshot`, and
  `peer_discovered`/`peer_updated`/`peer_expired`;
- messaging: `queued`, `private_accepted`, `message`, and `private_message`;
- attachment: `attachment_offer`, `attachment_shared`, `offers`, `offer_removed`,
  `offers_pruned`, `download_started`, `download_progress`, and `download_complete`
  (all lifecycle/download records carry their operation ID);
- loss indication: `lagged`.

Local filesystem paths are no longer present in status/daemon-started contracts.
Attachment commands that inherently select a caller-owned input/output path keep it
only on owner-authenticated IPC.

## Compatibility and migration

This is an intentional local-API compatibility boundary. Clients send only strict
protocol-v2 IPC envelopes and require exact correlated replies. Older clients and
daemons are rejected before any payload is consumed. There is no permissive
downgrade, capability probe, or field defaulting; operators must upgrade and restart
the CLI and daemon together. Network gossip/direct protocol
compatibility is unchanged.

The shared daemon cache admits at most 1,024 completed plus in-flight operations.
Matching concurrent requests join one execution. A terminal success, failure, or
post-install partial success is replayed exactly for ten minutes from completion;
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

`offers` contains at most 512 entries. `truncated` reports an incomplete bounded result; malformed meshmsg tags, unsupported formats, missing or
partial blobs, and per-item store failures are omitted, counted, privately diagnosed,
and force truncation. Producer validation is bounded to 4096 tag records plus one
presence lookahead, including records after the 512th public item. A list/stream
failure returns canonical `offers_failed` rather than panicking. The current variant
has no cursor, so truncation is a bounded prefix rather than pagination.

Lifecycle successes and compact partial errors repeat the exact operation ID;
remove/prune selectors, effective age, dry-run mode, maximum, and applicable cutoff.
Remove has no cutoff. The canonical prune request variant contains
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
validator is used by production, generic IPC dispatch, and CLI consumption;
caller-side validation accepts one required daemon-authoritative cutoff while
producer/generic validation binds its exact value. The protocol-v2 lifecycle command is submitted directly and its strict response is
validated before consumption.

Attachment operation errors use the same compact boundary and retain exact
operation-ID correlation. Lifecycle selectors and counts exist only in typed requests
and lifecycle success variants; they are not repeated in generic errors.

Adding or changing fields requires a future protocol-version migration because typed
variants deny unknown fields. Unsupported protocol versions always fail closed.
