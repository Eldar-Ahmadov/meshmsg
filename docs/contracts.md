# Stable JSON, IPC, HTTP, and SSE contracts

The stable application contract is `typed_contracts_v1`. JSON objects use a numeric
`schema_version`; version 1 is the common envelope version. A family may have a
higher version where its payload evolved (for example `message`/peer-directory v2
and mutation results v3). Family versions are exact, not minimum versions.

## Correlation and mutation identity

A `request_id` is exactly 32 lowercase hexadecimal characters. It identifies one
CLI result, one HTTP exchange/SSE connection, or one IPC request. `POST
/api/request` requires exactly one valid `X-Meshmsg-Request-Id` header and requires
that the strict JSON outer envelope repeat the same ID. A missing, duplicated,
malformed, or body/header-mismatched ID is rejected before IPC. Other routes may
omit the header; the bridge then generates an ID for the exchange. Every response
returns its exchange ID in `X-Meshmsg-Request-Id` and every JSON body. The HTTP
bridge passes the same ID to IPC. IPC responses and every event on an IPC subscription echo that
request's ID.

An `operation_id` has the same lexical representation but a different meaning: it
identifies a retry-safe mutation and may be reused only for an identical mutation.
It is never generated from, compared with, or substituted for `request_id`.
Different retries have different request IDs and the same operation ID. Attachment
`offer_id` and signed message IDs retain their documented operation identity.

## Error envelope

Every machine-readable application error is:

```json
{
  "type": "error",
  "schema_version": 1,
  "code": "daemon_offline",
  "message": "Command failed.",
  "retryable": true,
  "outcome": "not_started",
  "request_id": "0123456789abcdef0123456789abcdef"
}
```

`code` is a closed, stable lowercase ASCII token. Each admitted code maps to one
fixed bounded public message; unknown codes and noncanonical messages fail closed.
`message` contains no control characters (including tabs) and is at most 1024 UTF-8
bytes. Internal causes and paths remain only in local diagnostics; automation must
branch on `code`. `outcome` is exactly
`not_started`, `unknown`, or `partial`. `request_id` is omitted only when no request
could be decoded or admitted (for example pre-frame IPC timeout/capacity output).
`operation_id`, `offer_id`, and attachment partial-count fields appear only where
relevant. HTTP replaces private daemon diagnostics with fixed public messages.

With `--json`, one-shot failures write exactly one error object to **stdout**, write
nothing to stderr, and exit 1. Success exits 0. Streaming commands use stdout NDJSON;
a terminal process failure follows the same error rule. Without `--json`, diagnostics
remain human-readable on stderr. Clap help/version still exit successfully.

## IPC

Each newline-delimited request is a strict nested envelope:

```json
{
  "schema_version": 1,
  "request_id": "0123456789abcdef0123456789abcdef",
  "request": { "command": "status" }
}
```

The typed command union is: `send`, `private_send`, `bench_send`, `subscribe`,
`status`, `peers`, `offers`, `offers_remove`, `offers_prune`, `share`, `download`,
`web_download`, and `stop`. Unknown, missing, duplicate, or wrong-typed envelope or
command fields are rejected. Unsupported versions and malformed IDs fail closed.
Responses are dispatched by the exact `(type, schema_version)` pair and then fully
deserialized into a deny-unknown-fields DTO with semantic and bounded-value checks.
Unknown families, unsupported versions, and unknown/missing/wrong-typed fields fail
closed. This applies to every command response and subscription event, including
stop, attachment share/download metadata, lifecycle/progress/loss/peer events, and
all benchmark records. Download progress permits `0/0` only for an empty blob;
otherwise `total_bytes` is positive and `received_bytes <= total_bytes`. A CLI
download accepts completion only when `output` has the exact retained OS-string/byte
representation it submitted; Path-equivalent dot components, repeated/trailing
separators, and other lexical rewrites are rejected. Benchmark send records are
version 2: `attempted = queued + failed + incomplete`, where the bounded `incomplete`
count identifies the one serial in-flight submission abandoned by cancellation or a
deadline, or for which the daemon reply was lost; no queued/failed classification was
received.
Fixed-payload body bytes are exact, envelope bytes are bounded by complete encoded
envelopes, and scheduler accounting is bounded by monotonic-clock slots eligible at
the reported elapsed milliseconds—not merely by the final plan. Finite nonnegative
achieved rates must agree with counts, bytes, and elapsed time.
`send_failed` requires exactly one failure and the fixed control-free `first_error`
text `Message submission failed.`; all other completion reasons require
`first_error:null`. Daemon diagnostics and paths are never accepted there. Receive
metrics likewise enforce possible unique/highest/duplicate/out-of-order relationships,
body-byte and elapsed-rate coherence, retained latency samples and feasible percentile
ranks, local lag event/drop sums, exact bounded missing samples, and completion/validity
state. A send client accepts `interrupted` only after it initiated cancellation. Once
a benchmark started, synthesized partial summaries set `accounting_complete:false`,
retain only the latest validated counters, and preserve the request ID; terminal
errors use partial/unknown outcomes and strict daemon errors are preserved.
Listen/chat therefore never print an unrecognized daemon event. Error objects are strictly decoded against the closed error contract. Status
includes capabilities, replay limits, mutation-cache semantics, attachment limits,
and attachment-storage pressure.

CLI-only setup/state-file records are `initialized`, `joined`, `alias`, `invite`,
`doctor`, and daemon-process `daemon_started`; they do not cross IPC. The exhaustive
IPC success/event families are:

- lifecycle: `stopping` v1;
- state/capabilities: `status` v1, `connected` v1, `peers_snapshot` v2,
  `peer_discovered`/`peer_updated`/`peer_expired` v2 and `peer_up`/`peer_down` v1;
- messaging: `queued` v3, `private_accepted` v3, `message` v2,
  `private_message` v1;
- attachment: `attachment_offer` v2, `attachment_shared` v3, `offers` v1,
  `offer_removed`/`offers_pruned` v1, `download_started`/`download_progress`/
  `download_complete` v1;
- benchmark: send `started`, `progress`, and `summary` v2; receive `started`,
  `progress`, and `summary` v1 (one explicit request ID is preserved across each
  complete benchmark stream);
- loss indication: `lagged` v1.

Local filesystem paths are no longer present in status/daemon-started contracts.
Attachment commands that inherently select a caller-owned input/output path keep it
only on owner-authenticated IPC; HTTP never accepts or returns such paths.

## HTTP and SSE

`POST /api/request` uses the same strict outer shape as IPC, with its `request`
restricted to `send`, `status`, `peers`, `download`, and `download_status`. Unknown
fields and duplicate keys fail closed. `POST /api/attachment` carries request and
operation IDs in separate headers. Every JSON response has `type`, exact
`schema_version`, and `request_id`; every HTTP response also has
`X-Meshmsg-Request-Id`. Binary downloads carry the header but no synthetic JSON.

SSE `data` records are JSON DTOs with the SSE connection's request ID. Connected,
message, queued, attachment, lag, peer snapshot, and peer transition source DTOs are
strictly deserialized before reconstruction from a public allowlist. A malformed or
unsupported daemon event terminates that IPC subscription and yields a sanitized
SSE disconnect error; it is never skipped in a way that could hide a contract gap. A
connected handshake that cannot be reconstructed as a valid public connected event,
including `endpoint_online:false`, yields a correlated `invalid_daemon_response`
error and closes the feed cleanly. IPC connection establishment and reading this
first frame share one eight-second startup deadline; the read receives only the
remaining budget. Offline/disconnect notices use the standard error
envelope (`daemon_offline` or `daemon_disconnected`) rather than an ad-hoc
event shape. SSE has no replay IDs because request IDs are correlation identifiers,
not event cursors.

## Compatibility and migration

This is an intentional local-API compatibility boundary. New daemons advertise
`typed_contracts_v1`. New clients send only nested IPC/HTTP schema-1 envelopes and
require exact correlated replies. Old unversioned clients are rejected; new clients
reject old uncorrelated replies before any payload is consumed. There is no
permissive downgrade or field defaulting. Operators must upgrade and restart the
CLI, web bridge, and daemon together. Network gossip/direct protocol compatibility
and mutation idempotency/lifecycle semantics are unchanged.

Adding optional fields still requires a new family version because DTOs deny unknown
fields. A future transport version must use a new capability token, negotiate before
mutations, and define an explicit migration; unsupported versions always fail closed.
