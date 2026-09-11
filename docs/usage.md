# Usage reference

## Commands

The canonical top-level commands are:

- `init [--force] [--no-default-alias]`
- `join [--advertise-self] [--force] [--no-default-alias] <invite source>`
- `alias show|set <name>|clear|reset-hostname`
- `daemon`
- `web [--listen 127.0.0.1:8787] [--origin https://host.tailnet.ts.net]`
- `invite`
- `send [--to <recipient>]`, `listen`, `chat`, `status`, `peers`, `stop`, and `doctor`
- `share <path>`, `offers [remove|prune]`, and `download <offer source> --output <path>`
- `bench-send`, `bench-receive`, and interactive `bench-tui`

Run `meshmsg <command> --help` for command-specific options.

## Mobile web broadcast

`meshmsg web` serves a separate loopback-only HTTP process bridging the chosen state directory's daemon IPC. It exposes only text broadcast, status and a live feed; it never starts or stops the daemon. Remote access requires operator-managed Tailscale Serve (never Funnel) and an explicit HTTPS `--origin`. There is no app authentication. See [Mobile web UI](web.md) for the full setup, bounds and failure semantics.

## Starting and joining a topic

Create a fresh topic and start its daemon:

```sh
meshmsg init
meshmsg --json daemon
```

Fresh state has `advertise_self=true` but no invite. After the endpoint becomes online, the daemon atomically stores an invite containing its endpoint. Until that first successful daemon startup, `meshmsg invite` intentionally fails.

The attachment limit defaults to 4 GiB. Configure it for each daemon invocation with bytes or an environment variable:

```sh
meshmsg --json daemon --max-attachment-bytes 8589934592
MESHMSG_MAX_ATTACHMENT_BYTES=8589934592 meshmsg --json daemon
meshmsg daemon --max-attachment-storage-bytes 17179869184 \
  --min-attachment-free-bytes 1073741824 \
  --attachment-retention-secs 2592000
```

The matching storage variables are `MESHMSG_MAX_ATTACHMENT_STORAGE_BYTES`, `MESHMSG_MIN_ATTACHMENT_FREE_BYTES`, and `MESHMSG_ATTACHMENT_RETENTION_SECS`. Defaults are 16 GiB total unique retained content, a 1 GiB free-space reserve, and automatic retention disabled. Set a nonzero retention explicitly to opt in; zero prevents surprise deletion during upgrades. See [Attachments](attachments.md) for lifecycle, deduplication, and pressure semantics.

Export the invite from another terminal:

```sh
meshmsg invite
```

Join from another machine, using stdin to avoid putting the capability in shell history:

```sh
printf '%s' '<invite>' | meshmsg join --token-stdin
meshmsg --json daemon
```

`join` defaults to `advertise_self=false`: the peer uses the invite to bootstrap but does not add itself to its stored invite. To advertise the joining peer:

```sh
meshmsg join --advertise-self '<invite>'
meshmsg --json daemon
meshmsg invite
```

Every peer can export its stored invite. Advertising changes only that peer's stored invite; it does not create a leader or relay. Invites contain at most 16 bootstrap peers. Adding a new identity to a full list fails without mutation, while an existing identity can refresh its endpoint at capacity.

## Node aliases

By default, `init` and `join` capture the first label of the current OS hostname, normalize it to lowercase, persist it, and enable it as the advertised alias. Changing the OS hostname later has no effect. **This discloses the captured hostname to other topic participants**, along with signed endpoint-presence metadata. Opt out at creation time when that disclosure is inappropriate:

```sh
meshmsg init --no-default-alias
meshmsg join --no-default-alias --token-stdin < invite.txt
```

The CLI also accepts `--no-alias` as a compatibility spelling. A legacy state without `alias.json` is treated as opted out. Alias configuration is local to one state directory:

```sh
meshmsg alias show
meshmsg alias set build-node-2
meshmsg alias clear
meshmsg alias reset-hostname
```

`set` installs a custom override and enables advertising. `clear` is a persistent privacy opt-out: it removes the custom override and disables alias advertising while retaining the old captured hostname only as local state. The older `disable` spelling remains accepted as a compatibility alias for `clear`. Direct messages addressed by canonical public key remain available. Only `reset-hostname` captures the current short hostname, removes the override, and enables advertising again. Alias changes require the daemon to be stopped and take effect at its next start. `show` may be used while it runs; JSON mode distinguishes all stored values:

```json
{"type":"alias","enabled":true,"hostname":"laptop","custom":"build-node-2","alias":"build-node-2"}
```

Aliases contain 1–63 ASCII letters, digits, or hyphens, must start and end with a letter or digit, and are stored lowercase. If the default hostname does not satisfy this grammar, use `--no-default-alias` and set a valid alias later.

An alias is signed discovery metadata, not a verified person, account, or authorization rule. Any topic participant can advertise any valid alias. Uniqueness is checked only at each send: if one claimant disappears or expires, a formerly colliding alias can later resolve to a different remaining key. There is no trust-on-first-use pin or reassignment confirmation. Do not use an alias when identity or continuity matters; verify and use the full public key.

## Peer directory

`meshmsg peers` asks the running daemon for a sanitized, point-in-time directory. Use `meshmsg --json peers` for the stable schema version 2:

```json
{"type":"peers_snapshot","schema_version": 2,"generated_at_ms":1700000000000,"directory_epoch":"0123456789abcdef0123456789abcdef","directory_revision":7,"self":{"public_key":"<local-key>","alias":"laptop","online":true},"peers":[{"public_key":"<remote-key>","alias":"build-node-2","online":true,"last_seen_ms":1699999999000,"expires_at_ms":1700000149000}]}
```

`self` is always a separate object and the remote `peers` array always excludes it. The array is sorted bytewise by canonical `public_key`; `alias` is always present and is either a normalized alias or JSON `null`. `self.online` is true only when the local endpoint is online **and** its topic is joined. A remote is present with `online:true` only while its authenticated signed-presence lease is current. This is a local freshness judgment, not an active reachability probe, trust assertion, Gossip-neighbor relationship, or delivery guarantee. Expired remotes are omitted.

`last_seen_ms` is the local daemon's receipt time, not the sender-controlled signed timestamp. `expires_at_ms` is locally derived and no more than the fixed 150,000 ms presence lifetime after receipt. The snapshot contains at most 1,024 remote identities and fits a bounded 512 KiB IPC frame. It never contains endpoint addresses, relays, sockets, raw signed records, signatures, invites, capabilities, or message bodies.

Local subscriptions start with `connected`, then an atomic `peers_snapshot`, then live events that occurred after that snapshot:

```json
{"type":"peer_discovered","schema_version": 2,"directory_epoch":"0123456789abcdef0123456789abcdef","directory_revision":8,"peer":{"public_key":"<remote-key>","alias":"node-1","online":true,"last_seen_ms":1700000000000,"expires_at_ms":1700000150000}}
{"type":"peer_updated","schema_version": 2,"directory_epoch":"0123456789abcdef0123456789abcdef","directory_revision":9,"peer":{"public_key":"<remote-key>","alias":"node-2","online":true,"last_seen_ms":1700000030000,"expires_at_ms":1700000180000}}
{"type":"peer_expired","schema_version": 2,"directory_epoch":"0123456789abcdef0123456789abcdef","directory_revision":10,"peer":{"public_key":"<remote-key>","alias":"node-2","online":false,"last_seen_ms":1700000030000,"expires_at_ms":1700000180000}}
```

These events are reconstructed from an explicit metadata allowlist, are limited to 512 encoded JSON bytes, and contain no message body or routing data. An identical periodic presence refresh advances freshness in later snapshots without emitting an event. First observation emits `peer_discovered`; an alias change emits `peer_updated`; hidden routing-only changes emit no public event; lease cleanup emits one `peer_expired`; a later valid presence emits `peer_discovered` again. The older `peer_up`/`peer_down` events remain available to local IPC listeners for compatibility, but are low-level broadcast-Gossip neighbor changes and must not be used as directory online state. The web SSE bridge filters them out.

A stateful client should use the subscription's startup snapshot, apply lifecycle events only when their `directory_epoch` matches and `directory_revision` increases without a gap, and replace all state after a gap, `lagged`, reconnect, or epoch change. The revision is a lifecycle-event cursor: silent freshness refreshes and hidden route-only updates may change a later snapshot without incrementing it. `meshmsg listen` prints the startup snapshot and live events. After a lag, disconnect, or out-of-order lifecycle event, the web UI immediately invalidates its current-peer summary and reconnects its SSE subscription; it applies no lifecycle events until the new subscription receives `connected` followed by a valid atomic startup snapshot. The CLI checks the daemon's `peer_directory_v2` capability before sending the new IPC command, so an old daemon fails with an upgrade-and-restart error and no fallback or ambiguous request.

## Messaging

Use separate terminals for interaction:

```sh
printf '%s' 'hello' | meshmsg send --message-stdin
meshmsg listen
meshmsg chat
meshmsg status
```

Stop the daemon cleanly:

```sh
meshmsg stop
```

Client commands use owner-only local IPC and never create another Iroh endpoint. IPC uses the strict nested `typed_contracts_v1` request envelope and exact request/response correlation documented in [Stable contracts](contracts.md); unversioned clients and replies fail closed. The daemon permits at most 64 simultaneous local connections (including listeners and benchmarks), requires an initial request frame within eight seconds, and returns `ipc_capacity` when full. Ordinary commands have a 10-second daemon-side IPC deadline; offer listing, private send, and attachment operations use longer command-appropriate bounds. A `command_timeout` releases the connection slot but can leave the outcome of an already-submitted mutating operation unknown. Clients fail with an actionable error when the daemon is unavailable.

A successful send reports `queued`:

```json
{"type":"queued","schema_version":3,"operation_id":"<32-lowercase-hex>","from":"<peer-id>","message_id":"<same-operation-id>","timestamp_ms":1700000000000,"body":"hello","delivery_acknowledged":false}
```

`queued` means the local Gossip implementation accepted the broadcast request. It is not a delivery acknowledgement. The operation ID is also the signed V2 wire message ID, so a retry uses the same replay identity. Remote `message` records remain schema version 2. New broadcast bodies must contain at least one byte and are limited to 3900 UTF-8 bytes. Empty or oversized requests are rejected with `invalid_message` and `outcome:"not_started"` before operation-cache admission, preserving their explicit or generated operation ID for correction and reuse. Receive/event consumers continue accepting released valid EnvelopeV2 bodies through the exact 3928-byte worst-case capacity of a 4096-byte frame. Signed remote envelopes with invalid text or attachment semantics are dropped before replay admission. Broadcasts use the topic-bound V2 Gossip protocol and do not interoperate with pre-V2 peers.

### Retry-safe operation IDs

`send`, `send --to`, `share`, `offers remove`, `offers prune`, and `download` accept `--operation-id` with exactly 32 lowercase hexadecimal characters. The CLI generates a cryptographically random ID when omitted. To recover from a lost response, retry the identical command with the same explicit ID:

```sh
meshmsg --json send --operation-id 0123456789abcdef0123456789abcdef 'hello'
meshmsg --json share --operation-id fedcba9876543210fedcba9876543210 ./report.pdf
meshmsg --json offers prune --operation-id aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --max-delete 10
meshmsg --json download --operation-id bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb '<offer>' --output ./report.pdf
```

The daemon joins concurrent duplicates and returns the exact cached terminal success, failure, or download partial success without repeating broadcast, transfer, publication, deletion, export, or installation work. Reusing an ID with a different operation kind, recipient, body, exact submitted absolute share-path representation, share-content digest, lifecycle selector/age/dry-run/limit, download token, or exact output representation fails with versioned `operation_id_conflict`; errors and successful mutation responses include `operation_id`. Prune retries retain the original selected set, so `--max-delete` bounds one operation rather than each transport attempt. Remove retries replay the original authoritative counts. A terminal failure remains terminal for that ID—use a new ID only when intentionally starting a new attempt.

The daemon retains at most 1,024 in-flight/terminal IDs. Terminal entries expire after 10 minutes and oldest terminal entries can be evicted under pressure; in-flight entries are never evicted. The cache is intentionally memory-only and is cleared by daemon restart. Status reports `operation_cache_capacity`, `operation_cache_ttl_ms`, and `operation_cache_persistent:false`. Therefore same-ID retry protection applies only while the ID remains in the current daemon's cache. After expiry, eviction, or restart, do not reuse an old ID unless repeating the side effect is acceptable. Private receivers still durably suppress the same wire ID for their separate replay window, but that does not make sender operation outcomes restart-persistent.

This IPC is intentionally incompatible with mutation requests from older clients: all seven operations above (including daemon-only `web_download`) require `operation_id`, and `share` additionally requires its validated 64-character lowercase `source_digest`. Messaging/share clients require `idempotent_mutations_v1`; lifecycle/download clients and the web bridge require `idempotent_attachment_operations_v1`. They fail before submission against an older daemon. Local `queued`, `private_accepted`, and `attachment_shared` responses are schema 3; lifecycle/download results and progress are schema 2. Incoming wire records retain their existing schemas.

### Private sends

Address one currently reachable node by its canonical full public key or by a uniquely advertised alias:

```sh
meshmsg send --to build-node-2 'private hello'
printf '%s' 'private hello' | meshmsg send --to '<full-peer-key>' --message-stdin
```

Public-key parsing takes precedence over alias parsing and requires the canonical full encoding. The daemon must know a current signed endpoint presence for that key, unless its endpoint was pinned from the local invite. Alias lookup uses unexpired signed presence records and succeeds only when exactly one peer currently advertises the normalized alias. Zero matches or collisions fail closed; meshmsg never guesses or falls back to broadcast. Because presence is periodic and expires, a recently started, disconnected, renamed, or stopped peer may temporarily be unresolved, and a stopped peer's alias may remain visible until expiry.

Before submitting a private body over local IPC, the CLI checks that the running daemon explicitly advertises `private_send_v2`. It then uses the distinct `private_send` IPC command; it never encodes a recipient into the legacy broadcast `send` command and never retries or falls back to broadcast. An older or stale daemon therefore causes an error saying the message was not submitted. Upgrade and restart the daemon, then rerun the command only after reviewing that failure.

A private message travels over a separate authenticated, encrypted Iroh connection and is signed and bound to the sender, recipient, and topic. It is not placed in the broadcast message stream. On success, human output says the private message was accepted; JSON reports metadata, never the sent body:

```json
{"type":"private_accepted","schema_version":3,"operation_id":"<32-lowercase-hex>","to":"<full-peer-key>","message_id":"<same-operation-id>","timestamp_ms":1700000000000,"body_bytes":13,"acceptance_acknowledged":true,"duplicate_accepted":false,"durable":false,"read":false}
```

A new acceptance means the authenticated recipient durably recorded a domain-separated SHA-256 fingerprint of the signed semantic payload, queued the volatile body, and durably recorded the delivery transition before signing success. The body itself is never persisted. `duplicate_accepted:true` means the same sender/ID/fingerprint previously reached that confirmed state and was not queued again. Neither result means a person or `listen` client read it or that the body survives process failure.

The direct v2 signed rejection results are mapped to stable daemon errors. `private_message_conflict` means the sender/ID is already bound to different content. `private_recipient_busy` means no record was created because a queue/rate/quota bound rejected it. `private_replay_unavailable` means the persistence worker had already failed. `private_delivery_unknown` means a durable pending record exists but the recipient cannot prove whether the volatile queue insertion happened; it will never redeliver or claim acceptance for that ID. Transport loss remains `private_send_failed` with an unknown outcome. Reuse the same ID only for an exact retry; changing to a new ID can duplicate an uncertain message.

`listen` and `chat` subscribers receive accepted messages as `private_message` events containing `private:true`, the canonical `from`, message ID, timestamp, body, and explicit `durable:false`/`read:false` fields. Replay persistence stores only sender, ID, fingerprint, expiration, and pending/confirmed state. Persistence runs on a dedicated blocking worker with a bounded 64-request queue. Live IDs are never pressure-evicted: new admission returns signed `Busy` when the queue, global 8,192-ID quota, per-sender 512-ID quota, per-sender 8/second (burst 16) rate, global 128/second (burst 256) rate, volatile delivery queue, or WAL bound is unavailable. Status exposes these bounds plus `direct_replay_available` and stable `direct_replay_error`; terminal failure makes subsequent direct requests return signed unavailable results.

Nonempty lines entered in `chat` are still broadcasts; blank lines are ignored without allocating an operation ID or contacting the daemon. It has no direct-reply mode. Private bodies are suppressed from unattended daemon logs and replay persistence. The mobile web process neither sends private messages nor exposes them in its SSE feed.

## Input sources

Join, send, and download each require exactly one input source. Positional values are convenient but visible in shell history and potentially process listings:

```sh
meshmsg join '<invite>'
meshmsg send 'hello'
meshmsg download '<signed-offer>' --output ./report.pdf
```

Prefer file or stdin input for sensitive values:

```sh
meshmsg join --token-file invite.txt
meshmsg join --advertise-self --token-stdin < invite.txt
meshmsg send --message-file message.txt
printf '%s' 'hello' | meshmsg send --message-stdin
meshmsg download --offer-file signed-offer.txt --output ./report.pdf
printf '%s' '<signed-offer>' | meshmsg download --offer-stdin --output ./report.pdf
```

File and stdin flags conflict with each other and with the positional value. Stdin is read through EOF; `-` is a literal filename, not stdin. Invite and attachment-offer input remove one final LF and an optional preceding CR. Message input is preserved exactly. Inputs must be UTF-8. Invite and attachment-offer input are limited to 1 MiB. Broadcast message bodies must be nonempty and are limited to 3900 UTF-8 bytes for positional, file, stdin, chat, IPC, and web input alike. Private `send --to` bodies use their separate nonempty 4096-byte contract for positional, file, and stdin input.

These forms prevent argv and history disclosure only. Broadcast messages remain plaintext to every topic participant. Private-message transport is encrypted between the two daemons, but the body is still available to the sender and recipient processes, their owner-only IPC subscribers, and the operators of those machines.

## Status and diagnosis

```sh
meshmsg --json status
meshmsg --json doctor
```

Representative status:

```json
{"type":"status","running":true,"alias":"build-node-2","alias_enabled":true,"captured_hostname":"laptop","custom_alias":"build-node-2","advertised_aliases":2,"advertises_self":false,"has_invite":true,"bootstrap_peer_count":3,"self_advertised":false,"endpoint_online":true,"topic_joined":true,"neighbors":2}
```

`neighbors` is the current direct broadcast-Gossip-neighbor count. `advertised_aliases` is the number of currently unexpired directory entries carrying an alias, not a trusted contact count or reachability guarantee. `topic_joined` becomes false when no direct neighbors remain, including for a lone first peer. These are local observations, not delivery guarantees.

Startup and bootstrap are bounded. If joining configured peers or becoming online times out, the daemon exits nonzero so a service manager can retry. JSON mode emits one standard error envelope (`command_timeout` when the bounded outcome is unknown, otherwise `command_failed`) and never emits a second startup record.

`doctor` validates stored state, identity binding, expected public key, topic, and invite invariants offline.

## JSON automation

The global `--json` option produces versioned JSON for one-shot commands and NDJSON for streams. Every success has `type`, `schema_version`, and a 32-lowercase-hex `request_id` where a request exists. Every failure uses the [stable error envelope](contracts.md#error-envelope), writes exactly one object to stdout (never stderr), and exits 1:

```sh
meshmsg --json daemon
meshmsg --json status
meshmsg --json peers
meshmsg --json invite
meshmsg --json alias show
meshmsg --json listen
meshmsg --json send 'hello'
meshmsg --json send --to build-node-2 'private hello'
meshmsg --json share ./report.pdf
meshmsg --json offers
meshmsg --json offers prune --dry-run
meshmsg --json offers remove <offer-id> --direction outgoing
meshmsg --json download '<signed-offer>' --output ./report-copy.pdf
```

`listen` and `chat` receive complete messages through owner-only IPC. Slow subscribers receive a versioned, request-correlated `lagged` event when their bounded queue drops events. Request IDs correlate transport exchanges; they are intentionally distinct from retry-safe operation IDs and are not replay cursors. See [Stable JSON, IPC, HTTP, and SSE contracts](contracts.md) for the complete DTO inventory, strictness, and upgrade policy.
