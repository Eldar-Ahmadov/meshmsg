# Operations and security

## Trust and privacy model

An invite is effectively a topic-access capability. Anyone who obtains it can join the topic, read plaintext broadcast messages and attachment offers, and send signed broadcasts. Broadcasts and attachment offers remain topic-wide plaintext, but their wire format changed incompatibly to the topic-bound V2 envelope and `/meshmsg/broadcast-gossip/2`; do not mistake the private-send feature for encryption of the topic-wide swarm.

`meshmsg send --to` uses a separate authenticated, encrypted Iroh transport. Its signed request binds the sender key, recipient key, topic, message ID, timestamp, and body. This protects the private body from other topic participants while it travels between the two daemons. It does not protect either endpoint: the sender and recipient processes, machine operators, and owner-only local `listen`/`chat` subscribers can access the plaintext. Network infrastructure can still observe connection metadata. There is no human-friendly key verification, account identity, access revocation, key rotation, multi-device identity, or group-private messaging. Private mode covers text only; attachments retain their existing topic-wide offer and reusable-capability model.

Direct protocol v2 (`/meshmsg/direct/2`) returns one of six signed results. `Accepted` means the recipient durably recorded a content-bound ID, placed the body into its volatile delivery queue, and then durably recorded `delivery_confirmed`, in that order. `DuplicateAccepted` means an exact replay found that previously confirmed state and was not delivered again. Neither result proves that a subscriber read the body or that the body survives process failure. `DeliveryOutcomeUnknown` means only the first durable `recorded` state exists: a crash or persistence failure may have happened either before or after volatile queue insertion, so the recipient never retries delivery and never upgrades that state on replay. `Conflict` means the same sender/ID is bound to different signed content. `Busy` means bounded capacity rejected a new ID before recording it. `Unavailable` means replay persistence has terminally failed and this request was not submitted to it.

Each replay transaction persists only `(sender, message_id, fingerprint, expires_at, state)` metadata—never plaintext or reversible body data. The fingerprint is SHA-256 with an explicit domain and binds sender, recipient, topic, message ID, and body. It intentionally excludes the generated timestamp so an identical caller operation can be reconstructed after sender restart. A new transaction syncs a checksummed `recorded` WAL entry, inserts the body into the already-reserved volatile queue, then syncs a checksummed `delivery_confirmed` transition before returning `Accepted`. Therefore every successful acceptance acknowledgement is after durability and queue insertion. The unavoidable crash interval between the first sync and the second sync is represented honestly as `DeliveryOutcomeUnknown`; because bodies are not persisted, automatically delivering such a record after restart would risk duplication and is forbidden.

The dedicated blocking worker owns the map and all filesystem I/O behind a bounded 64-request queue; async protocol tasks hold no synchronous persistence lock. Every 256 WAL records and at clean shutdown, it atomically commits a checksummed compact snapshot before atomically resetting the WAL. Recovery tolerates an old WAL over a newer snapshot, truncates and syncs only an incomplete final append, and fails closed on malformed complete records, checksums, bindings, transitions, conflicts, or oversized state. Existing v1 map entries lack fingerprints and migrate as conservative legacy-unknown records: any reuse conflicts until expiry. A terminal worker error sets status to `direct_replay_available:false` with stable `direct_replay_error:"direct replay persistence worker failed"`; a triggering pre-append failure returns signed `Unavailable` while an append/sync ambiguity returns signed `DeliveryOutcomeUnknown`; queued/subsequent requests receive signed `Unavailable`, and shutdown reports the worker failure.

Live replay IDs remain for 630 seconds (twice the five-minute acceptance window plus 30 seconds) and are never evicted. Capacity is 8,192 IDs globally and 512 per signed sender. New IDs are token-bucket limited to 128/second with burst 256 globally and 8/second with burst 16 per sender. Queue, rate, quota, WAL, or volatile delivery pressure returns signed `Busy`. Exact `delivery_confirmed` duplicates bypass new-ID limits and return `DuplicateAccepted`; exact `recorded` duplicates return `DeliveryOutcomeUnknown`; conflicts are checked before those limits. Rotating identities can still share/exhaust the global budget, so this is bounded resource isolation rather than Sybil resistance. Private messages still have no history, offline inbox, store-and-forward, or durable body recovery.

### Daemon output and diagnostics

The daemon never writes to stdout or stderr from an async, network, IPC, or event-loop task. Producers use bounded `try_send` admission to dedicated writer threads. Daemon stdout retains the documented human event stream or JSON NDJSON event API, but rendering and terminal writes happen after event processing; message bodies and attachment offer/ticket details are suppressed from this process-level stream. Human diagnostics use stderr, while JSON mode keeps stderr empty and does not mix diagnostics into the stdout event contract.

Routing is explicit: startup success and public daemon events go to daemon stdout; status and diagnostic status are bounded IPC responses and are not terminal logs; sampled warnings/errors and human startup failures go through the diagnostic stderr writer. The final human CLI fatal is written only after that writer drains successfully. After a drain timeout, the detached writer remains the sole stderr owner and the fatal is suppressed rather than raced. In JSON mode startup/terminal failure remains the one canonical stdout error attempt and stderr remains empty; its terminal write also has a bounded deadline.

Diagnostic records are typed and bounded: timestamp, level, stable event/code, allowlisted fields, and exact lowercase-hex request/operation/run IDs where applicable. They never accept arbitrary error text. Repeated diagnostics use ten-second sampled admissions, but every suppression is counted immediately, including an unfinished final window. Queue-full/disabled drops, lock-contention drops, and writer-abandoned records are distinct. A failed or panicking writer atomically closes admission, counts the failed current record and every abandoned queued record, resets occupancy, and exposes terminal unhealthy state. Inside the top-level unwind boundary, a temporary process panic hook performs no I/O, preventing a caught worker or process panic from synchronously taking stderr. The previous hook is always restored before `main` returns. These counters remain process-wide when JSON mode disables diagnostic rendering. Every daemon `type:"error"` event—including rejected network traffic and generated-event guards—is strictly decoded and reserialized through the shared error DTO before admission; noncanonical semantics, private text, and unsupported fields are dropped.

RAII closes daemon stdout admission and waits at most 500 ms on every return or unwind path before network resources are dropped; normal shutdown closes and drains explicitly before fallible router/replay teardown. No later event admission succeeds. A timed-out isolated writer is abandoned so shutdown cannot hang. Diagnostic startup and daemon-output startup failures abort production startup rather than silently degrading. Use separately negotiated `diagnostic_status_v2` for independently named stdout and diagnostic occupancy/capacity/high-water marks, all drop classes, accepted/sampled/suppressed/written counts, writer loss/failure/panic/health, and process panic count. Independent maxima are never added because their peaks may occur at different times.

### Aliases and presence

Aliases are convenience labels, not identities or access-control names. Presence records are signed by their advertised peer key and bound to the topic, but any invite holder can advertise any valid alias. A malicious or accidental duplicate makes alias resolution fail closed at that moment; it can deny use of that alias but cannot make meshmsg choose between simultaneous claimants. Alias bindings are not pinned, however. If a claimant disappears or its presence expires, a later send can resolve the same alias to a different sole claimant without confirmation. For identity- or continuity-sensitive communication, verify the canonical full public key out of band and address it directly.

By default, `init` and `join` persist and advertise the machine's lowercased short hostname. This can reveal a person's name, employer naming scheme, device role, or other sensitive inventory data. `--no-default-alias` prevents capture and advertising; `meshmsg alias clear` (the older `disable` spelling remains a compatibility alias) persistently opts an existing state out. Disabling the alias does not disable signed presence or direct sends by public key.

Broadcast envelope V2 signs its domain, version, configured topic, sender, random 128-bit message ID, timestamp, kind, and body. Receivers accept timestamps from five minutes in the past through 60 seconds in the future. Accepted `(sender, message_id)` pairs are stored exactly—not probabilistically—in one-minute in-memory buckets. A particular ID is retained for approximately 360–420 seconds depending on its insertion offset within the bucket. At the tight boundary—a maximum-future-skew message inserted in the bucket's final millisecond—the ID remains present through its final inclusive freshness millisecond, and the bucket expires one millisecond later when that message first becomes stale. Thus every accepted ID is replay-rejected for its entire possible freshness lifetime, although older-timestamp messages can remain recorded after they become stale. No still-live ID is evicted.

Before envelope deserialization or signature verification, the daemon charges a dedicated authenticated-hop verification-attempt bucket: 500 frames/second with a 1,000-frame burst per source and 1,500/second with a 3,000-frame global burst. It tracks at most 128 recently active transport sources for 60 seconds. This is the cheap malformed-input DoS bound. A separate accepted-traffic transport bucket has the same per-source/global limits and is consumed only after signature, complete semantics, timestamp freshness, and exact replay checks succeed. Malformed, stale, future, and exact-replay frames therefore pay the verification-attempt budget but cannot consume accepted-traffic tokens needed by a corrected retry or unrelated valid frame. Invalid, replayed, and overload rejection events are sampled at most once per ten seconds, with a suppressed count, instead of producing one IPC event and stdout record per rejected frame.

After verification, admission is additionally limited to 100 messages/second with a 200-message burst per signed sender and 1,000 messages/second with a 2,000-message global burst. At most 4,096 signed-sender states, 42,200 live IDs per signed sender (`200 + 100 × 420 seconds`), and 422,000 live IDs globally (`2,000 + 1,000 × 420 seconds`) are retained. Each authenticated immediate transport source is additionally limited to 256 simultaneous signed sender keys and 211,000 live IDs (`1,000 + 500 × 420 seconds`), across at most 128 replay-source states. These quotas are derived from token-bucket bursts/rates and the maximum bucket lifetime. A duplicate is rejected before post-verification rate checks; traffic beyond any rate, sender/source count, or exact-ID capacity is rejected rather than displacing accepted IDs.

The transport source is the authenticated peer that delivered this Gossip hop, not necessarily the envelope's original signer. Binding rotating signed keys to that hop prevents one connected peer from consuming all 4,096 signed-sender slots, but Gossip forwarding can aggregate honest authors behind one hop and the same attacker can use multiple authenticated peers or paths. Per-source controls can therefore throttle aggregate forwarded traffic and cannot provide global Sybil resistance; all sources also share the global safety limits. Replay state is in memory, so restarting the daemon clears it; timestamp freshness still prevents indefinite replay. The separate V2 Gossip ALPN prevents legacy unbound envelopes from entering this receive path.

Signed presence is control-plane discovery on a derived Gossip topic. It exposes the alias (when enabled), peer public key, timestamp, and at most 8 Iroh endpoint addresses to topic participants. Records refresh about every 30 seconds and carry a nominal 150-second lifetime; the bounded 60-second future clock skew can affect the observed expiry, so disappearance and alias changes are not immediate. Presence proves that a key signed a claim, not that the alias is truthful, a human is present, or the endpoint is currently reachable.

Dynamic presence tracks at most 1024 identities, including short-lived replay watermarks. Expired entries are removed by a 15-second maintenance timer even without client traffic or status requests; once full, the directory rejects new identities deterministically while still allowing newer records for tracked identities. A newer record replaces that identity's complete presence address snapshot instead of merging rotating addresses. Expiry removes only the dedicated presence lookup entry: invite/bootstrap and attachment-ticket routes use a separate Iroh lookup, and the bounded invite pins remain available for full-key resolution. Incoming presence processing is additionally limited per authenticated Gossip transport hop (not by the freely chosen signed sender identity); excess records are dropped and can be learned from a later periodic presence announcement.

Daemon logs suppress incoming broadcast and private message bodies, recording metadata and byte counts. Owner-only local subscribers still receive complete bodies. Log suppression is operational hygiene, not a privacy boundary against the machine operator.

## Web access boundary

The optional `meshmsg web` process has **no app authentication**. It binds only loopback and must be exposed remotely only through **Tailscale Serve, never Funnel**, with tailnet access rules restricted to trusted users/devices. Those users can read the feed and broadcast as the daemon's identity. Host/Origin checks and CSP are browser defenses, not authentication against an authorized or local client. Web shutdown does not stop the daemon or remove an operator-managed Serve route. See [Mobile web UI operations](web.md) for explicit origin configuration, limits, recovery and exposure checks.

## Daemon behavior

The foreground daemon:

- holds an exclusive lock for state and identity;
- publishes its endpoint only after it is online;
- emits bounded signed presence on a separate derived Gossip topic;
- accepts bounded authenticated direct-message connections with limited concurrency and replay state;
- transactionally replaces identity and configuration;
- restricts the Linux state directory to `0700` and socket to `0600`;
- uses a protected owner/System/Administrators named-pipe ACL on Windows;
- authenticates the connected pipe server's process owner on Windows;
- removes stale Unix sockets safely;
- bounds IPC frames, subscriber queues, and all local IPC connections to 64;
- acquires connection capacity immediately after platform accept/authentication and before peer cleanup, snapshot construction, event subscription, or other per-client preparation;
- requires the first complete IPC frame within eight seconds, rejects excess connections with `ipc_capacity`, and bounds blocked response writes;
- applies 10-second ordinary-command, 30-second listing, 35-second private-send, and 60-minute-plus-10-second attachment IPC deadlines;
- serves persistent attachments on the same endpoint and router as Gossip;
- tracks local client tasks and attachment tasks, closes admission, drains clients briefly, and then aborts remaining work at shutdown;
- reports local and Gossip receiver lag;
- retries bootstrap peers after connectivity loss;
- suppresses incoming message bodies in unattended logs;
- shuts down on `meshmsg stop`, Ctrl-C, SIGINT, or SIGTERM.

Broadcast application envelopes are limited to 4096 serialized bytes. New text bodies must be nonempty and are conservatively limited to 3900 UTF-8 bytes, leaving bounded space for EnvelopeV2 signatures and metadata. Wire and event consumers retain the released V2-compatible worst-case maximum of 3928 bytes (at a one-byte postcard timestamp); the complete envelope is still bounded to 4096 bytes. Invalid local bodies are rejected before operation-cache, wire, and message-event side effects; invalid signed remote text or attachment semantics are rejected before accepted-traffic/replay admission and fanout, while still paying the separate pre-verification attempt bound. Private bodies must be nonempty and are limited to 4096 UTF-8 bytes, with a bounded 6 KiB protocol frame. Incoming private acceptance uses bounded connection, volatile delivery, and replay-persistence queues and can return a signed `Busy` rejection under load; callers should retain the same operation ID when retrying an outcome known not to have been accepted. A local `command_timeout` means the daemon released that IPC connection, not necessarily that already-submitted work was cancelled; for mutating commands the outcome may be unknown. Stop is stricter: the daemon reserves bounded command-queue capacity and submits the stop command before returning `stopping` with `outcome:"accepted"`; queue timeout or closure returns an error with `outcome:"not_started"` and never a false success.

State uses schema-versioned `config.json` as the commit record and immutable identity generations. Alias state is stored separately in versioned `alias.json` inside the state directory and is read when the daemon starts, so changes require a stopped daemon and restart. `doctor` rejects a missing, oversized, corrupt, unknown-version, or mismatched selected key. Unselected generations left by interrupted forced replacement are harmless. Persistent reads share one no-follow/reparse-rejecting, regular-file, same-handle metadata-preflight and streaming-limit implementation; a file that grows after inspection is still stopped at limit plus one without growing the destination buffer past the configured logical bound. Optional state is absent only when this open reports a genuine missing directory entry. Dangling links and other redirected entries fail closed. Non-forced initialization syncs a complete temporary config and atomically links it into the previously absent `config.json` name without replacement; a concurrently appearing file, directory, symlink, or Windows reparse point wins and causes `state already exists` without being modified. Forced initialization retains atomic replacement semantics.

### Persistent-state inventory and migration

| State | Maximum read | Version/migration |
|---|---:|---|
| `config.json` | 64 KiB | Current top-level `schema_version: 1`; the sole supported legacy form is the previously released unversioned shape (v0). |
| `.secret-<generation>.key` | 256 bytes | Identity binding version 1; exactly one canonical 32-byte hexadecimal key after surrounding whitespace. |
| `alias.json` | 4 KiB | Version 1. Absence is the only supported legacy opt-out; unknown versions fail closed. |
| `attachment-retention-v1.json` | 8 MiB and 8,192 entries | Schema version 1; absence reconstructs conservative timestamps from authoritative pins. |
| `direct-replay-v1-*.json` | 4 MiB and 8,192 entries | Legacy version 1 migrates conservatively to checksummed v2 state; the old file remains as the rollback backup. |
| `direct-replay-v2-*.snapshot.json` | 4 MiB and 8,192 entries | Checksummed snapshot version 2. |
| `direct-replay-v2-*.wal` | 8 MiB; 512 bytes per record | WAL version 2; each read/repair uses one no-follow/reparse-aware checked handle. A transaction opens and validates one append handle and retains that exact file identity and expected length across both the synced `recorded` and `delivery_confirmed` records. Append capacity is reserved for confirmation before the first record. Replacement, header/binding, length-continuity, or post-sync identity mismatch terminates persistence with an unknown outcome after recording may have begun; replacement state is never opened for append. Only an unterminated final fragment of at most 512 bytes is truncated; a 513-byte tail and complete malformed/checksum-invalid records remain untouched and fail closed. |
| `config.json.v0.bak` | 64 KiB | Exact pre-migration bytes, atomically created once without replacement and with owner-only permissions. Any colliding entry is reopened through the bounded no-follow/reparse-safe reader and accepted only when it is a regular file with byte-identical legacy contents; differing files and redirected or non-file entries abort migration untouched. |

Lock/socket files and web lease markers are never loaded as structured state. Attachment payloads and the Iroh blob database are streamed or accessed through Iroh rather than whole-file state reads.

The daemon performs the v0-to-v1 config migration only while holding the exclusive state lock. It first bounded-reads and strictly parses the complete legacy object, validates topic/invite semantics including whether the selected identity may advertise with the stored bootstrap set, and validates the selected generation and public-key binding. It then writes and syncs an owner-only temporary backup and atomically links it into the absent `config.json.v0.bak` name without replacement. A colliding entry always wins; migration reopens it safely and continues only for byte-identical regular-file contents. After the backup name and directory are synced, migration atomically replaces and syncs `config.json`. A crash before replacement leaves v0 authoritative and restart resumes from the identical backup; a crash after replacement leaves complete v1 authoritative. Repeating migration is idempotent. Parse, corruption, identity mismatch, unknown/future version, conflicting or redirected backup, or write/sync failure stops startup without guessing, selecting another key, or mutating the colliding entry.

For rollback, stop every process using the state directory and retain the failed/current `config.json` separately for diagnosis. Restore only the exact owner-only `config.json.v0.bak` to `config.json` with an atomic same-filesystem replacement and directory sync, then use the older binary. Never copy a backup from another state directory: it selects an identity generation and topic. Successful v1 startup does not delete the backup automatically. Current `doctor` can inspect legacy or current state without migrating it. Version probes decode unsigned 64-bit values before schema-specific narrow fields, so future values such as 256 are unsupported rather than misclassified as parse failures. Replay snapshot/legacy vectors and attachment-index maps use bounded visitors that reject an extra entry and overlong sender, ID, fingerprint, recipient, topic, checksum, or tag key before growing the retained collection. Before serde decoding, an allocation-free lexical pass incrementally counts every JSON string's decoded UTF-8 length, including backslash escapes, Unicode escapes, and surrogate pairs, so escaped amplification cannot create unbounded parser scratch before those field-specific checks. Persistent-state diagnostics name the state class and error category (missing, too large, I/O, parse, corruption, or unsupported version); public JSON errors remain canonical and do not expose local paths, key material, or message bodies. These checks prevent pathname races from producing false migration or replay success, but they are not isolation from another process with the same account's state-directory access: such a process can still cause fail-closed unavailability or unknown delivery outcomes, and direct in-place tampering is detected on recovery by strict parsing/checksums rather than prevented as an authorization boundary.

## Windows

Windows supports the same commands. Keep `meshmsg --json daemon` running in a dedicated PowerShell window.

The default state directory inherits the current user's `%LOCALAPPDATA%` ACL. If `--state-dir` points elsewhere, restrict it to the intended account. Transactional replacement relies on local-filesystem flush and write-through behavior; network shares or storage that ignores flushes can weaken durability.

There is no built-in Windows Service installer. Ctrl-C and `meshmsg stop` shut down the foreground daemon cleanly.

## systemd user service

Initialize or join first, then create `~/.config/systemd/user/meshmsg.service`:

```ini
[Unit]
Description=meshmsg peer daemon
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=300
StartLimitBurst=10

[Service]
Type=simple
ExecStart=%h/.cargo/bin/meshmsg --json daemon
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
```

Enable it:

```sh
systemctl --user daemon-reload
systemctl --user enable --now meshmsg
meshmsg status
journalctl --user -u meshmsg -f
```

To keep it running after logout:

```sh
sudo loginctl enable-linger "$USER"
```

Startup timeouts exit nonzero, so `Restart=on-failure` retries temporary connectivity failures.

## Compatibility

The local `{"command":"send","body":"…"}` IPC request remains compatible, but the broadcast wire protocol changed to the topic-bound V2 envelope and `/meshmsg/broadcast-gossip/2`; pre-V2 peers cannot exchange broadcasts or attachment offers with V2 peers. Private sends use a distinct local `private_send` command only after the daemon advertises the `private_send_v2` IPC capability. The daemon rejects an ambiguous legacy `send` request containing `to`, and the CLI never retries or falls back to broadcast. This fail-closed split prevents an older daemon that ignores unknown `send` fields from broadcasting a private body; old daemons do not receive that body because capability negotiation fails first, and would reject the distinct command if the daemon changed between negotiation and submission.

Current clients use a separate derived presence topic, direct-message protocol `/meshmsg/direct/2`, and the topic-bound `/meshmsg/broadcast-gossip/2` protocol. Pre-V2 peers do not exchange broadcasts or attachment offers with V2 peers; this deliberate protocol separation prevents legacy envelopes from entering the V2 receive path. Legacy signed attachment tokens are explicitly rejected because they are not topic-bound, while raw Iroh `BlobTicket` downloads remain supported. Older peers may still advertise presence, but they advertise only `private_send_v1` locally and do not accept `/meshmsg/direct/2` or its signed result semantics. A private send to an old peer therefore fails rather than falling back to plaintext broadcast. The web UI is broadcast-only and filters private events.
