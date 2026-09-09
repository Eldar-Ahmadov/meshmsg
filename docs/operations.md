# Operations and security

## Trust and privacy model

An invite is effectively a topic-access capability. Anyone who obtains it can join the topic, read plaintext broadcast messages and attachment offers, and send signed broadcasts. Broadcasts and attachment offers remain topic-wide plaintext, but their wire format changed incompatibly to the topic-bound V2 envelope and `/meshmsg/broadcast-gossip/2`; do not mistake the private-send feature for encryption of the topic-wide swarm.

`meshmsg send --to` uses a separate authenticated, encrypted Iroh transport. Its signed request binds the sender key, recipient key, topic, message ID, timestamp, and body. This protects the private body from other topic participants while it travels between the two daemons. It does not protect either endpoint: the sender and recipient processes, machine operators, and owner-only local `listen`/`chat` subscribers can access the plaintext. Network infrastructure can still observe connection metadata. There is no human-friendly key verification, account identity, access revocation, key rotation, multi-device identity, or group-private messaging. Private mode covers text only; attachments retain their existing topic-wide offer and reusable-capability model.

Direct protocol v2 (`/meshmsg/direct/2`) returns one of six signed results. `Accepted` means the recipient durably recorded a content-bound ID, placed the body into its volatile delivery queue, and then durably recorded `delivery_confirmed`, in that order. `DuplicateAccepted` means an exact replay found that previously confirmed state and was not delivered again. Neither result proves that a subscriber read the body or that the body survives process failure. `DeliveryOutcomeUnknown` means only the first durable `recorded` state exists: a crash or persistence failure may have happened either before or after volatile queue insertion, so the recipient never retries delivery and never upgrades that state on replay. `Conflict` means the same sender/ID is bound to different signed content. `Busy` means bounded capacity rejected a new ID before recording it. `Unavailable` means replay persistence has terminally failed and this request was not submitted to it.

Each replay transaction persists only `(sender, message_id, fingerprint, expires_at, state)` metadata—never plaintext or reversible body data. The fingerprint is SHA-256 with an explicit domain and binds sender, recipient, topic, message ID, and body. It intentionally excludes the generated timestamp so an identical caller operation can be reconstructed after sender restart. A new transaction syncs a checksummed `recorded` WAL entry, inserts the body into the already-reserved volatile queue, then syncs a checksummed `delivery_confirmed` transition before returning `Accepted`. Therefore every successful acceptance acknowledgement is after durability and queue insertion. The unavoidable crash interval between the first sync and the second sync is represented honestly as `DeliveryOutcomeUnknown`; because bodies are not persisted, automatically delivering such a record after restart would risk duplication and is forbidden.

The dedicated blocking worker owns the map and all filesystem I/O behind a bounded 64-request queue; async protocol tasks hold no synchronous persistence lock. Every 256 WAL records and at clean shutdown, it atomically commits a checksummed compact snapshot before atomically resetting the WAL. Recovery tolerates an old WAL over a newer snapshot, truncates and syncs only an incomplete final append, and fails closed on malformed complete records, checksums, bindings, transitions, conflicts, or oversized state. Existing v1 map entries lack fingerprints and migrate as conservative legacy-unknown records: any reuse conflicts until expiry. A terminal worker error sets status to `direct_replay_available:false` with stable `direct_replay_error:"direct replay persistence worker failed"`; a triggering pre-append failure returns signed `Unavailable` while an append/sync ambiguity returns signed `DeliveryOutcomeUnknown`; queued/subsequent requests receive signed `Unavailable`, and shutdown reports the worker failure.

Live replay IDs remain for 630 seconds (twice the five-minute acceptance window plus 30 seconds) and are never evicted. Capacity is 8,192 IDs globally and 512 per signed sender. New IDs are token-bucket limited to 128/second with burst 256 globally and 8/second with burst 16 per sender. Queue, rate, quota, WAL, or volatile delivery pressure returns signed `Busy`. Exact `delivery_confirmed` duplicates bypass new-ID limits and return `DuplicateAccepted`; exact `recorded` duplicates return `DeliveryOutcomeUnknown`; conflicts are checked before those limits. Rotating identities can still share/exhaust the global budget, so this is bounded resource isolation rather than Sybil resistance. Private messages still have no history, offline inbox, store-and-forward, or durable body recovery.

### Aliases and presence

Aliases are convenience labels, not identities or access-control names. Presence records are signed by their advertised peer key and bound to the topic, but any invite holder can advertise any valid alias. A malicious or accidental duplicate makes alias resolution fail closed at that moment; it can deny use of that alias but cannot make meshmsg choose between simultaneous claimants. Alias bindings are not pinned, however. If a claimant disappears or its presence expires, a later send can resolve the same alias to a different sole claimant without confirmation. For identity- or continuity-sensitive communication, verify the canonical full public key out of band and address it directly.

By default, `init` and `join` persist and advertise the machine's lowercased short hostname. This can reveal a person's name, employer naming scheme, device role, or other sensitive inventory data. `--no-default-alias` prevents capture and advertising; `meshmsg alias clear` (the older `disable` spelling remains a compatibility alias) persistently opts an existing state out. Disabling the alias does not disable signed presence or direct sends by public key.

Broadcast envelope V2 signs its domain, version, configured topic, sender, random 128-bit message ID, timestamp, kind, and body. Receivers accept timestamps from five minutes in the past through 60 seconds in the future. Accepted `(sender, message_id)` pairs are stored exactly—not probabilistically—in one-minute in-memory buckets. A particular ID is retained for approximately 360–420 seconds depending on its insertion offset within the bucket. At the tight boundary—a maximum-future-skew message inserted in the bucket's final millisecond—the ID remains present through its final inclusive freshness millisecond, and the bucket expires one millisecond later when that message first becomes stale. Thus every accepted ID is replay-rejected for its entire possible freshness lifetime, although older-timestamp messages can remain recorded after they become stale. No still-live ID is evicted.

Before envelope deserialization or signature verification, the daemon rate-limits the authenticated immediate Gossip transport hop to 500 messages/second with a 1,000-message burst, with a 1,500 messages/second and 3,000-message burst global pre-verification limit. It tracks at most 128 recently active transport sources for 60 seconds. Invalid, replayed, and overload rejection events are sampled at most once per ten seconds, with a suppressed count, instead of producing one IPC event and stdout record per rejected frame.

After verification, admission is limited to 100 messages/second with a 200-message burst per signed sender and 1,000 messages/second with a 2,000-message global burst. At most 4,096 signed-sender states, 42,200 live IDs per signed sender (`200 + 100 × 420 seconds`), and 422,000 live IDs globally (`2,000 + 1,000 × 420 seconds`) are retained. Each authenticated immediate transport source is additionally limited to 256 simultaneous signed sender keys and 211,000 live IDs (`1,000 + 500 × 420 seconds`), across at most 128 replay-source states. These quotas are derived from token-bucket bursts/rates and the maximum bucket lifetime. A duplicate is rejected before post-verification rate checks; traffic beyond any rate, sender/source count, or exact-ID capacity is rejected rather than displacing accepted IDs.

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

Broadcast application envelopes are limited to 4096 serialized bytes; their maximum text body is smaller because signatures and metadata consume space. Private bodies must be nonempty and are limited to 4096 UTF-8 bytes, with a bounded 6 KiB protocol frame. Incoming private acceptance uses bounded connection, volatile delivery, and replay-persistence queues and can return a signed `Busy` rejection under load; callers should retain the same operation ID when retrying an outcome known not to have been accepted. A local `command_timeout` means the daemon released that IPC connection, not necessarily that already-submitted work was cancelled; for mutating commands the outcome may be unknown. Stop is stricter: the daemon reserves bounded command-queue capacity and submits the stop command before returning `stopping` with `outcome:"accepted"`; queue timeout or closure returns an error with `outcome:"not_started"` and never a false success.

State uses `config.json` as the commit record and immutable identity generations. Alias state is stored separately in `alias.json` inside the state directory and is read when the daemon starts, so changes require a stopped daemon and restart. `doctor` rejects a missing, corrupt, or mismatched selected key. Unselected generations left by interrupted forced replacement are harmless.

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
