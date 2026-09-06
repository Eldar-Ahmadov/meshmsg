# Usage reference

## Commands

The canonical top-level commands are:

- `init [--force] [--no-default-alias]`
- `join [--advertise-self] [--force] [--no-default-alias] <invite source>`
- `alias show|set <name>|clear|disable|reset-hostname`
- `daemon`
- `web [--listen 127.0.0.1:8787] [--origin https://host.tailnet.ts.net]`
- `invite`
- `send [--to <recipient>]`, `listen`, `chat`, `status`, `stop`, and `doctor`
- `share <path>`, `offers`, and `download <offer source> --output <path>`
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
meshmsg alias disable
meshmsg alias reset-hostname
```

`set` installs a custom override and enables advertising. `clear` is a persistent privacy opt-out: it removes the custom override and disables alias advertising while retaining the old captured hostname only as local state. `disable` is a synonym for `clear`. Direct messages addressed by canonical public key remain available. Only `reset-hostname` captures the current short hostname, removes the override, and enables advertising again. Alias changes require the daemon to be stopped and take effect at its next start. `show` may be used while it runs; JSON mode distinguishes all stored values:

```json
{"type":"alias","enabled":true,"hostname":"laptop","custom":"build-node-2","alias":"build-node-2"}
```

Aliases contain 1–63 ASCII letters, digits, or hyphens, must start and end with a letter or digit, and are stored lowercase. If the default hostname does not satisfy this grammar, use `--no-default-alias` and set a valid alias later.

An alias is signed discovery metadata, not a verified person, account, or authorization rule. Any topic participant can advertise any valid alias. Uniqueness is checked only at each send: if one claimant disappears or expires, a formerly colliding alias can later resolve to a different remaining key. There is no trust-on-first-use pin or reassignment confirmation. Do not use an alias when identity or continuity matters; verify and use the full public key.

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

Client commands use owner-only local IPC and never create another Iroh endpoint. They fail with an actionable error when the daemon is unavailable.

A successful send reports `queued`:

```json
{"type":"queued","from":"<peer-id>","body":"hello","delivery_acknowledged":false}
```

`queued` means the local Gossip implementation accepted the broadcast request. It is not a delivery acknowledgement. Omitting `--to` preserves this existing broadcast behavior and wire format.

### Private sends

Address one currently reachable node by its canonical full public key or by a uniquely advertised alias:

```sh
meshmsg send --to build-node-2 'private hello'
printf '%s' 'private hello' | meshmsg send --to '<full-peer-key>' --message-stdin
```

Public-key parsing takes precedence over alias parsing and requires the canonical full encoding. The daemon must know a current signed endpoint presence for that key, unless its endpoint was pinned from the local invite. Alias lookup uses unexpired signed presence records and succeeds only when exactly one peer currently advertises the normalized alias. Zero matches or collisions fail closed; meshmsg never guesses or falls back to broadcast. Because presence is periodic and expires, a recently started, disconnected, renamed, or stopped peer may temporarily be unresolved, and a stopped peer's alias may remain visible until expiry.

A private message travels over a separate authenticated, encrypted Iroh connection and is signed and bound to the sender, recipient, and topic. It is not placed in the broadcast message stream. On success, human output says the private message was accepted; JSON reports metadata, never the sent body:

```json
{"type":"private_accepted","schema_version":1,"to":"<full-peer-key>","message_id":"<32-hex-digits>","timestamp_ms":1700000000000,"body_bytes":13,"acceptance_acknowledged":true,"durable":false,"read":false}
```

This acknowledgement means the authenticated recipient daemon validated the request and accepted it into a bounded in-memory queue. It does **not** mean a person or `listen` client read it, that it was written to disk, or that it will survive a daemon/process failure. There is no offline queue, store-and-forward, automatic retry, history, or later retrieval. A failed or timed-out send has an unknown remote outcome; check before manually resending because duplicates are possible.

`listen` and `chat` subscribers receive accepted messages as `private_message` events containing `private:true`, the canonical `from`, message ID, timestamp, body, and explicit `durable:false`/`read:false` fields. Lines entered in `chat` are still broadcasts; it has no direct-reply mode. Private bodies are suppressed from unattended daemon logs. The mobile web process neither sends private messages nor exposes them in its SSE feed.

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
printf '%s' '<signed-offer>' | meshmsg download --offer-stdin --output ./report.pdf
```

File and stdin flags conflict with each other and with the positional value. Stdin is read through EOF; `-` is a literal filename, not stdin. Invite and attachment-offer input remove one final LF and an optional preceding CR. Message input is preserved exactly. Inputs must be UTF-8. Invite and attachment-offer input are limited to 1 MiB and message bodies to 4096 bytes.

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

Startup and bootstrap are bounded. If joining configured peers or becoming online times out, the daemon exits nonzero so a service manager can retry. JSON mode emits a structured `startup_error`.

`doctor` validates stored state, identity binding, expected public key, topic, and invite invariants offline.

## JSON automation

The global `--json` option produces JSON for one-shot commands and NDJSON for streams:

```sh
meshmsg --json daemon
meshmsg --json status
meshmsg --json invite
meshmsg --json alias show
meshmsg --json listen
meshmsg --json send 'hello'
meshmsg --json send --to build-node-2 'private hello'
meshmsg --json share ./report.pdf
meshmsg --json offers
meshmsg --json download '<signed-offer>' --output ./report-copy.pdf
```

`listen` and `chat` receive complete messages through owner-only IPC. Slow subscribers receive a `lagged` event when their bounded queue drops events.
