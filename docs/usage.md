# Usage reference

## Commands

The canonical top-level commands are:

- `init [--force]`
- `join [--advertise-self] [--force] <invite source>`
- `daemon`
- `invite`
- `send`, `listen`, `chat`, `status`, `stop`, and `doctor`
- `share <path>`, `offers`, and `download <offer-or-ticket> --output <path>`
- `bench-send` and `bench-receive`

Run `meshmsg <command> --help` for command-specific options.

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

`queued` means the local Gossip implementation accepted the broadcast request. It is not a delivery acknowledgement.

## Input sources

Join and send each require exactly one input source. Positional values are convenient but visible in shell history and potentially process listings:

```sh
meshmsg join '<invite>'
meshmsg send 'hello'
```

Prefer file or stdin input for sensitive values:

```sh
meshmsg join --token-file invite.txt
meshmsg join --advertise-self --token-stdin < invite.txt
meshmsg send --message-file message.txt
printf '%s' 'hello' | meshmsg send --message-stdin
```

File and stdin flags conflict with each other and with the positional value. Stdin is read through EOF; `-` is a literal filename, not stdin. Invite input removes one final LF and an optional preceding CR. Message input is preserved exactly. Inputs must be UTF-8. Invite input is limited to 1 MiB and message bodies to 4096 bytes.

These forms prevent argv and history disclosure only. Messages remain plaintext to every topic participant.

## Status and diagnosis

```sh
meshmsg --json status
meshmsg --json doctor
```

Representative status:

```json
{"type":"status","running":true,"advertises_self":false,"has_invite":true,"bootstrap_peer_count":3,"self_advertised":false,"endpoint_online":true,"topic_joined":true,"neighbors":2}
```

`neighbors` is the current direct Gossip-neighbor count. `topic_joined` becomes false when no direct neighbors remain, including for a lone first peer. These are local observations, not delivery guarantees.

Startup and bootstrap are bounded. If joining configured peers or becoming online times out, the daemon exits nonzero so a service manager can retry. JSON mode emits a structured `startup_error`.

`doctor` validates stored state, identity binding, expected public key, topic, and invite invariants offline.

## JSON automation

The global `--json` option produces JSON for one-shot commands and NDJSON for streams:

```sh
meshmsg --json daemon
meshmsg --json status
meshmsg --json invite
meshmsg --json listen
meshmsg --json send 'hello'
meshmsg --json share ./report.pdf
meshmsg --json offers
meshmsg --json download '<signed-offer>' --output ./report-copy.pdf
```

`listen` and `chat` receive complete messages through owner-only IPC. Slow subscribers receive a `lagged` event when their bounded queue drops events.
