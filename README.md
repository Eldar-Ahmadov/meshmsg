# meshmsg

`meshmsg` 0.1.1 is a small peer-to-peer messaging CLI built on [Iroh Gossip](https://github.com/n0-computer/iroh-gossip). Each machine runs one local daemon that owns its persistent identity and network connection. CLI commands talk to that daemon over an owner-only Unix socket; there is no central message broker.

## Trust and privacy model

**meshmsg is currently a trusted plaintext swarm, not a private messenger.** An invite is effectively membership capability: anyone who obtains it can join the topic, read plaintext messages, and send signed messages. Seeds are full gossip peers rather than opaque relays. Signatures authenticate a peer key, but there is no end-to-end encryption, membership revocation, key rotation, replay protection, or human-friendly identity verification.

Daemon stdout/stderr suppresses incoming message bodies for **both seed and member roles** by default, reducing accidental disclosure to terminals and journald. It logs sender, timestamp, and byte count. Owner-only local `listen` and `chat` IPC subscribers still receive complete bodies. Log suppression is operational hygiene, not a privacy boundary against the machine operator or another swarm participant.

## Install

Build locally:

```sh
cargo install --locked --path .
```

Release archives are provided for `x86_64-unknown-linux-gnu` and portable `x86_64-unknown-linux-musl`. Verify `SHA256SUMS` before installing a downloaded binary.

State defaults to `$XDG_DATA_HOME/meshmsg` (`~/.local/share/meshmsg`). Override it with `--state-dir` or `MESHMSG_STATE_DIR` consistently for daemon and CLI commands.

## First message

Initialize and run an always-on seed:

```sh
meshmsg seed init
meshmsg --json seed run
```

`seed run` is seed-only and rejects member state. It runs in the foreground and writes an owner-only control socket at `~/.local/share/meshmsg/daemon.sock`. Daemon startup output never includes the invite capability. In another shell, retrieve it explicitly:

```sh
meshmsg seed invite
```

On each client:

```sh
meshmsg join '<invite>'
meshmsg --json daemon
```

Then use separate terminals:

```sh
meshmsg send 'hello'
meshmsg listen
meshmsg status
meshmsg chat
```

Stop the local daemon cleanly:

```sh
meshmsg stop
```

`send`, `listen`, `chat`, and `status` never create another Iroh endpoint. They fail with an actionable error when the daemon is unavailable. The exclusive state lock prevents multiple processes from using one identity.

## Send semantics

A successful send reports `queued`, for example:

```json
{"type":"queued","from":"<peer-id>","body":"hello","delivery_acknowledged":false}
```

`queued` means the local gossip implementation accepted the broadcast request. It is **not** a delivery acknowledgement and does not guarantee that any remote peer received or persisted the message.

## Redundant seeds

On another always-on machine:

```sh
meshmsg seed join '<invite-from-existing-seed>'
meshmsg --json seed run
```

The seed persists an expanded invite containing itself and previous seeds. Distribute the newest invite to clients. Seeds are equal peers; there is no leader. Invites accept up to 16 seeds, reject adding a seventeenth, and replace a restarting seed's stale endpoint by identity.

A member must use `meshmsg daemon`; seed-only `seed run` and `seed invite` reject member state. The generic daemon supports both roles.

## Startup, status, and diagnosis

Startup and topic bootstrap are bounded. If joining configured seeds or becoming online exceeds its deadline, the process exits nonzero with an actionable error so systemd can retry; JSON mode also emits a `startup_error` event with `phase` and `retryable` fields. At least one configured seed must be reachable for a member or additional seed to bootstrap.

Live status distinguishes the observations available after startup:

```sh
meshmsg --json status
```

```json
{"type":"status","running":true,"endpoint_online":true,"topic_joined":true,"neighbors":2}
```

These are local runtime states, not guarantees of end-to-end message delivery. `neighbors` is the current direct gossip-neighbor count, including the neighbor consumed during initial bootstrap. `topic_joined` is derived from that live gossip state and becomes false when no direct neighbors remain (including for a lone first seed).

Validate persisted role, identity, topic, and invite invariants offline:

```sh
meshmsg --json doctor
```

Member state must contain an invite; every configured invite must parse and match the persisted topic.

## Local daemon operation

The foreground daemon:

- holds an exclusive lock for state and identity;
- uses atomic state writes;
- restricts the state directory to `0700` and socket to `0600`;
- removes stale sockets safely;
- bounds IPC frames and subscriber queues;
- reports lag when a local or gossip receiver drops events;
- suppresses incoming bodies from unattended logs for every role;
- shuts down on `meshmsg stop`, Ctrl-C, SIGINT, or SIGTERM.

Application envelopes are limited to 4096 serialized bytes. Maximum body text is smaller because signatures and metadata consume space.

## systemd user service

Initialize seed or member state first, then create `~/.config/systemd/user/meshmsg.service`:

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

For service operation after logout:

```sh
sudo loginctl enable-linger "$USER"
```

Startup timeouts exit nonzero, so `Restart=on-failure` retries temporary network/bootstrap failures without a permanently hung service.

## JSON automation

Use the global `--json` option for one-shot JSON and NDJSON streams:

```sh
meshmsg --json daemon
meshmsg --json status
meshmsg --json listen
meshmsg --json send 'hello'
```

`listen` and `chat` receive complete messages through owner-only IPC. Slow subscribers receive a `lagged` event when their bounded queue drops events.

## Development and release checks

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
bash tests/integration-3-seed-2-client.sh target/debug/meshmsg
```

CI also runs dependency audit/policy checks. Pushing a version tag matching `Cargo.toml` builds GNU on an older Ubuntu baseline plus a portable musl archive, generates `SHA256SUMS`, and uploads release assets. The release workflow does not run for ordinary commits.

Licensed under either of Apache-2.0 or MIT at your option; see `LICENSE-APACHE` and `LICENSE-MIT`.
