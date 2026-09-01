# meshmsg

`meshmsg` 0.1.1 is a small peer-to-peer messaging CLI built on [Iroh Gossip](https://github.com/n0-computer/iroh-gossip). Each machine runs one local daemon that owns its persistent identity and network connection. CLI commands talk to that daemon over owner-only local IPC (a Unix socket on Linux or a named pipe on Windows); there is no central message broker.

## Trust and privacy model

**meshmsg is currently a trusted plaintext swarm, not a private messenger.** An invite is effectively membership capability: anyone who obtains it can join the topic, read plaintext messages, and send signed messages. Seeds are full gossip peers rather than opaque relays. Signatures authenticate a peer key, but there is no end-to-end encryption, membership revocation, key rotation, replay protection, or human-friendly identity verification.

Daemon stdout/stderr suppresses incoming message bodies for **both seed and member roles** by default, reducing accidental disclosure to terminals and journald. It logs sender, timestamp, and byte count. Owner-only local `listen` and `chat` IPC subscribers still receive complete bodies. Log suppression is operational hygiene, not a privacy boundary against the machine operator or another swarm participant.

## Install

Build locally:

```sh
cargo install --locked --path .
```

Release archives are provided for `x86_64-unknown-linux-gnu`, portable `x86_64-unknown-linux-musl`, and `x86_64-pc-windows-msvc`. Download a release from the private repository with GitHub CLI, then verify it against the release's unified `SHA256SUMS` file:

```sh
gh release download v0.1.1 --repo Eldar-Ahmadov/meshmsg
sha256sum -c SHA256SUMS --ignore-missing
```

On Linux, extract the matching `.tar.gz` and install `meshmsg` on `PATH`. On Windows x86-64, extract the `.zip` and place `meshmsg.exe` on `PATH`; the release binary statically links the MSVC C runtime, so no separate Visual C++ Redistributable is required. PowerShell can verify it with `(Get-FileHash .\meshmsg-*.zip -Algorithm SHA256).Hash` against the corresponding line in `SHA256SUMS`.

State defaults to `$XDG_DATA_HOME/meshmsg` (`~/.local/share/meshmsg`) on Linux and the platform local data directory (normally `%LOCALAPPDATA%\meshmsg`) on Windows. Override it with `--state-dir` or `MESHMSG_STATE_DIR` consistently for daemon and CLI commands.

## First message

Initialize and run an always-on seed:

```sh
meshmsg seed init
meshmsg --json seed run
```

`seed run` is seed-only and rejects member state. It runs in the foreground and exposes owner-only local control IPC: `~/.local/share/meshmsg/daemon.sock` on Linux or a local-only named pipe with a protected owner/System/Administrators DACL on Windows. Windows clients also authenticate the connected pipe server's process owner before sending requests, preventing another local account from squatting the predictable pipe name. Daemon startup output never includes the invite capability. In another shell, retrieve it explicitly:

```sh
meshmsg seed invite
```

On each client (stdin avoids putting the invite capability in argv or shell history):

```sh
printf '%s' '<invite>' | meshmsg join --token-stdin
meshmsg --json daemon
```

Then use separate terminals:

```sh
printf '%s' 'hello' | meshmsg send --message-stdin
meshmsg listen
meshmsg status
meshmsg chat
```

Stop the local daemon cleanly:

```sh
meshmsg stop
```

`send`, `listen`, `chat`, and `status` never create another Iroh endpoint. They fail with an actionable error when the daemon is unavailable. The exclusive state lock prevents multiple processes from using one identity.

## Input sources and confidentiality

Join and send each require exactly one input source. Existing positional forms remain supported, but expose their contents through shell history and potentially process inspection:

```sh
meshmsg join '<invite>'
meshmsg seed join '<invite>'
meshmsg send 'hello'
```

Prefer explicit UTF-8 file or stdin input for sensitive values:

```sh
meshmsg join --token-file invite.txt
meshmsg seed join --token-stdin < invite.txt
meshmsg send --message-file message.txt
printf '%s' 'hello' | meshmsg send --message-stdin       # sends "hello"
printf '%s\n' 'hello' | meshmsg send --message-stdin     # sends "hello\n"
```

File and stdin flags conflict with each other and with the corresponding positional value. Stdin is read through EOF; a path of `-` means a literal file named `-`, not stdin. Invite input removes exactly one final LF (and a CR immediately before it), while message input is preserved exactly, including spaces and newlines. Empty messages are allowed; empty invite input is not. Inputs must be valid UTF-8. File and stdin reads reject invite tokens over 1 MiB and message bodies over 4096 bytes before allocating beyond those limits. Input files are not deleted or permission-modified, and invite files remain sensitive membership capabilities.

These forms prevent argv and history disclosure only. Successful `send` output still includes the queued body in human and JSON output, and every swarm participant receives plaintext.

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

Validate persisted role, identity, expected public key, topic, and invite invariants offline:

```sh
meshmsg --json doctor
```

Member state must contain an invite; every configured invite must parse and match the persisted topic. Current state binds the expected public key to an immutable identity generation, so `doctor` rejects a missing, corrupt, or mismatched selected key. Legacy state is migrated automatically under the state lock by daemon startup or `doctor`, without changing its identity. If a legacy daemon is running, stop it before asking `doctor` to migrate. Identity generations not selected by `config.json` are harmless and retained to keep lock-free diagnosis crash-safe.

Using an older meshmsg binary after this version has initialized, joined, migrated, or force-replaced state is unsupported. Newly initialized or joined state has no legacy `secret.key`; migration retains that file only for data compatibility, not as a safe downgrade path.

## Local daemon operation

The foreground daemon:

- holds an exclusive lock for state and identity;
- transactionally replaces identity and configuration, with `config.json` as the commit record;
- restricts the Linux state directory to `0700` and socket to `0600`;
- uses a local-only Windows named pipe with a protected owner/System/Administrators DACL;
- removes stale Unix sockets safely (Windows named pipes disappear when their server exits);
- bounds IPC frames and subscriber queues;
- reports lag when a local or gossip receiver drops events;
- suppresses incoming bodies from unattended logs for every role;
- shuts down on `meshmsg stop`, Ctrl-C, SIGINT, or SIGTERM.

Application envelopes are limited to 4096 serialized bytes. Maximum body text is smaller because signatures and metadata consume space.

## Windows daemon operation

Windows builds support the same `daemon`, `seed run`, `send`, `listen`, `chat`, `status`, and `stop` commands. Keep `meshmsg daemon` or `meshmsg --json seed run` running in a dedicated PowerShell window. The default state directory inherits the current user's `%LOCALAPPDATA%` ACL; if `--state-dir` points elsewhere, ensure that directory is accessible only to the intended Windows account. Transactional replacement relies on local-filesystem flush/write-through behavior; network shares or storage that ignores flushes can weaken durability. There is not yet a built-in Windows Service installer or automatic startup integration; use Task Scheduler if unattended startup is required. Ctrl-C and `meshmsg stop` shut the foreground daemon down cleanly.

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

CI also runs dependency audit/policy checks. Pushing a version tag matching `Cargo.toml` builds GNU on an older Ubuntu baseline, portable Linux musl, and native Windows x86-64 archives. It packages the Windows binary with the README and both licenses, generates one `SHA256SUMS` covering all three archives, and creates or updates the GitHub release. The release workflow does not run for ordinary commits.

Licensed under either of Apache-2.0 or MIT at your option; see `LICENSE-APACHE` and `LICENSE-MIT`.
