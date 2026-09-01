# meshmsg

`meshmsg` 0.1.4 is a small peer-to-peer messaging CLI built on [Iroh Gossip](https://github.com/n0-computer/iroh-gossip). Every node is an equal gossip peer with a persistent identity and network connection. CLI commands talk to the foreground daemon over owner-only local IPC (a Unix socket on Linux or a named pipe on Windows); there is no central message broker.

## Trust and privacy model

**meshmsg is currently a trusted plaintext swarm, not a private messenger.** An invite is effectively topic access capability: anyone who obtains it can join the topic, read plaintext messages, and send signed messages. Endpoint-advertising nodes remain ordinary gossip peers rather than relays or leaders. Signatures authenticate a peer key, but there is no end-to-end encryption, access revocation, key rotation, replay protection, or human-friendly identity verification.

Daemon stdout and stderr suppress incoming message bodies by default, reducing accidental disclosure to terminals and journald. They log sender, timestamp, and byte count. Owner-only local `listen` and `chat` IPC subscribers still receive complete bodies. Log suppression is operational hygiene, not a privacy boundary against the machine operator or another swarm participant.

## Install

Install the latest release on x86-64 Linux:

```sh
curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/Eldar-Ahmadov/meshmsg/main/install.sh | bash
```

The installer detects the local operating system and architecture, downloads the portable `x86_64-unknown-linux-musl` archive from the latest published GitHub release, verifies it against that release's `SHA256SUMS`, and then installs `meshmsg`. It uses `/usr/local/bin` when run as root and `$HOME/.local/bin` otherwise. Override the destination without running as root:

```sh
curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/Eldar-Ahmadov/meshmsg/main/install.sh \
  | MESHMSG_INSTALL_DIR="$HOME/bin" bash
```

Review [`install.sh`](install.sh) before piping it to a shell. Unsupported operating systems or architectures fail without downloading an archive.

To build from source instead:

```sh
cargo install --locked --path .
```

Release archives are provided for `x86_64-unknown-linux-gnu`, portable `x86_64-unknown-linux-musl`, and `x86_64-pc-windows-msvc`. To install manually, download a release and verify it against `SHA256SUMS`:

```sh
gh release download v0.1.4 --repo Eldar-Ahmadov/meshmsg
sha256sum -c SHA256SUMS --ignore-missing
```

On Linux, extract the matching `.tar.gz` and install `meshmsg` on `PATH`. On Windows x86-64, extract the `.zip` and place `meshmsg.exe` on `PATH`; the release binary statically links the MSVC C runtime, so no separate Visual C++ Redistributable is required. PowerShell can verify it with `(Get-FileHash .\meshmsg-*.zip -Algorithm SHA256).Hash` against the corresponding line in `SHA256SUMS`.

State defaults to `$XDG_DATA_HOME/meshmsg` (`~/.local/share/meshmsg`) on Linux and the platform local data directory (normally `%LOCALAPPDATA%\meshmsg`) on Windows. Override it with `--state-dir` or `MESHMSG_STATE_DIR` consistently for daemon and CLI commands.

## Start a topic

Create a fresh topic and run its daemon:

```sh
meshmsg init
meshmsg --json daemon
```

Freshly initialized state has `advertise_self=true` but no invite. After the endpoint becomes online, the daemon atomically stores an invite containing its endpoint while it holds the state lock. Therefore `meshmsg invite` intentionally fails until the first successful daemon startup. Daemon startup output never includes the invite capability.

In another shell, export the stored invite explicitly:

```sh
meshmsg invite
```

Join from another machine (stdin avoids putting the capability in argv or shell history):

```sh
printf '%s' '<invite>' | meshmsg join --token-stdin
meshmsg --json daemon
```

`join` defaults to `advertise_self=false`. Such a peer uses the invite's endpoint list to bootstrap but does not add itself to its stored invite. To publish the joining peer's endpoint after it is online:

```sh
meshmsg join --advertise-self '<invite>'
meshmsg --json daemon
meshmsg invite
```

Every peer can export its stored invite. Advertising changes only that peer's stored invite; it does not create a distinct node category. Invites contain at most 16 bootstrap peers. Adding a new identity to a full list fails without mutating the list, while restarting an already-listed identity refreshes its endpoint at capacity. `join --advertise-self` checks capacity before generating an identity or committing replacement state.

Use separate terminals for local interaction:

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

## Commands

The canonical top-level commands are:

- `init [--force]`
- `join [--advertise-self] [--force] <invite source>`
- `daemon`
- `invite`
- `send`, `listen`, `chat`, `status`, `stop`, and `doctor`

There are no compatibility command aliases or nested initialization/run command groups.

## Input sources and confidentiality

Join and send each require exactly one input source. Positional forms are supported but expose contents through shell history and potentially process inspection:

```sh
meshmsg join '<invite>'
meshmsg send 'hello'
```

Prefer explicit UTF-8 file or stdin input:

```sh
meshmsg join --token-file invite.txt
meshmsg join --advertise-self --token-stdin < invite.txt
meshmsg send --message-file message.txt
printf '%s' 'hello' | meshmsg send --message-stdin       # sends "hello"
printf '%s\n' 'hello' | meshmsg send --message-stdin     # sends "hello\n"
```

File and stdin flags conflict with each other and with the corresponding positional value. Stdin is read through EOF; a path of `-` means a literal file named `-`, not stdin. Invite input removes exactly one final LF (and a CR immediately before it), while message input is preserved exactly, including spaces and newlines. Empty messages are allowed; empty invite input is not. Inputs must be valid UTF-8. Reads reject invite tokens over 1 MiB and message bodies over 4096 bytes before allocating beyond those limits. Input files are not deleted or permission-modified, and invite files remain sensitive topic capabilities.

These forms prevent argv and history disclosure only. Successful `send` output includes the queued body in human and JSON output, and every topic participant receives plaintext.

## Send semantics

A successful send reports `queued`, for example:

```json
{"type":"queued","from":"<peer-id>","body":"hello","delivery_acknowledged":false}
```

`queued` means the local gossip implementation accepted the broadcast request. It is not a delivery acknowledgement and does not guarantee that any remote peer received or persisted the message.

## Startup, status, and diagnosis

Startup and topic bootstrap are bounded. If joining configured bootstrap peers or becoming online exceeds its deadline, the process exits nonzero with an actionable error so a service manager can retry. JSON mode emits a `startup_error` event with `phase` and `retryable` fields. At least one listed bootstrap peer must normally be reachable when joining. The local peer's own identity is excluded from bootstrap attempts, allowing a restarted sole advertiser to start without dialing itself.

Live JSON status reports connectivity and truthful stored-state facts:

```sh
meshmsg --json status
```

```json
{"type":"status","running":true,"advertises_self":false,"has_invite":true,"bootstrap_peer_count":3,"self_advertised":false,"endpoint_online":true,"topic_joined":true,"neighbors":2}
```

`neighbors` is the current direct gossip-neighbor count, including the neighbor consumed during initial bootstrap. `topic_joined` is derived from live gossip state and becomes false when no direct neighbors remain, including for a lone first peer. These are local runtime observations, not end-to-end delivery guarantees.

Validate state, identity binding, expected public key, topic, and invite invariants offline:

```sh
meshmsg --json doctor
```

State and identity are committed atomically, with `config.json` selecting an immutable identity generation. `doctor` rejects a missing, corrupt, or mismatched selected key. This release is a clean state and invite-format break: prior state and invite wire formats are not migrated or accepted, and deprecated JSON fields are rejected. Reinitialize or join again rather than reusing prior data. Identity generations not selected by `config.json` may remain after an interrupted forced replacement and are harmless.

## Local daemon operation

The foreground daemon:

- holds an exclusive lock for state and identity;
- publishes its endpoint only after endpoint-online completes and while still holding that lock;
- transactionally replaces identity and configuration, with `config.json` as the commit record;
- restricts the Linux state directory to `0700` and socket to `0600`;
- uses a local-only Windows named pipe with a protected owner/System/Administrators DACL;
- authenticates the connected pipe server's process owner on Windows;
- removes stale Unix sockets safely;
- bounds IPC frames and subscriber queues;
- reports lag when a local or gossip receiver drops events;
- suppresses incoming bodies from unattended logs;
- shuts down on `meshmsg stop`, Ctrl-C, SIGINT, or SIGTERM.

Application envelopes are limited to 4096 serialized bytes. Maximum body text is smaller because signatures and metadata consume space.

## Windows daemon operation

Windows builds support the same commands. Keep `meshmsg --json daemon` running in a dedicated PowerShell window. The default state directory inherits the current user's `%LOCALAPPDATA%` ACL; if `--state-dir` points elsewhere, ensure that directory is accessible only to the intended Windows account. Transactional replacement relies on local-filesystem flush/write-through behavior; network shares or storage that ignores flushes can weaken durability. There is not yet a built-in Windows Service installer. Ctrl-C and `meshmsg stop` shut the foreground daemon down cleanly.

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

For service operation after logout:

```sh
sudo loginctl enable-linger "$USER"
```

Startup timeouts exit nonzero, so `Restart=on-failure` retries temporary network/bootstrap failures without hanging permanently.

## JSON automation

Use the global `--json` option for one-shot JSON and NDJSON streams:

```sh
meshmsg --json daemon
meshmsg --json status
meshmsg --json invite
meshmsg --json listen
meshmsg --json send 'hello'
```

`listen` and `chat` receive complete messages through owner-only IPC. Slow subscribers receive a `lagged` event when their bounded queue drops events.

## Development and release checks

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo build --locked
bash tests/integration-5-peer.sh target/debug/meshmsg
```

CI also runs dependency audit and policy checks. Pushing a version tag matching `Cargo.toml` builds GNU on an older Ubuntu baseline, portable Linux musl, and native Windows x86-64 archives. It packages the Windows binary with the README and both licenses, generates one `SHA256SUMS` covering all three archives, and creates or updates the GitHub release. The release workflow does not run for ordinary commits.

Licensed under either of Apache-2.0 or MIT at your option; see `LICENSE-APACHE` and `LICENSE-MIT`.
