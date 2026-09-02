# meshmsg

`meshmsg` 0.1.5 is a small peer-to-peer messaging CLI built on [Iroh Gossip](https://github.com/n0-computer/iroh-gossip). Every node is an equal gossip peer with a persistent identity and network connection. CLI commands talk to the foreground daemon over owner-only local IPC (a Unix socket on Linux or a named pipe on Windows); there is no central message broker.

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
gh release download v0.1.5 --repo Eldar-Ahmadov/meshmsg
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
- `bench-send` and `bench-receive`

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

## Benchmarking a three-node swarm

Benchmark commands use the existing daemon and topic. Benchmark bodies are ordinary signed plaintext messages, so every topic participant can read them and they consume the same network and subscriber resources as chat traffic. Use an isolated topic when possible.

Choose one explicit 128-bit hexadecimal run ID, then start a receiver on nodes B and C before starting node A:

```sh
# Nodes B and C (wait for bench_receive_started in JSON output)
meshmsg --json bench-receive \
  --run-id 0123456789abcdef0123456789abcdef \
  --duration-secs 15 --expected 1000 | tee bench-receive.ndjson

# Node A: 100 messages/s for 10 seconds, with 512-byte bodies
meshmsg --json bench-send \
  --run-id 0123456789abcdef0123456789abcdef \
  --rate 100 --duration-secs 10 --payload-bytes 512 > bench-send.ndjson
```

Run each rate several times and increase it gradually, for example 10, 25, 50, 100, 200, then 500 messages/s. Compare A's `bench_send_summary` with both `bench_receive_summary` records. Reverse the sender and also test simultaneous senders in separate runs when that reflects the intended workload. Only one send benchmark may be active on a given daemon.

`bench-send` defaults to 100 messages/s for 10 seconds with 256-byte bodies and generates a random run ID when omitted. For coordinated receivers, always supply the run ID explicitly. Rates are limited to 1–10,000 messages/s, durations to 1–86,400 seconds, and a run to 10,000,000 planned messages. `--payload-bytes` is the exact complete benchmark body size, including its 106-byte metadata header. The maximum is below 4096 because the signed envelope must also fit; invalid sizes are rejected before sending rather than truncated.

The sender keeps one local IPC connection open and schedules from a monotonic clock without catch-up bursts. Its summary includes planned, attempted, locally queued, failed, schedule-missed, body/envelope bytes, and achieved rates. `delivery_acknowledged` is always false. A schedule miss identifies local sender/daemon saturation, not network loss.

`bench-receive` keeps one subscription open, filters by run ID, and bounds sequence tracking to a 10,000,000-message bitmap. It reports unique and missing messages (when expected is supplied or learned), a sample of at most 100 missing sequence numbers, duplicates, first-seen out-of-order messages, body throughput, and bounded latency percentiles. Latency is a signed-message, one-way wall-clock observation; clocks are not synchronized, so negative or implausible samples are excluded and counted as `clock_invalid`. It is not RTT or network-only latency.

Both local IPC lag and gossip-receiver lag appear in the summary. If `lag.incomplete` is true, sequence gaps cannot be attributed solely to the network. Gossip replication also means payload bytes are not wire bytes: topology, protocol framing, signatures, retransmission, and fan-out can make actual interface traffic much larger. Use OS network counters alongside these summaries for wire throughput.

Both commands emit one started record and one summary record in `--json` NDJSON mode. Representative records are:

```json
{"type":"bench_send_started","schema_version":1,"run_id":"0123456789abcdef0123456789abcdef","rate":100,"duration_secs":10,"payload_bytes":512,"planned":1000,"delivery_acknowledged":false}
{"type":"bench_send_summary","schema_version":1,"run_id":"0123456789abcdef0123456789abcdef","rate":100,"duration_secs":10,"payload_bytes":512,"planned":1000,"attempted":1000,"queued":1000,"failed":0,"schedule_missed":0,"queued_body_bytes":512000,"queued_envelope_bytes":610000,"elapsed_ms":10000,"achieved_messages_per_second":100.0,"achieved_body_bytes_per_second":51200.0,"completion_reason":"deadline","first_error":null,"delivery_acknowledged":false}
{"type":"bench_receive_started","schema_version":1,"run_id":"0123456789abcdef0123456789abcdef","duration_secs":15,"expected":1000}
{"type":"bench_receive_summary","schema_version":1,"run_id":"0123456789abcdef0123456789abcdef","completion_reason":"deadline","elapsed_ms":15000,"expected":1000,"complete":true,"measurement_valid":true,"unique":1000,"missing":0,"missing_sequence_sample":[],"duplicates":0,"out_of_order":0,"highest_sequence":999,"body_bytes":512000,"achieved_messages_per_second":66.67,"achieved_body_bytes_per_second":34133.33,"latency":{"observations":1000,"samples":1000,"sampled":false,"clock_invalid":0,"p50_ms":12,"p95_ms":30,"p99_ms":45},"lag":{"local_events":0,"local_dropped":0,"gossip_events":0,"incomplete":false},"peer_up":0,"peer_down":0,"ignored_messages":0,"malformed_messages":0}
```

Send completion reasons are `deadline`, `interrupted`, `daemon_stopped`, or `send_failed`; `first_error` is a string only for `send_failed` and otherwise null. Receive completion reasons are `deadline`, `interrupted`, or `daemon_stopped`. For a receiver with no valid matching message and no `--expected`, `expected`, `missing`, and `highest_sequence` are null. Latency percentiles are null when there are no valid samples. `complete` means all expected sequences were observed. `measurement_valid` additionally requires no local/gossip lag and no malformed matching messages. `latency.sampled` means the percentiles use a bounded deterministic reservoir rather than every valid observation. Ctrl-C produces an `interrupted` summary; a daemon disconnect produces a partial summary followed by a nonzero exit.


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
- retries configured bootstrap peers after connectivity loss until a gossip neighbor returns;
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
