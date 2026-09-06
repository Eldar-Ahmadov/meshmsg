# meshmsg

`meshmsg` is a small peer-to-peer messaging CLI built on [Iroh Gossip](https://github.com/n0-computer/iroh-gossip) and [Iroh Blobs](https://docs.iroh.computer/protocols/blobs). Every node is an equal peer with a persistent identity and network connection; there is no central message broker.

> [!WARNING]
> Broadcast messages and attachment offers remain plaintext to everyone with the topic invite. `send --to` instead uses a separately encrypted, authenticated direct connection, but it provides no offline delivery, durable storage, or read receipt. Default aliases disclose a captured short hostname to topic participants. See [Operations and security](docs/operations.md#trust-and-privacy-model).

## Install

Install the latest x86-64 Linux release:

```sh
curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/Eldar-Ahmadov/meshmsg/main/install.sh | bash
```

Or install from a local checkout:

```sh
cargo install --locked --path .
```

See [Installation](docs/installation.md) for Git-revision installs, manual release verification, supported targets, and state-directory configuration.

## Quick start

Create a topic and keep its daemon running:

```sh
meshmsg init
meshmsg --json daemon
```

In another terminal, export the invite:

```sh
meshmsg invite
```

Join from another machine and start its daemon:

```sh
printf '%s' '<invite>' | meshmsg join --token-stdin
meshmsg --json daemon
```

Send and receive messages through the local daemon:

```sh
meshmsg send 'hello'                  # unchanged topic-wide broadcast
meshmsg send --to laptop 'private'   # unique advertised alias
meshmsg send --to '<full-peer-key>' 'private'
meshmsg listen
meshmsg chat
meshmsg status
meshmsg peers                         # sanitized current directory snapshot
```

`meshmsg --json peers` returns a deterministic, versioned snapshot containing a separate local identity and sorted current remote public keys, optional normalized aliases, and bounded local freshness only—never endpoint routes or raw presence records. `listen` begins with the same snapshot and then emits sanitized discovery/update/expiry events.

`init` and `join` capture the machine's short hostname once as the default advertised alias. Use `--no-default-alias` to opt out, or manage it later with `meshmsg alias show|set|clear|reset-hostname`. A private-send success acknowledges only acceptance by the recipient daemon—not reading or durable delivery.

Stop it cleanly:

```sh
meshmsg stop
```

See the [Usage reference](docs/usage.md) for all commands, invite behavior, input sources, status, diagnosis, and JSON automation.

Run an interactive benchmark setup and live monitor against the existing daemon with:

```sh
meshmsg bench-tui
```

See [Benchmarking](docs/benchmarking.md) for measurement semantics, coordinated multi-node runs, and NDJSON output.

## Mobile web broadcast

Run `meshmsg web` alongside the existing daemon, then open `http://127.0.0.1:8787/`. For phone access, use **Tailscale Serve, never Funnel**, with an explicitly configured HTTPS `--origin`. There is no app authentication: tailnet access rules are the remote access boundary. The UI queues text broadcasts locally (not delivery acknowledgements) and shows a bounded live feed without history, including read-only attachment cards with safe metadata but no transfer controls or capabilities.

See [Mobile web UI](docs/web.md) for setup, security boundaries, reconnect behavior, and operations.

## Attachments

Files and deterministic directory snapshots are announced through signed Gossip offers and transferred with Iroh Blobs. Receiving an offer never downloads it automatically.

```sh
meshmsg --json share ./report.pdf
meshmsg offers
printf '%s' '<signed-offer>' | meshmsg download --offer-stdin --output ./received-report.pdf

meshmsg --json share ./results
meshmsg download '<signed-directory-offer>' --output ./received-results
```

Downloads are explicit, size-limited, content-verified, persistent across provider restarts, and refuse to overwrite existing paths. See [Attachments](docs/attachments.md) for formats, limits, persistence, and security details.

## Documentation

- [Installation](docs/installation.md)
- [Usage reference](docs/usage.md)
- [Mobile web UI](docs/web.md)
- [Attachments](docs/attachments.md)
- [Operations and security](docs/operations.md)
- [Benchmarking](docs/benchmarking.md)
- [Development and releases](docs/development.md)

## Development

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo build --locked
node tests/web-ui.cjs
python3 tests/integration-web.py target/debug/meshmsg
python3 tests/integration-web-peer.py target/debug/meshmsg
bash tests/integration-5-peer.sh target/debug/meshmsg
bash tests/integration-attachments.sh target/debug/meshmsg
bash tests/integration-direct-messages.sh target/debug/meshmsg
```

Licensed under either Apache-2.0 or MIT; see [`LICENSE-APACHE`](LICENSE-APACHE) and [`LICENSE-MIT`](LICENSE-MIT).
