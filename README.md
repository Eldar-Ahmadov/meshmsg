# meshmsg

`meshmsg` is a small peer-to-peer messaging CLI built on [Iroh Gossip](https://github.com/n0-computer/iroh-gossip) and [Iroh Blobs](https://docs.iroh.computer/protocols/blobs). Every node is an equal peer with a persistent identity and network connection; there is no central message broker.

> [!WARNING]
> `meshmsg` is currently a trusted plaintext swarm, not a private messenger. Anyone with the invite can join the topic, read messages and attachment offers, and send signed messages. See [Operations and security](docs/operations.md#trust-and-privacy-model).

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
meshmsg send 'hello'
meshmsg listen
meshmsg chat
meshmsg status
```

Stop it cleanly:

```sh
meshmsg stop
```

See the [Usage reference](docs/usage.md) for all commands, invite behavior, input sources, status, diagnosis, and JSON automation.

## Attachments

Files and deterministic directory snapshots are announced through signed Gossip offers and transferred with Iroh Blobs. Receiving an offer never downloads it automatically.

```sh
meshmsg --json share ./report.pdf
meshmsg offers
meshmsg download '<signed-offer>' --output ./received-report.pdf

meshmsg --json share ./results
meshmsg download '<signed-directory-offer>' --output ./received-results
```

Downloads are explicit, size-limited, content-verified, persistent across provider restarts, and refuse to overwrite existing paths. See [Attachments](docs/attachments.md) for formats, limits, persistence, and security details.

## Documentation

- [Installation](docs/installation.md)
- [Usage reference](docs/usage.md)
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
bash tests/integration-5-peer.sh target/debug/meshmsg
bash tests/integration-attachments.sh target/debug/meshmsg
```

Licensed under either Apache-2.0 or MIT; see [`LICENSE-APACHE`](LICENSE-APACHE) and [`LICENSE-MIT`](LICENSE-MIT).
