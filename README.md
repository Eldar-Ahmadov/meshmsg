# meshmsg

A small peer-to-peer messaging CLI built on [Iroh Gossip](https://github.com/n0-computer/iroh-gossip). Each machine runs one local daemon that owns its persistent identity and network connection. The CLI talks to that daemon over an owner-only Unix socket; there is no central message broker.

## Install

```sh
cargo install --path .
```

State defaults to `$XDG_DATA_HOME/meshmsg` (`~/.local/share/meshmsg`). Override it with `--state-dir` or `MESHMSG_STATE_DIR` on both the daemon and CLI commands.

## First message

Initialize and run the seed daemon on the VPS:

```sh
meshmsg seed init
meshmsg seed run
```

`seed run` is the seed-compatible spelling of `meshmsg daemon`: both run in the foreground. The daemon writes its control socket to `~/.local/share/meshmsg/daemon.sock` with mode `0600`. Retrieve the seed invite from another shell:

```sh
meshmsg seed invite
```

On each client, save the invite and start its daemon:

```sh
meshmsg join '<invite>'
meshmsg daemon
```

Then use separate terminals to send, listen, inspect live status, or chat:

```sh
meshmsg send 'hello'
meshmsg listen
meshmsg status
meshmsg chat
```

Stop the local daemon cleanly with:

```sh
meshmsg stop
```

`send`, `listen`, `chat`, and `status` never create their own Iroh endpoint. If the daemon is unavailable they fail with an instruction to start `meshmsg daemon`. This prevents multiple processes from using the same persistent identity.

## Add redundant seeds

On a new always-on machine:

```sh
meshmsg seed join '<invite-from-existing-seed>'
meshmsg seed run
```

The new seed connects to the same topic and persists a new invite containing itself and the previous seeds. Distribute that expanded invite to clients. Seeds are equal peers; there is no leader. Up to 16 seeds are accepted, and a full invite cannot add a seventeenth seed. A restarting seed replaces its own old endpoint.

## Local daemon and automation

The daemon is intentionally foreground-only so a process supervisor owns lifecycle and logs. It holds an exclusive state lock, removes stale socket files at startup, rejects a second daemon for the same state directory, and removes its socket on clean shutdown, Ctrl-C, or SIGTERM. The state directory and control socket are owner-only. IPC frames are bounded, and local listener disconnects do not affect the daemon.

Use `--json` for one-shot JSON and NDJSON streams:

```sh
meshmsg --json daemon
meshmsg --json status
meshmsg --json listen
meshmsg --json send 'hello'
```

`listen` and `chat` receive full message events over the local socket. A bounded event queue protects the daemon from slow local listeners; a lag event reports dropped local events. The private identity is stored in `secret.key` with mode `0600`. Application envelopes are limited to 4096 bytes; the maximum text length is smaller because signatures and other metadata consume space.

## Privacy model

Seeds are full gossip peers, not opaque relays. Messages are signed but currently plaintext, so every participating seed and client can technically read them. End-to-end encryption is not implemented.

To reduce accidental disclosure, a seed daemon suppresses received message bodies in its own stdout/service logs. Local `meshmsg listen` and `meshmsg chat` clients still receive full bodies through the owner-only socket. This is not a privacy boundary against the machine or seed operator.

## systemd user service

The same service works for seed and member state. For a seed, initialize it first with `meshmsg seed init`; for a member, run `meshmsg join` first.

Create `~/.config/systemd/user/meshmsg.service` (adjust the executable path):

```ini
[Unit]
Description=meshmsg peer daemon
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=%h/.cargo/bin/meshmsg --json daemon
Restart=on-failure
RestartSec=3

[Install]
WantedBy=default.target
```

Then run:

```sh
systemctl --user daemon-reload
systemctl --user enable --now meshmsg
meshmsg status
journalctl --user -u meshmsg -f
```
