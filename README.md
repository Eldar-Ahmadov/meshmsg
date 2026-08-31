# meshmsg

A small peer-to-peer messaging CLI built on [Iroh Gossip](https://github.com/n0-computer/iroh-gossip). The VPS is a persistent bootstrap **seed**, not a message broker.

## Install

```sh
cargo install --path .
```

State defaults to `$XDG_DATA_HOME/meshmsg` (`~/.local/share/meshmsg`). Override it with `--state-dir` or `MESHMSG_STATE_DIR`.

## First message

On the VPS:

```sh
meshmsg seed init
meshmsg seed run
```

`seed run` prints an invite. It can also be retrieved in another shell after the seed has started:

```sh
meshmsg seed invite
```

On each client:

```sh
meshmsg join '<invite>'
meshmsg listen
```

Send from another joined client:

```sh
meshmsg send 'hello'
```

Or send and receive interactively:

```sh
meshmsg chat
```

## Add redundant seeds

On a new always-on machine, join the existing seed set and run it:

```sh
meshmsg seed join '<invite-from-existing-seed>'
meshmsg seed run
```

The new seed retains its own identity, connects to the same topic, and prints a new invite containing both the old seed set and itself. Distribute that expanded invite to clients so they can bootstrap through any listed seed. Seeds are equal peers; there is no leader or broker. Up to 16 seeds are accepted in an invite.

A seed safely ignores its own endpoint in its persisted invite when restarting.

## Automation

Use `--json` for one-shot JSON and NDJSON event streams:

```sh
meshmsg --json status
meshmsg --json listen
meshmsg --json send 'hello'
meshmsg doctor
```

The private identity is stored in `secret.key` with mode `0600`. Keep at least one seed process running so new peers can bootstrap and the gossip swarm remains available.

## systemd seed service

Create `~/.config/systemd/user/meshmsg-seed.service` (adjust the executable path):

```ini
[Unit]
Description=meshmsg Iroh Gossip seed
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=%h/.cargo/bin/meshmsg --json seed run
Restart=on-failure
RestartSec=3

[Install]
WantedBy=default.target
```

Then run:

```sh
systemctl --user daemon-reload
systemctl --user enable --now meshmsg-seed
journalctl --user -u meshmsg-seed -f
```
