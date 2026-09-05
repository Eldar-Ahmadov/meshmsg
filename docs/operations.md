# Operations and security

## Trust and privacy model

**meshmsg is a trusted plaintext swarm, not a private messenger.** An invite is effectively a topic-access capability: anyone who obtains it can join the topic, read plaintext messages, and send signed messages.

Signatures authenticate peer keys, but meshmsg has no end-to-end encryption, access revocation, key rotation, replay protection, or human-friendly identity verification. Endpoint-advertising nodes remain ordinary peers rather than leaders or relays.

Daemon logs suppress incoming message bodies, recording sender, timestamp, and byte count. Owner-only local `listen` and `chat` subscribers still receive complete bodies. Log suppression is operational hygiene, not a privacy boundary against the machine operator or another topic member.

## Web access boundary

The optional `meshmsg web` process has **no app authentication**. It binds only loopback and must be exposed remotely only through **Tailscale Serve, never Funnel**, with tailnet access rules restricted to trusted users/devices. Those users can read the feed and broadcast as the daemon's identity. Host/Origin checks and CSP are browser defenses, not authentication against an authorized or local client. Web shutdown does not stop the daemon or remove an operator-managed Serve route. See [Mobile web UI operations](web.md) for explicit origin configuration, limits, recovery and exposure checks.

## Daemon behavior

The foreground daemon:

- holds an exclusive lock for state and identity;
- publishes its endpoint only after it is online;
- transactionally replaces identity and configuration;
- restricts the Linux state directory to `0700` and socket to `0600`;
- uses a protected owner/System/Administrators named-pipe ACL on Windows;
- authenticates the connected pipe server's process owner on Windows;
- removes stale Unix sockets safely;
- bounds IPC frames and subscriber queues;
- serves persistent attachments on the same endpoint and router as Gossip;
- limits attachment concurrency and aborts tracked async transfers at shutdown;
- reports local and Gossip receiver lag;
- retries bootstrap peers after connectivity loss;
- suppresses incoming message bodies in unattended logs;
- shuts down on `meshmsg stop`, Ctrl-C, SIGINT, or SIGTERM.

Application envelopes are limited to 4096 serialized bytes. The maximum text body is smaller because signatures and metadata consume space.

State uses `config.json` as the commit record and immutable identity generations. `doctor` rejects a missing, corrupt, or mismatched selected key. Unselected generations left by interrupted forced replacement are harmless.

## Windows

Windows supports the same commands. Keep `meshmsg --json daemon` running in a dedicated PowerShell window.

The default state directory inherits the current user's `%LOCALAPPDATA%` ACL. If `--state-dir` points elsewhere, restrict it to the intended account. Transactional replacement relies on local-filesystem flush and write-through behavior; network shares or storage that ignores flushes can weaken durability.

There is no built-in Windows Service installer. Ctrl-C and `meshmsg stop` shut down the foreground daemon cleanly.

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

To keep it running after logout:

```sh
sudo loginctl enable-linger "$USER"
```

Startup timeouts exit nonzero, so `Restart=on-failure` retries temporary connectivity failures.
