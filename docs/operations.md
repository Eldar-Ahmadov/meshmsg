# Operations and security

## Trust and privacy model

An invite is effectively a topic-access capability. Anyone who obtains it can join the topic, read plaintext broadcast messages and attachment offers, and send signed broadcasts. Existing broadcast and attachment behavior is unchanged; do not mistake the private-send feature for encryption of the topic-wide swarm.

`meshmsg send --to` uses a separate authenticated, encrypted Iroh transport. Its signed request binds the sender key, recipient key, topic, message ID, timestamp, and body. This protects the private body from other topic participants while it travels between the two daemons. It does not protect either endpoint: the sender and recipient processes, machine operators, and owner-only local `listen`/`chat` subscribers can access the plaintext. Network infrastructure can still observe connection metadata. There is no human-friendly key verification, account identity, access revocation, key rotation, multi-device identity, or group-private messaging. Private mode covers text only; attachments retain their existing topic-wide offer and reusable-capability model.

The recipient's signed acceptance acknowledgement means only that its daemon authenticated and validated the message and placed it into a bounded volatile queue. It is not a read receipt, disk write, durable-delivery proof, or guarantee that any subscriber received the event. Private messages have no history, offline inbox, store-and-forward, retry, or recovery after a process failure. The sender's operation times out after 30 seconds; an error or timeout can leave the outcome unknown, so manual retries can duplicate a message.

Replay defense is deliberately limited: IDs are remembered in a bounded in-memory recipient cache for about 10 minutes and are lost on daemon restart. Signed timestamps accept bounded clock skew, so grossly incorrect clocks can reject traffic. These controls reduce accidental/immediate replay; they are not durable exactly-once delivery.

### Aliases and presence

Aliases are convenience labels, not identities or access-control names. Presence records are signed by their advertised peer key and bound to the topic, but any invite holder can advertise any valid alias. A malicious or accidental duplicate makes alias resolution fail closed at that moment; it can deny use of that alias but cannot make meshmsg choose between simultaneous claimants. Alias bindings are not pinned, however. If a claimant disappears or its presence expires, a later send can resolve the same alias to a different sole claimant without confirmation. For identity- or continuity-sensitive communication, verify the canonical full public key out of band and address it directly.

By default, `init` and `join` persist and advertise the machine's lowercased short hostname. This can reveal a person's name, employer naming scheme, device role, or other sensitive inventory data. `--no-default-alias` prevents capture and advertising; `meshmsg alias clear` (or its `disable` synonym) persistently opts an existing state out. Disabling the alias does not disable signed presence or direct sends by public key.

Signed presence is control-plane discovery on a derived Gossip topic. It exposes the alias (when enabled), peer public key, timestamp, and bounded Iroh endpoint addresses to topic participants. Records refresh about every 30 seconds and carry a nominal 150-second lifetime; accepted clock skew can affect the observed expiry, so disappearance and alias changes are not immediate. Presence proves that a key signed a claim, not that the alias is truthful, a human is present, or the endpoint is currently reachable.

Daemon logs suppress incoming broadcast and private message bodies, recording metadata and byte counts. Owner-only local subscribers still receive complete bodies. Log suppression is operational hygiene, not a privacy boundary against the machine operator.

## Web access boundary

The optional `meshmsg web` process has **no app authentication**. It binds only loopback and must be exposed remotely only through **Tailscale Serve, never Funnel**, with tailnet access rules restricted to trusted users/devices. Those users can read the feed and broadcast as the daemon's identity. Host/Origin checks and CSP are browser defenses, not authentication against an authorized or local client. Web shutdown does not stop the daemon or remove an operator-managed Serve route. See [Mobile web UI operations](web.md) for explicit origin configuration, limits, recovery and exposure checks.

## Daemon behavior

The foreground daemon:

- holds an exclusive lock for state and identity;
- publishes its endpoint only after it is online;
- emits bounded signed presence on a separate derived Gossip topic;
- accepts bounded authenticated direct-message connections with limited concurrency and replay state;
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

Broadcast application envelopes are limited to 4096 serialized bytes; their maximum text body is smaller because signatures and metadata consume space. Private bodies must be nonempty and are limited to 4096 UTF-8 bytes, with a bounded 6 KiB protocol frame. Incoming private acceptance uses a bounded volatile queue and can reject a message under load.

State uses `config.json` as the commit record and immutable identity generations. Alias state is stored separately in `alias.json` inside the state directory and is read when the daemon starts, so changes require a stopped daemon and restart. `doctor` rejects a missing, corrupt, or mismatched selected key. Unselected generations left by interrupted forced replacement are harmless.

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

## Compatibility

The original signed broadcast topic and envelope format are unchanged. New clients use a separate derived presence topic and `/meshmsg/direct/1` protocol, so old and new clients can continue exchanging supported broadcasts and attachment offers. Older clients do not advertise compatible presence, resolve aliases, accept this direct protocol, or display private-message events. A private send to an old peer therefore fails rather than falling back to plaintext broadcast. The web UI is also broadcast-only and filters private events.
