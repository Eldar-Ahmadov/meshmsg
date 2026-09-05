# Mobile broadcast web UI

`meshmsg web` is a **separate foreground process** serving an embedded, responsive vanilla HTML/CSS/JS UI. It talks to an existing daemon through the same Unix socket or Windows named pipe as the CLI. It does not start, initialize, join, stop, or reconfigure the daemon. Use the same OS account and `--state-dir` as the daemon. No Node.js, asset directory, or frontend build is required at runtime.

## Local use

With an initialized/joined state and its daemon running in another terminal:

```sh
meshmsg --state-dir /path/to/state daemon
```

Start the web process separately:

```sh
meshmsg --state-dir /path/to/state web
```

Open **http://127.0.0.1:8787/** on that machine. The numeric host matters: `localhost` is not an alias in the Host allowlist. `--listen 127.0.0.1:9898` selects another port; IPv6 loopback (for example `--listen '[::1]:8787'`) is also supported. Non-loopback binds are rejected. Startup diagnostics go to stderr; `--json` does not turn HTTP serving into a CLI event stream.

The web process may start while the daemon is offline. Status and the feed recover when that daemon starts or restarts. Ctrl-C stops **only web**. `meshmsg stop` separately stops the daemon.

## Phone access through Tailscale Serve — never Funnel

There is **no app authentication, login, token, session, or user separation**. Tailscale membership and tailnet access rules are the remote access boundary. Everyone permitted to reach this service can read the live feed and broadcast as the daemon's identity. Restrict access to the intended trusted people/devices before exposing it. Any local process can also access the loopback bridge; Host/Origin checks are browser defenses, not authentication against such clients.

These are operator instructions, **not automatically executed by meshmsg**. They change your Serve configuration: inspect any existing routes and coordinate with their owner first. Use a current Tailscale client, an authenticated host and phone in your tailnet, and the HTTPS/MagicDNS setup required by Tailscale Serve. Substitute the host's actual full Tailscale HTTPS name:

```sh
# Terminal 1: existing daemon remains running.
# Terminal 2: explicitly permit the browser's external HTTPS origin.
meshmsg --state-dir /path/to/state web \
  --listen 127.0.0.1:8787 \
  --origin https://my-host.my-tailnet.ts.net

# Terminal 3: operator-managed tailnet-only HTTPS reverse proxy.
tailscale serve status
tailscale serve --bg --https=443 http://127.0.0.1:8787
```

Open **https://my-host.my-tailnet.ts.net/** on the phone while Tailscale is connected. `--origin` must be the exact origin (scheme + hostname, with a nondefault port if applicable): HTTPS only, no credentials, path, query, or trailing slash. Serve the UI at the origin root, not a path prefix. The local numeric HTTP origin remains allowed for diagnostics.

**Never expose this bridge through Tailscale Funnel**, a public reverse proxy, router forwarding, or a LAN listener. Tailscale Serve protects the browser-to-host path; it does not change meshmsg's [trusted plaintext swarm model](operations.md#trust-and-privacy-model). Possession of a topic invite remains a separate capability.

To withdraw this specific Serve listener, coordinate with other users of that HTTPS listener and then use:

```sh
tailscale serve --https=443 off
```

Do not reset unrelated Serve routes. Stopping web does not remove the operator-managed Serve route; it will point at an unavailable backend until web returns or the operator removes the route.

### Verify the exposure

1. Check `tailscale serve status`: the route must be tailnet-only Serve, not public Funnel.
2. From an allowed phone, check that the displayed identity matches `meshmsg --json status` for the chosen state directory.
3. Confirm that an unauthorized tailnet device is denied by your tailnet access rules. No app-layer denial can substitute for these rules.
4. Send a unique test message and confirm receipt using `meshmsg listen` on a **different peer**. “Queued locally” is not this receipt check.
5. Hide the phone tab, reopen it, restart the daemon, and verify reconnect/gap warnings. Stop web and verify the daemon still answers CLI status.

Actual Tailscale proxy/header handling and mobile browser behavior must be checked in your deployment. The automated tests simulate the configured HTTPS Host/Origin pair; they do not configure Tailscale or claim a phone-browser end-to-end test.

## UI semantics and recovery

- **Identity/status:** daemon identity, endpoint availability, topic join state, and neighbor count. None proves delivery. The web UI omits local paths and invites.
- **Broadcast:** submits exactly once. A successful response means **queued locally, not delivered or acknowledged**. The UI permits at most 4096 UTF-8 body bytes; the signed envelope overhead can make the daemon's actual accepted body smaller. The daemon remains authoritative.
- **Rejected:** invalid input, a throttle/capacity response, or explicit daemon rejection leaves the draft intact. Correct it and submit manually if appropriate.
- **Outcome unknown:** connection failures, lost/unexpected replies, and timeouts might happen after a send was queued. The draft stays intact. Check with peers before manually resending; duplicates are possible. Neither server nor UI retries a send. Even an offline connect failure is conservatively reported unknown for a send.
- **Live feed:** newest 100 entries in this tab; incoming text, daemon-confirmed local queued sends, read-only attachment information cards, peer changes, and gap notices. Attachment cards show only direction/sender, timestamp, filename, file or directory type, and known size. They do not expose signed offer tokens, blob tickets, local paths/outputs, or controls to share, upload, download, or otherwise mutate attachments. Every connected web tab subscribes independently, so sends from CLI, chat, or another web tab and shares from local CLI/processes appear in all currently connected live feeds with the daemon's canonical sender and timestamp. The sending tab does not add an optimistic copy: the canonical entry is the same daemon event every tab receives. If that event falls in a disconnect/lag gap, it is not reconstructed from the HTTP reply. The feed has no history, replay, delivery receipts, or attachment operations. Untrusted names, senders, and messages containing markup are displayed literally, without links or HTML interpretation.
- **Sleep/reconnect:** hiding the tab closes its feed; returning reconnects it. Disconnects retry with 1–15 second backoff plus jitter. Status is checked every 15 seconds while visible. Reconnects (including the server's periodic stream rollover), lag, sleep, or a slow reader can lose messages; warnings remain visible. No SSE event IDs or replay cursor are provided.
- **Draft lifetime:** drafts/feed are memory-only in the current tab, not saved in local storage or to disk. Failed submissions and in-flight edits are preserved while the page remains open; refresh, closing the tab, or OS tab eviction can lose them.

## HTTP surface and limits

Only these routes exist:

| Route | Purpose |
| --- | --- |
| `GET /`, `/app.css`, `/app.js` | Embedded UI assets |
| `POST /api/request` | Exactly `{"command":"status"}` or `{"command":"send","body":"text"}`; unknown commands/fields rejected |
| `GET /api/events` | One local IPC `subscribe` connection streamed as SSE, including incoming messages, local queued sends, and safe read-only incoming/shared attachment metadata |

No filesystem, share/upload/download/offers, attachment mutation, benchmark, stop, invite, or topic command or endpoint is exposed. Attachment SSE records are rebuilt from an explicit metadata allowlist; signed offer tokens, blob tickets, offer IDs, local paths/outputs, and other daemon fields are omitted. A write requires `Content-Type: application/json` (without encoding) and an exact same-origin `Origin` matching an allowed `Host`. GETs require an allowed Host and, when present, a matching Origin. Cross-site browser fetches are rejected. There is no permissive CORS/preflight support. Duplicate Host/Origin values fail closed. `Forwarded`, `X-Forwarded-*`, and Tailscale identity headers are **not** trusted or used for authorization. The reverse proxy must preserve the configured Host. A 403 behind Serve indicates an origin/Host mismatch: fix the explicit configuration, not the protections.

Responses use `Cache-Control: no-store`, `nosniff`, no-referrer, frame denial and a CSP forbidding inline scripts, third-party resources, forms, and framing. Assets are same-origin. Untrusted feed values only reach `textContent`.

Per web process:

- 64 simultaneous HTTP connections; excess sockets close immediately. HTTP/1 connections are not reused.
- 16 in-flight IPC request/reply operations and 16 live feeds; excess operations return 503.
- One send attempt per second globally across all clients, no burst; excess returns 429. CLI sends are unaffected. This is load control, not protection from a malicious authorized client.
- 32 HTTP headers, 16 KiB header buffer; 25,600-byte JSON body/frame bounds and a nonblank, 4096-byte UTF-8 send body bound.
- 5-second header/body-read timeouts; 8-second IPC request/subscribe-handshake timeout; UI submit timeout 12 seconds. Client disconnect/timeout does not cancel an already-queued daemon action.
- 32 buffered events per live feed; 10-second SSE comments; 5-second event-channel backpressure timeout; maximum HTTP connection lifetime 5 minutes. A slow reader is disconnected rather than retaining unbounded history.

Resource limits can cause feed gaps. A hostile authorized/local client can still deny service; this MVP is for a small trusted tailnet. Run only the web instances you need, as limits are per process.

## Tests and validation limits

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo build --locked
node --check src/web/app.js
node tests/web-ui.cjs
python3 tests/integration-web.py target/debug/meshmsg
python3 tests/integration-web-peer.py target/debug/meshmsg
```

The fake-daemon HTTP harness uses Unix sockets (Linux/macOS). It checks allowlists, Host/Origin, asset security headers, simultaneous-feed synchronization for web and local CLI sends plus safe incoming/outgoing attachment metadata, capability/path filtering, SSE framing/capacity/cleanup, request bounds/timeouts, queued/rejected/ambiguous outcomes, no send retry, offline/restart, and independent shutdown. The real-peer harness creates temporary isolated states, starts two actual daemons, checks canonical queued and real attachment events in two web feeds plus web-to-peer and peer-to-both-feeds receipt, and cleans up. It requires working Iroh networking and does not change Tailscale configuration.

The Node test uses a small DOM mock to exercise UI behavior, not a real browser. Windows named-pipe ownership checks remain shared with the CLI, but Windows execution, mobile layout/accessibility, actual browser CSP enforcement, real phone sleep, and real Tailscale Serve access/header behavior require platform/manual validation. The two-peer test is not a WAN reliability or load benchmark.
