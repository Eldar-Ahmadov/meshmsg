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

The web process may start while the daemon is offline. Status and the feed recover when that daemon starts or restarts. Concurrent/restarted web processes use separate owner-only temporary roots, though normally only one instance is useful. Ctrl-C stops **only web**. `meshmsg stop` separately stops the daemon.

## Phone access through Tailscale Serve — never Funnel

There is **no app authentication, login, token, session, or user separation**. Tailscale membership and tailnet access rules are the remote access boundary. Everyone permitted to reach this service can read the live feed, broadcast, and share browser-selected files as the daemon's identity. Restrict access to the intended trusted people/devices before exposing it. Any local process can also access the loopback bridge; Host/Origin checks are browser defenses, not authentication against such clients.

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

**Never expose this bridge through Tailscale Funnel**, a public reverse proxy, router forwarding, or a LAN listener. Tailscale Serve protects the browser-to-host path; it does not make meshmsg broadcasts private or change the [trust and privacy model](operations.md#trust-and-privacy-model). Possession of a topic invite remains a separate capability.

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

- **Identity/status:** the chat header keeps a compact live-connection and current authenticated-presence summary. Its accessible cog link opens the read-only `/settings` status page, which shows daemon availability, endpoint availability, topic join state, neighbor count, and daemon identity with a manual refresh control. None proves delivery. The web UI omits local paths, invites, capabilities, and operational controls.
- **Broadcast:** first negotiates `idempotent_mutations_v1` and fails closed before submission if the daemon does not advertise it, then submits once per user action. The tab generates an operation ID and retains it with an unchanged draft after an unknown response; manually submitting that same draft again reuses the ID so the current daemon can return its cached outcome without another broadcast. A successful response means **queued locally; delivery is unconfirmed and not acknowledged**. The UI permits at most 4096 UTF-8 body bytes; the signed envelope overhead can make the daemon's actual accepted body smaller. The daemon remains authoritative.
- **Share attachment:** uploads one browser-selected regular file and submits it through the daemon's existing attachment protocol. The tab similarly retains and reuses its operation ID with the same selected `File` after an unknown response. Filenames must satisfy the same portable component rules as CLI shares, and the streamed body is bounded by the daemon's configured attachment limit. A successful response means the offer was shared locally, not delivered. The canonical outgoing card comes from the daemon event, so the sending tab does not create an optimistic duplicate. Files are topic-wide plaintext capabilities, not private-message attachments. Browser directory selection is not supported.
- **Rejected:** invalid input, a throttle/capacity response, or explicit daemon rejection leaves the draft or file selection intact. Correct it and submit manually if appropriate. Versioned daemon mutation errors are strictly decoded and forwarded without rewriting `code`, `outcome`, `retryable`, or `operation_id`; malformed or mismatched daemon replies become an explicit local `invalid_daemon_response` with `outcome:unknown`.
- **Outcome unknown:** connection failures, lost/unexpected replies, and timeouts might happen after a message was queued or an attachment offer was published. The draft/file selection and operation ID stay intact. The UI never retries automatically; a manual retry with unchanged input reuses the ID and is safe while it remains in the same daemon's 10-minute bounded cache. A daemon restart, expiry, or pressure eviction clears that guarantee and is reported as such by daemon status.
- **Live feed:** newest 100 entries in this tab; incoming text, daemon-confirmed local queued sends, attachment information cards, sanitized peer-directory changes, and gap notices. Incoming broadcast messages and offers use `schema_version:2`; local queued sends and outgoing shares use schema 3 and carry matching `operation_id`/V2 `message_id`; the bridge rejects legacy or malformed versions instead of rewriting them as V2. Each subscription is uninitialized until it receives `connected` and then a valid atomic peer snapshot; only then are discovered/updated/expired events applied. An out-of-order lifecycle event, invalid/missing startup snapshot, disconnect, lag, or hidden tab immediately invalidates the current-peer summary and reconnects rather than comparing against an old directory. Identical presence refreshes do not create feed entries. Callbacks and timers from superseded subscriptions, and status replies started before a disconnect or visibility-generation change, are ignored. Incoming attachment cards include an explicit browser Download control when the connected daemon advertises `web_download_v1`; an older running daemon leaves cards informational until it is upgraded/restarted. Files retain their offered name and directory snapshots download as their deterministic `.tar` archive. After preparation, the UI presents a real **Save file** link that requires another user click. Signed offers remain only in bounded, short-lived server memory and are represented in SSE/API by opaque retryable IDs—raw offer tokens, blob tickets, and server paths never enter the DOM. Outgoing cards remain informational. Every connected web tab subscribes independently, so sends from CLI, chat, or another web tab and shares from local CLI/processes appear in all currently connected live feeds with the daemon's canonical sender and timestamp. The sending tab does not add an optimistic copy: the canonical entry is the same daemon event every tab receives. If that event falls in a disconnect/lag gap, it is not reconstructed from the HTTP reply. The feed has no history, replay, or delivery receipts. Untrusted names, senders, and messages containing markup are displayed literally, without links or HTML interpretation.
- **Sleep/reconnect:** hiding the tab closes its feed; returning reconnects it. A subscription has 8 seconds to produce its ordered startup snapshot. Failed subscriptions retry with exponential delay starting at 1 second, adding up to 0.5 second jitter while capping the total at 15 seconds; the delay resets only after an authoritative snapshot. Status is checked every 15 seconds while visible. Reconnects (including the server's periodic stream rollover), lag, sleep, or a slow reader can lose messages; warnings remain visible. No SSE event IDs or replay cursor are provided.
- **Draft lifetime:** drafts/feed are memory-only in the current tab, not saved in local storage or to disk. Failed submissions and in-flight edits are preserved while the page remains open; refresh, closing the tab, or OS tab eviction can lose them.

## HTTP surface and limits

Only these routes exist:

| Route | Purpose |
| --- | --- |
| `GET /`, `/settings`, `/app.css`, `/app.js`, `/settings.js` | Embedded chat/status UI and assets |
| `POST /api/request` | Status, peers, send, or start/poll a download using a server-issued opaque ID; unknown commands/fields rejected |
| `POST /api/attachment` | Stream one file as unencoded `application/octet-stream`; its percent-encoded portable filename is supplied in `X-Meshmsg-File-Name` and its retry ID in `X-Meshmsg-Operation-Id` |
| `GET /api/events` | One local IPC `subscribe` connection streamed as SSE, including incoming messages, local queued sends, safe attachment metadata and opaque incoming-download IDs, an initial peer snapshot, and peer lifecycle events |
| `GET /api/download/<id>` | Stream or resume a ready download during its sliding 65-minute ready TTL |

No private/direct messaging, alias mutation, browser-selected server filesystem path, directory upload, offers listing, benchmark, stop, invite, or topic command or endpoint is exposed. Private-message events are not included in the SSE feed. Peer snapshots and lifecycle events are rebuilt recursively from an explicit allowlist: only canonical public keys, normalized aliases, online state, and bounded local freshness timestamps survive. Endpoint/address/relay/socket data and raw signed presence records never reach HTTP or SSE. Attachment SSE records are rebuilt from an explicit metadata allowlist; signed offer tokens, blob tickets, offer IDs, local paths/outputs, and other daemon fields are omitted. The web process stores at most 128 live offers for ten minutes and 128 jobs, runs at most two downloads and two uploads concurrently, chooses owner-only temporary paths itself, streams downloads with `Content-Disposition: attachment` and `Cache-Control: no-store`, and keeps a ready file for 65 minutes after readiness or its latest retrieval so an interrupted request can be retried or resumed with a single HTTP byte range. Failed jobs expire after ten minutes. Only an exact `download_complete` schema-version-1 daemon response can publish a ready file. Background download IPC is hard-limited to 70 minutes so a stalled daemon cannot retain a transfer permit forever; pending jobs expire after 71 minutes, and the UI polls to the `poll_timeout_ms` deadline returned by the server. Ready jobs use the separate sliding 65-minute bound. A 30-second cleanup pass enforces these TTLs, and pruning removes a late result rather than resurrecting an expired job. Each web process uses a fresh random owner-only subdirectory under `web-downloads-v2`; it never removes another process's recent root. This prevents a restart from racing a daemon export that outlived its IPC connection. A small owner-only lease file is refreshed when preparation starts, when a job becomes ready, and whenever its file is retrieved. On startup, roots with leases untouched for three hours—strictly longer than the combined 71-minute pending and 65-minute ready lifetimes—are removed as stale. Empty current roots can therefore remain until a later startup. Prepared files are opened without following links/reparse points and their size is taken from the opened handle. These defenses are practical hardening rather than isolation from another process running as the same OS user, which can already access the state directory and daemon IPC endpoint. A write requires an exact same-origin `Origin` matching an allowed `Host`; JSON requests require unencoded `application/json`; sends require a lowercase 32-hex `operation_id` and negotiate `idempotent_mutations_v1` before sending the mutation. The attachment route requires unencoded `application/octet-stream`, a validated encoded filename header, and a lowercase 32-hex `X-Meshmsg-Operation-Id` header. GETs require an allowed Host and, when present, a matching Origin. Cross-site browser fetches are rejected. There is no permissive CORS/preflight support. Duplicate Host/Origin values fail closed. `Forwarded`, `X-Forwarded-*`, and Tailscale identity headers are **not** trusted or used for authorization. The reverse proxy must preserve the configured Host. A 403 behind Serve indicates an origin/Host mismatch: fix the explicit configuration, not the protections.

Responses use `Cache-Control: no-store`, `nosniff`, no-referrer, frame denial and a CSP forbidding inline scripts, third-party resources, forms, and framing. Assets are same-origin. Untrusted feed values only reach `textContent`.

Per web process:

- 64 simultaneous HTTP connections; excess sockets close immediately. HTTP/1 connections are not reused.
- 16 in-flight ordinary IPC request/reply operations, 16 live feeds, two concurrent attachment downloads, two concurrent uploads, and bounded short-lived offer/job registries; excess operations return 503. The bridge also serializes each upload operation ID and retains up to 1,024 name/size/domain-separated-SHA-256 input fingerprints for a full 10 minutes after completion or the latest retry; long upload/share time is not charged against that window. It propagates the digest into the daemon's operation fingerprint and rejects same-ID changed-file retries, including equal-size changes. Uploads are streamed to fresh owner-only paths under `web-uploads-v1`, bounded by the daemon's advertised configured limit, and submitted only when both `web_share_v1` and `idempotent_mutations_v1` are advertised. Definite completion/rejection removes staging immediately. A lost reply or timeout leaves its isolated path for a three-hour race-safety window so a daemon that may still be reading it is not raced; the 30-second maintenance pass and later startups remove it after that window.
- One new send operation ID per second globally across all clients, no burst; same-ID retries bypass this throttle and excess new IDs return 429. CLI sends are unaffected. This is load control, not protection from a malicious authorized client.
- 32 HTTP headers, 16 KiB header buffer; 25,600-byte JSON body/frame bounds and a nonblank, 4096-byte UTF-8 send body bound.
- 5-second ordinary JSON body-read timeout; 8-second IPC request/subscribe-handshake timeout; UI message submit timeout 12 seconds. Attachment upload/share operations are hard-limited to 70 minutes, and HTTP connections to 75 minutes. Client disconnect/timeout does not cancel an already-submitted daemon action.
- 32 buffered events per live feed; 10-second SSE comments; 5-second event-channel backpressure timeout; maximum HTTP connection lifetime 75 minutes; ready downloads advertise byte ranges, so a larger/slower interrupted transfer can resume during the ready-file TTL. A slow SSE reader is still disconnected by event-channel backpressure rather than retaining unbounded history.

A successful browser preparation uses the daemon's normal verified download path and creates the same persistent `meshmsg/in/v1/...` blob pin as a CLI download. The HTTP temporary file expires, but the blob pin survives daemon restarts and currently has no removal command; account for that storage retention.

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

The fake-daemon HTTP harness uses Unix sockets (Linux/macOS). It checks allowlists, Host/Origin, asset security headers, simultaneous-feed synchronization, bounded attachment uploads, negotiated opaque attachment downloads, retry after a rejected start or interrupted response, safe response headers, unique-root restart/orphan behavior, capability/path filtering, SSE framing/capacity/cleanup, request bounds/timeouts, queued/rejected/ambiguous outcomes, no send retry, offline/restart, and independent shutdown. The real-peer harness creates temporary isolated states, starts two actual daemons, checks a browser upload and canonical queued/share events plus verified browser downloads of a real file and deterministic directory tar, and cleans up. It requires working Iroh networking and does not change Tailscale configuration.

The Node test uses a small DOM mock to exercise UI behavior, not a real browser. Windows named-pipe ownership checks remain shared with the CLI, but Windows execution, mobile layout/accessibility, actual browser CSP enforcement, real phone sleep, and real Tailscale Serve access/header behavior require platform/manual validation. The two-peer test is not a WAN reliability or load benchmark.
