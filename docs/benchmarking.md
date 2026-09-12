# Benchmarking

`meshmsg-bench` is an optional protocol client. It does not add a benchmark command, handler, event, capability, or error to the daemon. Every generated message is submitted with the ordinary canonical `send` or `private_send` request, and receivers consume the ordinary `subscribe` feed. This measures the same local IPC and messaging path used by normal clients.

Build the non-interactive client explicitly:

```sh
cargo build --features bench --bin meshmsg-bench
```

The `bench` feature contains no Ratatui/Crossterm dependency. The interactive dashboard is a separate binary behind the additive `bench-tui` feature:

```sh
cargo build --features bench-tui --bin meshmsg-bench-tui
meshmsg-bench-tui --state-dir /path/to/node-state
```

The default `meshmsg` build compiles neither benchmark client. `full` enables `web` and `bench-tui` (which in turn enables `bench`).

## Running a coordinated test

Choose one lowercase 128-bit hexadecimal run ID. Start receivers before the sender:

```sh
# Receiver nodes
meshmsg-bench --json receive \
  --run-id 0123456789abcdef0123456789abcdef \
  --duration-secs 15 --expected 1000 | tee bench-receive.ndjson

# Sender node
meshmsg-bench --json send \
  --run-id 0123456789abcdef0123456789abcdef \
  --rate 100 --duration-secs 10 --payload-bytes 512 > bench-send.ndjson
```

Use `send --to <recipient>` to benchmark ordinary private sends. Broadcast benchmark bodies are readable by topic participants, so prefer an isolated topic.

Use `meshmsg-bench-tui` for an interactive sender/receiver setup and live dashboard. `meshmsg-bench` intentionally accepts only `send` and `receive`; this keeps automation and benchmark integrations independent of terminal UI libraries.

## Semantics and limits

The sender defaults to 100 messages/s for 10 seconds with 256-byte bodies. Limits are 1–10,000 messages/s, 1–86,400 seconds, and 10,000,000 planned messages. The payload includes a versioned run ID, sequence, total, sender timestamp, and padding.

Each attempted message gets a fresh operation ID and an ordinary request. `queued` counts successful ordinary responses (`queued` for broadcast or `private_accepted` for private sends), not remote delivery. `failed` stops the run at the first failed request. `schedule_missed` counts monotonic-clock slots skipped while ordinary requests are still in flight. Body-byte rates exclude signatures, protocol framing, retransmission, and fan-out.

A receiver keeps one ordinary subscription open, filters `message` and `private_message` events by run ID, and tracks unique, missing, duplicate, and first-seen out-of-order sequences in a bounded bitmap. Latency is a one-way wall-clock observation; unsynchronized or implausible values are counted as clock-invalid. Local or Gossip lag makes loss attribution incomplete.

JSON output is benchmark-tool NDJSON, not daemon IPC. It contains `bench_send_started`, best-effort `bench_send_progress`, `bench_send_summary`, and corresponding receive records, all at tool schema version 1. Ctrl-C emits an interrupted summary. These records are intentionally absent from `meshmsg-protocol`.
