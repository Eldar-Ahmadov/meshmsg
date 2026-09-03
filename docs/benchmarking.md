# Benchmarking

Benchmark commands use the existing daemon and topic. Benchmark bodies are ordinary signed plaintext messages: every participant can read them, and they consume the same network and subscriber resources as chat. Prefer an isolated topic.

## Running a three-node test

Choose one 128-bit hexadecimal run ID. Start receivers on nodes B and C before the sender on node A:

```sh
# Nodes B and C
meshmsg --json bench-receive \
  --run-id 0123456789abcdef0123456789abcdef \
  --duration-secs 15 --expected 1000 | tee bench-receive.ndjson

# Node A
meshmsg --json bench-send \
  --run-id 0123456789abcdef0123456789abcdef \
  --rate 100 --duration-secs 10 --payload-bytes 512 > bench-send.ndjson
```

Run each rate several times and increase gradually, for example 10, 25, 50, 100, 200, and 500 messages/s. Compare the sender summary with both receiver summaries. Reverse the sender and test simultaneous senders when that matches the intended workload. Only one send benchmark may run on a daemon at a time.

## Sender semantics

`bench-send` defaults to 100 messages/s for 10 seconds with 256-byte bodies and generates a random run ID when omitted. Supply an explicit ID for coordinated receivers.

Limits:

- rate: 1–10,000 messages/s;
- duration: 1–86,400 seconds;
- planned messages: at most 10,000,000;
- payload: exact complete body size, including the 106-byte benchmark header and bounded by the signed envelope.

The sender keeps one IPC connection open and schedules from a monotonic clock without catch-up bursts. Its summary includes planned, attempted, locally queued, failed, schedule-missed, body/envelope bytes, and achieved rates. `delivery_acknowledged` is always false. Schedule misses indicate local sender or daemon saturation, not network loss.

Completion reasons are `deadline`, `interrupted`, `daemon_stopped`, and `send_failed`.

## Receiver semantics

`bench-receive` keeps one subscription open, filters by run ID, and bounds sequence tracking to a 10,000,000-message bitmap. It reports unique, missing, duplicate, and first-seen out-of-order messages, throughput, and bounded latency percentiles.

Latency is a one-way signed-message wall-clock observation. Clocks are not synchronized, so negative or implausible values are excluded and counted as `clock_invalid`. It is not RTT or network-only latency.

Both local IPC lag and Gossip receiver lag appear in the summary. If `lag.incomplete` is true, sequence gaps cannot be attributed solely to the network. Payload bytes are not wire bytes: topology, framing, signatures, retransmission, and fan-out add overhead.

Receiver completion reasons are `deadline`, `interrupted`, and `daemon_stopped`. Without a valid matching message or `--expected`, expected, missing, and highest sequence are null. `complete` means all expected sequences were seen; `measurement_valid` additionally requires no local/Gossip lag and no malformed matching messages.

## Representative output

```json
{"type":"bench_send_started","schema_version":1,"run_id":"0123456789abcdef0123456789abcdef","rate":100,"duration_secs":10,"payload_bytes":512,"planned":1000,"delivery_acknowledged":false}
{"type":"bench_send_summary","schema_version":1,"run_id":"0123456789abcdef0123456789abcdef","planned":1000,"attempted":1000,"queued":1000,"failed":0,"schedule_missed":0,"completion_reason":"deadline","delivery_acknowledged":false}
{"type":"bench_receive_started","schema_version":1,"run_id":"0123456789abcdef0123456789abcdef","duration_secs":15,"expected":1000}
{"type":"bench_receive_summary","schema_version":1,"run_id":"0123456789abcdef0123456789abcdef","completion_reason":"deadline","expected":1000,"complete":true,"measurement_valid":true,"unique":1000,"missing":0,"duplicates":0,"out_of_order":0}
```

Ctrl-C emits an interrupted summary. A daemon disconnect emits a partial summary and exits nonzero.
