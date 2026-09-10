# Benchmarking

Benchmark commands use the existing daemon and topic. Benchmark bodies are ordinary signed plaintext messages: every participant can read them, and they consume the same network and subscriber resources as chat. Prefer an isolated topic.

For an interactive setup, live progress, and result screen, run `meshmsg bench-tui` in a terminal. Select sender or receiver, edit the fields, and press Enter. The sender defaults to 100 messages/s for 10 seconds with 256-byte bodies and a generated run ID; the receiver defaults to a 15-second window and permits an optional expected count. `q`, Escape, or Ctrl-C stops an active run while retaining its final summary. `--json` is intentionally incompatible with `bench-tui`; use the commands below for automation.

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

- scheduler rate: 1–10,000 messages/s; broadcast receivers admit at most the documented 100 messages/s sustained per sender (200 burst) and 1,000 messages/s globally (2,000 burst), so higher settings are intentional overload/rate-limit tests rather than supported loss measurements;
- duration: 1–86,400 seconds;
- planned messages: at most 10,000,000;
- payload: exact complete body size, including the 106-byte benchmark header and bounded by the signed envelope.

The sender keeps one IPC connection open and schedules from a monotonic clock without catch-up bursts. Send records use schema version 2. `attempted` means a submission was started, and every attempt has exactly one terminal local classification: `attempted = queued + failed + incomplete`. `queued` means the daemon's Gossip sender accepted the complete signed envelope; `failed` means it definitively rejected the submission; `incomplete` (at most one because submissions are serial) means interruption/deadline abandoned the in-flight operation or the daemon reply was lost, so no terminal queued/failed classification was received. `schedule_missed` counts eligible monotonic-clock slots deliberately skipped before submission. At every record, `attempted + schedule_missed` cannot exceed the slots eligible at `elapsed_ms` (allowing only its sub-millisecond truncation interval); accounting-complete terminal records cover every slot eligible by then, and deadline records cover the complete plan. Thus future slots cannot be reported as early misses, and incomplete attempts are not mislabeled as failures or silently omitted.

`queued_body_bytes` is exactly `queued * payload_bytes`. `queued_envelope_bytes` is the sum of the complete encoded application envelopes accepted by the local Gossip sender; it is larger than body bytes and excludes Iroh/network framing, fan-out, and retransmission. Achieved rates derive from queued counts/bytes and elapsed milliseconds. `delivery_acknowledged` is always false. Schedule misses indicate local sender or daemon saturation, not network loss.

JSON mode may emit bounded-cadence `bench_send_progress` records between the started record and terminal summary. These schema-version-2 records snapshot the same attempted, queued, failed, incomplete, schedule-missed, byte, elapsed, and achieved-rate counters. Progress has no unresolved attempt; incomplete is terminal-summary information. Records are local queue and scheduler observations, not delivery acknowledgements. Progress is best-effort and stale snapshots may be dropped when the output consumer is blocked; started and final records are retained.

Completion reasons are `deadline`, `interrupted`, `daemon_stopped`, and `send_failed`. A client accepts `interrupted` only after that same client has sent the cancellation byte; unsolicited daemon claims of interruption fail closed. Deadline and requested interruption preserve those reasons even when the one in-flight attempt is incomplete. `daemon_stopped` means command admission or its reply channel was lost. `send_failed` stops at the first definitive failure and carries only the fixed public error text.

After a started record, disconnects, malformed records, and daemon terminal errors still produce one correlated partial summary from the latest validated snapshot. Daemon-produced terminal summaries must set `accounting_complete:true`; `false` is reserved for a client-synthesized snapshot, which does not invent attempts or missed slots after its last validated record. Every following daemon error must contain exactly the active benchmark request ID, including codes that may omit correlation before admission; missing or mismatched correlation is invalid after start. Disconnects and invalid responses use a correlated `outcome:partial`; a valid strict daemon error with matching correlation and `outcome:partial` or `outcome:unknown` is preserved unchanged. A post-start `outcome:not_started` claim is temporally impossible and is normalized to `invalid_daemon_response`/`partial`. A valid `send_failed` summary is followed by the stable `send_failed`/`partial` error in CLI JSON mode. Numeric validation checks configured ranges before scheduler division, rejects overflowing counts/bytes/times and oversized sample counts, and never treats malformed machine-boundary values as trusted arithmetic inputs.

## Receiver semantics

`bench-receive` keeps one subscription open, filters by run ID, and bounds sequence tracking to a 10,000,000-message bitmap. It reports unique, missing, duplicate, and first-seen out-of-order messages, throughput, and bounded latency percentiles.

Latency is a one-way signed-message wall-clock observation. Clocks are not synchronized, so negative or implausible values are excluded and counted as `clock_invalid`. It is not RTT or network-only latency.

Both local IPC lag and Gossip receiver lag appear in the summary. Each local lag event contributes a positive dropped count, so the aggregate dropped count cannot be below the event count. If `lag.incomplete` is true, sequence gaps cannot be attributed solely to the network. Payload bytes are not wire bytes: topology, framing, signatures, retransmission, and fan-out add overhead.

Receiver completion reasons are `deadline`, `interrupted`, and `daemon_stopped`. Without a valid matching message or `--expected`, expected, missing, and highest sequence are null. With unique messages, highest sequence is present and compatible with the distinct count; duplicates cannot precede the first unique message, and at most `unique - 1` first-seen messages can be out of order. Latency observations plus clock-invalid observations equal the unique count. Positive latency observations retain samples and complete ordered percentiles; sample caps are checked before percentile-rank arithmetic, and ranks that select the same small-sample observation must have equal values. Missing-sequence samples are strictly ordered and contain the first `min(missing, 100)` absent sequences. An untruncated sample is the exact complement of the reported unique/highest state. For a truncated sample, every unlisted sequence through the sample tail is necessarily observed; its inferred cardinality and greatest sequence must remain feasible with `unique` and `highest_sequence`, while unconstrained later observations remain permitted. `complete` means all expected sequences were seen; `measurement_valid` additionally requires no local/Gossip lag and no malformed matching messages.

JSON mode emits best-effort `bench_receive_progress` snapshots at most four times per second. These `schema_version: 1` records include unique, missing-so-far (null while expected is unknown), duplicates, out-of-order, throughput, bounded latency percentiles, malformed counts, and lag/clock indicators. A lagged measurement is labeled incomplete: observed gaps must not be described as network loss when local IPC or Gossip lag prevents attribution. Started and final summary schemas retain their existing meanings.

## Representative output

```json
{"type":"bench_send_started","schema_version":2,"run_id":"0123456789abcdef0123456789abcdef","rate":100,"duration_secs":10,"payload_bytes":512,"planned":1000,"delivery_acknowledged":false}
{"type":"bench_send_summary","schema_version":2,"run_id":"0123456789abcdef0123456789abcdef","planned":1000,"attempted":1000,"queued":1000,"failed":0,"incomplete":0,"schedule_missed":0,"accounting_complete":true,"completion_reason":"deadline","delivery_acknowledged":false}
{"type":"bench_receive_started","schema_version":1,"run_id":"0123456789abcdef0123456789abcdef","duration_secs":15,"expected":1000}
{"type":"bench_receive_summary","schema_version":1,"run_id":"0123456789abcdef0123456789abcdef","completion_reason":"deadline","expected":1000,"complete":true,"measurement_valid":true,"unique":1000,"missing":0,"duplicates":0,"out_of_order":0}
```

Ctrl-C emits an interrupted summary. A daemon disconnect emits a partial summary and exits nonzero.
