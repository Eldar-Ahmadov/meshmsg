use crate::{contracts, ipc};
use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use serde_json::Value;
use std::{
    path::PathBuf,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{mpsc, oneshot};

const BENCH_MAGIC: &str = "meshmsg-bench-v2";
const MAX_BENCH_MESSAGES: u64 = 10_000_000;
const MAX_LATENCY_SAMPLES: usize = 1_000_000;
const MAX_PROGRESS_LATENCY_SAMPLES: usize = 4_096;
const MAX_MISSING_SEQUENCE_SAMPLE: usize = 100;
const MAX_LATENCY_MS: u64 = 24 * 60 * 60 * 1000;

#[derive(Parser, Debug)]
#[command(
    name = "meshmsg-bench",
    version,
    about = "Benchmark meshmsg through its ordinary local protocol"
)]
struct Cli {
    /// State directory (defaults to $XDG_DATA_HOME/meshmsg)
    #[arg(long, global = true, env = "MESHMSG_STATE_DIR")]
    state_dir: Option<PathBuf>,
    /// Emit benchmark progress and summaries as NDJSON
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Issue ordinary canonical Send or PrivateSend requests at a sustained rate
    Send(SendArgs),
    /// Consume the ordinary subscription feed and measure one run
    Receive(ReceiveArgs),
}

#[derive(Args, Debug)]
struct SendArgs {
    /// 128-bit hexadecimal run identifier (generated when omitted)
    #[arg(long, value_parser = parse_run_id)]
    run_id: Option<String>,
    /// Send privately to one canonical public key or uniquely advertised alias
    #[arg(long, value_name = "RECIPIENT")]
    to: Option<String>,
    /// Sustained messages per second
    #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(u32).range(1..=10_000))]
    rate: u32,
    /// Test duration in seconds
    #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u64).range(1..=86_400))]
    duration_secs: u64,
    /// Exact benchmark body size in bytes
    #[arg(long, default_value_t = 256)]
    payload_bytes: usize,
}

#[derive(Args, Debug)]
struct ReceiveArgs {
    /// 128-bit hexadecimal run identifier emitted by send
    #[arg(long, value_parser = parse_run_id)]
    run_id: String,
    /// Observation duration in seconds
    #[arg(long, default_value_t = 15, value_parser = clap::value_parser!(u64).range(1..=86_400))]
    duration_secs: u64,
    /// Expected sequence count; otherwise learned from the first valid message
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..=10_000_000))]
    expected: Option<u64>,
}

fn parse_run_id(value: &str) -> std::result::Result<String, String> {
    if value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("run ID must contain exactly 32 hexadecimal characters".into());
    }
    Ok(value.to_ascii_lowercase())
}

fn state_dir(value: Option<PathBuf>) -> PathBuf {
    value.unwrap_or_else(|| {
        dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("meshmsg")
    })
}

pub async fn entry(arguments: Vec<std::ffi::OsString>) -> std::process::ExitCode {
    let cli = match Cli::try_parse_from(arguments) {
        Ok(cli) => cli,
        Err(error)
            if matches!(
                error.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) =>
        {
            print!("{error}");
            return std::process::ExitCode::SUCCESS;
        }
        Err(error) => {
            eprintln!("error: {error}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let dir = state_dir(cli.state_dir);
    let result = match cli.command {
        Command::Send(args) => {
            send(
                &dir,
                args.run_id,
                args.to,
                args.rate,
                args.duration_secs,
                args.payload_bytes,
                cli.json,
            )
            .await
        }
        Command::Receive(args) => {
            receive(
                &dir,
                args.run_id,
                args.duration_secs,
                args.expected,
                cli.json,
            )
            .await
        }
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn generated_run_id() -> String {
    ipc::new_operation_id()
}

fn valid_run_id(value: &str) -> bool {
    contracts::valid_operation_id(value)
}

#[derive(Debug, PartialEq)]
struct BenchFrame<'a> {
    run_id: &'a str,
    sequence: u64,
    total: u64,
    timestamp_ms: u64,
}

fn unix_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| u64::try_from(value.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn build_body(
    run_id: &str,
    sequence: u64,
    total: u64,
    timestamp_ms: u64,
    payload_bytes: usize,
) -> Result<String> {
    anyhow::ensure!(valid_run_id(run_id), "invalid benchmark run ID");
    anyhow::ensure!(
        total > 0 && total <= MAX_BENCH_MESSAGES && sequence < total,
        "invalid benchmark sequence"
    );
    let mut body = format!("{BENCH_MAGIC}|{run_id}|{sequence:020}|{total:020}|{timestamp_ms:013}|");
    anyhow::ensure!(
        payload_bytes >= body.len(),
        "payload size must be at least {} bytes",
        body.len()
    );
    body.extend(std::iter::repeat_n('x', payload_bytes - body.len()));
    Ok(body)
}

fn parse_body(body: &str) -> Result<Option<BenchFrame<'_>>> {
    if !body.starts_with("meshmsg-bench") {
        return Ok(None);
    }
    let mut fields = body.splitn(6, '|');
    anyhow::ensure!(
        fields.next() == Some(BENCH_MAGIC),
        "invalid benchmark framing"
    );
    let run_id = fields.next().context("invalid benchmark framing")?;
    let sequence_text = fields.next().context("invalid benchmark framing")?;
    let total_text = fields.next().context("invalid benchmark framing")?;
    let timestamp_text = fields.next().context("invalid benchmark framing")?;
    let padding = fields.next().context("invalid benchmark framing")?;
    anyhow::ensure!(
        valid_run_id(run_id) && padding.bytes().all(|byte| byte == b'x'),
        "invalid benchmark framing"
    );
    for (value, width) in [(sequence_text, 20), (total_text, 20), (timestamp_text, 13)] {
        anyhow::ensure!(
            value.len() == width && value.bytes().all(|byte| byte.is_ascii_digit()),
            "invalid benchmark framing"
        );
    }
    let sequence = sequence_text.parse()?;
    let total = total_text.parse()?;
    let timestamp_ms = timestamp_text.parse()?;
    anyhow::ensure!(
        total > 0 && total <= MAX_BENCH_MESSAGES && sequence < total,
        "invalid benchmark sequence"
    );
    Ok(Some(BenchFrame {
        run_id,
        sequence,
        total,
        timestamp_ms,
    }))
}

pub(crate) fn validate_sender_config(
    run_id: &str,
    rate: u32,
    duration_secs: u64,
    payload_bytes: usize,
    private: bool,
) -> Result<u64> {
    anyhow::ensure!(valid_run_id(run_id), "invalid benchmark run ID");
    anyhow::ensure!(
        (1..=10_000).contains(&rate),
        "rate must be between 1 and 10000 messages per second"
    );
    anyhow::ensure!(
        (1..=86_400).contains(&duration_secs),
        "duration must be between 1 and 86400 seconds"
    );
    let total = u64::from(rate)
        .checked_mul(duration_secs)
        .context("benchmark message count overflow")?;
    anyhow::ensure!(
        total <= MAX_BENCH_MESSAGES,
        "benchmark plans {total} messages; maximum is {MAX_BENCH_MESSAGES}"
    );
    let maximum = if private {
        crate::message::MAX_PRIVATE_BODY_BYTES
    } else {
        crate::message::MAX_BROADCAST_BODY_BYTES
    };
    anyhow::ensure!(
        payload_bytes <= maximum,
        "payload size cannot exceed {maximum} bytes"
    );
    build_body(run_id, total - 1, total, 9_999_999_999_999, payload_bytes)?;
    Ok(total)
}

#[derive(Default)]
struct SendStats {
    attempted: u64,
    queued: u64,
    failed: u64,
    schedule_missed: u64,
    body_bytes: u64,
    first_error: Option<String>,
}

fn eligible_slots(elapsed: Duration, period: Duration, planned: u64) -> u64 {
    let Some(slots) = elapsed.as_nanos().checked_div(period.as_nanos()) else {
        return 0;
    };
    u64::try_from(slots)
        .unwrap_or(u64::MAX)
        .saturating_add(1)
        .min(planned)
}

fn finish_schedule_accounting(
    stats: &mut SendStats,
    elapsed: Duration,
    period: Duration,
    planned: u64,
) {
    let eligible = eligible_slots(elapsed, period, planned);
    let accounted = stats.attempted.saturating_add(stats.schedule_missed);
    stats.schedule_missed = stats
        .schedule_missed
        .saturating_add(eligible.saturating_sub(accounted));
    debug_assert!(stats.attempted.saturating_add(stats.schedule_missed) <= planned);
}

#[allow(clippy::too_many_arguments)]
fn send_value(
    kind: &str,
    run_id: &str,
    rate: u32,
    duration_secs: u64,
    payload_bytes: usize,
    total: u64,
    stats: &SendStats,
    elapsed: Duration,
) -> Value {
    let elapsed_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
    let seconds = elapsed_ms.max(1) as f64 / 1000.0;
    serde_json::json!({"type":kind,"schema_version":1,"run_id":run_id,"rate":rate,"duration_secs":duration_secs,"payload_bytes":payload_bytes,"planned":total,"attempted":stats.attempted,"queued":stats.queued,"failed":stats.failed,"schedule_missed":stats.schedule_missed,"queued_body_bytes":stats.body_bytes,"elapsed_ms":elapsed_ms,"achieved_messages_per_second":stats.queued as f64 / seconds,"achieved_body_bytes_per_second":stats.body_bytes as f64 / seconds,"delivery_acknowledged":false})
}

fn print_value(json: bool, value: &Value) {
    if json {
        println!("{value}");
        return;
    }
    match value["type"].as_str() {
        Some("bench_send_started") => println!("benchmark send started\nrun id: {}\nplanned messages: {}", value["run_id"].as_str().unwrap_or(""), value["planned"].as_u64().unwrap_or(0)),
        Some("bench_send_summary") => println!("benchmark send complete ({})\nattempted: {}\nqueued: {}\nfailed: {}\nschedule missed: {}\nachieved: {:.2} messages/s", value["completion_reason"].as_str().unwrap_or("unknown"), value["attempted"].as_u64().unwrap_or(0), value["queued"].as_u64().unwrap_or(0), value["failed"].as_u64().unwrap_or(0), value["schedule_missed"].as_u64().unwrap_or(0), value["achieved_messages_per_second"].as_f64().unwrap_or(0.0)),
        Some("bench_receive_started") => println!("benchmark receive started\nrun id: {}\nobservation window: {}s", value["run_id"].as_str().unwrap_or(""), value["duration_secs"].as_u64().unwrap_or(0)),
        Some("bench_receive_summary") => println!("benchmark receive complete ({})\nunique: {}\nmissing: {}\nduplicates: {}\nout of order: {}\nreceived: {:.2} messages/s", value["completion_reason"].as_str().unwrap_or("unknown"), value["unique"].as_u64().unwrap_or(0), value["missing"].as_u64().map_or_else(|| "unknown".into(), |v| v.to_string()), value["duplicates"].as_u64().unwrap_or(0), value["out_of_order"].as_u64().unwrap_or(0), value["achieved_messages_per_second"].as_f64().unwrap_or(0.0)),
        _ => {}
    }
}

async fn issue_send(dir: &std::path::Path, to: Option<&str>, body: String) -> Result<()> {
    let operation_id = ipc::new_operation_id().parse()?;
    let request = match to {
        Some(recipient) => meshmsg_protocol::Request::PrivateSend {
            operation_id,
            to: recipient.parse()?,
            body: meshmsg_protocol::PrivateBody::new(body)?,
        },
        None => meshmsg_protocol::Request::Send {
            operation_id,
            body: meshmsg_protocol::BroadcastBody::new(body)?,
        },
    };
    let expected = if to.is_some() {
        "private_accepted"
    } else {
        "queued"
    };
    ipc::send_request_checked(dir, &request, expected, Some(3)).await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn send_events(
    dir: &std::path::Path,
    run_id: Option<String>,
    to: Option<String>,
    rate: u32,
    duration_secs: u64,
    payload_bytes: usize,
    events: mpsc::Sender<Value>,
    mut cancel: oneshot::Receiver<()>,
) -> Result<()> {
    let run_id = run_id.unwrap_or_else(generated_run_id);
    let total = validate_sender_config(&run_id, rate, duration_secs, payload_bytes, to.is_some())?;
    events.send(serde_json::json!({"type":"bench_send_started","schema_version":1,"run_id":run_id,"rate":rate,"duration_secs":duration_secs,"payload_bytes":payload_bytes,"planned":total,"private":to.is_some(),"delivery_acknowledged":false})).await.ok();
    let started = Instant::now();
    let period = Duration::from_nanos(1_000_000_000 / u64::from(rate));
    let deadline = started + Duration::from_secs(duration_secs);
    let mut next = 0_u64;
    let mut stats = SendStats::default();
    let mut reason = "deadline";
    let mut next_progress = Duration::from_millis(250);
    while next < total {
        let target = started + period.saturating_mul(u32::try_from(next).unwrap_or(u32::MAX));
        tokio::select! { _ = tokio::time::sleep_until(target.into()) => {}, _ = &mut cancel => { reason = "interrupted"; break; } }
        if Instant::now() >= deadline {
            break;
        }
        let due =
            (started.elapsed().as_nanos() / period.as_nanos()).min(u128::from(total - 1)) as u64;
        if due > next {
            stats.schedule_missed += due - next;
            next = due;
        }
        stats.attempted += 1;
        let body = build_body(&run_id, next, total, unix_timestamp_ms(), payload_bytes)?;
        match issue_send(dir, to.as_deref(), body).await {
            Ok(()) => {
                stats.queued += 1;
                stats.body_bytes += payload_bytes as u64;
            }
            Err(error) => {
                stats.failed += 1;
                stats.first_error = Some(format!("{error:#}"));
                reason = "send_failed";
                break;
            }
        }
        next += 1;
        if started.elapsed() >= next_progress {
            let _ = events.try_send(send_value(
                "bench_send_progress",
                &run_id,
                rate,
                duration_secs,
                payload_bytes,
                total,
                &stats,
                started.elapsed(),
            ));
            next_progress += Duration::from_millis(250);
        }
    }
    if reason == "deadline" && Instant::now() < deadline {
        tokio::select! { _ = tokio::time::sleep_until(deadline.into()) => {}, _ = &mut cancel => reason = "interrupted" }
    }
    let elapsed = started.elapsed();
    finish_schedule_accounting(&mut stats, elapsed, period, total);
    let mut summary = send_value(
        "bench_send_summary",
        &run_id,
        rate,
        duration_secs,
        payload_bytes,
        total,
        &stats,
        elapsed,
    );
    summary["completion_reason"] = reason.into();
    summary["accounting_complete"] = true.into();
    summary["first_error"] = stats.first_error.into();
    events.send(summary).await.ok();
    anyhow::ensure!(reason != "send_failed", "ordinary send request failed");
    Ok(())
}

fn output_worker(json: bool) -> (mpsc::Sender<Value>, tokio::task::JoinHandle<()>) {
    let (tx, mut rx) = mpsc::channel(16);
    let worker = tokio::task::spawn_blocking(move || {
        while let Some(value) = rx.blocking_recv() {
            print_value(json, &value);
        }
    });
    (tx, worker)
}

async fn send(
    dir: &std::path::Path,
    run_id: Option<String>,
    to: Option<String>,
    rate: u32,
    duration_secs: u64,
    payload_bytes: usize,
    json: bool,
) -> Result<()> {
    let (cancel_tx, cancel_rx) = oneshot::channel();
    let signal = tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            let _ = cancel_tx.send(());
        }
    });
    let (events, output) = output_worker(json);
    let result = send_events(
        dir,
        run_id,
        to,
        rate,
        duration_secs,
        payload_bytes,
        events,
        cancel_rx,
    )
    .await;
    signal.abort();
    output.await.context("benchmark output worker failed")?;
    result
}

#[derive(Debug)]
struct ReceiveStats {
    run_id: String,
    expected: Option<u64>,
    seen: Vec<u8>,
    unique: u64,
    duplicates: u64,
    out_of_order: u64,
    highest: Option<u64>,
    body_bytes: u64,
    latencies: Vec<u64>,
    observations: u64,
    sampled: bool,
    clock_invalid: u64,
    local_lag: u64,
    local_dropped: u64,
    gossip_lag: u64,
    peer_up: u64,
    peer_down: u64,
    ignored: u64,
    malformed: u64,
}

impl ReceiveStats {
    fn new(run_id: String, expected: Option<u64>) -> Result<Self> {
        anyhow::ensure!(
            expected.is_none_or(|n| (1..=MAX_BENCH_MESSAGES).contains(&n)),
            "expected count must be between 1 and {MAX_BENCH_MESSAGES}"
        );
        let seen = expected.map_or_else(Vec::new, |n| vec![0; n.div_ceil(8) as usize]);
        Ok(Self {
            run_id,
            expected,
            seen,
            unique: 0,
            duplicates: 0,
            out_of_order: 0,
            highest: None,
            body_bytes: 0,
            latencies: Vec::new(),
            observations: 0,
            sampled: false,
            clock_invalid: 0,
            local_lag: 0,
            local_dropped: 0,
            gossip_lag: 0,
            peer_up: 0,
            peer_down: 0,
            ignored: 0,
            malformed: 0,
        })
    }
    fn record(&mut self, value: &Value) {
        match value["type"].as_str() {
            Some("message" | "private_message") => {
                let Some(body) = value["body"].as_str() else {
                    self.ignored += 1;
                    return;
                };
                let frame = match parse_body(body) {
                    Ok(Some(v)) => v,
                    Ok(None) => {
                        self.ignored += 1;
                        return;
                    }
                    Err(_) => {
                        if body.contains(&self.run_id) {
                            self.malformed += 1
                        } else {
                            self.ignored += 1
                        };
                        return;
                    }
                };
                if frame.run_id != self.run_id {
                    self.ignored += 1;
                    return;
                }
                if self.expected.is_none() {
                    self.expected = Some(frame.total);
                    self.seen = vec![0; frame.total.div_ceil(8) as usize];
                }
                if self.expected != Some(frame.total) {
                    self.malformed += 1;
                    return;
                }
                let byte = (frame.sequence / 8) as usize;
                let mask = 1 << (frame.sequence % 8);
                if self.seen[byte] & mask != 0 {
                    self.duplicates += 1;
                    return;
                }
                self.seen[byte] |= mask;
                if self.highest.is_some_and(|v| frame.sequence < v) {
                    self.out_of_order += 1;
                }
                self.highest = Some(
                    self.highest
                        .map_or(frame.sequence, |v| v.max(frame.sequence)),
                );
                self.unique += 1;
                self.body_bytes = self.body_bytes.saturating_add(body.len() as u64);
                match unix_timestamp_ms().checked_sub(frame.timestamp_ms) {
                    Some(latency) if latency <= MAX_LATENCY_MS => {
                        self.observations += 1;
                        if self.latencies.len() < MAX_LATENCY_SAMPLES {
                            self.latencies.push(latency)
                        } else {
                            self.sampled = true;
                        }
                    }
                    _ => self.clock_invalid += 1,
                }
            }
            Some("lagged") if value["source"] == "local" => {
                self.local_lag += 1;
                self.local_dropped += value["dropped"].as_u64().unwrap_or(0);
            }
            Some("lagged") if value["source"] == "gossip" => self.gossip_lag += 1,
            Some("peer_up") => self.peer_up += 1,
            Some("peer_down") => self.peer_down += 1,
            _ => {}
        }
    }
    fn percentile(sorted: &[u64], p: usize) -> Option<u64> {
        if sorted.is_empty() {
            None
        } else {
            sorted
                .get((p * sorted.len()).div_ceil(100).saturating_sub(1))
                .copied()
        }
    }
    fn value(&self, kind: &str, elapsed: Duration) -> Value {
        let mut samples = if kind == "bench_receive_progress"
            && self.latencies.len() > MAX_PROGRESS_LATENCY_SAMPLES
        {
            self.latencies
                .iter()
                .step_by(self.latencies.len().div_ceil(MAX_PROGRESS_LATENCY_SAMPLES))
                .copied()
                .collect()
        } else {
            self.latencies.clone()
        };
        samples.sort_unstable();
        let ms = elapsed.as_millis() as u64;
        let seconds = ms.max(1) as f64 / 1000.0;
        let incomplete = self.local_lag > 0 || self.gossip_lag > 0;
        serde_json::json!({"type":kind,"schema_version":1,"run_id":self.run_id,"elapsed_ms":ms,"expected":self.expected,"unique":self.unique,"missing":self.expected.map(|v|v.saturating_sub(self.unique)),"duplicates":self.duplicates,"out_of_order":self.out_of_order,"highest_sequence":self.highest,"body_bytes":self.body_bytes,"achieved_messages_per_second":self.unique as f64/seconds,"achieved_body_bytes_per_second":self.body_bytes as f64/seconds,"latency":{"observations":self.observations,"samples":samples.len(),"sampled":self.sampled || samples.len() < self.latencies.len(),"clock_invalid":self.clock_invalid,"p50_ms":Self::percentile(&samples,50),"p95_ms":Self::percentile(&samples,95),"p99_ms":Self::percentile(&samples,99)},"lag":{"local_events":self.local_lag,"local_dropped":self.local_dropped,"gossip_events":self.gossip_lag,"incomplete":incomplete},"malformed_messages":self.malformed})
    }
    fn summary(&self, reason: &str, elapsed: Duration) -> Value {
        let mut value = self.value("bench_receive_summary", elapsed);
        let missing = self.expected.unwrap_or(0);
        let sample: Vec<u64> = (0..missing)
            .filter(|n| {
                self.seen
                    .get((n / 8) as usize)
                    .is_some_and(|v| v & (1 << (n % 8)) == 0)
            })
            .take(MAX_MISSING_SEQUENCE_SAMPLE)
            .collect();
        let complete = self.expected == Some(self.unique);
        let valid = complete && self.local_lag == 0 && self.gossip_lag == 0 && self.malformed == 0;
        value["completion_reason"] = reason.into();
        value["complete"] = complete.into();
        value["measurement_valid"] = valid.into();
        value["missing_sequence_sample"] = sample.into();
        value["peer_up"] = self.peer_up.into();
        value["peer_down"] = self.peer_down.into();
        value["ignored_messages"] = self.ignored.into();
        value
    }
}

async fn receive_events(
    dir: &std::path::Path,
    run_id: String,
    duration_secs: u64,
    expected: Option<u64>,
    events: mpsc::Sender<Value>,
    mut cancel: oneshot::Receiver<()>,
) -> Result<()> {
    let mut stats = ReceiveStats::new(run_id.clone(), expected)?;
    let mut reader = ipc::subscribe_with_id(dir, &contracts::new_request_id()).await?;
    let connected = reader
        .read()
        .await?
        .context("daemon stopped before subscription connected")?;
    anyhow::ensure!(
        connected["type"] == "connected",
        "unexpected subscription response"
    );
    events.send(serde_json::json!({"type":"bench_receive_started","schema_version":1,"run_id":run_id,"duration_secs":duration_secs,"expected":expected})).await.ok();
    let started = Instant::now();
    let deadline = tokio::time::sleep(Duration::from_secs(duration_secs));
    tokio::pin!(deadline);
    let mut progress = tokio::time::interval(Duration::from_millis(250));
    progress.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    progress.tick().await;
    let mut reason = "deadline";
    loop {
        tokio::select! {
            value = reader.read() => match value? { Some(value) => stats.record(&value), None => { reason = "daemon_stopped"; break; } },
            _ = &mut deadline => break,
            _ = progress.tick() => { let _ = events.try_send(stats.value("bench_receive_progress", started.elapsed())); },
            _ = &mut cancel => { reason = "interrupted"; break; }
        }
    }
    events
        .send(stats.summary(reason, started.elapsed()))
        .await
        .ok();
    anyhow::ensure!(
        reason != "daemon_stopped",
        "daemon stopped during benchmark"
    );
    Ok(())
}

async fn receive(
    dir: &std::path::Path,
    run_id: String,
    duration_secs: u64,
    expected: Option<u64>,
    json: bool,
) -> Result<()> {
    let (cancel_tx, cancel_rx) = oneshot::channel();
    let signal = tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            let _ = cancel_tx.send(());
        }
    });
    let (events, output) = output_worker(json);
    let result = receive_events(dir, run_id, duration_secs, expected, events, cancel_rx).await;
    signal.abort();
    output.await.context("benchmark output worker failed")?;
    result
}

#[cfg(feature = "bench-tui")]
pub(crate) async fn send_tui(
    dir: &std::path::Path,
    run_id: String,
    rate: u32,
    duration_secs: u64,
    payload_bytes: usize,
    events: mpsc::Sender<Value>,
    cancellation: oneshot::Receiver<()>,
) -> Result<()> {
    send_events(
        dir,
        Some(run_id),
        None,
        rate,
        duration_secs,
        payload_bytes,
        events,
        cancellation,
    )
    .await
}
#[cfg(feature = "bench-tui")]
pub(crate) async fn receive_tui(
    dir: &std::path::Path,
    run_id: String,
    duration_secs: u64,
    expected: Option<u64>,
    events: mpsc::Sender<Value>,
    cancellation: oneshot::Receiver<()>,
) -> Result<()> {
    receive_events(dir, run_id, duration_secs, expected, events, cancellation).await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn framing_round_trip() {
        let id = "0123456789abcdef0123456789abcdef";
        let body = build_body(id, 2, 3, 1_700_000_000_000, 256).unwrap();
        assert_eq!(body.len(), 256);
        assert_eq!(parse_body(&body).unwrap().unwrap().sequence, 2);
        assert!(parse_body("hello").unwrap().is_none());
    }
    #[test]
    fn sender_bounds() {
        let id = "0123456789abcdef0123456789abcdef";
        assert!(validate_sender_config(id, 100, 1, 256, false).is_ok());
        assert!(validate_sender_config(id, 0, 1, 256, false).is_err());
        assert!(validate_sender_config(id, 100, 1, 32, false).is_err());
    }

    #[test]
    fn non_tui_cli_has_only_send_and_receive() {
        assert!(Cli::try_parse_from(["meshmsg-bench", "send"]).is_ok());
        assert!(Cli::try_parse_from([
            "meshmsg-bench",
            "receive",
            "--run-id",
            "0123456789abcdef0123456789abcdef"
        ])
        .is_ok());
        assert!(Cli::try_parse_from(["meshmsg-bench", "tui"]).is_err());
    }

    #[test]
    fn interrupted_sender_accounts_only_elapsed_slots() {
        let mut stats = SendStats {
            attempted: 2,
            queued: 2,
            ..SendStats::default()
        };
        finish_schedule_accounting(
            &mut stats,
            Duration::from_millis(35),
            Duration::from_millis(10),
            100,
        );

        assert_eq!(
            eligible_slots(Duration::from_millis(35), Duration::from_millis(10), 100),
            4
        );
        assert_eq!(stats.schedule_missed, 2);
        assert_eq!(stats.attempted + stats.schedule_missed, 4);
        assert!(stats.attempted + stats.schedule_missed <= 100);
    }

    #[test]
    fn first_send_failure_does_not_mark_future_slots_missed() {
        let mut stats = SendStats {
            attempted: 1,
            failed: 1,
            first_error: Some("scripted failure".into()),
            ..SendStats::default()
        };
        let elapsed = Duration::from_millis(1);
        finish_schedule_accounting(&mut stats, elapsed, Duration::from_millis(10), 100);
        let summary = send_value(
            "bench_send_summary",
            "0123456789abcdef0123456789abcdef",
            100,
            1,
            256,
            100,
            &stats,
            elapsed,
        );

        assert_eq!(summary["attempted"], 1);
        assert_eq!(summary["failed"], 1);
        assert_eq!(summary["schedule_missed"], 0);
        assert!(stats.attempted + stats.schedule_missed <= 100);
    }
}
