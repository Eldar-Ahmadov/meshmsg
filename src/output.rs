//! Bounded, nonblocking process output for daemon events and diagnostics.
//!
//! Producers only perform `try_send`; a dedicated thread owns each terminal
//! stream. Diagnostic records are typed and deliberately exclude arbitrary error
//! text so paths, message bodies, tickets, secrets, and peer routes cannot enter
//! this subsystem.

use serde::Serialize;
use std::{
    collections::HashMap,
    fmt::Write as _,
    io::{self, Write},
    panic::{catch_unwind, AssertUnwindSafe},
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        mpsc::{sync_channel, Receiver, SyncSender, TrySendError},
        Arc, Mutex, OnceLock, TryLockError,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub(crate) const OUTPUT_QUEUE_CAPACITY: usize = 256;
const DIAGNOSTIC_QUEUE_CAPACITY: usize = 128;
pub(crate) const DRAIN_TIMEOUT: Duration = Duration::from_millis(500);
const MAX_FIELDS: usize = 8;
const MAX_FIELD_BYTES: usize = 256;
const MAX_EVENT_CODE_BYTES: usize = 64;
const DIAGNOSTIC_SAMPLE_WINDOW: Duration = Duration::from_secs(10);

static PROCESS_PANICS: AtomicU64 = AtomicU64::new(0);
static DAEMON_STDOUT_DETACHED: AtomicBool = AtomicBool::new(false);

/// The default panic hook writes synchronously to stderr before `catch_unwind`
/// can isolate a writer or renderer panic. Install a deliberately I/O-free hook
/// before starting any output worker. Panics still unwind/abort normally and are
/// observable through process exit and the writer/process counters.
pub(crate) fn test_switch(name: &str) -> bool {
    cfg!(debug_assertions) && std::env::var_os(name).is_some()
}

type PanicHook = Box<dyn Fn(&std::panic::PanicHookInfo<'_>) + Send + Sync + 'static>;

pub(crate) struct PanicHookGuard {
    previous: Option<PanicHook>,
}

impl Drop for PanicHookGuard {
    fn drop(&mut self) {
        if let Some(previous) = self.previous.take() {
            std::panic::set_hook(previous);
        }
    }
}

pub(crate) fn install_panic_hook() -> PanicHookGuard {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {
        PROCESS_PANICS.fetch_add(1, Ordering::Relaxed);
    }));
    PanicHookGuard {
        previous: Some(previous),
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Level {
    Info,
    Warn,
    Error,
    Fatal,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct Field {
    key: &'static str,
    value: String,
}

impl Field {
    pub(crate) fn new(key: &'static str, value: impl ToString) -> Self {
        debug_assert!(key
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_'));
        let raw = value.to_string();
        let safe = match key {
            "phase" if matches!(raw.as_str(), "topic_join" | "endpoint_online") => raw,
            "port" if raw.parse::<u16>().is_ok() => raw,
            "suppressed_since_last" | "index" if raw.parse::<u64>().is_ok() => raw,
            _ => "[redacted]".to_owned(),
        };
        Self {
            key,
            value: sanitize(&safe, MAX_FIELD_BYTES),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct DiagnosticRecord {
    timestamp_ms: u64,
    level: Level,
    event: String,
    code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    operation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    run_id: Option<String>,
    fields: Vec<Field>,
}

impl DiagnosticRecord {
    pub(crate) fn new(level: Level, event: &str, code: &str) -> Self {
        Self {
            timestamp_ms: now_ms(),
            level,
            event: stable_token(event),
            code: stable_token(code),
            request_id: None,
            operation_id: None,
            run_id: None,
            fields: Vec::new(),
        }
    }

    pub(crate) fn request_id(mut self, value: Option<&str>) -> Self {
        self.request_id = correlation(value);
        self
    }

    pub(crate) fn operation_id(mut self, value: Option<&str>) -> Self {
        self.operation_id = correlation(value);
        self
    }

    pub(crate) fn run_id(mut self, value: Option<&str>) -> Self {
        self.run_id = correlation(value);
        self
    }

    pub(crate) fn field(mut self, field: Field) -> Self {
        if self.fields.len() < MAX_FIELDS {
            self.fields.push(field);
        }
        self
    }
}

fn correlation(value: Option<&str>) -> Option<String> {
    value
        .filter(|value| {
            value.len() == 32
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        .map(str::to_owned)
}

fn stable_token(value: &str) -> String {
    let value: String = value
        .bytes()
        .take(MAX_EVENT_CODE_BYTES)
        .filter(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
        .map(char::from)
        .collect();
    if value.is_empty() {
        "internal".to_owned()
    } else {
        value
    }
}

pub(crate) fn sanitize(value: &str, maximum: usize) -> String {
    let mut output = String::with_capacity(value.len().min(maximum));
    for character in value.chars() {
        let character = if character.is_control() {
            '\u{fffd}'
        } else {
            character
        };
        if output.len() + character.len_utf8() > maximum {
            break;
        }
        output.push(character);
    }
    output
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

#[derive(Default)]
struct Metrics {
    accepted: AtomicU64,
    queue_dropped: AtomicU64,
    contention_dropped: AtomicU64,
    sampled: AtomicU64,
    suppressed: AtomicU64,
    written: AtomicU64,
    write_failed: AtomicU64,
    writer_panicked: AtomicU64,
    writer_lost: AtomicU64,
    occupancy: AtomicUsize,
    high_watermark: AtomicUsize,
    terminal: AtomicBool,
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct MetricsSnapshot {
    pub(crate) accepted: u64,
    pub(crate) dropped: u64,
    pub(crate) queue_dropped: u64,
    pub(crate) contention_dropped: u64,
    pub(crate) sampled: u64,
    pub(crate) suppressed: u64,
    pub(crate) written: u64,
    pub(crate) write_failed: u64,
    pub(crate) writer_panicked: u64,
    pub(crate) writer_lost: u64,
    pub(crate) occupancy: usize,
    pub(crate) high_watermark: usize,
    pub(crate) writer_healthy: bool,
    pub(crate) writer_terminal: bool,
    pub(crate) process_panics: u64,
}

impl Metrics {
    fn snapshot(&self) -> MetricsSnapshot {
        let queue_dropped = self.queue_dropped.load(Ordering::Relaxed);
        let contention_dropped = self.contention_dropped.load(Ordering::Relaxed);
        let writer_lost = self.writer_lost.load(Ordering::Relaxed);
        let writer_terminal = self.terminal.load(Ordering::Acquire);
        MetricsSnapshot {
            accepted: self.accepted.load(Ordering::Relaxed),
            dropped: queue_dropped
                .saturating_add(contention_dropped)
                .saturating_add(writer_lost),
            queue_dropped,
            contention_dropped,
            sampled: self.sampled.load(Ordering::Relaxed),
            suppressed: self.suppressed.load(Ordering::Relaxed),
            written: self.written.load(Ordering::Relaxed),
            write_failed: self.write_failed.load(Ordering::Relaxed),
            writer_panicked: self.writer_panicked.load(Ordering::Relaxed),
            writer_lost,
            occupancy: self.occupancy.load(Ordering::Acquire),
            high_watermark: self.high_watermark.load(Ordering::Relaxed),
            writer_healthy: !writer_terminal,
            writer_terminal,
            process_panics: PROCESS_PANICS.load(Ordering::Relaxed),
        }
    }
}

enum Item {
    Event(serde_json::Value),
    Diagnostic(DiagnosticRecord),
}

type Renderer = Arc<dyn Fn(serde_json::Value) -> String + Send + Sync>;

struct Dispatcher {
    sender: Arc<Mutex<Option<SyncSender<Item>>>>,
    capacity: usize,
    metrics: Arc<Metrics>,
    done: Mutex<Option<std::sync::mpsc::Receiver<()>>>,
}

impl Dispatcher {
    fn start(
        capacity: usize,
        json: bool,
        mut sink: Box<dyn Write + Send>,
        renderer: Option<Renderer>,
        name: &str,
    ) -> io::Result<Arc<Self>> {
        if name.contains('\0') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "output worker name is invalid",
            ));
        }
        let (sender, receiver) = sync_channel(capacity);
        let sender = Arc::new(Mutex::new(Some(sender)));
        let worker_sender = sender.clone();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let metrics = Arc::new(Metrics::default());
        let worker_metrics = metrics.clone();
        std::thread::Builder::new()
            .name(name.to_owned())
            .spawn(move || {
                let result = catch_unwind(AssertUnwindSafe(|| {
                    writer_loop(
                        &receiver,
                        &worker_sender,
                        json,
                        &mut sink,
                        renderer.as_ref(),
                        &worker_metrics,
                    )
                }));
                if result.is_err() {
                    worker_metrics
                        .writer_panicked
                        .fetch_add(1, Ordering::Relaxed);
                    terminate_writer(&receiver, &worker_sender, &worker_metrics, true);
                }
                let _ = done_tx.send(());
            })?;
        Ok(Arc::new(Self {
            sender,
            capacity,
            metrics,
            done: Mutex::new(Some(done_rx)),
        }))
    }

    fn offer(&self, item: Item) -> bool {
        let sender = match self.sender.try_lock() {
            Ok(sender) => sender,
            Err(TryLockError::Poisoned(poisoned)) => {
                self.sender.clear_poison();
                poisoned.into_inner()
            }
            Err(TryLockError::WouldBlock) => {
                self.metrics
                    .contention_dropped
                    .fetch_add(1, Ordering::Relaxed);
                return false;
            }
        };
        if self.metrics.terminal.load(Ordering::Acquire) {
            self.metrics.queue_dropped.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        let Some(sender) = sender.as_ref() else {
            self.metrics.queue_dropped.fetch_add(1, Ordering::Relaxed);
            return false;
        };
        let current = self.metrics.occupancy.load(Ordering::Acquire);
        if current >= self.capacity {
            self.metrics.queue_dropped.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        let occupancy = self.metrics.occupancy.fetch_add(1, Ordering::AcqRel) + 1;
        match sender.try_send(item) {
            Ok(()) => {
                self.metrics.accepted.fetch_add(1, Ordering::Relaxed);
                self.metrics
                    .high_watermark
                    .fetch_max(occupancy.min(self.capacity), Ordering::Relaxed);
                true
            }
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                self.metrics.occupancy.fetch_sub(1, Ordering::AcqRel);
                self.metrics.queue_dropped.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    fn reject(&self) {
        self.metrics.queue_dropped.fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot(&self) -> MetricsSnapshot {
        let snapshot = self.metrics.snapshot();
        debug_assert!(snapshot.occupancy <= self.capacity);
        debug_assert!(snapshot.high_watermark <= self.capacity);
        snapshot
    }

    fn close_admission(&self) {
        match self.sender.lock() {
            Ok(mut sender) => {
                sender.take();
            }
            Err(poisoned) => {
                self.sender.clear_poison();
                poisoned.into_inner().take();
            }
        }
    }

    fn close_and_wait(&self, timeout: Duration) -> bool {
        self.close_admission();
        let receiver = match self.done.lock() {
            Ok(mut done) => done.take(),
            Err(poisoned) => poisoned.into_inner().take(),
        };
        match receiver {
            Some(receiver) => receiver.recv_timeout(timeout).is_ok(),
            None => self.metrics.occupancy.load(Ordering::Acquire) == 0,
        }
    }
}

fn terminate_writer(
    receiver: &Receiver<Item>,
    sender: &Mutex<Option<SyncSender<Item>>>,
    metrics: &Metrics,
    current_is_lost: bool,
) {
    metrics.terminal.store(true, Ordering::Release);
    match sender.lock() {
        Ok(mut sender) => {
            sender.take();
        }
        Err(poisoned) => {
            sender.clear_poison();
            poisoned.into_inner().take();
        }
    }
    let mut lost = usize::from(current_is_lost);
    while receiver.try_recv().is_ok() {
        lost = lost.saturating_add(1);
    }
    // Admission is closed before draining, so this is the exact terminal reset.
    metrics.occupancy.store(0, Ordering::Release);
    metrics
        .writer_lost
        .fetch_add(u64::try_from(lost).unwrap_or(u64::MAX), Ordering::Relaxed);
}

fn writer_loop(
    receiver: &Receiver<Item>,
    sender: &Mutex<Option<SyncSender<Item>>>,
    json: bool,
    sink: &mut dyn Write,
    renderer: Option<&Renderer>,
    metrics: &Metrics,
) {
    while let Ok(item) = receiver.recv() {
        let result = write_item(sink, json, renderer, item);
        if result.is_err() {
            metrics.write_failed.fetch_add(1, Ordering::Relaxed);
            terminate_writer(receiver, sender, metrics, true);
            break;
        }
        metrics.occupancy.fetch_sub(1, Ordering::AcqRel);
        metrics.written.fetch_add(1, Ordering::Relaxed);
    }
}

fn write_item(
    sink: &mut dyn Write,
    json: bool,
    renderer: Option<&Renderer>,
    item: Item,
) -> io::Result<()> {
    let mut bytes = Vec::with_capacity(256);
    match item {
        Item::Event(value) if json => serde_json::to_writer(&mut bytes, &value)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?,
        Item::Event(value) => {
            let line = renderer.map_or_else(|| "event".to_owned(), |render| render(value));
            bytes.extend_from_slice(line.as_bytes());
        }
        Item::Diagnostic(record) if json => serde_json::to_writer(&mut bytes, &record)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?,
        Item::Diagnostic(record) => render_diagnostic_human(&record, &mut bytes),
    }
    bytes.push(b'\n');
    sink.write_all(&bytes)?;
    sink.flush()
}

fn render_diagnostic_human(record: &DiagnosticRecord, bytes: &mut Vec<u8>) {
    let mut line = String::with_capacity(256);
    let _ = write!(
        line,
        "{} {:?} {} [{}]",
        record.timestamp_ms, record.level, record.event, record.code
    );
    for (name, value) in [
        ("request_id", record.request_id.as_deref()),
        ("operation_id", record.operation_id.as_deref()),
        ("run_id", record.run_id.as_deref()),
    ] {
        if let Some(value) = value {
            let _ = write!(line, " {name}={value}");
        }
    }
    for field in &record.fields {
        let _ = write!(line, " {}={}", field.key, field.value);
    }
    bytes.extend_from_slice(line.as_bytes());
}

pub(crate) struct DaemonOutput(Arc<Dispatcher>);

impl DaemonOutput {
    pub(crate) fn start(
        json: bool,
        renderer: impl Fn(serde_json::Value) -> String + Send + Sync + 'static,
    ) -> io::Result<Self> {
        let sink: Box<dyn Write + Send> = if test_switch("MESHMSG_TEST_BLOCK_DAEMON_STDOUT") {
            Box::new(BlockForever)
        } else if test_switch("MESHMSG_TEST_PANIC_DAEMON_STDOUT") {
            Box::new(DelayedPanic)
        } else {
            Box::new(io::stdout())
        };
        Dispatcher::start(
            OUTPUT_QUEUE_CAPACITY,
            json,
            sink,
            Some(Arc::new(renderer)),
            "meshmsg-daemon-output",
        )
        .map(Self)
    }

    #[cfg(test)]
    pub(crate) fn start_with_sink(
        json: bool,
        renderer: impl Fn(serde_json::Value) -> String + Send + Sync + 'static,
        sink: Box<dyn Write + Send>,
        name: &str,
    ) -> io::Result<Self> {
        Dispatcher::start(
            OUTPUT_QUEUE_CAPACITY,
            json,
            sink,
            Some(Arc::new(renderer)),
            name,
        )
        .map(Self)
    }

    pub(crate) fn event(&self, mut value: serde_json::Value) -> bool {
        if value.get("type").and_then(serde_json::Value::as_str) == Some("error") {
            let Ok(error) = crate::contracts::ErrorEnvelopeV1::from_value(&value) else {
                self.0.reject();
                return false;
            };
            // Re-serialize the strict DTO rather than preserving the caller's
            // object representation. Unknown fields, private diagnostics,
            // noncanonical text, and invalid semantics never reach the queue.
            value = error.into_value();
        } else if value.get("schema_version").is_none() {
            value["schema_version"] = crate::contracts::SCHEMA_VERSION.into();
        }
        self.0.offer(Item::Event(value))
    }

    pub(crate) fn metrics(&self) -> MetricsSnapshot {
        self.0.snapshot()
    }

    pub(crate) fn shutdown(&self, timeout: Duration) -> bool {
        let drained = self.0.close_and_wait(timeout);
        if !drained {
            DAEMON_STDOUT_DETACHED.store(true, Ordering::Release);
        }
        drained
    }
}

impl Drop for DaemonOutput {
    fn drop(&mut self) {
        // RAII is the backstop for every `?`, early return, and unwind path.
        self.0.close_admission();
        if !self.0.close_and_wait(DRAIN_TIMEOUT) {
            DAEMON_STDOUT_DETACHED.store(true, Ordering::Release);
        }
    }
}

pub(crate) fn stdout_available() -> bool {
    !DAEMON_STDOUT_DETACHED.load(Ordering::Acquire)
}

struct Sampler {
    entries: Mutex<HashMap<String, (Instant, u64)>>,
}

impl Sampler {
    fn admit_at(
        &self,
        key: String,
        now: Instant,
        window: Duration,
        metrics: &Metrics,
    ) -> Option<u64> {
        let mut entries = match self.entries.try_lock() {
            Ok(entries) => entries,
            Err(TryLockError::Poisoned(poisoned)) => {
                self.entries.clear_poison();
                poisoned.into_inner()
            }
            Err(TryLockError::WouldBlock) => {
                metrics.contention_dropped.fetch_add(1, Ordering::Relaxed);
                return None;
            }
        };
        if let Some((last, suppressed)) = entries.get_mut(&key) {
            if now.saturating_duration_since(*last) < window {
                *suppressed = suppressed.saturating_add(1);
                metrics.suppressed.fetch_add(1, Ordering::Relaxed);
                return None;
            }
            let count = *suppressed;
            *last = now;
            *suppressed = 0;
            metrics.sampled.fetch_add(1, Ordering::Relaxed);
            Some(count)
        } else {
            entries.insert(key, (now, 0));
            metrics.sampled.fetch_add(1, Ordering::Relaxed);
            Some(0)
        }
    }
}

static DIAGNOSTICS: OnceLock<Option<Arc<Dispatcher>>> = OnceLock::new();
static SAMPLER: OnceLock<Sampler> = OnceLock::new();
static DIAGNOSTIC_METRICS: OnceLock<Arc<Metrics>> = OnceLock::new();
static DIAGNOSTIC_DISABLED_DROPS: AtomicU64 = AtomicU64::new(0);

fn diagnostic_counters() -> &'static Arc<Metrics> {
    DIAGNOSTIC_METRICS.get_or_init(|| Arc::new(Metrics::default()))
}

pub(crate) fn init_diagnostics(human_output: bool) -> io::Result<()> {
    if DIAGNOSTICS.get().is_some() {
        return Ok(());
    }
    if !human_output {
        let _ = DIAGNOSTICS.set(None);
        return Ok(());
    }
    if test_switch("MESHMSG_TEST_DIAGNOSTIC_STARTUP_FAIL") {
        return Err(io::Error::other(
            "injected diagnostic writer startup failure",
        ));
    }
    let sink: Box<dyn Write + Send> = if test_switch("MESHMSG_TEST_BLOCK_STDERR") {
        Box::new(BlockForever)
    } else {
        Box::new(io::stderr())
    };
    let dispatcher = Dispatcher::start(
        DIAGNOSTIC_QUEUE_CAPACITY,
        false,
        sink,
        None,
        "meshmsg-diagnostics",
    )?;
    let _ = DIAGNOSTICS.set(Some(dispatcher));
    Ok(())
}

pub(crate) fn diagnostic(record: DiagnosticRecord) -> bool {
    match DIAGNOSTICS.get().and_then(Option::as_ref) {
        Some(dispatcher) => dispatcher.offer(Item::Diagnostic(record)),
        None => {
            DIAGNOSTIC_DISABLED_DROPS.fetch_add(1, Ordering::Relaxed);
            false
        }
    }
}

pub(crate) fn sampled_diagnostic(mut record: DiagnosticRecord) -> bool {
    let key = format!("{}:{}", record.event, record.code);
    let sampler = SAMPLER.get_or_init(|| Sampler {
        entries: Mutex::new(HashMap::new()),
    });
    let counters = diagnostic_counters();
    let Some(suppressed) =
        sampler.admit_at(key, Instant::now(), DIAGNOSTIC_SAMPLE_WINDOW, counters)
    else {
        return false;
    };
    record = record.field(Field::new("suppressed_since_last", suppressed));
    diagnostic(record)
}

pub(crate) fn diagnostic_capacity() -> usize {
    if DIAGNOSTICS.get().and_then(Option::as_ref).is_some() {
        DIAGNOSTIC_QUEUE_CAPACITY
    } else {
        0
    }
}

pub(crate) fn shutdown_diagnostics(timeout: Duration) -> bool {
    DIAGNOSTICS
        .get()
        .and_then(Option::as_ref)
        .is_none_or(|dispatcher| dispatcher.close_and_wait(timeout))
}

pub(crate) fn diagnostic_metrics() -> MetricsSnapshot {
    let mut snapshot = DIAGNOSTICS
        .get()
        .and_then(Option::as_ref)
        .map_or_else(MetricsSnapshot::default, |dispatcher| dispatcher.snapshot());
    let sampled = diagnostic_counters().snapshot();
    snapshot.sampled = sampled.sampled;
    snapshot.suppressed = sampled.suppressed;
    snapshot.contention_dropped = snapshot
        .contention_dropped
        .saturating_add(sampled.contention_dropped);
    snapshot.queue_dropped = snapshot
        .queue_dropped
        .saturating_add(DIAGNOSTIC_DISABLED_DROPS.load(Ordering::Relaxed));
    snapshot.dropped = snapshot
        .queue_dropped
        .saturating_add(snapshot.contention_dropped)
        .saturating_add(snapshot.writer_lost);
    snapshot.process_panics = PROCESS_PANICS.load(Ordering::Relaxed);
    snapshot
}

/// Perform one terminal write on an isolated owner and wait only to `timeout`.
/// On timeout the caller must never write that stream again in this process.
pub(crate) fn write_terminal_bounded(
    stderr: bool,
    bytes: Vec<u8>,
    timeout: Duration,
) -> io::Result<bool> {
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("meshmsg-terminal-output".into())
        .spawn(move || {
            let result = if stderr {
                let mut stream = io::stderr().lock();
                stream.write_all(&bytes).and_then(|()| stream.flush())
            } else {
                let mut stream = io::stdout().lock();
                stream.write_all(&bytes).and_then(|()| stream.flush())
            };
            let _ = done_tx.send(result);
        })?;
    match done_rx.recv_timeout(timeout) {
        Ok(result) => result.map(|()| true),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Ok(false),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Ok(false),
    }
}

struct DelayedPanic;
impl Write for DelayedPanic {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        std::thread::sleep(Duration::from_millis(50));
        panic!("injected daemon output panic");
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct BlockForever;
impl Write for BlockForever {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        loop {
            std::thread::park();
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Condvar;

    struct BlockedSink(Arc<(Mutex<bool>, Condvar)>);
    impl Write for BlockedSink {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let (lock, wake) = &*self.0;
            let mut open = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            while !*open {
                open = wake
                    .wait(open)
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
            }
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct FailedSink;
    impl Write for FailedSink {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "disconnected"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct PanicSink;
    impl Write for PanicSink {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            panic!("sink panic")
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn record(index: usize) -> DiagnosticRecord {
        DiagnosticRecord::new(Level::Warn, "test_event", "test_code")
            .field(Field::new("index", index))
    }

    #[test]
    fn sanitizes_and_validates_correlations() {
        assert_eq!(sanitize("a\n🙂b", 6), "a�");
        let record = DiagnosticRecord::new(Level::Info, "BAD/event", "code")
            .request_id(Some("11111111111111111111111111111111"))
            .operation_id(Some("not secret/path"))
            .run_id(Some("ABCDEFABCDEFABCDEFABCDEFABCDEFAB"));
        let encoded = serde_json::to_string(&record).unwrap();
        assert!(encoded.contains("request_id"));
        assert!(!encoded.contains("secret/path") && !encoded.contains("run_id"));
    }

    #[test]
    fn human_diagnostics_render_all_valid_correlations_only() {
        let record = DiagnosticRecord::new(Level::Warn, "event", "code")
            .request_id(Some("11111111111111111111111111111111"))
            .operation_id(Some("22222222222222222222222222222222"))
            .run_id(Some("abcdefabcdefabcdefabcdefabcdefab"));
        let mut bytes = Vec::new();
        render_diagnostic_human(&record, &mut bytes);
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("request_id=11111111111111111111111111111111"));
        assert!(text.contains("operation_id=22222222222222222222222222222222"));
        assert!(text.contains("run_id=abcdefabcdefabcdefabcdefabcdefab"));
    }

    #[test]
    fn blocked_sink_is_bounded_and_drain_times_out() {
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let dispatcher = Dispatcher::start(
            2,
            true,
            Box::new(BlockedSink(gate.clone())),
            None,
            "blocked-output-test",
        )
        .unwrap();
        let started = Instant::now();
        for index in 0..1000 {
            dispatcher.offer(Item::Diagnostic(record(index)));
        }
        assert!(started.elapsed() < Duration::from_millis(100));
        assert!(dispatcher.snapshot().queue_dropped > 0);
        assert!(!dispatcher.close_and_wait(Duration::from_millis(10)));
        *gate.0.lock().unwrap() = true;
        gate.1.notify_all();
    }

    #[test]
    fn daemon_error_admission_rejects_unknown_and_private_fields() {
        #[derive(Clone)]
        struct Capture(Arc<Mutex<Vec<u8>>>);
        impl Write for Capture {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let output = DaemonOutput::start_with_sink(
            true,
            |_| String::new(),
            Box::new(Capture(bytes.clone())),
            "strict-error-output-test",
        )
        .unwrap();
        assert!(!output.event(serde_json::json!({
            "type":"error", "schema_version":1, "code":"invalid_message",
            "message":"private path /home/alice", "outcome":"not_started",
            "retryable":false, "private_diagnostic":"secret"
        })));
        assert!(output.event(
            crate::contracts::ErrorEnvelopeV1::new(
                "invalid_message",
                "discarded private cause",
                "not_started",
                false,
            )
            .into_value()
        ));
        assert!(output.shutdown(Duration::from_secs(1)));
        let text = String::from_utf8(bytes.lock().unwrap().clone()).unwrap();
        assert_eq!(text.lines().count(), 1);
        assert!(text.contains("The message is invalid."));
        assert!(!text.contains("alice") && !text.contains("secret"));
    }

    #[test]
    fn independent_writer_high_watermarks_survive_interleaved_peaks() {
        let stdout_gate = Arc::new((Mutex::new(false), Condvar::new()));
        let stderr_gate = Arc::new((Mutex::new(false), Condvar::new()));
        let stdout = Dispatcher::start(
            4,
            true,
            Box::new(BlockedSink(stdout_gate.clone())),
            None,
            "interleaved-stdout-test",
        )
        .unwrap();
        let diagnostics = Dispatcher::start(
            3,
            false,
            Box::new(BlockedSink(stderr_gate.clone())),
            None,
            "interleaved-stderr-test",
        )
        .unwrap();
        for index in 0..10 {
            stdout.offer(Item::Diagnostic(record(index)));
        }
        assert_eq!(stdout.snapshot().high_watermark, 4);
        assert_eq!(diagnostics.snapshot().high_watermark, 0);
        *stdout_gate.0.lock().unwrap() = true;
        stdout_gate.1.notify_all();
        let deadline = Instant::now() + Duration::from_secs(1);
        while stdout.snapshot().occupancy != 0 && Instant::now() < deadline {
            std::thread::yield_now();
        }
        assert_eq!(stdout.snapshot().occupancy, 0);
        for index in 0..10 {
            diagnostics.offer(Item::Diagnostic(record(index)));
        }
        assert_eq!(diagnostics.snapshot().high_watermark, 3);
        assert_eq!(stdout.snapshot().high_watermark, 4);
        *stderr_gate.0.lock().unwrap() = true;
        stderr_gate.1.notify_all();
        assert!(stdout.close_and_wait(Duration::from_secs(1)));
        assert!(diagnostics.close_and_wait(Duration::from_secs(1)));
    }

    #[test]
    fn writer_error_counts_current_and_every_abandoned_record() {
        let dispatcher =
            Dispatcher::start(8, false, Box::new(FailedSink), None, "failed-output-test").unwrap();
        let mut accepted = 0;
        for index in 0..8 {
            accepted += usize::from(dispatcher.offer(Item::Diagnostic(record(index))));
        }
        assert!(dispatcher.close_and_wait(Duration::from_secs(1)));
        let metrics = dispatcher.snapshot();
        assert_eq!(metrics.write_failed, 1);
        assert_eq!(metrics.writer_lost, u64::try_from(accepted).unwrap());
        assert_eq!(metrics.occupancy, 0);
        assert!(metrics.writer_terminal && !metrics.writer_healthy);
    }

    #[test]
    fn panicking_sink_isolated_and_accounts_for_queue() {
        let dispatcher =
            Dispatcher::start(8, false, Box::new(PanicSink), None, "panic-output-test").unwrap();
        let mut accepted = 0;
        for index in 0..8 {
            accepted += usize::from(dispatcher.offer(Item::Diagnostic(record(index))));
        }
        assert!(dispatcher.close_and_wait(Duration::from_secs(1)));
        let metrics = dispatcher.snapshot();
        assert_eq!(metrics.writer_panicked, 1);
        assert_eq!(metrics.writer_lost, u64::try_from(accepted).unwrap());
        assert_eq!(metrics.occupancy, 0);
        assert!(!dispatcher.offer(Item::Diagnostic(record(9))));
    }

    #[test]
    fn ordering_and_clean_drain_are_preserved() {
        #[derive(Clone)]
        struct Capture(Arc<Mutex<Vec<u8>>>);
        impl Write for Capture {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let dispatcher = Dispatcher::start(
            8,
            true,
            Box::new(Capture(bytes.clone())),
            None,
            "ordered-output-test",
        )
        .unwrap();
        for index in 0..4 {
            assert!(dispatcher.offer(Item::Diagnostic(record(index))));
        }
        assert!(dispatcher.close_and_wait(Duration::from_secs(1)));
        let text = String::from_utf8(bytes.lock().unwrap().clone()).unwrap();
        let values: Vec<String> = text
            .lines()
            .map(|line| {
                serde_json::from_str::<serde_json::Value>(line).unwrap()["fields"][0]["value"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect();
        assert_eq!(values, ["0", "1", "2", "3"]);
    }

    #[test]
    fn sampling_is_truthful_before_next_window_and_poison_safe() {
        let sampler = Sampler {
            entries: Mutex::new(HashMap::new()),
        };
        let metrics = Metrics::default();
        let start = Instant::now();
        assert_eq!(
            sampler.admit_at("warning".into(), start, Duration::from_secs(10), &metrics),
            Some(0)
        );
        assert_eq!(
            sampler.admit_at(
                "warning".into(),
                start + Duration::from_secs(9),
                Duration::from_secs(10),
                &metrics
            ),
            None
        );
        assert_eq!(metrics.snapshot().suppressed, 1);
        let poison = Sampler {
            entries: Mutex::new(HashMap::new()),
        };
        std::thread::scope(|scope| {
            let poison = &poison;
            let _ = scope
                .spawn(move || {
                    let _guard = poison.entries.lock().unwrap();
                    panic!("poison sampler");
                })
                .join();
        });
        assert_eq!(
            poison.admit_at("safe".into(), start, Duration::from_secs(1), &metrics),
            Some(0)
        );
    }

    #[test]
    fn sampler_contention_has_its_own_counter() {
        let sampler = Sampler {
            entries: Mutex::new(HashMap::new()),
        };
        let metrics = Metrics::default();
        let _guard = sampler.entries.lock().unwrap();
        assert_eq!(
            sampler.admit_at(
                "contended".into(),
                Instant::now(),
                Duration::from_secs(1),
                &metrics
            ),
            None
        );
        assert_eq!(metrics.snapshot().contention_dropped, 1);
        assert_eq!(metrics.snapshot().suppressed, 0);
    }

    #[test]
    fn startup_failure_is_returned() {
        assert!(Dispatcher::start(1, false, Box::new(io::sink()), None, "bad\0name").is_err());
    }
}
