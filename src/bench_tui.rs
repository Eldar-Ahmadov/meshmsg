use crate::node;
use anyhow::{Context, Result};
use crossterm::{
    cursor::{Hide, Show},
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
    Frame, Terminal,
};
use serde_json::Value;
use std::{io, io::IsTerminal, path::Path, time::Duration};
use tokio::{sync::oneshot, task::JoinHandle};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Role {
    Sender,
    Receiver,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum View {
    Setup,
    Running,
    Result,
}

struct App {
    role: Role,
    view: View,
    selected: usize,
    run_id: String,
    sender_rate: String,
    sender_duration: String,
    payload_bytes: String,
    receiver_duration: String,
    expected: String,
    latest: Option<Value>,
    error: Option<String>,
    cancelling: bool,
}

impl Default for App {
    fn default() -> Self {
        Self {
            role: Role::Sender,
            view: View::Setup,
            selected: 0,
            run_id: generated_run_id(),
            sender_rate: "100".into(),
            sender_duration: "10".into(),
            payload_bytes: "256".into(),
            receiver_duration: "15".into(),
            expected: String::new(),
            latest: None,
            error: None,
            cancelling: false,
        }
    }
}

#[derive(Debug)]
enum Config {
    Sender {
        run_id: String,
        rate: u32,
        duration_secs: u64,
        payload_bytes: usize,
    },
    Receiver {
        run_id: String,
        duration_secs: u64,
        expected: Option<u64>,
    },
}

impl App {
    fn field_count(&self) -> usize {
        match self.role {
            Role::Sender => 5,
            Role::Receiver => 4,
        }
    }

    fn validate(&self) -> Result<Config> {
        anyhow::ensure!(
            self.run_id.len() == 32
                && self
                    .run_id
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
            "run ID must contain exactly 32 lowercase hexadecimal characters"
        );
        match self.role {
            Role::Sender => {
                let rate = self
                    .sender_rate
                    .parse::<u32>()
                    .context("rate must be a number")?;
                let duration_secs = self
                    .sender_duration
                    .parse::<u64>()
                    .context("duration must be a number")?;
                let payload_bytes = self
                    .payload_bytes
                    .parse::<usize>()
                    .context("payload size must be a number")?;
                node::validate_bench_sender_config(
                    &self.run_id,
                    rate,
                    duration_secs,
                    payload_bytes,
                )?;
                Ok(Config::Sender {
                    run_id: self.run_id.clone(),
                    rate,
                    duration_secs,
                    payload_bytes,
                })
            }
            Role::Receiver => {
                let duration_secs = self
                    .receiver_duration
                    .parse::<u64>()
                    .context("duration must be a number")?;
                anyhow::ensure!(
                    (1..=86_400).contains(&duration_secs),
                    "duration must be between 1 and 86400 seconds"
                );
                let expected = if self.expected.is_empty() {
                    None
                } else {
                    let value = self
                        .expected
                        .parse::<u64>()
                        .context("expected count must be a number")?;
                    anyhow::ensure!(
                        (1..=10_000_000).contains(&value),
                        "expected count must be between 1 and 10000000"
                    );
                    Some(value)
                };
                Ok(Config::Receiver {
                    run_id: self.run_id.clone(),
                    duration_secs,
                    expected,
                })
            }
        }
    }

    fn selected_input_mut(&mut self) -> Option<(&mut String, usize, bool)> {
        match (self.role, self.selected) {
            (_, 1) => Some((&mut self.run_id, 32, true)),
            (Role::Sender, 2) => Some((&mut self.sender_rate, 5, false)),
            (Role::Sender, 3) => Some((&mut self.sender_duration, 5, false)),
            (Role::Sender, 4) => Some((&mut self.payload_bytes, 4, false)),
            (Role::Receiver, 2) => Some((&mut self.receiver_duration, 5, false)),
            (Role::Receiver, 3) => Some((&mut self.expected, 8, false)),
            _ => None,
        }
    }

    fn edit(&mut self, key: KeyCode) {
        let Some((value, limit, hexadecimal)) = self.selected_input_mut() else {
            return;
        };
        match key {
            KeyCode::Backspace => {
                value.pop();
            }
            KeyCode::Char(character)
                if value.len() < limit
                    && ((!hexadecimal && character.is_ascii_digit())
                        || (hexadecimal && character.is_ascii_hexdigit())) =>
            {
                value.push(character.to_ascii_lowercase());
            }
            _ => {}
        }
    }

    fn reset_after_result(&mut self) {
        self.view = View::Setup;
        self.latest = None;
        self.error = None;
        self.cancelling = false;
    }
}

struct TerminalGuard {
    terminal: Terminal<CrosstermBackend<io::Stdout>>,
}

impl TerminalGuard {
    fn enter() -> Result<Self> {
        enable_raw_mode().context("enable terminal raw mode")?;
        if let Err(error) = execute!(io::stdout(), EnterAlternateScreen, Hide) {
            let _ = disable_raw_mode();
            let _ = execute!(io::stdout(), LeaveAlternateScreen, Show);
            return Err(error).context("enter alternate screen");
        }
        match Terminal::new(CrosstermBackend::new(io::stdout())) {
            Ok(terminal) => Ok(Self { terminal }),
            Err(error) => {
                let _ = disable_raw_mode();
                let _ = execute!(io::stdout(), LeaveAlternateScreen, Show);
                Err(error).context("initialize terminal")
            }
        }
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen, Show);
    }
}

pub(crate) async fn run(dir: &Path) -> Result<()> {
    anyhow::ensure!(
        io::stdin().is_terminal() && io::stdout().is_terminal(),
        "bench-tui requires an interactive stdin and stdout terminal"
    );

    let mut terminal = TerminalGuard::enter()?;
    let mut app = App::default();
    // Progress is a snapshot, not history; a small bounded queue prevents a slow
    // terminal from accumulating data during a long benchmark.
    let (event_tx, mut event_rx) = tokio::sync::mpsc::channel::<Value>(16);
    let mut cancellation: Option<oneshot::Sender<()>> = None;
    let mut task: Option<JoinHandle<Result<()>>> = None;
    let mut run_error: Option<String> = None;
    let mut quit = false;

    while !quit {
        while let Ok(value) = event_rx.try_recv() {
            if matches!(
                value["type"].as_str(),
                Some("bench_send_summary" | "bench_receive_summary")
            ) {
                app.view = View::Result;
            }
            app.latest = Some(value);
        }
        if task.as_ref().is_some_and(|handle| handle.is_finished()) {
            let result = task.take().expect("finished task exists").await;
            if let Err(error) = result
                .context("benchmark task failed")
                .and_then(|value| value)
            {
                let error = format!("{error:#}");
                app.error = Some(error.clone());
                run_error = Some(error);
                app.view = View::Result;
            }
            cancellation = None;
        }

        terminal.terminal.draw(|frame| render(frame, &app))?;
        if !event::poll(Duration::from_millis(50)).context("poll terminal input")? {
            continue;
        }
        let Event::Key(key) = event::read().context("read terminal input")? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            if app.view == View::Running {
                stop_or_force_quit(&mut app, &mut cancellation, task.as_ref(), &mut quit);
            } else {
                quit = true;
            }
            continue;
        }

        match app.view {
            View::Setup => match key.code {
                KeyCode::Char('q') | KeyCode::Esc => quit = true,
                KeyCode::Tab | KeyCode::Down => {
                    app.selected = (app.selected + 1) % app.field_count();
                }
                KeyCode::BackTab | KeyCode::Up => {
                    app.selected = (app.selected + app.field_count() - 1) % app.field_count();
                }
                KeyCode::Left | KeyCode::Right if app.selected == 0 => {
                    app.role = match app.role {
                        Role::Sender => Role::Receiver,
                        Role::Receiver => Role::Sender,
                    };
                    app.selected = 0;
                    app.error = None;
                }
                KeyCode::Enter => match app.validate() {
                    Ok(config) => {
                        let (cancel_tx, cancel_rx) = oneshot::channel();
                        cancellation = Some(cancel_tx);
                        let path = dir.to_path_buf();
                        let events = event_tx.clone();
                        task = Some(tokio::spawn(async move {
                            match config {
                                Config::Sender {
                                    run_id,
                                    rate,
                                    duration_secs,
                                    payload_bytes,
                                } => {
                                    node::bench_send_tui(
                                        &path,
                                        run_id,
                                        rate,
                                        duration_secs,
                                        payload_bytes,
                                        events,
                                        cancel_rx,
                                    )
                                    .await
                                }
                                Config::Receiver {
                                    run_id,
                                    duration_secs,
                                    expected,
                                } => {
                                    node::bench_receive_tui(
                                        &path,
                                        run_id,
                                        duration_secs,
                                        expected,
                                        events,
                                        cancel_rx,
                                    )
                                    .await
                                }
                            }
                        }));
                        app.error = None;
                        run_error = None;
                        app.latest = None;
                        app.cancelling = false;
                        app.view = View::Running;
                    }
                    Err(error) => app.error = Some(error.to_string()),
                },
                code => app.edit(code),
            },
            View::Running => match key.code {
                KeyCode::Char('q') | KeyCode::Esc => {
                    stop_or_force_quit(&mut app, &mut cancellation, task.as_ref(), &mut quit);
                }
                _ => {}
            },
            View::Result => match key.code {
                KeyCode::Char('r') | KeyCode::Enter => app.reset_after_result(),
                KeyCode::Char('q') | KeyCode::Esc => quit = true,
                _ => {}
            },
        }
    }

    if let Some(cancel) = cancellation.take() {
        let _ = cancel.send(());
    }
    if let Some(handle) = task {
        match tokio::time::timeout(Duration::from_secs(6), handle).await {
            Ok(Ok(Err(error))) => run_error = Some(format!("{error:#}")),
            Ok(Err(error)) => run_error = Some(format!("benchmark task failed: {error}")),
            Err(_) => run_error = Some("timed out waiting for benchmark cancellation".into()),
            Ok(Ok(Ok(()))) => {}
        }
    }
    if let Some(error) = run_error {
        anyhow::bail!(error);
    }
    Ok(())
}

fn stop_or_force_quit(
    app: &mut App,
    cancellation: &mut Option<oneshot::Sender<()>>,
    task: Option<&JoinHandle<Result<()>>>,
    quit: &mut bool,
) {
    if app.cancelling {
        if let Some(task) = task {
            task.abort();
        }
        *quit = true;
    } else if let Some(cancel) = cancellation.take() {
        let _ = cancel.send(());
        app.cancelling = true;
    }
}

fn generated_run_id() -> String {
    rand::random::<[u8; 16]>()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

const MIN_TERMINAL_WIDTH: u16 = 40;
const MIN_TERMINAL_HEIGHT: u16 = 12;

fn render(frame: &mut Frame<'_>, app: &App) {
    let area = frame.area();
    if area.width < MIN_TERMINAL_WIDTH || area.height < MIN_TERMINAL_HEIGHT {
        frame.render_widget(
            Paragraph::new(format!(
                "Terminal too small\nMinimum: {MIN_TERMINAL_WIDTH}x{MIN_TERMINAL_HEIGHT}\nCurrent: {}x{}",
                area.width, area.height
            ))
            .wrap(Wrap { trim: false }),
            area,
        );
        return;
    }
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(3),
        ])
        .split(area);
    frame.render_widget(
        Paragraph::new("meshmsg benchmark")
            .style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
            .block(Block::default().borders(Borders::ALL)),
        chunks[0],
    );
    match app.view {
        View::Setup => render_setup(frame, chunks[1], app),
        View::Running | View::Result => render_metrics(frame, chunks[1], app),
    }
    let help = match app.view {
        View::Setup => "↑/↓ or Tab: field  ←/→: role  Enter: start  q: quit",
        View::Running => {
            if app.cancelling {
                "Cancelling… q/Esc/Ctrl-C again: force quit"
            } else {
                "q/Esc/Ctrl-C: stop and retain final summary"
            }
        }
        View::Result => "r/Enter: configure another run  q: quit",
    };
    frame.render_widget(
        Paragraph::new(help).block(Block::default().borders(Borders::ALL).title("Keys")),
        chunks[2],
    );
}

fn render_setup(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let role = match app.role {
        Role::Sender => "sender",
        Role::Receiver => "receiver",
    };
    let mut fields = vec![("Role", role.to_owned()), ("Run ID", app.run_id.clone())];
    match app.role {
        Role::Sender => fields.extend([
            ("Rate (messages/s)", app.sender_rate.clone()),
            ("Duration (seconds)", app.sender_duration.clone()),
            ("Payload (bytes)", app.payload_bytes.clone()),
        ]),
        Role::Receiver => fields.extend([
            ("Duration (seconds)", app.receiver_duration.clone()),
            (
                "Expected count (optional)",
                if app.expected.is_empty() {
                    "unknown".into()
                } else {
                    app.expected.clone()
                },
            ),
        ]),
    }
    let items = fields
        .into_iter()
        .enumerate()
        .map(|(index, (label, value))| {
            let marker = if index == app.selected { ">" } else { " " };
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!("{marker} {label}: "),
                    Style::default().fg(Color::Yellow),
                ),
                Span::raw(value),
            ]))
        });
    let title = match &app.error {
        Some(error) => format!("Configure — {error}"),
        None => "Configure".into(),
    };
    frame.render_widget(
        List::new(items).block(Block::default().borders(Borders::ALL).title(title)),
        area,
    );
}

fn render_metrics(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let mut lines = Vec::new();
    if let Some(value) = &app.latest {
        lines.push(Line::from(format!(
            "Run: {}   elapsed: {} ms",
            text(value, "run_id", "unknown"),
            number(value, "elapsed_ms")
        )));
        match app.role {
            Role::Sender => {
                lines.push(Line::from(format!(
                    "attempted {} / planned {}   queued {}   failed {}",
                    number(value, "attempted"),
                    number(value, "planned"),
                    number(value, "queued"),
                    number(value, "failed")
                )));
                lines.push(Line::from(format!(
                    "schedule missed: {}   achieved: {:.2} messages/s, {:.2} body bytes/s",
                    number(value, "schedule_missed"),
                    value["achieved_messages_per_second"]
                        .as_f64()
                        .unwrap_or(0.0),
                    value["achieved_body_bytes_per_second"]
                        .as_f64()
                        .unwrap_or(0.0)
                )));
                lines.push(Line::from(Span::styled(
                    "Local queue acceptance only; delivery is not acknowledged.",
                    Style::default().fg(Color::Yellow),
                )));
            }
            Role::Receiver => {
                let missing = value["missing"]
                    .as_u64()
                    .map_or_else(|| "unknown".into(), |count| count.to_string());
                lines.push(Line::from(format!(
                    "unique {}   missing so far {}   duplicates {}   out of order {}",
                    number(value, "unique"),
                    missing,
                    number(value, "duplicates"),
                    number(value, "out_of_order")
                )));
                lines.push(Line::from(format!(
                    "throughput: {:.2} messages/s, {:.2} body bytes/s   latency p50/p95/p99: {}/{}/{} ms",
                    value["achieved_messages_per_second"]
                        .as_f64()
                        .unwrap_or(0.0),
                    value["achieved_body_bytes_per_second"]
                        .as_f64()
                        .unwrap_or(0.0),
                    optional_number(&value["latency"]["p50_ms"]),
                    optional_number(&value["latency"]["p95_ms"]),
                    optional_number(&value["latency"]["p99_ms"]),
                )));
                let lag = value["lag"]["incomplete"].as_bool().unwrap_or(false);
                lines.push(Line::from(format!(
                    "lag incomplete: {} (local events {}, dropped {}; gossip events {})",
                    yes_no(lag),
                    number(&value["lag"], "local_events"),
                    number(&value["lag"], "local_dropped"),
                    number(&value["lag"], "gossip_events")
                )));
                lines.push(Line::from(format!(
                    "clock-invalid latency: {}   malformed matching: {}",
                    number(&value["latency"], "clock_invalid"),
                    number(value, "malformed_messages")
                )));
                if value["type"] == "bench_receive_summary" {
                    lines.push(Line::from(format!(
                        "complete: {}   measurement valid: {}",
                        yes_no(value["complete"].as_bool().unwrap_or(false)),
                        yes_no(value["measurement_valid"].as_bool().unwrap_or(false))
                    )));
                }
            }
        }
        if let Some(reason) = value["completion_reason"].as_str() {
            lines.push(Line::from(format!("Completion: {reason}")));
        }
    } else {
        lines.push(Line::from("Connecting to the local daemon…"));
    }
    if let Some(error) = &app.error {
        lines.push(Line::from(Span::styled(
            format!("Error: {error}"),
            Style::default().fg(Color::Red),
        )));
    }
    let title = if app.view == View::Result {
        "Result"
    } else {
        "Running"
    };
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(Block::default().borders(Borders::ALL).title(title)),
        area,
    );
}

fn text<'a>(value: &'a Value, key: &str, fallback: &'a str) -> &'a str {
    value[key].as_str().unwrap_or(fallback)
}

fn number(value: &Value, key: &str) -> u64 {
    value[key].as_u64().unwrap_or(0)
}

fn optional_number(value: &Value) -> String {
    value.as_u64().map_or_else(|| "–".into(), |n| n.to_string())
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;

    fn rendered(app: &App, width: u16, height: u16) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| render(frame, app)).unwrap();
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect()
    }

    #[test]
    fn defaults_are_valid_sender_configuration() {
        let app = App::default();
        let Config::Sender {
            rate,
            duration_secs,
            payload_bytes,
            ..
        } = app.validate().unwrap()
        else {
            panic!("expected sender")
        };
        assert_eq!((rate, duration_secs, payload_bytes), (100, 10, 256));
        assert_eq!(app.run_id.len(), 32);
    }

    #[test]
    fn sender_uses_authoritative_payload_boundary() {
        let mut app = App::default();
        let maximum = (106..=4096)
            .rev()
            .find(|payload| {
                node::validate_bench_sender_config(&app.run_id, 100, 10, *payload).is_ok()
            })
            .unwrap();
        app.payload_bytes = maximum.to_string();
        assert!(app.validate().is_ok());
        app.payload_bytes = (maximum + 1).to_string();
        assert!(app.validate().is_err());
    }

    #[test]
    fn receiver_allows_unknown_expected_and_enforces_bounds() {
        let mut app = App {
            role: Role::Receiver,
            ..App::default()
        };
        assert!(matches!(
            app.validate().unwrap(),
            Config::Receiver { expected: None, .. }
        ));
        app.expected = "10000001".into();
        assert!(app.validate().is_err());
    }

    #[test]
    fn editing_accepts_only_bounded_ascii_for_benchmark_fields() {
        let mut app = App {
            selected: 2,
            ..App::default()
        };
        app.sender_rate.clear();
        app.edit(KeyCode::Char('二'));
        app.edit(KeyCode::Char('7'));
        assert_eq!(app.sender_rate, "7");
        app.selected = 1;
        app.run_id.clear();
        for character in "ABCDEFghijklmnopqrstuvwxyz0123456789abcdef0123456789".chars() {
            app.edit(KeyCode::Char(character));
        }
        assert!(app.run_id.len() <= 32);
        assert!(app.run_id.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }

    #[test]
    fn second_stop_request_forces_quit() {
        let mut app = App {
            view: View::Running,
            cancelling: true,
            ..App::default()
        };
        let mut cancellation = None;
        let mut quit = false;
        stop_or_force_quit(&mut app, &mut cancellation, None, &mut quit);
        assert!(quit);
    }

    #[test]
    fn tiny_terminal_renders_resize_guidance() {
        let output = rendered(&App::default(), 20, 5);
        assert!(output.contains("Terminal too small"));
        assert!(output.contains("Minimum: 40x12"));

        let resized = rendered(&App::default(), 80, 24);
        assert!(resized.contains("Configure"));
        assert!(!resized.contains("Terminal too small"));
    }

    #[test]
    fn renders_receiver_validity_and_lag_on_narrow_backend() {
        let app = App {
            role: Role::Receiver,
            view: View::Result,
            latest: Some(serde_json::json!({
                "type":"bench_receive_summary", "run_id":"0123456789abcdef0123456789abcdef",
                "elapsed_ms":1000, "unique":9, "missing":1, "duplicates":2,
                "out_of_order":3, "achieved_messages_per_second":9.0,
                "latency":{"p50_ms":1,"p95_ms":2,"p99_ms":3,"clock_invalid":1},
                "lag":{"incomplete":true,"local_events":1,"local_dropped":4,"gossip_events":0},
                "malformed_messages":0, "complete":false, "measurement_valid":false,
                "completion_reason":"deadline"
            })),
            ..App::default()
        };
        let output = rendered(&app, 48, 24);
        assert!(output.contains("measurement valid: no"));
        assert!(output.contains("lag incomplete: yes"));
    }

    #[test]
    fn renders_sender_delivery_disclaimer() {
        let app = App {
            view: View::Running,
            latest: Some(serde_json::json!({
                "type":"bench_send_progress", "run_id":"0123456789abcdef0123456789abcdef",
                "elapsed_ms":500, "attempted":50, "planned":1000, "queued":49,
                "failed":1, "schedule_missed":2, "achieved_messages_per_second":98.0
            })),
            ..App::default()
        };
        let output = rendered(&app, 80, 14);
        assert!(output.contains("delivery is not acknowledged"));
        assert!(output.contains("schedule missed: 2"));
    }
}
