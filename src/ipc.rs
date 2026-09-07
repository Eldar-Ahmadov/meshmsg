//! Shared bounded newline-delimited local daemon protocol. Platform connection
//! ownership checks remain in node::connect_daemon for both CLI and web clients.
use crate::node::{connect_daemon, LocalClientStream};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

// JSON may escape each envelope byte as six ASCII bytes.
pub(crate) const MAX_IPC_REQUEST_SIZE: usize = 4096 * 6 + 1024;
// A complete, non-paginated directory can contain the bounded maximum of 1024
// remote identities. Individual live events remain tiny reconstructed objects,
// while this hard frame limit accommodates the proven worst-case snapshot.
pub(crate) const MAX_IPC_EVENT_SIZE: usize = 512 * 1024;
pub(crate) const PRIVATE_SEND_CAPABILITY: &str = "private_send_v1";
pub(crate) const WEB_DOWNLOAD_CAPABILITY: &str = "web_download_v1";
pub(crate) const WEB_SHARE_CAPABILITY: &str = "web_share_v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct BenchConfig {
    pub(crate) run_id: String,
    pub(crate) rate: u32,
    pub(crate) duration_secs: u64,
    pub(crate) payload_bytes: usize,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum IpcRequest {
    Send {
        body: String,
    },
    PrivateSend {
        to: String,
        body: String,
    },
    BenchSend {
        config: BenchConfig,
    },
    Subscribe,
    Status,
    Peers,
    Offers,
    Share {
        path: PathBuf,
    },
    Download {
        offer: String,
        output: PathBuf,
    },
    /// Export the verified offered blob without interpreting it. Used by the
    /// local web bridge with a server-selected temporary output path.
    WebDownload {
        offer: String,
        output: PathBuf,
    },
    Stop,
}

pub(crate) async fn read_frame<S>(stream: &mut S, maximum: usize) -> Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut frame = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        let read = stream.read(&mut byte).await.context("read daemon socket")?;
        anyhow::ensure!(read != 0, "daemon socket closed before a complete response");
        if byte[0] == b'\n' {
            break;
        }
        anyhow::ensure!(
            frame.len() < maximum,
            "local IPC frame exceeds {maximum} bytes"
        );
        frame.push(byte[0]);
    }
    Ok(frame)
}

pub(crate) async fn write_value<S>(stream: &mut S, value: &serde_json::Value) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let mut encoded = serde_json::to_vec(value)?;
    anyhow::ensure!(
        encoded.len() <= MAX_IPC_EVENT_SIZE,
        "local IPC event exceeds {MAX_IPC_EVENT_SIZE} bytes"
    );
    encoded.push(b'\n');
    stream
        .write_all(&encoded)
        .await
        .context("write daemon socket")?;
    Ok(())
}

pub(crate) async fn send_request(dir: &Path, request: &IpcRequest) -> Result<serde_json::Value> {
    let mut stream = connect_daemon(dir).await?;
    write_request(&mut stream, request).await?;
    let frame = read_frame(&mut stream, MAX_IPC_EVENT_SIZE).await?;
    serde_json::from_slice(&frame).context("invalid response from local daemon")
}

fn json_kind(value: Option<&serde_json::Value>) -> &'static str {
    match value {
        None => "missing",
        Some(serde_json::Value::Null) => "null",
        Some(serde_json::Value::Bool(_)) => "boolean",
        Some(serde_json::Value::Number(_)) => "number",
        Some(serde_json::Value::String(_)) => "string",
        Some(serde_json::Value::Array(_)) => "array",
        Some(serde_json::Value::Object(_)) => "object",
    }
}

const MAX_DIAGNOSTIC_CHARS: usize = 80;

fn diagnostic_string(value: Option<&serde_json::Value>, fallback: &str) -> String {
    match value.and_then(serde_json::Value::as_str) {
        Some(text) => {
            let mut chars = text.chars();
            let mut quoted = String::from("\"");
            for character in chars.by_ref().take(MAX_DIAGNOSTIC_CHARS) {
                match character {
                    '\"' => quoted.push_str("\\\""),
                    '\\' => quoted.push_str("\\\\"),
                    '\u{8}' => quoted.push_str("\\b"),
                    '\u{c}' => quoted.push_str("\\f"),
                    '\n' => quoted.push_str("\\n"),
                    '\r' => quoted.push_str("\\r"),
                    '\t' => quoted.push_str("\\t"),
                    control if control.is_control() => {
                        use std::fmt::Write as _;
                        write!(quoted, "\\u{:04x}", control as u32).unwrap();
                    }
                    visible => quoted.push(visible),
                }
            }
            quoted.push('\"');
            if chars.next().is_some() {
                quoted.push('…');
            }
            quoted
        }
        None => fallback.to_owned(),
    }
}

fn observed_string(value: Option<&serde_json::Value>) -> String {
    diagnostic_string(value, json_kind(value))
}

pub(crate) fn daemon_error_message(value: &serde_json::Value) -> String {
    diagnostic_string(value.get("message"), "unknown error")
}

/// Validate the common response envelope before command-specific code consumes it.
/// A missing schema version is intentional for the original, unversioned IPC replies.
/// Diagnostics include only bounded, escaped discriminators and never serialize
/// the complete response, which may contain message or token data.
pub(crate) fn validate_response(
    value: &serde_json::Value,
    expected_type: &str,
    expected_schema_version: Option<u64>,
) -> Result<()> {
    if value.get("type").and_then(serde_json::Value::as_str) == Some("error") {
        anyhow::bail!("daemon rejected request: {}", daemon_error_message(value));
    }
    let response_type = value.get("type");
    anyhow::ensure!(
        response_type.and_then(serde_json::Value::as_str) == Some(expected_type),
        "daemon returned unexpected response type (expected {expected_type}, observed {})",
        observed_string(response_type)
    );
    if let Some(version) = expected_schema_version {
        let observed_version = value.get("schema_version");
        anyhow::ensure!(
            observed_version.and_then(serde_json::Value::as_u64) == Some(version),
            "daemon returned unsupported {expected_type} response version (expected {version}, observed {})",
            observed_version
                .and_then(serde_json::Value::as_u64)
                .map_or_else(|| observed_string(observed_version), |value| value.to_string())
        );
    }
    Ok(())
}

pub(crate) async fn send_request_checked(
    dir: &Path,
    request: &IpcRequest,
    expected_type: &str,
    expected_schema_version: Option<u64>,
) -> Result<serde_json::Value> {
    let value = send_request(dir, request).await?;
    validate_response(&value, expected_type, expected_schema_version)?;
    Ok(value)
}

pub(crate) async fn write_request<S: AsyncWrite + Unpin>(
    stream: &mut S,
    request: &IpcRequest,
) -> Result<()> {
    let mut encoded = serde_json::to_vec(request)?;
    anyhow::ensure!(
        encoded.len() <= MAX_IPC_REQUEST_SIZE,
        "local IPC request is too large"
    );
    encoded.push(b'\n');
    stream.write_all(&encoded).await?;
    Ok(())
}

pub(crate) struct SubscriptionReader<S> {
    reader: BufReader<S>,
    frame: Vec<u8>,
}

impl<S: AsyncRead + Unpin> SubscriptionReader<S> {
    pub(crate) fn new(stream: S) -> Self {
        Self {
            reader: BufReader::new(stream),
            frame: Vec::new(),
        }
    }

    pub(crate) fn get_mut(&mut self) -> &mut S {
        self.reader.get_mut()
    }

    /// Reads one event while retaining any bytes consumed if this future is
    /// cancelled by a competing `select!` branch.
    pub(crate) async fn read(&mut self) -> Result<Option<serde_json::Value>> {
        let limit = MAX_IPC_EVENT_SIZE + 2;
        anyhow::ensure!(self.frame.len() < limit, "daemon event is too large");
        let remaining = limit - self.frame.len();
        let read = (&mut self.reader)
            .take(remaining as u64)
            .read_until(b'\n', &mut self.frame)
            .await?;
        if read == 0 && self.frame.is_empty() {
            return Ok(None);
        }
        anyhow::ensure!(
            self.frame.len() <= MAX_IPC_EVENT_SIZE + 1,
            "daemon event is too large"
        );
        anyhow::ensure!(self.frame.ends_with(b"\n"), "incomplete daemon event");
        let value = serde_json::from_slice(&self.frame).context("invalid daemon event")?;
        self.frame.clear();
        Ok(Some(value))
    }
}

pub(crate) async fn subscribe(dir: &Path) -> Result<SubscriptionReader<LocalClientStream>> {
    let mut stream = connect_daemon(dir).await?;
    let mut request = serde_json::to_vec(&IpcRequest::Subscribe)?;
    request.push(b'\n');
    stream.write_all(&request).await?;
    Ok(SubscriptionReader::new(stream))
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_response_validation_rejects_errors_wrong_types_and_versions() {
        let error = validate_response(
            &serde_json::json!({
                "type":"error", "message":"useful\n\u{1b}[31m", "body":"secret"
            }),
            "queued",
            None,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("useful\\n\\u001b[31m"));
        assert!(!error.contains('\n'));
        assert!(!error.contains("secret"));

        let c1 = observed_string(Some(&serde_json::json!("left\u{009b}right")));
        assert_eq!(c1, "\"left\\u009bright\"");
        assert!(!c1.chars().any(char::is_control));

        let long_observed = observed_string(Some(&serde_json::json!(
            "x".repeat(MAX_DIAGNOSTIC_CHARS + 1)
        )));
        assert_eq!(long_observed, format!("\"{}\"…", "x".repeat(80)));

        let long_message = "x".repeat(MAX_DIAGNOSTIC_CHARS + 500);
        let long_error = validate_response(
            &serde_json::json!({"type":"error", "message":long_message}),
            "queued",
            None,
        )
        .unwrap_err()
        .to_string();
        assert!(long_error.ends_with('…'));
        assert!(long_error.len() < 250);

        for value in [
            serde_json::json!({"type":"unexpected"}),
            serde_json::json!({"type":"status"}),
            serde_json::json!({"message":"success-shaped but untyped"}),
        ] {
            assert!(validate_response(&value, "queued", None).is_err());
        }
        let wrong_version = validate_response(
            &serde_json::json!({"type":"offers", "schema_version":2, "body":"secret"}),
            "offers",
            Some(1),
        )
        .unwrap_err()
        .to_string();
        assert!(wrong_version.contains("expected 1, observed 2"));
        assert!(!wrong_version.contains("secret"));
        let wrong_type = validate_response(
            &serde_json::json!({"type":"wrong\nforged", "body":"secret"}),
            "offers",
            Some(1),
        )
        .unwrap_err()
        .to_string();
        assert!(wrong_type.contains("observed \"wrong\\nforged\""));
        assert!(!wrong_type.contains("secret"));
        validate_response(
            &serde_json::json!({"type":"offers", "schema_version":1}),
            "offers",
            Some(1),
        )
        .unwrap();
    }

    #[tokio::test]
    async fn subscription_preserves_frames_and_handles_clean_eof() {
        let data = b"{\"type\":\"connected\"}\n{\"type\":\"message\",\"body\":\"a\\nb\"}\n";
        let mut reader = SubscriptionReader::new(&data[..]);
        assert_eq!(reader.read().await.unwrap().unwrap()["type"], "connected");
        assert_eq!(reader.read().await.unwrap().unwrap()["body"], "a\nb");
        assert!(reader.read().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn subscription_rejects_incomplete_and_oversized_frames_before_eof() {
        let mut incomplete = SubscriptionReader::new(&b"{\"type\":\"connected\"}"[..]);
        assert!(incomplete
            .read()
            .await
            .unwrap_err()
            .to_string()
            .contains("incomplete"));
        let (mut writer, reader) = tokio::io::duplex(MAX_IPC_EVENT_SIZE + 2);
        writer
            .write_all(&vec![b'x'; MAX_IPC_EVENT_SIZE + 2])
            .await
            .unwrap();
        // Writer deliberately stays open. The bound must not depend on EOF/newline.
        let mut reader = SubscriptionReader::new(reader);
        let error = tokio::time::timeout(std::time::Duration::from_secs(1), reader.read())
            .await
            .unwrap()
            .unwrap_err();
        assert!(error.to_string().contains("too large"));
    }

    #[tokio::test]
    async fn subscription_retains_partial_frame_when_select_cancels_read() {
        let (mut writer, stream) = tokio::io::duplex(64);
        let mut reader = SubscriptionReader::new(stream);
        writer.write_all(b"{\"type\":\"mes").await.unwrap();

        tokio::select! {
            result = reader.read() => panic!("partial frame unexpectedly completed: {result:?}"),
            _ = tokio::time::sleep(std::time::Duration::from_millis(10)) => {}
        }

        writer
            .write_all(b"sage\",\"body\":\"ok\"}\n")
            .await
            .unwrap();
        let event = reader.read().await.unwrap().unwrap();
        assert_eq!(event["type"], "message");
        assert_eq!(event["body"], "ok");
    }

    #[tokio::test]
    async fn request_wire_format_and_bounds_remain_compatible() {
        let mut bytes = Vec::new();
        write_request(
            &mut bytes,
            &IpcRequest::Send {
                body: "a\nb".into(),
            },
        )
        .await
        .unwrap();
        assert_eq!(bytes, b"{\"command\":\"send\",\"body\":\"a\\nb\"}\n");
        assert!(write_request(
            &mut bytes,
            &IpcRequest::Send {
                body: "x".repeat(MAX_IPC_REQUEST_SIZE),
            }
        )
        .await
        .is_err());
    }

    #[tokio::test]
    async fn web_download_is_a_distinct_raw_export_command() {
        let mut bytes = Vec::new();
        write_request(
            &mut bytes,
            &IpcRequest::WebDownload {
                offer: "signed-offer".into(),
                output: PathBuf::from("server-selected.blob"),
            },
        )
        .await
        .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["command"], "web_download");
        assert_eq!(value["offer"], "signed-offer");
        assert_eq!(value["output"], "server-selected.blob");
    }

    #[tokio::test]
    async fn peers_uses_a_distinct_fieldless_wire_command() {
        let mut bytes = Vec::new();
        write_request(&mut bytes, &IpcRequest::Peers).await.unwrap();
        assert_eq!(bytes, b"{\"command\":\"peers\"}\n");

        #[allow(dead_code)]
        #[derive(Deserialize)]
        #[serde(tag = "command", rename_all = "snake_case")]
        enum LegacyRequest {
            Send { body: String },
            Status,
        }
        assert!(serde_json::from_slice::<LegacyRequest>(&bytes).is_err());
    }

    #[tokio::test]
    async fn private_send_uses_a_distinct_wire_command_rejected_by_legacy_daemons() {
        let mut bytes = Vec::new();
        write_request(
            &mut bytes,
            &IpcRequest::PrivateSend {
                to: "peer".into(),
                body: "private text".into(),
            },
        )
        .await
        .unwrap();
        assert_eq!(
            bytes,
            b"{\"command\":\"private_send\",\"to\":\"peer\",\"body\":\"private text\"}\n"
        );

        #[allow(dead_code)]
        #[derive(Deserialize)]
        #[serde(tag = "command", rename_all = "snake_case")]
        enum LegacyRequest {
            Send { body: String },
            Status,
        }

        assert!(serde_json::from_slice::<LegacyRequest>(&bytes).is_err());
    }

    #[test]
    fn ambiguous_legacy_send_with_recipient_is_rejected() {
        let ambiguous = br#"{"command":"send","body":"private text","to":"peer"}"#;
        assert!(serde_json::from_slice::<IpcRequest>(ambiguous).is_err());
        assert!(matches!(
            serde_json::from_slice::<IpcRequest>(br#"{"command":"send","body":"broadcast"}"#)
                .unwrap(),
            IpcRequest::Send { body } if body == "broadcast"
        ));
    }
}
