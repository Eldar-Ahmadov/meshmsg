//! Shared bounded newline-delimited local daemon protocol. Platform connection
//! ownership checks remain in node::connect_daemon for both CLI and web clients.
use crate::node::{connect_daemon, LocalClientStream};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

// JSON may escape each envelope byte as six ASCII bytes.
pub(crate) const MAX_IPC_REQUEST_SIZE: usize = 4096 * 6 + 1024;
pub(crate) const MAX_IPC_EVENT_SIZE: usize = MAX_IPC_REQUEST_SIZE;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct BenchConfig {
    pub(crate) run_id: String,
    pub(crate) rate: u32,
    pub(crate) duration_secs: u64,
    pub(crate) payload_bytes: usize,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub(crate) enum IpcRequest {
    Send { body: String },
    BenchSend { config: BenchConfig },
    Subscribe,
    Status,
    Offers,
    Share { path: PathBuf },
    Download { offer: String, output: PathBuf },
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

pub(crate) async fn subscribe(dir: &Path) -> Result<BufReader<LocalClientStream>> {
    let mut stream = connect_daemon(dir).await?;
    let mut request = serde_json::to_vec(&IpcRequest::Subscribe)?;
    request.push(b'\n');
    stream.write_all(&request).await?;
    Ok(BufReader::new(stream))
}

pub(crate) async fn read_subscription<S: AsyncRead + Unpin>(
    reader: &mut BufReader<S>,
) -> Result<Option<serde_json::Value>> {
    let mut line = Vec::new();
    let read = reader
        .take((MAX_IPC_EVENT_SIZE + 2) as u64)
        .read_until(b'\n', &mut line)
        .await?;
    if read == 0 {
        return Ok(None);
    }
    anyhow::ensure!(
        line.len() <= MAX_IPC_EVENT_SIZE + 1,
        "daemon event is too large"
    );
    anyhow::ensure!(line.ends_with(b"\n"), "incomplete daemon event");
    Ok(Some(
        serde_json::from_slice(&line).context("invalid daemon event")?,
    ))
}
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn subscription_preserves_frames_and_handles_clean_eof() {
        let data = b"{\"type\":\"connected\"}\n{\"type\":\"message\",\"body\":\"a\\nb\"}\n";
        let mut reader = BufReader::new(&data[..]);
        assert_eq!(
            read_subscription(&mut reader).await.unwrap().unwrap()["type"],
            "connected"
        );
        assert_eq!(
            read_subscription(&mut reader).await.unwrap().unwrap()["body"],
            "a\nb"
        );
        assert!(read_subscription(&mut reader).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn subscription_rejects_incomplete_and_oversized_frames_before_eof() {
        let mut incomplete = BufReader::new(&b"{\"type\":\"connected\"}"[..]);
        assert!(read_subscription(&mut incomplete)
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
        let error = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            read_subscription(&mut BufReader::new(reader)),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert!(error.to_string().contains("too large"));
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
                body: "x".repeat(MAX_IPC_REQUEST_SIZE)
            }
        )
        .await
        .is_err());
    }
}
