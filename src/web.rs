//! Unauthenticated loopback HTTP bridge. Tailscale Serve is the access boundary;
//! Host/Origin checks defend browsers, not hostile local or authorized clients.
use crate::ipc::{self, IpcRequest};
use anyhow::{Context, Result};
use bytes::Bytes;
use futures_util::stream;
use http_body_util::{combinators::BoxBody, BodyExt, Full, Limited, StreamBody};
use hyper::{
    body::{Frame, Incoming},
    header::{HeaderMap, HeaderValue},
    server::conn::http1,
    service::service_fn,
    Method, Request, Response, StatusCode, Uri,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    convert::Infallible,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    net::TcpListener,
    sync::{mpsc, Semaphore},
    time::timeout,
};

type Body = BoxBody<Bytes, Infallible>;
const REQUEST_LIMIT: usize = ipc::MAX_IPC_REQUEST_SIZE;
const IPC_TIMEOUT: Duration = Duration::from_secs(8);
const SEND_INTERVAL: Duration = Duration::from_secs(1);
const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

struct WebState {
    dir: PathBuf,
    origins: Vec<String>,
    subscriptions: Arc<Semaphore>,
    requests: Semaphore,
    last_send: Mutex<Option<Instant>>,
}

impl WebState {
    fn new(dir: &Path, address: SocketAddr, origin: Option<String>) -> Result<Self> {
        anyhow::ensure!(
            address.ip().is_loopback(),
            "web must listen on loopback; use Tailscale Serve for remote access"
        );
        let mut origins = vec![format!("http://{address}")];
        if let Some(origin) = origin {
            let uri: Uri = origin.parse().context("invalid --origin")?;
            anyhow::ensure!(
                uri.scheme_str() == Some("https")
                    && uri.authority().is_some_and(|a| !a.as_str().contains('@'))
                    && uri.authority().is_some_and(|a| origin == format!("https://{a}")),
                "--origin must be an exact HTTPS origin without credentials, path, query or trailing slash"
            );
            origins.push(origin);
        }
        Ok(Self {
            dir: dir.into(),
            origins,
            subscriptions: Arc::new(Semaphore::new(16)),
            requests: Semaphore::new(16),
            last_send: Mutex::new(None),
        })
    }

    fn allowed(&self, headers: &HeaderMap, write: bool) -> bool {
        let Some(host) = single_header(headers, "host") else {
            return false;
        };
        // Never use Forwarded, X-Forwarded-Host/Proto or Tailscale identity headers.
        let supplied_origin = single_header(headers, "origin");
        if headers.contains_key("origin") && supplied_origin.is_none() {
            return false;
        }
        if single_header(headers, "sec-fetch-site") == Some("cross-site") {
            return false;
        }
        self.origins.iter().any(|origin| {
            let authority = origin.split_once("://").unwrap().1;
            host == authority
                && match supplied_origin {
                    Some(supplied) => supplied == origin,
                    None => !write,
                }
        })
    }

    fn take_send(&self, now: Instant) -> bool {
        let mut last = self.last_send.lock().expect("send throttle mutex poisoned");
        if last.is_some_and(|previous| now.duration_since(previous) < SEND_INTERVAL) {
            return false;
        }
        *last = Some(now);
        true
    }
}

fn single_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    Some(value)
}

// Deliberately independent of IpcRequest: new daemon commands cannot become web APIs.
#[derive(Debug, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
enum WebRequest {
    Send { body: String },
    Status {},
}

fn parse_request(bytes: &[u8]) -> Result<WebRequest> {
    let request: WebRequest = serde_json::from_slice(bytes)?;
    if let WebRequest::Send { body } = &request {
        anyhow::ensure!(
            !body.trim().is_empty() && body.len() <= 4096,
            "body must be nonblank and at most 4096 UTF-8 bytes"
        );
    }
    Ok(request)
}

fn response(
    status: StatusCode,
    content_type: &'static str,
    body: impl Into<Bytes>,
) -> Response<Body> {
    let mut response = Response::new(Full::new(body.into()).boxed());
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert("content-type", HeaderValue::from_static(content_type));
    headers.insert("cache-control", HeaderValue::from_static("no-store"));
    headers.insert("content-security-policy", HeaderValue::from_static(CSP));
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    response
}

fn json_response(status: StatusCode, value: Value) -> Response<Body> {
    response(status, "application/json", value.to_string())
}

fn error(status: StatusCode, outcome: &str, message: &str) -> Response<Body> {
    json_response(
        status,
        json!({"type":"error", "outcome":outcome, "message":message}),
    )
}

fn public_status(value: &Value) -> Value {
    let mut result = json!({"type":"status"});
    for key in [
        "peer",
        "running",
        "endpoint_online",
        "topic_joined",
        "neighbors",
    ] {
        if let Some(value) = value.get(key) {
            result[key] = value.clone();
        }
    }
    result
}

async fn api_request(state: &WebState, bytes: &[u8]) -> Response<Body> {
    let request = match parse_request(bytes) {
        Ok(request) => request,
        Err(_) => return error(StatusCode::BAD_REQUEST, "not_sent", "Only send (nonblank body, at most 4096 UTF-8 bytes) and status are supported; no extra fields."),
    };
    let Ok(_permit) = state.requests.try_acquire() else {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "not_sent",
            "Web request capacity reached.",
        );
    };
    let is_send = matches!(&request, WebRequest::Send { .. });
    if is_send && !state.take_send(Instant::now()) {
        return error(
            StatusCode::TOO_MANY_REQUESTS,
            "not_sent",
            "Wait one second before another broadcast.",
        );
    }
    let request = match request {
        WebRequest::Send { body } => IpcRequest::Send { body },
        WebRequest::Status {} => IpcRequest::Status,
    };
    match timeout(IPC_TIMEOUT, ipc::send_request(&state.dir, &request)).await {
        Ok(Ok(value)) if value["type"] == "error" => error(StatusCode::UNPROCESSABLE_ENTITY, "not_sent", value["message"].as_str().unwrap_or("Daemon rejected request.")),
        Ok(Ok(value)) if is_send && value["type"] == "queued" => json_response(StatusCode::OK, json!({"type":"queued", "delivery_acknowledged":false})),
        Ok(Ok(value)) if !is_send && value["type"] == "status" => json_response(StatusCode::OK, public_status(&value)),
        _ if is_send => error(StatusCode::BAD_GATEWAY, "unknown", "Outcome unknown: daemon unavailable or reply lost. It may have queued. Do not blindly resend."),
        _ => error(StatusCode::SERVICE_UNAVAILABLE, "offline", "Daemon offline or unresponsive. Start or restart it separately."),
    }
}

fn sse_frame(value: &Value) -> Bytes {
    // JSON encoding escapes message newlines; untrusted text cannot inject SSE fields.
    Bytes::from(format!("data: {value}\n\n"))
}

fn public_event(value: Value) -> Option<Value> {
    match value["type"].as_str()? {
        "connected" => Some(json!({"type":"connected", "peer":value["peer"]})),
        "message" => Some(
            json!({"type":"message", "from":value["from"], "body":value["body"], "timestamp_ms":value["timestamp_ms"]}),
        ),
        "queued" => Some(json!({
            "type":"queued", "from":value["from"], "body":value["body"],
            "timestamp_ms":value["timestamp_ms"], "delivery_acknowledged":false
        })),
        "attachment_offer" => Some(json!({
            "type":"attachment_offer", "direction":"incoming", "from":value["from"],
            "timestamp_ms":value["timestamp_ms"], "name":value["name"],
            "kind":value["kind"], "size":value["size"]
        })),
        "attachment_shared" => Some(json!({
            "type":"attachment_shared", "direction":"outgoing", "from":value["from"],
            "timestamp_ms":value["timestamp_ms"], "name":value["name"],
            "kind":value["kind"], "size":value["size"]
        })),
        "lagged" => Some(
            json!({"type":"lagged", "message":"Feed gap: daemon dropped events. No history or replay is available."}),
        ),
        "peer_up" | "peer_down" => Some(json!({"type":value["type"], "peer":value["peer"]})),
        _ => None,
    }
}

async fn events(state: Arc<WebState>) -> Response<Body> {
    let Ok(permit) = state.subscriptions.clone().try_acquire_owned() else {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "offline",
            "Too many live feeds.",
        );
    };
    let (tx, rx) = mpsc::channel::<Bytes>(32);
    tokio::spawn(async move {
        let _permit = permit;
        let opened = timeout(IPC_TIMEOUT, async {
            let mut reader = ipc::subscribe(&state.dir).await?;
            let first = ipc::read_subscription(&mut reader)
                .await?
                .context("daemon closed")?;
            anyhow::ensure!(
                first["type"] == "connected",
                "invalid subscription handshake"
            );
            Result::<_>::Ok((reader, first))
        })
        .await;
        let Ok(Ok((mut reader, first))) = opened else {
            let _ = tx.send(sse_frame(&json!({"type":"offline", "message":"Daemon offline. Reconnecting; feed gaps have no history."}))).await;
            return;
        };
        if tx
            .send(sse_frame(&public_event(first).unwrap()))
            .await
            .is_err()
        {
            return;
        }
        let mut heartbeat = tokio::time::interval(Duration::from_secs(10));
        loop {
            // Keep the read future alive across heartbeats: canceling a partial IPC
            // line would silently corrupt framing when the daemon resumes writing.
            let read = ipc::read_subscription(&mut reader);
            tokio::pin!(read);
            let value = loop {
                tokio::select! {
                    value = &mut read => break value,
                    _ = tx.closed() => return,
                    _ = heartbeat.tick() => {
                        if !matches!(timeout(Duration::from_secs(5), tx.send(Bytes::from_static(b": heartbeat\n\n"))).await, Ok(Ok(()))) { return; }
                    }
                }
            };
            let value = match value {
                Ok(Some(value)) => public_event(value),
                _ => {
                    let _ = timeout(Duration::from_secs(5), tx.send(sse_frame(&json!({"type":"offline", "message":"Daemon disconnected. Feed gap; no history. Reconnecting."})))).await;
                    return;
                }
            };
            if let Some(value) = value {
                if !matches!(
                    timeout(Duration::from_secs(5), tx.send(sse_frame(&value))).await,
                    Ok(Ok(()))
                ) {
                    return;
                }
            }
        }
    });
    let stream = stream::unfold(rx, |mut rx| async move {
        rx.recv()
            .await
            .map(|bytes| (Ok::<_, Infallible>(Frame::data(bytes)), rx))
    });
    let mut response = response(StatusCode::OK, "text/event-stream", Bytes::new());
    response
        .headers_mut()
        .insert("x-accel-buffering", HeaderValue::from_static("no"));
    *response.body_mut() = BodyExt::boxed(StreamBody::new(stream));
    response
}

async fn route(
    request: Request<Incoming>,
    state: Arc<WebState>,
) -> Result<Response<Body>, Infallible> {
    let write = request.method() != Method::GET;
    if !state.allowed(request.headers(), write) {
        return Ok(error(
            StatusCode::FORBIDDEN,
            "not_sent",
            "Host/Origin rejected.",
        ));
    }
    if request.uri().query().is_some() {
        return Ok(error(StatusCode::NOT_FOUND, "not_sent", "Not found."));
    }
    let result = match (request.method(), request.uri().path()) {
        (&Method::GET, "/") => response(
            StatusCode::OK,
            "text/html; charset=utf-8",
            include_str!("web/index.html"),
        ),
        (&Method::GET, "/app.css") => response(
            StatusCode::OK,
            "text/css; charset=utf-8",
            include_str!("web/app.css"),
        ),
        (&Method::GET, "/app.js") => response(
            StatusCode::OK,
            "text/javascript; charset=utf-8",
            include_str!("web/app.js"),
        ),
        (&Method::GET, "/api/events") => events(state).await,
        (&Method::POST, "/api/request") => {
            if single_header(request.headers(), "content-type") != Some("application/json")
                || request.headers().contains_key("content-encoding")
            {
                error(
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    "not_sent",
                    "Use unencoded application/json.",
                )
            } else {
                match timeout(
                    Duration::from_secs(5),
                    Limited::new(request.into_body(), REQUEST_LIMIT).collect(),
                )
                .await
                {
                    Ok(Ok(body)) => api_request(&state, &body.to_bytes()).await,
                    Ok(Err(_)) => error(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "not_sent",
                        "Request body too large or incomplete.",
                    ),
                    Err(_) => error(
                        StatusCode::REQUEST_TIMEOUT,
                        "not_sent",
                        "Request body timeout.",
                    ),
                }
            }
        }
        _ => error(StatusCode::NOT_FOUND, "not_sent", "Not found."),
    };
    Ok(result)
}

pub(crate) async fn run(dir: &Path, address: SocketAddr, origin: Option<String>) -> Result<()> {
    // Validate before binding; port zero is resolved to the actual listener below.
    WebState::new(dir, address, origin.clone())?;
    let listener = TcpListener::bind(address)
        .await
        .context("bind web listener")?;
    let address = listener.local_addr()?;
    let state = Arc::new(WebState::new(dir, address, origin)?);
    eprintln!("meshmsg web: http://{address} (no app authentication; Tailscale Serve only). Stopping web does not stop daemon.");
    serve(listener, state).await
}

async fn serve(listener: TcpListener, state: Arc<WebState>) -> Result<()> {
    let connections = Arc::new(Semaphore::new(64));
    let mut tasks = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (socket, _) = accepted?;
                let Ok(permit) = connections.clone().try_acquire_owned() else { continue; };
                let state = state.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    let mut builder = http1::Builder::new();
                    builder.timer(TokioTimer::new()).header_read_timeout(Duration::from_secs(5)).max_headers(32).max_buf_size(16 * 1024).keep_alive(false);
                    // Bound slow readers and SSE lifetime as well as idle connections.
                    let _ = timeout(Duration::from_secs(300), builder.serve_connection(TokioIo::new(socket), service_fn(move |request| route(request, state.clone())))).await;
                });
            }
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {},
            _ = tokio::signal::ctrl_c() => break,
        }
    }
    tasks.abort_all();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> WebState {
        WebState::new(
            Path::new("unused"),
            "127.0.0.1:8787".parse().unwrap(),
            Some("https://node.example.ts.net".into()),
        )
        .unwrap()
    }

    fn headers(host: &str, origin: Option<&str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("host", host.parse().unwrap());
        if let Some(origin) = origin {
            headers.insert("origin", origin.parse().unwrap());
        }
        headers
    }

    #[test]
    fn host_origin_pairs_are_explicit_and_forwarded_headers_do_not_authorize() {
        let state = state();
        assert!(state.allowed(&headers("127.0.0.1:8787", None), false));
        assert!(state.allowed(
            &headers("node.example.ts.net", Some("https://node.example.ts.net")),
            true
        ));
        assert!(state.allowed(
            &headers("127.0.0.1:8787", Some("http://127.0.0.1:8787")),
            true
        ));
        for (host, origin) in [
            ("evil.example", None),
            ("127.0.0.1:8787", None),
            ("127.0.0.1:8787", Some("null")),
            ("node.example.ts.net", Some("https://evil.example")),
            ("127.0.0.1:8787", Some("https://node.example.ts.net")),
            ("node.example.ts.net", Some("http://node.example.ts.net")),
        ] {
            let mut headers = headers(host, origin);
            headers.insert("x-forwarded-host", "node.example.ts.net".parse().unwrap());
            headers.insert("x-forwarded-proto", "https".parse().unwrap());
            assert!(!state.allowed(&headers, true));
        }
        let mut duplicate = headers("127.0.0.1:8787", Some("http://127.0.0.1:8787"));
        duplicate.append("origin", "http://127.0.0.1:8787".parse().unwrap());
        assert!(!state.allowed(&duplicate, true));
        let mut duplicate_host = headers("127.0.0.1:8787", None);
        duplicate_host.append("host", "127.0.0.1:8787".parse().unwrap());
        assert!(!state.allowed(&duplicate_host, false));
        assert!(!state.allowed(
            &headers("127.0.0.1:8787", Some("https://evil.example")),
            false
        ));
        let mut cross_site = headers("127.0.0.1:8787", None);
        cross_site.insert("sec-fetch-site", "cross-site".parse().unwrap());
        assert!(!state.allowed(&cross_site, false));
    }

    #[test]
    fn listener_and_public_origin_reject_unsafe_configuration() {
        assert!(WebState::new(Path::new("."), "0.0.0.0:8787".parse().unwrap(), None).is_err());
        for origin in [
            "http://node.example",
            "https://user@node.example",
            "https://node.example/",
            "https://node.example/path",
            "https://node.example?x",
            "null",
        ] {
            assert!(
                WebState::new(
                    Path::new("."),
                    "127.0.0.1:8787".parse().unwrap(),
                    Some(origin.into())
                )
                .is_err(),
                "{origin}"
            );
        }
    }

    #[test]
    fn web_allowlist_is_strict_and_utf8_bounded() {
        for command in [
            "subscribe",
            "stop",
            "share",
            "offers",
            "download",
            "bench_send",
            "init",
            "join",
            "topic",
        ] {
            assert!(parse_request(json!({"command":command}).to_string().as_bytes()).is_err());
        }
        for value in [
            json!({"command":"status", "body":"ignored"}),
            json!({"command":"send", "body":" "}),
            json!({"command":"send", "body":"a", "path":"/etc/passwd"}),
            json!({"command":"send", "body":"二".repeat(1366)}),
        ] {
            assert!(parse_request(value.to_string().as_bytes()).is_err());
        }
        assert!(parse_request(br#"{"command":"send","command":"status","body":"a"}"#).is_err());
        assert!(parse_request(br#"{"command":"status"}"#).is_ok());
        assert!(parse_request(
            json!({"command":"send", "body":"二".repeat(1365)})
                .to_string()
                .as_bytes()
        )
        .is_ok());
    }

    #[test]
    fn sends_are_globally_throttled_without_automatic_retries() {
        let state = state();
        let now = Instant::now();
        assert!(state.take_send(now));
        assert!(!state.take_send(now));
        assert!(!state.take_send(now + Duration::from_millis(999)));
        assert!(state.take_send(now + SEND_INTERVAL));
    }

    #[test]
    fn only_safe_live_metadata_is_exposed_and_sse_newlines_are_escaped() {
        assert!(public_event(json!({"type":"download_progress", "path":"secret"})).is_none());
        let incoming = public_event(json!({
            "type":"attachment_offer", "from":"peer", "timestamp_ms":42,
            "name":"<report>.pdf", "kind":"file", "size":1234,
            "offer_id":"private-id", "offer":"signed-secret", "ticket":"blob-secret",
            "path":"private-path", "output":"private-output"
        }))
        .unwrap();
        assert_eq!(
            incoming,
            json!({
                "type":"attachment_offer", "direction":"incoming", "from":"peer",
                "timestamp_ms":42, "name":"<report>.pdf", "kind":"file", "size":1234
            })
        );
        let outgoing = public_event(json!({
            "type":"attachment_shared", "from":"local", "timestamp_ms":43,
            "name":"folder.tar", "kind":"directory_tar_v1", "size":5678,
            "offer":"signed-secret", "ticket":"blob-secret", "delivery_acknowledged":true
        }))
        .unwrap();
        assert_eq!(
            outgoing,
            json!({
                "type":"attachment_shared", "direction":"outgoing", "from":"local",
                "timestamp_ms":43, "name":"folder.tar", "kind":"directory_tar_v1", "size":5678
            })
        );
        assert!(!incoming.to_string().contains("secret"));
        assert!(!outgoing.to_string().contains("secret"));
        let value = public_event(json!({"type":"message", "body":"<script>\ndata: injected\n", "from":"peer", "private":"secret"})).unwrap();
        let frame = String::from_utf8(sse_frame(&value).to_vec()).unwrap();
        assert_eq!(frame.lines().count(), 2);
        assert!(!frame.contains("secret"));
        let queued = public_event(json!({
            "type":"queued", "from":"local", "body":"hello", "timestamp_ms":42,
            "delivery_acknowledged":true, "private":"secret"
        }))
        .unwrap();
        assert_eq!(
            queued,
            json!({
                "type":"queued", "from":"local", "body":"hello", "timestamp_ms":42,
                "delivery_acknowledged":false
            })
        );
        let status = public_status(
            &json!({"type":"status", "peer":"peer", "socket":"private", "invite":"secret"}),
        );
        assert!(status.get("socket").is_none());
        assert!(status.get("invite").is_none());
    }

    #[test]
    fn embedded_ui_uses_text_rendering_and_restrictive_csp() {
        let js = include_str!("web/app.js");
        assert!(!js.contains("innerHTML"));
        assert!(!js.contains("localStorage"));
        assert!(js.contains("textContent"));
        assert!(js.contains("feed.children.length > 100"));
        let response = response(StatusCode::OK, "text/html", "test");
        assert_eq!(response.headers()["content-security-policy"], CSP);
        assert!(!CSP.contains("unsafe-inline"));
        assert!(!response
            .headers()
            .contains_key("access-control-allow-origin"));
    }
}
