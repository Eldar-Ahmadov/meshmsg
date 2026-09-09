//! Unauthenticated loopback HTTP bridge. Tailscale Serve is the access boundary;
//! Host/Origin checks defend browsers, not hostile local or authorized clients.
use crate::{
    alias::validate_alias,
    attachment::{validate_display_name, AttachmentKind},
    config::prepare_state_dir,
    contracts::{self, ErrorEnvelopeV1},
    direct::MAX_DYNAMIC_PRESENCE_IDENTITIES,
    ipc::{self, IpcRequest, WEB_DOWNLOAD_CAPABILITY, WEB_SHARE_CAPABILITY},
    peers::PEER_LEASE_MS,
};
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
use iroh::PublicKey;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    convert::Infallible,
    fs::{self, File, OpenOptions},
    future::Future,
    net::SocketAddr,
    path::{Path, PathBuf},
    str::FromStr,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime},
};
use tokio::{
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt},
    net::TcpListener,
    sync::{mpsc, Semaphore},
    time::{interval, timeout, Instant as TokioInstant},
};

type Body = BoxBody<Bytes, std::io::Error>;
const REQUEST_LIMIT: usize = ipc::MAX_IPC_REQUEST_SIZE;
const IPC_TIMEOUT: Duration = Duration::from_secs(8);
const HTTP_CONNECTION_LIFETIME: Duration = Duration::from_secs(75 * 60);
const SEND_INTERVAL: Duration = Duration::from_secs(1);
const WEB_SHARE_TIMEOUT: Duration = Duration::from_secs(70 * 60);
const DOWNLOAD_TTL: Duration = Duration::from_secs(10 * 60);
const DOWNLOAD_READY_TTL: Duration = Duration::from_secs(65 * 60);
const WEB_DOWNLOAD_IPC_TIMEOUT: Duration = Duration::from_secs(70 * 60);
const DOWNLOAD_PENDING_TTL: Duration = Duration::from_secs(71 * 60);
const STALE_DOWNLOAD_ROOT_AGE: Duration = Duration::from_secs(3 * 60 * 60);
const RETAINED_UPLOAD_TTL: Duration = STALE_DOWNLOAD_ROOT_AGE;
const MAX_DOWNLOAD_OFFERS: usize = 128;
const MAX_DOWNLOAD_JOBS: usize = 128;
const MAX_DOWNLOADS: usize = 2;
const MAX_UPLOADS: usize = 2;
const MAX_UPLOAD_OPERATIONS: usize = 1024;
const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

#[derive(Clone)]
struct StoredOffer {
    offer_id: String,
    offer: String,
    name: String,
    created: Instant,
}

enum DownloadJob {
    Pending {
        created: Instant,
    },
    Ready {
        path: PathBuf,
        name: String,
        size: u64,
        created: Instant,
    },
    Failed {
        error: ipc::LifecycleErrorV1,
        created: Instant,
    },
}

#[derive(Clone, Eq, PartialEq)]
struct UploadFingerprint {
    name: String,
    size: u64,
    digest: [u8; 32],
}

struct UploadOperation {
    gate: Arc<tokio::sync::Mutex<()>>,
    fingerprint: Option<UploadFingerprint>,
    created: Instant,
}

struct WebState {
    dir: PathBuf,
    origins: Vec<String>,
    subscriptions: Arc<Semaphore>,
    requests: Semaphore,
    downloads: Arc<Semaphore>,
    uploads: Arc<Semaphore>,
    offers: Mutex<HashMap<String, StoredOffer>>,
    jobs: Arc<Mutex<HashMap<String, DownloadJob>>>,
    download_root: PathBuf,
    upload_root: PathBuf,
    upload_operations: Mutex<HashMap<String, UploadOperation>>,
    last_send: Mutex<Option<(String, Instant)>>,
}

fn restrict_download_directory(path: &Path) -> Result<()> {
    fs::create_dir_all(path).context("create web download directory")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .context("restrict web download directory permissions")?;
    }
    Ok(())
}

fn touch_download_root(path: &Path) -> Result<()> {
    restrict_download_directory(path)?;
    let lease = path.join(".lease");
    fs::write(&lease, random_id()).context("refresh web download lease")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(lease, fs::Permissions::from_mode(0o600))
            .context("restrict web download lease permissions")?;
    }
    Ok(())
}

fn prune_upload_root(root: &Path, now: SystemTime) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let stale = entry
            .metadata()
            .ok()
            .and_then(|metadata| metadata.modified().ok())
            .and_then(|modified| now.duration_since(modified).ok())
            .is_some_and(|age| age >= RETAINED_UPLOAD_TTL);
        if stale && entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            let _ = fs::remove_dir_all(path);
        }
    }
}

fn prepare_temporary_root(dir: &Path, parent_name: &str) -> Result<PathBuf> {
    let parent = dir.join(parent_name);
    restrict_download_directory(&parent)?;
    if let Ok(entries) = fs::read_dir(&parent) {
        for entry in entries.flatten() {
            let path = entry.path();
            let stale = fs::metadata(path.join(".lease"))
                .or_else(|_| entry.metadata())
                .ok()
                .and_then(|metadata| metadata.modified().ok())
                .and_then(|modified| modified.elapsed().ok())
                .is_some_and(|age| age >= STALE_DOWNLOAD_ROOT_AGE);
            if stale {
                if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                    let _ = fs::remove_dir_all(path);
                } else {
                    let _ = fs::remove_file(path);
                }
            }
        }
    }
    for _ in 0..4 {
        let process_root = parent.join(random_id());
        match fs::create_dir(&process_root) {
            Ok(()) => {
                touch_download_root(&process_root)?;
                return Ok(process_root);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error).context("create unique web temporary directory"),
        }
    }
    anyhow::bail!("could not allocate a unique web temporary directory")
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
        prepare_state_dir(dir)?;
        let download_root = prepare_temporary_root(dir, "web-downloads-v2")?;
        let upload_root = prepare_temporary_root(dir, "web-uploads-v1")?;
        Ok(Self {
            dir: dir.into(),
            origins,
            subscriptions: Arc::new(Semaphore::new(16)),
            requests: Semaphore::new(16),
            downloads: Arc::new(Semaphore::new(MAX_DOWNLOADS)),
            uploads: Arc::new(Semaphore::new(MAX_UPLOADS)),
            offers: Mutex::new(HashMap::new()),
            jobs: Arc::new(Mutex::new(HashMap::new())),
            download_root,
            upload_root,
            upload_operations: Mutex::new(HashMap::new()),
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

    fn upload_operation_gate(
        &self,
        operation_id: &str,
        now: Instant,
    ) -> Option<Arc<tokio::sync::Mutex<()>>> {
        let mut operations = self
            .upload_operations
            .lock()
            .expect("upload operation mutex poisoned");
        operations.retain(|_, operation| {
            now.duration_since(operation.created) < DOWNLOAD_TTL
                || Arc::strong_count(&operation.gate) > 1
        });
        if let Some(operation) = operations.get(operation_id) {
            return Some(operation.gate.clone());
        }
        if operations.len() >= MAX_UPLOAD_OPERATIONS {
            return None;
        }
        let gate = Arc::new(tokio::sync::Mutex::new(()));
        operations.insert(
            operation_id.to_owned(),
            UploadOperation {
                gate: gate.clone(),
                fingerprint: None,
                created: now,
            },
        );
        Some(gate)
    }

    fn check_upload_fingerprint(
        &self,
        operation_id: &str,
        fingerprint: UploadFingerprint,
        now: Instant,
    ) -> bool {
        let mut operations = self
            .upload_operations
            .lock()
            .expect("upload operation mutex poisoned");
        let Some(operation) = operations.get_mut(operation_id) else {
            return false;
        };
        operation.created = now;
        match &operation.fingerprint {
            Some(expected) => expected == &fingerprint,
            None => {
                operation.fingerprint = Some(fingerprint);
                true
            }
        }
    }

    fn refresh_upload_operation(&self, operation_id: &str, now: Instant) {
        if let Some(operation) = self
            .upload_operations
            .lock()
            .expect("upload operation mutex poisoned")
            .get_mut(operation_id)
        {
            operation.created = now;
        }
    }

    fn take_send(&self, operation_id: &str, now: Instant) -> bool {
        let mut last = self.last_send.lock().expect("send throttle mutex poisoned");
        if last.as_ref().is_some_and(|(previous_id, previous)| {
            previous_id != operation_id && now.duration_since(*previous) < SEND_INTERVAL
        }) {
            return false;
        }
        *last = Some((operation_id.to_owned(), now));
        true
    }

    fn remember_offer(
        &self,
        offer_id: &str,
        offer: &str,
        name: &str,
        now: Instant,
    ) -> Option<String> {
        if !ipc::valid_operation_id(offer_id)
            || offer.is_empty()
            || offer.len() > REQUEST_LIMIT
            || name.is_empty()
        {
            return None;
        }
        let mut offers = self.offers.lock().expect("offer registry mutex poisoned");
        offers.retain(|_, value| now.duration_since(value.created) <= DOWNLOAD_TTL);
        if offers.len() >= MAX_DOWNLOAD_OFFERS {
            let oldest = offers
                .iter()
                .min_by_key(|(_, value)| value.created)
                .map(|(id, _)| id.clone());
            if let Some(id) = oldest {
                offers.remove(&id);
            }
        }
        let id = random_id();
        offers.insert(
            id.clone(),
            StoredOffer {
                offer_id: offer_id.to_owned(),
                offer: offer.to_owned(),
                name: name.to_owned(),
                created: now,
            },
        );
        Some(id)
    }

    fn get_offer(&self, id: &str, now: Instant) -> Option<StoredOffer> {
        if !valid_id(id) {
            return None;
        }
        let mut offers = self.offers.lock().expect("offer registry mutex poisoned");
        offers.retain(|_, value| now.duration_since(value.created) <= DOWNLOAD_TTL);
        offers.get(id).cloned()
    }

    fn prune(&self, now: Instant) {
        self.offers
            .lock()
            .expect("offer registry mutex poisoned")
            .retain(|_, value| now.duration_since(value.created) <= DOWNLOAD_TTL);
        self.prune_jobs(now);
        prune_upload_root(&self.upload_root, SystemTime::now());
    }

    fn prune_jobs(&self, now: Instant) {
        let mut jobs = self.jobs.lock().expect("download jobs mutex poisoned");
        jobs.retain(|_, job| {
            let (created, path, ttl) = match job {
                DownloadJob::Pending { created } => (*created, None, DOWNLOAD_PENDING_TTL),
                DownloadJob::Failed { created, .. } => (*created, None, DOWNLOAD_TTL),
                DownloadJob::Ready { created, path, .. } => {
                    (*created, Some(path), DOWNLOAD_READY_TTL)
                }
            };
            let keep = now.duration_since(created) <= ttl;
            if !keep {
                if let Some(path) = path {
                    let _ = fs::remove_file(path);
                }
            }
            keep
        });
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

enum RequestIdHeader {
    Missing,
    One(String),
    Invalid,
    Duplicate,
}

fn request_id_header(headers: &HeaderMap) -> RequestIdHeader {
    let mut values = headers.get_all("x-meshmsg-request-id").iter();
    let Some(first) = values.next() else {
        return RequestIdHeader::Missing;
    };
    if values.next().is_some() {
        return RequestIdHeader::Duplicate;
    }
    match first.to_str() {
        Ok(value) if contracts::valid_request_id(value) => RequestIdHeader::One(value.to_owned()),
        _ => RequestIdHeader::Invalid,
    }
}

// Deliberately independent of IpcRequest: new daemon commands cannot become web APIs.
#[derive(Debug, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
enum WebRequest {
    Send { operation_id: String, body: String },
    Status {},
    Peers {},
    Download { id: String },
    DownloadStatus { id: String },
}

#[derive(Debug, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct MutationErrorDto {
    #[serde(rename = "type")]
    kind: String,
    schema_version: u8,
    code: String,
    message: String,
    request_id: String,
    operation_id: String,
    retryable: bool,
    outcome: String,
}

impl MutationErrorDto {
    fn parse(value: Value, operation_id: &str) -> Option<Self> {
        ErrorEnvelopeV1::from_value(&value).ok()?;
        let error: Self = serde_json::from_value(value).ok()?;
        (error.kind == "error"
            && error.schema_version == 1
            && error.operation_id == operation_id
            && contracts::valid_request_id(&error.request_id)
            && ipc::valid_operation_id(&error.operation_id)
            && matches!(error.outcome.as_str(), "not_started" | "unknown"))
        .then_some(error)
    }

    fn status(&self) -> StatusCode {
        if self.outcome == "unknown" {
            StatusCode::BAD_GATEWAY
        } else if self.code.ends_with("_busy") || self.code == "operation_capacity" {
            StatusCode::SERVICE_UNAVAILABLE
        } else {
            StatusCode::UNPROCESSABLE_ENTITY
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct QueuedMutationDto {
    #[serde(rename = "type")]
    kind: String,
    schema_version: u8,
    request_id: String,
    operation_id: String,
    from: String,
    message_id: String,
    timestamp_ms: u64,
    body: String,
    delivery_acknowledged: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SharedMutationDto {
    #[serde(rename = "type")]
    kind: String,
    schema_version: u8,
    request_id: String,
    operation_id: String,
    from: String,
    message_id: String,
    timestamp_ms: u64,
    offer_id: String,
    source_digest: String,
    #[serde(rename = "kind")]
    kind_name: AttachmentKind,
    name: String,
    size: u64,
    ticket: String,
    offer: String,
    delivery_acknowledged: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConnectedEventDto {
    #[serde(rename = "type")]
    kind: String,
    schema_version: u8,
    request_id: String,
    peer: String,
    endpoint_online: bool,
    topic_joined: bool,
    alias: Option<String>,
    ipc_capabilities: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MessageEventDto {
    #[serde(rename = "type")]
    kind: String,
    schema_version: u8,
    request_id: String,
    from: String,
    message_id: String,
    timestamp_ms: u64,
    body: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OfferEventDto {
    #[serde(rename = "type")]
    kind: String,
    schema_version: u8,
    request_id: String,
    from: String,
    message_id: String,
    timestamp_ms: u64,
    offer_id: String,
    name: String,
    #[serde(rename = "kind")]
    kind_name: AttachmentKind,
    size: u64,
    ticket: String,
    offer: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LaggedEventDto {
    #[serde(rename = "type")]
    kind: String,
    schema_version: u8,
    request_id: String,
    source: String,
    dropped: Option<u64>,
    message: String,
}

impl SharedMutationDto {
    fn parse(
        value: Value,
        operation_id: &str,
        source_digest: &str,
        name: &str,
        size: u64,
    ) -> Option<Self> {
        let shared: Self = serde_json::from_value(value).ok()?;
        (shared.kind == "attachment_shared"
            && shared.schema_version == 3
            && shared.operation_id == operation_id
            && contracts::valid_request_id(&shared.request_id)
            && shared.message_id == operation_id
            && shared.offer_id == operation_id
            && shared.source_digest == source_digest
            && shared.kind_name == AttachmentKind::File
            && shared.name == name
            && shared.size == size
            && ipc::valid_operation_id(&shared.message_id)
            && ipc::valid_content_digest(&shared.source_digest)
            && !shared.from.is_empty()
            && shared.timestamp_ms != 0
            && !shared.ticket.is_empty()
            && !shared.offer.is_empty()
            && !shared.delivery_acknowledged)
            .then_some(shared)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WebRequestFrame {
    schema_version: u8,
    request_id: String,
    request: WebRequest,
}

fn parse_request(bytes: &[u8]) -> Result<WebRequest> {
    let frame: WebRequestFrame = serde_json::from_slice(bytes)?;
    anyhow::ensure!(
        frame.schema_version == contracts::SCHEMA_VERSION,
        "unsupported HTTP request schema"
    );
    anyhow::ensure!(
        contracts::valid_request_id(&frame.request_id),
        "invalid HTTP request ID"
    );
    if let Ok(expected) = HTTP_REQUEST_ID.try_with(Clone::clone) {
        anyhow::ensure!(
            frame.request_id == expected,
            "HTTP request IDs do not match"
        );
    }
    let request = frame.request;
    match &request {
        WebRequest::Send { operation_id, body } => {
            anyhow::ensure!(
                ipc::valid_operation_id(operation_id),
                "invalid operation ID"
            );
            anyhow::ensure!(
                !body.trim().is_empty() && body.len() <= 4096,
                "body must be nonblank and at most 4096 UTF-8 bytes"
            )
        }
        WebRequest::Download { id } | WebRequest::DownloadStatus { id } => {
            anyhow::ensure!(valid_id(id), "invalid download ID")
        }
        _ => {}
    }
    Ok(request)
}

fn random_id() -> String {
    rand::random::<[u8; 16]>()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn valid_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

tokio::task_local! {
    static HTTP_REQUEST_ID: String;
}

fn http_request_id() -> String {
    HTTP_REQUEST_ID
        .try_with(Clone::clone)
        .unwrap_or_else(|_| contracts::new_request_id())
}

fn response(
    status: StatusCode,
    content_type: &'static str,
    body: impl Into<Bytes>,
) -> Response<Body> {
    let mut response = Response::new(
        Full::new(body.into())
            .map_err(|never| match never {})
            .boxed(),
    );
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
    if let Ok(value) = HeaderValue::from_str(&http_request_id()) {
        headers.insert("x-meshmsg-request-id", value);
    }
    response
}

fn json_response(status: StatusCode, mut value: Value) -> Response<Body> {
    let request_id = http_request_id();
    if value.get("type").and_then(Value::as_str) == Some("error") {
        let code = value
            .get("code")
            .and_then(Value::as_str)
            .filter(|code| contracts::known_error_code(code))
            .unwrap_or("request_failed");
        let outcome = value
            .get("outcome")
            .and_then(Value::as_str)
            .filter(|value| matches!(*value, "not_started" | "unknown" | "partial"))
            .unwrap_or("not_started");
        let retryable = value.get("retryable").and_then(Value::as_bool).unwrap_or(
            status == StatusCode::TOO_MANY_REQUESTS
                || status == StatusCode::SERVICE_UNAVAILABLE
                || status == StatusCode::REQUEST_TIMEOUT
                || outcome == "unknown",
        );
        let mut envelope = ErrorEnvelopeV1::new(
            code,
            value
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("Request failed."),
            outcome,
            retryable,
        );
        envelope.request_id = Some(request_id.clone());
        envelope.operation_id = value
            .get("operation_id")
            .and_then(Value::as_str)
            .filter(|id| ipc::valid_operation_id(id))
            .map(str::to_owned);
        envelope.offer_id = value
            .get("offer_id")
            .and_then(Value::as_str)
            .filter(|id| ipc::valid_operation_id(id))
            .map(str::to_owned);
        envelope.selected_tags = value
            .get("selected_tags")
            .and_then(Value::as_u64)
            .and_then(|count| usize::try_from(count).ok());
        envelope.removed_tags = value
            .get("removed_tags")
            .and_then(Value::as_u64)
            .and_then(|count| usize::try_from(count).ok());
        envelope.quota_bytes_released = value.get("quota_bytes_released").and_then(Value::as_u64);
        value = envelope.into_value();
    } else {
        value = contracts::correlate(value, &request_id);
    }
    response(status, "application/json", value.to_string())
}

fn error(status: StatusCode, outcome: &str, message: &str) -> Response<Body> {
    let code = match status {
        StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY => "invalid_request",
        StatusCode::FORBIDDEN => "request_forbidden",
        StatusCode::NOT_FOUND => "not_found",
        StatusCode::TOO_MANY_REQUESTS => "request_throttled",
        StatusCode::REQUEST_TIMEOUT => "request_timeout",
        StatusCode::PAYLOAD_TOO_LARGE => "payload_too_large",
        StatusCode::UNSUPPORTED_MEDIA_TYPE => "unsupported_media_type",
        StatusCode::RANGE_NOT_SATISFIABLE => "invalid_range",
        StatusCode::SERVICE_UNAVAILABLE => "capacity_or_offline",
        _ => "request_failed",
    };
    json_response(
        status,
        json!({"type":"error", "schema_version":1, "code":code, "outcome":outcome, "message":message}),
    )
}

fn public_status(value: &Value) -> Value {
    let mut result = json!({"type":"status"});
    if let Some(peer) = public_key(&value["peer"]) {
        result["peer"] = peer.into();
    }
    for key in ["running", "endpoint_online", "topic_joined"] {
        if let Some(value) = value[key].as_bool() {
            result[key] = value.into();
        }
    }
    if let Some(neighbors) = value["neighbors"].as_u64() {
        result["neighbors"] = neighbors.into();
    }
    if let Some(capacity) = value["operation_cache_capacity"].as_u64() {
        result["operation_cache_capacity"] = capacity.into();
    }
    if let Some(ttl_ms) = value["operation_cache_ttl_ms"].as_u64() {
        result["operation_cache_ttl_ms"] = ttl_ms.into();
    }
    if let Some(persistent) = value["operation_cache_persistent"].as_bool() {
        result["operation_cache_persistent"] = persistent.into();
    }
    if let Some(retention) = value["attachment_retention_secs"].as_u64() {
        result["attachment_retention_secs"] = retention.into();
    }
    let storage = &value["attachment_storage"];
    let numeric = [
        "tagged_bytes",
        "tagged_blobs",
        "tags",
        "tag_capacity",
        "quota_bytes",
        "available_bytes",
        "min_free_bytes",
        "sampled_at_ms",
    ];
    let booleans = ["pressure", "over_quota", "below_min_free"];
    if numeric.iter().all(|key| storage[*key].as_u64().is_some())
        && booleans.iter().all(|key| storage[*key].as_bool().is_some())
    {
        result["attachment_storage"] = json!({
            "tagged_bytes":storage["tagged_bytes"],
            "tagged_blobs":storage["tagged_blobs"],
            "tags":storage["tags"],
            "tag_capacity":storage["tag_capacity"],
            "quota_bytes":storage["quota_bytes"],
            "available_bytes":storage["available_bytes"],
            "min_free_bytes":storage["min_free_bytes"],
            "sampled_at_ms":storage["sampled_at_ms"],
            "pressure":storage["pressure"],
            "over_quota":storage["over_quota"],
            "below_min_free":storage["below_min_free"]
        });
    }
    result
}

fn public_key(value: &Value) -> Option<&str> {
    let text = value.as_str()?;
    let key = PublicKey::from_str(text).ok()?;
    (key.to_string() == text).then_some(text)
}

fn public_alias(value: &Value) -> Option<Option<&str>> {
    if value.is_null() {
        return Some(None);
    }
    let alias = value.as_str()?;
    validate_alias(alias).ok()?;
    Some(Some(alias))
}

fn public_remote_peer(value: &Value, expected_online: bool) -> Option<Value> {
    let public_key = public_key(&value["public_key"])?;
    let alias = public_alias(&value["alias"])?;
    let online = value["online"].as_bool()?;
    if online != expected_online {
        return None;
    }
    let last_seen_ms = value["last_seen_ms"].as_u64()?;
    let expires_at_ms = value["expires_at_ms"].as_u64()?;
    if expires_at_ms < last_seen_ms || expires_at_ms.saturating_sub(last_seen_ms) > PEER_LEASE_MS {
        return None;
    }
    Some(json!({
        "public_key":public_key, "alias":alias, "online":online,
        "last_seen_ms":last_seen_ms, "expires_at_ms":expires_at_ms
    }))
}

fn directory_position(value: &Value) -> Option<(&str, u64)> {
    let epoch = value["directory_epoch"].as_str()?;
    if epoch.len() != 32
        || !epoch
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return None;
    }
    Some((epoch, value["directory_revision"].as_u64()?))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PeerSourceDto {
    public_key: String,
    alias: Option<String>,
    online: bool,
    last_seen_ms: u64,
    expires_at_ms: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SelfPeerSourceDto {
    public_key: String,
    alias: Option<String>,
    online: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PeersSnapshotSourceDto {
    #[serde(rename = "type")]
    kind: String,
    schema_version: u8,
    request_id: String,
    generated_at_ms: u64,
    directory_epoch: String,
    directory_revision: u64,
    #[serde(rename = "self")]
    self_peer: SelfPeerSourceDto,
    peers: Vec<PeerSourceDto>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PeerTransitionSourceDto {
    #[serde(rename = "type")]
    kind: String,
    schema_version: u8,
    request_id: String,
    directory_epoch: String,
    directory_revision: u64,
    peer: PeerSourceDto,
}

fn public_peers_snapshot(value: &Value) -> Option<Value> {
    let decoded: PeersSnapshotSourceDto = serde_json::from_value(value.clone()).ok()?;
    if decoded.kind != "peers_snapshot"
        || decoded.schema_version != 2
        || !contracts::valid_request_id(&decoded.request_id)
    {
        return None;
    }
    let _validated_shape = (
        decoded.generated_at_ms,
        decoded.directory_epoch,
        decoded.directory_revision,
        decoded.self_peer.public_key,
        decoded.self_peer.alias,
        decoded.self_peer.online,
        decoded.peers.len(),
    );
    for peer in &decoded.peers {
        let _ = (
            &peer.public_key,
            &peer.alias,
            peer.online,
            peer.last_seen_ms,
            peer.expires_at_ms,
        );
    }
    if value["type"] != "peers_snapshot" || value["schema_version"] != 2 {
        return None;
    }
    let generated_at_ms = value["generated_at_ms"].as_u64()?;
    let (directory_epoch, directory_revision) = directory_position(value)?;
    let self_value = &value["self"];
    let self_key = public_key(&self_value["public_key"])?;
    let self_alias = public_alias(&self_value["alias"])?;
    let self_online = self_value["online"].as_bool()?;
    let source = value["peers"].as_array()?;
    if source.len() > MAX_DYNAMIC_PRESENCE_IDENTITIES {
        return None;
    }
    let mut remotes = Vec::with_capacity(source.len());
    let mut previous: Option<String> = None;
    for item in source {
        let peer = public_remote_peer(item, true)?;
        let key = peer["public_key"].as_str()?;
        if key == self_key || previous.as_deref().is_some_and(|previous| previous >= key) {
            return None;
        }
        let last_seen_ms = peer["last_seen_ms"].as_u64()?;
        let expires_at_ms = peer["expires_at_ms"].as_u64()?;
        if last_seen_ms > generated_at_ms
            || expires_at_ms < generated_at_ms
            || expires_at_ms.saturating_sub(generated_at_ms) > PEER_LEASE_MS
        {
            return None;
        }
        previous = Some(key.to_owned());
        remotes.push(peer);
    }
    Some(json!({
        "type":"peers_snapshot", "schema_version":2,
        "generated_at_ms":generated_at_ms,
        "directory_epoch":directory_epoch, "directory_revision":directory_revision,
        "self":{"public_key":self_key, "alias":self_alias, "online":self_online},
        "peers":remotes
    }))
}

fn public_peer_transition(value: &Value, event_type: &str) -> Option<Value> {
    let decoded: PeerTransitionSourceDto = serde_json::from_value(value.clone()).ok()?;
    if decoded.kind != event_type
        || decoded.schema_version != 2
        || !contracts::valid_request_id(&decoded.request_id)
    {
        return None;
    }
    let _validated_shape = (
        decoded.directory_epoch,
        decoded.directory_revision,
        decoded.peer.public_key,
        decoded.peer.alias,
        decoded.peer.online,
        decoded.peer.last_seen_ms,
        decoded.peer.expires_at_ms,
    );
    if value["schema_version"] != 2 {
        return None;
    }
    let expected_online = event_type != "peer_expired";
    let peer = public_remote_peer(&value["peer"], expected_online)?;
    let (directory_epoch, directory_revision) = directory_position(value)?;
    Some(json!({
        "type":event_type, "schema_version":2,
        "directory_epoch":directory_epoch, "directory_revision":directory_revision,
        "peer":peer
    }))
}

async fn bounded_download_ipc<F: Future>(
    future: F,
    limit: Duration,
) -> Result<F::Output, tokio::time::error::Elapsed> {
    timeout(limit, future).await
}

fn compatible_download_complete(
    value: &Value,
    expected_offer_id: &str,
    expected_name: &str,
    expected_output: &Path,
) -> bool {
    ipc::DownloadCompleteV1::from_value(value).is_ok_and(|complete| {
        complete.offer_id == expected_offer_id
            && complete.name == expected_name
            && complete.output() == expected_output
    })
}

fn start_download(state: &WebState, offer_id: String) -> Response<Body> {
    let now = Instant::now();
    state.prune_jobs(now);
    if state
        .jobs
        .lock()
        .expect("download jobs mutex poisoned")
        .len()
        >= MAX_DOWNLOAD_JOBS
    {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "not_started",
            "Web download queue is full.",
        );
    }
    let Ok(permit) = state.downloads.clone().try_acquire_owned() else {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "not_started",
            "Web attachment download capacity reached.",
        );
    };
    let Some(stored) = state.get_offer(&offer_id, now) else {
        return error(
            StatusCode::NOT_FOUND,
            "not_started",
            "Attachment offer is unavailable or expired.",
        );
    };
    if touch_download_root(&state.download_root).is_err() {
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "not_started",
            "Web download staging is unavailable.",
        );
    }
    let job_id = random_id();
    let output = state.download_root.join(format!("{job_id}.blob"));
    {
        let mut jobs = state.jobs.lock().expect("download jobs mutex poisoned");
        if jobs.len() >= MAX_DOWNLOAD_JOBS {
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "not_started",
                "Web download queue is full.",
            );
        }
        jobs.insert(job_id.clone(), DownloadJob::Pending { created: now });
    }
    let dir = state.dir.clone();
    let jobs = state.jobs.clone();
    let download_root = state.download_root.clone();
    let ready_id = job_id.clone();
    let request_id = http_request_id();
    tokio::spawn(HTTP_REQUEST_ID.scope(request_id, async move {
        let _permit = permit;
        let result = bounded_download_ipc(
            web_ipc_request(
                &dir,
                &IpcRequest::WebDownload {
                    offer: stored.offer,
                    output: output.clone(),
                },
            ),
            WEB_DOWNLOAD_IPC_TIMEOUT,
        )
        .await;
        let job = match result {
            Ok(Ok(value))
                if compatible_download_complete(
                    &value,
                    &stored.offer_id,
                    &stored.name,
                    &output,
                ) =>
            {
                match open_download_file(&output) {
                    Ok((file, size))
                        if value["size"].as_u64() == Some(size)
                            && touch_download_root(&download_root).is_ok() =>
                    {
                        drop(file);
                        DownloadJob::Ready {
                            path: output,
                            name: stored.name,
                            size,
                            created: Instant::now(),
                        }
                    }
                    _ => {
                        let _ = fs::remove_file(&output);
                        DownloadJob::Failed {
                            error: ipc::LifecycleErrorV1::new(
                                "attachment_lifecycle_internal",
                                "Daemon completed without an exported file.",
                                "unknown",
                                true,
                            ),
                            created: Instant::now(),
                        }
                    }
                }
            }
            Ok(Ok(value)) => {
                let _ = fs::remove_file(&output);
                let error = if value["type"] == "error" {
                    ipc::LifecycleErrorV1::from_value(&value).unwrap_or_else(|_| {
                        ipc::LifecycleErrorV1::new(
                            "attachment_lifecycle_internal",
                            "Daemon returned a malformed attachment lifecycle error.",
                            "unknown",
                            true,
                        )
                    })
                } else {
                    ipc::LifecycleErrorV1::new(
                        "attachment_lifecycle_internal",
                        "Daemon returned an incompatible attachment download response.",
                        "unknown",
                        true,
                    )
                };
                log_private_lifecycle_diagnostic("download", &error);
                DownloadJob::Failed {
                    error: public_lifecycle_error(error),
                    created: Instant::now(),
                }
            }
            Ok(Err(_)) => {
                let _ = fs::remove_file(&output);
                DownloadJob::Failed {
                    error: ipc::LifecycleErrorV1::new(
                        "attachment_storage_shutdown",
                        "Daemon unavailable or disconnected during download.",
                        "unknown",
                        true,
                    ),
                    created: Instant::now(),
                }
            }
            Err(_) => {
                // Dropping IPC cannot cancel a command the daemon already accepted.
                // Remove what exists now; the unique root quarantines any later export
                // until stale-root cleanup is safe.
                let _ = fs::remove_file(&output);
                DownloadJob::Failed {
                    error: ipc::LifecycleErrorV1::new(
                        "attachment_command_timeout",
                        "Daemon attachment preparation exceeded its time limit.",
                        "unknown",
                        true,
                    ),
                    created: Instant::now(),
                }
            }
        };
        let mut jobs = jobs.lock().expect("download jobs mutex poisoned");
        if matches!(jobs.get(&ready_id), Some(DownloadJob::Pending { .. })) {
            jobs.insert(ready_id, job);
        } else if let DownloadJob::Ready { path, .. } = job {
            let _ = fs::remove_file(path);
        }
    }));
    json_response(
        StatusCode::ACCEPTED,
        json!({
            "type":"download_started", "id":job_id,
            "poll_timeout_ms":DOWNLOAD_PENDING_TTL.as_millis() as u64
        }),
    )
}

fn public_lifecycle_error(error: ipc::LifecycleErrorV1) -> ipc::LifecycleErrorV1 {
    // ErrorEnvelopeV1 construction and decoding already enforce fixed public
    // text for every admitted code. Never rewrite it from an internal cause.
    error
}

fn log_private_lifecycle_diagnostic(context: &str, error: &ipc::LifecycleErrorV1) {
    eprintln!(
        "meshmsg web {context} diagnostic [{}; {}]: {:?}",
        error.code, error.outcome, error.message
    );
}

fn download_status(state: &WebState, id: &str) -> Response<Body> {
    state.prune_jobs(Instant::now());
    let jobs = state.jobs.lock().expect("download jobs mutex poisoned");
    match jobs.get(id) {
        Some(DownloadJob::Pending { .. }) => {
            json_response(StatusCode::OK, json!({"type":"download_pending", "id":id}))
        }
        Some(DownloadJob::Ready { .. }) => json_response(
            StatusCode::OK,
            json!({"type":"download_ready", "url":format!("/api/download/{id}")}),
        ),
        Some(DownloadJob::Failed { error, .. }) => json_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            serde_json::to_value(public_lifecycle_error(error.clone()))
                .expect("lifecycle error DTO serializes"),
        ),
        None => error(
            StatusCode::NOT_FOUND,
            "failed",
            "Download is unavailable or expired.",
        ),
    }
}

fn mutation_error_response(error: MutationErrorDto) -> Response<Body> {
    let status = error.status();
    json_response(
        status,
        serde_json::to_value(error).expect("mutation error DTO serializes"),
    )
}

fn local_mutation_error(
    operation_id: &str,
    code: &str,
    message: &str,
    retryable: bool,
    outcome: &str,
) -> MutationErrorDto {
    MutationErrorDto {
        kind: "error".into(),
        schema_version: 1,
        code: code.into(),
        message: message.into(),
        request_id: http_request_id(),
        operation_id: operation_id.into(),
        retryable,
        outcome: outcome.into(),
    }
}

fn daemon_supports_idempotent_mutations(status: &Value) -> bool {
    status["type"] == "status"
        && status["ipc_capabilities"]
            .as_array()
            .is_some_and(|capabilities| {
                capabilities.iter().any(|capability| {
                    capability.as_str() == Some(ipc::IDEMPOTENT_MUTATIONS_CAPABILITY)
                })
            })
}

async fn api_request(state: &WebState, bytes: &[u8]) -> Response<Body> {
    let request = match parse_request(bytes) {
        Ok(request) => request,
        Err(_) => return error(StatusCode::BAD_REQUEST, "not_sent", "Only send, status, peers, and opaque attachment download IDs are supported; no extra fields."),
    };
    let Ok(_permit) = state.requests.try_acquire() else {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "not_sent",
            "Web request capacity reached.",
        );
    };
    let request = match request {
        WebRequest::Download { id } => return start_download(state, id),
        WebRequest::DownloadStatus { id } => return download_status(state, &id),
        request => request,
    };
    let is_send = matches!(&request, WebRequest::Send { .. });
    let is_peers = matches!(&request, WebRequest::Peers {});
    if let WebRequest::Send { operation_id, .. } = &request {
        let negotiated = timeout(
            IPC_TIMEOUT,
            web_ipc_request(&state.dir, &IpcRequest::Status),
        )
        .await;
        match negotiated {
            Ok(Ok(status))
                if ipc::StatusV1::from_value(&status).is_ok()
                    && daemon_supports_idempotent_mutations(&status) => {}
            Ok(Ok(_)) => {
                return mutation_error_response(local_mutation_error(
                    operation_id,
                    "idempotency_unsupported",
                    "Daemon does not advertise retry-safe mutations. Upgrade and restart it; the message was not submitted.",
                    false,
                    "not_started",
                ));
            }
            _ => {
                return mutation_error_response(local_mutation_error(
                    operation_id,
                    "daemon_unavailable",
                    "Daemon unavailable during capability negotiation; the message was not submitted.",
                    true,
                    "not_started",
                ));
            }
        }
        if !state.take_send(operation_id, Instant::now()) {
            let mut response = mutation_error_response(local_mutation_error(
                operation_id,
                "send_throttled",
                "Wait one second before another broadcast.",
                true,
                "not_started",
            ));
            *response.status_mut() = StatusCode::TOO_MANY_REQUESTS;
            return response;
        }
    }
    let send_expected = match &request {
        WebRequest::Send { operation_id, body } => Some((operation_id.clone(), body.clone())),
        _ => None,
    };
    let request = match request {
        WebRequest::Send { operation_id, body } => IpcRequest::Send { operation_id, body },
        WebRequest::Status {} => IpcRequest::Status,
        WebRequest::Peers {} => IpcRequest::Peers,
        WebRequest::Download { .. } | WebRequest::DownloadStatus { .. } => unreachable!(),
    };
    match timeout(IPC_TIMEOUT, web_ipc_request(&state.dir, &request)).await {
        Ok(Ok(value)) if is_send && value["type"] == "error" => {
            let operation_id = &send_expected.as_ref().expect("send metadata exists").0;
            match MutationErrorDto::parse(value, operation_id) {
                Some(error) => mutation_error_response(error),
                None => mutation_error_response(local_mutation_error(
                    operation_id,
                    "invalid_daemon_response",
                    "Daemon returned an invalid mutation error; outcome unknown.",
                    true,
                    "unknown",
                )),
            }
        }
        Ok(Ok(value)) if is_send => {
            let (operation_id, expected_body) =
                send_expected.as_ref().expect("send metadata exists");
            match serde_json::from_value::<QueuedMutationDto>(value) {
                Ok(queued)
                    if queued.kind == "queued"
                        && queued.schema_version == 3
                        && contracts::valid_request_id(&queued.request_id)
                        && queued.operation_id == *operation_id
                        && contracts::valid_request_id(&queued.request_id)
                        && queued.message_id == *operation_id
                        && queued.body == *expected_body
                        && ipc::valid_operation_id(&queued.message_id)
                        && !queued.from.is_empty()
                        && queued.timestamp_ms != 0
                        && !queued.delivery_acknowledged =>
                {
                    json_response(
                        StatusCode::OK,
                        json!({
                            "type":"queued", "schema_version":3,
                            "operation_id":queued.operation_id,
                            "message_id":queued.message_id,
                            "delivery_acknowledged":false
                        }),
                    )
                }
                _ => mutation_error_response(local_mutation_error(
                    operation_id,
                    "invalid_daemon_response",
                    "Daemon returned an invalid queued response; outcome unknown.",
                    true,
                    "unknown",
                )),
            }
        }
        Ok(Ok(value)) if !is_send && !is_peers && ipc::StatusV1::from_value(&value).is_ok() => {
            json_response(StatusCode::OK, public_status(&value))
        }
        Ok(Ok(value)) if is_peers => match public_peers_snapshot(&value) {
            Some(value) => json_response(StatusCode::OK, value),
            None => error(
                StatusCode::BAD_GATEWAY,
                "offline",
                "Daemon returned an invalid peer directory.",
            ),
        },
        _ if is_send => {
            let operation_id = &send_expected.as_ref().expect("send metadata exists").0;
            mutation_error_response(local_mutation_error(
                operation_id,
                "send_outcome_unknown",
                "Outcome unknown: daemon unavailable or reply lost. Retry unchanged with this operation ID while the same daemon cache is active.",
                true,
                "unknown",
            ))
        }
        _ => error(
            StatusCode::SERVICE_UNAVAILABLE,
            "offline",
            "Daemon offline or unresponsive. Start or restart it separately.",
        ),
    }
}

fn sse_frame(value: &Value) -> Bytes {
    // JSON encoding escapes message newlines; untrusted text cannot inject SSE fields.
    let request_id = http_request_id();
    let value = if value.get("type").and_then(Value::as_str) == Some("error") {
        let mut error = ErrorEnvelopeV1::new(
            value
                .get("code")
                .and_then(Value::as_str)
                .unwrap_or("feed_error"),
            value
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("Live feed failed."),
            value
                .get("outcome")
                .and_then(Value::as_str)
                .unwrap_or("unknown"),
            value
                .get("retryable")
                .and_then(Value::as_bool)
                .unwrap_or(true),
        );
        error.request_id = Some(request_id);
        error.into_value()
    } else {
        contracts::correlate(value.clone(), &request_id)
    };
    Bytes::from(format!("data: {value}\n\n"))
}

async fn web_ipc_request(dir: &Path, request: &IpcRequest) -> Result<Value> {
    ipc::send_request_with_id(dir, request, &http_request_id()).await
}

fn public_event(state: &WebState, value: Value, download_supported: bool) -> Option<Value> {
    match value["type"].as_str()? {
        "connected" => {
            let decoded: ConnectedEventDto = serde_json::from_value(value.clone()).ok()?;
            if decoded.kind != "connected"
                || decoded.schema_version != 1
                || !contracts::valid_request_id(&decoded.request_id)
                || !decoded.endpoint_online
                || decoded.ipc_capabilities.len() > 64
            {
                return None;
            }
            let _validated = (decoded.peer, decoded.topic_joined, decoded.alias);
            let mut connected = json!({"type":"connected"});
            if let Some(peer) = public_key(&value["peer"]) {
                connected["peer"] = peer.into();
            }
            connected["download_supported"] = download_supported.into();
            Some(connected)
        }
        "message" => {
            let decoded: MessageEventDto = serde_json::from_value(value.clone()).ok()?;
            if decoded.kind != "message"
                || decoded.schema_version != 2
                || !contracts::valid_request_id(&decoded.request_id)
                || decoded.from.is_empty()
                || decoded.timestamp_ms == 0
                || decoded.body.len() > 4096
            {
                return None;
            }
            let _validated_message_id = decoded.message_id;
            let message_id = value["message_id"].as_str()?;
            if value["schema_version"] != 2 || !valid_id(message_id) {
                return None;
            }
            Some(json!({
                "type":"message", "schema_version":2, "from":value["from"],
                "message_id":message_id, "body":value["body"],
                "timestamp_ms":value["timestamp_ms"]
            }))
        }
        "queued" => {
            let decoded: QueuedMutationDto = serde_json::from_value(value.clone()).ok()?;
            if decoded.kind != "queued"
                || decoded.schema_version != 3
                || !contracts::valid_request_id(&decoded.request_id)
                || decoded.from.is_empty()
                || decoded.timestamp_ms == 0
                || decoded.body.len() > 4096
                || decoded.delivery_acknowledged
            {
                return None;
            }
            let message_id = value["message_id"].as_str()?;
            let operation_id = value["operation_id"].as_str()?;
            if value["schema_version"] != 3 || !valid_id(message_id) || operation_id != message_id {
                return None;
            }
            Some(json!({
                "type":"queued", "schema_version":3, "from":value["from"],
                "operation_id":operation_id, "message_id":message_id, "body":value["body"],
                "timestamp_ms":value["timestamp_ms"], "delivery_acknowledged":false
            }))
        }
        "attachment_offer" => {
            let decoded: OfferEventDto = serde_json::from_value(value.clone()).ok()?;
            if decoded.kind != "attachment_offer"
                || decoded.schema_version != 2
                || !contracts::valid_request_id(&decoded.request_id)
                || decoded.from.is_empty()
                || decoded.timestamp_ms == 0
                || !ipc::valid_operation_id(&decoded.message_id)
                || !ipc::valid_operation_id(&decoded.offer_id)
                || decoded.name.is_empty()
                || decoded.ticket.is_empty()
                || decoded.offer.is_empty()
            {
                return None;
            }
            let _validated = (decoded.kind_name, decoded.size);
            let message_id = value["message_id"].as_str()?;
            if value["schema_version"] != 2 || !valid_id(message_id) {
                return None;
            }
            let offer = value["offer"].as_str()?;
            let name = value["name"].as_str()?;
            let kind = value["kind"].as_str()?;
            if !matches!(kind, "file" | "directory_tar_v1") || value["size"].as_u64().is_none() {
                return None;
            }
            let mut public = json!({
                "type":"attachment_offer", "schema_version":2,
                "direction":"incoming", "from":value["from"], "message_id":message_id,
                "timestamp_ms":value["timestamp_ms"], "name":name,
                "kind":kind, "size":value["size"]
            });
            if download_supported {
                public["download_id"] = state
                    .remember_offer(&decoded.offer_id, offer, name, Instant::now())?
                    .into();
            }
            Some(public)
        }
        "attachment_shared" => {
            let decoded: SharedMutationDto = serde_json::from_value(value.clone()).ok()?;
            if decoded.kind != "attachment_shared"
                || decoded.schema_version != 3
                || !contracts::valid_request_id(&decoded.request_id)
                || decoded.from.is_empty()
                || decoded.timestamp_ms == 0
                || decoded.operation_id != decoded.message_id
                || decoded.offer_id != decoded.message_id
                || !ipc::valid_operation_id(&decoded.message_id)
                || !ipc::valid_content_digest(&decoded.source_digest)
                || decoded.name.is_empty()
                || decoded.ticket.is_empty()
                || decoded.offer.is_empty()
                || decoded.delivery_acknowledged
            {
                return None;
            }
            let _validated = (decoded.kind_name, decoded.size);
            let message_id = value["message_id"].as_str()?;
            let operation_id = value["operation_id"].as_str()?;
            if value["schema_version"] != 3 || !valid_id(message_id) || operation_id != message_id {
                return None;
            }
            Some(json!({
                "type":"attachment_shared", "schema_version":3,
                "direction":"outgoing", "from":value["from"],
                "operation_id":operation_id, "message_id":message_id,
                "timestamp_ms":value["timestamp_ms"], "name":value["name"],
                "kind":value["kind"], "size":value["size"]
            }))
        }
        "peers_snapshot" => public_peers_snapshot(&value),
        event_type @ ("peer_discovered" | "peer_updated" | "peer_expired") => {
            public_peer_transition(&value, event_type)
        }
        "lagged" => {
            let decoded: LaggedEventDto = serde_json::from_value(value).ok()?;
            if decoded.kind != "lagged"
                || decoded.schema_version != 1
                || !contracts::valid_request_id(&decoded.request_id)
                || !matches!(decoded.source.as_str(), "local" | "gossip")
                || decoded.message.is_empty()
            {
                return None;
            }
            let _dropped = decoded.dropped;
            Some(
                json!({"type":"lagged", "message":"Feed gap: daemon dropped events. No history or replay is available."}),
            )
        }
        _ => None,
    }
}

async fn within_startup_deadline<T>(
    deadline: TokioInstant,
    future: impl Future<Output = T>,
) -> std::result::Result<T, tokio::time::error::Elapsed> {
    timeout(
        deadline.saturating_duration_since(TokioInstant::now()),
        future,
    )
    .await
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
    let request_id = http_request_id();
    tokio::spawn(HTTP_REQUEST_ID.scope(request_id.clone(), async move {
        let _permit = permit;
        let startup_deadline = TokioInstant::now() + IPC_TIMEOUT;
        let opened = within_startup_deadline(
            startup_deadline,
            ipc::subscribe_with_id(&state.dir, &request_id),
        )
        .await;
        let Ok(Ok(mut reader)) = opened else {
            let _ = tx.send(sse_frame(&json!({"type":"error", "schema_version":1, "code":"daemon_offline", "message":"Daemon offline. Reconnecting; feed gaps have no history.", "retryable":true, "outcome":"unknown"}))).await;
            return;
        };
        let first = match within_startup_deadline(startup_deadline, reader.read()).await {
            Ok(Ok(Some(first))) => first,
            Ok(Ok(None)) => {
                let _ = tx.send(sse_frame(&json!({"type":"error", "schema_version":1, "code":"daemon_disconnected", "message":"Daemon disconnected. Feed gap; no history. Reconnecting.", "retryable":true, "outcome":"unknown"}))).await;
                return;
            }
            Ok(Err(_)) => {
                let _ = tx.send(sse_frame(&json!({"type":"error", "schema_version":1, "code":"invalid_daemon_response", "message":"The daemon returned an invalid response.", "retryable":true, "outcome":"unknown"}))).await;
                return;
            }
            Err(_) => {
                let _ = tx.send(sse_frame(&json!({"type":"error", "schema_version":1, "code":"daemon_offline", "message":"Daemon offline. Reconnecting; feed gaps have no history.", "retryable":true, "outcome":"unknown"}))).await;
                return;
            }
        };
        let download_supported = first["ipc_capabilities"]
            .as_array()
            .is_some_and(|capabilities| {
                capabilities
                    .iter()
                    .any(|value| value.as_str() == Some(WEB_DOWNLOAD_CAPABILITY))
            });
        let Some(connected) = public_event(&state, first, download_supported) else {
            let _ = tx.send(sse_frame(&json!({"type":"error", "schema_version":1, "code":"invalid_daemon_response", "message":"The daemon returned an invalid response.", "retryable":true, "outcome":"unknown"}))).await;
            return;
        };
        if tx.send(sse_frame(&connected)).await.is_err() {
            return;
        }
        let mut heartbeat = tokio::time::interval(Duration::from_secs(10));
        loop {
            // Keep the read future alive across heartbeats: canceling a partial IPC
            // line would silently corrupt framing when the daemon resumes writing.
            let read = reader.read();
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
                Ok(Some(value)) => public_event(&state, value, download_supported),
                _ => {
                    let _ = timeout(Duration::from_secs(5), tx.send(sse_frame(&json!({"type":"error", "schema_version":1, "code":"daemon_disconnected", "message":"Daemon disconnected. Feed gap; no history. Reconnecting.", "retryable":true, "outcome":"unknown"})))).await;
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
    }));
    let stream = stream::unfold(rx, |mut rx| async move {
        rx.recv()
            .await
            .map(|bytes| (Ok::<_, std::io::Error>(Frame::data(bytes)), rx))
    });
    let mut response = response(StatusCode::OK, "text/event-stream", Bytes::new());
    response
        .headers_mut()
        .insert("x-accel-buffering", HeaderValue::from_static("no"));
    *response.body_mut() = BodyExt::boxed(StreamBody::new(stream));
    response
}

fn open_download_file(path: &Path) -> std::io::Result<(File, u64)> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(std::io::Error::other(
            "download output is not a regular file",
        ));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(std::io::Error::other("download output is a reparse point"));
        }
    }
    Ok((file, metadata.len()))
}

fn content_disposition(name: &str) -> HeaderValue {
    let mut fallback: String = name
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_') {
                character
            } else {
                '_'
            }
        })
        .collect();
    if fallback.is_empty() || fallback == "." || fallback == ".." {
        fallback = "attachment".into();
    }
    let encoded: String = name
        .as_bytes()
        .iter()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || matches!(*byte, b'.' | b'-' | b'_') {
                (*byte as char).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect();
    HeaderValue::from_str(&format!(
        "attachment; filename=\"{fallback}\"; filename*=UTF-8''{encoded}"
    ))
    .expect("sanitized content disposition is a valid header")
}

fn requested_range(headers: &HeaderMap, size: u64) -> Option<Result<(u64, u64), ()>> {
    let value = single_header(headers, "range")?;
    let Some(range) = value.strip_prefix("bytes=") else {
        return Some(Err(()));
    };
    if range.contains(',') {
        return Some(Err(()));
    }
    let Some((start, end)) = range.split_once('-') else {
        return Some(Err(()));
    };
    let Ok(start) = start.parse::<u64>() else {
        return Some(Err(()));
    };
    if start >= size {
        return Some(Err(()));
    }
    let end = if end.is_empty() {
        size - 1
    } else {
        let Ok(end) = end.parse::<u64>() else {
            return Some(Err(()));
        };
        end.min(size - 1)
    };
    if end < start {
        return Some(Err(()));
    }
    Some(Ok((start, end)))
}

async fn serve_download(state: &WebState, id: &str, headers: &HeaderMap) -> Response<Body> {
    if !valid_id(id) {
        return error(StatusCode::NOT_FOUND, "failed", "Download not found.");
    }
    let now = Instant::now();
    state.prune_jobs(now);
    let (path, name, expected_size) = {
        let mut jobs = state.jobs.lock().expect("download jobs mutex poisoned");
        let Some(DownloadJob::Ready {
            path,
            name,
            size,
            created,
        }) = jobs.get_mut(id)
        else {
            return error(
                StatusCode::NOT_FOUND,
                "failed",
                "Download is not ready or is unavailable.",
            );
        };
        *created = now;
        (path.clone(), name.clone(), *size)
    };
    if touch_download_root(&state.download_root).is_err() {
        return error(
            StatusCode::NOT_FOUND,
            "failed",
            "Download file is unavailable.",
        );
    }
    let (file, size) = match open_download_file(&path) {
        Ok((file, size)) if size == expected_size => (tokio::fs::File::from_std(file), size),
        _ => {
            return error(
                StatusCode::NOT_FOUND,
                "failed",
                "Download file is unavailable.",
            );
        }
    };
    let (status, start, length) = match requested_range(headers, size) {
        None => (StatusCode::OK, 0, size),
        Some(Ok((start, end))) => (StatusCode::PARTIAL_CONTENT, start, end - start + 1),
        Some(Err(())) => {
            let mut result = error(
                StatusCode::RANGE_NOT_SATISFIABLE,
                "failed",
                "Requested download range is unavailable.",
            );
            result.headers_mut().insert(
                "content-range",
                HeaderValue::from_str(&format!("bytes */{size}"))
                    .expect("file size is a valid range header"),
            );
            return result;
        }
    };
    let mut file = file;
    if start != 0 && file.seek(std::io::SeekFrom::Start(start)).await.is_err() {
        return error(
            StatusCode::NOT_FOUND,
            "failed",
            "Download file is unavailable.",
        );
    }
    let stream = stream::try_unfold(file.take(length), |mut file| async move {
        let mut buffer = vec![0_u8; 64 * 1024];
        let read = file.read(&mut buffer).await?;
        if read == 0 {
            return Ok(None);
        }
        buffer.truncate(read);
        Ok(Some((Frame::data(Bytes::from(buffer)), file)))
    });
    let mut result = response(status, "application/octet-stream", Bytes::new());
    result
        .headers_mut()
        .insert("content-disposition", content_disposition(&name));
    result.headers_mut().insert(
        "content-length",
        HeaderValue::from_str(&length.to_string()).expect("file size is a valid header"),
    );
    result
        .headers_mut()
        .insert("accept-ranges", HeaderValue::from_static("bytes"));
    if status == StatusCode::PARTIAL_CONTENT {
        result.headers_mut().insert(
            "content-range",
            HeaderValue::from_str(&format!("bytes {start}-{}/{size}", start + length - 1))
                .expect("validated byte range is a valid header"),
        );
    }
    *result.body_mut() = BodyExt::boxed(StreamBody::new(stream));
    result
}

fn decode_upload_name(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let pair = bytes.get(index + 1..index + 3)?;
            let text = std::str::from_utf8(pair).ok()?;
            decoded.push(u8::from_str_radix(text, 16).ok()?);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).ok()
}

fn daemon_supports_web_share(status: &Value) -> Option<u64> {
    let supported = status["type"] == "status"
        && status["ipc_capabilities"].as_array().is_some_and(|values| {
            values
                .iter()
                .any(|value| value.as_str() == Some(WEB_SHARE_CAPABILITY))
                && values
                    .iter()
                    .any(|value| value.as_str() == Some(ipc::IDEMPOTENT_MUTATIONS_CAPABILITY))
        });
    if !supported {
        return None;
    }
    status["max_attachment_bytes"]
        .as_u64()
        .filter(|limit| *limit > 0)
}

async fn upload_attachment(state: &WebState, mut request: Request<Incoming>) -> Response<Body> {
    let Some(operation_id) = single_header(request.headers(), "x-meshmsg-operation-id")
        .filter(|value| ipc::valid_operation_id(value))
        .map(str::to_owned)
    else {
        return error(
            StatusCode::BAD_REQUEST,
            "not_shared",
            "A 32-character lowercase hexadecimal operation ID is required.",
        );
    };
    let Some(encoded_name) = single_header(request.headers(), "x-meshmsg-file-name") else {
        return error(
            StatusCode::BAD_REQUEST,
            "not_shared",
            "A single encoded attachment filename is required.",
        );
    };
    let Some(name) = decode_upload_name(encoded_name) else {
        return error(
            StatusCode::BAD_REQUEST,
            "not_shared",
            "Invalid attachment filename encoding.",
        );
    };
    if validate_display_name(&name).is_err() {
        return error(
            StatusCode::BAD_REQUEST,
            "not_shared",
            "The attachment filename is not portable or is too long.",
        );
    }
    let declared_size = match single_header(request.headers(), "content-length") {
        Some(value) => match value.parse::<u64>() {
            Ok(value) => Some(value),
            Err(_) => {
                return error(
                    StatusCode::BAD_REQUEST,
                    "not_shared",
                    "Invalid attachment size.",
                )
            }
        },
        None if request.headers().contains_key("content-length") => {
            return error(
                StatusCode::BAD_REQUEST,
                "not_shared",
                "Invalid attachment size.",
            );
        }
        None => None,
    };
    let Ok(_permit) = state.uploads.clone().try_acquire_owned() else {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "not_shared",
            "Web attachment upload capacity reached.",
        );
    };
    let status = match timeout(
        IPC_TIMEOUT,
        web_ipc_request(&state.dir, &IpcRequest::Status),
    )
    .await
    {
        Ok(Ok(status)) if ipc::StatusV1::from_value(&status).is_ok() => status,
        _ => {
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "not_shared",
                "Daemon offline or unresponsive. Start or restart it separately.",
            )
        }
    };
    let Some(maximum) = daemon_supports_web_share(&status) else {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "not_shared",
            "The daemon does not support web attachment sharing. Upgrade and restart it.",
        );
    };
    if declared_size.is_some_and(|size| size > maximum) {
        return error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "not_shared",
            "Attachment exceeds the daemon's configured size limit.",
        );
    }
    let Some(operation_gate) = state.upload_operation_gate(&operation_id, Instant::now()) else {
        return json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({
                "type":"error", "schema_version":1,
                "code":"share_operation_capacity", "outcome":"not_shared",
                "operation_id":operation_id,
                "message":"Web attachment operation cache is full."
            }),
        );
    };
    let _operation_guard = operation_gate.lock().await;
    if touch_download_root(&state.upload_root).is_err() {
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "not_shared",
            "Web upload staging is unavailable.",
        );
    }
    let operation_root = state.upload_root.join(&operation_id);
    if restrict_download_directory(&operation_root).is_err() {
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "not_shared",
            "Web upload staging is unavailable.",
        );
    }
    // Always receive a retry into a fresh sibling. Only matching bytes are
    // allowed to reuse the stable source path submitted to the daemon.
    let retry_path = operation_root.join(format!(".retry-{}", random_id()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = match options.open(&retry_path) {
        Ok(file) => file,
        Err(_) => {
            let _ = fs::remove_file(&retry_path);
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "not_shared",
                "Web upload staging is unavailable.",
            );
        }
    };
    let receive = async {
        let mut file = tokio::fs::File::from_std(file);
        let mut received = 0_u64;
        let mut hasher = Sha256::new();
        hasher.update(b"meshmsg-share-source-v1\0");
        hasher.update(b"file\0");
        while let Some(frame) = request.body_mut().frame().await {
            let frame = frame.context("read upload body")?;
            let data = frame
                .into_data()
                .map_err(|_| anyhow::anyhow!("upload trailers are unsupported"))?;
            received = received
                .checked_add(data.len() as u64)
                .context("upload size overflow")?;
            anyhow::ensure!(received <= maximum, "upload exceeds size limit");
            hasher.update(&data);
            file.write_all(&data).await.context("stage upload")?;
        }
        anyhow::ensure!(
            declared_size.is_none_or(|size| size == received),
            "incomplete upload"
        );
        file.sync_all().await.context("sync staged upload")?;
        Result::<(u64, [u8; 32])>::Ok((received, hasher.finalize().into()))
    };
    let (received, digest) = match timeout(WEB_SHARE_TIMEOUT, receive).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => {
            let _ = fs::remove_file(&retry_path);
            return error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "not_shared",
                "Attachment was incomplete or exceeded the configured size limit.",
            );
        }
        Err(_) => {
            let _ = fs::remove_file(&retry_path);
            return error(
                StatusCode::REQUEST_TIMEOUT,
                "not_shared",
                "Attachment upload exceeded its time limit.",
            );
        }
    };
    let fingerprint = UploadFingerprint {
        name: name.clone(),
        size: received,
        digest,
    };
    if !state.check_upload_fingerprint(&operation_id, fingerprint, Instant::now()) {
        let _ = fs::remove_file(&retry_path);
        return json_response(
            StatusCode::CONFLICT,
            json!({
                "type":"error", "schema_version":1,
                "code":"operation_id_conflict", "outcome":"not_started",
                "retryable":false, "operation_id":operation_id,
                "message":"operation ID was already used with different attachment input"
            }),
        );
    }
    let path = operation_root.join(&name);
    if path.exists() {
        let _ = fs::remove_file(&retry_path);
    } else if fs::rename(&retry_path, &path).is_err() {
        let _ = fs::remove_file(&retry_path);
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "not_shared",
            "Web upload staging is unavailable.",
        );
    }
    let source_digest = data_encoding::HEXLOWER.encode(&digest);
    let result = timeout(
        WEB_SHARE_TIMEOUT,
        web_ipc_request(
            &state.dir,
            &IpcRequest::Share {
                operation_id: operation_id.clone(),
                source_digest: source_digest.clone(),
                path: path.clone(),
            },
        ),
    )
    .await;
    // A long upload/share cannot consume the browser-side binding's TTL: its
    // retention begins again at the latest terminal or unknown outcome.
    state.refresh_upload_operation(&operation_id, Instant::now());
    match result {
        Ok(Ok(value)) if value["type"] == "error" => {
            let _ = fs::remove_dir_all(&operation_root);
            let public_error = ipc::LifecycleErrorV1::from_value(&value)
                .ok()
                .filter(|error| error.operation_id.as_deref() == Some(&operation_id))
                .map(|error| {
                    log_private_lifecycle_diagnostic("share", &error);
                    public_lifecycle_error(error).into_value()
                });
            match public_error.and_then(|value| MutationErrorDto::parse(value, &operation_id)) {
                Some(error) => mutation_error_response(error),
                None => mutation_error_response(local_mutation_error(
                    &operation_id,
                    "invalid_daemon_response",
                    "Daemon returned an invalid share error; outcome unknown.",
                    true,
                    "unknown",
                )),
            }
        }
        Ok(Ok(value)) => {
            let valid =
                SharedMutationDto::parse(value, &operation_id, &source_digest, &name, received);
            let _ = fs::remove_dir_all(&operation_root);
            match valid {
                Some(shared) => json_response(
                    StatusCode::OK,
                    json!({
                        "type":"attachment_shared", "schema_version":3,
                        "operation_id":shared.operation_id,
                        "message_id":shared.message_id,
                        "offer_id":shared.offer_id,
                        "source_digest":shared.source_digest,
                        "name":shared.name, "size":shared.size,
                        "delivery_acknowledged":false
                    }),
                ),
                None => mutation_error_response(local_mutation_error(
                    &operation_id,
                    "invalid_daemon_response",
                    "Daemon returned an invalid share response; outcome unknown.",
                    true,
                    "unknown",
                )),
            }
        }
        Ok(Err(_)) | Err(_) => {
            // The daemon may still have opened the source or published its offer.
            // Retain the isolated staging directory for stale-startup cleanup.
            mutation_error_response(local_mutation_error(
                &operation_id,
                "share_outcome_unknown",
                "Share outcome unknown: daemon unavailable or reply lost. Retry the unchanged file with this operation ID while the same daemon cache is active.",
                true,
                "unknown",
            ))
        }
    }
}

async fn route_inner(
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
    let path = request.uri().path();
    if request.method() == Method::GET {
        if let Some(id) = path.strip_prefix("/api/download/") {
            return Ok(serve_download(&state, id, request.headers()).await);
        }
    }
    let result = match (request.method(), path) {
        (&Method::GET, "/") => response(
            StatusCode::OK,
            "text/html; charset=utf-8",
            include_str!("web/index.html"),
        ),
        (&Method::GET, "/settings") => response(
            StatusCode::OK,
            "text/html; charset=utf-8",
            include_str!("web/settings.html"),
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
        (&Method::GET, "/settings.js") => response(
            StatusCode::OK,
            "text/javascript; charset=utf-8",
            include_str!("web/settings.js"),
        ),
        (&Method::GET, "/api/events") => events(state).await,
        (&Method::POST, "/api/attachment") => {
            if single_header(request.headers(), "content-type") != Some("application/octet-stream")
                || request.headers().contains_key("content-encoding")
            {
                error(
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    "not_shared",
                    "Use unencoded application/octet-stream.",
                )
            } else {
                upload_attachment(&state, request).await
            }
        }
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

async fn route(
    request: Request<Incoming>,
    state: Arc<WebState>,
) -> Result<Response<Body>, Infallible> {
    let json_request = request.method() == Method::POST && request.uri().path() == "/api/request";
    let header = request_id_header(request.headers());
    let (request_id, header_error) = match header {
        RequestIdHeader::One(value) => (value, None),
        RequestIdHeader::Missing if json_request => (
            contracts::new_request_id(),
            Some("X-Meshmsg-Request-Id is required for JSON requests."),
        ),
        RequestIdHeader::Missing => (contracts::new_request_id(), None),
        RequestIdHeader::Invalid => (
            contracts::new_request_id(),
            Some("X-Meshmsg-Request-Id must be 32 lowercase hexadecimal characters."),
        ),
        RequestIdHeader::Duplicate => (
            contracts::new_request_id(),
            Some("X-Meshmsg-Request-Id must occur exactly once."),
        ),
    };
    HTTP_REQUEST_ID
        .scope(request_id, async move {
            if let Some(message) = header_error {
                return Ok(error(StatusCode::BAD_REQUEST, "not_started", message));
            }
            route_inner(request, state).await
        })
        .await
}

pub(crate) async fn run(dir: &Path, address: SocketAddr, origin: Option<String>) -> Result<()> {
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
    let mut cleanup = interval(Duration::from_secs(30));
    // Keep one registered signal future for the server lifetime. Recreating it in
    // each select can lose the shutdown wake-up when another ready branch wins.
    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            biased;
            result = &mut shutdown => {
                result.context("listen for web shutdown signal")?;
                break;
            }
            accepted = listener.accept() => {
                let (socket, _) = accepted?;
                let Ok(permit) = connections.clone().try_acquire_owned() else { continue; };
                let state = state.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    let mut builder = http1::Builder::new();
                    builder.timer(TokioTimer::new()).header_read_timeout(Duration::from_secs(5)).max_headers(32).max_buf_size(16 * 1024).keep_alive(false);
                    // Bound slow readers and SSE lifetime as well as idle connections.
                    let _ = timeout(HTTP_CONNECTION_LIFETIME, builder.serve_connection(TokioIo::new(socket), service_fn(move |request| route(request, state.clone())))).await;
                });
            }
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {},
            _ = cleanup.tick() => state.prune(Instant::now()),
        }
    }
    tasks.abort_all();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> WebState {
        let dir = std::env::temp_dir().join(format!("meshmsg-web-unit-{}", random_id()));
        WebState::new(
            &dir,
            "127.0.0.1:8787".parse().unwrap(),
            Some("https://node.example.ts.net".into()),
        )
        .unwrap()
    }

    fn web_request(value: Value) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "schema_version":contracts::SCHEMA_VERSION,
            "request_id":"11111111111111111111111111111111",
            "request":value
        }))
        .unwrap()
    }

    fn ipc_event(mut value: Value) -> Value {
        value["request_id"] = "11111111111111111111111111111111".into();
        value
    }

    fn headers(host: &str, origin: Option<&str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("host", host.parse().unwrap());
        if let Some(origin) = origin {
            headers.insert("origin", origin.parse().unwrap());
        }
        headers
    }

    #[tokio::test(start_paused = true)]
    async fn sse_startup_connection_and_first_frame_share_one_timeout_budget() {
        let started = TokioInstant::now();
        let deadline = started + IPC_TIMEOUT;
        within_startup_deadline(deadline, tokio::time::sleep(Duration::from_secs(5)))
            .await
            .unwrap();
        assert_eq!(TokioInstant::now() - started, Duration::from_secs(5));

        let second =
            within_startup_deadline(deadline, tokio::time::sleep(Duration::from_secs(4))).await;
        assert!(second.is_err());
        assert_eq!(TokioInstant::now() - started, IPC_TIMEOUT);
    }

    #[test]
    fn upload_fingerprint_ttl_starts_after_long_completion_and_latest_retry() {
        let state = state();
        let id = "0123456789abcdef0123456789abcdef";
        let start = Instant::now();
        let first_gate = state.upload_operation_gate(id, start).unwrap();
        let original = UploadFingerprint {
            name: "same.bin".into(),
            size: 4,
            digest: [1; 32],
        };
        let changed_same_size = UploadFingerprint {
            name: "same.bin".into(),
            size: 4,
            digest: [2; 32],
        };
        let after_long_upload = start + Duration::from_secs(70 * 60);
        assert!(state.check_upload_fingerprint(id, original, after_long_upload));
        let completion = after_long_upload + Duration::from_secs(70 * 60);
        state.refresh_upload_operation(id, completion);
        drop(first_gate);

        let before_expiry = completion + DOWNLOAD_TTL - Duration::from_millis(1);
        let retry_gate = state.upload_operation_gate(id, before_expiry).unwrap();
        assert!(!state.check_upload_fingerprint(id, changed_same_size.clone(), before_expiry));
        drop(retry_gate);
        let after_original_expiry = completion + DOWNLOAD_TTL + Duration::from_secs(1);
        assert!(state
            .upload_operation_gate(id, after_original_expiry)
            .is_some());
        assert!(!state.check_upload_fingerprint(
            id,
            changed_same_size.clone(),
            after_original_expiry,
        ));

        let after_latest_retry_expiry = before_expiry + DOWNLOAD_TTL + Duration::from_secs(2);
        assert!(state
            .upload_operation_gate(id, after_latest_retry_expiry)
            .is_some());
        assert!(state.check_upload_fingerprint(id, changed_same_size, after_latest_retry_expiry,));
    }

    #[test]
    fn public_attachment_errors_preserve_actions_but_hide_private_diagnostics() {
        let operation_id = "0123456789abcdef0123456789abcdef";
        let offer_id = "fedcba9876543210fedcba9876543210";
        for code in [
            "download_failed",
            "share_failed",
            "attachment_lifecycle_internal",
            "attachment_min_free_space",
            "attachment_removal_partial",
        ] {
            let mut private = ipc::LifecycleErrorV1::new(
                code,
                "open /home/alice/private/file.bin failed: database secret detail",
                "unknown",
                true,
            );
            private.operation_id = Some(operation_id.into());
            private.offer_id = Some(offer_id.into());
            private.selected_tags = Some(2);
            private.removed_tags = Some(1);
            private.quota_bytes_released = Some(7);
            let public = public_lifecycle_error(private);
            assert_eq!(public.code, code);
            assert_eq!(public.outcome, "unknown");
            assert!(public.retryable);
            assert_eq!(public.operation_id.as_deref(), Some(operation_id));
            assert_eq!(public.offer_id.as_deref(), Some(offer_id));
            assert_eq!(public.selected_tags, Some(2));
            assert_eq!(public.removed_tags, Some(1));
            assert_eq!(public.quota_bytes_released, Some(7));
            assert!(!public.message.contains("/home/alice"));
            assert!(!public.message.contains("database"));
            assert!(ipc::LifecycleErrorV1::from_value(&public.into_value()).is_ok());
        }
    }

    #[test]
    fn request_id_header_distinguishes_missing_duplicate_malformed_and_valid() {
        let mut headers = HeaderMap::new();
        assert!(matches!(
            request_id_header(&headers),
            RequestIdHeader::Missing
        ));
        headers.append(
            "x-meshmsg-request-id",
            HeaderValue::from_static("11111111111111111111111111111111"),
        );
        assert!(
            matches!(request_id_header(&headers), RequestIdHeader::One(value) if value == "11111111111111111111111111111111")
        );
        headers.append(
            "x-meshmsg-request-id",
            HeaderValue::from_static("22222222222222222222222222222222"),
        );
        assert!(matches!(
            request_id_header(&headers),
            RequestIdHeader::Duplicate
        ));
        headers.remove("x-meshmsg-request-id");
        headers.insert("x-meshmsg-request-id", HeaderValue::from_static("BAD"));
        assert!(matches!(
            request_id_header(&headers),
            RequestIdHeader::Invalid
        ));
    }

    #[test]
    fn mutation_error_dto_is_strict_and_operation_bound() {
        let id = "0123456789abcdef0123456789abcdef";
        let value = json!({
            "type":"error", "schema_version":1, "code":"send_failed",
            "message":"Message submission failed.", "request_id":"11111111111111111111111111111111",
            "operation_id":id, "retryable":true, "outcome":"unknown"
        });
        let parsed = MutationErrorDto::parse(value.clone(), id).unwrap();
        assert_eq!(serde_json::to_value(parsed).unwrap(), value);
        let mut extra = value.clone();
        extra["extra"] = true.into();
        assert!(MutationErrorDto::parse(extra, id).is_none());
        assert!(MutationErrorDto::parse(value, "fedcba9876543210fedcba9876543210").is_none());

        let mut lifecycle =
            ipc::LifecycleErrorV1::new("attachment_quota_exceeded", "quota", "not_started", false);
        lifecycle.request_id = Some("11111111111111111111111111111111".into());
        lifecycle.operation_id = Some(id.into());
        let lifecycle_value = lifecycle.into_value();
        assert!(ipc::LifecycleErrorV1::from_value(&lifecycle_value).is_ok());
        assert!(MutationErrorDto::parse(lifecycle_value.clone(), id).is_some());
        let mut malformed = lifecycle_value;
        malformed["extra"] = true.into();
        assert!(ipc::LifecycleErrorV1::from_value(&malformed).is_err());
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
            assert!(parse_request(&web_request(json!({"command":command}))).is_err());
        }
        for value in [
            json!({"command":"status", "body":"ignored"}),
            json!({"command":"send", "operation_id":"0123456789abcdef0123456789abcdef", "body":" "}),
            json!({"command":"send", "operation_id":"0123456789abcdef0123456789abcdef", "body":"a", "path":"/etc/passwd"}),
            json!({"command":"send", "operation_id":"0123456789abcdef0123456789abcdef", "body":"二".repeat(1366)}),
        ] {
            assert!(parse_request(&web_request(value)).is_err());
        }
        assert!(parse_request(br#"{"schema_version":1,"request_id":"11111111111111111111111111111111","request":{"command":"send","command":"status","body":"a"}}"#).is_err());
        assert!(parse_request(&web_request(json!({"command":"status"}))).is_ok());
        assert!(parse_request(&web_request(json!({"command":"peers"}))).is_ok());
        assert!(parse_request(&web_request(
            json!({"command":"download","id":"0123456789abcdef0123456789abcdef"})
        ))
        .is_ok());
        assert!(parse_request(&web_request(
            json!({"command":"download","id":"../../secret"})
        ))
        .is_err());
        assert!(parse_request(
            &web_request(json!({"command":"send", "operation_id":"0123456789abcdef0123456789abcdef", "body":"二".repeat(1365)}))
        )
        .is_ok());
    }

    #[test]
    fn download_handles_are_opaque_retryable_and_headers_are_safe() {
        let state = state();
        let second = WebState::new(&state.dir, "127.0.0.1:8788".parse().unwrap(), None).unwrap();
        assert_ne!(state.download_root, second.download_root);
        let now = Instant::now();
        let id = state
            .remember_offer(
                "11111111111111111111111111111111",
                "signed-secret",
                "résumé\r\n.txt",
                now,
            )
            .unwrap();
        assert!(valid_id(&id));
        let stored = state.get_offer(&id, now).unwrap();
        assert_eq!(stored.offer, "signed-secret");
        assert_eq!(state.get_offer(&id, now).unwrap().offer, "signed-secret");
        let disposition = content_disposition(&stored.name);
        let header = disposition.to_str().unwrap();
        assert!(!header.contains('\r') && !header.contains('\n'));
        assert!(header.contains("filename*=UTF-8''r%C3%A9sum%C3%A9%0D%0A.txt"));
        let expired = state
            .remember_offer(
                "22222222222222222222222222222222",
                "expired",
                "old.txt",
                now - DOWNLOAD_TTL - Duration::from_secs(1),
            )
            .unwrap();
        assert!(state.get_offer(&expired, now).is_none());
        state.jobs.lock().unwrap().insert(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            DownloadJob::Pending {
                created: now - DOWNLOAD_PENDING_TTL - Duration::from_secs(1),
            },
        );
        state.prune_jobs(now);
        assert!(state.jobs.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn download_deadline_releases_capacity_and_lifetimes_do_not_overlap_cleanup() {
        assert!(STALE_DOWNLOAD_ROOT_AGE > DOWNLOAD_PENDING_TTL + DOWNLOAD_READY_TTL);
        let semaphore = Arc::new(Semaphore::new(1));
        let permit = semaphore.clone().try_acquire_owned().unwrap();
        let result = tokio::spawn(async move {
            let _permit = permit;
            bounded_download_ipc(std::future::pending::<()>(), Duration::from_millis(1)).await
        })
        .await
        .unwrap();
        assert!(result.is_err());
        assert!(semaphore.try_acquire().is_ok());

        let output = PathBuf::from("/tmp/expected.blob");
        let complete = json!({
            "type":"download_complete", "schema_version":1,
            "request_id":"11111111111111111111111111111111",
            "offer_id":"22222222222222222222222222222222",
            "kind":"file", "name":"safe.txt", "size":4,
            "from":"0000000000000000000000000000000000000000000000000000000000000000",
            "output":output.clone(), "installed":true, "pinned":true,
            "destination_synced":true, "cleanup_complete":true, "warnings":[]
        });
        assert!(compatible_download_complete(
            &complete,
            "22222222222222222222222222222222",
            "safe.txt",
            &output,
        ));
        for mutation in [
            ("schema_version", json!(2)),
            ("request_id", json!("bad")),
            ("offer_id", json!("bad")),
            ("kind", json!("unknown")),
            ("name", json!("bad\nname")),
            ("from", json!("peer")),
            ("output", json!("")),
            ("installed", json!(false)),
            ("pinned", json!(false)),
            ("warnings", json!(["bad\twarning"])),
        ] {
            let mut malformed = complete.clone();
            malformed[mutation.0] = mutation.1;
            assert!(!compatible_download_complete(
                &malformed,
                "22222222222222222222222222222222",
                "safe.txt",
                &output,
            ));
        }
        let mut unknown = complete.clone();
        unknown["extra"] = true.into();
        assert!(!compatible_download_complete(
            &unknown,
            "22222222222222222222222222222222",
            "safe.txt",
            &output,
        ));
        assert!(!compatible_download_complete(
            &complete,
            "33333333333333333333333333333333",
            "safe.txt",
            &output,
        ));
    }

    #[test]
    fn ready_refreshes_root_lease() {
        let state = state();
        let lease = state.download_root.join(".lease");
        let before = fs::read(&lease).unwrap();
        touch_download_root(&state.download_root).unwrap();
        assert_ne!(fs::read(lease).unwrap(), before);
    }

    #[cfg(unix)]
    #[test]
    fn download_open_rejects_symbolic_links() {
        use std::os::unix::fs::symlink;
        let state = state();
        let target = state.download_root.join("target");
        let link = state.download_root.join("link");
        fs::write(&target, b"secret").unwrap();
        symlink(&target, &link).unwrap();
        assert!(open_download_file(&link).is_err());
    }

    #[test]
    fn upload_names_and_share_capability_are_strict() {
        assert_eq!(
            decode_upload_name("r%C3%A9sum%C3%A9.txt").as_deref(),
            Some("résumé.txt")
        );
        for invalid in ["%", "%zz", "%ff"] {
            assert!(decode_upload_name(invalid).is_none(), "{invalid}");
        }
        assert_eq!(
            daemon_supports_web_share(&json!({
                "type":"status", "ipc_capabilities":[WEB_SHARE_CAPABILITY, ipc::IDEMPOTENT_MUTATIONS_CAPABILITY],
                "max_attachment_bytes":123
            })),
            Some(123)
        );
        for status in [
            json!({"type":"status", "ipc_capabilities":[], "max_attachment_bytes":123}),
            json!({"type":"status", "ipc_capabilities":[WEB_SHARE_CAPABILITY]}),
            json!({"type":"status", "ipc_capabilities":[WEB_SHARE_CAPABILITY], "max_attachment_bytes":0}),
            json!({"type":"connected", "ipc_capabilities":[WEB_SHARE_CAPABILITY], "max_attachment_bytes":123}),
        ] {
            assert_eq!(daemon_supports_web_share(&status), None);
        }
    }

    #[test]
    fn upload_success_metadata_must_match_the_staged_file() {
        let id = "0123456789abcdef0123456789abcdef";
        let digest = "01".repeat(32);
        let valid = json!({
            "type":"attachment_shared", "schema_version":3,
            "request_id":"11111111111111111111111111111111", "operation_id":id, "message_id":id, "offer_id":id,
            "source_digest":digest, "from":"peer", "timestamp_ms":1,
            "kind":"file", "name":"report.txt", "size":7,
            "ticket":"ticket", "offer":"offer", "delivery_acknowledged":false
        });
        assert!(SharedMutationDto::parse(valid.clone(), id, &digest, "report.txt", 7).is_some());
        for (field, replacement) in [
            ("operation_id", json!("fedcba9876543210fedcba9876543210")),
            ("message_id", json!("fedcba9876543210fedcba9876543210")),
            ("offer_id", json!("fedcba9876543210fedcba9876543210")),
            ("source_digest", json!("02".repeat(32))),
            ("name", json!("other.txt")),
            ("size", json!(8)),
        ] {
            let mut mismatch = valid.clone();
            mismatch[field] = replacement;
            assert!(SharedMutationDto::parse(mismatch, id, &digest, "report.txt", 7).is_none());
        }
        let mut extra = valid;
        extra["extra"] = true.into();
        assert!(SharedMutationDto::parse(extra, id, &digest, "report.txt", 7).is_none());
    }

    #[test]
    fn retained_uploads_are_pruned_only_after_the_race_safety_window() {
        let state = state();
        let operation = state.upload_root.join("retained-operation");
        fs::create_dir(&operation).unwrap();
        fs::write(operation.join("upload.txt"), b"data").unwrap();
        let modified = fs::metadata(&operation).unwrap().modified().unwrap();
        prune_upload_root(
            &state.upload_root,
            modified + RETAINED_UPLOAD_TTL - Duration::from_secs(1),
        );
        assert!(operation.exists());
        prune_upload_root(
            &state.upload_root,
            modified + RETAINED_UPLOAD_TTL + Duration::from_secs(1),
        );
        assert!(!operation.exists());
        assert!(state.upload_root.join(".lease").exists());
    }

    #[test]
    fn sends_are_globally_throttled_without_automatic_retries() {
        let state = state();
        let now = Instant::now();
        let first = "0123456789abcdef0123456789abcdef";
        let second = "fedcba9876543210fedcba9876543210";
        assert!(state.take_send(first, now));
        assert!(state.take_send(first, now));
        assert!(!state.take_send(second, now + Duration::from_millis(999)));
        assert!(state.take_send(second, now + SEND_INTERVAL));
    }

    #[test]
    fn only_safe_live_metadata_is_exposed_and_sse_newlines_are_escaped() {
        let state = state();
        let public_event = |value| public_event(&state, value, true);
        assert!(public_event(json!({"type":"download_progress", "path":"secret"})).is_none());
        let incoming = public_event(ipc_event(json!({
            "type":"attachment_offer", "schema_version":2,
            "message_id":"01010101010101010101010101010101",
            "from":"peer", "timestamp_ms":42,
            "name":"<report>.pdf", "kind":"file", "size":1234,
            "offer_id":"01010101010101010101010101010101",
            "offer":"signed-secret", "ticket":"blob-secret"
        })))
        .unwrap();
        assert!(valid_id(incoming["download_id"].as_str().unwrap()));
        let legacy = super::public_event(
            &state,
            json!({
                "type":"attachment_offer", "schema_version":1,
                "from":"peer", "timestamp_ms":42,
                "name":"legacy.txt", "kind":"file", "size":1, "offer":"secret"
            }),
            false,
        );
        assert!(legacy.is_none());
        let mut expected_incoming = incoming.clone();
        expected_incoming
            .as_object_mut()
            .unwrap()
            .remove("download_id");
        assert_eq!(
            expected_incoming,
            json!({
                "type":"attachment_offer", "schema_version":2,
                "direction":"incoming", "from":"peer",
                "message_id":"01010101010101010101010101010101",
                "timestamp_ms":42, "name":"<report>.pdf", "kind":"file", "size":1234
            })
        );
        let outgoing = public_event(ipc_event(json!({
            "type":"attachment_shared", "schema_version":3,
            "operation_id":"02020202020202020202020202020202",
            "message_id":"02020202020202020202020202020202",
            "offer_id":"02020202020202020202020202020202",
            "source_digest":"02".repeat(32),
            "from":"local", "timestamp_ms":43,
            "name":"folder.tar", "kind":"directory_tar_v1", "size":5678,
            "offer":"signed-secret", "ticket":"blob-secret", "delivery_acknowledged":false
        })))
        .unwrap();
        assert_eq!(
            outgoing,
            json!({
                "type":"attachment_shared", "schema_version":3,
                "direction":"outgoing", "from":"local",
                "operation_id":"02020202020202020202020202020202",
                "message_id":"02020202020202020202020202020202",
                "timestamp_ms":43, "name":"folder.tar", "kind":"directory_tar_v1", "size":5678
            })
        );
        assert!(!incoming.to_string().contains("secret"));
        assert!(!outgoing.to_string().contains("secret"));
        assert!(public_event(json!({
            "type":"private_message", "from":"peer", "body":"dm-secret",
            "private":true, "timestamp_ms":44
        }))
        .is_none());
        assert!(public_event(json!({
            "type":"private_accepted", "to":"peer", "body":"dm-secret"
        }))
        .is_none());
        assert!(public_event(json!({
            "type":"peer_up", "peer":{"endpoint":"private-route", "body":"secret"}
        }))
        .is_none());
        assert!(public_event(json!({
            "type":"connected", "peer":{"endpoint":"private-route", "body":"secret"}
        }))
        .is_none());
        let connected_source = ipc_event(json!({
            "type":"connected", "schema_version":1, "peer":iroh::SecretKey::generate().public().to_string(),
            "endpoint_online":true, "topic_joined":true, "alias":null,
            "ipc_capabilities":[WEB_DOWNLOAD_CAPABILITY]
        }));
        let connected = public_event(connected_source.clone()).unwrap();
        assert!(connected["download_supported"].as_bool().unwrap());
        let mut offline_handshake = connected_source;
        offline_handshake["endpoint_online"] = false.into();
        assert!(public_event(offline_handshake).is_none());
        for low_level_neighbor_event in [
            json!({"type":"peer_up", "peer":"2su5Z4MwjA5XsXQFa4c8sEqi2zS6SLLXv4k7Fv9VwK8"}),
            json!({"type":"peer_down", "peer":"10.0.0.1:443"}),
            json!({"type":"peer_up", "peer":[{"endpoint":"private-route"}]}),
        ] {
            assert!(public_event(low_level_neighbor_event).is_none());
        }
        let malformed_status = public_status(&json!({
            "type":"status", "peer":{"endpoint":"private-route", "body":"secret"},
            "running":{"body":"secret"}, "neighbors":[{"address":"private"}],
            "endpoint_online":true, "topic_joined":false
        }));
        assert_eq!(
            malformed_status,
            json!({"type":"status", "endpoint_online":true, "topic_joined":false})
        );
        assert!(!malformed_status.to_string().contains("private"));
        assert!(!malformed_status.to_string().contains("body"));
        let value = public_event(ipc_event(json!({
            "type":"message", "schema_version":2,
            "message_id":"03030303030303030303030303030303",
            "body":"<script>\ndata: injected\n", "from":"peer", "timestamp_ms":41
        })))
        .unwrap();
        let frame = String::from_utf8(sse_frame(&value).to_vec()).unwrap();
        assert_eq!(frame.lines().count(), 2);
        assert!(!frame.contains("secret"));
        let queued = public_event(ipc_event(json!({
            "type":"queued", "schema_version":3,
            "operation_id":"04040404040404040404040404040404",
            "message_id":"04040404040404040404040404040404",
            "from":"local", "body":"hello", "timestamp_ms":42,
            "delivery_acknowledged":false
        })))
        .unwrap();
        assert_eq!(
            queued,
            json!({
                "type":"queued", "schema_version":3,
                "operation_id":"04040404040404040404040404040404",
                "message_id":"04040404040404040404040404040404",
                "from":"local", "body":"hello", "timestamp_ms":42,
                "delivery_acknowledged":false
            })
        );
        let status = public_status(
            &json!({"type":"status", "peer":"peer", "socket":"private", "invite":"secret"}),
        );
        assert!(status.get("socket").is_none());
        assert!(status.get("invite").is_none());
        let status = public_status(&json!({
            "type":"status", "attachment_retention_secs":60,
            "attachment_storage":{
                "tagged_bytes":10, "tagged_blobs":1, "tags":2, "tag_capacity":8192,
                "quota_bytes":100, "available_bytes":1000, "min_free_bytes":20,
                "sampled_at_ms":1, "pressure":false, "over_quota":false, "below_min_free":false,
                "path":"private"
            }
        }));
        assert_eq!(status["attachment_retention_secs"], 60);
        assert_eq!(status["attachment_storage"]["tagged_bytes"], 10);
        assert!(status["attachment_storage"].get("path").is_none());
        let malformed = public_status(&json!({
            "type":"status", "attachment_storage":{"tagged_bytes":10}
        }));
        assert!(malformed.get("attachment_storage").is_none());

        let self_key = iroh::SecretKey::generate().public().to_string();
        let remote_key = iroh::SecretKey::generate().public().to_string();
        let injected = ipc_event(json!({
            "type":"peers_snapshot", "schema_version":2, "generated_at_ms":1_000,
            "directory_epoch":"0123456789abcdef0123456789abcdef", "directory_revision":0,
            "self":{"public_key":self_key, "alias":"local", "online":true},
            "peers":[{
                "public_key":remote_key, "alias":null, "online":true,
                "last_seen_ms":900, "expires_at_ms":1_100
            }]
        }));
        let sanitized = public_peers_snapshot(&injected).unwrap();
        assert_eq!(sanitized["type"], "peers_snapshot");
        assert_eq!(sanitized["self"]["public_key"], self_key);
        assert_eq!(sanitized["peers"][0]["public_key"], remote_key);
        for forbidden in [
            "endpoint",
            "address",
            "socket",
            "invite",
            "capabilities",
            "body",
            "secret",
            "route",
        ] {
            assert!(
                !sanitized.to_string().contains(forbidden),
                "leaked {forbidden}"
            );
        }
        let transition = public_event(ipc_event(json!({
            "type":"peer_updated", "schema_version":2,
            "directory_epoch":"0123456789abcdef0123456789abcdef", "directory_revision":1,
            "peer":{
                "public_key":remote_key, "alias":"renamed", "online":true,
                "last_seen_ms":1_000, "expires_at_ms":151_000
            }
        })))
        .unwrap();
        assert_eq!(transition["type"], "peer_updated");
        assert!(transition["peer"].get("endpoint").is_none());
        assert!(transition["peer"].get("body").is_none());
        assert!(public_event(json!({
            "type":"peer_discovered", "schema_version":1,
            "peer":{
                "public_key":remote_key, "alias":"UPPER", "online":true,
                "last_seen_ms":1_000, "expires_at_ms":1_100
            }
        }))
        .is_none());
    }

    #[test]
    fn embedded_ui_uses_text_rendering_and_restrictive_csp() {
        let js = include_str!("web/app.js");
        let settings_js = include_str!("web/settings.js");
        let index = include_str!("web/index.html");
        let settings = include_str!("web/settings.html");
        for source in [js, settings_js] {
            assert!(!source.contains("innerHTML"));
            assert!(!source.contains("localStorage"));
            assert!(source.contains("textContent"));
        }
        assert!(js.contains("feed.children.length > 100"));
        assert!(index.contains("href=\"/settings\""));
        assert!(index.contains("type=\"file\""));
        assert!(js.contains("fetch('/api/attachment'"));
        assert!(!index.contains("Local daemon"));
        assert!(settings.contains("MESHMSG STATUS"));
        for private in ["state dir", "invite", "offer", "token", "ticket"] {
            assert!(!settings.to_ascii_lowercase().contains(private));
        }
        let response = response(StatusCode::OK, "text/html", "test");
        assert_eq!(response.headers()["content-security-policy"], CSP);
        assert!(!CSP.contains("unsafe-inline"));
        assert!(!response
            .headers()
            .contains_key("access-control-allow-origin"));
    }
}
