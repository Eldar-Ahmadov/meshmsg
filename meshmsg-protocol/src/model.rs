use crate::id::{ContentDigest, MessageId, OfferId, OperationId, PeerId, RequestId, TopicId};
use crate::PROTOCOL_VERSION;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::{fmt, path::PathBuf};

pub const MAX_PEERS: usize = 1024;
pub const PEER_LEASE_MS: u64 = 150_000;
pub const MAX_OFFERS: usize = 512;
pub const MAX_OFFER_SCAN: usize = 4096;
pub const MAX_LIFECYCLE_ITEMS: usize = 512;
pub const MAX_WARNINGS: usize = 32;
pub const MAX_PUBLIC_TEXT_BYTES: usize = 1024;
/// Maximum UTF-8 serialization length of every local IPC path on every target.
pub const MAX_IPC_PATH_BYTES: usize = 32 * 1024;

/// A marker that serializes as the one supported protocol version and rejects
/// every other value while deserializing.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProtocolVersion;

impl Serialize for ProtocolVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u8(PROTOCOL_VERSION)
    }
}

impl PartialEq<u8> for ProtocolVersion {
    fn eq(&self, other: &u8) -> bool {
        *other == PROTOCOL_VERSION
    }
}

impl<'de> Deserialize<'de> for ProtocolVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let version = u8::deserialize(deserializer)?;
        if version == PROTOCOL_VERSION {
            Ok(Self)
        } else {
            Err(de::Error::custom(format_args!(
                "unsupported protocol version {version}; expected {PROTOCOL_VERSION}"
            )))
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RequestFrame {
    pub protocol_version: ProtocolVersion,
    pub request_id: RequestId,
    pub request: Request,
}

impl RequestFrame {
    pub fn try_new(request_id: RequestId, request: Request) -> Result<Self, &'static str> {
        request.validate()?;
        Ok(Self {
            protocol_version: ProtocolVersion,
            request_id,
            request,
        })
    }

    pub fn new(request_id: RequestId, request: Request) -> Self {
        Self::try_new(request_id, request).expect("invalid protocol request construction")
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        self.request.validate()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestFrameWire {
    protocol_version: ProtocolVersion,
    request_id: RequestId,
    request: Request,
}

impl<'de> Deserialize<'de> for RequestFrame {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = RequestFrameWire::deserialize(deserializer)?;
        wire.request.validate().map_err(de::Error::custom)?;
        Ok(Self {
            protocol_version: wire.protocol_version,
            request_id: wire.request_id,
            request: wire.request,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Send {
        operation_id: OperationId,
        body: BroadcastBody,
    },
    PrivateSend {
        operation_id: OperationId,
        to: Recipient,
        body: PrivateBody,
    },
    Subscribe,
    Status,
    Peers,
    Offers,
    OffersRemove {
        operation_id: OperationId,
        offer_id: OfferId,
        direction: Option<OfferDirection>,
        provider: Option<PeerId>,
    },
    OffersPrune {
        operation_id: OperationId,
        older_than_secs: u64,
        direction: Option<OfferDirection>,
        dry_run: bool,
        max_delete: usize,
    },
    Share {
        operation_id: OperationId,
        source_digest: ContentDigest,
        path: PathBuf,
    },
    Download {
        operation_id: OperationId,
        offer: String,
        output: PathBuf,
        mode: DownloadMode,
    },
    Stop,
}

impl Request {
    fn validate(&self) -> Result<(), &'static str> {
        match self {
            Self::OffersPrune { max_delete, .. }
                if !(1..=MAX_LIFECYCLE_ITEMS).contains(max_delete) =>
            {
                Err("invalid lifecycle maximum")
            }
            Self::Share { path, .. } if !safe_ipc_path(path) => Err("unsafe share path"),
            Self::Download { offer, output, .. }
                if offer.is_empty()
                    || offer.len() > AttachmentToken::MAX_BYTES
                    || !safe_ipc_path(output) =>
            {
                Err("invalid download request")
            }
            _ => Ok(()),
        }
    }

    /// Validates that a daemon response belongs to this request's response
    /// family and, for mutations, carries the same operation ID.
    pub fn validate_response(&self, response: &Response) -> Result<(), &'static str> {
        response.validate()?;
        if let Response::Error(error) = response {
            return self.validate_error_response(error);
        }

        let family_matches = matches!(
            (self, response),
            (Self::Send { .. }, Response::Queued(_))
                | (Self::PrivateSend { .. }, Response::PrivateAccepted(_))
                | (Self::Status, Response::Status(_))
                | (Self::Peers, Response::PeersSnapshot(_))
                | (Self::Offers, Response::Offers(_))
                | (Self::OffersRemove { .. }, Response::OfferRemoved(_))
                | (Self::OffersPrune { .. }, Response::OffersPruned(_))
                | (Self::Share { .. }, Response::AttachmentShared(_))
                | (Self::Download { .. }, Response::DownloadComplete(_))
                | (Self::Stop, Response::Stopping {})
        );
        if !family_matches {
            return Err("daemon response family does not match request");
        }

        if let Some(expected) = self.operation_id() {
            let actual = match response {
                Response::Queued(value) => Some(&value.operation_id),
                Response::PrivateAccepted(value) => Some(&value.operation_id),
                Response::OfferRemoved(value) => Some(&value.operation_id),
                Response::OffersPruned(value) => Some(&value.operation_id),
                Response::AttachmentShared(value) => Some(&value.operation_id),
                Response::DownloadComplete(value) => Some(&value.operation_id),
                _ => None,
            };
            if actual != Some(expected) {
                return Err("daemon response operation ID does not match request");
            }
        }
        Ok(())
    }

    fn operation_id(&self) -> Option<&OperationId> {
        match self {
            Self::Send { operation_id, .. }
            | Self::PrivateSend { operation_id, .. }
            | Self::OffersRemove { operation_id, .. }
            | Self::OffersPrune { operation_id, .. }
            | Self::Share { operation_id, .. }
            | Self::Download { operation_id, .. } => Some(operation_id),
            Self::Subscribe | Self::Status | Self::Peers | Self::Offers | Self::Stop => None,
        }
    }

    fn validate_error_response(&self, error: &ProtocolError) -> Result<(), &'static str> {
        let pre_admission = error.operation_id.is_none()
            && matches!(
                error.code,
                ErrorCode::IpcCapacity | ErrorCode::InitialFrameTimeout
            );
        if pre_admission || error.operation_id.as_ref() == self.operation_id() {
            Ok(())
        } else {
            Err("daemon error operation ID does not match request")
        }
    }
}

macro_rules! bounded_text {
    ($name:ident, $maximum:expr, $description:literal) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub const MAX_BYTES: usize = $maximum;

            pub fn new(value: impl Into<String>) -> Result<Self, TextError> {
                let value = value.into();
                if value.is_empty()
                    || value.len() > Self::MAX_BYTES
                    || value.chars().any(char::is_control)
                {
                    return Err(TextError($description, Self::MAX_BYTES));
                }
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn into_string(self) -> String {
                self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.0)
                    .finish()
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                Self::new(String::deserialize(deserializer)?).map_err(de::Error::custom)
            }
        }

        impl std::str::FromStr for $name {
            type Err = TextError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }
    };
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TextError(&'static str, usize);

impl fmt::Display for TextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid {} (expected 1..={} UTF-8 bytes)",
            self.0, self.1
        )
    }
}

impl std::error::Error for TextError {}

macro_rules! message_body {
    ($name:ident, $maximum:expr, $description:literal) => {
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub const MAX_BYTES: usize = $maximum;

            pub fn new(value: impl Into<String>) -> Result<Self, TextError> {
                let value = value.into();
                if value.is_empty() || value.len() > Self::MAX_BYTES {
                    return Err(TextError($description, Self::MAX_BYTES));
                }
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn into_string(self) -> String {
                self.0
            }
        }

        impl std::ops::Deref for $name {
            type Target = str;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                Self::new(String::deserialize(deserializer)?).map_err(de::Error::custom)
            }
        }
    };
}

message_body!(
    BroadcastBody,
    crate::MAX_BROADCAST_BODY_BYTES,
    "broadcast message body"
);
// Private/direct traffic deliberately retains its independent 4096-byte body
// and 6 KiB transport-frame contract.
message_body!(PrivateBody, 4096, "private message body");
message_body!(MessageBody, 4096, "message body");
bounded_text!(
    AttachmentToken,
    crate::MAX_SIGNED_ATTACHMENT_TOKEN_BYTES,
    "attachment token"
);
bounded_text!(Alias, 63, "alias");
bounded_text!(Recipient, 64, "private message recipient");

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AttachmentName(String);

impl AttachmentName {
    pub const MAX_BYTES: usize = 100;

    pub fn new(value: impl Into<String>) -> Result<Self, TextError> {
        let value = value.into();
        let invalid_device = value.split('.').next().is_some_and(|stem| {
            matches!(
                stem.to_ascii_uppercase().as_str(),
                "CON"
                    | "PRN"
                    | "AUX"
                    | "NUL"
                    | "COM1"
                    | "COM2"
                    | "COM3"
                    | "COM4"
                    | "COM5"
                    | "COM6"
                    | "COM7"
                    | "COM8"
                    | "COM9"
                    | "LPT1"
                    | "LPT2"
                    | "LPT3"
                    | "LPT4"
                    | "LPT5"
                    | "LPT6"
                    | "LPT7"
                    | "LPT8"
                    | "LPT9"
            )
        });
        let invalid = value.is_empty()
            || value == "."
            || value == ".."
            || value.len() > Self::MAX_BYTES
            || value.chars().any(char::is_control)
            || value.contains(['/', '\\'])
            || value
                .chars()
                .any(|character| matches!(character, '<' | '>' | ':' | '"' | '|' | '?' | '*'))
            || value.ends_with(['.', ' '])
            || invalid_device;
        if invalid {
            Err(TextError("portable attachment name", Self::MAX_BYTES))
        } else {
            Ok(Self(value))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl Serialize for AttachmentName {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for AttachmentName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DownloadMode {
    Install,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OfferDirection {
    Incoming,
    Outgoing,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectionError;

impl fmt::Display for DirectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid offer direction")
    }
}

impl std::error::Error for DirectionError {}

impl std::str::FromStr for OfferDirection {
    type Err = DirectionError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "incoming" => Ok(Self::Incoming),
            "outgoing" => Ok(Self::Outgoing),
            _ => Err(DirectionError),
        }
    }
}

impl fmt::Display for OfferDirection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Incoming => "incoming",
            Self::Outgoing => "outgoing",
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttachmentKind {
    File,
    DirectoryTarV1,
}

impl std::str::FromStr for AttachmentKind {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "file" => Ok(Self::File),
            "directory_tar_v1" => Ok(Self::DirectoryTarV1),
            _ => Err("invalid attachment kind"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ResponseFrame {
    pub protocol_version: ProtocolVersion,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<RequestId>,
    #[serde(flatten)]
    pub response: Response,
}

impl ResponseFrame {
    pub fn try_new(
        request_id: Option<RequestId>,
        response: Response,
    ) -> Result<Self, &'static str> {
        response.validate()?;
        valid_response_correlation(request_id.as_ref(), &response)?;
        Ok(Self {
            protocol_version: ProtocolVersion,
            request_id,
            response,
        })
    }

    pub fn new(request_id: Option<RequestId>, response: Response) -> Self {
        Self::try_new(request_id, response).expect("invalid protocol response construction")
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Response {
    Status(Status),
    Queued(Queued),
    PrivateAccepted(PrivateAccepted),
    #[serde(rename = "peers_snapshot")]
    PeersSnapshot(PeerSnapshot),
    Offers(OffersList),
    AttachmentShared(AttachmentShared),
    #[serde(rename = "offer_removed")]
    OfferRemoved(OfferRemoved),
    OffersPruned(OffersPruned),
    DownloadComplete(DownloadResult),
    Stopping {},
    Error(ProtocolError),
}

#[derive(Deserialize)]
struct ResponseFrameWire {
    protocol_version: ProtocolVersion,
    request_id: Option<RequestId>,
    #[serde(flatten)]
    response: Response,
}

impl<'de> Deserialize<'de> for ResponseFrame {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ResponseFrameWire::deserialize(deserializer)?;
        wire.response.validate().map_err(de::Error::custom)?;
        valid_response_correlation(wire.request_id.as_ref(), &wire.response)
            .map_err(de::Error::custom)?;
        Ok(Self {
            protocol_version: wire.protocol_version,
            request_id: wire.request_id,
            response: wire.response,
        })
    }
}

fn valid_response_correlation(
    request_id: Option<&RequestId>,
    response: &Response,
) -> Result<(), &'static str> {
    match (request_id, response) {
        (
            None,
            Response::Error(ProtocolError {
                operation_id: None,
                code:
                    ErrorCode::IpcCapacity | ErrorCode::InitialFrameTimeout | ErrorCode::InvalidRequest,
                ..
            }),
        ) => Ok(()),
        (Some(_), _) => Ok(()),
        _ => Err("uncorrelated daemon response"),
    }
}

impl Response {
    pub fn validate(&self) -> Result<(), &'static str> {
        match self {
            Self::Status(status) => status.validate(),
            Self::Queued(value) => value.validate(),
            Self::PrivateAccepted(value) => value.validate(),
            Self::PeersSnapshot(value) => value.validate(),
            Self::Offers(value) => value.validate(),
            Self::AttachmentShared(value) => value.validate(),
            Self::OfferRemoved(value) => value.validate(),
            Self::OffersPruned(value) => value.validate(),
            Self::DownloadComplete(value) => value.validate(),
            Self::Stopping {} => Ok(()),
            Self::Error(value) => value.validate(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct EventFrame {
    pub protocol_version: ProtocolVersion,
    pub request_id: RequestId,
    #[serde(flatten)]
    pub event: Event,
}

impl EventFrame {
    pub fn try_new(request_id: RequestId, event: Event) -> Result<Self, &'static str> {
        event.validate()?;
        Ok(Self {
            protocol_version: ProtocolVersion,
            request_id,
            event,
        })
    }

    pub fn new(request_id: RequestId, event: Event) -> Self {
        Self::try_new(request_id, event).expect("invalid protocol event construction")
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Event {
    Connected(Connected),
    Message(Message),
    PrivateMessage(PrivateMessage),
    Queued(Queued),
    AttachmentOffer(AttachmentOffer),
    AttachmentShared(AttachmentShared),
    PeersSnapshot(PeerSnapshot),
    PeerDiscovered(PeerTransition),
    PeerUpdated(PeerTransition),
    PeerExpired(PeerTransition),
    DownloadStarted {
        operation_id: OperationId,
        output: PathBuf,
    },
    DownloadProgress {
        operation_id: OperationId,
        received_bytes: u64,
        total_bytes: u64,
        output: PathBuf,
    },
    DownloadComplete(DownloadResult),
    Lagged {
        source: EventSource,
        dropped: u64,
        message: String,
    },
}

#[derive(Deserialize)]
struct EventFrameWire {
    protocol_version: ProtocolVersion,
    request_id: RequestId,
    #[serde(flatten)]
    event: Event,
}

impl<'de> Deserialize<'de> for EventFrame {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = EventFrameWire::deserialize(deserializer)?;
        wire.event.validate().map_err(de::Error::custom)?;
        Ok(Self {
            protocol_version: wire.protocol_version,
            request_id: wire.request_id,
            event: wire.event,
        })
    }
}

impl Event {
    fn validate(&self) -> Result<(), &'static str> {
        match self {
            Self::Connected(_) => Ok(()),
            Self::Message(value) => value.validate(),
            Self::PrivateMessage(value) => value.validate(),
            Self::Queued(value) => value.validate(),
            Self::AttachmentOffer(value) => value.validate(),
            Self::AttachmentShared(value) => value.validate(),
            Self::PeersSnapshot(value) => value.validate(),
            Self::PeerDiscovered(value) | Self::PeerUpdated(value) => value.validate(true),
            Self::PeerExpired(value) => value.validate(false),
            Self::DownloadStarted { output, .. } if safe_ipc_path(output) => Ok(()),
            Self::DownloadStarted { .. } => Err("unsafe download output path"),
            Self::DownloadProgress {
                received_bytes,
                total_bytes,
                output,
                ..
            } if received_bytes <= total_bytes && safe_ipc_path(output) => Ok(()),
            Self::DownloadProgress { .. } => Err("invalid download progress"),
            Self::DownloadComplete(value) => value.validate(),
            Self::Lagged { message, .. } if valid_public_text(message, MAX_PUBLIC_TEXT_BYTES) => {
                Ok(())
            }
            Self::Lagged { .. } => Err("invalid lag event"),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttachmentStorageStatus {
    pub tagged_bytes: u64,
    pub tagged_blobs: usize,
    pub tags: usize,
    pub tag_capacity: usize,
    pub quota_bytes: u64,
    pub available_bytes: u64,
    pub min_free_bytes: u64,
    pub pressure: bool,
    pub over_quota: bool,
    pub below_min_free: bool,
    pub sampled_at_ms: u64,
}

impl AttachmentStorageStatus {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.tags > self.tag_capacity
            || self.tagged_blobs > self.tags
            || self.over_quota != (self.tagged_bytes > self.quota_bytes)
            || self.below_min_free != (self.available_bytes < self.min_free_bytes)
            || self.pressure != (self.over_quota || self.below_min_free)
        {
            return Err("invalid attachment storage status");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    pub running: bool,
    pub peer: PeerId,
    pub topic: TopicId,
    pub advertises_self: bool,
    pub has_invite: bool,
    pub bootstrap_peer_count: usize,
    pub self_advertised: bool,
    pub neighbors: usize,
    pub endpoint_online: bool,
    pub topic_joined: bool,
    pub alias: Option<Alias>,
    pub alias_enabled: bool,
    pub captured_hostname: Option<String>,
    pub custom_alias: Option<String>,
    pub advertised_aliases: usize,
    pub operation_cache_capacity: usize,
    pub operation_cache_ttl_ms: u64,
    pub operation_cache_persistent: bool,
    pub direct_replay_available: bool,
    pub direct_replay_error: Option<String>,
    pub direct_replay_capacity: usize,
    pub direct_replay_per_sender_capacity: usize,
    pub direct_replay_queue_capacity: usize,
    pub direct_replay_global_rate_per_second: u64,
    pub direct_replay_global_rate_burst: u64,
    pub direct_replay_sender_rate_per_second: u64,
    pub direct_replay_sender_rate_burst: u64,
    pub max_attachment_bytes: u64,
    pub attachment_storage: AttachmentStorageStatus,
    pub attachment_retention_secs: u64,
}

impl Status {
    pub fn validate(&self) -> Result<(), &'static str> {
        fn valid_public_text(value: &str, maximum: usize) -> bool {
            !value.is_empty() && value.len() <= maximum && !value.chars().any(char::is_control)
        }

        if !self.running
            || self.max_attachment_bytes == 0
            || self
                .captured_hostname
                .as_deref()
                .is_some_and(|value| !valid_public_text(value, 253))
            || self
                .custom_alias
                .as_deref()
                .is_some_and(|value| !valid_public_text(value, 63))
            || self
                .direct_replay_error
                .as_deref()
                .is_some_and(|value| !valid_public_text(value, 1024))
        {
            return Err("invalid status values");
        }
        self.attachment_storage.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Connected {
    pub peer: PeerId,
    pub endpoint_online: bool,
    pub topic_joined: bool,
    pub alias: Option<Alias>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Message {
    pub from: PeerId,
    pub message_id: MessageId,
    pub timestamp_ms: u64,
    pub body: BroadcastBody,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateMessage {
    pub private: bool,
    pub from: PeerId,
    pub message_id: MessageId,
    pub timestamp_ms: u64,
    pub body: MessageBody,
    pub acceptance_acknowledged: bool,
    pub durable: bool,
    pub read: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Queued {
    pub operation_id: OperationId,
    pub from: PeerId,
    pub message_id: MessageId,
    pub timestamp_ms: u64,
    pub body: BroadcastBody,
    pub delivery_acknowledged: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateAccepted {
    pub operation_id: OperationId,
    pub to: PeerId,
    pub message_id: MessageId,
    pub timestamp_ms: u64,
    pub body_bytes: usize,
    pub acceptance_acknowledged: bool,
    pub duplicate_accepted: bool,
    pub durable: bool,
    pub read: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttachmentOffer {
    pub from: PeerId,
    pub message_id: MessageId,
    pub timestamp_ms: u64,
    pub offer_id: OfferId,
    pub kind: AttachmentKind,
    pub name: AttachmentName,
    pub size: u64,
    pub ticket: AttachmentToken,
    pub offer: AttachmentToken,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelfPeer {
    pub public_key: PeerId,
    pub alias: Option<Alias>,
    pub online: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RemotePeer {
    pub public_key: PeerId,
    pub alias: Option<Alias>,
    pub online: bool,
    pub last_seen_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PeerSnapshot {
    pub generated_at_ms: u64,
    pub directory_epoch: OperationId,
    pub directory_revision: u64,
    #[serde(rename = "self")]
    pub self_peer: SelfPeer,
    pub peers: Vec<RemotePeer>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PeerTransition {
    pub directory_epoch: OperationId,
    pub directory_revision: u64,
    pub peer: RemotePeer,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OfferListItem {
    pub direction: OfferDirection,
    pub offer_id: OfferId,
    pub provider: Option<PeerId>,
    pub name: AttachmentName,
    pub kind: AttachmentKind,
    pub hash: ContentDigest,
    pub format: String,
    pub status: String,
    pub size: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OffersList {
    pub blobs: Vec<OfferListItem>,
    pub truncated: bool,
    pub item_errors: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttachmentShared {
    pub operation_id: OperationId,
    pub from: PeerId,
    pub message_id: MessageId,
    pub timestamp_ms: u64,
    pub offer_id: OfferId,
    pub source_digest: ContentDigest,
    pub kind: AttachmentKind,
    pub name: AttachmentName,
    pub size: u64,
    pub ticket: AttachmentToken,
    pub offer: AttachmentToken,
    pub delivery_acknowledged: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OfferRemoved {
    pub operation_id: OperationId,
    pub offer_id: OfferId,
    pub direction: Option<OfferDirection>,
    pub provider: Option<PeerId>,
    pub maximum: usize,
    pub selected_tags: usize,
    pub removed_tags: usize,
    pub released_bytes: u64,
    pub limited: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OffersPruned {
    pub operation_id: OperationId,
    pub direction: Option<OfferDirection>,
    pub older_than_secs: u64,
    pub maximum: usize,
    pub dry_run: bool,
    pub selected_tags: usize,
    pub removed_tags: usize,
    pub released_bytes: u64,
    pub limited: bool,
    pub cutoff_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DownloadRequestContext {
    pub operation_id: OperationId,
    pub token_digest: ContentDigest,
    pub offer_id: OfferId,
    pub provider: PeerId,
    pub kind: AttachmentKind,
    pub name: AttachmentName,
    pub declared_size: Option<u64>,
    pub output: PathBuf,
    pub mode: DownloadMode,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DownloadResult {
    pub operation_id: OperationId,
    pub token_digest: ContentDigest,
    pub offer_id: OfferId,
    pub kind: AttachmentKind,
    pub name: AttachmentName,
    pub size: u64,
    pub from: PeerId,
    pub output: PathBuf,
    pub mode: DownloadMode,
    pub installed: bool,
    pub pinned: bool,
    pub destination_synced: bool,
    pub cleanup_complete: bool,
    pub warnings: Vec<String>,
}

fn valid_public_text(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && !value.chars().any(char::is_control)
}

pub fn validate_ipc_path(path: &std::path::Path) -> Result<(), &'static str> {
    (path.is_absolute()
        && path
            .to_str()
            .is_some_and(|value| !value.is_empty() && value.len() <= MAX_IPC_PATH_BYTES))
    .then_some(())
    .ok_or("IPC path must be absolute UTF-8 and at most 32768 bytes")
}

fn safe_ipc_path(path: &std::path::Path) -> bool {
    validate_ipc_path(path).is_ok()
}

impl Message {
    fn validate(&self) -> Result<(), &'static str> {
        (self.timestamp_ms != 0)
            .then_some(())
            .ok_or("invalid message timestamp")
    }
}

impl PrivateMessage {
    fn validate(&self) -> Result<(), &'static str> {
        (self.private
            && self.timestamp_ms != 0
            && self.acceptance_acknowledged
            && !self.durable
            && !self.read)
            .then_some(())
            .ok_or("invalid private-message acceptance flags")
    }
}

impl Queued {
    fn validate(&self) -> Result<(), &'static str> {
        (self.operation_id.as_str() == self.message_id.as_str()
            && self.timestamp_ms != 0
            && !self.delivery_acknowledged)
            .then_some(())
            .ok_or("invalid queued-message correlation")
    }
}

impl PrivateAccepted {
    fn validate(&self) -> Result<(), &'static str> {
        (self.operation_id.as_str() == self.message_id.as_str()
            && self.timestamp_ms != 0
            && self.body_bytes > 0
            && self.body_bytes <= PrivateBody::MAX_BYTES
            && self.acceptance_acknowledged
            && !self.durable
            && !self.read)
            .then_some(())
            .ok_or("invalid private acceptance")
    }
}

fn valid_signed_offer_shape(value: &AttachmentToken) -> bool {
    !value.as_str().is_empty()
        && data_encoding::BASE64URL_NOPAD
            .decode(value.as_str().as_bytes())
            .is_ok_and(|decoded| !decoded.is_empty())
}

impl AttachmentOffer {
    fn validate(&self) -> Result<(), &'static str> {
        (self.offer_id.as_str() == self.message_id.as_str()
            && self.timestamp_ms != 0
            && !self.ticket.as_str().is_empty()
            && valid_signed_offer_shape(&self.offer))
        .then_some(())
        .ok_or("invalid attachment offer binding")
    }
}

impl AttachmentShared {
    fn validate(&self) -> Result<(), &'static str> {
        (self.operation_id.as_str() == self.message_id.as_str()
            && self.offer_id.as_str() == self.message_id.as_str()
            && self.timestamp_ms != 0
            && !self.ticket.as_str().is_empty()
            && valid_signed_offer_shape(&self.offer)
            && !self.delivery_acknowledged)
            .then_some(())
            .ok_or("invalid shared-attachment binding")
    }
}

impl RemotePeer {
    fn validate(&self, expected_online: bool) -> Result<(), &'static str> {
        (self.online == expected_online
            && self.expires_at_ms >= self.last_seen_ms
            && self.expires_at_ms.saturating_sub(self.last_seen_ms) <= PEER_LEASE_MS)
            .then_some(())
            .ok_or("invalid peer lease")
    }
}

impl PeerSnapshot {
    fn validate(&self) -> Result<(), &'static str> {
        if self.peers.len() > MAX_PEERS {
            return Err("peer snapshot exceeds capacity");
        }
        let mut previous: Option<&PeerId> = None;
        for peer in &self.peers {
            peer.validate(true)?;
            if peer.public_key == self.self_peer.public_key
                || previous.is_some_and(|value| value >= &peer.public_key)
                || peer.last_seen_ms > self.generated_at_ms
                || peer.expires_at_ms < self.generated_at_ms
                || peer.expires_at_ms.saturating_sub(self.generated_at_ms) > PEER_LEASE_MS
            {
                return Err("invalid peer snapshot ordering or lease");
            }
            previous = Some(&peer.public_key);
        }
        Ok(())
    }
}

impl PeerTransition {
    fn validate(&self, online: bool) -> Result<(), &'static str> {
        if self.directory_revision == 0 {
            return Err("invalid peer directory revision");
        }
        self.peer.validate(online)
    }
}

impl OfferListItem {
    fn validate(&self) -> Result<(), &'static str> {
        let selector_valid = match self.direction {
            OfferDirection::Incoming => self.provider.is_some(),
            OfferDirection::Outgoing => self.provider.is_none(),
        };
        (selector_valid && self.format == "raw" && self.status == "complete" && self.size.is_some())
            .then_some(())
            .ok_or("invalid offer list item")
    }
}

impl OffersList {
    fn validate(&self) -> Result<(), &'static str> {
        if self.blobs.len() > MAX_OFFERS
            || self.item_errors > MAX_OFFER_SCAN
            || self.item_errors != 0 && !self.truncated
        {
            return Err("invalid offer listing bounds");
        }
        self.blobs.iter().try_for_each(OfferListItem::validate)
    }
}

fn validate_lifecycle_counts(
    maximum: usize,
    dry_run: bool,
    selected_tags: usize,
    removed_tags: usize,
    released_bytes: u64,
    limited: bool,
) -> Result<(), &'static str> {
    (maximum > 0
        && maximum <= MAX_LIFECYCLE_ITEMS
        && selected_tags <= maximum
        && removed_tags <= selected_tags
        && (!dry_run || removed_tags == 0)
        && (dry_run || removed_tags == selected_tags)
        && (!limited || selected_tags == maximum)
        && (selected_tags != 0 || released_bytes == 0))
        .then_some(())
        .ok_or("invalid lifecycle counts or outcome")
}

impl OfferRemoved {
    fn validate(&self) -> Result<(), &'static str> {
        validate_lifecycle_counts(
            self.maximum,
            false,
            self.selected_tags,
            self.removed_tags,
            self.released_bytes,
            self.limited,
        )
    }
}

impl OffersPruned {
    fn validate(&self) -> Result<(), &'static str> {
        validate_lifecycle_counts(
            self.maximum,
            self.dry_run,
            self.selected_tags,
            self.removed_tags,
            self.released_bytes,
            self.limited,
        )
    }
}

impl DownloadResult {
    fn validate(&self) -> Result<(), &'static str> {
        (safe_ipc_path(&self.output)
            && self.installed
            && self.pinned
            && (self.destination_synced && self.cleanup_complete || !self.warnings.is_empty())
            && self.warnings.len() <= MAX_WARNINGS
            && self
                .warnings
                .iter()
                .all(|warning| valid_public_text(warning, MAX_PUBLIC_TEXT_BYTES)))
        .then_some(())
        .ok_or("invalid download completion")
    }

    pub fn validate_for_request(
        &self,
        expected: &DownloadRequestContext,
    ) -> Result<(), &'static str> {
        self.validate()?;
        (self.operation_id == expected.operation_id
            && self.token_digest == expected.token_digest
            && self.offer_id == expected.offer_id
            && self.from == expected.provider
            && self.kind == expected.kind
            && self.name == expected.name
            && expected.declared_size.is_none_or(|size| self.size == size)
            && self.output == expected.output
            && self.mode == expected.mode)
            .then_some(())
            .ok_or("download completion does not match request")
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventSource {
    Local,
    Gossip,
}

/// Compact protocol-v4 error payload. Correlation and versioning are carried by
/// the containing [`ResponseFrame`]; the flattened wire frame therefore contains
/// exactly protocol version, request ID, optional operation ID, typed code, and
/// typed outcome (plus the `type` discriminator).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolError {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<OperationId>,
    pub code: ErrorCode,
    pub outcome: Outcome,
}

impl ProtocolError {
    fn validate(&self) -> Result<(), &'static str> {
        if self.outcome == Outcome::Partial && self.operation_id.is_none() {
            return Err("partial outcome requires operation correlation");
        }
        Ok(())
    }

    pub fn new(operation_id: Option<OperationId>, code: ErrorCode, outcome: Outcome) -> Self {
        Self {
            operation_id,
            code,
            outcome,
        }
    }

    /// Stable adapter text. It is intentionally not part of the protocol.
    pub fn message(&self) -> &'static str {
        self.code.message()
    }

    /// Retry guidance is a local presentation policy, not transmitted state.
    pub fn retry_advice(&self) -> RetryAdvice {
        let advice = self.code.retry_advice(self.outcome);
        if self.operation_id.is_none()
            && matches!(
                advice,
                RetryAdvice::SameOperationReconciliation
                    | RetryAdvice::NewOperationAfterConditionsChange
            )
        {
            RetryAdvice::RetrySameRequest
        } else {
            advice
        }
    }

    /// Compatibility adapter for callers that do not yet consume typed advice.
    /// Prefer [`Self::retry_advice`] so a fresh operation is not confused with
    /// reconciliation of an existing operation.
    pub fn retryable(&self) -> bool {
        self.retry_advice() != RetryAdvice::Never
    }
}

/// Local guidance for handling a terminal error. This is deliberately not a
/// protocol-v4 field: the wire carries only the typed code and outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryAdvice {
    /// Reconcile or repeat the exact operation with its existing operation ID.
    SameOperationReconciliation,
    /// Wait for the stated condition to change, then make a fresh attempt with
    /// a new operation ID. Reusing the old ID can only replay its cached result.
    NewOperationAfterConditionsChange,
    /// Retry the request after its transient condition changes. This covers
    /// non-mutations and mutation failures rejected before cache admission.
    RetrySameRequest,
    /// Retrying cannot safely or meaningfully resolve the error.
    Never,
}

impl RetryAdvice {
    pub fn message(self) -> &'static str {
        match self {
            Self::SameOperationReconciliation => {
                "reconcile or retry the exact operation with the same operation ID"
            }
            Self::NewOperationAfterConditionsChange => {
                "after conditions change, retry as a new operation with a new operation ID"
            }
            Self::RetrySameRequest => "after conditions change, retry the same request",
            Self::Never => "do not retry",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    NotStarted,
    Partial,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    DaemonOffline,
    DaemonDisconnected,
    DaemonStopping,
    CommandTimeout,
    AttachmentCommandTimeout,
    AttachmentStorageShutdown,
    IpcCapacity,
    OperationCapacity,
    AttachmentStorageBusy,
    OperationIdConflict,
    InvalidAttachmentOffer,
    ShareFailed,
    DownloadFailed,
    OffersFailed,
    OffersBusy,
    AttachmentLifecycleInternal,
    SendFailed,
    PrivateSendFailed,
    RecipientUnresolved,
    PrivateMessageConflict,
    InvalidRequest,
    InvalidMessage,
    InitialFrameTimeout,
    PrivateSendBusy,
    PrivateRecipientBusy,
    PrivateReplayUnavailable,
    PrivateDeliveryUnknown,
    AttachmentQuotaExceeded,
    AttachmentTagCapacity,
    AttachmentMinFreeSpace,
    AttachmentRemovalPartial,
    CommandFailed,
    InternalContractError,
}

impl ErrorCode {
    pub fn message(self) -> &'static str {
        match self {
            Self::DaemonOffline => "Daemon is offline.",
            Self::CommandTimeout | Self::AttachmentCommandTimeout => {
                "The request timed out; reconcile before retrying."
            }
            Self::DaemonStopping | Self::AttachmentStorageShutdown => {
                "The daemon is shutting down or unavailable."
            }
            Self::IpcCapacity | Self::OperationCapacity | Self::AttachmentStorageBusy => {
                "Local capacity is currently unavailable."
            }
            Self::OperationIdConflict => "The operation ID is bound to different input.",
            Self::ShareFailed => "Attachment sharing failed.",
            Self::DownloadFailed => "Attachment download failed.",
            Self::SendFailed | Self::PrivateSendFailed => "Message submission failed.",
            Self::RecipientUnresolved => "The recipient could not be resolved.",
            Self::InvalidRequest => "The request contract is invalid or unsupported.",
            Self::InitialFrameTimeout => "The initial local request timed out.",
            Self::InvalidMessage => "The message is invalid.",
            Self::PrivateSendBusy | Self::PrivateRecipientBusy => {
                "The requested operation is currently busy."
            }
            Self::PrivateMessageConflict => "The message ID is bound to different content.",
            Self::PrivateReplayUnavailable => "Recipient replay protection is unavailable.",
            Self::AttachmentQuotaExceeded => "The attachment storage quota is exceeded.",
            Self::AttachmentMinFreeSpace => "The attachment free-space reserve is unavailable.",
            Self::AttachmentTagCapacity => "The attachment pin capacity is exhausted.",
            Self::AttachmentRemovalPartial => "Attachment removal completed only partially.",
            Self::DaemonDisconnected => "The daemon disconnected; the event feed has a gap.",
            Self::CommandFailed => "The command failed.",
            Self::InternalContractError => "An internal contract error occurred.",
            Self::InvalidAttachmentOffer => "The attachment request is invalid.",
            Self::OffersBusy => "Attachment listing is currently busy.",
            Self::OffersFailed | Self::AttachmentLifecycleInternal => {
                "The attachment lifecycle operation failed."
            }
            Self::PrivateDeliveryUnknown => "The private-message outcome is unknown.",
        }
    }

    pub fn retry_advice(self, outcome: Outcome) -> RetryAdvice {
        match outcome {
            Outcome::Partial => {
                if matches!(
                    self,
                    Self::SendFailed | Self::PrivateDeliveryUnknown | Self::InternalContractError
                ) {
                    RetryAdvice::Never
                } else {
                    RetryAdvice::SameOperationReconciliation
                }
            }
            Outcome::Unknown => {
                if self == Self::InternalContractError {
                    RetryAdvice::Never
                } else {
                    RetryAdvice::SameOperationReconciliation
                }
            }
            Outcome::NotStarted => {
                if matches!(
                    self,
                    Self::InitialFrameTimeout
                        | Self::IpcCapacity
                        | Self::OperationCapacity
                        | Self::OffersBusy
                ) {
                    RetryAdvice::RetrySameRequest
                } else if matches!(
                    self,
                    Self::DaemonOffline
                        | Self::DaemonDisconnected
                        | Self::DaemonStopping
                        | Self::CommandTimeout
                        | Self::AttachmentCommandTimeout
                        | Self::AttachmentStorageShutdown
                        | Self::AttachmentStorageBusy
                        | Self::PrivateSendBusy
                        | Self::PrivateRecipientBusy
                        | Self::PrivateReplayUnavailable
                        | Self::RecipientUnresolved
                        | Self::AttachmentQuotaExceeded
                        | Self::AttachmentTagCapacity
                        | Self::AttachmentMinFreeSpace
                        | Self::DownloadFailed
                ) {
                    RetryAdvice::NewOperationAfterConditionsChange
                } else {
                    RetryAdvice::Never
                }
            }
        }
    }

    /// Compatibility adapter for callers that do not yet consume typed advice.
    /// Prefer [`Self::retry_advice`] to retain the retry strategy.
    pub fn retryable(self, outcome: Outcome) -> bool {
        self.retry_advice(outcome) != RetryAdvice::Never
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = serde_json::to_value(self).map_err(|_| fmt::Error)?;
        formatter.write_str(value.as_str().ok_or(fmt::Error)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn native_absolute_ascii_path(serialized_bytes: usize) -> PathBuf {
        let prefix = if cfg!(windows) { r"C:\" } else { "/" };
        assert!(serialized_bytes >= prefix.len());
        PathBuf::from(format!(
            "{prefix}{}",
            "x".repeat(serialized_bytes - prefix.len())
        ))
    }

    #[test]
    fn unknown_versions_and_fields_fail_closed() {
        let id = RequestId::new_random();
        for version in [1, 2, 3, 255] {
            let wrong = format!(
                r#"{{"protocol_version":{version},"request_id":"{id}","request":{{"command":"status"}}}}"#
            );
            assert!(serde_json::from_str::<RequestFrame>(&wrong).is_err());
        }
        let extra = format!(
            r#"{{"protocol_version":4,"request_id":"{id}","request":{{"command":"status"}},"extra":true}}"#
        );
        assert!(serde_json::from_str::<RequestFrame>(&extra).is_err());
    }

    #[test]
    fn download_request_keeps_its_string_source_api_and_wire_shape() {
        let offer = String::from("public-string-token");
        let request = Request::Download {
            operation_id: OperationId::new_random(),
            offer: offer.clone(),
            output: std::env::temp_dir().join("meshmsg-download-source-api"),
            mode: DownloadMode::Install,
        };
        let Request::Download {
            offer: source_offer,
            ..
        } = &request
        else {
            unreachable!()
        };
        let _: &String = source_offer;
        assert_eq!(source_offer, &offer);
        let wire = serde_json::to_value(&request).unwrap();
        assert_eq!(wire["command"], "download");
        assert_eq!(wire["offer"], offer);
        assert_eq!(serde_json::from_value::<Request>(wire).unwrap(), request);
    }

    #[test]
    fn request_response_validation_centralizes_family_and_operation_correlation() {
        let operation_id = OperationId::new_random();
        let request = Request::Send {
            operation_id: operation_id.clone(),
            body: BroadcastBody::new("hello").unwrap(),
        };
        let queued = |operation_id: OperationId| {
            Response::Queued(Queued {
                message_id: operation_id.as_str().parse().unwrap(),
                operation_id,
                from: "1".repeat(64).parse().unwrap(),
                timestamp_ms: 1,
                body: BroadcastBody::new("hello").unwrap(),
                delivery_acknowledged: false,
            })
        };

        assert!(request
            .validate_response(&queued(operation_id.clone()))
            .is_ok());
        assert!(request
            .validate_response(&queued(OperationId::new_random()))
            .is_err());
        assert!(request.validate_response(&Response::Stopping {}).is_err());
        assert!(request
            .validate_response(&Response::Error(ProtocolError::new(
                Some(operation_id),
                ErrorCode::CommandTimeout,
                Outcome::Unknown,
            )))
            .is_ok());
        assert!(request
            .validate_response(&Response::Error(ProtocolError::new(
                Some(OperationId::new_random()),
                ErrorCode::CommandTimeout,
                Outcome::Unknown,
            )))
            .is_err());
        assert!(request
            .validate_response(&Response::Error(ProtocolError::new(
                None,
                ErrorCode::IpcCapacity,
                Outcome::NotStarted,
            )))
            .is_ok());
    }

    #[test]
    fn every_ipc_path_rejects_exactly_one_byte_over_the_cross_platform_limit() {
        let exact = native_absolute_ascii_path(MAX_IPC_PATH_BYTES);
        let oversized = native_absolute_ascii_path(MAX_IPC_PATH_BYTES + 1);
        assert_eq!(
            exact.as_os_str().as_encoded_bytes().len(),
            MAX_IPC_PATH_BYTES
        );
        assert_eq!(
            oversized.as_os_str().as_encoded_bytes().len(),
            MAX_IPC_PATH_BYTES + 1
        );
        let operation_id = OperationId::new_random();
        let digest: ContentDigest = "a".repeat(64).parse().unwrap();
        assert!(Request::Share {
            operation_id: operation_id.clone(),
            source_digest: digest.clone(),
            path: exact.clone(),
        }
        .validate()
        .is_ok());
        assert!(Request::Share {
            operation_id: operation_id.clone(),
            source_digest: digest,
            path: oversized.clone(),
        }
        .validate()
        .is_err());
        assert!(Request::Download {
            operation_id,
            offer: "x".into(),
            output: oversized.clone(),
            mode: DownloadMode::Install,
        }
        .validate()
        .is_err());
        assert!(Event::DownloadStarted {
            operation_id: OperationId::new_random(),
            output: oversized.clone(),
        }
        .validate()
        .is_err());
        assert!(Event::DownloadProgress {
            operation_id: OperationId::new_random(),
            received_bytes: 0,
            total_bytes: 0,
            output: oversized.clone(),
        }
        .validate()
        .is_err());
        let completion = DownloadResult {
            operation_id: OperationId::new_random(),
            token_digest: "b".repeat(64).parse().unwrap(),
            offer_id: OfferId::new_random(),
            kind: AttachmentKind::File,
            name: AttachmentName::new("x").unwrap(),
            size: 0,
            from: "1".repeat(64).parse().unwrap(),
            output: oversized,
            mode: DownloadMode::Install,
            installed: true,
            pinned: true,
            destination_synced: true,
            cleanup_complete: true,
            warnings: Vec::new(),
        };
        assert!(completion.validate().is_err());
    }

    #[test]
    fn retry_advice_covers_cached_pre_admission_and_uncertain_contexts() {
        let cached_condition_failures = [
            ErrorCode::AttachmentStorageBusy,
            ErrorCode::PrivateSendBusy,
            ErrorCode::PrivateRecipientBusy,
            ErrorCode::PrivateReplayUnavailable,
            ErrorCode::RecipientUnresolved,
            ErrorCode::AttachmentQuotaExceeded,
            ErrorCode::AttachmentTagCapacity,
            ErrorCode::AttachmentMinFreeSpace,
            ErrorCode::DownloadFailed,
        ];
        for code in cached_condition_failures {
            assert_eq!(
                code.retry_advice(Outcome::NotStarted),
                RetryAdvice::NewOperationAfterConditionsChange
            );
            let error =
                ProtocolError::new(Some(OperationId::new_random()), code, Outcome::NotStarted);
            assert_eq!(
                error.retry_advice(),
                RetryAdvice::NewOperationAfterConditionsChange
            );
            assert!(code.retryable(Outcome::NotStarted));
            assert!(error.retryable());
        }

        for code in [
            ErrorCode::OperationCapacity,
            ErrorCode::IpcCapacity,
            ErrorCode::InitialFrameTimeout,
            ErrorCode::OffersBusy,
        ] {
            assert_eq!(
                code.retry_advice(Outcome::NotStarted),
                RetryAdvice::RetrySameRequest
            );
            assert_eq!(
                ProtocolError::new(None, code, Outcome::NotStarted).retry_advice(),
                RetryAdvice::RetrySameRequest
            );
        }

        for (code, outcome) in [
            (ErrorCode::CommandTimeout, Outcome::Unknown),
            (ErrorCode::AttachmentRemovalPartial, Outcome::Partial),
            (ErrorCode::PrivateDeliveryUnknown, Outcome::Unknown),
        ] {
            assert_eq!(
                ProtocolError::new(Some(OperationId::new_random()), code, outcome,).retry_advice(),
                RetryAdvice::SameOperationReconciliation
            );
            assert_eq!(
                ProtocolError::new(None, code, outcome).retry_advice(),
                RetryAdvice::RetrySameRequest
            );
        }

        let invalid = ProtocolError::new(None, ErrorCode::InvalidRequest, Outcome::NotStarted);
        assert_eq!(invalid.retry_advice(), RetryAdvice::Never);
        assert!(!invalid.retryable());
        assert!(!ErrorCode::InvalidRequest.retryable(Outcome::NotStarted));
    }

    #[test]
    fn protocol_error_wire_is_compact_typed_and_strict() {
        let request_id = RequestId::new_random();
        let operation_id = OperationId::new_random();
        let frame = ResponseFrame {
            protocol_version: ProtocolVersion,
            request_id: Some(request_id.clone()),
            response: Response::Error(ProtocolError::new(
                Some(operation_id.clone()),
                ErrorCode::CommandTimeout,
                Outcome::Unknown,
            )),
        };
        let value = serde_json::to_value(&frame).unwrap();
        let keys = value.as_object().unwrap();
        assert_eq!(keys.len(), 6);
        for forbidden in [
            "message",
            "retryable",
            "retry_advice",
            "selected_tags",
            "removed_tags",
        ] {
            assert!(!keys.contains_key(forbidden));
        }
        assert_eq!(
            serde_json::from_value::<ResponseFrame>(value.clone()).unwrap(),
            frame
        );
        for field in ["message", "retryable", "retry_advice", "selected_tags"] {
            let mut malformed = value.clone();
            malformed[field] = serde_json::Value::Null;
            assert!(serde_json::from_value::<ResponseFrame>(malformed).is_err());
        }
    }

    #[test]
    fn response_and_event_families_reject_schema_versions_and_unknown_fields() {
        let request_id = RequestId::new_random();
        let response =
            format!(r#"{{"protocol_version":4,"request_id":"{request_id}","type":"stopping"}}"#);
        assert!(serde_json::from_str::<ResponseFrame>(&response).is_ok());
        for malformed in [
            response.replace("\"type\":", "\"schema_version\":1,\"type\":"),
            response.replace("\"stopping\"", "\"stopping\",\"extra\":true"),
        ] {
            assert!(serde_json::from_str::<ResponseFrame>(&malformed).is_err());
        }

        let event = format!(
            r#"{{"protocol_version":4,"request_id":"{request_id}","type":"connected","peer":"{}","endpoint_online":true,"topic_joined":true,"alias":null}}"#,
            "2".repeat(64)
        );
        assert!(serde_json::from_str::<EventFrame>(&event).is_ok());
        for malformed in [
            event.replace("\"type\":", "\"schema_version\":1,\"type\":"),
            event.replace("\"alias\":null", "\"alias\":null,\"extra\":true"),
        ] {
            assert!(serde_json::from_str::<EventFrame>(&malformed).is_err());
        }
    }

    #[test]
    fn request_enforces_command_specific_message_bounds_without_restricting_utf8() {
        let operation_id = OperationId::new_random();
        let request = RequestFrame::new(
            RequestId::new_random(),
            Request::Send {
                operation_id: operation_id.clone(),
                body: BroadcastBody::new("hello\n世界\u{0}").unwrap(),
            },
        );
        let encoded = serde_json::to_vec(&request).unwrap();
        assert_eq!(
            serde_json::from_slice::<RequestFrame>(&encoded).unwrap(),
            request
        );

        let decode_body =
            |command: &str, bytes: usize| {
                let to = "0".repeat(64);
                let recipient = (command == "private_send").then(|| format!(r#","to":"{to}""#));
                serde_json::from_value::<Request>(serde_json::from_str(&format!(
                r#"{{"command":"{command}","operation_id":"{operation_id}"{},"body":"{}"}}"#,
                recipient.unwrap_or_default(),
                "x".repeat(bytes)
            )).unwrap())
            };
        assert!(decode_body("send", BroadcastBody::MAX_BYTES).is_ok());
        assert!(decode_body("send", BroadcastBody::MAX_BYTES + 1).is_err());
        assert!(decode_body("private_send", PrivateBody::MAX_BYTES).is_ok());
        assert!(decode_body("private_send", PrivateBody::MAX_BYTES + 1).is_err());

        let request_id = RequestId::new_random();
        let peer = "0".repeat(64);
        let message_id = MessageId::new_random();
        let decode_event = |kind: &str, body: &str, private_fields: &str| {
            serde_json::from_str::<EventFrame>(&format!(
                r#"{{"protocol_version":4,"request_id":"{request_id}","type":"{kind}","from":"{peer}","message_id":"{message_id}","timestamp_ms":1,"body":"{body}"{private_fields}}}"#
            ))
        };
        assert!(decode_event("message", &"x".repeat(BroadcastBody::MAX_BYTES), "").is_ok());
        assert!(decode_event("message", &"x".repeat(BroadcastBody::MAX_BYTES + 1), "").is_err());
        let private_fields =
            r#","private":true,"acceptance_acknowledged":true,"durable":false,"read":false"#;
        assert!(decode_event(
            "private_message",
            &"x".repeat(MessageBody::MAX_BYTES),
            private_fields
        )
        .is_ok());
    }

    #[test]
    fn every_active_family_rejects_structurally_valid_semantic_forgeries() {
        let request = "1".repeat(32);
        let operation = "2".repeat(32);
        let other = "3".repeat(32);
        let peer = "4".repeat(64);
        let other_peer = "5".repeat(64);
        let digest = "6".repeat(64);

        let invalid_responses = [
            format!(
                r#"{{"protocol_version":4,"request_id":"{request}","type":"queued","operation_id":"{operation}","from":"{peer}","message_id":"{other}","timestamp_ms":1,"body":"x","delivery_acknowledged":false}}"#
            ),
            format!(
                r#"{{"protocol_version":4,"request_id":"{request}","type":"private_accepted","operation_id":"{operation}","to":"{peer}","message_id":"{operation}","timestamp_ms":1,"body_bytes":1,"acceptance_acknowledged":false,"duplicate_accepted":false,"durable":false,"read":false}}"#
            ),
            format!(
                r#"{{"protocol_version":4,"request_id":"{request}","type":"offer_removed","operation_id":"{operation}","offer_id":"{other}","direction":null,"provider":null,"maximum":1,"selected_tags":1,"removed_tags":0,"released_bytes":0,"limited":false}}"#
            ),
            format!(
                r#"{{"protocol_version":4,"request_id":"{request}","type":"offers_pruned","operation_id":"{operation}","direction":null,"older_than_secs":1,"maximum":1,"dry_run":true,"selected_tags":0,"removed_tags":0,"released_bytes":1,"limited":false,"cutoff_ms":1}}"#
            ),
            format!(
                r#"{{"protocol_version":4,"request_id":"{request}","type":"download_complete","operation_id":"{operation}","token_digest":"{digest}","offer_id":"{other}","kind":"file","name":"x","size":1,"from":"{peer}","output":"relative","mode":"install","installed":true,"pinned":true,"destination_synced":true,"cleanup_complete":true,"warnings":[]}}"#
            ),
            format!(
                r#"{{"protocol_version":4,"request_id":"{request}","type":"peers_snapshot","generated_at_ms":10,"directory_epoch":"{operation}","directory_revision":1,"self":{{"public_key":"{peer}","alias":null,"online":true}},"peers":[{{"public_key":"{other_peer}","alias":null,"online":true,"last_seen_ms":11,"expires_at_ms":12}}]}}"#
            ),
            format!(
                r#"{{"protocol_version":4,"request_id":"{request}","type":"offers","blobs":[],"truncated":false,"item_errors":1}}"#
            ),
        ];
        for frame in invalid_responses {
            assert!(
                serde_json::from_str::<ResponseFrame>(&frame).is_err(),
                "{frame}"
            );
        }

        let invalid_events = [
            format!(
                r#"{{"protocol_version":4,"request_id":"{request}","type":"private_message","private":false,"from":"{peer}","message_id":"{operation}","timestamp_ms":1,"body":"x","acceptance_acknowledged":true,"durable":false,"read":false}}"#
            ),
            format!(
                r#"{{"protocol_version":4,"request_id":"{request}","type":"attachment_offer","from":"{peer}","message_id":"{operation}","timestamp_ms":1,"offer_id":"{other}","kind":"file","name":"x","size":0,"ticket":"ticket","offer":"eA"}}"#
            ),
            format!(
                r#"{{"protocol_version":4,"request_id":"{request}","type":"download_progress","operation_id":"{operation}","received_bytes":2,"total_bytes":1,"output":"/tmp/x"}}"#
            ),
            format!(
                r#"{{"protocol_version":4,"request_id":"{request}","type":"peer_expired","directory_epoch":"{operation}","directory_revision":1,"peer":{{"public_key":"{peer}","alias":null,"online":true,"last_seen_ms":1,"expires_at_ms":2}}}}"#
            ),
            format!(
                r#"{{"protocol_version":4,"request_id":"{request}","type":"lagged","source":"local","dropped":1,"message":"bad\nmessage"}}"#
            ),
        ];
        for frame in invalid_events {
            assert!(
                serde_json::from_str::<EventFrame>(&frame).is_err(),
                "{frame}"
            );
        }
    }

    #[test]
    fn protocol_v4_cleanup_round_trips_only_context_specific_frames() {
        let request_id = RequestId::new_random();
        let operation_id = OperationId::new_random();
        let removed = ResponseFrame::new(
            Some(request_id.clone()),
            Response::OfferRemoved(OfferRemoved {
                operation_id: operation_id.clone(),
                offer_id: OfferId::new_random(),
                direction: Some(OfferDirection::Incoming),
                provider: Some("7".repeat(64).parse().unwrap()),
                maximum: 8,
                selected_tags: 1,
                removed_tags: 1,
                released_bytes: 12,
                limited: false,
            }),
        );
        let removed_wire = serde_json::to_value(&removed).unwrap();
        assert!(removed_wire.get("older_than_secs").is_none());
        assert!(removed_wire.get("dry_run").is_none());
        assert!(removed_wire.get("cutoff_ms").is_none());
        assert_eq!(
            serde_json::from_value::<ResponseFrame>(removed_wire).unwrap(),
            removed
        );

        let pruned = ResponseFrame::new(
            Some(request_id.clone()),
            Response::OffersPruned(OffersPruned {
                operation_id,
                direction: None,
                older_than_secs: 60,
                maximum: 8,
                dry_run: true,
                selected_tags: 1,
                removed_tags: 0,
                released_bytes: 12,
                limited: false,
                cutoff_ms: 1_000,
            }),
        );
        let pruned_wire = serde_json::to_value(&pruned).unwrap();
        assert!(pruned_wire.get("offer_id").is_none());
        assert!(pruned_wire.get("provider").is_none());
        assert_eq!(
            serde_json::from_value::<ResponseFrame>(pruned_wire).unwrap(),
            pruned
        );

        let stopping = ResponseFrame::new(Some(request_id.clone()), Response::Stopping {});
        let stopping_wire = serde_json::to_value(&stopping).unwrap();
        assert!(stopping_wire.get("outcome").is_none());
        assert_eq!(
            serde_json::from_value::<ResponseFrame>(stopping_wire).unwrap(),
            stopping
        );

        for removed_v4_surface in [
            serde_json::json!({
                "protocol_version": 4,
                "request_id": request_id,
                "type": "stopping"
            }),
            serde_json::json!({
                "protocol_version": 4,
                "request_id": RequestId::new_random(),
                "type": "error",
                "code": "invalid_request",
                "outcome": "not_started"
            }),
        ] {
            assert!(serde_json::from_value::<EventFrame>(removed_v4_surface).is_err());
        }
        let inactive_code = serde_json::json!({
            "protocol_version": 4,
            "request_id": RequestId::new_random(),
            "type": "error",
            "code": "request_forbidden",
            "outcome": "not_started"
        });
        assert!(serde_json::from_value::<ResponseFrame>(inactive_code).is_err());
    }

    #[test]
    fn attachment_names_follow_portable_component_rules() {
        for valid in ["photo.jpg", "résumé.txt", "hello world"] {
            assert!(AttachmentName::new(valid).is_ok(), "{valid}");
        }
        for invalid in [
            "",
            ".",
            "..",
            "../secret",
            "a/b",
            "a\\b",
            "CON",
            "con.txt",
            "NUL.bin",
            "COM1",
            "LPT9.log",
            "bad:name",
            "bad*name",
            "trailing.",
            "trailing ",
            "line\nfeed",
        ] {
            assert!(AttachmentName::new(invalid).is_err(), "{invalid}");
        }
        assert!(AttachmentName::new("x".repeat(AttachmentName::MAX_BYTES + 1)).is_err());
    }
}
