use crate::id::{ContentDigest, MessageId, OfferId, OperationId, PeerId, RequestId, TopicId};
use crate::PROTOCOL_VERSION;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::{fmt, path::PathBuf};

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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequestFrame {
    pub protocol_version: ProtocolVersion,
    pub request_id: RequestId,
    pub request: Request,
}

impl RequestFrame {
    pub fn new(request_id: RequestId, request: Request) -> Self {
        Self {
            protocol_version: ProtocolVersion,
            request_id,
            request,
        }
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        Ok(())
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

message_body!(BroadcastBody, 3900, "broadcast message body");
message_body!(PrivateBody, 4096, "private message body");
message_body!(MessageBody, 4096, "message body");
bounded_text!(AttachmentToken, 16_384, "attachment token");
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
    Raw,
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

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ResponseFrame {
    pub protocol_version: ProtocolVersion,
    pub schema_version: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<RequestId>,
    #[serde(flatten)]
    pub response: Response,
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
    OfferRemoved(LifecycleResult),
    OffersPruned(LifecycleResult),
    DownloadComplete(DownloadResult),
    Stopping {
        outcome: String,
    },
    Error(ProtocolError),
}

#[derive(Deserialize)]
struct ResponseFrameWire {
    protocol_version: ProtocolVersion,
    schema_version: u8,
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
        if !wire.response.supports_schema(wire.schema_version) {
            return Err(de::Error::custom(
                "unsupported response family schema version",
            ));
        }
        wire.response.validate().map_err(de::Error::custom)?;
        Ok(Self {
            protocol_version: wire.protocol_version,
            schema_version: wire.schema_version,
            request_id: wire.request_id,
            response: wire.response,
        })
    }
}

impl Response {
    fn validate(&self) -> Result<(), &'static str> {
        match self {
            Self::Status(status) => status.validate(),
            _ => Ok(()),
        }
    }

    fn supports_schema(&self, version: u8) -> bool {
        match self {
            Self::Status(_) | Self::Offers(_) | Self::Stopping { .. } | Self::Error(_) => {
                version == 1
            }
            Self::Queued(_)
            | Self::PrivateAccepted(_)
            | Self::AttachmentShared(_)
            | Self::OfferRemoved(_)
            | Self::OffersPruned(_) => version == 3,
            Self::PeersSnapshot(_) | Self::DownloadComplete(_) => version == 2,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
pub enum DaemonFrame {
    Response(ResponseFrame),
    Event(EventFrame),
}

impl DaemonFrame {
    pub fn protocol_version(&self) -> ProtocolVersion {
        match self {
            Self::Response(frame) => frame.protocol_version,
            Self::Event(frame) => frame.protocol_version,
        }
    }

    pub fn request_id(&self) -> Option<&RequestId> {
        match self {
            Self::Response(frame) => frame.request_id.as_ref(),
            Self::Event(frame) => Some(&frame.request_id),
        }
    }

    /// Convert an already admitted frame to its family payload for adapters
    /// that still render the historical command JSON shape.
    pub fn into_payload_value(self) -> Result<serde_json::Value, serde_json::Error> {
        let mut value = serde_json::to_value(self)?;
        value
            .as_object_mut()
            .expect("daemon frames serialize as objects")
            .remove("protocol_version");
        Ok(value)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct EventFrame {
    pub protocol_version: ProtocolVersion,
    pub schema_version: u8,
    pub request_id: RequestId,
    #[serde(flatten)]
    pub event: Event,
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
    PeerUp {
        peer: PeerId,
    },
    PeerDown {
        peer: PeerId,
    },
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
    Stopping {},
    Error(ProtocolError),
}

#[derive(Deserialize)]
struct EventFrameWire {
    protocol_version: ProtocolVersion,
    schema_version: u8,
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
        if !wire.event.supports_schema(wire.schema_version) {
            return Err(de::Error::custom("unsupported event family schema version"));
        }
        Ok(Self {
            protocol_version: wire.protocol_version,
            schema_version: wire.schema_version,
            request_id: wire.request_id,
            event: wire.event,
        })
    }
}

impl Event {
    fn supports_schema(&self, version: u8) -> bool {
        match self {
            Self::Connected(_)
            | Self::PrivateMessage(_)
            | Self::PeerUp { .. }
            | Self::PeerDown { .. }
            | Self::Lagged { .. }
            | Self::Stopping {}
            | Self::Error(_) => version == 1,
            Self::Message(_)
            | Self::AttachmentOffer(_)
            | Self::PeersSnapshot(_)
            | Self::PeerDiscovered(_)
            | Self::PeerUpdated(_)
            | Self::PeerExpired(_)
            | Self::DownloadStarted { .. }
            | Self::DownloadProgress { .. }
            | Self::DownloadComplete(_) => version == 2,
            Self::Queued(_) | Self::AttachmentShared(_) => version == 3,
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
    pub body: MessageBody,
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
pub struct Peer {
    pub peer: PeerId,
    pub alias: Option<Alias>,
    pub online: bool,
    pub last_seen_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PeersSnapshot {
    pub peers: Vec<Peer>,
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
pub struct OffersSnapshot {
    pub offers: Vec<AttachmentOffer>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OffersChanged {
    pub operation_id: OperationId,
    pub selected: u16,
    pub removed: u16,
    pub released_bytes: u64,
    pub dry_run: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DownloadComplete {
    pub operation_id: OperationId,
    pub offer_id: OfferId,
    pub output: PathBuf,
    pub size: u64,
    pub mode: DownloadMode,
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
    pub has_more: bool,
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
pub struct LifecycleResult {
    pub operation_id: OperationId,
    pub offer_id: Option<OfferId>,
    pub direction: Option<OfferDirection>,
    pub provider: Option<PeerId>,
    pub older_than_secs: Option<u64>,
    pub maximum: usize,
    pub dry_run: bool,
    pub selected_tags: usize,
    pub removed_tags: usize,
    pub released_bytes: u64,
    pub limited: bool,
    pub cutoff_ms: Option<u64>,
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
    pub installed: bool,
    pub pinned: bool,
    pub destination_synced: bool,
    pub cleanup_complete: bool,
    pub warnings: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventSource {
    Local,
    Gossip,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolError {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<OperationId>,
    pub code: ErrorCode,
    pub message: String,
    pub outcome: Outcome,
    pub retryable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offer_id: Option<OfferId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_tags: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub removed_tags: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quota_bytes_released: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suppressed_since_last: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direction: Option<OfferDirection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<PeerId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub older_than_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub maximum: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dry_run: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cutoff_ms: Option<u64>,
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
    DaemonUnavailable,
    CapacityOrOffline,
    DaemonStopping,
    CommandTimeout,
    AttachmentCommandTimeout,
    AttachmentStorageShutdown,
    IpcCapacity,
    OperationCapacity,
    AttachmentStorageBusy,
    OperationIdConflict,
    InvalidOperationId,
    InvalidSourceDigest,
    InvalidAttachmentOffer,
    InvalidOfferSelector,
    InvalidPruneRequest,
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
    UnsupportedSchema,
    InvalidMessage,
    NetworkEventRejected,
    InitialFrameTimeout,
    PrivateSendBusy,
    PrivateRecipientBusy,
    PrivateReplayUnavailable,
    PrivateDeliveryUnknown,
    AttachmentQuotaExceeded,
    AttachmentTagCapacity,
    AttachmentMinFreeSpace,
    AttachmentRemovalPartial,
    ShareOperationCapacity,
    DownloadOperationCapacity,
    DownloadStagingUnavailable,
    InvalidDaemonResponse,
    RequestRejected,
    CommandFailed,
    FeedError,
    StartupFailed,
    InternalContractError,
    RequestForbidden,
    NotFound,
    PayloadTooLarge,
    UnsupportedMediaType,
    InvalidRange,
    IdempotencyUnsupported,
    RequestThrottled,
    SendThrottled,
    RequestTimeout,
    RequestFailed,
    SendOutcomeUnknown,
    ShareOutcomeUnknown,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_versions_and_fields_fail_closed() {
        let id = RequestId::new_random();
        for version in [1, 3, 255] {
            let wrong = format!(
                r#"{{"protocol_version":{version},"request_id":"{id}","request":{{"command":"status"}}}}"#
            );
            assert!(serde_json::from_str::<RequestFrame>(&wrong).is_err());
        }
        let extra = format!(
            r#"{{"protocol_version":2,"request_id":"{id}","request":{{"command":"status"}},"extra":true}}"#
        );
        assert!(serde_json::from_str::<RequestFrame>(&extra).is_err());
    }

    #[test]
    fn response_and_event_families_reject_wrong_schemas_and_unknown_fields() {
        let request_id = RequestId::new_random();
        let response = format!(
            r#"{{"protocol_version":2,"schema_version":1,"request_id":"{request_id}","type":"stopping","outcome":"accepted"}}"#
        );
        assert!(serde_json::from_str::<ResponseFrame>(&response).is_ok());
        for malformed in [
            response.replace("\"schema_version\":1", "\"schema_version\":2"),
            response.replace(
                "\"outcome\":\"accepted\"",
                "\"outcome\":\"accepted\",\"extra\":true",
            ),
        ] {
            assert!(serde_json::from_str::<ResponseFrame>(&malformed).is_err());
        }

        let event = format!(
            r#"{{"protocol_version":2,"schema_version":1,"request_id":"{request_id}","type":"connected","peer":"{}","endpoint_online":true,"topic_joined":true,"alias":null}}"#,
            "2".repeat(64)
        );
        assert!(serde_json::from_str::<EventFrame>(&event).is_ok());
        for malformed in [
            event.replace("\"schema_version\":1", "\"schema_version\":2"),
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
