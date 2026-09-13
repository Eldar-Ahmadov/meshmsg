//! Shared, strict local IPC protocol for meshmsg.
//!
//! This crate is the single serialization boundary between the daemon and all
//! local clients. It deliberately supports exactly one protocol version.

pub mod attachment;
pub mod framing;
pub mod id;
pub mod model;

/// The only signed broadcast envelope version accepted on the wire.
pub const SIGNED_BROADCAST_ENVELOPE_VERSION: u8 = 3;
/// Hard application-envelope limit. Gossip transport headroom is additional.
pub const MAX_SIGNED_BROADCAST_ENVELOPE_BYTES: usize = 64 * 1024;
/// Worst-case postcard overhead for the V3 envelope at a maximum-width `u64`
/// timestamp and a body whose length uses a three-byte varint.
pub const MAX_SIGNED_BROADCAST_ENVELOPE_OVERHEAD_BYTES: usize = 178;
/// Largest UTF-8 broadcast body proven to fit the complete worst-case envelope.
pub const MAX_BROADCAST_BODY_BYTES: usize =
    MAX_SIGNED_BROADCAST_ENVELOPE_BYTES - MAX_SIGNED_BROADCAST_ENVELOPE_OVERHEAD_BYTES;
/// Largest unpadded base64url representation of one complete signed envelope.
pub const MAX_SIGNED_ATTACHMENT_TOKEN_BYTES: usize =
    (MAX_SIGNED_BROADCAST_ENVELOPE_BYTES * 4).div_ceil(3);

pub use attachment::{
    validate_attachment_event, AttachmentEventRef, AttachmentValidationError,
    ENVELOPE_ACCEPTANCE_WINDOW_MS, ENVELOPE_FUTURE_SKEW_MS,
};
pub use framing::{read_frame, read_json, write_json, FrameLimit, FrameReader, ProtocolIoError};
pub use id::{ContentDigest, MessageId, OfferId, OperationId, PeerId, RequestId, TopicId};
pub use model::*;

/// The only local IPC protocol version accepted by this crate. V3 is a hard
/// break because `BroadcastBody` and signed attachment-token bounds changed.
pub const PROTOCOL_VERSION: u8 = 3;
