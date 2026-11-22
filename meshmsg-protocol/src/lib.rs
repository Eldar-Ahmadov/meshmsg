//! Shared, strict local IPC protocol for meshmsg.
//!
//! This crate is the single serialization boundary between the daemon and all
//! local clients. It deliberately supports exactly one protocol version.

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
/// Largest UTF-8 private/direct body. Deliberately equal to the broadcast body
/// bound so the shared IPC request/event frame budgets remain valid.
pub const MAX_PRIVATE_BODY_BYTES: usize = MAX_BROADCAST_BODY_BYTES;
/// Largest unpadded base64url representation of one complete signed envelope.
pub const MAX_SIGNED_ATTACHMENT_TOKEN_BYTES: usize =
    (MAX_SIGNED_BROADCAST_ENVELOPE_BYTES * 4).div_ceil(3);

pub use framing::{read_frame, read_json, write_json, FrameLimit, FrameReader, ProtocolIoError};
pub use id::{ContentDigest, MessageId, OfferId, OperationId, PeerId, RequestId, TopicId};
pub use model::*;

/// The only local IPC protocol version accepted by this crate. There is no
/// negotiation: every other version is rejected.
pub const PROTOCOL_VERSION: u8 = 5;
