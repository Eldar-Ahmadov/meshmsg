//! Shared, strict local IPC protocol for meshmsg.
//!
//! This crate is the single serialization boundary between the daemon and all
//! local clients. It deliberately supports exactly one protocol version.

pub mod attachment;
pub mod framing;
pub mod id;
pub mod model;

pub use attachment::{
    validate_attachment_event, AttachmentEventRef, AttachmentValidationError,
    ENVELOPE_ACCEPTANCE_WINDOW_MS, ENVELOPE_FUTURE_SKEW_MS,
};
pub use framing::{read_frame, read_json, write_json, FrameLimit, FrameReader, ProtocolIoError};
pub use id::{ContentDigest, MessageId, OfferId, OperationId, PeerId, RequestId, TopicId};
pub use model::*;

/// The only local IPC protocol version accepted by this crate.
pub const PROTOCOL_VERSION: u8 = 2;
