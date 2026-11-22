use crate::{
    clock::unix_timestamp_ms,
    direct_replay::{ReplayDecision, ReplayStore},
    ids::id_string,
    presence::validate_endpoint_addr,
};
use anyhow::{Context, Result};
use iroh::{
    endpoint::Connection,
    protocol::{AcceptError, ProtocolHandler},
    Endpoint, EndpointAddr, PublicKey, SecretKey,
};
use iroh_gossip::proto::TopicId;
use serde::{Deserialize, Serialize};
use serde_byte_array::ByteArray;
use sha2::{Digest, Sha256};
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::mpsc;

pub(crate) const DIRECT_ALPN: &[u8] = b"/meshmsg/direct/2";
const DIRECT_VERSION: u8 = 2;
const SIGNATURE_LENGTH: usize = iroh::Signature::LENGTH;
/// Maximum private body plus generous headroom for postcard framing, keys,
/// topic, ID, timestamp, and signature (measured worst case is under 256 bytes).
const MAX_DIRECT_FRAME: usize = meshmsg_protocol::MAX_PRIVATE_BODY_BYTES + 2 * 1024;
const INCOMING_QUEUE_CAPACITY: usize = 256;
pub(crate) const SEND_CONCURRENCY: usize = 8;
const DIRECT_ACCEPTANCE_WINDOW: Duration = Duration::from_secs(5 * 60);
const DIRECT_TIMEOUT: Duration = Duration::from_secs(30);
const REPLAY_SAFETY_MARGIN: Duration = Duration::from_secs(30);
const REPLAY_LIFETIME: Duration =
    Duration::from_secs(DIRECT_ACCEPTANCE_WINDOW.as_secs() * 2 + REPLAY_SAFETY_MARGIN.as_secs());
const MESSAGE_DOMAIN: &[u8] = b"meshmsg-direct-message-v2";
const ACK_DOMAIN: &[u8] = b"meshmsg-direct-ack-v2";
const REPLAY_FINGERPRINT_DOMAIN: &[u8] = b"meshmsg-direct-replay-fingerprint-v2";
type Signature = ByteArray<SIGNATURE_LENGTH>;

const _: () = assert!(REPLAY_LIFETIME.as_secs() >= DIRECT_ACCEPTANCE_WINDOW.as_secs() * 2);

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DirectPayload {
    version: u8,
    sender: PublicKey,
    recipient: PublicKey,
    topic: TopicId,
    id: [u8; 16],
    timestamp_ms: u64,
    body: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct DirectFrame {
    payload: DirectPayload,
    signature: Signature,
}

fn replay_fingerprint(payload: &DirectPayload) -> Result<[u8; 32]> {
    // Timestamp is intentionally excluded: a caller can reconstruct the same
    // semantic operation after sender restart without knowing the first attempt's
    // generated timestamp. All caller-controlled and routing fields are bound.
    let canonical = postcard::to_stdvec(&(
        REPLAY_FINGERPRINT_DOMAIN,
        payload.sender,
        payload.recipient,
        payload.topic,
        payload.id,
        &payload.body,
    ))?;
    Ok(Sha256::digest(canonical).into())
}

impl DirectFrame {
    #[cfg(test)]
    fn new(secret: &SecretKey, recipient: PublicKey, topic: TopicId, body: String) -> Result<Self> {
        Self::new_with_id(secret, recipient, topic, body, rand::random())
    }

    fn new_with_id(
        secret: &SecretKey,
        recipient: PublicKey,
        topic: TopicId,
        body: String,
        id: [u8; 16],
    ) -> Result<Self> {
        meshmsg_protocol::PrivateBody::validate(&body)?;
        let payload = DirectPayload {
            version: DIRECT_VERSION,
            sender: secret.public(),
            recipient,
            topic,
            id,
            timestamp_ms: unix_timestamp_ms()?,
            body,
        };
        let signed = postcard::to_stdvec(&(MESSAGE_DOMAIN, &payload))?;
        Ok(Self {
            payload,
            signature: ByteArray::new(secret.sign(&signed).to_bytes()),
        })
    }

    fn encode(&self) -> Result<Vec<u8>> {
        let bytes = postcard::to_stdvec(self)?;
        anyhow::ensure!(
            bytes.len() <= MAX_DIRECT_FRAME,
            "private message frame is too large"
        );
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        anyhow::ensure!(
            bytes.len() <= MAX_DIRECT_FRAME,
            "private message frame is too large"
        );
        let (frame, remainder): (Self, &[u8]) =
            postcard::take_from_bytes(bytes).context("decode private message")?;
        anyhow::ensure!(
            remainder.is_empty(),
            "private message contains trailing bytes"
        );
        anyhow::ensure!(
            frame.payload.version == DIRECT_VERSION,
            "unsupported private message version"
        );
        meshmsg_protocol::PrivateBody::validate(&frame.payload.body)?;
        let signed = postcard::to_stdvec(&(MESSAGE_DOMAIN, &frame.payload))?;
        frame
            .payload
            .sender
            .verify(&signed, &iroh::Signature::from_bytes(&frame.signature))
            .context("verify private message signature")?;
        let at_ms = unix_timestamp_ms()?;
        let skew_ms = DIRECT_ACCEPTANCE_WINDOW.as_millis() as u64;
        anyhow::ensure!(
            frame.payload.timestamp_ms <= at_ms.saturating_add(skew_ms),
            "private message timestamp is too far in the future"
        );
        anyhow::ensure!(
            at_ms <= frame.payload.timestamp_ms.saturating_add(skew_ms),
            "private message is stale"
        );
        Ok(frame)
    }
}

// Postcard encodes the variant index. Older recipients may still answer with
// the retired indices 4 and 5; those fail to decode and the send conservatively
// reports `private_send_failed` with an unknown outcome.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
enum AckResult {
    Accepted,
    DuplicateAccepted,
    Conflict,
    Busy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AckPayload {
    version: u8,
    sender: PublicKey,
    recipient: PublicKey,
    topic: TopicId,
    id: [u8; 16],
    result: AckResult,
}

#[derive(Debug, Serialize, Deserialize)]
struct AckFrame {
    payload: AckPayload,
    signature: Signature,
}

impl AckFrame {
    fn new(secret: &SecretKey, message: &DirectPayload, result: AckResult) -> Result<Self> {
        let payload = AckPayload {
            version: DIRECT_VERSION,
            sender: secret.public(),
            recipient: message.sender,
            topic: message.topic,
            id: message.id,
            result,
        };
        let signed = postcard::to_stdvec(&(ACK_DOMAIN, &payload))?;
        Ok(Self {
            payload,
            signature: ByteArray::new(secret.sign(&signed).to_bytes()),
        })
    }

    fn encode(&self) -> Result<Vec<u8>> {
        let bytes = postcard::to_stdvec(self)?;
        anyhow::ensure!(
            bytes.len() <= MAX_DIRECT_FRAME,
            "private acknowledgement is too large"
        );
        Ok(bytes)
    }

    fn decode(bytes: &[u8], message: &DirectPayload) -> Result<Self> {
        anyhow::ensure!(
            bytes.len() <= MAX_DIRECT_FRAME,
            "private acknowledgement is too large"
        );
        let (ack, remainder): (Self, &[u8]) =
            postcard::take_from_bytes(bytes).context("decode private acknowledgement")?;
        anyhow::ensure!(
            remainder.is_empty(),
            "private acknowledgement contains trailing bytes"
        );
        anyhow::ensure!(
            ack.payload.version == DIRECT_VERSION,
            "unsupported private acknowledgement version"
        );
        anyhow::ensure!(
            ack.payload.sender == message.recipient,
            "private acknowledgement has wrong sender"
        );
        anyhow::ensure!(
            ack.payload.recipient == message.sender,
            "private acknowledgement has wrong recipient"
        );
        anyhow::ensure!(
            ack.payload.topic == message.topic && ack.payload.id == message.id,
            "private acknowledgement does not match message"
        );
        let signed = postcard::to_stdvec(&(ACK_DOMAIN, &ack.payload))?;
        ack.payload
            .sender
            .verify(&signed, &iroh::Signature::from_bytes(&ack.signature))
            .context("verify private acknowledgement signature")?;
        Ok(ack)
    }
}

#[derive(Debug)]
struct IncomingDirect {
    from: PublicKey,
    id: [u8; 16],
    timestamp_ms: u64,
    body: String,
}

fn incoming_event(msg: IncomingDirect) -> meshmsg_protocol::Event {
    meshmsg_protocol::Event::PrivateMessage(meshmsg_protocol::PrivateMessage {
        from: msg
            .from
            .to_string()
            .parse()
            .expect("public key is canonical"),
        message_id: id_string(&msg.id).parse().expect("message ID is canonical"),
        timestamp_ms: msg.timestamp_ms,
        body: meshmsg_protocol::PrivateBody::new(msg.body).expect("validated direct body"),
    })
}

#[derive(Debug, Clone)]
pub(crate) struct DirectHandler {
    secret: SecretKey,
    topic: TopicId,
    incoming: mpsc::Sender<meshmsg_protocol::Event>,
    replay: Arc<Mutex<ReplayStore>>,
    connections: Arc<tokio::sync::Semaphore>,
}

impl DirectHandler {
    fn new(
        secret: SecretKey,
        topic: TopicId,
        incoming: mpsc::Sender<meshmsg_protocol::Event>,
    ) -> Self {
        Self {
            secret,
            topic,
            incoming,
            replay: Arc::new(Mutex::new(ReplayStore::new(REPLAY_LIFETIME))),
            connections: Arc::new(tokio::sync::Semaphore::new(32)),
        }
    }

    fn accept_message(&self, remote: PublicKey, bytes: &[u8]) -> Result<AckFrame> {
        let frame = DirectFrame::decode(bytes)?;
        anyhow::ensure!(
            frame.payload.sender == remote,
            "TLS peer does not match message sender"
        );
        anyhow::ensure!(
            frame.payload.recipient == self.secret.public(),
            "private message has wrong recipient"
        );
        anyhow::ensure!(
            frame.payload.topic == self.topic,
            "private message has wrong topic"
        );
        let fingerprint = replay_fingerprint(&frame.payload)?;
        let now_wall_ms = unix_timestamp_ms()?;

        // Reserve volatile delivery capacity before admitting a new ID. Known IDs
        // are still classified without a permit, so an already accepted message
        // can always be re-acknowledged. Recording and delivery happen under one
        // lock with no await between them, so neither can occur without the other.
        let permit = self.incoming.try_reserve().ok();
        let mut replay = self.replay.lock().expect("direct replay store poisoned");
        let result = match replay.admit(
            frame.payload.sender,
            frame.payload.id,
            fingerprint,
            permit.is_some(),
            now_wall_ms,
            Instant::now(),
        ) {
            ReplayDecision::Accepted => {
                permit
                    .expect("accepted admission reserved delivery capacity")
                    .send(incoming_event(IncomingDirect {
                        from: frame.payload.sender,
                        id: frame.payload.id,
                        timestamp_ms: frame.payload.timestamp_ms,
                        body: frame.payload.body.clone(),
                    }));
                AckResult::Accepted
            }
            ReplayDecision::DuplicateAccepted => AckResult::DuplicateAccepted,
            ReplayDecision::Conflict => AckResult::Conflict,
            ReplayDecision::Busy => AckResult::Busy,
        };
        drop(replay);
        AckFrame::new(&self.secret, &frame.payload, result)
    }
}

impl ProtocolHandler for DirectHandler {
    async fn accept(&self, connection: Connection) -> std::result::Result<(), AcceptError> {
        let remote = connection.remote_id();
        let connections = self.connections.clone();
        let result = async {
            let _permit = connections
                .try_acquire_owned()
                .context("private-message connection capacity reached")?;
            tokio::time::timeout(DIRECT_TIMEOUT, async {
                let (mut send, mut recv) = connection.accept_bi().await?;
                let request = recv.read_to_end(MAX_DIRECT_FRAME).await?;
                let ack = self.accept_message(remote, &request)?.encode()?;
                send.write_all(&ack).await?;
                send.finish()?;
                // Keep the connection alive until the authenticated peer has
                // consumed the acknowledgement; dropping immediately can reset it.
                send.stopped().await?;
                Ok::<(), anyhow::Error>(())
            })
            .await
            .context("private-message request timed out")??;
            Ok::<(), anyhow::Error>(())
        }
        .await;
        result.map_err(|error| AcceptError::from_boxed(error.into_boxed_dyn_error()))
    }
}

/// Builds the protocol handler together with its bounded stream of
/// already-validated private-message events.
pub(crate) fn setup(
    secret: SecretKey,
    topic: TopicId,
) -> (DirectHandler, mpsc::Receiver<meshmsg_protocol::Event>) {
    let (incoming, receiver) = mpsc::channel(INCOMING_QUEUE_CAPACITY);
    (DirectHandler::new(secret, topic, incoming), receiver)
}

#[derive(Debug)]
struct AcceptedDirect {
    recipient: PublicKey,
    timestamp_ms: u64,
    body_bytes: usize,
    duplicate: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectRejection {
    Conflict,
    Busy,
}

#[derive(Debug)]
enum DirectSendOutcome {
    Accepted(AcceptedDirect),
    Rejected(DirectRejection),
}

async fn send(
    endpoint: Endpoint,
    secret: SecretKey,
    topic: TopicId,
    address: EndpointAddr,
    body: String,
    operation_id: [u8; 16],
) -> Result<DirectSendOutcome> {
    validate_endpoint_addr(&address, address.id)?;
    let frame = DirectFrame::new_with_id(&secret, address.id, topic, body, operation_id)?;
    let encoded = frame.encode()?;
    let body_bytes = frame.payload.body.len();
    let recipient = frame.payload.recipient;
    let timestamp_ms = frame.payload.timestamp_ms;
    let operation = async {
        let connection = endpoint
            .connect(address, DIRECT_ALPN)
            .await
            .context("connect to private-message recipient")?;
        anyhow::ensure!(
            connection.remote_id() == recipient,
            "connected peer does not match recipient"
        );
        let (mut send, mut recv) = connection
            .open_bi()
            .await
            .context("open private-message stream")?;
        send.write_all(&encoded)
            .await
            .context("send private message")?;
        send.finish().context("finish private message")?;
        let bytes = recv
            .read_to_end(MAX_DIRECT_FRAME)
            .await
            .context("read private-message acknowledgement")?;
        let ack = AckFrame::decode(&bytes, &frame.payload)?;
        match ack.payload.result {
            AckResult::Accepted | AckResult::DuplicateAccepted => {
                Ok(DirectSendOutcome::Accepted(AcceptedDirect {
                    recipient,
                    timestamp_ms,
                    body_bytes,
                    duplicate: ack.payload.result == AckResult::DuplicateAccepted,
                }))
            }
            AckResult::Conflict => Ok(DirectSendOutcome::Rejected(DirectRejection::Conflict)),
            AckResult::Busy => Ok(DirectSendOutcome::Rejected(DirectRejection::Busy)),
        }
    };
    tokio::time::timeout(DIRECT_TIMEOUT, operation)
        .await
        .context("private-message operation timed out")?
}

#[derive(Debug, Clone)]
pub(crate) struct DirectSender {
    endpoint: Endpoint,
    secret: SecretKey,
    topic: TopicId,
    permits: Arc<tokio::sync::Semaphore>,
}

impl DirectSender {
    pub(crate) fn new(endpoint: Endpoint, secret: SecretKey, topic: TopicId) -> Self {
        Self {
            endpoint,
            secret,
            topic,
            permits: Arc::new(tokio::sync::Semaphore::new(SEND_CONCURRENCY)),
        }
    }

    /// Reserves one bounded send task before the caller spawns it.
    pub(crate) fn try_reserve(
        &self,
        operation_id: meshmsg_protocol::OperationId,
    ) -> Result<DirectSendPermit, meshmsg_protocol::ProtocolError> {
        self.permits
            .clone()
            .try_acquire_owned()
            .map(|permit| DirectSendPermit {
                sender: self.clone(),
                _permit: permit,
            })
            .map_err(|_| {
                meshmsg_protocol::ProtocolError::new(
                    Some(operation_id),
                    meshmsg_protocol::ErrorCode::PrivateSendBusy,
                    meshmsg_protocol::Outcome::NotStarted,
                )
            })
    }

    pub(crate) fn close(&self) {
        self.permits.close();
    }
}

pub(crate) struct DirectSendPermit {
    sender: DirectSender,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl DirectSendPermit {
    pub(crate) async fn send(
        self,
        address: EndpointAddr,
        body: String,
        operation_id: [u8; 16],
    ) -> meshmsg_protocol::Response {
        match send(
            self.sender.endpoint,
            self.sender.secret,
            self.sender.topic,
            address,
            body,
            operation_id,
        )
        .await
        {
            Ok(DirectSendOutcome::Accepted(accepted)) => {
                meshmsg_protocol::Response::PrivateAccepted(meshmsg_protocol::PrivateAccepted {
                    operation_id: id_string(&operation_id)
                        .parse()
                        .expect("operation ID is canonical"),
                    to: accepted
                        .recipient
                        .to_string()
                        .parse()
                        .expect("public key is canonical"),
                    timestamp_ms: accepted.timestamp_ms,
                    body_bytes: accepted.body_bytes,
                    duplicate_accepted: accepted.duplicate,
                })
            }
            Ok(DirectSendOutcome::Rejected(rejection)) => {
                rejection_response(rejection, operation_id)
            }
            Err(_) => meshmsg_protocol::Response::Error(meshmsg_protocol::ProtocolError::new(
                Some(
                    id_string(&operation_id)
                        .parse()
                        .expect("operation ID is canonical"),
                ),
                meshmsg_protocol::ErrorCode::PrivateSendFailed,
                meshmsg_protocol::Outcome::Unknown,
            )),
        }
    }
}

fn rejection_response(
    rejection: DirectRejection,
    operation_id: [u8; 16],
) -> meshmsg_protocol::Response {
    let code = match rejection {
        DirectRejection::Conflict => meshmsg_protocol::ErrorCode::PrivateMessageConflict,
        DirectRejection::Busy => meshmsg_protocol::ErrorCode::PrivateRecipientBusy,
    };
    meshmsg_protocol::Response::Error(meshmsg_protocol::ProtocolError::new(
        Some(
            id_string(&operation_id)
                .parse()
                .expect("operation ID is canonical"),
        ),
        code,
        meshmsg_protocol::Outcome::NotStarted,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn delivered_body(rx: &mut mpsc::Receiver<meshmsg_protocol::Event>) -> String {
        match rx.try_recv().expect("a delivered private message") {
            meshmsg_protocol::Event::PrivateMessage(message) => message.body.as_str().to_owned(),
            _ => panic!("expected private-message event"),
        }
    }

    #[test]
    fn replay_is_reacknowledged_without_redelivery_until_the_recipient_restarts() {
        let sender = SecretKey::generate();
        let receiver = SecretKey::generate();
        let topic = TopicId::from_bytes([9; 32]);
        let (tx, mut rx) = mpsc::channel(2);
        let handler = DirectHandler::new(receiver.clone(), topic, tx);
        let frame =
            DirectFrame::new(&sender, receiver.public(), topic, "deliver once".into()).unwrap();
        let bytes = frame.encode().unwrap();

        for expected in [AckResult::Accepted, AckResult::DuplicateAccepted] {
            let ack = handler.accept_message(sender.public(), &bytes).unwrap();
            assert_eq!(ack.payload.result, expected);
            assert_eq!(ack.payload.id, frame.payload.id);
        }
        assert_eq!(delivered_body(&mut rx), "deliver once");
        assert!(rx.try_recv().is_err());
        let conflict = DirectFrame::new_with_id(
            &sender,
            receiver.public(),
            topic,
            "different signed body".into(),
            frame.payload.id,
        )
        .unwrap();
        let conflict_ack = handler
            .accept_message(sender.public(), &conflict.encode().unwrap())
            .unwrap();
        assert_eq!(conflict_ack.payload.result, AckResult::Conflict);
        assert!(rx.try_recv().is_err());
        // Every clone served by the router shares one store.
        let ack = handler
            .clone()
            .accept_message(sender.public(), &bytes)
            .unwrap();
        assert_eq!(ack.payload.result, AckResult::DuplicateAccepted);
        assert!(rx.try_recv().is_err());

        // Replay state is memory-only: a restarted recipient has forgotten the
        // ID and delivers the same signed frame again as a new message.
        let (restart_tx, mut restart_rx) = mpsc::channel(2);
        let restarted = DirectHandler::new(receiver.clone(), topic, restart_tx);
        let ack = restarted.accept_message(sender.public(), &bytes).unwrap();
        assert_eq!(ack.payload.result, AckResult::Accepted);
        assert_eq!(delivered_body(&mut restart_rx), "deliver once");
    }

    #[test]
    fn full_delivery_queue_is_busy_for_new_ids_without_recording_them() {
        let sender = SecretKey::generate();
        let receiver = SecretKey::generate();
        let topic = TopicId::from_bytes([10; 32]);
        let (tx, mut rx) = mpsc::channel(1);
        let handler = DirectHandler::new(receiver.clone(), topic, tx);
        let frame = |body: &str| {
            DirectFrame::new(&sender, receiver.public(), topic, body.into())
                .unwrap()
                .encode()
                .unwrap()
        };
        let accept = |bytes: &[u8]| {
            handler
                .accept_message(sender.public(), bytes)
                .unwrap()
                .payload
                .result
        };
        let (first, second) = (frame("first"), frame("second"));

        assert_eq!(accept(&first), AckResult::Accepted);
        assert_eq!(accept(&second), AckResult::Busy);
        // An accepted ID is still re-acknowledged while the queue is full.
        assert_eq!(accept(&first), AckResult::DuplicateAccepted);
        assert_eq!(delivered_body(&mut rx), "first");
        assert!(rx.try_recv().is_err());
        // The busy ID left no record, so it is admitted once capacity returns.
        assert_eq!(accept(&second), AckResult::Accepted);
        assert_eq!(delivered_body(&mut rx), "second");
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn direct_v2_fingerprint_is_retry_stable_body_sensitive_and_ack_results_are_signed() {
        let sender = SecretKey::generate();
        let receiver = SecretKey::generate();
        let topic = TopicId::from_bytes([13; 32]);
        let id = [13; 16];
        let frame =
            DirectFrame::new_with_id(&sender, receiver.public(), topic, "same body".into(), id)
                .unwrap();
        let mut later = frame.payload.clone();
        later.timestamp_ms += 1;
        assert_eq!(
            replay_fingerprint(&frame.payload).unwrap(),
            replay_fingerprint(&later).unwrap()
        );
        later.body.push('!');
        assert_ne!(
            replay_fingerprint(&frame.payload).unwrap(),
            replay_fingerprint(&later).unwrap()
        );

        for result in [
            AckResult::Accepted,
            AckResult::DuplicateAccepted,
            AckResult::Conflict,
            AckResult::Busy,
        ] {
            let ack = AckFrame::new(&receiver, &frame.payload, result).unwrap();
            let decoded = AckFrame::decode(&ack.encode().unwrap(), &frame.payload).unwrap();
            assert_eq!(decoded.payload.result, result);
        }
        // The variant indices are the direct v2 wire encoding and must not shift;
        // the two retired trailing results no longer decode.
        for (result, index) in [
            (AckResult::Accepted, 0),
            (AckResult::DuplicateAccepted, 1),
            (AckResult::Conflict, 2),
            (AckResult::Busy, 3),
        ] {
            assert_eq!(postcard::to_stdvec(&result).unwrap(), [index]);
        }
        for retired in [4, 5] {
            assert!(postcard::from_bytes::<AckResult>(&[retired]).is_err());
        }
        let mut legacy_version =
            AckFrame::new(&receiver, &frame.payload, AckResult::Accepted).unwrap();
        legacy_version.payload.version = 1;
        let signed = postcard::to_stdvec(&(ACK_DOMAIN, &legacy_version.payload)).unwrap();
        legacy_version.signature = ByteArray::new(receiver.sign(&signed).to_bytes());
        assert!(AckFrame::decode(&legacy_version.encode().unwrap(), &frame.payload).is_err());
    }

    #[test]
    fn send_outcomes_map_to_stable_ipc_contracts() {
        for (rejection, code, retry_advice) in [
            (
                DirectRejection::Conflict,
                "private_message_conflict",
                meshmsg_protocol::RetryAdvice::Never,
            ),
            (
                DirectRejection::Busy,
                "private_recipient_busy",
                meshmsg_protocol::RetryAdvice::NewOperationAfterConditionsChange,
            ),
        ] {
            let response = rejection_response(rejection, [1; 16]);
            let meshmsg_protocol::Response::Error(error) = response else {
                panic!("expected error response");
            };
            assert_eq!(error.code.to_string(), code);
            assert_eq!(error.outcome.to_string(), "not_started");
            assert_eq!(error.retry_advice(), retry_advice);
        }
    }

    #[test]
    fn direct_frame_binds_all_fields_and_detects_tampering() {
        let sender = SecretKey::generate();
        let receiver = SecretKey::generate();
        let topic = TopicId::from_bytes([4; 32]);
        let frame = DirectFrame::new(&sender, receiver.public(), topic, "secret".into()).unwrap();
        let bytes = frame.encode().unwrap();
        let decoded = DirectFrame::decode(&bytes).unwrap();
        assert_eq!(decoded.payload.sender, sender.public());
        assert_eq!(decoded.payload.recipient, receiver.public());
        assert_eq!(decoded.payload.topic, topic);
        assert_eq!(decoded.payload.body, "secret");
        let mut tampered = bytes;
        *tampered.last_mut().unwrap() ^= 1;
        assert!(DirectFrame::decode(&tampered).is_err());
    }

    #[test]
    fn maximum_private_body_fits_direct_frame() {
        let sender = SecretKey::generate();
        let receiver = SecretKey::generate();
        let topic = TopicId::from_bytes([4; 32]);
        let body = "界".repeat(meshmsg_protocol::MAX_PRIVATE_BODY_BYTES / 3);
        let frame = DirectFrame::new(&sender, receiver.public(), topic, body.clone()).unwrap();
        let bytes = frame.encode().unwrap();
        assert!(bytes.len() <= MAX_DIRECT_FRAME);
        assert_eq!(DirectFrame::decode(&bytes).unwrap().payload.body, body);
        let body = "a".repeat(meshmsg_protocol::MAX_PRIVATE_BODY_BYTES);
        let frame = DirectFrame::new(&sender, receiver.public(), topic, body).unwrap();
        assert!(frame.encode().unwrap().len() <= MAX_DIRECT_FRAME);
        assert!(DirectFrame::new(
            &sender,
            receiver.public(),
            topic,
            "a".repeat(meshmsg_protocol::MAX_PRIVATE_BODY_BYTES + 1)
        )
        .and_then(|frame| DirectFrame::decode(&frame.encode()?))
        .is_err());
    }
}
