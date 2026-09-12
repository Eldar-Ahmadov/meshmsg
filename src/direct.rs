use crate::{
    direct_replay::{self, ReplayClient, ReplayDecision},
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
    path::Path,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::mpsc;

pub(crate) use crate::direct_replay::ReplayWorker;

pub(crate) const DIRECT_ALPN: &[u8] = b"/meshmsg/direct/2";
const DIRECT_VERSION: u8 = 2;
const SIGNATURE_LENGTH: usize = iroh::Signature::LENGTH;
const MAX_DIRECT_FRAME: usize = 6 * 1024;
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

fn now_ms() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64)
}

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
        crate::message::validate_private_body(&body)?;
        let payload = DirectPayload {
            version: DIRECT_VERSION,
            sender: secret.public(),
            recipient,
            topic,
            id,
            timestamp_ms: now_ms()?,
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
        crate::message::validate_private_body(&frame.payload.body)?;
        let signed = postcard::to_stdvec(&(MESSAGE_DOMAIN, &frame.payload))?;
        frame
            .payload
            .sender
            .verify(&signed, &iroh::Signature::from_bytes(&frame.signature))
            .context("verify private message signature")?;
        let at_ms = now_ms()?;
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
enum AckResult {
    Accepted,
    DuplicateAccepted,
    Conflict,
    Busy,
    Unavailable,
    DeliveryOutcomeUnknown,
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
pub(crate) struct IncomingDirect {
    pub(crate) from: PublicKey,
    pub(crate) id: [u8; 16],
    pub(crate) timestamp_ms: u64,
    pub(crate) body: String,
}

#[derive(Debug, Clone)]
pub(crate) struct DirectHandler {
    secret: SecretKey,
    topic: TopicId,
    incoming: mpsc::Sender<IncomingDirect>,
    replay: ReplayClient,
    connections: Arc<tokio::sync::Semaphore>,
}

impl DirectHandler {
    pub(crate) fn new(
        secret: SecretKey,
        topic: TopicId,
        incoming: mpsc::Sender<IncomingDirect>,
        state_dir: &Path,
    ) -> Result<(Self, ReplayWorker)> {
        let (replay, worker) = direct_replay::start(state_dir, secret.public(), topic)?;
        Ok((
            Self {
                secret,
                topic,
                incoming,
                replay,
                connections: Arc::new(tokio::sync::Semaphore::new(32)),
            },
            worker,
        ))
    }

    async fn accept_message(&self, remote: PublicKey, bytes: &[u8]) -> Result<AckFrame> {
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

        // Reserve volatile delivery capacity before asking the worker to make a new
        // ID durable. The worker still recognizes duplicates when no permit is
        // available, so an already accepted request can always be re-acknowledged.
        // The delivery closure travels in the bounded in-memory worker request but
        // is never serialized. The worker invokes it only after sync, making the
        // commit+delivery sequence safe even if this protocol future is cancelled.
        let delivery = self
            .incoming
            .clone()
            .try_reserve_owned()
            .ok()
            .map(|permit| {
                let payload = frame.payload.clone();
                Box::new(move || {
                    permit.send(IncomingDirect {
                        from: payload.sender,
                        id: payload.id,
                        timestamp_ms: payload.timestamp_ms,
                        body: payload.body,
                    });
                }) as Box<dyn FnOnce() + Send + 'static>
            });
        let expires_at_ms = now_ms()?.saturating_add(REPLAY_LIFETIME.as_millis() as u64);
        let fingerprint = replay_fingerprint(&frame.payload)?;
        let decision = self
            .replay
            .admit(
                frame.payload.sender,
                frame.payload.id,
                fingerprint,
                expires_at_ms,
                delivery,
            )
            .await?;
        let result = match decision {
            ReplayDecision::Accepted => AckResult::Accepted,
            ReplayDecision::DuplicateAccepted => AckResult::DuplicateAccepted,
            ReplayDecision::Conflict => AckResult::Conflict,
            ReplayDecision::DeliveryOutcomeUnknown => AckResult::DeliveryOutcomeUnknown,
            ReplayDecision::Busy => AckResult::Busy,
            ReplayDecision::Unavailable => AckResult::Unavailable,
        };
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
                let ack = self.accept_message(remote, &request).await?.encode()?;
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

#[derive(Debug)]
pub(crate) struct AcceptedDirect {
    pub(crate) recipient: PublicKey,
    pub(crate) id: [u8; 16],
    pub(crate) timestamp_ms: u64,
    pub(crate) body_bytes: usize,
    pub(crate) duplicate: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DirectRejection {
    Conflict,
    Busy,
    Unavailable,
    DeliveryOutcomeUnknown,
}

#[derive(Debug)]
pub(crate) enum DirectSendOutcome {
    Accepted(AcceptedDirect),
    Rejected(DirectRejection),
}

pub(crate) async fn send(
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
    let id = frame.payload.id;
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
                    id,
                    timestamp_ms,
                    body_bytes,
                    duplicate: ack.payload.result == AckResult::DuplicateAccepted,
                }))
            }
            AckResult::Conflict => Ok(DirectSendOutcome::Rejected(DirectRejection::Conflict)),
            AckResult::Busy => Ok(DirectSendOutcome::Rejected(DirectRejection::Busy)),
            AckResult::Unavailable => Ok(DirectSendOutcome::Rejected(DirectRejection::Unavailable)),
            AckResult::DeliveryOutcomeUnknown => Ok(DirectSendOutcome::Rejected(
                DirectRejection::DeliveryOutcomeUnknown,
            )),
        }
    };
    tokio::time::timeout(DIRECT_TIMEOUT, operation)
        .await
        .context("private-message operation timed out")?
}

pub(crate) fn id_string(id: &[u8; 16]) -> String {
    data_encoding::HEXLOWER.encode(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn replay_is_reacknowledged_without_redelivery() {
        let sender = SecretKey::generate();
        let receiver = SecretKey::generate();
        let topic = TopicId::from_bytes([9; 32]);
        let (tx, mut rx) = mpsc::channel(2);
        let dir =
            std::env::temp_dir().join(format!("meshmsg-replay-test-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let (handler, mut worker) = DirectHandler::new(receiver.clone(), topic, tx, &dir).unwrap();
        let frame =
            DirectFrame::new(&sender, receiver.public(), topic, "deliver once".into()).unwrap();
        let bytes = frame.encode().unwrap();

        for _ in 0..2 {
            let ack = handler
                .accept_message(sender.public(), &bytes)
                .await
                .unwrap();
            assert!(matches!(
                ack.payload.result,
                AckResult::Accepted | AckResult::DuplicateAccepted
            ));
            assert_eq!(ack.payload.id, frame.payload.id);
        }
        assert_eq!(rx.try_recv().unwrap().body, "deliver once");
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
            .await
            .unwrap();
        assert_eq!(conflict_ack.payload.result, AckResult::Conflict);
        assert!(rx.try_recv().is_err());
        drop(handler);
        worker.shutdown().await.unwrap();

        // Restarting the handler reloads the accepted ID and re-acknowledges it
        // without placing the plaintext into the new process queue.
        let (restart_tx, mut restart_rx) = mpsc::channel(2);
        let (restarted, mut restarted_worker) =
            DirectHandler::new(receiver.clone(), topic, restart_tx, &dir).unwrap();
        let ack = restarted
            .accept_message(sender.public(), &bytes)
            .await
            .unwrap();
        assert_eq!(ack.payload.result, AckResult::DuplicateAccepted);
        let conflict_ack = restarted
            .accept_message(sender.public(), &conflict.encode().unwrap())
            .await
            .unwrap();
        assert_eq!(conflict_ack.payload.result, AckResult::Conflict);
        assert!(restart_rx.try_recv().is_err());
        drop(restarted);
        restarted_worker.shutdown().await.unwrap();
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_file() {
                let bytes = std::fs::read(path).unwrap();
                assert!(!bytes
                    .windows(b"deliver once".len())
                    .any(|value| value == b"deliver once"));
                assert!(!bytes
                    .windows(b"different signed body".len())
                    .any(|value| value == b"different signed body"));
            }
        }
        std::fs::remove_dir_all(dir).unwrap();
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
            AckResult::Unavailable,
            AckResult::DeliveryOutcomeUnknown,
        ] {
            let ack = AckFrame::new(&receiver, &frame.payload, result).unwrap();
            let decoded = AckFrame::decode(&ack.encode().unwrap(), &frame.payload).unwrap();
            assert_eq!(decoded.payload.result, result);
        }
        let mut legacy_version =
            AckFrame::new(&receiver, &frame.payload, AckResult::Accepted).unwrap();
        legacy_version.payload.version = 1;
        let signed = postcard::to_stdvec(&(ACK_DOMAIN, &legacy_version.payload)).unwrap();
        legacy_version.signature = ByteArray::new(receiver.sign(&signed).to_bytes());
        assert!(AckFrame::decode(&legacy_version.encode().unwrap(), &frame.payload).is_err());
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
}
