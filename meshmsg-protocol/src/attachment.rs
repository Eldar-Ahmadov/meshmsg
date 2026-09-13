use crate::{AttachmentKind, AttachmentName, AttachmentToken, MessageId, OfferId, PeerId, TopicId};
use data_encoding::BASE64URL_NOPAD;
use iroh::PublicKey;
use iroh_blobs::{ticket::BlobTicket, BlobFormat};
use iroh_gossip::proto::TopicId as GossipTopicId;
use serde::{Deserialize, Serialize};
use serde_byte_array::ByteArray;
use std::{fmt, str::FromStr};

const ENVELOPE_DOMAIN: &str = "meshmsg-broadcast";
const ENVELOPE_VERSION: u8 = 2;
const ATTACHMENT_PREFIX: &str = "meshmsg-attachment-v1:";
const ATTACHMENT_OFFER_VERSION: u8 = 1;
const MAX_ENVELOPE_SIZE: usize = 4096;
pub const ENVELOPE_FUTURE_SKEW_MS: u64 = 60_000;
pub const ENVELOPE_ACCEPTANCE_WINDOW_MS: u64 = 5 * 60_000;
const SIGNATURE_LENGTH: usize = iroh::Signature::LENGTH;
type Signature = ByteArray<SIGNATURE_LENGTH>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttachmentValidationError(&'static str);

impl fmt::Display for AttachmentValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for AttachmentValidationError {}

fn invalid(reason: &'static str) -> AttachmentValidationError {
    AttachmentValidationError(reason)
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum EnvelopeKind {
    Message,
    AttachmentOffer,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    domain: String,
    version: u8,
    topic: GossipTopicId,
    from: PublicKey,
    message_id: [u8; 16],
    timestamp_ms: u64,
    kind: EnvelopeKind,
    body: String,
    signature: Signature,
}

#[derive(Serialize)]
struct EnvelopeSignaturePayload<'a> {
    domain: &'a str,
    version: u8,
    topic: GossipTopicId,
    from: PublicKey,
    message_id: [u8; 16],
    timestamp_ms: u64,
    kind: EnvelopeKind,
    body: &'a str,
}

#[derive(Debug, Deserialize, Serialize)]
struct AttachmentWire {
    version: u8,
    offer: SignedOffer,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
struct SignedOffer {
    offer_id: String,
    kind: AttachmentKind,
    name: String,
    size: u64,
    ticket: String,
}

pub struct AttachmentEventRef<'a> {
    pub from: &'a PeerId,
    pub message_id: &'a MessageId,
    pub timestamp_ms: u64,
    pub offer_id: &'a OfferId,
    pub kind: AttachmentKind,
    pub name: &'a AttachmentName,
    pub size: u64,
    pub ticket: &'a AttachmentToken,
    pub offer: &'a AttachmentToken,
}

pub fn validate_attachment_event(
    event: AttachmentEventRef<'_>,
    expected_topic: &TopicId,
    now_ms: u64,
) -> Result<(), AttachmentValidationError> {
    let encoded = BASE64URL_NOPAD
        .decode(event.offer.as_str().as_bytes())
        .map_err(|_| invalid("malformed signed attachment token"))?;
    if encoded.is_empty() || encoded.len() > MAX_ENVELOPE_SIZE {
        return Err(invalid("signed attachment token exceeds envelope bounds"));
    }
    let (envelope, remainder): (Envelope, &[u8]) = postcard::take_from_bytes(&encoded)
        .map_err(|_| invalid("malformed signed attachment envelope"))?;
    if !remainder.is_empty()
        || envelope.domain != ENVELOPE_DOMAIN
        || envelope.version != ENVELOPE_VERSION
        || envelope.kind != EnvelopeKind::AttachmentOffer
        || envelope.timestamp_ms == 0
    {
        return Err(invalid("invalid signed attachment envelope shape"));
    }

    let topic_bytes: [u8; 32] = data_encoding::HEXLOWER
        .decode(expected_topic.as_str().as_bytes())
        .map_err(|_| invalid("invalid expected attachment topic"))?
        .try_into()
        .map_err(|_| invalid("invalid expected attachment topic"))?;
    if envelope.topic != GossipTopicId::from_bytes(topic_bytes) {
        return Err(invalid("attachment event belongs to another topic"));
    }
    let oldest = now_ms.saturating_sub(ENVELOPE_ACCEPTANCE_WINDOW_MS);
    let newest = now_ms.saturating_add(ENVELOPE_FUTURE_SKEW_MS);
    if !(oldest..=newest).contains(&envelope.timestamp_ms) {
        return Err(invalid(
            "attachment event timestamp is outside the acceptance window",
        ));
    }

    let signed = postcard::to_stdvec(&EnvelopeSignaturePayload {
        domain: &envelope.domain,
        version: envelope.version,
        topic: envelope.topic,
        from: envelope.from,
        message_id: envelope.message_id,
        timestamp_ms: envelope.timestamp_ms,
        kind: envelope.kind,
        body: &envelope.body,
    })
    .map_err(|_| invalid("cannot encode attachment signature payload"))?;
    envelope
        .from
        .verify(&signed, &iroh::Signature::from_bytes(&envelope.signature))
        .map_err(|_| invalid("invalid attachment signature"))?;

    let body = envelope
        .body
        .strip_prefix(ATTACHMENT_PREFIX)
        .ok_or_else(|| invalid("attachment envelope has no typed offer"))?;
    let body = BASE64URL_NOPAD
        .decode(body.as_bytes())
        .map_err(|_| invalid("malformed attachment offer body"))?;
    let (wire, remainder): (AttachmentWire, &[u8]) =
        postcard::take_from_bytes(&body).map_err(|_| invalid("malformed attachment offer body"))?;
    if !remainder.is_empty() || wire.version != ATTACHMENT_OFFER_VERSION {
        return Err(invalid(
            "invalid attachment offer version or trailing bytes",
        ));
    }
    let ticket = BlobTicket::from_str(&wire.offer.ticket)
        .map_err(|_| invalid("invalid attachment blob ticket"))?;
    if ticket.format() != BlobFormat::Raw || ticket.to_string() != wire.offer.ticket {
        return Err(invalid("noncanonical attachment blob ticket"));
    }
    if ticket.addr().id != envelope.from {
        return Err(invalid(
            "attachment ticket provider does not match signature",
        ));
    }

    let envelope_id = data_encoding::HEXLOWER.encode(&envelope.message_id);
    if envelope.from.to_string() != event.from.as_str()
        || envelope_id != event.message_id.as_str()
        || envelope.timestamp_ms != event.timestamp_ms
        || wire.offer.offer_id != event.offer_id.as_str()
        || wire.offer.offer_id != event.message_id.as_str()
        || wire.offer.kind != event.kind
        || wire.offer.name != event.name.as_str()
        || wire.offer.size != event.size
        || wire.offer.ticket != event.ticket.as_str()
    {
        return Err(invalid(
            "attachment event does not match its authenticated offer",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::SecretKey;
    use iroh_blobs::Hash;

    struct Fixture {
        from: PeerId,
        message_id: MessageId,
        offer_id: OfferId,
        name: AttachmentName,
        ticket: AttachmentToken,
        token: AttachmentToken,
        topic: TopicId,
        timestamp_ms: u64,
    }

    impl Fixture {
        fn event(&self) -> AttachmentEventRef<'_> {
            AttachmentEventRef {
                from: &self.from,
                message_id: &self.message_id,
                timestamp_ms: self.timestamp_ms,
                offer_id: &self.offer_id,
                kind: AttachmentKind::File,
                name: &self.name,
                size: 7,
                ticket: &self.ticket,
                offer: &self.token,
            }
        }
    }

    fn fixture(topic_byte: u8, timestamp_ms: u64) -> Fixture {
        let secret = SecretKey::generate();
        let gossip_topic = GossipTopicId::from_bytes([topic_byte; 32]);
        let message_id = [1_u8; 16];
        let offer_id = data_encoding::HEXLOWER.encode(&message_id);
        let ticket = BlobTicket::new(
            iroh::EndpointAddr::new(secret.public()),
            Hash::new(b"attachment fixture"),
            BlobFormat::Raw,
        )
        .to_string();
        let body = postcard::to_stdvec(&AttachmentWire {
            version: ATTACHMENT_OFFER_VERSION,
            offer: SignedOffer {
                offer_id: offer_id.clone(),
                kind: AttachmentKind::File,
                name: "safe.txt".into(),
                size: 7,
                ticket: ticket.clone(),
            },
        })
        .unwrap();
        let body = format!("{ATTACHMENT_PREFIX}{}", BASE64URL_NOPAD.encode(&body));
        let signed = postcard::to_stdvec(&EnvelopeSignaturePayload {
            domain: ENVELOPE_DOMAIN,
            version: ENVELOPE_VERSION,
            topic: gossip_topic,
            from: secret.public(),
            message_id,
            timestamp_ms,
            kind: EnvelopeKind::AttachmentOffer,
            body: &body,
        })
        .unwrap();
        let envelope = Envelope {
            domain: ENVELOPE_DOMAIN.into(),
            version: ENVELOPE_VERSION,
            topic: gossip_topic,
            from: secret.public(),
            message_id,
            timestamp_ms,
            kind: EnvelopeKind::AttachmentOffer,
            body,
            signature: ByteArray::new(secret.sign(&signed).to_bytes()),
        };
        Fixture {
            from: secret.public().to_string().parse().unwrap(),
            message_id: offer_id.parse().unwrap(),
            offer_id: offer_id.parse().unwrap(),
            name: AttachmentName::new("safe.txt").unwrap(),
            ticket: AttachmentToken::new(ticket).unwrap(),
            token: AttachmentToken::new(
                BASE64URL_NOPAD.encode(&postcard::to_stdvec(&envelope).unwrap()),
            )
            .unwrap(),
            topic: data_encoding::HEXLOWER
                .encode(&[topic_byte; 32])
                .parse()
                .unwrap(),
            timestamp_ms,
        }
    }

    #[test]
    fn authenticated_attachment_boundary_rejects_forgery_topic_freshness_and_binding() {
        let now = 1_000_000;
        let valid = fixture(7, now);
        assert!(validate_attachment_event(valid.event(), &valid.topic, now).is_ok());

        let mut forged = fixture(7, now);
        let mut encoded = BASE64URL_NOPAD
            .decode(forged.token.as_str().as_bytes())
            .unwrap();
        *encoded.last_mut().unwrap() ^= 1;
        forged.token = AttachmentToken::new(BASE64URL_NOPAD.encode(&encoded)).unwrap();
        assert!(validate_attachment_event(forged.event(), &forged.topic, now).is_err());

        let cross_topic = fixture(8, now);
        assert!(validate_attachment_event(cross_topic.event(), &valid.topic, now).is_err());

        let stale = fixture(7, now - ENVELOPE_ACCEPTANCE_WINDOW_MS - 1);
        assert!(validate_attachment_event(stale.event(), &stale.topic, now).is_err());

        let mut malformed = fixture(7, now);
        malformed.ticket = AttachmentToken::new("not-a-ticket").unwrap();
        assert!(validate_attachment_event(malformed.event(), &malformed.topic, now).is_err());
    }
}
