use super::{validate_display_name, AttachmentOffer};
use crate::{
    gossip::{Envelope, EnvelopeKind},
    ids::id_string,
};
use anyhow::{Context, Result};
use bytes::Bytes;
use data_encoding::BASE64URL_NOPAD;
use iroh::{PublicKey, SecretKey};
use iroh_blobs::{ticket::BlobTicket, BlobFormat};
use iroh_gossip::proto::TopicId;
use serde::{Deserialize, Serialize};
#[cfg(test)]
use std::time::Duration;

pub(crate) const ATTACHMENT_PREFIX: &str = "meshmsg-attachment-v1:";
pub(crate) const ATTACHMENT_OFFER_VERSION: u8 = 1;
#[cfg(test)]
const ENVELOPE_FUTURE_SKEW: Duration = Duration::from_secs(60);
#[cfg(test)]
pub(crate) const ENVELOPE_ACCEPTANCE_WINDOW: Duration = Duration::from_secs(5 * 60);

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct AttachmentWire {
    pub(crate) version: u8,
    pub(crate) offer: AttachmentOffer,
}

pub(crate) struct EncodedOffer {
    pub(crate) encoded: Bytes,
    pub(crate) from: PublicKey,
    pub(crate) message_id: [u8; 16],
    pub(crate) timestamp_ms: u64,
    pub(crate) offer: AttachmentOffer,
}

pub(crate) fn attachment_body(offer: &AttachmentOffer) -> Result<String> {
    let encoded = postcard::to_stdvec(&AttachmentWire {
        version: ATTACHMENT_OFFER_VERSION,
        offer: offer.clone(),
    })?;
    Ok(format!(
        "{ATTACHMENT_PREFIX}{}",
        BASE64URL_NOPAD.encode(&encoded)
    ))
}

pub(crate) fn parse_attachment_body(body: &str) -> Result<Option<AttachmentOffer>> {
    let Some(encoded) = body.strip_prefix(ATTACHMENT_PREFIX) else {
        return Ok(None);
    };
    let bytes = BASE64URL_NOPAD
        .decode(encoded.as_bytes())
        .context("decode attachment offer")?;
    let (wire, remainder): (AttachmentWire, &[u8]) =
        postcard::take_from_bytes(&bytes).context("parse attachment offer")?;
    anyhow::ensure!(
        remainder.is_empty(),
        "attachment offer contains trailing bytes"
    );
    anyhow::ensure!(
        wire.version == ATTACHMENT_OFFER_VERSION,
        "unsupported attachment offer version"
    );
    validate_display_name(&wire.offer.name)?;
    anyhow::ensure!(
        crate::contracts::valid_operation_id(&wire.offer.offer_id),
        "invalid attachment offer ID"
    );
    let ticket: BlobTicket = wire
        .offer
        .ticket
        .parse()
        .context("parse attachment ticket")?;
    anyhow::ensure!(
        ticket.format() == BlobFormat::Raw,
        "unsupported attachment blob format"
    );
    anyhow::ensure!(
        ticket.to_string() == wire.offer.ticket,
        "attachment ticket is not canonical"
    );
    Ok(Some(wire.offer))
}

pub(crate) fn validate_offer_binding(
    from: PublicKey,
    message_id: [u8; 16],
    timestamp_ms: u64,
    body: &str,
) -> Result<AttachmentOffer> {
    anyhow::ensure!(
        timestamp_ms != 0,
        "attachment envelope timestamp is invalid"
    );
    let offer = parse_attachment_body(body)?
        .context("attachment envelope does not contain a typed offer")?;
    anyhow::ensure!(
        id_string(&message_id) == offer.offer_id,
        "attachment envelope message ID does not match offer ID"
    );
    let ticket: BlobTicket = offer.ticket.parse().context("parse attachment ticket")?;
    anyhow::ensure!(
        ticket.addr().id == from,
        "attachment provider does not match its signature"
    );
    Ok(offer)
}

pub(crate) fn parse_signed_offer_token(
    token: &str,
    expected_topic: TopicId,
) -> Result<(AttachmentOffer, BlobTicket)> {
    let bytes = BASE64URL_NOPAD
        .decode(token.as_bytes())
        .context("decode signed attachment offer")?;
    let envelope = Envelope::decode(&bytes, expected_topic)
        .map_err(|_| anyhow::anyhow!("unsupported or malformed signed attachment token"))?;
    anyhow::ensure!(
        envelope.kind == EnvelopeKind::AttachmentOffer,
        "token is not an attachment offer"
    );
    let offer = validate_offer_binding(
        envelope.from,
        envelope.message_id,
        envelope.timestamp_ms,
        &envelope.body,
    )?;
    let ticket = offer.ticket.parse().context("parse attachment ticket")?;
    Ok((offer, ticket))
}

pub(crate) fn encode_signed_offer(
    secret: &SecretKey,
    topic: TopicId,
    operation_id: &meshmsg_protocol::OperationId,
    offer: AttachmentOffer,
    timestamp_ms: u64,
) -> Result<EncodedOffer> {
    anyhow::ensure!(
        operation_id.as_str() == offer.offer_id,
        "attachment operation ID does not match offer ID"
    );
    let message_id = operation_id.to_bytes();
    let body = attachment_body(&offer)?;
    validate_offer_binding(secret.public(), message_id, timestamp_ms, &body)?;
    let encoded = Envelope::encode_with_id_at(
        secret,
        topic,
        EnvelopeKind::AttachmentOffer,
        body,
        message_id,
        timestamp_ms,
    )?;
    Ok(EncodedOffer {
        encoded,
        from: secret.public(),
        message_id,
        timestamp_ms,
        offer,
    })
}

pub(crate) fn offer_event(
    from: PublicKey,
    message_id: [u8; 16],
    timestamp_ms: u64,
    encoded: &[u8],
    offer: AttachmentOffer,
) -> meshmsg_protocol::Event {
    meshmsg_protocol::Event::AttachmentOffer(meshmsg_protocol::AttachmentOffer {
        from: from.to_string().parse().expect("public key is canonical"),
        message_id: id_string(&message_id)
            .parse()
            .expect("message ID is canonical"),
        timestamp_ms,
        offer_id: offer.offer_id.parse().expect("validated offer ID"),
        kind: match offer.kind {
            super::AttachmentKind::File => meshmsg_protocol::AttachmentKind::File,
            super::AttachmentKind::DirectoryTarV1 => {
                meshmsg_protocol::AttachmentKind::DirectoryTarV1
            }
        },
        name: meshmsg_protocol::AttachmentName::new(offer.name).expect("validated attachment name"),
        size: offer.size,
        ticket: meshmsg_protocol::AttachmentToken::new(offer.ticket)
            .expect("validated attachment ticket"),
        offer: meshmsg_protocol::AttachmentToken::new(BASE64URL_NOPAD.encode(encoded))
            .expect("bounded signed attachment offer"),
    })
}

#[cfg(test)]
pub(crate) fn validate_attachment_event(
    expected_topic: Option<TopicId>,
    live_now_ms: Option<u64>,
    from: &str,
    message_id: &str,
    timestamp_ms: u64,
    offer: &AttachmentOffer,
    token: &str,
) -> Result<()> {
    anyhow::ensure!(
        crate::contracts::valid_operation_id(message_id),
        "invalid attachment message ID"
    );
    anyhow::ensure!(
        offer.offer_id == message_id,
        "attachment event IDs do not match"
    );
    let encoded = BASE64URL_NOPAD
        .decode(token.as_bytes())
        .context("decode signed attachment event")?;
    let envelope = Envelope::decode_signed(&encoded)?;
    if let Some(expected_topic) = expected_topic {
        anyhow::ensure!(
            envelope.topic == expected_topic,
            "attachment event belongs to another topic"
        );
    }
    if let Some(now_ms) = live_now_ms {
        let oldest = now_ms.saturating_sub(ENVELOPE_ACCEPTANCE_WINDOW.as_millis() as u64);
        let newest = now_ms.saturating_add(ENVELOPE_FUTURE_SKEW.as_millis() as u64);
        anyhow::ensure!(
            (oldest..=newest).contains(&envelope.timestamp_ms),
            "attachment event timestamp is outside the live acceptance window"
        );
    }
    let signed_offer = validate_offer_binding(
        envelope.from,
        envelope.message_id,
        envelope.timestamp_ms,
        &envelope.body,
    )?;
    anyhow::ensure!(
        envelope.from.to_string() == from,
        "attachment event provider does not match"
    );
    anyhow::ensure!(
        id_string(&envelope.message_id) == message_id,
        "attachment event message ID does not match"
    );
    anyhow::ensure!(
        envelope.timestamp_ms == timestamp_ms && timestamp_ms != 0,
        "attachment event timestamp does not match"
    );
    anyhow::ensure!(
        &signed_offer == offer,
        "attachment event metadata does not match its signed offer"
    );
    Ok(())
}

#[cfg(debug_assertions)]
fn fixture_event_value(event: meshmsg_protocol::Event) -> serde_json::Value {
    serde_json::to_value(meshmsg_protocol::EventFrame::new(
        meshmsg_protocol::RequestId::new_random(),
        event,
    ))
    .expect("attachment fixture serialization")
}

#[cfg(debug_assertions)]
pub(crate) fn signed_attachment_fixture(
    dir: &std::path::Path,
    offer_id: &str,
    kind: &str,
    name: &str,
    size: u64,
) -> Result<serde_json::Value> {
    anyhow::ensure!(
        crate::contracts::valid_operation_id(offer_id),
        "invalid fixture offer ID"
    );
    validate_display_name(name)?;
    let kind = match kind {
        "file" => super::AttachmentKind::File,
        "directory_tar_v1" => super::AttachmentKind::DirectoryTarV1,
        _ => anyhow::bail!("invalid fixture attachment kind"),
    };
    let (state, secret) = crate::config::State::load_for_doctor(dir)?;
    let topic = state.topic_id()?;
    let timestamp_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_millis() as u64;
    let offer = AttachmentOffer {
        offer_id: offer_id.to_owned(),
        kind,
        name: name.to_owned(),
        size,
        ticket: BlobTicket::new(
            iroh::EndpointAddr::new(secret.public()),
            iroh_blobs::Hash::new(format!("{offer_id}:{kind:?}:{name}:{size}").as_bytes()),
            BlobFormat::Raw,
        )
        .to_string(),
    };
    let operation_id = offer_id.parse()?;
    let signed = encode_signed_offer(&secret, topic, &operation_id, offer, timestamp_ms)?;
    Ok(fixture_event_value(offer_event(
        signed.from,
        signed.message_id,
        signed.timestamp_ms,
        &signed.encoded,
        signed.offer,
    )))
}

#[cfg(test)]
pub(crate) fn signed_attachment_event_for_topic_for_test(
    secret: &SecretKey,
    topic: TopicId,
    offer_id: &str,
    kind: super::AttachmentKind,
    name: &str,
    size: u64,
    timestamp_ms: u64,
) -> serde_json::Value {
    let offer = AttachmentOffer {
        offer_id: offer_id.to_owned(),
        kind,
        name: name.to_owned(),
        size,
        ticket: BlobTicket::new(
            iroh::EndpointAddr::new(secret.public()),
            iroh_blobs::Hash::new(b"test attachment"),
            BlobFormat::Raw,
        )
        .to_string(),
    };
    let operation_id = offer_id.parse().unwrap();
    let signed = encode_signed_offer(secret, topic, &operation_id, offer, timestamp_ms)
        .expect("test signed attachment envelope");
    fixture_event_value(offer_event(
        signed.from,
        signed.message_id,
        signed.timestamp_ms,
        &signed.encoded,
        signed.offer,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attachment::{runtime::download_request_context, AttachmentKind};
    use serde_byte_array::ByteArray;
    use std::path::Path;

    fn test_topic() -> TopicId {
        TopicId::from_bytes([7; 32])
    }

    fn operation_id_bytes(operation_id: &str) -> [u8; 16] {
        operation_id
            .parse::<meshmsg_protocol::OperationId>()
            .expect("validated operation ID")
            .to_bytes()
    }

    fn encode_unchecked_signed_envelope(
        secret: &SecretKey,
        kind: EnvelopeKind,
        body: String,
        message_id: [u8; 16],
        timestamp_ms: u64,
    ) -> Bytes {
        let topic = test_topic();
        let signed = postcard::to_stdvec(&crate::gossip::EnvelopeSignaturePayload {
            domain: crate::gossip::ENVELOPE_DOMAIN,
            version: crate::gossip::ENVELOPE_VERSION,
            topic,
            from: secret.public(),
            message_id,
            timestamp_ms,
            kind,
            body: &body,
        })
        .unwrap();
        postcard::to_stdvec(&Envelope {
            domain: crate::gossip::ENVELOPE_DOMAIN.to_owned(),
            version: crate::gossip::ENVELOPE_VERSION,
            topic,
            from: secret.public(),
            message_id,
            timestamp_ms,
            kind,
            body,
            signature: ByteArray::new(secret.sign(&signed).to_bytes()),
        })
        .unwrap()
        .into()
    }
    fn sample_offer(provider: PublicKey) -> AttachmentOffer {
        AttachmentOffer {
            offer_id: "0123456789abcdef0123456789abcdef".to_owned(),
            kind: AttachmentKind::File,
            name: "report.txt".to_owned(),
            size: 6,
            ticket: BlobTicket::new(
                iroh::EndpointAddr::new(provider),
                iroh_blobs::Hash::new(b"report"),
                BlobFormat::Raw,
            )
            .to_string(),
        }
    }

    #[test]
    fn signed_attachment_offer_round_trips_and_rejects_tampering() {
        let secret = SecretKey::generate();
        let offer = sample_offer(secret.public());
        let encoded = Envelope::encode_with_id_at(
            &secret,
            test_topic(),
            EnvelopeKind::AttachmentOffer,
            attachment_body(&offer).unwrap(),
            operation_id_bytes(&offer.offer_id),
            42,
        )
        .unwrap();
        let token = BASE64URL_NOPAD.encode(&encoded);

        let (decoded, ticket) = parse_signed_offer_token(&token, test_topic()).unwrap();
        assert_eq!(decoded, offer);
        assert_eq!(ticket.addr().id, secret.public());
        let operation_id: meshmsg_protocol::OperationId =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".parse().unwrap();
        let context = download_request_context(
            &operation_id,
            &token,
            Path::new("/tmp/report.txt"),
            test_topic(),
        )
        .unwrap();
        assert_eq!(context.offer_id.to_string(), offer.offer_id);
        assert_eq!(context.provider.to_string(), secret.public().to_string());
        assert_eq!(context.kind, meshmsg_protocol::AttachmentKind::File);
        assert_eq!(context.name.as_str(), "report.txt");
        assert_eq!(context.declared_size, Some(6));
        assert_eq!(
            context.token_digest,
            crate::ipc::download_token_digest(&token)
        );
        validate_attachment_event(
            Some(test_topic()),
            Some(42),
            &secret.public().to_string(),
            &decoded.offer_id,
            42,
            &decoded,
            &token,
        )
        .unwrap();
        assert!(validate_attachment_event(
            Some(TopicId::from_bytes([8; 32])),
            Some(42),
            &secret.public().to_string(),
            &decoded.offer_id,
            42,
            &decoded,
            &token,
        )
        .is_err());
        assert!(validate_attachment_event(
            Some(test_topic()),
            Some(42 + ENVELOPE_ACCEPTANCE_WINDOW.as_millis() as u64 + 1),
            &secret.public().to_string(),
            &decoded.offer_id,
            42,
            &decoded,
            &token,
        )
        .is_err());
        // Saved signed tokens are portable capabilities: their nonzero signed
        // timestamp remains authenticated but does not expire at download time.
        assert!(parse_signed_offer_token(&token, test_topic()).is_ok());
        let zero_time = encode_unchecked_signed_envelope(
            &secret,
            EnvelopeKind::AttachmentOffer,
            attachment_body(&offer).unwrap(),
            operation_id_bytes(&offer.offer_id),
            0,
        );
        let zero_time_envelope = Envelope::decode(&zero_time, test_topic()).unwrap();
        assert!(validate_offer_binding(
            zero_time_envelope.from,
            zero_time_envelope.message_id,
            zero_time_envelope.timestamp_ms,
            &zero_time_envelope.body,
        )
        .is_err());
        assert!(
            parse_signed_offer_token(&BASE64URL_NOPAD.encode(&zero_time), test_topic()).is_err()
        );

        let mut tampered = encoded.to_vec();
        let last = tampered.last_mut().unwrap();
        *last ^= 1;
        assert!(
            parse_signed_offer_token(&BASE64URL_NOPAD.encode(&tampered), test_topic()).is_err()
        );
    }

    #[test]
    fn attachment_wire_rejects_provider_mismatch_version_and_trailing_bytes() {
        let signer = SecretKey::generate();
        let other = SecretKey::generate();
        let mismatched = sample_offer(other.public());
        let operation_id = mismatched.offer_id.parse().unwrap();
        assert!(crate::attachment::protocol::encode_signed_offer(
            &signer,
            test_topic(),
            &operation_id,
            mismatched,
            42,
        )
        .is_err());

        let version = postcard::to_stdvec(&AttachmentWire {
            version: ATTACHMENT_OFFER_VERSION + 1,
            offer: sample_offer(signer.public()),
        })
        .unwrap();
        let body = format!("{ATTACHMENT_PREFIX}{}", BASE64URL_NOPAD.encode(&version));
        assert!(parse_attachment_body(&body).is_err());

        let mut trailing = postcard::to_stdvec(&AttachmentWire {
            version: ATTACHMENT_OFFER_VERSION,
            offer: sample_offer(signer.public()),
        })
        .unwrap();
        trailing.push(0);
        let body = format!("{ATTACHMENT_PREFIX}{}", BASE64URL_NOPAD.encode(&trailing));
        assert!(parse_attachment_body(&body).is_err());
    }

    #[test]
    fn ordinary_and_malformed_prefixed_signed_text_remain_messages() {
        let secret = SecretKey::generate();
        for body in ["legacy text", "meshmsg-attachment-v1:not-an-offer"] {
            let encoded = Envelope::encode_at(
                &secret,
                test_topic(),
                EnvelopeKind::Message,
                body.to_owned(),
                42,
            )
            .unwrap();
            let envelope = Envelope::decode(&encoded, test_topic()).unwrap();
            let event = serde_json::to_value(crate::gossip::message_event(&envelope)).unwrap();
            assert_eq!(event["type"], "message");
            assert_eq!(event["body"], body);
        }
    }
}
