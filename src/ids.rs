//! The one place network identities become local-API identities. Both sides
//! are the same fixed-width bytes, so the conversions are infallible; the
//! tests prove the byte path emits the text the network types print.

/// Local-API identity of an Iroh endpoint key.
pub(crate) fn peer_id(key: iroh::PublicKey) -> meshmsg_protocol::PeerId {
    meshmsg_protocol::PeerId::from_bytes(*key.as_bytes())
}

/// Local-API identity of a gossip topic.
pub(crate) fn topic_id(topic: iroh_gossip::TopicId) -> meshmsg_protocol::TopicId {
    meshmsg_protocol::TopicId::from_bytes(*topic.as_bytes())
}

/// Local-API identity of a stored blob.
pub(crate) fn content_digest(hash: iroh_blobs::Hash) -> meshmsg_protocol::ContentDigest {
    meshmsg_protocol::ContentDigest::from_bytes(*hash.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_id_bytes_print_the_public_key_text() {
        for _ in 0..16 {
            let key = iroh::SecretKey::generate().public();
            assert_eq!(peer_id(key).to_string(), key.to_string());
            assert_eq!(key.to_string().parse(), Ok(peer_id(key)));
        }
    }

    #[test]
    fn topic_id_bytes_print_the_gossip_topic_text() {
        for bytes in [[0_u8; 32], [0xab; 32], rand::random()] {
            let topic = iroh_gossip::TopicId::from_bytes(bytes);
            assert_eq!(topic_id(topic).to_string(), topic.to_string());
            assert_eq!(topic.to_string().parse(), Ok(topic_id(topic)));
        }
    }

    #[test]
    fn content_digest_bytes_print_the_blob_hash_text() {
        for bytes in [[0_u8; 32], [0xab; 32], rand::random()] {
            let hash = iroh_blobs::Hash::from_bytes(bytes);
            assert_eq!(content_digest(hash).to_string(), hash.to_string());
            assert_eq!(hash.to_string().parse(), Ok(content_digest(hash)));
        }
    }

    #[test]
    fn sixteen_byte_ids_print_fixed_width_lowercase_hex() {
        let text = "abababababababababababababababab";
        assert_eq!(
            meshmsg_protocol::OperationId::from_bytes([0xab; 16]).to_string(),
            text
        );
        assert_eq!(
            meshmsg_protocol::MessageId::from_bytes([0xab; 16]).to_string(),
            text
        );
        assert_eq!(
            meshmsg_protocol::OfferId::from_bytes([0xab; 16]).to_string(),
            text
        );
    }
}
