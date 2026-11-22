use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::{fmt, str::FromStr};

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IdError {
    kind: &'static str,
    expected_hex_chars: usize,
}

impl fmt::Display for IdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid {}: expected {} lowercase hexadecimal characters",
            self.kind, self.expected_hex_chars
        )
    }
}

impl std::error::Error for IdError {}

macro_rules! hex_id {
    ($name:ident, $bytes:expr, $kind:literal) => {
        /// Fixed-width binary ID. Lowercase hexadecimal exists only at the
        /// text edges (`Display`, `FromStr`, serde); the derived ordering on
        /// the bytes equals the lexical ordering of that text.
        #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; $bytes]);

        impl $name {
            pub const HEX_LEN: usize = $bytes * 2;

            pub fn new_random() -> Self {
                Self(rand::random())
            }

            pub const fn from_bytes(bytes: [u8; $bytes]) -> Self {
                Self(bytes)
            }

            pub const fn to_bytes(self) -> [u8; $bytes] {
                self.0
            }

            pub const fn as_bytes(&self) -> &[u8; $bytes] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.to_string())
                    .finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                let mut text = [0_u8; $bytes * 2];
                data_encoding::HEXLOWER.encode_mut(&self.0, &mut text);
                formatter.write_str(std::str::from_utf8(&text).expect("hexadecimal is ASCII"))
            }
        }

        impl FromStr for $name {
            type Err = IdError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                let error = IdError {
                    kind: $kind,
                    expected_hex_chars: Self::HEX_LEN,
                };
                let valid = value.len() == Self::HEX_LEN
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
                if !valid {
                    return Err(error);
                }
                let mut bytes = [0_u8; $bytes];
                data_encoding::HEXLOWER
                    .decode_mut(value.as_bytes(), &mut bytes)
                    .map_err(|_| error)?;
                Ok(Self(bytes))
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.collect_str(self)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                value.parse().map_err(de::Error::custom)
            }
        }
    };
}

hex_id!(RequestId, 16, "request ID");
hex_id!(OperationId, 16, "operation ID");
hex_id!(MessageId, 16, "message ID");
hex_id!(OfferId, 16, "offer ID");
hex_id!(PeerId, 32, "peer ID");
hex_id!(TopicId, 32, "topic ID");
hex_id!(ContentDigest, 32, "content digest");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_reject_noncanonical_text() {
        assert!("ABCDEF00000000000000000000000000"
            .parse::<RequestId>()
            .is_err());
        assert!("0".repeat(31).parse::<OperationId>().is_err());
        assert!("g".repeat(64).parse::<PeerId>().is_err());
    }

    #[test]
    fn generated_ids_round_trip_through_json() {
        let id = RequestId::new_random();
        let encoded = serde_json::to_string(&id).unwrap();
        assert_eq!(serde_json::from_str::<RequestId>(&encoded).unwrap(), id);
    }

    #[test]
    fn ids_are_bytes_with_lowercase_hex_only_at_the_text_edges() {
        let bytes = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 0xff];
        let text = "000102030405060708090a0b0c0d0eff";
        let id = MessageId::from_bytes(bytes);
        assert_eq!(id.to_string(), text);
        assert_eq!(text.parse::<MessageId>().unwrap(), id);
        assert_eq!(id.as_bytes(), &bytes);
        assert_eq!(serde_json::to_string(&id).unwrap(), format!("\"{text}\""));
        assert_eq!(format!("{id:?}"), format!("MessageId(\"{text}\")"));
    }

    #[test]
    fn byte_order_matches_the_lexical_order_of_the_hex_text() {
        let mut ids: Vec<PeerId> = (0..64).map(|_| PeerId::new_random()).collect();
        ids.sort_unstable();
        let text: Vec<String> = ids.iter().map(PeerId::to_string).collect();
        let mut sorted_text = text.clone();
        sorted_text.sort_unstable();
        assert_eq!(text, sorted_text);
    }

    #[test]
    fn typed_ids_expose_their_validated_bytes_without_reparsing() {
        let operation: OperationId = "000102030405060708090a0b0c0d0e0f".parse().unwrap();
        assert_eq!(
            operation.to_bytes(),
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        );
        let peer: PeerId = "ab".repeat(32).parse().unwrap();
        assert_eq!(peer.to_bytes(), [0xab; 32]);
    }
}
