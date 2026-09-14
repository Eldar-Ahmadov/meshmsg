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
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            pub const HEX_LEN: usize = $bytes * 2;

            pub fn new_random() -> Self {
                Self(data_encoding::HEXLOWER.encode(&rand::random::<[u8; $bytes]>()))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn into_string(self) -> String {
                self.0
            }

            pub fn to_bytes(&self) -> [u8; $bytes] {
                let mut bytes = [0_u8; $bytes];
                data_encoding::HEXLOWER
                    .decode_mut(self.0.as_bytes(), &mut bytes)
                    .expect("canonical hexadecimal ID");
                bytes
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

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
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

        impl FromStr for $name {
            type Err = IdError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                let valid = value.len() == Self::HEX_LEN
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
                valid.then(|| Self(value.to_owned())).ok_or(IdError {
                    kind: $kind,
                    expected_hex_chars: Self::HEX_LEN,
                })
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
