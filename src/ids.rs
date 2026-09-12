/// Canonical lowercase wire/API representation of a 128-bit message or operation ID.
pub(crate) fn id_string(id: &[u8; 16]) -> String {
    data_encoding::HEXLOWER.encode(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_fixed_width_lowercase_hex() {
        assert_eq!(id_string(&[0xab; 16]), "abababababababababababababababab");
    }
}
