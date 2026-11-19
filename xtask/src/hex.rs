//! Lower-case hexadecimal encoding and strict decoding (hand-rolled).

/// Encode `bytes` as lower-case hex.
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        out.push(nibble(b >> 4));
        out.push(nibble(b & 0x0f));
    }
    out
}

fn nibble(n: u8) -> char {
    char::from_digit(u32::from(n), 16).unwrap_or('?')
}

/// Decode hex (either case). Rejects odd length and non-hex characters.
pub fn decode(text: &str) -> Result<Vec<u8>, String> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err(format!("odd hex length {}", bytes.len()));
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for (i, pair) in bytes.as_chunks::<2>().0.iter().enumerate() {
        let &[hi, lo] = pair;
        let digit = |c: u8, pos: usize| {
            char::from(c)
                .to_digit(16)
                .ok_or_else(|| format!("non-hex character {:?} at offset {pos}", char::from(c)))
        };
        let hi = digit(hi, 2 * i)?;
        let lo = digit(lo, 2 * i + 1)?;
        let byte = u8::try_from(hi * 16 + lo).map_err(|_| "hex digit range".to_string())?;
        out.push(byte);
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_all_bytes() {
        let all: Vec<u8> = (0u8..=255).collect();
        let h = encode(&all);
        assert_eq!(h.len(), 512);
        assert!(h.starts_with("000102"));
        assert!(h.ends_with("fdfeff"));
        assert_eq!(decode(&h).unwrap(), all);
    }

    #[test]
    fn known_values() {
        assert_eq!(encode(b""), "");
        assert_eq!(encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
        assert_eq!(decode("DEADbeef").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn rejects_malformed() {
        assert!(decode("abc").is_err());
        assert!(decode("zz").is_err());
        assert!(decode("0g").is_err());
        assert!(decode(" 0").is_err());
    }
}
