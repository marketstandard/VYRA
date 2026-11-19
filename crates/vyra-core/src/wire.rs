//! Wire framing for serialized VYRA objects.
//!
//! Every serialized object starts with a fixed 7-byte header:
//!
//! ```text
//! offset 0..4  magic       b"VYRA"
//! offset 4     version     1
//! offset 5     object type ObjectType as u8
//! offset 6     suite id    u8 (interpreted by the crate that owns the object)
//! offset 7..   payload
//! ```
//!
//! [`decode`] checks the header only; the payload length and the suite id are
//! validated by the owning crate, typically with a [`Reader`]. Nothing here
//! indexes in a way that can panic.

use crate::error::{Error, Result};

/// Magic bytes at the start of every VYRA object.
pub const MAGIC: [u8; 4] = *b"VYRA";

/// Current wire format version.
pub const VERSION: u8 = 1;

/// Header length in bytes: magic (4) + version (1) + object type (1) + suite (1).
pub const HEADER_LEN: usize = 7;

/// The kind of object a serialization holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ObjectType {
    /// KEM public (encapsulation) key.
    KemPublicKey = 1,
    /// KEM secret (decapsulation) key.
    KemSecretKey = 2,
    /// KEM ciphertext.
    KemCiphertext = 3,
    /// Signature public (verifying) key.
    SigPublicKey = 4,
    /// Signature secret (signing) key.
    SigSecretKey = 5,
    /// Signature.
    Signature = 6,
    /// Sealed box (KEM + AEAD).
    SealedBox = 7,
}

impl ObjectType {
    /// The byte value written to the header.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Parse a header byte.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidEncoding`] for an unassigned value.
    pub const fn from_u8(b: u8) -> Result<Self> {
        match b {
            1 => Ok(ObjectType::KemPublicKey),
            2 => Ok(ObjectType::KemSecretKey),
            3 => Ok(ObjectType::KemCiphertext),
            4 => Ok(ObjectType::SigPublicKey),
            5 => Ok(ObjectType::SigSecretKey),
            6 => Ok(ObjectType::Signature),
            7 => Ok(ObjectType::SealedBox),
            _ => Err(Error::InvalidEncoding("unknown object type")),
        }
    }
}

impl TryFrom<u8> for ObjectType {
    type Error = Error;

    fn try_from(b: u8) -> Result<Self> {
        ObjectType::from_u8(b)
    }
}

/// Serialize `payload` behind a header for `object_type` and `suite`.
pub fn encode(object_type: ObjectType, suite: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN.saturating_add(payload.len()));
    out.extend_from_slice(&MAGIC);
    out.push(VERSION);
    out.push(object_type.as_u8());
    out.push(suite);
    out.extend_from_slice(payload);
    out
}

/// Check the header of `bytes` and return `(suite_id, payload)`.
///
/// The suite id is returned unvalidated; the caller maps it to a suite and
/// reports [`Error::UnknownSuite`] itself.
///
/// # Errors
///
/// - [`Error::InvalidLength`] if `bytes` is shorter than [`HEADER_LEN`];
/// - [`Error::InvalidEncoding`] for wrong magic, unsupported version, or an
///   object type other than `expected_type`.
pub fn decode(bytes: &[u8], expected_type: ObjectType) -> Result<(u8, &[u8])> {
    let mut r = Reader::new(bytes);
    let header = r.take(HEADER_LEN, "wire header")?;
    let (magic, rest) = header
        .split_at_checked(MAGIC.len())
        .ok_or(Error::Internal("header split"))?;
    if magic != MAGIC {
        return Err(Error::InvalidEncoding("bad magic"));
    }
    let [version, object_type, suite] = rest else {
        return Err(Error::Internal("header length"));
    };
    if *version != VERSION {
        return Err(Error::InvalidEncoding("unsupported version"));
    }
    if *object_type != expected_type.as_u8() {
        return Err(Error::InvalidEncoding("unexpected object type"));
    }
    Ok((*suite, r.rest()))
}

/// A bounds-checked cursor over a byte slice. Never panics.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    remaining: &'a [u8],
}

impl<'a> Reader<'a> {
    /// Start reading `bytes` from the beginning.
    pub const fn new(bytes: &'a [u8]) -> Self {
        Reader { remaining: bytes }
    }

    /// Take the next `n` bytes; `what` names the field in the error.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`] with `expected = n` and `actual` = bytes left,
    /// if fewer than `n` bytes remain. The reader is unchanged on error.
    pub fn take(&mut self, n: usize, what: &'static str) -> Result<&'a [u8]> {
        match self.remaining.split_at_checked(n) {
            Some((head, tail)) => {
                self.remaining = tail;
                Ok(head)
            }
            None => Err(Error::InvalidLength {
                what,
                expected: n,
                actual: self.remaining.len(),
            }),
        }
    }

    /// Number of unread bytes.
    pub const fn remaining(&self) -> usize {
        self.remaining.len()
    }

    /// Consume and return all unread bytes.
    pub fn rest(&mut self) -> &'a [u8] {
        core::mem::take(&mut self.remaining)
    }

    /// Finish reading.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`] (`what = "trailing bytes"`, `expected = 0`)
    /// if any bytes are left unread.
    pub fn finish(self) -> Result<()> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(Error::InvalidLength {
                what: "trailing bytes",
                expected: 0,
                actual: self.remaining.len(),
            })
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn header_layout() {
        let enc = encode(ObjectType::Signature, 9, b"p");
        assert_eq!(enc, b"VYRA\x01\x06\x09p");
    }

    #[test]
    fn object_type_round_trip() {
        for b in 0u8..=255 {
            match ObjectType::from_u8(b) {
                Ok(t) => assert_eq!(t.as_u8(), b),
                Err(e) => {
                    assert!(b == 0 || b > 7);
                    assert_eq!(e, Error::InvalidEncoding("unknown object type"));
                }
            }
        }
    }
}
