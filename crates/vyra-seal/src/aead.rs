//! ChaCha20-Poly1305 (RFC 8439) wrapper. ESTABLISHED primitive, used unmodified
//! from the RustCrypto `chacha20poly1305` crate.
//!
//! The wrapper only converts slices to the upstream array types and maps the
//! upstream error. It encrypts and decrypts in place with a detached tag so the
//! caller controls every buffer that ever holds plaintext. Upstream verifies
//! the tag (in constant time) before it decrypts, so on failure the buffer
//! still holds ciphertext.

use chacha20poly1305::{AeadInOut, ChaCha20Poly1305, Key, KeyInit, Nonce, Tag};
use vyra_core::{Error, Result};

/// ChaCha20-Poly1305 key length in bytes.
pub const KEY_LEN: usize = 32;

/// ChaCha20-Poly1305 nonce length in bytes.
pub const NONCE_LEN: usize = 12;

/// Poly1305 tag length in bytes.
pub const TAG_LEN: usize = 16;

/// Largest plaintext ChaCha20-Poly1305 accepts here, in bytes.
///
/// RFC 8439 §2.8 allows up to 2^38 − 64 bytes (the 32-bit block counter starts
/// at 1). The upstream crate rejects any buffer with `len / 64 >= 2^32 − 1`,
/// one byte stricter, so the usable maximum is `(2^32 − 1) · 64 − 1`.
pub const MAX_PLAINTEXT_LEN: u64 = (u32::MAX as u64) * 64 - 1;

fn cipher(key: &[u8]) -> Result<ChaCha20Poly1305> {
    let key = <&Key>::try_from(key).map_err(|_| Error::Internal("AEAD key length"))?;
    Ok(ChaCha20Poly1305::new(key))
}

fn nonce(nonce: &[u8]) -> Result<&Nonce> {
    <&Nonce>::try_from(nonce).map_err(|_| Error::Internal("AEAD nonce length"))
}

/// Encrypt `buffer` in place and return the tag.
///
/// # Errors
///
/// [`Error::InvalidLength`] if `buffer` exceeds [`MAX_PLAINTEXT_LEN`];
/// [`Error::Internal`] for a key or nonce of the wrong length.
pub(crate) fn encrypt_in_place(
    key: &[u8],
    nonce_bytes: &[u8],
    aad: &[u8],
    buffer: &mut [u8],
) -> Result<Tag> {
    check_plaintext_len(buffer.len())?;
    let cipher = cipher(key)?;
    let nonce = nonce(nonce_bytes)?;
    cipher
        .encrypt_inout_detached(nonce, aad, buffer.into())
        .map_err(|_| Error::Internal("AEAD encryption"))
}

/// Verify `tag` over `aad` and `buffer`, then decrypt `buffer` in place.
///
/// # Errors
///
/// [`Error::DecryptionFailed`] for any authentication failure (no detail);
/// [`Error::Internal`] for a key, nonce or tag of the wrong length.
pub(crate) fn decrypt_in_place(
    key: &[u8],
    nonce_bytes: &[u8],
    aad: &[u8],
    buffer: &mut [u8],
    tag: &[u8],
) -> Result<()> {
    let cipher = cipher(key)?;
    let nonce = nonce(nonce_bytes)?;
    let tag = <&Tag>::try_from(tag).map_err(|_| Error::Internal("AEAD tag length"))?;
    cipher
        .decrypt_inout_detached(nonce, aad, buffer.into(), tag)
        .map_err(|_| Error::DecryptionFailed)
}

/// Reject plaintexts longer than [`MAX_PLAINTEXT_LEN`].
pub(crate) fn check_plaintext_len(len: usize) -> Result<()> {
    // usize -> u64 is lossless on every target Rust supports.
    if len as u64 > MAX_PLAINTEXT_LEN {
        return Err(Error::InvalidLength {
            what: "sealed box plaintext (exceeds ChaCha20-Poly1305 limit)",
            expected: usize::try_from(MAX_PLAINTEXT_LEN).unwrap_or(usize::MAX),
            actual: len,
        });
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    // RFC 8439 §2.8.2 test vector.
    const KEY: [u8; 32] = [
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e,
        0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d,
        0x9e, 0x9f,
    ];
    const NONCE: [u8; 12] = [
        0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    ];
    const AAD: [u8; 12] = [
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
    ];
    const PLAINTEXT: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    const CIPHERTEXT: [u8; 114] = [
        0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e,
        0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee,
        0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa, 0xfb, 0x69, 0xda,
        0x92, 0x72, 0x8b, 0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6,
        0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c, 0x98, 0x03, 0xae,
        0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85,
        0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc, 0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5,
        0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b, 0x61, 0x16,
    ];
    const TAG: [u8; 16] = [
        0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06,
        0x91,
    ];

    #[test]
    fn rfc8439_2_8_2_through_wrapper() {
        let mut buf = PLAINTEXT.to_vec();
        let tag = encrypt_in_place(&KEY, &NONCE, &AAD, &mut buf).unwrap();
        assert_eq!(buf, CIPHERTEXT);
        assert_eq!(tag.as_slice(), TAG);

        decrypt_in_place(&KEY, &NONCE, &AAD, &mut buf, &TAG).unwrap();
        assert_eq!(buf, PLAINTEXT);
    }

    #[test]
    fn wrapper_rejects_tampering_without_decrypting() {
        let mut buf = CIPHERTEXT.to_vec();
        let mut bad_tag = TAG;
        bad_tag[15] ^= 1;
        assert_eq!(
            decrypt_in_place(&KEY, &NONCE, &AAD, &mut buf, &bad_tag),
            Err(Error::DecryptionFailed)
        );
        // Tag is checked before decryption: the buffer still holds ciphertext.
        assert_eq!(buf, CIPHERTEXT);
    }

    #[test]
    fn wrapper_rejects_wrong_lengths() {
        let mut buf = [0u8; 4];
        assert!(matches!(
            encrypt_in_place(&KEY[..31], &NONCE, &[], &mut buf),
            Err(Error::Internal(_))
        ));
        assert!(matches!(
            encrypt_in_place(&KEY, &NONCE[..11], &[], &mut buf),
            Err(Error::Internal(_))
        ));
        assert!(matches!(
            decrypt_in_place(&KEY, &NONCE, &[], &mut buf, &TAG[..15]),
            Err(Error::Internal(_))
        ));
    }

    #[test]
    fn max_plaintext_matches_rfc_minus_one() {
        assert_eq!(MAX_PLAINTEXT_LEN, (1u64 << 38) - 64 - 1);
        assert!(check_plaintext_len(1 << 20).is_ok());
    }
}
