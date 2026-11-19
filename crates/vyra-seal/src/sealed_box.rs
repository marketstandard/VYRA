//! The sealed box: hybrid KEM + ChaCha20-Poly1305 in the KEM-DEM pattern.
//!
//! Wire format (VYRA-ORIGINAL):
//!
//! ```text
//! sealed = "VYRA" ‖ 0x01 ‖ 0x07 (SealedBox) ‖ suite_id     header, 7 bytes
//!          ‖ kem_ct_raw                                      ct1 ‖ ct2, fixed per suite
//!          ‖ ciphertext                                      len(plaintext) bytes
//!          ‖ tag                                             16 bytes
//! ```
//!
//! Sealing:
//!
//! ```text
//! (kem_ct, K)  = HybridKem(suite).encapsulate_to(pk)          fresh per seal
//! key ‖ nonce  = kdf::derive(suite_id, K, kem_ct_raw)         see crate::kdf
//! aad'         = "VYRA-SEAL-v1" ‖ suite_id ‖ aad              fixed-length prefix
//! ct ‖ tag     = ChaCha20-Poly1305(key, nonce).encrypt(plaintext, aad')
//! ```
//!
//! `aad'` needs no length framing: the label and the suite id have fixed
//! lengths, so the caller's `aad` is everything after byte 13, and the AEAD
//! itself authenticates `len(aad')`.

use core::fmt;

use vyra_core::wire::{self, HEADER_LEN, ObjectType, Reader};
use vyra_core::{EntropySource, Error, Result, SecretBytes};
use vyra_kem::{HybridCiphertext, HybridKem, HybridPublicKey, HybridSecretKey, KemSuite};
use zeroize::Zeroizing;

use crate::aead::{self, MAX_PLAINTEXT_LEN, TAG_LEN};
use crate::kdf::{self, SEAL_LABEL};

/// Error for a key or sealed box whose suite differs from the [`SealedBox`] suite.
const SUITE_MISMATCH: Error =
    Error::InvalidEncoding("sealed box suite does not match SealedBox suite");

/// Public-key authenticated encryption of one message to one recipient.
///
/// See the [crate documentation](crate) for the construction, the security
/// properties it aims for and its limits. Every [`seal`](Self::seal) runs a
/// fresh hybrid KEM encapsulation, so every message is encrypted under its own
/// single-use AEAD key.
pub struct SealedBox {
    kem: HybridKem,
}

impl SealedBox {
    /// A sealed box over the hybrid KEM `suite`.
    pub fn new(suite: KemSuite) -> Self {
        SealedBox {
            kem: HybridKem::new(suite),
        }
    }

    /// The KEM suite this sealed box uses.
    pub const fn suite(&self) -> KemSuite {
        self.kem.suite()
    }

    /// Bytes a sealed box adds to its plaintext for `suite`:
    /// wire header (7) + raw hybrid KEM ciphertext + Poly1305 tag (16).
    pub const fn overhead(suite: KemSuite) -> usize {
        HEADER_LEN + suite.ciphertext_len() + TAG_LEN
    }

    /// Encrypt `plaintext` to `pk`, authenticating `aad` as well.
    ///
    /// The output length is `plaintext.len() + SealedBox::overhead(suite)`.
    /// `aad` is not included in the output; the recipient must supply the same
    /// bytes to [`open`](Self::open).
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidEncoding`] if `pk` belongs to another suite;
    /// - [`Error::InvalidLength`] if `plaintext` is longer than
    ///   [`MAX_PLAINTEXT_LEN`];
    /// - [`Error::EntropyFailure`] if `rng` fails.
    pub fn seal(
        &self,
        pk: &HybridPublicKey,
        aad: &[u8],
        plaintext: &[u8],
        rng: &mut dyn EntropySource,
    ) -> Result<Vec<u8>> {
        if pk.suite() != self.suite() {
            return Err(SUITE_MISMATCH);
        }
        aead::check_plaintext_len(plaintext.len())?;

        let (kem_ct, shared) = self.kem.encapsulate_to(pk, rng)?;
        let kem_ct_raw = kem_ct.as_raw();
        let dem = kdf::derive(self.suite().id(), &shared, kem_ct_raw);
        drop(shared);

        // Header and KEM ciphertext are public. The buffer is zeroizing from the
        // start, so any early return after plaintext has been copied in wipes
        // it. Reserve the exact remaining capacity before the plaintext is
        // copied in, so the buffer never reallocates while it holds plaintext.
        let mut out = Zeroizing::new(wire::encode(
            ObjectType::SealedBox,
            self.suite().id(),
            kem_ct_raw,
        ));
        let body_start = out.len();
        let body_len = plaintext
            .len()
            .checked_add(TAG_LEN)
            .ok_or(Error::InvalidLength {
                what: "sealed box plaintext",
                expected: usize::try_from(MAX_PLAINTEXT_LEN).unwrap_or(usize::MAX),
                actual: plaintext.len(),
            })?;
        out.reserve_exact(body_len);
        out.extend_from_slice(plaintext);

        let tag = {
            let (_, body) = out
                .split_at_mut_checked(body_start)
                .ok_or(Error::Internal("sealed box body offset"))?;
            aead::encrypt_in_place(
                dem.key()?,
                dem.nonce()?,
                &associated_data(self.suite(), aad),
                body,
            )?
        };
        out.extend_from_slice(tag.as_slice());
        // Hand over the finished (encrypted) bytes; the wrapper is left empty
        // and is wiped on drop.
        Ok(core::mem::take(&mut *out))
    }

    /// Decrypt and authenticate a sealed box with `sk`, checking `aad`.
    ///
    /// The plaintext is returned as [`SecretBytes`]: it is zeroized on drop and
    /// redacted under `Debug`, because a sealed box usually carries
    /// confidential data. Copy it out with
    /// [`expose`](SecretBytes::expose) if a plain buffer is needed.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidLength`] if `sealed` is shorter than its header, or
    ///   shorter than `SealedBox::overhead(suite)`;
    /// - [`Error::InvalidEncoding`] for a wrong magic, version or object type,
    ///   or if `sealed` or `sk` belongs to another suite;
    /// - [`Error::UnknownSuite`] for an unknown suite id;
    /// - [`Error::DecryptionFailed`] for any authentication failure: a
    ///   modified KEM ciphertext, body, tag or `aad`, the wrong recipient key,
    ///   or trailing / missing body bytes. No further detail is given.
    pub fn open(&self, sk: &HybridSecretKey, aad: &[u8], sealed: &[u8]) -> Result<SecretBytes> {
        let (suite_id, payload) = wire::decode(sealed, ObjectType::SealedBox)?;
        let suite = KemSuite::from_id(suite_id)?;
        if suite != self.suite() || sk.suite() != self.suite() {
            return Err(SUITE_MISMATCH);
        }

        let mut reader = Reader::new(payload);
        let kem_ct_raw = reader.take(suite.ciphertext_len(), "sealed box KEM ciphertext")?;
        let body = reader.rest();
        let ct_len = body
            .len()
            .checked_sub(TAG_LEN)
            .ok_or(Error::InvalidLength {
                what: "sealed box AEAD body",
                expected: TAG_LEN,
                actual: body.len(),
            })?;
        let (ciphertext, tag) = body
            .split_at_checked(ct_len)
            .ok_or(Error::Internal("sealed box tag offset"))?;

        let kem_ct = HybridCiphertext::from_raw(suite, kem_ct_raw)?;
        let shared = self.kem.decapsulate_with(sk, &kem_ct)?;
        let dem = kdf::derive(suite.id(), &shared, kem_ct_raw);
        drop(shared);

        let mut plaintext = SecretBytes::from_slice(ciphertext);
        aead::decrypt_in_place(
            dem.key()?,
            dem.nonce()?,
            &associated_data(suite, aad),
            plaintext.expose_mut(),
            tag,
        )?;
        Ok(plaintext)
    }
}

/// `"VYRA-SEAL-v1" ‖ suite_id ‖ aad`.
fn associated_data(suite: KemSuite, aad: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(SEAL_LABEL.len().saturating_add(1).saturating_add(aad.len()));
    out.extend_from_slice(SEAL_LABEL);
    out.push(suite.id());
    out.extend_from_slice(aad);
    out
}

impl fmt::Debug for SealedBox {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealedBox")
            .field("suite", &self.suite())
            .finish()
    }
}
