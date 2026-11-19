//! DEM key and nonce derivation. VYRA-ORIGINAL encoding.
//!
//! ```text
//! key(32) ‖ nonce(12) = SHAKE256( 0x01 ‖ frame("VYRA-SEAL-v1") ‖ frame([suite_id])
//!                                 ‖ frame(K) ‖ frame(kem_ct_raw) )[0..44]
//! frame(x) = u64_be(len(x)) ‖ x
//! ```
//!
//! This is [`vyra_core::Transcript::finalize_xof`] with label [`SEAL_LABEL`]
//! and three fields: the one-byte suite id, the 32-byte hybrid KEM shared
//! secret `K`, and the raw hybrid KEM ciphertext `ct1 ‖ ct2` (no wire header).
//!
//! `K` is fresh for every seal (a new encapsulation), so each derived key is
//! used to encrypt exactly one message and the derived nonce never repeats
//! under a key. Hashing the KEM ciphertext into the DEM key is redundant with
//! the hybrid combiner (which already hashes it into `K`); it is kept so the
//! DEM key is bound to the exact ciphertext bytes it travelled with.

use vyra_core::{Error, Result, SecretBytes, Transcript};

use crate::aead::{KEY_LEN, NONCE_LEN};

/// Domain-separation label of the sealed box. Also the first bytes of the
/// AEAD associated data (see [`crate::sealed_box`]).
pub const SEAL_LABEL: &[u8] = b"VYRA-SEAL-v1";

/// Number of SHAKE256 output bytes read: key (32) followed by nonce (12).
pub const DEM_OUTPUT_LEN: usize = KEY_LEN + NONCE_LEN;

/// A derived single-use ChaCha20-Poly1305 key and nonce, zeroized on drop.
pub(crate) struct DemKey {
    bytes: SecretBytes,
}

impl DemKey {
    /// The 32-byte AEAD key.
    pub(crate) fn key(&self) -> Result<&[u8]> {
        self.bytes
            .expose()
            .get(..KEY_LEN)
            .ok_or(Error::Internal("DEM key length"))
    }

    /// The 12-byte AEAD nonce.
    pub(crate) fn nonce(&self) -> Result<&[u8]> {
        self.bytes
            .expose()
            .get(KEY_LEN..DEM_OUTPUT_LEN)
            .ok_or(Error::Internal("DEM nonce length"))
    }
}

/// Derive the DEM key and nonce from the suite id, the KEM shared secret and
/// the raw KEM ciphertext.
pub(crate) fn derive(suite_id: u8, shared_secret: &SecretBytes, kem_ct_raw: &[u8]) -> DemKey {
    let mut t = Transcript::new(SEAL_LABEL);
    t.append(&[suite_id])
        .append(shared_secret.expose())
        .append(kem_ct_raw);
    let mut bytes = SecretBytes::zeroed(DEM_OUTPUT_LEN);
    t.finalize_xof(bytes.expose_mut());
    DemKey { bytes }
}
