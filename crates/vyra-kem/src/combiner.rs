//! The hybrid KEM combiner. VYRA-ORIGINAL encoding of an established technique.
//!
//! ```text
//! K = SHA3-256( frame("VYRA-KEM-v1") ‖ frame([suite_id]) ‖ frame(ss1) ‖ frame(ss2)
//!               ‖ frame(ct1) ‖ frame(ct2) ‖ frame(pk1) ‖ frame(pk2) )
//! frame(x) = u64_be(len(x)) ‖ x
//! ```
//!
//! Hashing both component ciphertexts alongside both shared secrets is the
//! construction of Giacon, Heuer and Poettering ("KEM Combiners", PKC 2018);
//! hashing the suite id and both public keys makes the output depend on the
//! parameter choice and on the recipient's public keys. On decapsulation those
//! public keys are derived from the secret key (never read from storage), so a
//! decapsulated key is tied to the key pair the secret key actually belongs to.
//! See docs/DECISIONS.md D-01.

use vyra_core::{SecretBytes, Transcript};
use zeroize::Zeroize;

/// Domain-separation label of the combiner transcript.
pub const COMBINER_LABEL: &[u8] = b"VYRA-KEM-v1";

/// Length of the combined shared secret in bytes.
pub const COMBINED_SECRET_LEN: usize = 32;

/// Derive the hybrid shared secret from both components' outputs.
///
/// Pure function of its inputs; it does not check lengths (the caller does).
pub fn combine(
    suite_id: u8,
    ss1: &[u8],
    ss2: &[u8],
    ct1: &[u8],
    ct2: &[u8],
    pk1: &[u8],
    pk2: &[u8],
) -> SecretBytes {
    let mut t = Transcript::new(COMBINER_LABEL);
    t.append(&[suite_id])
        .append(ss1)
        .append(ss2)
        .append(ct1)
        .append(ct2)
        .append(pk1)
        .append(pk2);
    let mut key = t.finalize();
    let out = SecretBytes::from_slice(&key);
    key.zeroize();
    out
}
