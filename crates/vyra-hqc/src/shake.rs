//! SHAKE256-based seed expander and domain-separated hash functions.
//!
//! HQC v5.1 (specification Table 3; reference tag `v5.1.0`,
//! `src/common/symmetric.c`): XOF reads are plain sequential squeezes with no
//! alignment padding. The XOF absorbs **no** domain byte (v5.1 change: the
//! previous version appended `0x01` to every XOF input); only the KEM seed
//! expansion appends one byte, `k/8` (16, 24 or 32), see
//! [`SeedExpander::new_with_domain`].
//!
//! Domain bytes of the hash functions (unchanged in v5.1):
//! - 0x00: G function (SHA3-512)
//! - 0x01: H function (SHA3-256)
//! - 0x02: I function (SHA3-512, PKE keygen)
//! - 0x03: J function (SHA3-256, rejection key)

use sha3::{Digest, Sha3_256, Sha3_512};
use shake::{ExtendableOutput, Shake256, Update, XofReader};

/// Domain separation bytes.
pub(crate) const DOMAIN_G: u8 = 0x00;
pub(crate) const DOMAIN_H: u8 = 0x01;
pub(crate) const DOMAIN_I: u8 = 0x02;
pub(crate) const DOMAIN_J: u8 = 0x03;

/// SHAKE256-based seed expander (plain sequential squeezing).
pub(crate) struct SeedExpander {
    reader: <Shake256 as ExtendableOutput>::Reader,
}

impl SeedExpander {
    /// Initialize: SHAKE256(seed), then finalize for squeezing
    /// (v5.1 `xof_init`: no domain byte).
    pub(crate) fn new(seed: &[u8]) -> Self {
        let mut hasher = Shake256::default();
        hasher.update(seed);
        Self {
            reader: hasher.finalize_xof(),
        }
    }

    /// Initialize: SHAKE256(seed || domain_separator) (v5.1
    /// `xof_init_dom_sep`, used only by the KEM with `k/8` as separator).
    pub(crate) fn new_with_domain(seed: &[u8], domain_separator: u8) -> Self {
        let mut hasher = Shake256::default();
        hasher.update(seed);
        hasher.update(&[domain_separator]);
        Self {
            reader: hasher.finalize_xof(),
        }
    }

    /// Read bytes from the XOF stream.
    ///
    /// Matches `xof_get_bytes` of the v5.1.0 reference: a plain squeeze with
    /// no alignment padding.
    pub(crate) fn get_bytes(&mut self, output: &mut [u8]) {
        self.reader.read(output);
    }
}

/// G function: `SHA3-512(parts[0] || parts[1] || ... || 0x00)`. Returns 64 bytes.
///
/// Streaming absorption of `parts` is byte-equivalent to hashing their
/// concatenation, without materializing a concatenated buffer.
pub(crate) fn hash_g(parts: &[&[u8]]) -> [u8; 64] {
    let mut hasher = Sha3_512::default();
    for part in parts {
        Update::update(&mut hasher, part);
    }
    Update::update(&mut hasher, &[DOMAIN_G]);
    let result = hasher.finalize();
    let mut out = [0u8; 64];
    out.copy_from_slice(&result);
    out
}

/// H function: SHA3-256(data || 0x01). Returns 32 bytes.
pub(crate) fn hash_h(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::default();
    Update::update(&mut hasher, data);
    Update::update(&mut hasher, &[DOMAIN_H]);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// I function: SHA3-512(data || 0x02). Returns 64 bytes.
pub(crate) fn hash_i(data: &[u8]) -> [u8; 64] {
    let mut hasher = Sha3_512::default();
    Update::update(&mut hasher, data);
    Update::update(&mut hasher, &[DOMAIN_I]);
    let result = hasher.finalize();
    let mut out = [0u8; 64];
    out.copy_from_slice(&result);
    out
}

/// J function: `SHA3-256(parts[0] || parts[1] || ... || 0x03)`. Returns 32 bytes.
///
/// Streaming absorption of `parts` is byte-equivalent to hashing their
/// concatenation, without materializing a concatenated buffer.
pub(crate) fn hash_j(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha3_256::default();
    for part in parts {
        Update::update(&mut hasher, part);
    }
    Update::update(&mut hasher, &[DOMAIN_J]);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}
