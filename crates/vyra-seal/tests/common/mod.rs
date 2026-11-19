//! Shared helpers for the vyra-seal integration tests.
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]

use core::ops::Range;

use vyra_core::DeterministicEntropy;
use vyra_core::wire::HEADER_LEN;
use vyra_kem::{
    HybridKem, HybridPublicKey, HybridSecretKey, KemSuite, MlKem512, MlKem768, MlKem1024,
};
use vyra_seal::TAG_LEN;

/// A deterministic key pair for `suite`, seeded by `seed`.
pub fn keypair(suite: KemSuite, seed: &[u8]) -> (HybridPublicKey, HybridSecretKey) {
    let mut rng = DeterministicEntropy::from_seed(seed);
    HybridKem::new(suite).generate(&mut rng).unwrap()
}

/// ML-KEM (component 1) ciphertext length for `suite`.
pub fn ct1_len(suite: KemSuite) -> usize {
    match suite {
        KemSuite::Vyra1 => MlKem512::CIPHERTEXT_LEN,
        KemSuite::Vyra3 => MlKem768::CIPHERTEXT_LEN,
        KemSuite::Vyra5 => MlKem1024::CIPHERTEXT_LEN,
    }
}

/// Byte regions of a sealed box with a `pt_len`-byte plaintext.
#[derive(Debug, Clone)]
pub struct Regions {
    pub header: Range<usize>,
    pub ct1: Range<usize>,
    pub ct2: Range<usize>,
    pub body: Range<usize>,
    pub tag: Range<usize>,
}

pub fn regions(suite: KemSuite, pt_len: usize) -> Regions {
    let ct1_end = HEADER_LEN + ct1_len(suite);
    let ct_end = HEADER_LEN + suite.ciphertext_len();
    let body_end = ct_end + pt_len;
    Regions {
        header: 0..HEADER_LEN,
        ct1: HEADER_LEN..ct1_end,
        ct2: ct1_end..ct_end,
        body: ct_end..body_end,
        tag: body_end..body_end + TAG_LEN,
    }
}

/// `n` bit indices spread evenly over the bits of `bytes` (byte range), first
/// and last bit included. If the range has at most `n` bits, every bit.
pub fn spread_bits(bytes: Range<usize>, n: usize) -> Vec<usize> {
    let first = bytes.start * 8;
    let bits = (bytes.end - bytes.start) * 8;
    if bits <= n {
        return (first..first + bits).collect();
    }
    (0..n).map(|i| first + i * (bits - 1) / (n - 1)).collect()
}

/// Copy of `bytes` with bit `bit` (0 = LSB of byte 0) flipped.
pub fn flip_bit(bytes: &[u8], bit: usize) -> Vec<u8> {
    let mut out = bytes.to_vec();
    out[bit / 8] ^= 1 << (bit % 8);
    out
}

/// `len` bytes of a fixed, non-constant pattern.
pub fn pattern(len: usize, salt: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(salt) ^ ((i >> 8) as u8))
        .collect()
}
