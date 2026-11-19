//! Shared helpers for the vyra-sig integration tests.
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]

use vyra_core::{EntropySource, Error, Result};
use vyra_sig::SigSuite;

/// The transition suites (ML-DSA + Ed25519). Named `SUITES` because every
/// test written before U12 iterates it; those tests are unchanged.
pub const SUITES: [SigSuite; 3] = [SigSuite::Vyra2, SigSuite::Vyra3, SigSuite::Vyra5];

/// The dual post-quantum suites (ML-DSA + SLH-DSA).
///
/// SLH-DSA "s" signing takes about 1–3 s per signature even with optimised
/// dependencies, so tests over these suites use fewer iterations than the
/// transition-suite tests (each test states its numbers) and are split per
/// suite where that lets the test harness run them in parallel.
pub const PQ_SUITES: [SigSuite; 3] = [SigSuite::Pq1, SigSuite::Pq3, SigSuite::Pq5];

/// Every named suite.
pub const ALL_SUITES: [SigSuite; 6] = [
    SigSuite::Vyra2,
    SigSuite::Vyra3,
    SigSuite::Vyra5,
    SigSuite::Pq1,
    SigSuite::Pq3,
    SigSuite::Pq5,
];

/// The ML-DSA seed and the second component's seed of a raw composite secret
/// key (`seed_mldsa (32) ‖ seed_second`).
pub fn seeds(sk_raw: &[u8]) -> (&[u8], &[u8]) {
    sk_raw.split_at(32)
}

/// An entropy source that always fails.
pub struct Failing;

impl EntropySource for Failing {
    fn fill(&mut self, _dest: &mut [u8]) -> Result<()> {
        Err(Error::EntropyFailure)
    }
}

/// An entropy source that serves fixed bytes once, in order, then fails.
pub struct Fixed {
    data: Vec<u8>,
    pos: usize,
}

impl Fixed {
    pub fn new(data: &[u8]) -> Self {
        Fixed {
            data: data.to_vec(),
            pos: 0,
        }
    }
}

impl EntropySource for Fixed {
    fn fill(&mut self, dest: &mut [u8]) -> Result<()> {
        let end = self.pos + dest.len();
        if end > self.data.len() {
            return Err(Error::EntropyFailure);
        }
        dest.copy_from_slice(&self.data[self.pos..end]);
        self.pos = end;
        Ok(())
    }
}

/// Return a copy of `bytes` with bit `bit` of byte `index` flipped.
pub fn flip(bytes: &[u8], index: usize, bit: u8) -> Vec<u8> {
    let mut out = bytes.to_vec();
    out[index] ^= 1 << bit;
    out
}

/// A spread of byte positions covering the start, middle and end of `len`.
pub fn positions(len: usize) -> Vec<usize> {
    let mut v = vec![0, 1, len / 3, len / 2, (2 * len) / 3, len - 2, len - 1];
    v.sort_unstable();
    v.dedup();
    v
}
