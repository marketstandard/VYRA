//! T-4: an entropy source that fails after N bytes. For every N from 0 up
//! past the bytes an operation needs, the operation returns `Ok` exactly when
//! N covers its requirement, and `EntropyFailure` otherwise. This includes
//! the values straddling the ML-KEM/HQC boundary inside a hybrid operation.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use vyra_core::{DeterministicEntropy, EntropySource, Error, Kem, Result};
use vyra_kem::{HybridKem, KemSuite};

/// Serves `budget` bytes from a deterministic stream, then fails. A request
/// that does not fit fails as a whole (after a partial fill).
struct Budget {
    inner: DeterministicEntropy,
    budget: usize,
    used: usize,
}

impl Budget {
    fn new(budget: usize) -> Self {
        Budget {
            inner: DeterministicEntropy::from_seed(b"budget"),
            budget,
            used: 0,
        }
    }
}

impl EntropySource for Budget {
    fn fill(&mut self, dest: &mut [u8]) -> Result<()> {
        let left = self.budget.saturating_sub(self.used);
        if dest.len() > left {
            if let Some(part) = dest.get_mut(..left) {
                self.inner.fill(part)?;
            }
            self.used = self.budget;
            return Err(Error::EntropyFailure);
        }
        self.used += dest.len();
        self.inner.fill(dest)
    }
}

/// Bytes drawn by keygen and encapsulation: (ML-KEM, HQC) for each suite.
/// ML-KEM keygen 64 (d, z), encaps 32 (m); HQC keygen 32 (seed_kem),
/// encaps k + 16 (m, salt) with k = 16/24/32.
fn needs(suite: KemSuite) -> ((usize, usize), (usize, usize)) {
    match suite {
        KemSuite::Vyra1 => ((64, 32), (32, 32)),
        KemSuite::Vyra3 => ((64, 32), (32, 40)),
        KemSuite::Vyra5 => ((64, 32), (32, 48)),
    }
}

#[test]
fn t4_generate_and_encapsulate_need_all_their_bytes() {
    for suite in KemSuite::all() {
        let kem = HybridKem::new(suite);
        let ((kg1, kg2), (en1, en2)) = needs(suite);
        let keygen_need = kg1 + kg2;
        let encaps_need = en1 + en2;

        // The exact counts are what the operations really draw.
        let mut counter = Budget::new(usize::MAX);
        let (pk, _) = kem.generate_keypair(&mut counter).unwrap();
        assert_eq!(counter.used, keygen_need, "{suite} keygen draw");
        let mut counter = Budget::new(usize::MAX);
        kem.encapsulate(&pk, &mut counter).unwrap();
        assert_eq!(counter.used, encaps_need, "{suite} encaps draw");

        for n in 0..=keygen_need + 2 {
            let r = kem.generate_keypair(&mut Budget::new(n)).map(drop);
            if n >= keygen_need {
                assert_eq!(r, Ok(()), "{suite} keygen with {n}");
            } else {
                assert_eq!(r, Err(Error::EntropyFailure), "{suite} keygen with {n}");
            }
        }
        for n in 0..=encaps_need + 2 {
            let r = kem.encapsulate(&pk, &mut Budget::new(n)).map(drop);
            if n >= encaps_need {
                assert_eq!(r, Ok(()), "{suite} encaps with {n}");
            } else {
                assert_eq!(r, Err(Error::EntropyFailure), "{suite} encaps with {n}");
            }
        }
    }
}

#[test]
fn t4_components_need_all_their_bytes() {
    for c in common::components() {
        let mut counter = Budget::new(usize::MAX);
        let (pk, _) = c.generate_keypair(&mut counter).unwrap();
        let kg = counter.used;
        let mut counter = Budget::new(usize::MAX);
        c.encapsulate(&pk, &mut counter).unwrap();
        let en = counter.used;
        for n in 0..=kg + 1 {
            let ok = c.generate_keypair(&mut Budget::new(n)).is_ok();
            assert_eq!(ok, n >= kg, "{} keygen with {n}", c.name());
        }
        for n in 0..=en + 1 {
            let ok = c.encapsulate(&pk, &mut Budget::new(n)).is_ok();
            assert_eq!(ok, n >= en, "{} encaps with {n}", c.name());
        }
    }
}
