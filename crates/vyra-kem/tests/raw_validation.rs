//! S1 for the raw-bytes `Kem` methods: empty, len-1 and len+1 inputs are
//! rejected with `InvalidLength`, for every component and every hybrid suite.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use vyra_core::{DeterministicEntropy, Error, Kem};
use vyra_kem::{HybridKem, KemSuite};

fn all_kems() -> Vec<Box<dyn Kem>> {
    let mut v = common::components();
    for suite in KemSuite::all() {
        v.push(Box::new(HybridKem::new(suite)));
    }
    v
}

fn bad_lengths(len: usize) -> [usize; 3] {
    [0, len - 1, len + 1]
}

fn is_len_err<T>(r: &vyra_core::Result<T>) -> bool {
    matches!(r, Err(Error::InvalidLength { .. }))
}

#[test]
fn s1_raw_methods_reject_bad_lengths() {
    let mut rng = DeterministicEntropy::from_seed(b"raw-validation");
    for kem in all_kems() {
        let name = kem.name();
        let (pk, sk) = kem.generate_keypair(&mut rng).unwrap();
        assert_eq!(pk.len(), kem.public_key_len(), "{name}");
        assert_eq!(sk.len(), kem.secret_key_len(), "{name}");
        let (ct, ss) = kem.encapsulate(&pk, &mut rng).unwrap();
        assert_eq!(ct.len(), kem.ciphertext_len(), "{name}");
        assert_eq!(ss.len(), kem.shared_secret_len(), "{name}");

        for len in bad_lengths(pk.len()) {
            let r = kem.encapsulate(&vec![0u8; len], &mut rng);
            assert!(is_len_err(&r), "{name} encapsulate pk len {len}");
        }
        for len in bad_lengths(sk.len()) {
            let r = kem.decapsulate(&vec![0u8; len], &ct);
            assert!(is_len_err(&r), "{name} decapsulate sk len {len}");
        }
        for len in bad_lengths(ct.len()) {
            let r = kem.decapsulate(sk.expose(), &vec![0u8; len]);
            assert!(is_len_err(&r), "{name} decapsulate ct len {len}");
        }
        // Both wrong.
        assert!(is_len_err(&kem.decapsulate(&[], &[])), "{name}");
    }
}

#[test]
fn all_zero_inputs_of_correct_length_do_not_panic() {
    let mut rng = DeterministicEntropy::from_seed(b"zeros");
    for kem in all_kems() {
        let pk = vec![0u8; kem.public_key_len()];
        let sk = vec![0u8; kem.secret_key_len()];
        let ct = vec![0u8; kem.ciphertext_len()];
        // Implicit rejection: well-formed input never errors in decapsulation.
        assert!(kem.decapsulate(&sk, &ct).is_ok(), "{}", kem.name());
        // An all-zero ML-KEM key passes the modulus check; HQC has no check.
        let _ = kem.encapsulate(&pk, &mut rng);
    }
}

#[test]
fn entropy_failure_is_reported() {
    struct Failing;
    impl vyra_core::EntropySource for Failing {
        fn fill(&mut self, _dest: &mut [u8]) -> vyra_core::Result<()> {
            Err(Error::EntropyFailure)
        }
    }
    let mut ok = DeterministicEntropy::from_seed(b"ok");
    for kem in all_kems() {
        assert_eq!(
            kem.generate_keypair(&mut Failing).map(drop),
            Err(Error::EntropyFailure),
            "{} keygen",
            kem.name()
        );
        let (pk, _) = kem.generate_keypair(&mut ok).unwrap();
        assert_eq!(
            kem.encapsulate(&pk, &mut Failing).map(drop),
            Err(Error::EntropyFailure),
            "{} encaps",
            kem.name()
        );
    }
}
