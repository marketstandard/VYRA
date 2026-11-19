//! S10: arbitrary bytes into every decoder and every raw `Kem` method never
//! panic. Arbitrary-length inputs are cheap (rejected by length), so they run
//! the default case count; exact-length inputs run the full component
//! algorithms and use fewer cases.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use proptest::prelude::*;
use vyra_core::{DeterministicEntropy, Error, Kem};
use vyra_kem::{HybridCiphertext, HybridKem, HybridPublicKey, HybridSecretKey, KemSuite};

fn any_suite() -> impl Strategy<Value = KemSuite> {
    prop::sample::select(KemSuite::all().to_vec())
}

fn any_kem_index() -> impl Strategy<Value = usize> {
    0usize..9
}

/// Components 0..6, then the three hybrid suites.
fn kem_at(i: usize) -> Box<dyn Kem> {
    let mut v = common::components();
    for suite in KemSuite::all() {
        v.push(Box::new(HybridKem::new(suite)));
    }
    v.swap_remove(i % 9)
}

/// A wire header for `ty` and `suite` followed by `payload`.
fn framed(ty: u8, suite: u8, payload: &[u8]) -> Vec<u8> {
    let mut v = b"VYRA\x01".to_vec();
    v.push(ty);
    v.push(suite);
    v.extend_from_slice(payload);
    v
}

proptest! {
    #[test]
    fn s10_decoders_arbitrary_bytes(bytes in prop::collection::vec(any::<u8>(), 0..2048)) {
        let _ = HybridPublicKey::from_bytes(&bytes);
        let _ = HybridSecretKey::from_bytes(&bytes);
        let _ = HybridCiphertext::from_bytes(&bytes);
    }

    #[test]
    fn s10_decoders_valid_header_arbitrary_payload(
        ty in 0u8..8,
        suite in any::<u8>(),
        payload in prop::collection::vec(any::<u8>(), 0..64),
    ) {
        let bytes = framed(ty, suite, &payload);
        prop_assert!(HybridPublicKey::from_bytes(&bytes).is_err());
        prop_assert!(HybridSecretKey::from_bytes(&bytes).is_err());
        prop_assert!(HybridCiphertext::from_bytes(&bytes).is_err());
    }

    #[test]
    fn s10_raw_methods_arbitrary_lengths(
        i in any_kem_index(),
        a in prop::collection::vec(any::<u8>(), 0..512),
        b in prop::collection::vec(any::<u8>(), 0..512),
    ) {
        let kem = kem_at(i);
        let mut rng = DeterministicEntropy::from_seed(&a);
        // Lengths below 512 are wrong for every scheme, so all must be Err.
        prop_assert!(kem.encapsulate(&a, &mut rng).is_err());
        prop_assert!(kem.decapsulate(&a, &b).is_err());
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    #[test]
    fn s10_decoders_exact_length_arbitrary_content(suite in any_suite(), seed in any::<u64>()) {
        let mut rng = DeterministicEntropy::from_seed(&seed.to_le_bytes());
        let mut fill = |n: usize| {
            let mut v = vec![0u8; n];
            vyra_core::EntropySource::fill(&mut rng, &mut v).unwrap();
            v
        };
        let pk = fill(suite.public_key_len());
        let sk = fill(suite.secret_key_len());
        let ct = fill(suite.ciphertext_len());
        // Random public keys may fail the component checks (ML-KEM modulus,
        // HQC padding: added in U2-R1); that must be InvalidEncoding, not a panic.
        let r = HybridPublicKey::from_bytes(&framed(1, suite.id(), &pk));
        prop_assert!(matches!(r, Ok(_) | Err(Error::InvalidEncoding(_))), "{:?}", r.err());
        // Every seed of the right length is a valid secret key (U2-R2): its
        // correctly checked wire form parses; arbitrary bytes in place of the
        // 16-byte check value are rejected (U2-R2 option A).
        let typed = HybridSecretKey::from_raw(suite, &sk).unwrap();
        let wire = typed.to_bytes();
        prop_assert!(HybridSecretKey::from_bytes(wire.expose()).is_ok());
        let mut forged = sk.clone();
        forged.extend_from_slice(&fill(16));
        prop_assert_eq!(
            HybridSecretKey::from_bytes(&framed(2, suite.id(), &forged)).map(drop),
            Err(Error::InvalidEncoding("secret key check value mismatch"))
        );
        prop_assert!(HybridCiphertext::from_bytes(&framed(3, suite.id(), &ct)).is_ok());
    }

    #[test]
    fn s10_raw_methods_exact_length_arbitrary_content(i in any_kem_index(), seed in any::<u64>()) {
        let kem = kem_at(i);
        let mut rng = DeterministicEntropy::from_seed(&seed.to_le_bytes());
        let mut fill = |n: usize| {
            let mut v = vec![0u8; n];
            vyra_core::EntropySource::fill(&mut rng, &mut v).unwrap();
            v
        };
        let pk = fill(kem.public_key_len());
        let sk = fill(kem.secret_key_len());
        let ct = fill(kem.ciphertext_len());
        let mut rng2 = DeterministicEntropy::from_seed(b"encaps");
        // ML-KEM may reject a random key (modulus check); that is an Err, not a panic.
        if let Ok((c, k)) = kem.encapsulate(&pk, &mut rng2) {
            prop_assert_eq!(c.len(), kem.ciphertext_len());
            prop_assert_eq!(k.len(), kem.shared_secret_len());
        }
        // Implicit rejection: well-formed input always decapsulates. Since
        // U2-R2 every secret key is a seed, so this holds for hybrids too.
        let k = kem.decapsulate(&sk, &ct);
        prop_assert!(k.is_ok(), "{}", kem.name());
    }
}
