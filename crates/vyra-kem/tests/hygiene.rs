//! S9 (secret hygiene) and determinism.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use common::to_hex;
use vyra_core::{DeterministicEntropy, Kem, OsEntropy, SecretBytes};
use vyra_kem::{HybridKem, HybridSecretKey, KemSuite};
use zeroize::ZeroizeOnDrop;

/// Compile-time check of the `ZeroizeOnDrop` marker only. It cannot fail at
/// run time and does not show that memory is wiped: drop-zeroization is
/// verified by code inspection (`HybridSecretKey` holds a `vyra_core::SecretBytes`,
/// whose `Drop` zeroizes its buffer), not by this test.
fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

#[test]
fn s9_secret_key_debug_is_redacted() {
    assert_zeroize_on_drop::<HybridSecretKey>();
    assert_zeroize_on_drop::<SecretBytes>();
    let mut rng = OsEntropy::new();
    for suite in KemSuite::all() {
        let kem = HybridKem::new(suite);
        let (pk, sk) = kem.generate(&mut rng).unwrap();
        let shown = format!("{sk:?}");
        assert_eq!(
            shown,
            format!("HybridSecretKey {{ suite: {suite:?}, bytes: [REDACTED] }}")
        );
        let pretty = format!("{sk:#?}");
        assert!(pretty.contains("[REDACTED]"));
        // No prefix of the secret appears in hex or as a decimal list.
        let prefix = &sk.expose_raw()[..8];
        assert!(!pretty.contains(&to_hex(prefix)));
        let decimal = format!("{prefix:?}");
        assert!(!pretty.contains(decimal.trim_matches(['[', ']'])));

        let wire = sk.to_bytes();
        assert_eq!(format!("{wire:?}"), "[REDACTED]");

        let (_, key) = kem.encapsulate_to(&pk, &mut rng).unwrap();
        assert_eq!(format!("{key:?}"), "[REDACTED]");

        // Public objects show suite and length only.
        assert!(format!("{pk:?}").starts_with("HybridPublicKey { suite:"));
    }
}

/// Everything one deterministic run produces, hex encoded.
fn run(suite: KemSuite, seed: &[u8]) -> [String; 4] {
    let kem = HybridKem::new(suite);
    let mut rng = DeterministicEntropy::from_seed(seed);
    let (pk, sk) = kem.generate_keypair(&mut rng).unwrap();
    let (ct, ss) = kem.encapsulate(&pk, &mut rng).unwrap();
    let ss2 = kem.decapsulate(sk.expose(), &ct).unwrap();
    assert!(ss.ct_eq(&ss2));
    [
        to_hex(&pk),
        to_hex(sk.expose()),
        to_hex(&ct),
        to_hex(ss.expose()),
    ]
}

#[test]
fn determinism_same_seed_same_bytes() {
    for suite in KemSuite::all() {
        let a = run(suite, b"seed-A");
        let b = run(suite, b"seed-A");
        assert_eq!(a, b, "{suite}");
        let c = run(suite, b"seed-B");
        for (x, y) in a.iter().zip(c.iter()) {
            assert_ne!(x, y, "{suite}");
        }
    }
}

#[test]
fn determinism_components() {
    for kem in common::components() {
        let mut r1 = DeterministicEntropy::from_seed(b"c");
        let mut r2 = DeterministicEntropy::from_seed(b"c");
        let (pk1, sk1) = kem.generate_keypair(&mut r1).unwrap();
        let (pk2, sk2) = kem.generate_keypair(&mut r2).unwrap();
        assert_eq!(pk1, pk2, "{}", kem.name());
        assert!(sk1.ct_eq(&sk2), "{}", kem.name());
        let (ct1, k1) = kem.encapsulate(&pk1, &mut r1).unwrap();
        let (ct2, k2) = kem.encapsulate(&pk2, &mut r2).unwrap();
        assert_eq!(ct1, ct2, "{}", kem.name());
        assert!(k1.ct_eq(&k2), "{}", kem.name());
    }
}
