//! F7 composite round trips, determinism and entropy-failure behaviour.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use common::{Failing, SUITES};
use vyra_core::{DeterministicEntropy, Error, OsEntropy, SignatureScheme};
use vyra_sig::{CompositeSignature, SigSuite};

const KEYPAIRS_PER_SUITE: usize = 50;

fn cases() -> Vec<(Vec<u8>, Vec<u8>)> {
    let large: Vec<u8> = (0..64 * 1024).map(|i| (i % 251) as u8).collect();
    vec![
        (Vec::new(), Vec::new()),
        (Vec::new(), b"non-empty context".to_vec()),
        (large.clone(), Vec::new()),
        (large, vec![0xA5; 255]),
        (b"short message".to_vec(), b"ctx".to_vec()),
    ]
}

#[test]
fn f7_round_trip_fresh_keypairs_all_suites() {
    let cases = cases();
    let mut rng = OsEntropy::new();
    for suite in SUITES {
        let scheme = CompositeSignature::new(suite);
        for i in 0..KEYPAIRS_PER_SUITE {
            let (pk, sk) = scheme.generate(&mut rng).unwrap();
            assert_eq!(pk.suite(), suite);
            assert_eq!(pk.as_raw().len(), suite.public_key_len());
            assert_eq!(sk.expose_raw().len(), suite.secret_key_len());
            // Each key pair signs one case; all cases are covered many times.
            let (msg, ctx) = &cases[i % cases.len()];
            let sig = scheme.sign(&sk, msg, ctx, &mut rng).unwrap();
            assert_eq!(sig.as_raw().len(), suite.signature_len());
            scheme.verify(&pk, msg, ctx, &sig).unwrap();
        }
    }
}

#[test]
fn f7_every_case_on_one_key_per_suite() {
    let mut rng = OsEntropy::new();
    for suite in SUITES {
        let scheme = CompositeSignature::new(suite);
        let (pk, sk) = scheme.generate(&mut rng).unwrap();
        for (msg, ctx) in cases() {
            let sig = scheme.sign(&sk, &msg, &ctx, &mut rng).unwrap();
            scheme.verify(&pk, &msg, &ctx, &sig).unwrap();
        }
    }
}

#[test]
fn trait_interface_round_trip_with_empty_context() {
    let mut rng = OsEntropy::new();
    for suite in SUITES {
        let scheme = CompositeSignature::new(suite);
        let dyn_scheme: &dyn SignatureScheme = &scheme;
        assert_eq!(dyn_scheme.name(), suite.name());
        assert_eq!(dyn_scheme.level(), suite.level());
        let (pk, sk) = dyn_scheme.generate_keypair(&mut rng).unwrap();
        let sig = dyn_scheme.sign(sk.expose(), b"m", &mut rng).unwrap();
        dyn_scheme.verify(&pk, b"m", &sig).unwrap();
        // The trait uses the empty context: identical to the typed API with ctx = "".
        scheme.verify_raw(&pk, b"m", b"", &sig).unwrap();
        assert_eq!(
            scheme.verify_raw(&pk, b"m", b"x", &sig),
            Err(Error::VerificationFailed)
        );
    }
}

#[test]
fn keygen_is_reproducible_under_deterministic_entropy() {
    for suite in SUITES {
        let scheme = CompositeSignature::new(suite);
        let (pk1, sk1) = scheme
            .generate(&mut DeterministicEntropy::from_seed(b"keygen"))
            .unwrap();
        let (pk2, sk2) = scheme
            .generate(&mut DeterministicEntropy::from_seed(b"keygen"))
            .unwrap();
        let (pk3, _) = scheme
            .generate(&mut DeterministicEntropy::from_seed(b"other"))
            .unwrap();
        assert_eq!(pk1, pk2);
        assert!(sk1.ct_eq(&sk2));
        assert_ne!(pk1, pk3);

        // Key generation consumes the ML-DSA seed, then the Ed25519 seed.
        let mut stream = [0u8; 64];
        vyra_core::EntropySource::fill(
            &mut DeterministicEntropy::from_seed(b"keygen"),
            &mut stream,
        )
        .unwrap();
        assert_eq!(sk1.expose_raw(), &stream[..]);
    }
}

#[test]
fn signing_is_reproducible_under_deterministic_entropy() {
    for suite in SUITES {
        let scheme = CompositeSignature::new(suite);
        let (_, sk) = scheme
            .generate(&mut DeterministicEntropy::from_seed(b"k"))
            .unwrap();
        let a = scheme
            .sign(&sk, b"m", b"c", &mut DeterministicEntropy::from_seed(b"s"))
            .unwrap();
        let b = scheme
            .sign(&sk, b"m", b"c", &mut DeterministicEntropy::from_seed(b"s"))
            .unwrap();
        assert_eq!(a, b);
    }
}

#[test]
fn ed25519_half_is_deterministic_mldsa_half_is_hedged() {
    let mut rng = OsEntropy::new();
    for suite in SUITES {
        let scheme = CompositeSignature::new(suite);
        let (pk, sk) = scheme.generate(&mut rng).unwrap();
        let a = scheme.sign(&sk, b"m", b"c", &mut rng).unwrap();
        let b = scheme
            .sign(&sk, b"m", b"c", &mut DeterministicEntropy::from_seed(b"x"))
            .unwrap();
        assert_eq!(a.ed25519_part().unwrap(), b.ed25519_part().unwrap());
        assert_ne!(
            a.mldsa_part(),
            b.mldsa_part(),
            "ML-DSA signing must be hedged"
        );
        scheme.verify(&pk, b"m", b"c", &a).unwrap();
        scheme.verify(&pk, b"m", b"c", &b).unwrap();
    }
}

#[test]
fn entropy_failure_is_reported() {
    let mut rng = OsEntropy::new();
    for suite in SUITES {
        let scheme = CompositeSignature::new(suite);
        assert_eq!(
            scheme.generate(&mut Failing).map(|_| ()),
            Err(Error::EntropyFailure)
        );
        let (_, sk) = scheme.generate(&mut rng).unwrap();
        assert_eq!(
            scheme.sign(&sk, b"m", b"", &mut Failing).map(|_| ()),
            Err(Error::EntropyFailure)
        );
    }
}

#[test]
fn context_limit_applies_to_sign_and_verify() {
    let mut rng = OsEntropy::new();
    let scheme = CompositeSignature::new(SigSuite::Vyra2);
    let (pk, sk) = scheme.generate(&mut rng).unwrap();
    let sig = scheme.sign(&sk, b"m", &[7u8; 255], &mut rng).unwrap();
    scheme.verify(&pk, b"m", &[7u8; 255], &sig).unwrap();
    let too_long = [7u8; 256];
    assert!(matches!(
        scheme.sign(&sk, b"m", &too_long, &mut rng),
        Err(Error::InvalidLength { actual: 256, .. })
    ));
    assert!(matches!(
        scheme.verify(&pk, b"m", &too_long, &sig),
        Err(Error::InvalidLength { actual: 256, .. })
    ));
}

// ---------------------------------------------------------------------------
// Dual post-quantum suites (ML-DSA + SLH-DSA).
//
// SLH-DSA "s" signing costs about 1–3 s per signature even with optimised
// dependencies, so these tests use 2 fresh key pairs per suite (instead of
// 50) plus one key that signs every case, and run one test per suite so the
// harness parallelises them. Per suite: 2 + 5 + 1 = 8 signatures here and 3
// in the determinism test.
// ---------------------------------------------------------------------------

const PQ_KEYPAIRS_PER_SUITE: usize = 2;

fn pq_round_trip(suite: SigSuite) {
    assert!(suite.is_dual_pq());
    let cases = cases();
    let mut rng = OsEntropy::new();
    let scheme = CompositeSignature::new(suite);
    for (i, (msg, ctx)) in cases.iter().enumerate().take(PQ_KEYPAIRS_PER_SUITE) {
        let (pk, sk) = scheme.generate(&mut rng).unwrap();
        assert_eq!(pk.suite(), suite);
        assert_eq!(pk.as_raw().len(), suite.public_key_len());
        assert_eq!(sk.expose_raw().len(), suite.secret_key_len());
        let sig = scheme.sign(&sk, msg, ctx, &mut rng).unwrap();
        assert_eq!(sig.as_raw().len(), suite.signature_len(), "case {i}");
        scheme.verify(&pk, msg, ctx, &sig).unwrap();
    }
    // Every case (empty/non-empty/255-byte context, empty/64 KiB message) on one key.
    let (pk, sk) = scheme.generate(&mut rng).unwrap();
    for (msg, ctx) in &cases {
        let sig = scheme.sign(&sk, msg, ctx, &mut rng).unwrap();
        scheme.verify(&pk, msg, ctx, &sig).unwrap();
    }
    // Raw trait interface: empty context.
    let dyn_scheme: &dyn SignatureScheme = &scheme;
    assert_eq!(dyn_scheme.name(), suite.name());
    assert_eq!(dyn_scheme.level(), suite.level());
    let sig = dyn_scheme.sign(sk.expose_raw(), b"m", &mut rng).unwrap();
    dyn_scheme.verify(pk.as_raw(), b"m", &sig).unwrap();
    scheme.verify_raw(pk.as_raw(), b"m", b"", &sig).unwrap();
    assert_eq!(
        scheme.verify_raw(pk.as_raw(), b"m", b"x", &sig),
        Err(Error::VerificationFailed)
    );
}

#[test]
fn f7_round_trip_pq1() {
    pq_round_trip(SigSuite::Pq1);
}

#[test]
fn f7_round_trip_pq3() {
    pq_round_trip(SigSuite::Pq3);
}

#[test]
fn f7_round_trip_pq5() {
    pq_round_trip(SigSuite::Pq5);
}

/// Determinism under `DeterministicEntropy`; both halves are hedged.
fn pq_determinism(suite: SigSuite) {
    let scheme = CompositeSignature::new(suite);
    let (pk1, sk1) = scheme
        .generate(&mut DeterministicEntropy::from_seed(b"keygen"))
        .unwrap();
    let (pk2, sk2) = scheme
        .generate(&mut DeterministicEntropy::from_seed(b"keygen"))
        .unwrap();
    let (pk3, _) = scheme
        .generate(&mut DeterministicEntropy::from_seed(b"other"))
        .unwrap();
    assert_eq!(pk1, pk2);
    assert!(sk1.ct_eq(&sk2));
    assert_ne!(pk1, pk3);
    // Key generation consumes the ML-DSA seed (32), then the SLH-DSA seeds (3n).
    let mut stream = vec![0u8; suite.secret_key_len()];
    vyra_core::EntropySource::fill(&mut DeterministicEntropy::from_seed(b"keygen"), &mut stream)
        .unwrap();
    assert_eq!(sk1.expose_raw(), &stream[..]);
    assert_eq!(suite.secret_key_len(), 32 + suite.second_secret_key_len());

    let a = scheme
        .sign(&sk1, b"m", b"c", &mut DeterministicEntropy::from_seed(b"s"))
        .unwrap();
    let b = scheme
        .sign(&sk1, b"m", b"c", &mut DeterministicEntropy::from_seed(b"s"))
        .unwrap();
    assert_eq!(a, b);
    let c = scheme
        .sign(&sk1, b"m", b"c", &mut DeterministicEntropy::from_seed(b"t"))
        .unwrap();
    assert_ne!(
        a.mldsa_part(),
        c.mldsa_part(),
        "ML-DSA signing must be hedged"
    );
    assert_ne!(
        a.slhdsa_part().unwrap(),
        c.slhdsa_part().unwrap(),
        "SLH-DSA signing must be hedged"
    );
    for sig in [&a, &c] {
        scheme.verify(&pk1, b"m", b"c", sig).unwrap();
    }
}

#[test]
fn determinism_pq1() {
    pq_determinism(SigSuite::Pq1);
}

#[test]
fn determinism_pq3() {
    pq_determinism(SigSuite::Pq3);
}

#[test]
fn determinism_pq5() {
    pq_determinism(SigSuite::Pq5);
}

#[test]
fn pq_entropy_failure_and_context_limit() {
    for suite in common::PQ_SUITES {
        let scheme = CompositeSignature::new(suite);
        assert_eq!(
            scheme.generate(&mut Failing).map(|_| ()),
            Err(Error::EntropyFailure)
        );
        let (pk, sk) = scheme
            .generate(&mut DeterministicEntropy::from_seed(b"k"))
            .unwrap();
        assert_eq!(
            scheme.sign(&sk, b"m", b"", &mut Failing).map(|_| ()),
            Err(Error::EntropyFailure)
        );
        // Enough for ML-DSA's rnd but not for SLH-DSA's addrnd.
        assert_eq!(
            scheme
                .sign(&sk, b"m", b"", &mut common::Fixed::new(&[1u8; 32]))
                .map(|_| ()),
            Err(Error::EntropyFailure)
        );
        let too_long = [7u8; 256];
        assert!(matches!(
            scheme.sign(&sk, b"m", &too_long, &mut OsEntropy::new()),
            Err(Error::InvalidLength { actual: 256, .. })
        ));
        let sig =
            vyra_sig::CompositeSig::from_raw(suite, &vec![0u8; suite.signature_len()]).unwrap();
        assert!(matches!(
            scheme.verify(&pk, b"m", &too_long, &sig),
            Err(Error::InvalidLength { actual: 256, .. })
        ));
    }
}
