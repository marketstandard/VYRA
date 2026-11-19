//! T-4: sources that fail after N bytes, N swept across the range each
//! operation needs. No operation may return `Ok` having received fewer bytes
//! than it requires.
//!
//! Required bytes: composite `generate` 64 (ML-DSA seed 32 + Ed25519 seed 32);
//! composite `sign` 32 (ML-DSA `rnd`; Ed25519 is deterministic); ML-DSA
//! keygen 32, sign 32; Ed25519 keygen 32, sign 0. Dual-PQ suites and SLH-DSA:
//! see the section at the end.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use common::{Fixed, SUITES};
use vyra_core::{DeterministicEntropy, Error, SignatureScheme};
use vyra_sig::{CompositeSignature, Ed25519, MlDsa44, MlDsa65, MlDsa87};

fn stream(n: usize) -> Fixed {
    let mut bytes = vec![0u8; n];
    vyra_core::EntropySource::fill(&mut DeterministicEntropy::from_seed(b"sweep"), &mut bytes)
        .unwrap();
    Fixed::new(&bytes)
}

fn sweep_keygen(scheme: &dyn SignatureScheme, required: usize) {
    for n in 0..=required + 8 {
        let res = scheme.generate_keypair(&mut stream(n));
        if n < required {
            assert_eq!(
                res.map(|_| ()),
                Err(Error::EntropyFailure),
                "{} n={n}",
                scheme.name()
            );
        } else {
            assert!(res.is_ok(), "{} n={n}", scheme.name());
        }
    }
}

fn sweep_sign(scheme: &dyn SignatureScheme, required: usize) {
    let (pk, sk) = scheme
        .generate_keypair(&mut DeterministicEntropy::from_seed(b"k"))
        .unwrap();
    for n in 0..=required + 8 {
        let res = scheme.sign(sk.expose(), b"m", &mut stream(n));
        if n < required {
            assert_eq!(res, Err(Error::EntropyFailure), "{} n={n}", scheme.name());
        } else {
            let sig = res.unwrap();
            scheme.verify(&pk, b"m", &sig).unwrap();
        }
    }
}

#[test]
fn composite_entropy_sweep() {
    for suite in SUITES {
        let scheme = CompositeSignature::new(suite);
        sweep_keygen(&scheme, 64);
        sweep_sign(&scheme, 32);

        // Typed API too.
        for n in 0..64 {
            assert_eq!(
                scheme.generate(&mut stream(n)).map(|_| ()),
                Err(Error::EntropyFailure)
            );
        }
        let (_, sk) = scheme.generate(&mut stream(64)).unwrap();
        for n in 0..32 {
            assert_eq!(
                scheme.sign(&sk, b"m", b"c", &mut stream(n)).map(|_| ()),
                Err(Error::EntropyFailure)
            );
        }
        scheme.sign(&sk, b"m", b"c", &mut stream(32)).unwrap();
    }
}

#[test]
fn component_entropy_sweep() {
    let mldsa: [&dyn SignatureScheme; 3] = [&MlDsa44, &MlDsa65, &MlDsa87];
    for scheme in mldsa {
        sweep_keygen(scheme, 32);
        sweep_sign(scheme, 32);
    }
    sweep_keygen(&Ed25519, 32);
    sweep_sign(&Ed25519, 0);
}

// ---------------------------------------------------------------------------
// Dual post-quantum suites. Required bytes: composite `generate` 32 + 3n
// (ML-DSA seed, then SLH-DSA SK.seed ‖ SK.prf ‖ PK.seed): 80 / 104 / 128;
// composite `sign` 32 + n (ML-DSA rnd, then SLH-DSA addrnd): 48 / 56 / 64.
// SLH-DSA keygen 3n, sign n.
//
// Key generation is swept over every n in 0..=required+8. Signing is swept
// over every n in 0..required (all must fail; each attempt costs one SLH-DSA
// key derivation) and then checked at n = required and required + 8 only,
// because each successful SLH-DSA "s" signature takes about 1-3 s.
// ---------------------------------------------------------------------------

fn sweep_sign_pq(scheme: &dyn SignatureScheme, required: usize) {
    let (pk, sk) = scheme
        .generate_keypair(&mut DeterministicEntropy::from_seed(b"k"))
        .unwrap();
    for n in 0..required {
        assert_eq!(
            scheme.sign(sk.expose(), b"m", &mut stream(n)),
            Err(Error::EntropyFailure),
            "{} n={n}",
            scheme.name()
        );
    }
    for n in [required, required + 8] {
        let sig = scheme.sign(sk.expose(), b"m", &mut stream(n)).unwrap();
        scheme.verify(&pk, b"m", &sig).unwrap();
    }
}

fn pq_sweep(suite: vyra_sig::SigSuite, keygen: usize, sign: usize) {
    assert_eq!(keygen, 32 + suite.second_secret_key_len());
    let scheme = CompositeSignature::new(suite);
    sweep_keygen(&scheme, keygen);
    sweep_sign_pq(&scheme, sign);
    // Typed API at the boundary.
    assert_eq!(
        scheme.generate(&mut stream(keygen - 1)).map(|_| ()),
        Err(Error::EntropyFailure)
    );
    let (_, sk) = scheme.generate(&mut stream(keygen)).unwrap();
    assert_eq!(
        scheme
            .sign(&sk, b"m", b"c", &mut stream(sign - 1))
            .map(|_| ()),
        Err(Error::EntropyFailure)
    );
}

#[test]
fn composite_entropy_sweep_pq1() {
    pq_sweep(vyra_sig::SigSuite::Pq1, 80, 48);
}

#[test]
fn composite_entropy_sweep_pq3() {
    pq_sweep(vyra_sig::SigSuite::Pq3, 104, 56);
}

#[test]
fn composite_entropy_sweep_pq5() {
    pq_sweep(vyra_sig::SigSuite::Pq5, 128, 64);
}

#[test]
fn slhdsa_component_entropy_sweep() {
    let slh: [(&dyn SignatureScheme, usize); 3] = [
        (&vyra_sig::SlhDsaShake128s, 16),
        (&vyra_sig::SlhDsaShake192s, 24),
        (&vyra_sig::SlhDsaShake256s, 32),
    ];
    for (scheme, n) in slh {
        sweep_keygen(scheme, 3 * n);
        let (pk, sk) = scheme
            .generate_keypair(&mut DeterministicEntropy::from_seed(b"k"))
            .unwrap();
        for m in 0..n {
            assert_eq!(
                scheme.sign(sk.expose(), b"m", &mut stream(m)),
                Err(Error::EntropyFailure),
                "{} m={m}",
                scheme.name()
            );
        }
        // One successful signature per set at exactly n bytes.
        let sig = scheme.sign(sk.expose(), b"m", &mut stream(n)).unwrap();
        scheme.verify(&pk, b"m", &sig).unwrap();
    }
}
