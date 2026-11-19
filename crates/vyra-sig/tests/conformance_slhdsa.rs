//! F4(c) SLH-DSA conformance, SLH-DSA-SHAKE-128s / -192s / -256s.
//!
//! 1. **Official vectors:** NIST ACVP-Server `SLH-DSA-{keyGen,sigGen,sigVer}-FIPS205`
//!    (tag `v1.1.0.43`), subset: the three SHAKE "s" sets, external interface,
//!    pure (no pre-hash), deterministic and hedged signing, with and without
//!    context. Exact source, hashes and subset rule: `tests/data/PROVENANCE.md`.
//!    Counts: keyGen 30 (10 per set), sigGen 42 (7 deterministic + 7 hedged
//!    per set), sigVer 42 (2 valid + 12 invalid per set).
//!    Every case is driven **through VYRA's adapter** (RULES 23: no upstream
//!    call is needed):
//!    - keyGen: the adapter's stored secret key *is* the keyGen input
//!      `SK.seed ‖ SK.prf ‖ PK.seed`, served as the adapter's entropy; the
//!      adapter's public key must equal `pk`, and the vector's 4n-byte `sk`
//!      must equal the stored seeds followed by `PK.root`.
//!    - sigGen: the vector gives the standard 4n-byte `sk`; the adapter key is
//!      its first 3n bytes (the dropped `PK.root` is recomputed by the adapter
//!      and checked against `pk`). Hedged cases serve `additionalRandomness`
//!      as the adapter's n-byte `addrnd`; deterministic cases serve `PK.seed`,
//!      because FIPS 205 Algorithm 22 defines the deterministic variant as
//!      `opt_rand ← PK.seed`, i.e. the same computation. Signatures must be
//!      byte-identical, and verify through the adapter.
//!    - sigVer: the adapter verdict (`verify_with_context`) equals `testPassed`
//!      (wrong-length signatures are an `InvalidLength` error, which counts as
//!      "not verified"); the RustCrypto `slh-dsa` verdict is checked too.
//! 2. **Differential interop** against RustCrypto `slh-dsa` 0.2.0-rc.5 (an
//!    independent implementation; both target final FIPS 205, see
//!    `src/slhdsa.rs`): same seeds → same public key; the adapter's
//!    signatures (empty and VYRA composite context) verify under `slh-dsa`;
//!    same `addrnd` → byte-identical signature: the SLH-DSA half of a dual-PQ
//!    composite equals `slh-dsa`'s signature on `M'` under the composite
//!    context, and that `slh-dsa` signature verifies under the adapter (so
//!    signatures cross-verify in both directions). One `slh-dsa` key
//!    generation and one `slh-dsa` signature per set: see `differential`.
//!
//! Each parameter set runs as its own test so the harness can run them in
//! parallel (SLH-DSA "s" signing is slow).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

mod common;

use std::collections::BTreeMap;
use std::io::Read;

use common::Fixed;
use slh_dsa::signature::Keypair;
use vyra_core::{DeterministicEntropy, EntropySource, Error, SignatureScheme};
use vyra_sig::{
    CompositeSignature, ContextSignatureScheme, SigSuite, SlhDsaShake128s, SlhDsaShake192s,
    SlhDsaShake256s, composite_context, message_representative,
};

const KEY_GEN_GZ: &[u8] = include_bytes!("data/SLH-DSA-keyGen-FIPS205-shake-s.json.gz");
const SIG_GEN_GZ: &[u8] =
    include_bytes!("data/SLH-DSA-sigGen-FIPS205-shake-s-external-pure.json.gz");
const SIG_VER_GZ: &[u8] =
    include_bytes!("data/SLH-DSA-sigVer-FIPS205-shake-s-external-pure.json.gz");

fn load(gz: &[u8], mode: &str) -> serde_json::Value {
    let mut json = String::new();
    flate2::read::GzDecoder::new(gz)
        .read_to_string(&mut json)
        .unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["algorithm"], "SLH-DSA");
    assert_eq!(v["mode"], mode);
    assert_eq!(v["revision"], "FIPS205");
    v
}

fn hex_field(v: &serde_json::Value, key: &str) -> Vec<u8> {
    hex::decode(v[key].as_str().unwrap()).unwrap()
}

/// The groups of `v` for parameter set `ps`, checking the subset rule.
fn groups<'a>(v: &'a serde_json::Value, ps: &str) -> Vec<&'a serde_json::Value> {
    let all = v["testGroups"].as_array().unwrap();
    for g in all {
        assert!(
            [
                "SLH-DSA-SHAKE-128s",
                "SLH-DSA-SHAKE-192s",
                "SLH-DSA-SHAKE-256s"
            ]
            .contains(&g["parameterSet"].as_str().unwrap()),
            "subset contains only SHAKE-s groups"
        );
        if v["mode"] != "keyGen" {
            assert_eq!(g["signatureInterface"], "external");
            assert_eq!(g["preHash"], "pure");
        }
    }
    all.iter().filter(|g| g["parameterSet"] == ps).collect()
}

fn keygen_vectors(ps: &str, adapter: &dyn SignatureScheme, n: usize) {
    let v = load(KEY_GEN_GZ, "keyGen");
    let mut count = 0;
    for g in groups(&v, ps) {
        for t in g["tests"].as_array().unwrap() {
            let id = &t["tcId"];
            let seeds = [
                hex_field(t, "skSeed"),
                hex_field(t, "skPrf"),
                hex_field(t, "pkSeed"),
            ]
            .concat();
            let (pk, sk) = (hex_field(t, "pk"), hex_field(t, "sk"));
            assert_eq!(seeds.len(), 3 * n);
            let (got_pk, got_sk) = adapter.generate_keypair(&mut Fixed::new(&seeds)).unwrap();
            assert_eq!(got_pk, pk, "{ps} tcId {id}: public key");
            assert_eq!(got_sk.expose(), &seeds[..], "{ps} tcId {id}: stored seeds");
            // The standard 4n-byte secret key is the stored seeds ‖ PK.root.
            assert_eq!(sk, [&seeds[..], &pk[n..]].concat(), "{ps} tcId {id}: sk");
            count += 1;
        }
    }
    println!("{ps} keyGen: {count} vectors");
    assert_eq!(count, 10);
}

fn siggen_vectors(ps: &str, adapter: &dyn ContextSignatureScheme, n: usize) {
    let v = load(SIG_GEN_GZ, "sigGen");
    let mut counts = BTreeMap::<bool, usize>::new();
    let mut empty_ctx = 0;
    for g in groups(&v, ps) {
        let deterministic = g["deterministic"].as_bool().unwrap();
        for t in g["tests"].as_array().unwrap() {
            let id = &t["tcId"];
            let (sk, pk, msg, ctx, expected) = (
                hex_field(t, "sk"),
                hex_field(t, "pk"),
                hex_field(t, "message"),
                hex_field(t, "context"),
                hex_field(t, "signature"),
            );
            assert_eq!(sk.len(), 4 * n);
            let stored = &sk[..3 * n];
            // The adapter derives the same public key from the 3n-byte form.
            let (derived_pk, _) = adapter.generate_keypair(&mut Fixed::new(stored)).unwrap();
            assert_eq!(derived_pk, pk, "{ps} tcId {id}: derived public key");
            assert_eq!(&sk[3 * n..], &pk[n..], "{ps} tcId {id}: PK.root");

            let addrnd = if deterministic {
                assert!(t.get("additionalRandomness").is_none());
                sk[2 * n..3 * n].to_vec() // PK.seed (FIPS 205 Algorithm 22)
            } else {
                hex_field(t, "additionalRandomness")
            };
            assert_eq!(addrnd.len(), n);
            let got = adapter
                .sign_with_context(stored, &msg, &ctx, &mut Fixed::new(&addrnd))
                .unwrap();
            assert_eq!(got, expected, "{ps} tcId {id}: signature mismatch");

            adapter
                .verify_with_context(&pk, &msg, &ctx, &expected)
                .unwrap_or_else(|e| panic!("{ps} tcId {id}: adapter rejected: {e}"));
            let mut other_ctx = ctx.clone();
            other_ctx.push(0);
            if other_ctx.len() <= 255 {
                assert_eq!(
                    adapter.verify_with_context(&pk, &msg, &other_ctx, &expected),
                    Err(Error::VerificationFailed)
                );
            }
            if ctx.is_empty() {
                empty_ctx += 1;
                adapter.verify(&pk, &msg, &expected).unwrap();
            } else {
                assert_eq!(
                    adapter.verify(&pk, &msg, &expected),
                    Err(Error::VerificationFailed)
                );
            }
            *counts.entry(deterministic).or_default() += 1;
        }
    }
    println!("{ps} sigGen: {counts:?} (deterministic -> count), {empty_ctx} with empty context");
    assert_eq!(counts.get(&true), Some(&7), "{ps} deterministic");
    assert_eq!(counts.get(&false), Some(&7), "{ps} hedged");
    assert!(
        empty_ctx > 0,
        "{ps}: both empty and non-empty contexts covered"
    );
}

fn sigver_vectors<P: slh_dsa::ParameterSet>(ps: &str, adapter: &dyn ContextSignatureScheme) {
    let v = load(SIG_VER_GZ, "sigVer");
    let mut counts = BTreeMap::<bool, usize>::new();
    for g in groups(&v, ps) {
        for t in g["tests"].as_array().unwrap() {
            let id = &t["tcId"];
            let passed = t["testPassed"].as_bool().unwrap();
            let (pk, msg, ctx, sig) = (
                hex_field(t, "pk"),
                hex_field(t, "message"),
                hex_field(t, "context"),
                hex_field(t, "signature"),
            );
            let ours = adapter.verify_with_context(&pk, &msg, &ctx, &sig).is_ok();
            assert_eq!(
                ours, passed,
                "{ps} tcId {id} ({}): adapter verdict",
                t["reason"]
            );
            let theirs = match (
                slh_dsa::VerifyingKey::<P>::try_from(pk.as_slice()),
                slh_dsa::Signature::<P>::try_from(sig.as_slice()),
            ) {
                (Ok(vk), Ok(s)) => vk.try_verify_with_context(&msg, &ctx, &s).is_ok(),
                _ => false,
            };
            assert_eq!(theirs, passed, "{ps} tcId {id}: slh-dsa verdict");
            *counts.entry(passed).or_default() += 1;
        }
    }
    println!("{ps} sigVer: {counts:?} (testPassed -> count)");
    assert_eq!(counts.get(&true), Some(&2), "{ps} valid");
    assert_eq!(counts.get(&false), Some(&12), "{ps} invalid");
}

/// Differential against RustCrypto `slh-dsa`; see the module docs.
///
/// Sized for cost: `slh-dsa` is generic over the parameter set, so in a test
/// build its code is compiled into this (unoptimised) test crate; measured
/// here at about 12 s per key generation and 100 s per signature for
/// SHAKE-128s (against 0.2 s / 1.2 s for the `fips205`-based adapter, whose
/// work runs inside the optimised dependency). Each parameter set therefore
/// makes exactly **one** `slh-dsa` key generation and **one** `slh-dsa`
/// signature; its verification is cheap and is used freely.
fn differential<P: slh_dsa::ParameterSet>(
    ours: &dyn ContextSignatureScheme,
    suite: SigSuite,
    n: usize,
) {
    let vyra_ctx = composite_context(suite.id());

    // 1. Same seeds -> same public key (the one slh-dsa key generation).
    let (pk, sk) = ours
        .generate_keypair(&mut DeterministicEntropy::from_seed(&[b'k', suite.id()]))
        .unwrap();
    let s = sk.expose();
    let theirs = slh_dsa::SigningKey::<P>::slh_keygen_internal(&s[..n], &s[n..2 * n], &s[2 * n..]);
    let their_vk = theirs.verifying_key();
    assert_eq!(pk, their_vk.to_bytes().to_vec());
    // Their standard secret key is our stored seeds followed by PK.root.
    assert_eq!(theirs.to_bytes().to_vec(), [s, &pk[n..]].concat());

    // 2. Our signatures verify under theirs, with the empty context and with
    //    the VYRA composite context; wrong message or context is rejected.
    let message: Vec<u8> = (0..300).map(|j| j as u8).collect();
    for ctx in [&[][..], &vyra_ctx[..]] {
        let sig = ours
            .sign_with_context(s, &message, ctx, &mut DeterministicEntropy::from_seed(ctx))
            .unwrap();
        let parsed = slh_dsa::Signature::<P>::try_from(sig.as_slice()).unwrap();
        their_vk
            .try_verify_with_context(&message, ctx, &parsed)
            .unwrap();
        assert!(
            their_vk
                .try_verify_with_context(b"different", ctx, &parsed)
                .is_err()
        );
        let other_ctx: &[u8] = if ctx.is_empty() { b"x" } else { &[] };
        assert!(
            their_vk
                .try_verify_with_context(&message, other_ctx, &parsed)
                .is_err()
        );
    }

    // 3. End to end with the one slh-dsa signature: the SLH-DSA half of a
    //    dual-PQ composite equals slh-dsa's signature on M' under the
    //    composite context with the same addrnd (the n bytes the composite
    //    drew after the 32-byte ML-DSA rnd); that slh-dsa signature verifies
    //    under our adapter, and not under the empty context.
    let composite = CompositeSignature::new(suite);
    let (cpk, csk) = composite
        .generate(&mut DeterministicEntropy::from_seed(b"e2e key"))
        .unwrap();
    let csig = composite
        .sign(
            &csk,
            b"end to end",
            b"app",
            &mut DeterministicEntropy::from_seed(b"e2e sign"),
        )
        .unwrap();
    let mut stream = vec![0u8; 32 + n];
    DeterministicEntropy::from_seed(b"e2e sign")
        .fill(&mut stream)
        .unwrap();
    let slh_pk = cpk.slhdsa_part().unwrap();
    // Standard 4n-byte key = stored seeds ‖ PK.root (no slh-dsa key generation).
    let standard_sk = [&csk.expose_raw()[32..], &slh_pk[n..]].concat();
    let theirs = slh_dsa::SigningKey::<P>::try_from(standard_sk.as_slice()).unwrap();
    assert_eq!(theirs.verifying_key().to_bytes().as_slice(), slh_pk);
    let m_prime = message_representative(suite, cpk.as_raw(), b"app", b"end to end").unwrap();
    let expected = theirs
        .try_sign_with_context(&m_prime, &vyra_ctx, Some(&stream[32..]))
        .unwrap()
        .to_bytes()
        .to_vec();
    assert_eq!(csig.slhdsa_part().unwrap(), expected.as_slice());
    ours.verify_with_context(slh_pk, &m_prime, &vyra_ctx, &expected)
        .unwrap();
    assert_eq!(
        ours.verify(slh_pk, &m_prime, &expected),
        Err(Error::VerificationFailed)
    );
}

macro_rules! per_set {
    ($ours:ident, $theirs:ty, $ps:literal, $n:literal, $suite:expr,
     $kg:ident, $sg:ident, $sv:ident, $diff:ident) => {
        #[test]
        fn $kg() {
            keygen_vectors($ps, &$ours, $n);
        }

        #[test]
        fn $sg() {
            siggen_vectors($ps, &$ours, $n);
        }

        #[test]
        fn $sv() {
            sigver_vectors::<$theirs>($ps, &$ours);
        }

        #[test]
        fn $diff() {
            differential::<$theirs>(&$ours, $suite, $n);
        }
    };
}

per_set!(
    SlhDsaShake128s,
    slh_dsa::Shake128s,
    "SLH-DSA-SHAKE-128s",
    16,
    SigSuite::Pq1,
    nist_acvp_keygen_shake_128s,
    nist_acvp_siggen_shake_128s,
    nist_acvp_sigver_shake_128s,
    differential_slh_dsa_shake_128s
);
per_set!(
    SlhDsaShake192s,
    slh_dsa::Shake192s,
    "SLH-DSA-SHAKE-192s",
    24,
    SigSuite::Pq3,
    nist_acvp_keygen_shake_192s,
    nist_acvp_siggen_shake_192s,
    nist_acvp_sigver_shake_192s,
    differential_slh_dsa_shake_192s
);
per_set!(
    SlhDsaShake256s,
    slh_dsa::Shake256s,
    "SLH-DSA-SHAKE-256s",
    32,
    SigSuite::Pq5,
    nist_acvp_keygen_shake_256s,
    nist_acvp_siggen_shake_256s,
    nist_acvp_sigver_shake_256s,
    differential_slh_dsa_shake_256s
);

#[test]
fn entropy_use_is_exact() {
    // Key generation: exactly 3n bytes; signing: exactly n bytes.
    let schemes: [(&dyn SignatureScheme, usize); 3] = [
        (&SlhDsaShake128s, 16),
        (&SlhDsaShake192s, 24),
        (&SlhDsaShake256s, 32),
    ];
    for (scheme, n) in schemes {
        assert_eq!(
            scheme
                .generate_keypair(&mut Fixed::new(&vec![7u8; 3 * n - 1]))
                .map(|_| ()),
            Err(Error::EntropyFailure)
        );
        let (_, sk) = scheme
            .generate_keypair(&mut Fixed::new(&vec![7u8; 3 * n]))
            .unwrap();
        assert_eq!(
            scheme.sign(sk.expose(), b"m", &mut Fixed::new(&vec![9u8; n - 1])),
            Err(Error::EntropyFailure)
        );
        // 128s only: a successful sign is slow.
        if n == 16 {
            scheme
                .sign(sk.expose(), b"m", &mut Fixed::new(&vec![9u8; n]))
                .unwrap();
        }
    }
}

#[test]
fn context_limit_and_lengths() {
    let s = SlhDsaShake128s;
    let sk = [3u8; 48];
    assert!(matches!(
        s.sign_with_context(&sk, b"m", &[0u8; 256], &mut Fixed::new(&[0u8; 16])),
        Err(Error::InvalidLength {
            what: "FIPS 205 context",
            actual: 256,
            ..
        })
    ));
    assert!(matches!(
        s.verify_with_context(&[0u8; 32], b"m", &[0u8; 256], &[0u8; 7856]),
        Err(Error::InvalidLength {
            what: "FIPS 205 context",
            ..
        })
    ));
    for len in [0, 47, 49, 64] {
        assert!(matches!(
            s.sign(&vec![0u8; len], b"m", &mut Fixed::new(&[0u8; 16])),
            Err(Error::InvalidLength {
                what: "SLH-DSA secret key",
                ..
            })
        ));
    }
    assert!(matches!(
        s.verify(&[0u8; 31], b"m", &[0u8; 7856]),
        Err(Error::InvalidLength {
            what: "SLH-DSA public key",
            ..
        })
    ));
    assert!(matches!(
        s.verify(&[0u8; 32], b"m", &[0u8; 7855]),
        Err(Error::InvalidLength {
            what: "SLH-DSA signature",
            ..
        })
    ));
    assert_eq!(
        s.verify(&[0u8; 32], b"m", &[0u8; 7856]),
        Err(Error::VerificationFailed)
    );
}
