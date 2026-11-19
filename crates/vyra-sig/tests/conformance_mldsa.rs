//! F4(c) ML-DSA conformance, all three parameter sets.
//!
//! 1. **Official KAT (key generation):** NIST ACVP-Server `ML-DSA-keyGen-FIPS204`
//!    internal-projection vectors (75 cases, 25 per parameter set: seed ξ →
//!    pk, sk). The file `tests/data/ML-DSA-keyGen-FIPS204-internalProjection.json.gz`
//!    is copied byte-for-byte from the `fips204` 0.5.0 crate
//!    (`tests/nist_vectors/ML-DSA-keyGen-FIPS204/internalProjection.json.gz`),
//!    which took it from <https://github.com/usnistgov/ACVP-Server>.
//!    SHA-256 of the .gz: 1717b3497b96c16e6b9556be467c5bbc6dd113d962aa0a02bd669eadaef8c01b.
//!    The `ml-dsa` crate's own ACVP files are excluded from its published package.
//! 2. **Differential interop** against `fips204` 0.5.0 (an independent pure-Rust
//!    implementation by a different author): same seed → same public key; with
//!    the same `rnd`, byte-identical hedged signatures; each implementation's
//!    signatures verify under the other. Covered for the empty FIPS 204
//!    context (standalone adapter) and for the non-empty VYRA context
//!    `"VYRA-SIG-v1" ‖ suite_id` (the composite path, checked end to end).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

mod common;

use std::io::Read;

use common::Fixed;
use fips204::traits::{KeyGen, SerDes, Signer, Verifier};
use vyra_core::{DeterministicEntropy, EntropySource, Error, SignatureScheme};
use vyra_sig::{
    CompositeSignature, ContextSignatureScheme, MlDsa44, MlDsa65, MlDsa87, SigSuite,
    message_representative, mldsa_context,
};

const KAT_GZ: &[u8] = include_bytes!("data/ML-DSA-keyGen-FIPS204-internalProjection.json.gz");

fn load_kat() -> serde_json::Value {
    let mut json = String::new();
    flate2::read::GzDecoder::new(KAT_GZ)
        .read_to_string(&mut json)
        .unwrap();
    serde_json::from_str(&json).unwrap()
}

fn hex_field(v: &serde_json::Value, key: &str) -> Vec<u8> {
    hex::decode(v[key].as_str().unwrap()).unwrap()
}

#[allow(deprecated)]
fn expanded_sk(param_set: &str, seed: &ml_dsa::Seed) -> Vec<u8> {
    use ml_dsa::SigningKey;
    match param_set {
        "ML-DSA-44" => SigningKey::<ml_dsa::MlDsa44>::from_seed(seed)
            .expanded_key()
            .to_expanded()
            .to_vec(),
        "ML-DSA-65" => SigningKey::<ml_dsa::MlDsa65>::from_seed(seed)
            .expanded_key()
            .to_expanded()
            .to_vec(),
        "ML-DSA-87" => SigningKey::<ml_dsa::MlDsa87>::from_seed(seed)
            .expanded_key()
            .to_expanded()
            .to_vec(),
        other => panic!("unexpected parameter set {other}"),
    }
}

#[test]
fn nist_acvp_keygen_vectors() {
    let kat = load_kat();
    assert_eq!(kat["algorithm"], "ML-DSA");
    assert_eq!(kat["mode"], "keyGen");
    assert_eq!(kat["revision"], "FIPS204");

    let mut checked = std::collections::BTreeMap::<String, usize>::new();
    for group in kat["testGroups"].as_array().unwrap() {
        let param_set = group["parameterSet"].as_str().unwrap();
        let scheme: Box<dyn SignatureScheme> = match param_set {
            "ML-DSA-44" => Box::new(MlDsa44),
            "ML-DSA-65" => Box::new(MlDsa65),
            "ML-DSA-87" => Box::new(MlDsa87),
            other => panic!("unexpected parameter set {other}"),
        };
        for test in group["tests"].as_array().unwrap() {
            let seed = hex_field(test, "seed");
            let pk = hex_field(test, "pk");
            let sk = hex_field(test, "sk");

            // VYRA adapter: seed in, public key out, secret key stored as seed.
            let (got_pk, got_sk) = scheme.generate_keypair(&mut Fixed::new(&seed)).unwrap();
            assert_eq!(got_pk, pk, "{param_set} tcId {}", test["tcId"]);
            assert_eq!(got_sk.expose(), &seed[..]);

            // The upstream expanded secret key matches the NIST sk as well.
            let xi = ml_dsa::Seed::try_from(&seed[..]).unwrap();
            assert_eq!(
                expanded_sk(param_set, &xi),
                sk,
                "{param_set} tcId {}",
                test["tcId"]
            );

            // A key generated from the vector seed signs and verifies.
            let sig = scheme
                .sign(&seed, b"kat", &mut DeterministicEntropy::from_seed(b"r"))
                .unwrap();
            scheme.verify(&pk, b"kat", &sig).unwrap();

            *checked.entry(param_set.to_owned()).or_default() += 1;
        }
    }
    assert_eq!(checked.get("ML-DSA-44"), Some(&25));
    assert_eq!(checked.get("ML-DSA-65"), Some(&25));
    assert_eq!(checked.get("ML-DSA-87"), Some(&25));
}

macro_rules! differential {
    ($test:ident, $ours:expr, $theirs:ident, $suite:expr) => {
        #[test]
        fn $test() {
            use fips204::$theirs as other;
            let ours = $ours;
            for i in 0u8..8 {
                let seed_label = [b'k', i];
                let sign_label = [b's', i];
                let message: Vec<u8> = (0..(37 * usize::from(i))).map(|j| j as u8).collect();

                // Same seed -> same public key.
                let (pk, sk) = ours
                    .generate_keypair(&mut DeterministicEntropy::from_seed(&seed_label))
                    .unwrap();
                let xi: [u8; 32] = sk.expose().try_into().unwrap();
                let (their_pk, their_sk) = other::KG::keygen_from_seed(&xi);
                let their_pk_bytes = their_pk.clone().into_bytes();
                assert_eq!(pk, their_pk_bytes.to_vec());

                // Same rnd -> byte-identical hedged signature (empty FIPS 204 ctx).
                let sig = ours
                    .sign(
                        sk.expose(),
                        &message,
                        &mut DeterministicEntropy::from_seed(&sign_label),
                    )
                    .unwrap();
                let mut rnd = [0u8; 32];
                DeterministicEntropy::from_seed(&sign_label)
                    .fill(&mut rnd)
                    .unwrap();
                let their_sig = their_sk.try_sign_with_seed(&rnd, &message, &[]).unwrap();
                assert_eq!(sig, their_sig.to_vec());

                // Cross verification, both directions, with a fresh rnd too.
                let their_sig2 = their_sk
                    .try_sign_with_seed(&[i; 32], &message, &[])
                    .unwrap();
                ours.verify(&pk, &message, &their_sig2).unwrap();
                let our_sig_arr: [u8; other::SIG_LEN] = sig.as_slice().try_into().unwrap();
                assert!(their_pk.verify(&message, &our_sig_arr, &[]));

                // Negative cross checks: a different message, or a non-empty
                // FIPS 204 context on the other side, must not verify.
                assert!(!their_pk.verify(b"different", &our_sig_arr, &[]));
                assert!(!their_pk.verify(&message, &our_sig_arr, b"ctx"));
                let ctx_sig = their_sk.try_sign_with_seed(&rnd, &message, b"ctx").unwrap();
                assert_eq!(
                    ours.verify(&pk, &message, &ctx_sig),
                    Err(Error::VerificationFailed),
                    "VYRA's standalone ML-DSA adapter must use the empty FIPS 204 context"
                );

                // Non-empty FIPS 204 context (the path the composite uses):
                // byte-identical with fips204 and cross-verifying.
                let vyra_ctx = mldsa_context($suite);
                let ctx_ours = ours
                    .sign_with_context(
                        sk.expose(),
                        &message,
                        &vyra_ctx,
                        &mut DeterministicEntropy::from_seed(&sign_label),
                    )
                    .unwrap();
                let ctx_theirs = their_sk
                    .try_sign_with_seed(&rnd, &message, &vyra_ctx)
                    .unwrap();
                assert_eq!(ctx_ours, ctx_theirs.to_vec());
                let ctx_arr: [u8; other::SIG_LEN] = ctx_ours.as_slice().try_into().unwrap();
                assert!(their_pk.verify(&message, &ctx_arr, &vyra_ctx));
                assert!(!their_pk.verify(&message, &ctx_arr, &[]));
                ours.verify_with_context(&pk, &message, &vyra_ctx, &ctx_theirs)
                    .unwrap();
                assert_eq!(
                    ours.verify(&pk, &message, &ctx_theirs),
                    Err(Error::VerificationFailed)
                );

                // End to end through the composite: its ML-DSA half equals
                // fips204's signature on M' under the VYRA context.
                let composite = CompositeSignature::new($suite);
                let (cpk, csk) = composite
                    .generate(&mut DeterministicEntropy::from_seed(&seed_label))
                    .unwrap();
                assert_eq!(cpk.mldsa_part(), pk.as_slice());
                let csig = composite
                    .sign(
                        &csk,
                        &message,
                        b"app-ctx",
                        &mut DeterministicEntropy::from_seed(&sign_label),
                    )
                    .unwrap();
                let m_prime =
                    message_representative($suite, cpk.as_raw(), b"app-ctx", &message).unwrap();
                let expected = their_sk
                    .try_sign_with_seed(&rnd, &m_prime, &vyra_ctx)
                    .unwrap();
                assert_eq!(csig.mldsa_part(), expected.as_slice());
            }
        }
    };
}

differential!(
    differential_fips204_mldsa44,
    MlDsa44,
    ml_dsa_44,
    SigSuite::Vyra2
);
differential!(
    differential_fips204_mldsa65,
    MlDsa65,
    ml_dsa_65,
    SigSuite::Vyra3
);
differential!(
    differential_fips204_mldsa87,
    MlDsa87,
    ml_dsa_87,
    SigSuite::Vyra5
);

#[test]
fn hedged_signing_draws_exactly_32_bytes() {
    // Signing must consume exactly the 32-byte rnd: a source holding 32 bytes
    // suffices, 31 bytes fail with EntropyFailure.
    let (_, sk) = MlDsa65
        .generate_keypair(&mut DeterministicEntropy::from_seed(b"k"))
        .unwrap();
    MlDsa65
        .sign(sk.expose(), b"m", &mut Fixed::new(&[9u8; 32]))
        .unwrap();
    assert_eq!(
        MlDsa65.sign(sk.expose(), b"m", &mut Fixed::new(&[9u8; 31])),
        Err(Error::EntropyFailure)
    );
}
