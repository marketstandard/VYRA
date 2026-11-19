//! F4(c) ML-DSA signing/verification conformance against official NIST ACVP
//! vectors (`ML-DSA-sigGen-FIPS204`, `ML-DSA-sigVer-FIPS204`,
//! `internalProjection.json`). See `tests/data/PROVENANCE.md` for the exact
//! source commit, hashes and the subset selection.
//!
//! Included: every test group with `signatureInterface = "external"`,
//! `preHash = "pure"`, `externalMu = false` — the FIPS 204 Algorithm 2/3
//! interface VYRA uses — for all three parameter sets; sigGen both
//! `deterministic = true` (rnd = 0^32) and `false` (given `rnd`), contexts of
//! 0..=255 bytes.
//!
//! How each case is driven:
//! - sigGen signing: the vectors give the **expanded** secret key (skEncode),
//!   while VYRA's adapter stores only the 32-byte seed ξ, from which the
//!   expanded key cannot be inverted. Signing is therefore driven through the
//!   upstream `ml-dsa` crate directly (`ExpandedSigningKey::from_expanded`,
//!   then `sign_deterministic` / `sign_randomized` with the given `rnd`).
//!   The expected signature is additionally verified through VYRA's adapter
//!   (`ContextSignatureScheme::verify_with_context`, and the standalone
//!   `SignatureScheme::verify` when the context is empty).
//! - sigVer: VYRA's adapter verdict (`verify_with_context(pk, M, ctx, sig)`)
//!   must equal `testPassed`; the upstream verdict is checked too.
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
use ml_dsa::{
    EncodedVerifyingKey, ExpandedSigningKey, ExpandedSigningKeyBytes, MlDsaParams, VerifyingKey,
};
use vyra_core::RandCoreTryRng;
use vyra_sig::{ContextSignatureScheme, MlDsa44, MlDsa65, MlDsa87};

const SIG_GEN_GZ: &[u8] = include_bytes!("data/ML-DSA-sigGen-FIPS204-external-pure.json.gz");
const SIG_VER_GZ: &[u8] = include_bytes!("data/ML-DSA-sigVer-FIPS204-external-pure.json.gz");

fn load(gz: &[u8]) -> serde_json::Value {
    let mut json = String::new();
    flate2::read::GzDecoder::new(gz)
        .read_to_string(&mut json)
        .unwrap();
    serde_json::from_str(&json).unwrap()
}

fn hex_field(v: &serde_json::Value, key: &str) -> Vec<u8> {
    hex::decode(v[key].as_str().unwrap()).unwrap()
}

fn is_included(group: &serde_json::Value) -> bool {
    group["signatureInterface"] == "external"
        && group["preHash"] == "pure"
        && group["externalMu"] == false
}

/// Upstream signing from the expanded key; returns the encoded signature.
#[allow(deprecated)]
fn upstream_sign<P: MlDsaParams>(
    sk: &[u8],
    pk: &[u8],
    msg: &[u8],
    ctx: &[u8],
    rnd: Option<&[u8]>,
) -> Vec<u8> {
    let sk = ExpandedSigningKeyBytes::<P>::try_from(sk).unwrap();
    let esk = ExpandedSigningKey::<P>::from_expanded(&sk);
    // The NIST secret key and public key belong together.
    assert_eq!(esk.verifying_key().encode().as_slice(), pk);
    let sig = match rnd {
        None => esk.sign_deterministic(msg, ctx).unwrap(),
        Some(rnd) => {
            let mut src = Fixed::new(rnd);
            esk.sign_randomized(msg, ctx, &mut RandCoreTryRng::new(&mut src))
                .unwrap()
        }
    };
    sig.encode().to_vec()
}

fn upstream_verify<P: MlDsaParams>(pk: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
    let Ok(enc) = EncodedVerifyingKey::<P>::try_from(pk) else {
        return false;
    };
    let vk = VerifyingKey::<P>::decode(&enc);
    match ml_dsa::Signature::<P>::try_from(sig) {
        Ok(sig) => vk.verify_with_context(msg, ctx, &sig),
        Err(_) => false,
    }
}

fn adapter(param_set: &str) -> &'static dyn ContextSignatureScheme {
    match param_set {
        "ML-DSA-44" => &MlDsa44,
        "ML-DSA-65" => &MlDsa65,
        "ML-DSA-87" => &MlDsa87,
        other => panic!("unexpected parameter set {other}"),
    }
}

#[test]
fn nist_acvp_siggen_external_pure() {
    let v = load(SIG_GEN_GZ);
    assert_eq!(v["algorithm"], "ML-DSA");
    assert_eq!(v["mode"], "sigGen");
    assert_eq!(v["revision"], "FIPS204");

    // (parameter set, deterministic) -> cases
    let mut counts = BTreeMap::<(String, bool), usize>::new();
    for group in v["testGroups"].as_array().unwrap() {
        assert!(is_included(group), "subset contains only included groups");
        let ps = group["parameterSet"].as_str().unwrap();
        let deterministic = group["deterministic"].as_bool().unwrap();
        for t in group["tests"].as_array().unwrap() {
            let id = &t["tcId"];
            let (sk, pk, msg, ctx, expected) = (
                hex_field(t, "sk"),
                hex_field(t, "pk"),
                hex_field(t, "message"),
                hex_field(t, "context"),
                hex_field(t, "signature"),
            );
            let rnd = if deterministic {
                assert!(t.get("rnd").is_none());
                None
            } else {
                Some(hex_field(t, "rnd"))
            };

            // 1. Upstream reproduces the signature byte for byte.
            let got = match ps {
                "ML-DSA-44" => {
                    upstream_sign::<ml_dsa::MlDsa44>(&sk, &pk, &msg, &ctx, rnd.as_deref())
                }
                "ML-DSA-65" => {
                    upstream_sign::<ml_dsa::MlDsa65>(&sk, &pk, &msg, &ctx, rnd.as_deref())
                }
                "ML-DSA-87" => {
                    upstream_sign::<ml_dsa::MlDsa87>(&sk, &pk, &msg, &ctx, rnd.as_deref())
                }
                other => panic!("unexpected parameter set {other}"),
            };
            assert_eq!(got, expected, "{ps} tcId {id}: signature mismatch");

            // 2. VYRA's adapter accepts the official signature under the
            //    official context, and rejects it under a different context.
            let a = adapter(ps);
            a.verify_with_context(&pk, &msg, &ctx, &expected)
                .unwrap_or_else(|e| panic!("{ps} tcId {id}: adapter rejected: {e}"));
            let mut other_ctx = ctx.clone();
            other_ctx.push(0);
            if other_ctx.len() <= 255 {
                assert!(
                    a.verify_with_context(&pk, &msg, &other_ctx, &expected)
                        .is_err()
                );
            }
            if ctx.is_empty() {
                a.verify(&pk, &msg, &expected).unwrap();
            } else {
                assert!(a.verify(&pk, &msg, &expected).is_err());
            }
            *counts.entry((ps.to_owned(), deterministic)).or_default() += 1;
        }
    }
    println!("sigGen cases: {counts:?}");
    for ps in ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"] {
        assert_eq!(
            counts.get(&(ps.to_owned(), true)),
            Some(&15),
            "{ps} deterministic"
        );
        assert_eq!(
            counts.get(&(ps.to_owned(), false)),
            Some(&15),
            "{ps} hedged"
        );
    }
}

#[test]
fn nist_acvp_sigver_external_pure() {
    let v = load(SIG_VER_GZ);
    assert_eq!(v["algorithm"], "ML-DSA");
    assert_eq!(v["mode"], "sigVer");
    assert_eq!(v["revision"], "FIPS204");

    // (parameter set, expected verdict) -> cases
    let mut counts = BTreeMap::<(String, bool), usize>::new();
    for group in v["testGroups"].as_array().unwrap() {
        assert!(is_included(group), "subset contains only included groups");
        let ps = group["parameterSet"].as_str().unwrap();
        for t in group["tests"].as_array().unwrap() {
            let id = &t["tcId"];
            let passed = t["testPassed"].as_bool().unwrap();
            let (pk, msg, ctx, sig) = (
                hex_field(t, "pk"),
                hex_field(t, "message"),
                hex_field(t, "context"),
                hex_field(t, "signature"),
            );
            let ours = adapter(ps)
                .verify_with_context(&pk, &msg, &ctx, &sig)
                .is_ok();
            assert_eq!(
                ours, passed,
                "{ps} tcId {id} ({}): adapter verdict",
                t["reason"]
            );
            let upstream = match ps {
                "ML-DSA-44" => upstream_verify::<ml_dsa::MlDsa44>(&pk, &msg, &ctx, &sig),
                "ML-DSA-65" => upstream_verify::<ml_dsa::MlDsa65>(&pk, &msg, &ctx, &sig),
                "ML-DSA-87" => upstream_verify::<ml_dsa::MlDsa87>(&pk, &msg, &ctx, &sig),
                other => panic!("unexpected parameter set {other}"),
            };
            assert_eq!(upstream, passed, "{ps} tcId {id}: upstream verdict");
            *counts.entry((ps.to_owned(), passed)).or_default() += 1;
        }
    }
    println!("sigVer cases: {counts:?}");
    for ps in ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"] {
        assert_eq!(counts.get(&(ps.to_owned(), true)), Some(&3), "{ps} valid");
        assert_eq!(
            counts.get(&(ps.to_owned(), false)),
            Some(&12),
            "{ps} invalid"
        );
    }
}
