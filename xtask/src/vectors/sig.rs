//! `vectors/sig.json`: composite signature known answers for the transition
//! suites (ML-DSA + Ed25519, VYRA-SIG-2/3/5, [`PER_SUITE`] vectors each) and
//! the dual post-quantum suites (ML-DSA + SLH-DSA, VYRA-SIG-PQ1/3/5,
//! [`PQ_PER_SUITE`] vectors each because SLH-DSA signing takes seconds).
//!
//! The transition-suite entries are generated exactly as before the dual-PQ
//! suites existed (same seeds, inputs, fields and region names), so they are
//! byte-identical to the earlier file.

use serde_json::{Value, json};
use vyra_core::DeterministicEntropy;
use vyra_core::wire::HEADER_LEN;
use vyra_sig::{
    CompositePublicKey, CompositeSecretKey, CompositeSig, CompositeSignature, MAX_CONTEXT_LEN,
    SigSuite,
};

use super::{PER_SUITE, check_digest, compare, flipped, lib_err, seed, sha3_hex};
use crate::{Res, hex, json};

const KIND: &str = "sig";

/// Vectors per dual post-quantum suite (vector 0 in full hex, vector 1 as
/// digests): each costs several SLH-DSA signatures in generation and check.
pub const PQ_PER_SUITE: usize = 2;

/// Number of vectors stored for `suite`.
pub fn vectors_for(suite: SigSuite) -> usize {
    if suite.is_dual_pq() {
        PQ_PER_SUITE
    } else {
        PER_SUITE
    }
}

/// Message and context of vector `index` (fixed, varied lengths).
fn inputs(index: usize) -> (Vec<u8>, Vec<u8>) {
    let pattern = |n: usize, mul: usize| -> Vec<u8> {
        (0..n)
            .map(|i| u8::try_from(i.wrapping_mul(mul) % 256).unwrap_or(0))
            .collect()
    };
    match index {
        0 => (
            b"VYRA composite signature known-answer vector".to_vec(),
            b"VYRA-KAT".to_vec(),
        ),
        1 => (Vec::new(), Vec::new()),
        2 => (pattern(1024, 7), pattern(MAX_CONTEXT_LEN, 3)),
        3 => (vec![0x00], vec![0xff]),
        _ => (pattern(64 + index, 13), b"app/v1".to_vec()),
    }
}

/// Generate one vector from `seed_bytes`, `message` and `context`.
fn vector(
    suite: SigSuite,
    index: usize,
    seed_bytes: &[u8],
    message: &[u8],
    context: &[u8],
) -> Res<Value> {
    let ctx = format!("{} vector {index}", suite.name());
    let scheme = CompositeSignature::new(suite);
    let mut rng = DeterministicEntropy::from_seed(seed_bytes);
    let (pk, sk) = scheme.generate(&mut rng).map_err(lib_err(&ctx))?;
    let sig = scheme
        .sign(&sk, message, context, &mut rng)
        .map_err(lib_err(&ctx))?;
    scheme
        .verify(&pk, message, context, &sig)
        .map_err(lib_err(&ctx))?;
    let (pk_w, sk_w, sig_w) = (pk.to_bytes(), sk.to_bytes(), sig.to_bytes());
    if pk_w.len() != suite.encoded_public_key_len()
        || sk_w.len() != suite.encoded_secret_key_len()
        || sig_w.len() != suite.encoded_signature_len()
    {
        return Err(format!("{ctx}: wire length differs from suite constant"));
    }

    let mut negative = Vec::new();
    let second_start = HEADER_LEN + suite.mldsa_signature_len();
    let second_region = format!("{} signature", suite.second().name());
    for (region, offset) in [
        ("ML-DSA signature", HEADER_LEN + index),
        (second_region.as_str(), second_start + index),
    ] {
        let tampered = flipped(&sig_w, offset, 0x01)?;
        let tsig = CompositeSig::from_bytes(&tampered).map_err(lib_err(&ctx))?;
        if scheme.verify(&pk, message, context, &tsig).is_ok() {
            return Err(format!("{ctx}: tampered signature ({region}) verified"));
        }
        negative.push(json!({
            "kind": "tampered_signature",
            "region": region,
            "wire_offset": offset,
            "xor_mask": "01",
            "tampered_signature_sha3_256": sha3_hex(&tampered),
            "expected": "reject",
        }));
    }
    let mut longer = message.to_vec();
    longer.push(0x00);
    if scheme.verify(&pk, &longer, context, &sig).is_ok() {
        return Err(format!("{ctx}: signature verified on a modified message"));
    }
    negative.push(json!({
        "kind": "modified_message",
        "message": hex::encode(&longer),
        "expected": "reject",
    }));

    let mut v = json!({
        "index": index,
        "seed": hex::encode(seed_bytes),
        "message": hex::encode(message),
        "context": hex::encode(context),
        "public_key_len": pk_w.len(),
        "secret_key_len": sk_w.len(),
        "signature_len": sig_w.len(),
        "public_key_sha3_256": sha3_hex(&pk_w),
        "secret_key_sha3_256": sha3_hex(sk_w.expose()),
        "signature_sha3_256": sha3_hex(&sig_w),
        "negative": negative,
    });
    if index == 0
        && let Some(m) = v.as_object_mut()
    {
        m.insert("public_key".into(), json!(hex::encode(&pk_w)));
        m.insert("secret_key".into(), json!(hex::encode(sk_w.expose())));
        m.insert("signature".into(), json!(hex::encode(&sig_w)));
    }
    Ok(v)
}

/// The whole `sig.json` document.
pub fn generate() -> Res<Value> {
    let mut suites = Vec::new();
    for suite in SigSuite::all() {
        let mut vectors = Vec::new();
        for i in 0..vectors_for(suite) {
            let (m, c) = inputs(i);
            vectors.push(vector(suite, i, &seed(KIND, suite.id(), i), &m, &c)?);
        }
        suites.push(json!({
            "suite": suite.name(),
            "suite_id": suite.id(),
            "components": [suite.first().name(), suite.second().name()],
            "vectors": vectors,
        }));
    }
    Ok(json!({
        "title": "VYRA-SIG v1 known-answer vectors (composite ML-DSA + Ed25519 transition suites; ML-DSA + SLH-DSA dual post-quantum suites)",
        "generator": "cargo xtask vectors",
        "wire_version": vyra_core::wire::VERSION,
        "procedure": [
            "rng = DeterministicEntropy::from_seed(seed)",
            "(pk, sk) = CompositeSignature::new(suite).generate(rng)",
            "signature = sign(sk, message, context, rng)",
            "verify(pk, message, context, signature) is Ok",
        ],
        "hedging_note": "ML-DSA signing is hedged (FIPS 204): its 32-byte rnd is drawn from the same DeterministicEntropy stream right after key generation, so these signatures are reproducible only with that stream. With other randomness a different, equally valid ML-DSA half results. The Ed25519 half is deterministic (RFC 8032). In the dual post-quantum suites the SLH-DSA half is hedged too (FIPS 205 opt_rand, n bytes drawn from the same stream after the ML-DSA rnd).",
        "vectors_per_suite": format!("transition suites: {PER_SUITE}; dual post-quantum suites: {PQ_PER_SUITE} (SLH-DSA signing takes seconds; vector 0 in full hex)"),
        "digests": "SHA3-256 over the complete wire encoding (7-byte header included)",
        "full_hex": "vector 0 of every suite also carries public_key, secret_key and signature in full (wire encoding, hex)",
        "negative_vectors": "flip xor_mask at wire_offset of the signature, or verify the given modified message: verify must fail",
        "suites": suites,
    }))
}

fn suite_of(s: &Value) -> Res<SigSuite> {
    let id = json::u64_field(s, "suite_id", "sig suite")?;
    let id = u8::try_from(id).map_err(|_| format!("suite id {id} out of range"))?;
    SigSuite::from_id(id).map_err(|e| e.to_string())
}

/// Re-derive every stored vector from its stored seed and inputs and compare.
pub fn regenerate_stored(doc: &Value) -> Res<Vec<String>> {
    let mut out = Vec::new();
    for s in json::array_field(doc, "suites", "sig.json")? {
        let suite = suite_of(s)?;
        let vectors = json::array_field(s, "vectors", suite.name())?;
        if vectors.len() < vectors_for(suite) {
            out.push(format!("{}: only {} vectors", suite.name(), vectors.len()));
        }
        for v in vectors {
            let index = usize::try_from(json::u64_field(v, "index", suite.name())?)
                .map_err(|e| e.to_string())?;
            let ctx = format!("{} vector {index}", suite.name());
            let seed_bytes = json::hex_field(v, "seed", &ctx)?;
            let message = json::hex_field(v, "message", &ctx)?;
            let context = json::hex_field(v, "context", &ctx)?;
            let computed = vector(suite, index, &seed_bytes, &message, &context)?;
            compare(&ctx, v, &computed, &mut out);
        }
    }
    Ok(out)
}

/// Independently re-verify the stored full-hex vector of every suite.
pub fn verify_stored(doc: &Value) -> Res<Vec<String>> {
    let mut out = Vec::new();
    for s in json::array_field(doc, "suites", "sig.json")? {
        let suite = suite_of(s)?;
        let first = json::array_field(s, "vectors", suite.name())?
            .first()
            .ok_or_else(|| format!("{}: no vectors", suite.name()))?;
        let ctx = format!("{} vector 0", suite.name());
        let pk_w = json::hex_field(first, "public_key", &ctx)?;
        let sk_w = json::hex_field(first, "secret_key", &ctx)?;
        let sig_w = json::hex_field(first, "signature", &ctx)?;
        let message = json::hex_field(first, "message", &ctx)?;
        let context = json::hex_field(first, "context", &ctx)?;
        check_digest(&ctx, first, &pk_w, "public_key_sha3_256", &mut out);
        check_digest(&ctx, first, &sk_w, "secret_key_sha3_256", &mut out);
        check_digest(&ctx, first, &sig_w, "signature_sha3_256", &mut out);

        let scheme = CompositeSignature::new(suite);
        let pk = CompositePublicKey::from_bytes(&pk_w).map_err(lib_err(&ctx))?;
        let sk = CompositeSecretKey::from_bytes(&sk_w).map_err(lib_err(&ctx))?;
        let sig = CompositeSig::from_bytes(&sig_w).map_err(lib_err(&ctx))?;
        if let Err(e) = scheme.verify(&pk, &message, &context, &sig) {
            out.push(format!("{ctx}: stored signature does not verify: {e}"));
        }
        // The stored sk belongs to the stored pk: a fresh signature verifies.
        let fresh = scheme
            .sign(&sk, b"pair check", b"", &mut vyra_core::OsEntropy::new())
            .map_err(lib_err(&ctx))?;
        if scheme.verify(&pk, b"pair check", b"", &fresh).is_err() {
            out.push(format!("{ctx}: stored public and secret key do not match"));
        }
        for (n, neg) in json::array_field(first, "negative", &ctx)?
            .iter()
            .enumerate()
        {
            let nctx = format!("{ctx} negative {n}");
            let kind = json::str_field(neg, "kind", &nctx)?;
            let accepted = match kind {
                "tampered_signature" => {
                    let offset = usize::try_from(json::u64_field(neg, "wire_offset", &nctx)?)
                        .map_err(|e| e.to_string())?;
                    let mask = *json::hex_field(neg, "xor_mask", &nctx)?
                        .first()
                        .ok_or_else(|| format!("{nctx}: empty xor_mask"))?;
                    let tampered = flipped(&sig_w, offset, mask)?;
                    check_digest(
                        &nctx,
                        neg,
                        &tampered,
                        "tampered_signature_sha3_256",
                        &mut out,
                    );
                    match CompositeSig::from_bytes(&tampered) {
                        Ok(t) => scheme.verify(&pk, &message, &context, &t).is_ok(),
                        Err(_) => false,
                    }
                }
                "modified_message" => {
                    let m = json::hex_field(neg, "message", &nctx)?;
                    scheme.verify(&pk, &m, &context, &sig).is_ok()
                }
                other => {
                    out.push(format!("{nctx}: unknown kind {other}"));
                    false
                }
            };
            if accepted {
                out.push(format!("{nctx}: negative vector verified (must fail)"));
            }
        }
    }
    Ok(out)
}
