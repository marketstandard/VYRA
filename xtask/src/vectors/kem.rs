//! `vectors/kem.json`: hybrid KEM (VYRA-KEM-1/3/5) known answers.

use serde_json::{Value, json};
use vyra_core::wire::HEADER_LEN;
use vyra_core::{DeterministicEntropy, Kem, OsEntropy};
use vyra_kem::{
    HybridCiphertext, HybridKem, HybridPublicKey, HybridSecretKey, KemSuite, MlKem512, MlKem768,
    MlKem1024,
};

use super::{PER_SUITE, check_digest, compare, flipped, lib_err, seed, sha3_hex};
use crate::{Res, hex, json};

const KIND: &str = "kem";

/// Raw ML-KEM ciphertext length of `suite` (the `ct1` part).
fn ct1_len(suite: KemSuite) -> usize {
    match suite {
        KemSuite::Vyra1 => MlKem512.ciphertext_len(),
        KemSuite::Vyra3 => MlKem768.ciphertext_len(),
        KemSuite::Vyra5 => MlKem1024.ciphertext_len(),
    }
}

/// `(region, wire offset)` of the bit flips recorded for vector `index`.
/// Bit 0 of the first bytes of ct1 (ML-KEM `c1`) and ct2 (HQC `u`): bits
/// every decapsulation reads.
fn tamper_points(suite: KemSuite, index: usize) -> [(&'static str, usize); 2] {
    [
        ("ct1 (ML-KEM)", HEADER_LEN + index),
        ("ct2 (HQC)", HEADER_LEN + ct1_len(suite) + index),
    ]
}

/// Generate one vector from `seed_bytes`.
fn vector(suite: KemSuite, index: usize, seed_bytes: &[u8]) -> Res<Value> {
    let ctx = format!("{} vector {index}", suite.name());
    let kem = HybridKem::new(suite);
    let mut rng = DeterministicEntropy::from_seed(seed_bytes);
    let (pk, sk) = kem.generate(&mut rng).map_err(lib_err(&ctx))?;
    let (ct, ss) = kem.encapsulate_to(&pk, &mut rng).map_err(lib_err(&ctx))?;
    let ss_dec = kem.decapsulate_with(&sk, &ct).map_err(lib_err(&ctx))?;
    if !ss.ct_eq(&ss_dec) {
        return Err(format!("{ctx}: decapsulation disagrees with encapsulation"));
    }
    let (pk_w, sk_w, ct_w) = (pk.to_bytes(), sk.to_bytes(), ct.to_bytes());
    if pk_w.len() != suite.encoded_public_key_len()
        || sk_w.len() != suite.encoded_secret_key_len()
        || ct_w.len() != suite.encoded_ciphertext_len()
    {
        return Err(format!("{ctx}: wire length differs from suite constant"));
    }

    let mut negative = Vec::new();
    for (region, offset) in tamper_points(suite, index) {
        let tampered = flipped(&ct_w, offset, 0x01)?;
        let tct = HybridCiphertext::from_bytes(&tampered).map_err(lib_err(&ctx))?;
        let rejected = kem.decapsulate_with(&sk, &tct).map_err(lib_err(&ctx))?;
        if rejected.ct_eq(&ss) {
            return Err(format!(
                "{ctx}: tampered ciphertext ({region}) gave the original key"
            ));
        }
        negative.push(json!({
            "kind": "tampered_ciphertext",
            "region": region,
            "wire_offset": offset,
            "xor_mask": "01",
            "tampered_ciphertext_sha3_256": sha3_hex(&tampered),
            "expected_shared_secret": hex::encode(rejected.expose()),
            "note": "implicit rejection: decapsulation succeeds and returns this unrelated key",
        }));
    }

    let mut v = json!({
        "index": index,
        "seed": hex::encode(seed_bytes),
        "public_key_len": pk_w.len(),
        "secret_key_len": sk_w.len(),
        "ciphertext_len": ct_w.len(),
        "public_key_sha3_256": sha3_hex(&pk_w),
        "secret_key_sha3_256": sha3_hex(sk_w.expose()),
        "ciphertext_sha3_256": sha3_hex(&ct_w),
        "shared_secret": hex::encode(ss.expose()),
        "negative": negative,
    });
    if index == 0
        && let Some(m) = v.as_object_mut()
    {
        m.insert("public_key".into(), json!(hex::encode(&pk_w)));
        m.insert("secret_key".into(), json!(hex::encode(sk_w.expose())));
        m.insert("ciphertext".into(), json!(hex::encode(&ct_w)));
    }
    Ok(v)
}

/// The whole `kem.json` document.
pub fn generate() -> Res<Value> {
    let mut suites = Vec::new();
    for suite in KemSuite::all() {
        let mut vectors = Vec::new();
        for i in 0..PER_SUITE {
            vectors.push(vector(suite, i, &seed(KIND, suite.id(), i))?);
        }
        let (c1, c2) = suite.component_names();
        suites.push(json!({
            "suite": suite.name(),
            "suite_id": suite.id(),
            "components": [c1, c2],
            "vectors": vectors,
        }));
    }
    Ok(json!({
        "title": "VYRA-KEM v1 known-answer vectors (hybrid ML-KEM + HQC)",
        "generator": "cargo xtask vectors",
        "wire_version": vyra_core::wire::VERSION,
        "procedure": [
            "rng = DeterministicEntropy::from_seed(seed)",
            "(pk, sk) = HybridKem::new(suite).generate(rng)",
            "(ct, shared_secret) = encapsulate_to(pk, rng)",
            "decapsulate_with(sk, ct) == shared_secret",
        ],
        "digests": "SHA3-256 over the complete wire encoding (7-byte header included)",
        "full_hex": "vector 0 of every suite also carries public_key, secret_key and ciphertext in full (wire encoding, hex)",
        "negative_vectors": "flip xor_mask at wire_offset of the ciphertext; decapsulation must return expected_shared_secret (implicit rejection, docs/DECISIONS.md D-02)",
        "hqc_note": "HQC is the in-tree vyra-hqc port of the HQC v5.1 specification (reference tag v5.1.0), verified against the official v5.1 KATs; HQC is not yet a published FIPS standard (docs/DECISIONS.md D-14). These vectors pin VYRA's v1 format on HQC v5.1.",
        "suites": suites,
    }))
}

fn suite_of(s: &Value) -> Res<KemSuite> {
    let id = json::u64_field(s, "suite_id", "kem suite")?;
    let id = u8::try_from(id).map_err(|_| format!("suite id {id} out of range"))?;
    KemSuite::from_id(id).map_err(|e| e.to_string())
}

/// Re-derive every stored vector from its stored seed and compare.
pub fn regenerate_stored(doc: &Value) -> Res<Vec<String>> {
    let mut out = Vec::new();
    for s in json::array_field(doc, "suites", "kem.json")? {
        let suite = suite_of(s)?;
        let vectors = json::array_field(s, "vectors", suite.name())?;
        if vectors.len() < PER_SUITE {
            out.push(format!("{}: only {} vectors", suite.name(), vectors.len()));
        }
        for v in vectors {
            let index = json::u64_field(v, "index", suite.name())?;
            let index = usize::try_from(index).map_err(|e| e.to_string())?;
            let seed_bytes = json::hex_field(v, "seed", suite.name())?;
            let ctx = format!("{} vector {index}", suite.name());
            compare(&ctx, v, &vector(suite, index, &seed_bytes)?, &mut out);
        }
    }
    Ok(out)
}

/// Independently re-verify the stored full-hex vector of every suite.
pub fn verify_stored(doc: &Value) -> Res<Vec<String>> {
    let mut out = Vec::new();
    for s in json::array_field(doc, "suites", "kem.json")? {
        let suite = suite_of(s)?;
        let first = json::array_field(s, "vectors", suite.name())?
            .first()
            .ok_or_else(|| format!("{}: no vectors", suite.name()))?;
        let ctx = format!("{} vector 0", suite.name());
        let pk_w = json::hex_field(first, "public_key", &ctx)?;
        let sk_w = json::hex_field(first, "secret_key", &ctx)?;
        let ct_w = json::hex_field(first, "ciphertext", &ctx)?;
        let ss = json::hex_field(first, "shared_secret", &ctx)?;
        check_digest(&ctx, first, &pk_w, "public_key_sha3_256", &mut out);
        check_digest(&ctx, first, &sk_w, "secret_key_sha3_256", &mut out);
        check_digest(&ctx, first, &ct_w, "ciphertext_sha3_256", &mut out);

        let kem = HybridKem::new(suite);
        let pk = HybridPublicKey::from_bytes(&pk_w).map_err(lib_err(&ctx))?;
        let sk = HybridSecretKey::from_bytes(&sk_w).map_err(lib_err(&ctx))?;
        let ct = HybridCiphertext::from_bytes(&ct_w).map_err(lib_err(&ctx))?;
        let got = kem.decapsulate_with(&sk, &ct).map_err(lib_err(&ctx))?;
        if got.expose() != ss.as_slice() {
            out.push(format!(
                "{ctx}: decapsulating the stored ciphertext with the stored secret key gives {}, file says {}",
                hex::encode(got.expose()),
                hex::encode(&ss)
            ));
        }
        // The stored pk and sk belong together: a fresh encapsulation round-trips.
        let (fresh_ct, fresh_ss) = kem
            .encapsulate_to(&pk, &mut OsEntropy::new())
            .map_err(lib_err(&ctx))?;
        let back = kem
            .decapsulate_with(&sk, &fresh_ct)
            .map_err(lib_err(&ctx))?;
        if !back.ct_eq(&fresh_ss) {
            out.push(format!("{ctx}: stored public and secret key do not match"));
        }
        for (n, neg) in json::array_field(first, "negative", &ctx)?
            .iter()
            .enumerate()
        {
            let nctx = format!("{ctx} negative {n}");
            let offset = usize::try_from(json::u64_field(neg, "wire_offset", &nctx)?)
                .map_err(|e| e.to_string())?;
            let mask = *json::hex_field(neg, "xor_mask", &nctx)?
                .first()
                .ok_or_else(|| format!("{nctx}: empty xor_mask"))?;
            let expected = json::hex_field(neg, "expected_shared_secret", &nctx)?;
            let tampered = flipped(&ct_w, offset, mask)?;
            check_digest(
                &nctx,
                neg,
                &tampered,
                "tampered_ciphertext_sha3_256",
                &mut out,
            );
            let tct = HybridCiphertext::from_bytes(&tampered).map_err(lib_err(&nctx))?;
            let rej = kem.decapsulate_with(&sk, &tct).map_err(lib_err(&nctx))?;
            if rej.expose() != expected.as_slice() {
                out.push(format!(
                    "{nctx}: tampered ciphertext decapsulates to {}, file says {}",
                    hex::encode(rej.expose()),
                    hex::encode(&expected)
                ));
            }
            if rej.expose() == ss.as_slice() {
                out.push(format!(
                    "{nctx}: tampered ciphertext gives the original key"
                ));
            }
        }
    }
    Ok(out)
}
