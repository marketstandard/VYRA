//! `vectors/seal.json`: sealed box (hybrid KEM + ChaCha20-Poly1305) known answers.

use serde_json::{Value, json};
use vyra_core::wire::HEADER_LEN;
use vyra_core::{DeterministicEntropy, OsEntropy};
use vyra_kem::{HybridKem, HybridPublicKey, HybridSecretKey, KemSuite};
use vyra_seal::SealedBox;

use super::{PER_SUITE, check_digest, compare, flipped, lib_err, seed, sha3_hex};
use crate::{Res, hex, json};

const KIND: &str = "seal";

/// Associated data and plaintext of vector `index`.
fn inputs(index: usize) -> (Vec<u8>, Vec<u8>) {
    let pattern = |n: usize| -> Vec<u8> {
        (0..n)
            .map(|i| u8::try_from((i * 31 + 7) % 256).unwrap_or(0))
            .collect()
    };
    match index {
        0 => (
            b"VYRA-KAT aad".to_vec(),
            b"VYRA sealed box known-answer vector".to_vec(),
        ),
        1 => (Vec::new(), Vec::new()),
        2 => (b"a".to_vec(), vec![0x42]),
        3 => (pattern(40), pattern(256)),
        _ => (b"aad".to_vec(), pattern(1024)),
    }
}

/// Generate one vector.
fn vector(
    suite: KemSuite,
    index: usize,
    seed_bytes: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Res<Value> {
    let ctx = format!("seal {} vector {index}", suite.name());
    let sbox = SealedBox::new(suite);
    let mut rng = DeterministicEntropy::from_seed(seed_bytes);
    let (pk, sk) = HybridKem::new(suite)
        .generate(&mut rng)
        .map_err(lib_err(&ctx))?;
    let sealed = sbox
        .seal(&pk, aad, plaintext, &mut rng)
        .map_err(lib_err(&ctx))?;
    let opened = sbox.open(&sk, aad, &sealed).map_err(lib_err(&ctx))?;
    if opened.expose() != plaintext {
        return Err(format!("{ctx}: open did not return the plaintext"));
    }
    if sealed.len() != plaintext.len() + SealedBox::overhead(suite) {
        return Err(format!(
            "{ctx}: sealed length differs from overhead constant"
        ));
    }
    let (pk_w, sk_w) = (pk.to_bytes(), sk.to_bytes());

    let mut negative = Vec::new();
    let last = sealed.len().saturating_sub(1);
    for (region, offset) in [
        ("KEM ciphertext", HEADER_LEN + index),
        ("Poly1305 tag", last.saturating_sub(index)),
    ] {
        let tampered = flipped(&sealed, offset, 0x01)?;
        if sbox.open(&sk, aad, &tampered).is_ok() {
            return Err(format!("{ctx}: tampered sealed box ({region}) opened"));
        }
        negative.push(json!({
            "kind": "tampered_sealed_box",
            "region": region,
            "wire_offset": offset,
            "xor_mask": "01",
            "tampered_sealed_box_sha3_256": sha3_hex(&tampered),
            "expected": "reject",
        }));
    }
    if !plaintext.is_empty() {
        let offset = HEADER_LEN + suite.ciphertext_len();
        let tampered = flipped(&sealed, offset, 0x80)?;
        if sbox.open(&sk, aad, &tampered).is_ok() {
            return Err(format!("{ctx}: tampered sealed box (body) opened"));
        }
        negative.push(json!({
            "kind": "tampered_sealed_box",
            "region": "AEAD ciphertext body",
            "wire_offset": offset,
            "xor_mask": "80",
            "tampered_sealed_box_sha3_256": sha3_hex(&tampered),
            "expected": "reject",
        }));
    }
    let mut other_aad = aad.to_vec();
    other_aad.push(0x00);
    if sbox.open(&sk, &other_aad, &sealed).is_ok() {
        return Err(format!("{ctx}: opened under different associated data"));
    }
    negative.push(json!({
        "kind": "modified_aad",
        "aad": hex::encode(&other_aad),
        "expected": "reject",
    }));

    let mut v = json!({
        "index": index,
        "seed": hex::encode(seed_bytes),
        "aad": hex::encode(aad),
        "plaintext": hex::encode(plaintext),
        "public_key_sha3_256": sha3_hex(&pk_w),
        "secret_key_sha3_256": sha3_hex(sk_w.expose()),
        "sealed_box_len": sealed.len(),
        "sealed_box_sha3_256": sha3_hex(&sealed),
        "negative": negative,
    });
    if index == 0
        && let Some(m) = v.as_object_mut()
    {
        m.insert("public_key".into(), json!(hex::encode(&pk_w)));
        m.insert("secret_key".into(), json!(hex::encode(sk_w.expose())));
        m.insert("sealed_box".into(), json!(hex::encode(&sealed)));
    }
    Ok(v)
}

/// The whole `seal.json` document.
pub fn generate() -> Res<Value> {
    let mut suites = Vec::new();
    for suite in KemSuite::all() {
        let mut vectors = Vec::new();
        for i in 0..PER_SUITE {
            let (aad, pt) = inputs(i);
            vectors.push(vector(suite, i, &seed(KIND, suite.id(), i), &aad, &pt)?);
        }
        suites.push(json!({
            "suite": suite.name(),
            "suite_id": suite.id(),
            "overhead": SealedBox::overhead(suite),
            "vectors": vectors,
        }));
    }
    Ok(json!({
        "title": "VYRA-SEAL v1 known-answer vectors (hybrid KEM + ChaCha20-Poly1305 sealed box)",
        "generator": "cargo xtask vectors",
        "wire_version": vyra_core::wire::VERSION,
        "procedure": [
            "rng = DeterministicEntropy::from_seed(seed)",
            "(pk, sk) = HybridKem::new(suite).generate(rng)",
            "sealed_box = SealedBox::new(suite).seal(pk, aad, plaintext, rng)",
            "open(sk, aad, sealed_box) == plaintext",
        ],
        "warning": "Every vector uses its own seed. Reusing one DeterministicEntropy seed to seal two different messages to one key reuses the AEAD key and nonce; DeterministicEntropy is for tests only.",
        "digests": "SHA3-256 over the complete wire encoding (7-byte header included)",
        "full_hex": "vector 0 of every suite also carries public_key, secret_key (KEM wire encodings) and sealed_box in full (hex)",
        "negative_vectors": "flip xor_mask at wire_offset of the sealed box, or open with the given modified aad: open must fail",
        "hqc_note": "The KEM uses the in-tree vyra-hqc port of HQC v5.1 (docs/DECISIONS.md D-14).",
        "suites": suites,
    }))
}

fn suite_of(s: &Value) -> Res<KemSuite> {
    let id = json::u64_field(s, "suite_id", "seal suite")?;
    let id = u8::try_from(id).map_err(|_| format!("suite id {id} out of range"))?;
    KemSuite::from_id(id).map_err(|e| e.to_string())
}

/// Re-derive every stored vector from its stored seed and inputs and compare.
pub fn regenerate_stored(doc: &Value) -> Res<Vec<String>> {
    let mut out = Vec::new();
    for s in json::array_field(doc, "suites", "seal.json")? {
        let suite = suite_of(s)?;
        let vectors = json::array_field(s, "vectors", suite.name())?;
        if vectors.len() < PER_SUITE {
            out.push(format!("{}: only {} vectors", suite.name(), vectors.len()));
        }
        for v in vectors {
            let index = usize::try_from(json::u64_field(v, "index", suite.name())?)
                .map_err(|e| e.to_string())?;
            let ctx = format!("{} vector {index}", suite.name());
            let seed_bytes = json::hex_field(v, "seed", &ctx)?;
            let aad = json::hex_field(v, "aad", &ctx)?;
            let pt = json::hex_field(v, "plaintext", &ctx)?;
            compare(
                &ctx,
                v,
                &vector(suite, index, &seed_bytes, &aad, &pt)?,
                &mut out,
            );
        }
    }
    Ok(out)
}

/// Independently re-verify the stored full-hex vector of every suite.
pub fn verify_stored(doc: &Value) -> Res<Vec<String>> {
    let mut out = Vec::new();
    for s in json::array_field(doc, "suites", "seal.json")? {
        let suite = suite_of(s)?;
        let first = json::array_field(s, "vectors", suite.name())?
            .first()
            .ok_or_else(|| format!("{}: no vectors", suite.name()))?;
        let ctx = format!("{} vector 0", suite.name());
        let pk_w = json::hex_field(first, "public_key", &ctx)?;
        let sk_w = json::hex_field(first, "secret_key", &ctx)?;
        let sealed = json::hex_field(first, "sealed_box", &ctx)?;
        let aad = json::hex_field(first, "aad", &ctx)?;
        let pt = json::hex_field(first, "plaintext", &ctx)?;
        check_digest(&ctx, first, &pk_w, "public_key_sha3_256", &mut out);
        check_digest(&ctx, first, &sk_w, "secret_key_sha3_256", &mut out);
        check_digest(&ctx, first, &sealed, "sealed_box_sha3_256", &mut out);

        let sbox = SealedBox::new(suite);
        let pk = HybridPublicKey::from_bytes(&pk_w).map_err(lib_err(&ctx))?;
        let sk = HybridSecretKey::from_bytes(&sk_w).map_err(lib_err(&ctx))?;
        match sbox.open(&sk, &aad, &sealed) {
            Ok(p) if p.expose() == pt.as_slice() => {}
            Ok(_) => out.push(format!(
                "{ctx}: stored sealed box opens to a different plaintext"
            )),
            Err(e) => out.push(format!("{ctx}: stored sealed box does not open: {e}")),
        }
        let fresh = sbox
            .seal(&pk, b"pair check", b"x", &mut OsEntropy::new())
            .map_err(lib_err(&ctx))?;
        if sbox.open(&sk, b"pair check", &fresh).is_err() {
            out.push(format!("{ctx}: stored public and secret key do not match"));
        }
        for (n, neg) in json::array_field(first, "negative", &ctx)?
            .iter()
            .enumerate()
        {
            let nctx = format!("{ctx} negative {n}");
            let kind = json::str_field(neg, "kind", &nctx)?;
            let opened = match kind {
                "tampered_sealed_box" => {
                    let offset = usize::try_from(json::u64_field(neg, "wire_offset", &nctx)?)
                        .map_err(|e| e.to_string())?;
                    let mask = *json::hex_field(neg, "xor_mask", &nctx)?
                        .first()
                        .ok_or_else(|| format!("{nctx}: empty xor_mask"))?;
                    let tampered = flipped(&sealed, offset, mask)?;
                    check_digest(
                        &nctx,
                        neg,
                        &tampered,
                        "tampered_sealed_box_sha3_256",
                        &mut out,
                    );
                    sbox.open(&sk, &aad, &tampered).is_ok()
                }
                "modified_aad" => {
                    let other = json::hex_field(neg, "aad", &nctx)?;
                    sbox.open(&sk, &other, &sealed).is_ok()
                }
                other => {
                    out.push(format!("{nctx}: unknown kind {other}"));
                    false
                }
            };
            if opened {
                out.push(format!("{nctx}: negative vector opened (must fail)"));
            }
        }
    }
    Ok(out)
}
