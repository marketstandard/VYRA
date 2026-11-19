//! `cargo xtask sizes`: object sizes from code constants (gate P2), each
//! asserted equal to the length of an actually generated object.

use std::fmt::Write as _;
use std::path::Path;

use serde_json::{Value, json};
use vyra_core::wire::HEADER_LEN;
use vyra_core::{DeterministicEntropy, Kem, SignatureScheme};
use vyra_kem::{Hqc128, Hqc192, Hqc256, HybridKem, KemSuite, MlKem512, MlKem768, MlKem1024};
use vyra_seal::{SealedBox, TAG_LEN};
use vyra_sig::{
    CompositeSignature, Ed25519, MlDsa44, MlDsa65, MlDsa87, SigSuite, SlhDsaShake128s,
    SlhDsaShake192s, SlhDsaShake256s,
};

use crate::{Res, json};

fn mismatch(what: &str, constant: usize, actual: usize) -> String {
    format!("{what}: constant says {constant} bytes, generated object has {actual}")
}

fn eq(what: &str, constant: usize, actual: usize) -> Res<()> {
    if constant == actual {
        Ok(())
    } else {
        Err(mismatch(what, constant, actual))
    }
}

fn lib(what: &str) -> impl Fn(vyra_core::Error) -> String + '_ {
    move |e| format!("{what}: {e}")
}

fn kem_component(k: &dyn Kem) -> Res<Value> {
    let mut rng = DeterministicEntropy::from_seed(b"VYRA-sizes");
    let (pk, sk) = k.generate_keypair(&mut rng).map_err(lib(k.name()))?;
    let (ct, ss) = k.encapsulate(&pk, &mut rng).map_err(lib(k.name()))?;
    eq(
        &format!("{} public key", k.name()),
        k.public_key_len(),
        pk.len(),
    )?;
    eq(
        &format!("{} secret key", k.name()),
        k.secret_key_len(),
        sk.len(),
    )?;
    eq(
        &format!("{} ciphertext", k.name()),
        k.ciphertext_len(),
        ct.len(),
    )?;
    eq(
        &format!("{} shared secret", k.name()),
        k.shared_secret_len(),
        ss.len(),
    )?;
    Ok(json!({
        "name": k.name(),
        "kind": "kem",
        "level": k.level().category(),
        "public_key": k.public_key_len(),
        "secret_key": k.secret_key_len(),
        "ciphertext": k.ciphertext_len(),
        "shared_secret": k.shared_secret_len(),
    }))
}

fn sig_component(s: &dyn SignatureScheme) -> Res<Value> {
    let mut rng = DeterministicEntropy::from_seed(b"VYRA-sizes");
    let (pk, sk) = s.generate_keypair(&mut rng).map_err(lib(s.name()))?;
    let sig = s
        .sign(sk.expose(), b"sizes", &mut rng)
        .map_err(lib(s.name()))?;
    eq(
        &format!("{} public key", s.name()),
        s.public_key_len(),
        pk.len(),
    )?;
    eq(
        &format!("{} secret key", s.name()),
        s.secret_key_len(),
        sk.len(),
    )?;
    eq(
        &format!("{} signature", s.name()),
        s.signature_len(),
        sig.len(),
    )?;
    Ok(json!({
        "name": s.name(),
        "kind": "signature",
        "level": s.level().category(),
        "public_key": s.public_key_len(),
        "secret_key": s.secret_key_len(),
        "signature": s.signature_len(),
    }))
}

fn kem_suite(suite: KemSuite) -> Res<Value> {
    let n = suite.name();
    let kem = HybridKem::new(suite);
    let mut rng = DeterministicEntropy::from_seed(b"VYRA-sizes");
    let (pk, sk) = kem.generate(&mut rng).map_err(lib(n))?;
    let (ct, ss) = kem.encapsulate_to(&pk, &mut rng).map_err(lib(n))?;
    eq(
        &format!("{n} raw public key"),
        suite.public_key_len(),
        pk.as_raw().len(),
    )?;
    eq(
        &format!("{n} raw secret key"),
        suite.secret_key_len(),
        sk.expose_raw().len(),
    )?;
    eq(
        &format!("{n} raw ciphertext"),
        suite.ciphertext_len(),
        ct.as_raw().len(),
    )?;
    eq(
        &format!("{n} shared secret"),
        suite.shared_secret_len(),
        ss.len(),
    )?;
    eq(
        &format!("{n} wire public key"),
        suite.encoded_public_key_len(),
        pk.to_bytes().len(),
    )?;
    eq(
        &format!("{n} wire secret key"),
        suite.encoded_secret_key_len(),
        sk.to_bytes().len(),
    )?;
    eq(
        &format!("{n} wire ciphertext"),
        suite.encoded_ciphertext_len(),
        ct.to_bytes().len(),
    )?;
    eq(
        &format!("{n} Kem::public_key_len"),
        suite.public_key_len(),
        kem.public_key_len(),
    )?;
    let (c1, c2) = suite.component_names();
    Ok(json!({
        "suite": n,
        "suite_id": suite.id(),
        "level": suite.level().category(),
        "components": [c1, c2],
        "raw": {
            "public_key": suite.public_key_len(),
            "secret_key": suite.secret_key_len(),
            "ciphertext": suite.ciphertext_len(),
            "shared_secret": suite.shared_secret_len(),
        },
        "wire": {
            "public_key": suite.encoded_public_key_len(),
            "secret_key": suite.encoded_secret_key_len(),
            "ciphertext": suite.encoded_ciphertext_len(),
        },
    }))
}

fn sig_suite(suite: SigSuite) -> Res<Value> {
    let n = suite.name();
    let scheme = CompositeSignature::new(suite);
    let mut rng = DeterministicEntropy::from_seed(b"VYRA-sizes");
    let (pk, sk) = scheme.generate(&mut rng).map_err(lib(n))?;
    let sig = scheme.sign(&sk, b"sizes", b"", &mut rng).map_err(lib(n))?;
    eq(
        &format!("{n} raw public key"),
        suite.public_key_len(),
        pk.as_raw().len(),
    )?;
    eq(
        &format!("{n} raw secret key"),
        suite.secret_key_len(),
        sk.expose_raw().len(),
    )?;
    eq(
        &format!("{n} raw signature"),
        suite.signature_len(),
        sig.as_raw().len(),
    )?;
    eq(
        &format!("{n} wire public key"),
        suite.encoded_public_key_len(),
        pk.to_bytes().len(),
    )?;
    eq(
        &format!("{n} wire secret key"),
        suite.encoded_secret_key_len(),
        sk.to_bytes().len(),
    )?;
    eq(
        &format!("{n} wire signature"),
        suite.encoded_signature_len(),
        sig.to_bytes().len(),
    )?;
    Ok(json!({
        "suite": n,
        "suite_id": suite.id(),
        "level": suite.level().category(),
        "family": if suite.is_dual_pq() { "dual-pq" } else { "transition" },
        "components": [suite.first().name(), suite.second().name()],
        "raw": {
            "public_key": suite.public_key_len(),
            "secret_key": suite.secret_key_len(),
            "signature": suite.signature_len(),
        },
        "wire": {
            "public_key": suite.encoded_public_key_len(),
            "secret_key": suite.encoded_secret_key_len(),
            "signature": suite.encoded_signature_len(),
        },
    }))
}

fn seal_suite(suite: KemSuite) -> Res<Value> {
    let n = suite.name();
    let mut rng = DeterministicEntropy::from_seed(b"VYRA-sizes");
    let (pk, _sk) = HybridKem::new(suite).generate(&mut rng).map_err(lib(n))?;
    let sbox = SealedBox::new(suite);
    let overhead = SealedBox::overhead(suite);
    for len in [0usize, 1, 1000] {
        let sealed = sbox
            .seal(&pk, b"", &vec![0u8; len], &mut rng)
            .map_err(lib(n))?;
        eq(
            &format!("{n} sealed box of {len} bytes"),
            len + overhead,
            sealed.len(),
        )?;
    }
    eq(
        &format!("{n} overhead decomposition"),
        HEADER_LEN + suite.ciphertext_len() + TAG_LEN,
        overhead,
    )?;
    Ok(json!({
        "suite": n,
        "suite_id": suite.id(),
        "overhead": overhead,
        "header": HEADER_LEN,
        "kem_ciphertext": suite.ciphertext_len(),
        "tag": TAG_LEN,
    }))
}

/// Compute the sizes document, asserting every constant against a generated object.
pub fn compute() -> Res<Value> {
    let kem_components: Vec<&dyn Kem> =
        vec![&MlKem512, &MlKem768, &MlKem1024, &Hqc128, &Hqc192, &Hqc256];
    let sig_components: Vec<&dyn SignatureScheme> = vec![
        &MlDsa44,
        &MlDsa65,
        &MlDsa87,
        &Ed25519,
        &SlhDsaShake128s,
        &SlhDsaShake192s,
        &SlhDsaShake256s,
    ];
    let mut components = Vec::new();
    for k in kem_components {
        components.push(kem_component(k)?);
    }
    for s in sig_components {
        components.push(sig_component(s)?);
    }
    let kem_suites = KemSuite::all()
        .into_iter()
        .map(kem_suite)
        .collect::<Res<Vec<_>>>()?;
    let sig_suites = SigSuite::all()
        .into_iter()
        .map(sig_suite)
        .collect::<Res<Vec<_>>>()?;
    let seal_suites = KemSuite::all()
        .into_iter()
        .map(seal_suite)
        .collect::<Res<Vec<_>>>()?;
    Ok(json!({
        "generator": "cargo xtask sizes",
        "unit": "bytes",
        "wire_header_len": HEADER_LEN,
        "note": "raw = algorithm encoding; wire = 7-byte VYRA header + raw. Every value is a code constant asserted equal to the length of a generated object.",
        "components": components,
        "kem_suites": kem_suites,
        "sig_suites": sig_suites,
        "seal_suites": seal_suites,
    }))
}

/// Markdown tables for the sizes document.
pub fn markdown(doc: &Value) -> String {
    let mut s = String::from(
        "# VYRA object sizes\n\nGenerated by `cargo xtask sizes` from code constants; every value was \
         asserted equal to the length of an actually generated object. Bytes. \
         *Wire* = 7-byte VYRA header + raw encoding.\n\n## Components\n\n\
         | component | category | public key | secret key | ciphertext / signature | shared secret |\n\
         |---|---|---|---|---|---|\n",
    );
    let num = |v: &Value, k: &str| {
        v.get(k)
            .and_then(Value::as_u64)
            .map_or("-".to_string(), |n| n.to_string())
    };
    let text = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).unwrap_or("?").to_string();
    let list = |v: &Value, k: &str| -> Vec<Value> {
        v.get(k)
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
    };
    for c in list(doc, "components") {
        let third = if c.get("ciphertext").is_some() {
            num(&c, "ciphertext")
        } else {
            num(&c, "signature")
        };
        let _ = writeln!(
            s,
            "| {} | {} | {} | {} | {} | {} |",
            text(&c, "name"),
            num(&c, "level"),
            num(&c, "public_key"),
            num(&c, "secret_key"),
            third,
            num(&c, "shared_secret")
        );
    }
    s.push_str(
        "\n## Hybrid KEM suites\n\n\
         | suite | id | components | pk raw | pk wire | sk raw | sk wire | ct raw | ct wire | shared secret |\n\
         |---|---|---|---|---|---|---|---|---|---|\n",
    );
    for k in list(doc, "kem_suites") {
        let raw = k.get("raw").cloned().unwrap_or_default();
        let wire = k.get("wire").cloned().unwrap_or_default();
        let comps: Vec<String> = list(&k, "components")
            .iter()
            .filter_map(|c| c.as_str().map(str::to_string))
            .collect();
        let _ = writeln!(
            s,
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |",
            text(&k, "suite"),
            num(&k, "suite_id"),
            comps.join(" + "),
            num(&raw, "public_key"),
            num(&wire, "public_key"),
            num(&raw, "secret_key"),
            num(&wire, "secret_key"),
            num(&raw, "ciphertext"),
            num(&wire, "ciphertext"),
            num(&raw, "shared_secret")
        );
    }
    s.push_str(
        "\n## Composite signature suites\n\n\
         Transition suites pair ML-DSA with Ed25519 (classical fallback); dual \
         post-quantum suites pair ML-DSA with SLH-DSA (two post-quantum assumptions; \
         large signatures, signing takes seconds).\n\n\
         | suite | family | id | components | pk raw | pk wire | sk raw | sk wire | sig raw | sig wire |\n\
         |---|---|---|---|---|---|---|---|---|---|\n",
    );
    for k in list(doc, "sig_suites") {
        let raw = k.get("raw").cloned().unwrap_or_default();
        let wire = k.get("wire").cloned().unwrap_or_default();
        let comps: Vec<String> = list(&k, "components")
            .iter()
            .filter_map(|c| c.as_str().map(str::to_string))
            .collect();
        let _ = writeln!(
            s,
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |",
            text(&k, "suite"),
            text(&k, "family"),
            num(&k, "suite_id"),
            comps.join(" + "),
            num(&raw, "public_key"),
            num(&wire, "public_key"),
            num(&raw, "secret_key"),
            num(&wire, "secret_key"),
            num(&raw, "signature"),
            num(&wire, "signature")
        );
    }
    s.push_str(
        "\n## Sealed box overhead\n\n\
         | KEM suite | header | KEM ciphertext | tag | overhead |\n|---|---|---|---|---|\n",
    );
    for k in list(doc, "seal_suites") {
        let _ = writeln!(
            s,
            "| {} | {} | {} | {} | {} |",
            text(&k, "suite"),
            num(&k, "header"),
            num(&k, "kem_ciphertext"),
            num(&k, "tag"),
            num(&k, "overhead")
        );
    }
    s
}

/// Entries `results/sizes.json` must contain; problems as messages.
pub fn validate(doc: &Value) -> Vec<String> {
    let mut problems = Vec::new();
    let names = |key: &str, field: &str| -> Vec<String> {
        doc.get(key)
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.get(field).and_then(Value::as_str).map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    };
    let comps = names("components", "name");
    for c in [
        "ML-KEM-512",
        "ML-KEM-768",
        "ML-KEM-1024",
        "HQC-128",
        "HQC-192",
        "HQC-256",
        "ML-DSA-44",
        "ML-DSA-65",
        "ML-DSA-87",
        "Ed25519",
        "SLH-DSA-SHAKE-128s",
        "SLH-DSA-SHAKE-192s",
        "SLH-DSA-SHAKE-256s",
    ] {
        if !comps.iter().any(|n| n == c) {
            problems.push(format!("sizes.json: component {c} missing"));
        }
    }
    let lists: [(&str, &[&str]); 3] = [
        ("kem_suites", &["VYRA-KEM-1", "VYRA-KEM-3", "VYRA-KEM-5"]),
        (
            "sig_suites",
            &[
                "VYRA-SIG-2",
                "VYRA-SIG-3",
                "VYRA-SIG-5",
                "VYRA-SIG-PQ1",
                "VYRA-SIG-PQ3",
                "VYRA-SIG-PQ5",
            ],
        ),
        ("seal_suites", &["VYRA-KEM-1", "VYRA-KEM-3", "VYRA-KEM-5"]),
    ];
    for (key, suites) in lists {
        let present = names(key, "suite");
        for s in suites {
            if !present.iter().any(|n| n == s) {
                problems.push(format!("sizes.json: {key} entry {s} missing"));
            }
        }
    }
    problems
}

/// Entry point: compute, write JSON and markdown.
pub fn run(root: &Path) -> Res<()> {
    let doc = compute()?;
    let problems = validate(&doc);
    if !problems.is_empty() {
        return Err(problems.join("; "));
    }
    let dir = root.join("results");
    std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let jpath = dir.join("sizes.json");
    std::fs::write(&jpath, json::to_canonical(&doc))
        .map_err(|e| format!("write sizes.json: {e}"))?;
    std::fs::write(dir.join("sizes.md"), markdown(&doc))
        .map_err(|e| format!("write sizes.md: {e}"))?;
    println!(
        "wrote results/sizes.json and results/sizes.md (all sizes asserted against generated objects)"
    );
    Ok(())
}
