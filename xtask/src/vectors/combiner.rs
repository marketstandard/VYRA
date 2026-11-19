//! `vectors/combiner.json`: the hybrid KEM combiner on small explicit inputs.
//!
//! Every output is computed twice and the two must agree before anything is
//! written: once with `vyra_kem::combine`, once by hand-framing the inputs
//! into SHA3-256 here (independent of `vyra_core::Transcript`).

use serde_json::{Value, json};
use sha3::{Digest, Sha3_256};
use vyra_kem::{COMBINER_LABEL, combine};

use crate::{Res, hex, json};

/// The inputs of one combiner vector.
#[derive(Debug, Clone)]
struct Inputs {
    note: &'static str,
    suite_id: u8,
    ss1: Vec<u8>,
    ss2: Vec<u8>,
    ct1: Vec<u8>,
    ct2: Vec<u8>,
    pk1: Vec<u8>,
    pk2: Vec<u8>,
}

fn counting(start: u8, n: u8) -> Vec<u8> {
    (0..n).map(|i| start.wrapping_add(i)).collect()
}

fn cases() -> Vec<Inputs> {
    let base = Inputs {
        note: "baseline: 32-byte secrets 00..1f / 20..3f, short ASCII ct/pk",
        suite_id: 1,
        ss1: counting(0x00, 32),
        ss2: counting(0x20, 32),
        ct1: b"ct1".to_vec(),
        ct2: b"ct2".to_vec(),
        pk1: b"pk1".to_vec(),
        pk2: b"pk2".to_vec(),
    };
    vec![
        base.clone(),
        Inputs {
            note: "baseline with suite id 3 (suite binding)",
            suite_id: 3,
            ..base.clone()
        },
        Inputs {
            note: "baseline with ss1 and ss2 swapped (order binding)",
            ss1: base.ss2.clone(),
            ss2: base.ss1.clone(),
            ..base.clone()
        },
        Inputs {
            note: "all fields empty, suite id 5",
            suite_id: 5,
            ss1: Vec::new(),
            ss2: Vec::new(),
            ct1: Vec::new(),
            ct2: Vec::new(),
            pk1: Vec::new(),
            pk2: Vec::new(),
        },
        Inputs {
            note: "framing: ct1 = \"ab\", ct2 = \"c\"",
            ct1: b"ab".to_vec(),
            ct2: b"c".to_vec(),
            ..base.clone()
        },
        Inputs {
            note: "framing: ct1 = \"a\", ct2 = \"bc\" (same concatenation, different key)",
            ct1: b"a".to_vec(),
            ct2: b"bc".to_vec(),
            ..base.clone()
        },
        Inputs {
            note: "baseline with pk2 changed in one bit (public-key binding)",
            pk2: b"pk3".to_vec(),
            ..base
        },
    ]
}

/// SHA3-256 over `frame(label) ‖ frame([suite]) ‖ frame(ss1) ‖ ... ‖ frame(pk2)`
/// with `frame(x) = u64_be(len(x)) ‖ x`, written out by hand.
fn hand_framed(i: &Inputs) -> [u8; 32] {
    let suite = [i.suite_id];
    let fields: [&[u8]; 8] = [
        COMBINER_LABEL,
        &suite,
        &i.ss1,
        &i.ss2,
        &i.ct1,
        &i.ct2,
        &i.pk1,
        &i.pk2,
    ];
    let mut framed = Vec::new();
    for f in fields {
        framed.extend_from_slice(&(f.len() as u64).to_be_bytes());
        framed.extend_from_slice(f);
    }
    Sha3_256::digest(&framed).into()
}

fn via_library(i: &Inputs) -> Vec<u8> {
    combine(i.suite_id, &i.ss1, &i.ss2, &i.ct1, &i.ct2, &i.pk1, &i.pk2)
        .expose()
        .to_vec()
}

fn vector(index: usize, i: &Inputs) -> Res<Value> {
    let lib = via_library(i);
    let hand = hand_framed(i);
    if lib != hand {
        return Err(format!(
            "combiner vector {index}: vyra_kem::combine = {}, hand-framed SHA3-256 = {}",
            hex::encode(&lib),
            hex::encode(&hand)
        ));
    }
    Ok(json!({
        "index": index,
        "note": i.note,
        "suite_id": i.suite_id,
        "ss1": hex::encode(&i.ss1),
        "ss2": hex::encode(&i.ss2),
        "ct1": hex::encode(&i.ct1),
        "ct2": hex::encode(&i.ct2),
        "pk1": hex::encode(&i.pk1),
        "pk2": hex::encode(&i.pk2),
        "output": hex::encode(&hand),
    }))
}

/// The whole `combiner.json` document.
pub fn generate() -> Res<Value> {
    let mut vectors = Vec::new();
    let mut outputs = Vec::new();
    for (index, case) in cases().iter().enumerate() {
        let v = vector(index, case)?;
        let out = json::str_field(&v, "output", "combiner")?.to_string();
        if outputs.contains(&out) {
            return Err(format!(
                "combiner vector {index}: output collides with an earlier vector"
            ));
        }
        outputs.push(out);
        vectors.push(v);
    }
    Ok(json!({
        "title": "VYRA-KEM v1 combiner known-answer vectors",
        "generator": "cargo xtask vectors",
        "definition": "output = SHA3-256( frame(\"VYRA-KEM-v1\") || frame([suite_id]) || frame(ss1) || frame(ss2) || frame(ct1) || frame(ct2) || frame(pk1) || frame(pk2) ), frame(x) = u64_be(len(x)) || x (docs/DECISIONS.md D-01)",
        "label": hex::encode(COMBINER_LABEL),
        "cross_check": "each output was computed with vyra_kem::combine and independently by hand-framing into SHA3-256 in xtask; both agreed",
        "note": "inputs are deliberately small and not of real component lengths; combine() does not check lengths",
        "vectors": vectors,
    }))
}

fn inputs_of(v: &Value, ctx: &str) -> Res<Inputs> {
    let id = json::u64_field(v, "suite_id", ctx)?;
    Ok(Inputs {
        note: "",
        suite_id: u8::try_from(id).map_err(|_| format!("{ctx}: suite id {id} out of range"))?,
        ss1: json::hex_field(v, "ss1", ctx)?,
        ss2: json::hex_field(v, "ss2", ctx)?,
        ct1: json::hex_field(v, "ct1", ctx)?,
        ct2: json::hex_field(v, "ct2", ctx)?,
        pk1: json::hex_field(v, "pk1", ctx)?,
        pk2: json::hex_field(v, "pk2", ctx)?,
    })
}

/// Recompute every stored vector from its stored inputs (both ways).
pub fn verify_stored(doc: &Value) -> Res<Vec<String>> {
    let mut out = Vec::new();
    let vectors = json::array_field(doc, "vectors", "combiner.json")?;
    if vectors.len() < super::PER_SUITE {
        out.push(format!("only {} vectors", vectors.len()));
    }
    for (n, v) in vectors.iter().enumerate() {
        let ctx = format!("combiner vector {n}");
        let i = inputs_of(v, &ctx)?;
        let stored = json::hex_field(v, "output", &ctx)?;
        let hand = hand_framed(&i);
        let lib = via_library(&i);
        if stored != hand {
            out.push(format!(
                "{ctx}: hand-framed SHA3-256 gives {}, file says {}",
                hex::encode(&hand),
                hex::encode(&stored)
            ));
        }
        if stored != lib {
            out.push(format!(
                "{ctx}: vyra_kem::combine gives {}, file says {}",
                hex::encode(&lib),
                hex::encode(&stored)
            ));
        }
    }
    Ok(out)
}

/// The combiner vectors have no seeds: regeneration is the stored-input
/// recomputation of [`verify_stored`] plus the byte comparison.
pub fn regenerate_stored(doc: &Value) -> Res<Vec<String>> {
    let mut out = Vec::new();
    let generated = generate()?;
    super::compare("combiner.json", doc, &generated, &mut out);
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn hand_framing_matches_library_and_is_injective() {
        let c = cases();
        assert!(c.len() >= 5);
        for i in &c {
            assert_eq!(hand_framed(i).to_vec(), via_library(i));
        }
        // ct1/ct2 boundary shift changes the key.
        let a = c.iter().find(|i| i.ct1 == b"ab").unwrap();
        let b = c.iter().find(|i| i.ct1 == b"a").unwrap();
        assert_ne!(hand_framed(a), hand_framed(b));
    }
}
