//! Known-answer vectors for VYRA's own formats (gate F5).
//!
//! Every vector is generated from a fixed seed through
//! `DeterministicEntropy::from_seed`. Large objects are stored as SHA3-256
//! digests of their wire encoding; the first vector of every suite also
//! stores every object in full hex so third parties can test parsers.
//!
//! `vectors` writes the files; `vectors --check` regenerates them in memory,
//! byte-compares, re-derives each stored vector from its stored seed and
//! compares field by field, and independently re-verifies the stored full-hex
//! objects (decapsulate, verify, open, hand-framed combiner).

mod combiner;
mod kem;
mod readme;
mod seal;
mod sig;

use std::path::Path;

use serde_json::Value;
use sha3::{Digest, Sha3_256};

use crate::{Res, hex, json};

/// Vectors per suite.
pub const PER_SUITE: usize = 5;

/// One vector file: its name and generator / checker.
struct VectorFile {
    name: &'static str,
    generate: fn() -> Res<Value>,
    verify_stored: fn(&Value) -> Res<Vec<String>>,
    regenerate_stored: fn(&Value) -> Res<Vec<String>>,
}

const FILES: [VectorFile; 4] = [
    VectorFile {
        name: "kem.json",
        generate: kem::generate,
        verify_stored: kem::verify_stored,
        regenerate_stored: kem::regenerate_stored,
    },
    VectorFile {
        name: "sig.json",
        generate: sig::generate,
        verify_stored: sig::verify_stored,
        regenerate_stored: sig::regenerate_stored,
    },
    VectorFile {
        name: "seal.json",
        generate: seal::generate,
        verify_stored: seal::verify_stored,
        regenerate_stored: seal::regenerate_stored,
    },
    VectorFile {
        name: "combiner.json",
        generate: combiner::generate,
        verify_stored: combiner::verify_stored,
        regenerate_stored: combiner::regenerate_stored,
    },
];

/// Message printed by a successful `vectors --check`; the clone gate (D5) looks for it.
pub const CHECK_OK_MARKER: &str = "vectors --check: OK";

/// Generate every file in memory: `(file name, contents)`.
pub fn generate_all() -> Res<Vec<(String, String)>> {
    let mut out = Vec::new();
    for f in &FILES {
        let v = (f.generate)()?;
        out.push((f.name.to_string(), json::to_canonical(&v)));
    }
    out.push(("README.md".to_string(), readme::text()));
    Ok(out)
}

/// Entry point for `cargo xtask vectors [--check]`. Returns `Ok(false)` on mismatch.
pub fn run(root: &Path, check_only: bool) -> Res<bool> {
    let dir = root.join("vectors");
    if check_only {
        let problems = check(&dir)?;
        if problems.is_empty() {
            println!("{CHECK_OK_MARKER} (files byte-identical, stored vectors re-verified)");
            Ok(true)
        } else {
            eprintln!("vectors --check: FAILED ({} problem(s))", problems.len());
            for p in &problems {
                eprintln!("  - {p}");
            }
            Ok(false)
        }
    } else {
        std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        for (name, text) in generate_all()? {
            let path = dir.join(&name);
            std::fs::write(&path, text.as_bytes())
                .map_err(|e| format!("write {}: {e}", path.display()))?;
            println!("wrote vectors/{name} ({} bytes)", text.len());
        }
        Ok(true)
    }
}

/// All problems found by `--check`, empty if everything matches.
pub fn check(dir: &Path) -> Res<Vec<String>> {
    let mut problems = Vec::new();
    let generated = generate_all()?;
    // 1. Byte comparison of every file.
    for (name, text) in &generated {
        let path = dir.join(name);
        match std::fs::read(&path) {
            Err(e) => problems.push(format!("vectors/{name}: cannot read: {e}")),
            Ok(bytes) => {
                if bytes != text.as_bytes() {
                    let file_text = String::from_utf8_lossy(&bytes);
                    let detail = match json::first_line_diff(&file_text, text) {
                        Some((line, f, g)) => format!(
                            "first difference at line {line}:\n      file:      {}\n      generated: {}",
                            clip(&f),
                            clip(&g)
                        ),
                        None => "contents differ (line endings or trailing bytes)".to_string(),
                    };
                    problems.push(format!(
                        "vectors/{name}: differs from regenerated output; {detail}"
                    ));
                }
            }
        }
    }
    // 2. Semantic checks of what is stored.
    for f in &FILES {
        let path = dir.join(f.name);
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue; // already reported
        };
        let value = match json::parse(&text, f.name) {
            Ok(v) => v,
            Err(e) => {
                problems.push(format!("vectors/{e}"));
                continue;
            }
        };
        for (label, func) in [
            ("re-derivation from stored seeds", f.regenerate_stored),
            ("independent re-verification", f.verify_stored),
        ] {
            match func(&value) {
                Ok(found) => {
                    for p in found {
                        problems.push(format!("vectors/{} ({label}): {p}", f.name));
                    }
                }
                Err(e) => problems.push(format!("vectors/{} ({label}): {e}", f.name)),
            }
        }
    }
    Ok(problems)
}

fn clip(s: &str) -> String {
    if s.chars().count() > 160 {
        let head: String = s.chars().take(156).collect();
        format!("{head}...")
    } else {
        s.to_string()
    }
}

/// SHA3-256 of `bytes` as hex.
pub fn sha3_hex(bytes: &[u8]) -> String {
    hex::encode(&Sha3_256::digest(bytes))
}

/// The seed of vector `index` in `suite_name` of file kind `kind`.
pub fn seed(kind: &str, suite_id: u8, index: usize) -> Vec<u8> {
    format!("VYRA-KAT-v1/{kind}/suite-{suite_id}/vector-{index}").into_bytes()
}

/// A copy of `bytes` with `bytes[offset] ^= mask`.
pub fn flipped(bytes: &[u8], offset: usize, mask: u8) -> Res<Vec<u8>> {
    let mut out = bytes.to_vec();
    let b = out.get_mut(offset).ok_or_else(|| {
        format!(
            "tamper offset {offset} out of range ({} bytes)",
            bytes.len()
        )
    })?;
    *b ^= mask;
    Ok(out)
}

/// Map a library error to a message.
pub fn lib_err(ctx: &str) -> impl Fn(vyra_core::Error) -> String + '_ {
    move |e| format!("{ctx}: {e}")
}

/// Compare a stored vector with one regenerated from its stored seed.
pub fn compare(ctx: &str, stored: &Value, computed: &Value, out: &mut Vec<String>) {
    let mut diffs = Vec::new();
    json::diff("", stored, computed, &mut diffs, 8);
    for d in diffs {
        out.push(format!("{ctx}: {d}"));
    }
}

/// Check that `bytes` hash to the digest stored under `digest_key`.
pub fn check_digest(ctx: &str, v: &Value, bytes: &[u8], digest_key: &str, out: &mut Vec<String>) {
    match json::str_field(v, digest_key, ctx) {
        Ok(d) if d == sha3_hex(bytes) => {}
        Ok(d) => out.push(format!(
            "{ctx}: SHA3-256 of stored full hex is {}, but `{digest_key}` says {d}",
            sha3_hex(bytes)
        )),
        Err(e) => out.push(e),
    }
}
