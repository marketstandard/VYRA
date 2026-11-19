//! Documentation gates D3 (docs match code) and D4 (paper compiles).

use std::collections::BTreeSet;

use serde_json::Value;

use super::{Ctx, Finding, secs};
use crate::exec;
use crate::report::Status;

/// Every integer written in `text`. Digit groups joined by `,`, `_` or a
/// thin / narrow no-break space (e.g. `10,089`) count as one number.
pub fn numbers_in(text: &str) -> BTreeSet<u64> {
    let mut out = BTreeSet::new();
    let chars: Vec<char> = text.chars().collect();
    let mut current = String::new();
    let mut i = 0usize;
    while let Some(&c) = chars.get(i) {
        if c.is_ascii_digit() {
            current.push(c);
        } else if matches!(c, ',' | '_' | '\u{2009}' | '\u{202f}')
            && !current.is_empty()
            && chars.get(i + 1).is_some_and(char::is_ascii_digit)
        {
            // group separator inside a number
        } else if !current.is_empty() {
            if let Ok(n) = current.parse() {
                out.insert(n);
            }
            current.clear();
        }
        i += 1;
    }
    if let Ok(n) = current.parse() {
        out.insert(n);
    }
    out
}

/// `(what, value)` pairs D3 requires in SPEC.md, from a sizes document.
pub fn required_numbers(sizes: &Value) -> Vec<(String, u64)> {
    let mut out = Vec::new();
    for (key, fields) in [
        ("kem_suites", ["public_key", "secret_key", "ciphertext"]),
        ("sig_suites", ["public_key", "secret_key", "signature"]),
    ] {
        for s in sizes
            .get(key)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let name = s.get("suite").and_then(Value::as_str).unwrap_or("?");
            for form in ["raw", "wire"] {
                for f in fields {
                    if let Some(n) = s.get(form).and_then(|v| v.get(f)).and_then(Value::as_u64) {
                        out.push((format!("{name} {form} {f}"), n));
                    }
                }
            }
        }
    }
    out
}

/// Suite names (identifiers) listed in a sizes document.
pub fn suite_names(sizes: &Value) -> Vec<String> {
    let mut out = Vec::new();
    for key in ["kem_suites", "sig_suites"] {
        for s in sizes
            .get(key)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(n) = s.get("suite").and_then(Value::as_str) {
                out.push(n.to_string());
            }
        }
    }
    out
}

/// D3: every suite-level raw and wire size in `results/sizes.json` and every
/// suite identifier appears in `docs/SPEC.md`.
pub fn d3(ctx: &mut Ctx, _id: &str) -> Finding {
    let method = "every suite's raw+wire pk/sk/ct/sig size from results/sizes.json appears as a number in docs/SPEC.md, and every suite name appears";
    let sizes = match std::fs::read_to_string(ctx.root.join("results/sizes.json"))
        .map_err(|e| format!("results/sizes.json: {e}"))
        .and_then(|t| crate::json::parse(&t, "results/sizes.json"))
    {
        Ok(v) => v,
        Err(e) => return Finding::check(method, false, e),
    };
    let Ok(spec) = std::fs::read_to_string(ctx.root.join("docs/SPEC.md")) else {
        return Finding::check(method, false, "docs/SPEC.md does not exist");
    };
    let numbers = numbers_in(&spec);
    let required = required_numbers(&sizes);
    let mut missing: Vec<String> = required
        .iter()
        .filter(|(_, n)| !numbers.contains(n))
        .map(|(w, n)| format!("{w} = {n}"))
        .collect();
    for name in suite_names(&sizes) {
        if !spec.contains(&name) {
            missing.push(format!("suite identifier {name}"));
        }
    }
    if required.is_empty() {
        missing.push("results/sizes.json has no suite sizes".to_string());
    }
    if missing.is_empty() {
        Finding::check(
            method,
            true,
            format!(
                "{} sizes and all suite identifiers found in docs/SPEC.md",
                required.len()
            ),
        )
    } else {
        Finding::check(
            method,
            false,
            format!(
                "not found in docs/SPEC.md ({}):\n{}",
                missing.len(),
                missing.join("\n")
            ),
        )
    }
}

/// D4: `typst compile paper/vyra.typ paper/vyra.pdf`.
pub fn d4(ctx: &mut Ctx, _id: &str) -> Finding {
    let method = "typst compile paper/vyra.typ paper/vyra.pdf";
    if !ctx.root.join("paper/vyra.typ").is_file() {
        return Finding::check(method, false, "paper/vyra.typ does not exist");
    }
    if !exec::available("typst", &["--version"]) {
        return Finding {
            method: method.into(),
            status: Status::NotRun,
            exit_code: None,
            evidence: "NOT RUN: `typst` is not on PATH; the paper was NOT compiled".into(),
        };
    }
    let o = exec::run(
        &"typst".into(),
        &["compile", "paper/vyra.typ", "paper/vyra.pdf"],
        &ctx.root,
        &[],
    );
    Finding {
        method: method.into(),
        status: if o.success() {
            Status::Pass
        } else {
            Status::Fail
        },
        exit_code: o.code,
        evidence: format!(
            "exit {:?} ({})\n{}",
            o.code,
            secs(o.duration),
            exec::tail(&o.combined(), 12, 1500)
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn number_extraction() {
        let n = numbers_in("pk 1,184 bytes; sk=64, ct 10_089 and 2420.\n| 7 |x1y");
        for v in [1184, 64, 10089, 2420, 7, 1] {
            assert!(n.contains(&v), "{v}");
        }
        assert!(!n.contains(&184));
        assert!(numbers_in("a, 5").contains(&5));
        assert!(numbers_in("1, 2").contains(&1));
    }

    #[test]
    fn required_from_sizes() {
        let sizes = json!({
            "kem_suites": [{"suite": "VYRA-KEM-1", "raw": {"public_key": 10, "secret_key": 2, "ciphertext": 3, "shared_secret": 32}, "wire": {"public_key": 17, "secret_key": 9, "ciphertext": 10}}],
            "sig_suites": [{"suite": "VYRA-SIG-2", "raw": {"public_key": 4, "secret_key": 5, "signature": 6}, "wire": {"public_key": 11, "secret_key": 12, "signature": 13}}]
        });
        let r = required_numbers(&sizes);
        assert_eq!(r.len(), 12);
        assert!(r.contains(&("VYRA-KEM-1 wire ciphertext".to_string(), 10)));
        assert_eq!(suite_names(&sizes), vec!["VYRA-KEM-1", "VYRA-SIG-2"]);
    }
}
