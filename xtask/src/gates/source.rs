//! Source inspection gates: S7 (no unsafe) and the code-inspection half of S9.

use super::{Ctx, Finding, cargo, crate_dirs, rel, rs_files};
use crate::report::Status;

/// Whether `text` has a `#![forbid(unsafe_code)]` line.
pub fn forbids_unsafe(text: &str) -> bool {
    text.lines().any(|l| l.trim() == "#![forbid(unsafe_code)]")
}

/// S7: every crate root (`crates/*/src/lib.rs`, `src/main.rs`, `src/bin/*.rs`)
/// and `xtask/src/main.rs` contains `#![forbid(unsafe_code)]`.
pub fn s7(ctx: &mut Ctx, _id: &str) -> Finding {
    let mut roots = Vec::new();
    let mut problems = Vec::new();
    for dir in crate_dirs(&ctx.root) {
        let mut found = false;
        for cand in [dir.join("src/lib.rs"), dir.join("src/main.rs")] {
            if cand.is_file() {
                roots.push(cand);
                found = true;
            }
        }
        if let Ok(rd) = std::fs::read_dir(dir.join("src/bin")) {
            for e in rd.flatten() {
                let p = e.path();
                if p.extension().is_some_and(|x| x == "rs") {
                    roots.push(p);
                    found = true;
                } else if p.join("main.rs").is_file() {
                    roots.push(p.join("main.rs"));
                    found = true;
                }
            }
        }
        if !found {
            problems.push(format!("{}: no crate root found", rel(&ctx.root, &dir)));
        }
    }
    roots.push(ctx.root.join("xtask/src/main.rs"));
    let mut checked = Vec::new();
    for r in &roots {
        let text = std::fs::read_to_string(r).unwrap_or_default();
        let name = rel(&ctx.root, r);
        if forbids_unsafe(&text) {
            checked.push(name);
        } else {
            problems.push(format!("{name}: missing #![forbid(unsafe_code)]"));
        }
    }
    let ok = problems.is_empty();
    let evidence = if ok {
        format!("#![forbid(unsafe_code)] in: {}", checked.join(", "))
    } else {
        problems.join("\n")
    };
    Finding::check(
        "scan crates/*/src/{lib.rs,main.rs,bin/*.rs} and xtask/src/main.rs",
        ok,
        evidence,
    )
}

/// Secret-named types (name contains "secret", case-insensitive) whose
/// `#[derive(...)]` includes `PartialEq`: `(line, type name)`.
///
/// For every `derive(` line mentioning `PartialEq`, the following lines are
/// skipped while they are attributes, doc comments or blank; the first item
/// line then names the type (`struct X` / `enum X`).
pub fn secret_partial_eq(text: &str) -> Vec<(usize, String)> {
    let lines: Vec<&str> = text.lines().collect();
    let mut out = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let t = line.trim();
        if !(t.starts_with("#[derive(") && t.contains("PartialEq")) {
            continue;
        }
        for next in lines.iter().skip(i + 1) {
            let n = next.trim();
            if n.is_empty() || n.starts_with("#[") || n.starts_with("//") {
                continue;
            }
            let words: Vec<&str> = n
                .split(|c: char| !(c.is_alphanumeric() || c == '_' || c == '$'))
                .filter(|w| !w.is_empty())
                .collect();
            if let Some(pos) = words.iter().position(|w| *w == "struct" || *w == "enum")
                && let Some(name) = words.get(pos + 1)
                && name.to_lowercase().contains("secret")
            {
                out.push((i + 1, (*name).to_string()));
            }
            break;
        }
    }
    out
}

/// S9: secret-hygiene tests (mapped) plus "no derive(PartialEq) on secret types".
pub fn s9(ctx: &mut Ctx, id: &str) -> Finding {
    let mut f = cargo::run_targets(ctx, id);
    let mut hits = Vec::new();
    let mut scanned = 0usize;
    for dir in crate_dirs(&ctx.root) {
        for file in rs_files(&dir.join("src")) {
            scanned += 1;
            let text = std::fs::read_to_string(&file).unwrap_or_default();
            for (line, name) in secret_partial_eq(&text) {
                hits.push(format!(
                    "{}:{line}: {name} derives PartialEq",
                    rel(&ctx.root, &file)
                ));
            }
        }
    }
    f.method
        .push_str(" ; scan crates/*/src/**/*.rs: no derive(PartialEq) on types named *Secret*");
    if hits.is_empty() {
        f.evidence.push_str(&format!(
            "\ncode inspection: no secret-named type derives PartialEq ({scanned} files)"
        ));
    } else {
        f.status = Status::Fail;
        f.evidence.push_str(&format!("\n{}", hits.join("\n")));
    }
    f
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_secret_partial_eq() {
        let src = "\
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey { b: Vec<u8> }

/// docs
#[derive(Debug, PartialEq)]
/// more docs
#[repr(C)]
pub struct HybridSecretKey { b: Vec<u8> }

#[derive(Clone)]
pub struct SharedSecret;

#[derive(PartialEq)]
enum SecretKind { A }
";
        let hits = secret_partial_eq(src);
        assert_eq!(
            hits,
            vec![
                (5, "HybridSecretKey".to_string()),
                (13, "SecretKind".to_string())
            ]
        );
    }

    #[test]
    fn forbid_line_required() {
        assert!(forbids_unsafe("//! doc\n#![forbid(unsafe_code)]\n"));
        assert!(!forbids_unsafe("// #![forbid(unsafe_code)] mentioned\n"));
    }
}
