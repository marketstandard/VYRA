//! Claims-discipline gates C1–C3. These check that the documentation is
//! honest in form, not that the cryptography is sound.
//!
//! This file defines the C2 phrase list and is therefore itself on the C2
//! allow-list.

use std::path::Path;

use super::{Ctx, Finding};
use crate::exec;

/// C1: headings `docs/SECURITY.md` must contain.
pub const REQUIRED_SECURITY_HEADINGS: &[&str] = &[
    "Assumptions",
    "Attack models",
    "Parameter analysis",
    "Side channels",
    "Randomness",
    "Key lifecycle",
    "Limitations",
    "Open questions",
    "Deviations from the research report",
];

/// C2: phrases that must not occur (case-insensitive).
pub const FORBIDDEN_PHRASES: &[&str] = &[
    "provably secure",
    "unbreakable",
    "production-ready",
    "quantum-proof",
    "independently validated",
];

/// C2 allow-list: files exempt from the scan. Exact paths, or prefixes ending in `/`.
pub const C2_ALLOW_LIST: &[&str] = &[
    "docs/CHECKS.md",
    "docs/research/",
    "xtask/src/gates/claims.rs",
];

/// C2 scanned extensions.
pub const C2_EXTENSIONS: &[&str] = &["md", "rs", "typ", "toml"];

/// Markdown heading lines of `text`, lower-cased, without the leading `#`s.
pub fn headings(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim_start)
        .filter(|l| l.starts_with('#'))
        .map(|l| l.trim_start_matches('#').trim().to_lowercase())
        .collect()
}

/// Required headings not matched (case-insensitive substring of some heading line).
pub fn missing_headings(text: &str, required: &[&str]) -> Vec<String> {
    let hs = headings(text);
    required
        .iter()
        .filter(|r| {
            let r = r.to_lowercase();
            !hs.iter().any(|h| h.contains(&r))
        })
        .map(|r| (*r).to_string())
        .collect()
}

/// C1.
pub fn c1(ctx: &mut Ctx, _id: &str) -> Finding {
    let method = "docs/SECURITY.md heading lines contain (case-insensitive) each required heading";
    let path = ctx.root.join("docs/SECURITY.md");
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Finding::check(method, false, "docs/SECURITY.md does not exist");
    };
    let missing = missing_headings(&text, REQUIRED_SECURITY_HEADINGS);
    if missing.is_empty() {
        Finding::check(
            method,
            true,
            format!(
                "all {} required headings present",
                REQUIRED_SECURITY_HEADINGS.len()
            ),
        )
    } else {
        Finding::check(
            method,
            false,
            format!("missing headings: {}", missing.join("; ")),
        )
    }
}

/// Whether `path` (relative, `/`-separated) is exempt from C2.
pub fn c2_allowed(path: &str) -> bool {
    C2_ALLOW_LIST.iter().any(|a| {
        if a.ends_with('/') {
            path.starts_with(a)
        } else {
            path == *a
        }
    })
}

/// Occurrences in `text`: `(line number, index into FORBIDDEN_PHRASES)`.
pub fn scan_phrases(text: &str) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let lower = line.to_lowercase();
        for (i, p) in FORBIDDEN_PHRASES.iter().enumerate() {
            if lower.contains(p) {
                out.push((n + 1, i));
            }
        }
    }
    out
}

/// Files C2 scans: tracked plus untracked-but-not-ignored files with a
/// scanned extension (`git ls-files --cached --others --exclude-standard`).
fn c2_files(root: &Path) -> Result<Vec<String>, String> {
    let o = exec::run(
        &"git".into(),
        &["ls-files", "--cached", "--others", "--exclude-standard"],
        root,
        &[],
    );
    if !o.success() {
        return Err(format!(
            "git ls-files failed: {}",
            exec::tail(&o.combined(), 3, 300)
        ));
    }
    let mut files: Vec<String> = o
        .stdout
        .lines()
        .map(|l| l.trim().replace('\\', "/"))
        .filter(|l| {
            Path::new(l)
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| C2_EXTENSIONS.contains(&e))
        })
        .collect();
    files.sort();
    files.dedup();
    Ok(files)
}

/// C2.
pub fn c2(ctx: &mut Ctx, _id: &str) -> Finding {
    let method = "scan tracked + untracked-unignored *.md *.rs *.typ *.toml (case-insensitive), allow-list: docs/CHECKS.md, docs/research/**, xtask/src/gates/claims.rs";
    let files = match c2_files(&ctx.root) {
        Ok(f) => f,
        Err(e) => return Finding::check(method, false, e),
    };
    let mut hits = Vec::new();
    let mut scanned = 0usize;
    for f in &files {
        if c2_allowed(f) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(ctx.root.join(f)) else {
            continue; // deleted in the working tree
        };
        scanned += 1;
        for (line, phrase) in scan_phrases(&text) {
            // The phrase itself is not echoed into reports, so the report
            // files never trip C2 themselves.
            hits.push(format!("{f}:{line}: forbidden phrase #{}", phrase + 1));
        }
    }
    if hits.is_empty() {
        Finding::check(
            method,
            true,
            format!("no forbidden phrase in {scanned} files"),
        )
    } else {
        println!();
        for (i, p) in FORBIDDEN_PHRASES.iter().enumerate() {
            println!("      phrase #{}: {p:?}", i + 1);
        }
        Finding::check(
            method,
            false,
            format!(
                "{} occurrence(s) (phrase numbers refer to the list in xtask/src/gates/claims.rs):\n{}",
                hits.len(),
                hits.join("\n")
            ),
        )
    }
}

/// C3 check on SPEC text. Definition (kept deliberately simple):
///
/// 1. the file contains both tokens `ESTABLISHED` and `VYRA-ORIGINAL`;
/// 2. it has a heading containing "components" (case-insensitive);
/// 3. the first Markdown table after that heading has at least one data row,
///    and every data row (not the header or `---` separator) contains
///    `ESTABLISHED` or `VYRA-ORIGINAL`.
pub fn c3_problems(text: &str) -> Vec<String> {
    let mut problems = Vec::new();
    for token in ["ESTABLISHED", "VYRA-ORIGINAL"] {
        if !text.contains(token) {
            problems.push(format!("token {token} not found"));
        }
    }
    let lines: Vec<&str> = text.lines().collect();
    let heading = lines.iter().position(|l| {
        let t = l.trim_start();
        t.starts_with('#') && t.to_lowercase().contains("components")
    });
    let Some(h) = heading else {
        problems.push("no heading containing \"Components\"".to_string());
        return problems;
    };
    let table: Vec<&str> = lines
        .iter()
        .skip(h + 1)
        .skip_while(|l| !l.trim_start().starts_with('|'))
        .take_while(|l| l.trim_start().starts_with('|'))
        .copied()
        .collect();
    // Row 0 is the header, row 1 the separator.
    let rows: Vec<&str> = table
        .iter()
        .skip(1)
        .filter(|l| !l.chars().all(|c| matches!(c, '|' | '-' | ':' | ' ')))
        .copied()
        .collect();
    if rows.is_empty() {
        problems.push("no table rows under the Components heading".to_string());
    }
    for r in rows {
        if !(r.contains("ESTABLISHED") || r.contains("VYRA-ORIGINAL")) {
            problems.push(format!("row without label: {}", r.trim()));
        }
    }
    problems
}

/// C3.
pub fn c3(ctx: &mut Ctx, _id: &str) -> Finding {
    let method = "docs/SPEC.md: both tokens present; every row of the first table under the \"Components\" heading says ESTABLISHED or VYRA-ORIGINAL";
    let Ok(text) = std::fs::read_to_string(ctx.root.join("docs/SPEC.md")) else {
        return Finding::check(method, false, "docs/SPEC.md does not exist");
    };
    let problems = c3_problems(&text);
    if problems.is_empty() {
        Finding::check(method, true, "every component row is labelled")
    } else {
        Finding::check(method, false, problems.join("\n"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heading_matcher() {
        let doc =
            "# Title\n## 1. Assumptions\ntext mentioning Limitations\n### ATTACK MODELS and more\n";
        let missing = missing_headings(doc, &["Assumptions", "Attack models", "Limitations"]);
        assert_eq!(missing, vec!["Limitations".to_string()]);
        assert_eq!(
            headings("  ## Side channels\nx"),
            vec!["side channels".to_string()]
        );
    }

    #[test]
    fn phrase_scanner_is_case_insensitive() {
        let text = "fine\nThis is Production-Ready.\nUNBREAKABLE and quantum-proof\n";
        assert_eq!(scan_phrases(text), vec![(2, 2), (3, 1), (3, 3)]);
        assert!(scan_phrases("production ready (no hyphen)").is_empty());
    }

    #[test]
    fn allow_list() {
        assert!(c2_allowed("docs/CHECKS.md"));
        assert!(c2_allowed("docs/research/vyra-deep-research-report.md"));
        assert!(c2_allowed("xtask/src/gates/claims.rs"));
        assert!(!c2_allowed("docs/CHECKS.md.bak"));
        assert!(!c2_allowed("docs/SECURITY.md"));
        assert!(!c2_allowed("xtask/src/gates/mod.rs"));
        assert!(!c2_allowed("research/docs/x.md"));
    }

    #[test]
    fn c3_rules() {
        let good = "# Spec\n## Components\n\n| component | status |\n|---|---|\n| ML-KEM | ESTABLISHED |\n| combiner | VYRA-ORIGINAL |\n\ntext\n";
        assert!(c3_problems(good).is_empty());
        let bad = good.replace(
            "| combiner | VYRA-ORIGINAL |",
            "| combiner | new |\n| x | VYRA-ORIGINAL |",
        );
        let p = c3_problems(&bad);
        assert_eq!(p, vec!["row without label: | combiner | new |".to_string()]);
        assert!(!c3_problems("# Components\nno table ESTABLISHED VYRA-ORIGINAL").is_empty());
        assert!(!c3_problems("# Other\n| a | ESTABLISHED |\n").is_empty());
    }
}
