//! Scope gates: X1 (research report pinned) and X2 (no stray changes).

use sha2::{Digest, Sha256};

use super::{Ctx, Finding, git_dirty_files};
use crate::hex;
use crate::report::Status;

/// Recorded SHA-256 of the original research report.
pub const REPORT_SHA256: &str = "4f46d971c7fa17367ae0e06ba01d22653c22b3f6c8b61a786082d0474d9fd72b";

/// Path of the research report.
pub const REPORT_PATH: &str = "docs/research/vyra-deep-research-report.md";

/// `bytes` with every CRLF replaced by LF.
pub fn to_lf(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut it = bytes.iter().peekable();
    while let Some(&b) = it.next() {
        if b == b'\r' && it.peek() == Some(&&b'\n') {
            continue;
        }
        out.push(b);
    }
    out
}

/// `bytes` with every line ending as CRLF (LF-normalised first, so no `\r\r\n`).
pub fn to_crlf(bytes: &[u8]) -> Vec<u8> {
    let lf = to_lf(bytes);
    let mut out = Vec::with_capacity(lf.len() + lf.len() / 20);
    for b in lf {
        if b == b'\n' {
            out.push(b'\r');
        }
        out.push(b);
    }
    out
}

/// SHA-256 hex.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(&Sha256::digest(bytes))
}

/// Which normalisation of `bytes` matches `expected`: `(label, hash)` for
/// all three, and the matching label if any.
pub fn match_report(
    bytes: &[u8],
    expected: &str,
) -> (Vec<(&'static str, String)>, Option<&'static str>) {
    let forms = vec![
        ("raw bytes", sha256_hex(bytes)),
        ("LF-normalised", sha256_hex(&to_lf(bytes))),
        ("CRLF-normalised", sha256_hex(&to_crlf(bytes))),
    ];
    let hit = forms.iter().find(|(_, h)| h == expected).map(|(l, _)| *l);
    (forms, hit)
}

/// X1.
pub fn x1(ctx: &mut Ctx, _id: &str) -> Finding {
    let method = format!(
        "SHA-256 of {REPORT_PATH} (raw, LF-normalised, CRLF-normalised) vs recorded {REPORT_SHA256}"
    );
    let Ok(bytes) = std::fs::read(ctx.root.join(REPORT_PATH)) else {
        return Finding::check(method, false, format!("{REPORT_PATH} cannot be read"));
    };
    let (forms, hit) = match_report(&bytes, REPORT_SHA256);
    let listing: Vec<String> = forms.iter().map(|(l, h)| format!("{l}: {h}")).collect();
    match hit {
        Some(label) => Finding::check(
            method,
            true,
            format!(
                "matches the recorded hash as {label}\n{}",
                listing.join("\n")
            ),
        ),
        None => Finding::check(
            method,
            false,
            format!("no form matches the recorded hash\n{}", listing.join("\n")),
        ),
    }
}

/// Path part of a `git status --porcelain` line (`XY path`).
pub fn porcelain_path(line: &str) -> &str {
    line.get(3..).unwrap_or("").trim().trim_matches('"')
}

/// Whether a dirty path is one of the result files `verify` itself rewrites
/// (benchmarks, sizes, the report), which legitimately differ after a run.
pub fn is_verify_output(path: &str) -> bool {
    path.starts_with("results/")
}

/// X2: no stray changes. The tree must be clean when `verify` starts
/// (`git status --porcelain` empty), and after the gates have run the only
/// modified paths may be the `results/` files that `verify` regenerates
/// itself (timings differ run to run). In quick mode a tree that was dirty at
/// the start is NOT_RUN (with the file list).
pub fn x2(ctx: &mut Ctx, _id: &str) -> Finding {
    let method = "git status --porcelain empty at start; afterwards only results/ (rewritten by verify) may differ";
    let (Some(start), Some(now)) = (ctx.dirty_at_start.clone(), git_dirty_files(&ctx.root)) else {
        return Finding::check(method, false, "git status failed (not a git checkout?)");
    };
    let stray: Vec<&String> = now
        .iter()
        .filter(|l| !is_verify_output(porcelain_path(l)))
        .collect();
    if start.is_empty() && stray.is_empty() {
        return Finding::check(
            method,
            true,
            format!(
                "working tree clean at start; {} results/ file(s) rewritten by this run",
                now.len()
            ),
        );
    }
    let list = format!(
        "dirty at start ({}):
{}
non-results changes now ({}):
{}",
        start.len(),
        start.join(
            "
"
        ),
        stray.len(),
        stray.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(
            "
"
        )
    );
    Finding {
        method: method.into(),
        status: if ctx.quick {
            Status::NotRun
        } else {
            Status::Fail
        },
        exit_code: Some(0),
        evidence: if ctx.quick {
            format!(
                "NOT RUN (quick mode): X2 is decided in full mode after the final commit:
{list}"
            )
        } else {
            list
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_ending_normalisation() {
        assert_eq!(to_lf(b"a\r\nb\nc\r"), b"a\nb\nc\r".to_vec());
        assert_eq!(to_crlf(b"a\nb\r\n"), b"a\r\nb\r\n".to_vec());
        // SHA-256("abc"), FIPS 180-2 example.
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn porcelain_paths_and_outputs() {
        assert_eq!(
            porcelain_path(" M results/benchmarks.json"),
            "results/benchmarks.json"
        );
        assert_eq!(porcelain_path("?? crates/x.rs"), "crates/x.rs");
        assert!(is_verify_output("results/sizes.md"));
        assert!(!is_verify_output("crates/vyra-kem/src/lib.rs"));
        assert!(!is_verify_output("docs/results/x"));
    }

    #[test]
    fn report_match_labels() {
        let lf = b"x\ny\n";
        let expected = sha256_hex(lf);
        let (_, hit) = match_report(b"x\r\ny\r\n", &expected);
        assert_eq!(hit, Some("LF-normalised"));
        let (_, hit) = match_report(lf, &expected);
        assert_eq!(hit, Some("raw bytes"));
        let (_, hit) = match_report(lf, "00");
        assert_eq!(hit, None);
    }
}
