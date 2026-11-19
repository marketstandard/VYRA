//! `cargo xtask verify [--quick]`: run every gate of `docs/CHECKS.md`.
//!
//! Gates are never skipped silently: each one ends as PASS, FAIL or NOT_RUN
//! (NOT_RUN only where `docs/CHECKS.md` or the gate's definition allows it:
//! S12 without `cargo audit`, D4 without `typst`, V2 without a Kani report
//! (missing, or one that says `status: NOT RUN`), X2 in quick mode; see
//! [`NOT_RUN_ALLOWED`] -- any other NOT_RUN is turned into FAIL), and the
//! exit status is non-zero if any gate is FAIL.
//!
//! Cargo commands run with `CARGO_TARGET_DIR=target/verify` so that a build
//! with different feature unification can never try to overwrite the running
//! xtask executable (which Windows forbids). The commands are otherwise
//! exactly those of `docs/CHECKS.md`, with `--locked`.

mod cargo;
mod claims;
mod docs;
mod perf;
mod proofs;
mod repro;
mod scope;
mod source;
mod yielding;

use std::collections::HashMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::exec::{self, Outcome};
use crate::report::{self, GateResult, Meta, Status};
use crate::{Res, envinfo, json};

/// State shared by the gates of one verify run.
pub struct Ctx {
    /// Workspace root.
    pub root: PathBuf,
    /// Quick mode.
    pub quick: bool,
    /// Run the Kani runner before gate V2 (`--with-kani`).
    pub with_kani: bool,
    /// Results of `cargo test -p <crate> --test <target>` already run.
    pub test_cache: HashMap<(String, String), cargo::TestRun>,
    /// `git status --porcelain` lines captured before any gate ran (`None` if git failed).
    pub dirty_at_start: Option<Vec<String>>,
}

impl Ctx {
    /// Target directory for gate cargo commands.
    pub fn target_dir(&self) -> PathBuf {
        self.root.join("target").join("verify")
    }

    /// Run the real cargo with `args` in the workspace root (gate target dir).
    pub fn cargo(&self, args: &[&str], extra_env: &[(&str, &str)]) -> Outcome {
        let target = self.target_dir();
        let target = target.to_string_lossy().into_owned();
        let mut env: Vec<(&str, &str)> = vec![("CARGO_TARGET_DIR", target.as_str())];
        env.extend_from_slice(extra_env);
        exec::run(&exec::cargo(), args, &self.root, &env)
    }
}

/// What a gate function returns (id and description are added by the runner).
pub struct Finding {
    /// Command(s) or method.
    pub method: String,
    /// Outcome.
    pub status: Status,
    /// Exit code of the decisive command.
    pub exit_code: Option<i32>,
    /// Evidence text.
    pub evidence: String,
}

impl Finding {
    /// A finding without a process exit code.
    pub fn check(method: impl Into<String>, ok: bool, evidence: impl Into<String>) -> Self {
        Finding {
            method: method.into(),
            status: if ok { Status::Pass } else { Status::Fail },
            exit_code: None,
            evidence: evidence.into(),
        }
    }
}

type GateFn = fn(&mut Ctx, &str) -> Finding;

/// Every gate of docs/CHECKS.md, in order.
const GATES: &[(&str, &str, GateFn)] = &[
    ("F1", "workspace builds (all targets)", cargo::f1),
    (
        "F2",
        "workspace tests pass; no #[ignore] without reason",
        cargo::f2,
    ),
    ("F3", "hybrid KEM round trip, suites 1/3/5", cargo::mapped),
    (
        "F4",
        "component conformance (ML-KEM, HQC, ML-DSA, Ed25519)",
        cargo::mapped,
    ),
    ("F5", "VYRA known-answer vectors (vectors --check)", f5),
    ("F6", "serialization round trip and lengths", cargo::mapped),
    (
        "F7",
        "composite signature round trip, all suites",
        cargo::mapped,
    ),
    (
        "F8",
        "sealed box round trip incl. empty and 1 MiB",
        cargo::mapped,
    ),
    ("F9", "demonstration: vyra-cli demo", cargo::f9),
    ("S1", "length validation of every decoder", cargo::mapped),
    (
        "S2",
        "header validation (magic, version, type, suite)",
        cargo::mapped,
    ),
    (
        "S3",
        "KEM ciphertext tampering (implicit rejection)",
        cargo::mapped,
    ),
    ("S4", "signature tampering", cargo::mapped),
    ("S5", "AEAD tampering", cargo::mapped),
    ("S6", "combiner binding", cargo::mapped),
    (
        "S7",
        "no unsafe: #![forbid(unsafe_code)] in every crate root",
        source::s7,
    ),
    (
        "S8",
        "no panics in library code (clippy deny list)",
        cargo::s8,
    ),
    (
        "S9",
        "secret hygiene (tests + no derive(PartialEq) on secret types)",
        source::s9,
    ),
    ("S10", "parser robustness (property tests)", cargo::mapped),
    ("S11", "lint and format", cargo::s11),
    ("S12", "dependency advisories (cargo audit)", cargo::s12),
    ("C1", "docs/SECURITY.md required sections", claims::c1),
    ("C2", "forbidden claims absent", claims::c2),
    (
        "C3",
        "docs/SPEC.md labels components ESTABLISHED / VYRA-ORIGINAL",
        claims::c3,
    ),
    (
        "P1",
        "benchmarks written with all required entries",
        perf::p1,
    ),
    ("P2", "sizes written from code constants", perf::p2),
    (
        "D1",
        "API docs build with -D warnings; deny(missing_docs)",
        cargo::d1,
    ),
    ("D2", "doctests (included in F2)", d2),
    (
        "D3",
        "docs/SPEC.md sizes and suite ids equal results/sizes.json",
        docs::d3,
    ),
    ("D4", "paper compiles with typst", docs::d4),
    ("D5", "fresh git clone passes F1, F2, F5", repro::d5),
    (
        "Y1",
        "failure-injection tests (cargo test -p vyra-yield)",
        yielding::y1,
    ),
    (
        "Y2",
        "yield matrix reproducible and verdict pattern as claimed",
        yielding::y2,
    ),
    (
        "V1",
        "exhaustive enumeration proofs (cargo test -p vyra-proofs)",
        proofs::v1,
    ),
    (
        "V2",
        "bounded model checking report (Kani): harnesses and mutants",
        proofs::v2,
    ),
    ("X1", "research report preserved (SHA-256 pin)", scope::x1),
    (
        "X2",
        "no stray changes (git status --porcelain empty)",
        scope::x2,
    ),
];

/// Gates that may end NOT_RUN, and when (`quick_only`: only in quick mode).
/// Any other NOT_RUN is recorded as FAIL.
pub const NOT_RUN_ALLOWED: &[(&str, bool)] = &[
    ("S12", false), // cargo audit not installed
    ("D4", false),  // typst not on PATH
    ("V2", false),  // no Kani report, or the report says NOT RUN
    ("X2", true),   // tree dirty at start, quick mode
];

/// Whether gate `id` may end NOT_RUN in this mode.
pub fn not_run_allowed(id: &str, quick: bool) -> bool {
    NOT_RUN_ALLOWED
        .iter()
        .any(|(g, quick_only)| *g == id && (quick || !quick_only))
}

/// Gate ids in order (used by tests).
#[cfg(test)]
pub fn gate_ids() -> Vec<&'static str> {
    GATES.iter().map(|(id, _, _)| *id).collect()
}

fn f5(ctx: &mut Ctx, _id: &str) -> Finding {
    let method = "in-process: cargo xtask vectors --check (byte-compare + re-derive + re-verify)";
    match crate::vectors::check(&ctx.root.join("vectors")) {
        Ok(p) if p.is_empty() => Finding::check(method, true, crate::vectors::CHECK_OK_MARKER),
        Ok(p) => Finding::check(method, false, exec::tail(&p.join("\n"), 12, 2000)),
        Err(e) => Finding::check(method, false, e),
    }
}

fn d2(ctx: &mut Ctx, _id: &str) -> Finding {
    let f2 = ctx
        .test_cache
        .get(&("<workspace>".to_string(), "F2".to_string()));
    match f2 {
        Some(run) => Finding {
            method: "included in F2 (cargo test --workspace runs doctests)".into(),
            status: if run.ok() { Status::Pass } else { Status::Fail },
            exit_code: run.outcome.code,
            evidence: format!("doctest results counted in F2: {}", run.doc_summary()),
        },
        None => Finding::check("included in F2", false, "F2 did not run"),
    }
}

/// Normalised relative path with forward slashes.
pub fn rel(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

/// Every `.rs` file under `dir`, skipping `target` directories.
pub fn rs_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                if p.file_name().is_some_and(|n| n != "target" && n != ".git") {
                    stack.push(p);
                }
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

/// Crate directories `crates/*` that contain a `Cargo.toml`.
pub fn crate_dirs(root: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = std::fs::read_dir(root.join("crates"))
        .map(|rd| {
            rd.flatten()
                .map(|e| e.path())
                .filter(|p| p.join("Cargo.toml").is_file())
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    out
}

/// `git status --porcelain` lines, or `None` if git failed.
pub fn git_dirty_files(root: &Path) -> Option<Vec<String>> {
    let o = exec::run(&"git".into(), &["status", "--porcelain"], root, &[]);
    o.success().then(|| {
        o.stdout
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(str::to_string)
            .collect()
    })
}

/// Entry point. `Ok(true)` when no gate is FAIL.
pub fn run(root: &Path, quick: bool, with_kani: bool) -> Res<bool> {
    let started = Instant::now();
    let dirty = git_dirty_files(root);
    let meta = Meta {
        mode: if quick { "quick" } else { "full" }.to_string(),
        commit: envinfo::git_commit(root),
        date_utc: envinfo::utc_now(),
        dirty_at_start: dirty.as_ref().map(|d| !d.is_empty()),
    };
    let mut ctx = Ctx {
        root: root.to_path_buf(),
        quick,
        with_kani,
        test_cache: HashMap::new(),
        dirty_at_start: dirty.clone(),
    };
    println!(
        "verify ({} mode): {} gates; cargo commands use CARGO_TARGET_DIR={}",
        meta.mode,
        GATES.len(),
        ctx.target_dir().display()
    );
    let mut results = Vec::new();
    for (id, description, gate) in GATES {
        print!("[{id}] {description} ... ");
        let _ = std::io::stdout().flush();
        let t = Instant::now();
        let mut f = gate(&mut ctx, id);
        if f.status == Status::NotRun && !not_run_allowed(id, quick) {
            f.status = Status::Fail;
            f.evidence = format!(
                "NOT_RUN is not allowed for {id} in this mode (docs/CHECKS.md); recorded as FAIL\n{}",
                f.evidence
            );
        }
        let duration = t.elapsed();
        println!("{} ({:.1} s)", f.status.as_str(), duration.as_secs_f64());
        if f.status != Status::Pass {
            for line in exec::tail(&f.evidence, 6, 900).lines() {
                println!("      {line}");
            }
        }
        results.push(GateResult {
            id: (*id).to_string(),
            description: (*description).to_string(),
            method: scrub_paths(root, &f.method),
            status: f.status,
            exit_code: f.exit_code,
            duration,
            evidence: scrub_paths(root, &f.evidence),
        });
    }
    println!("\n{}", report::console_table(&results));
    write_report(root, &meta, &results)?;
    println!(
        "wrote results/verification-report.json and .md ({:.0} s total)",
        started.elapsed().as_secs_f64()
    );
    let (_, fail, not_run) = report::counts(&results);
    if not_run > 0 {
        let ids: Vec<&str> = results
            .iter()
            .filter(|r| r.status == Status::NotRun)
            .map(|r| r.id.as_str())
            .collect();
        println!("NOTE: NOT_RUN is not a pass: {}", ids.join(", "));
    }
    Ok(fail == 0)
}

/// Replace machine-specific absolute paths in report text with placeholders,
/// so the committed report does not record where the repository was checked
/// out, the temporary directory or the home directory (and with it the
/// account name) of the machine that ran the gates.
///
/// The workspace root becomes `<repo>`, the temporary directory `<tmp>` and
/// the home directory `<home>`. Each is matched as written and with the other
/// path separator.
pub fn scrub_paths(root: &Path, text: &str) -> String {
    let home = std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from);
    let mut pairs: Vec<(PathBuf, &str)> = vec![
        (root.to_path_buf(), "<repo>"),
        (std::env::temp_dir(), "<tmp>"),
    ];
    if let Some(h) = home {
        pairs.push((h, "<home>"));
    }
    let mut out = text.to_string();
    for (path, placeholder) in pairs {
        let raw = path.display().to_string();
        let raw = raw.trim_end_matches(['/', '\\']);
        // A root such as "/" or "C:" would match far too much.
        if raw.len() < 4 {
            continue;
        }
        for form in [
            raw.to_string(),
            raw.replace('\\', "/"),
            raw.replace('/', "\\"),
        ] {
            out = out.replace(&form, placeholder);
        }
    }
    out
}

fn write_report(root: &Path, meta: &Meta, results: &[GateResult]) -> Res<()> {
    let dir = root.join("results");
    std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    std::fs::write(
        dir.join("verification-report.json"),
        json::to_canonical(&report::to_json(meta, results)),
    )
    .map_err(|e| format!("write verification-report.json: {e}"))?;
    std::fs::write(
        dir.join("verification-report.md"),
        report::to_markdown(meta, results),
    )
    .map_err(|e| format!("write verification-report.md: {e}"))?;
    Ok(())
}

/// Format a duration as seconds for evidence text.
pub fn secs(d: Duration) -> String {
    format!("{:.1} s", d.as_secs_f64())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_checks_md_gate_is_registered_once() {
        let ids = gate_ids();
        let expected = [
            "F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8", "F9", "S1", "S2", "S3", "S4", "S5",
            "S6", "S7", "S8", "S9", "S10", "S11", "S12", "C1", "C2", "C3", "P1", "P2", "D1", "D2",
            "D3", "D4", "D5", "Y1", "Y2", "V1", "V2", "X1", "X2",
        ];
        assert_eq!(ids, expected);
        assert_eq!(ids.len(), 37);
    }

    #[test]
    fn report_text_has_no_machine_paths() {
        let root = Path::new(if cfg!(windows) {
            r"Q:\work\vyra-checkout"
        } else {
            "/work/vyra-checkout"
        });
        let tmp = std::env::temp_dir();
        let inside = root.join("crates").join("vyra");
        let text = format!(
            "Compiling vyra ({}) and {} then {}",
            inside.display(),
            inside.display().to_string().replace('\\', "/"),
            tmp.join("vyra-d5-1").display()
        );
        let out = scrub_paths(root, &text);
        assert!(out.contains("<repo>"), "{out}");
        assert!(out.contains("<tmp>"), "{out}");
        assert!(!out.contains("vyra-checkout"), "{out}");
        let tmp_text = tmp.display().to_string();
        assert!(
            !out.contains(tmp_text.trim_end_matches(['/', '\\'])),
            "{out}"
        );
        // Text without paths is unchanged.
        assert_eq!(scrub_paths(root, "exit Some(0)"), "exit Some(0)");
    }

    #[test]
    fn not_run_policy() {
        for id in ["S12", "D4", "V2"] {
            assert!(
                not_run_allowed(id, false) && not_run_allowed(id, true),
                "{id}"
            );
        }
        assert!(not_run_allowed("X2", true));
        assert!(!not_run_allowed("X2", false));
        for id in gate_ids() {
            if !["S12", "D4", "V2", "X2"].contains(&id) {
                assert!(!not_run_allowed(id, true), "{id}");
            }
        }
    }

    #[test]
    fn checks_md_lists_the_same_gates() {
        let text = std::fs::read_to_string(crate::workspace_root().join("docs/CHECKS.md"))
            .unwrap_or_default();
        for id in gate_ids() {
            assert!(
                text.contains(&format!("| {id} |")),
                "gate {id} not in docs/CHECKS.md"
            );
        }
    }
}
