//! Gates V1 and V2: machine-checked properties of VYRA's own encodings.
//!
//! V1 runs the exhaustive-enumeration tests of `vyra-proofs`. V2 judges the
//! bounded-model-checking evidence in `results/kani-report.txt`, the file
//! written by `tools/kani/in-container.sh` (through `run.ps1` / `run.sh`):
//! every harness SUCCESSFUL and every mutant of `tools/kani/mutants.tsv` with
//! its expected outcome. A report that says `status: NOT RUN` makes V2
//! NOT_RUN, never PASS. Docker is not started by default; `cargo xtask verify
//! --with-kani` runs the runner first.

use std::path::Path;

use super::{Ctx, Finding, cargo, secs};
use crate::exec;
use crate::report::Status;

/// The report file, relative to the workspace root.
pub const KANI_REPORT: &str = "results/kani-report.txt";
/// Marker line that starts the machine-readable summary of a report.
const SUMMARY_MARKER: &str = "===== SUMMARY =====";

/// V1: `cargo test -p vyra-proofs --locked`.
pub fn v1(ctx: &mut Ctx, _id: &str) -> Finding {
    cargo::crate_tests(ctx, "vyra-proofs")
}

/// What a Kani report says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KaniVerdict {
    /// The file states that no verification was run.
    NotRun(String),
    /// Every expectation met; the evidence line.
    Pass(String),
    /// Problems found, one message each.
    Fail(Vec<String>),
}

/// The harness names listed in `in-container.sh` (`harnesses=( ... )`).
pub fn expected_harnesses(script: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut inside = false;
    for line in script.lines() {
        let t = line.trim();
        if !inside {
            if let Some(rest) = t.strip_prefix("harnesses=(") {
                inside = true;
                let rest = rest.trim();
                if let Some(body) = rest.strip_suffix(')') {
                    out.extend(body.split_whitespace().map(str::to_string));
                    break;
                }
                out.extend(rest.split_whitespace().map(str::to_string));
            }
            continue;
        }
        if t.starts_with(')') {
            break;
        }
        out.extend(
            t.split_whitespace()
                .take_while(|w| !w.starts_with('#'))
                .map(str::to_string),
        );
    }
    out
}

/// `(id, expected outcome)` of every mutant in `mutants.tsv` (7th column).
pub fn expected_mutants(tsv: &str) -> Vec<(String, String)> {
    tsv.lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .filter_map(|l| {
            let cols: Vec<&str> = l.split('\t').collect();
            Some((
                cols.first()?.trim().to_string(),
                cols.get(6)?.trim().to_string(),
            ))
        })
        .collect()
}

/// Judge a Kani report against the harnesses and mutants it must cover.
pub fn judge_report(
    report: &str,
    harnesses: &[String],
    mutants: &[(String, String)],
) -> KaniVerdict {
    let lines: Vec<&str> = report
        .lines()
        .map(|l| l.trim_start_matches('\u{feff}').trim_end())
        .collect();
    if let Some(l) = lines.iter().find(|l| {
        l.to_ascii_lowercase().starts_with("status:") && l.to_ascii_uppercase().contains("NOT RUN")
    }) {
        let reason = lines
            .iter()
            .find(|l| l.starts_with("Reason"))
            .map_or(String::new(), |r| format!("; {r}"));
        return KaniVerdict::NotRun(format!("{KANI_REPORT} says `{l}`{reason}"));
    }
    let mut problems = Vec::new();
    if harnesses.is_empty() {
        problems.push("no harnesses listed in tools/kani/in-container.sh".to_string());
    }
    if mutants.is_empty() {
        problems.push("no mutants listed in tools/kani/mutants.tsv".to_string());
    }
    let Some(start) = lines.iter().position(|l| l.trim() == SUMMARY_MARKER) else {
        problems.push(format!(
            "no `{SUMMARY_MARKER}` section: the run did not finish or the file is not a Kani report"
        ));
        return KaniVerdict::Fail(problems);
    };
    let mut seen_harness: Vec<(String, String)> = Vec::new();
    let mut seen_mutant: Vec<(String, Vec<String>)> = Vec::new();
    let mut exit_status = None;
    for l in lines.iter().skip(start + 1) {
        let cols: Vec<&str> = l.split('\t').map(str::trim).collect();
        match cols.as_slice() {
            ["harness", name, result, ..] => {
                seen_harness.push(((*name).to_string(), (*result).to_string()));
            }
            ["mutant", id, rest @ ..] => {
                seen_mutant.push((
                    (*id).to_string(),
                    rest.iter().map(|s| (*s).to_string()).collect(),
                ));
            }
            _ => {
                if let Some(code) = l.trim().strip_prefix("overall exit status:") {
                    exit_status = code.trim().parse::<i64>().ok();
                }
            }
        }
    }
    for (name, result) in &seen_harness {
        if result != "SUCCESSFUL" {
            problems.push(format!("harness {name}: {result}"));
        }
    }
    for h in harnesses {
        if !seen_harness.iter().any(|(n, _)| n == h) {
            problems.push(format!("harness {h}: missing from the report"));
        }
    }
    for (id, expected) in mutants {
        let Some((_, rest)) = seen_mutant.iter().find(|(m, _)| m == id) else {
            problems.push(format!("mutant {id}: missing from the report"));
            continue;
        };
        let field = |k: &str| {
            rest.iter()
                .find_map(|c| c.strip_prefix(k).map(str::to_string))
        };
        let outcome = field("outcome=");
        let recorded = field("expected=");
        let verdict_ok = rest.iter().any(|c| c == "OK");
        if !(verdict_ok
            && outcome.as_deref() == Some(expected.as_str())
            && recorded.as_deref() == Some(expected.as_str()))
        {
            problems.push(format!(
                "mutant {id}: expected {expected}, report says {}",
                rest.join(" ")
            ));
        }
    }
    match exit_status {
        Some(0) => {}
        Some(n) => problems.push(format!("overall exit status {n}")),
        None => problems.push("no `overall exit status` line".to_string()),
    }
    if problems.is_empty() {
        KaniVerdict::Pass(format!(
            "{} harnesses SUCCESSFUL, {} mutants with their expected outcome ({} killed, {} survive as recorded), overall exit status 0",
            seen_harness.len(),
            mutants.len(),
            mutants.iter().filter(|(_, e)| e == "killed").count(),
            mutants.iter().filter(|(_, e)| e != "killed").count(),
        ))
    } else {
        KaniVerdict::Fail(problems)
    }
}

/// Run the Docker-based Kani runner (`--with-kani`).
fn run_kani(root: &Path) -> exec::Outcome {
    if cfg!(windows) {
        exec::run(
            &"powershell".into(),
            &[
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                "tools/kani/run.ps1",
            ],
            root,
            &[],
        )
    } else {
        exec::run(&"bash".into(), &["tools/kani/run.sh"], root, &[])
    }
}

/// V2: judge `results/kani-report.txt` (after running Kani with `--with-kani`).
pub fn v2(ctx: &mut Ctx, _id: &str) -> Finding {
    let mut method = format!(
        "parse {KANI_REPORT} (format of tools/kani/in-container.sh): every harness of in-container.sh SUCCESSFUL, every mutant of tools/kani/mutants.tsv with its expected outcome, overall exit status 0; `status: NOT RUN` -> NOT_RUN"
    );
    let mut evidence = Vec::new();
    let report_path = ctx.root.join(KANI_REPORT);
    let before = std::fs::read(&report_path).ok();
    let mut runner_failed = None;
    if ctx.with_kani {
        let runner = if cfg!(windows) {
            "powershell -File tools/kani/run.ps1"
        } else {
            "tools/kani/run.sh"
        };
        method = format!("{runner} (--with-kani); then {method}");
        let o = run_kani(&ctx.root);
        evidence.push(format!(
            "$ {runner} -> exit {:?} ({})\n{}",
            o.code,
            secs(o.duration),
            exec::tail(&o.combined(), 25, 2500)
        ));
        let after = std::fs::read(&report_path).ok();
        if !o.success() && after == before {
            runner_failed = Some(format!(
                "the Kani runner failed (exit {:?}) and did not write a new {KANI_REPORT}",
                o.code
            ));
        }
    }
    let Ok(report) = std::fs::read_to_string(&report_path) else {
        return Finding {
            method,
            status: if ctx.with_kani {
                Status::Fail
            } else {
                Status::NotRun
            },
            exit_code: None,
            evidence: format!(
                "NOT RUN: {KANI_REPORT} does not exist; no bounded-model-checking evidence (run `cargo xtask verify --with-kani` or tools/kani/run.ps1|run.sh)\n{}",
                evidence.join("\n")
            ),
        };
    };
    let script =
        std::fs::read_to_string(ctx.root.join("tools/kani/in-container.sh")).unwrap_or_default();
    let tsv = std::fs::read_to_string(ctx.root.join("tools/kani/mutants.tsv")).unwrap_or_default();
    let verdict = judge_report(
        &report,
        &expected_harnesses(&script),
        &expected_mutants(&tsv),
    );
    let (mut status, text) = match verdict {
        KaniVerdict::NotRun(why) => (
            Status::NotRun,
            format!("NOT RUN: {why}; no bounded-model-checking result is claimed"),
        ),
        KaniVerdict::Pass(why) => (Status::Pass, why),
        KaniVerdict::Fail(p) => (Status::Fail, p.join("\n")),
    };
    if let Some(why) = runner_failed {
        status = Status::Fail;
        evidence.push(why);
    }
    evidence.push(text);
    Finding {
        method,
        status,
        exit_code: None,
        evidence: evidence.join("\n"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCRIPT: &str = "harnesses=(\n  h_one\n  h_two\n)\nextra_args=()\n";
    const TSV: &str = "#id\tfile\tfrom\tto\tharness\ttest\texpected\n\
M1\tw.rs\ta\tb\th_one\tt\tkilled\n\
M2\tw.rs\ta\tb\th_two\tt\tsurvives\n";

    fn names() -> (Vec<String>, Vec<(String, String)>) {
        (expected_harnesses(SCRIPT), expected_mutants(TSV))
    }

    const GOOD: &str = "# VYRA Kani report\ndate (UTC):   2026-11-18T00:00:00Z\n\
===== harness h_one: SUCCESSFUL (10s wall, incl. build) =====\nVERIFICATION:- SUCCESSFUL\n\n\
===== SUMMARY =====\n\
harness\th_one\tSUCCESSFUL\t10s\n\
harness\th_two\tSUCCESSFUL\t12s\n\
mutant\tM1\th_one\tFAILED\toutcome=killed\texpected=killed\tOK\t9s\n\
mutant\tM2\th_two\tSUCCESSFUL\toutcome=survives\texpected=survives\tOK\t9s\n\
overall exit status: 0\n\u{feff}image sha256:abc\n";

    #[test]
    fn parses_script_and_tsv() {
        let (h, m) = names();
        assert_eq!(h, vec!["h_one", "h_two"]);
        assert_eq!(
            m,
            vec![
                ("M1".to_string(), "killed".to_string()),
                ("M2".to_string(), "survives".to_string())
            ]
        );
        assert_eq!(expected_harnesses("harnesses=(a b)\n"), vec!["a", "b"]);
    }

    #[test]
    fn real_script_and_tsv_are_parsed() {
        let root = crate::workspace_root().join("tools/kani");
        let script = std::fs::read_to_string(root.join("in-container.sh")).unwrap_or_default();
        let tsv = std::fs::read_to_string(root.join("mutants.tsv")).unwrap_or_default();
        let h = expected_harnesses(&script);
        assert!(h.len() >= 8, "{h:?}");
        assert!(
            h.iter()
                .all(|n| n.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
        );
        let m = expected_mutants(&tsv);
        assert!(m.len() >= 11, "{m:?}");
        assert!(
            m.iter().all(|(_, e)| e == "killed" || e == "survives"),
            "{m:?}"
        );
    }

    #[test]
    fn complete_report_passes() {
        let (h, m) = names();
        let v = judge_report(GOOD, &h, &m);
        assert!(
            matches!(&v, KaniVerdict::Pass(t) if t.contains("2 harnesses")),
            "{v:?}"
        );
    }

    #[test]
    fn not_run_report_is_not_run() {
        let (h, m) = names();
        let text = "# VYRA Kani report\nstatus: NOT RUN\n\nNo Kani verification has been run.\nReason (2026-11-18): Docker\n";
        assert!(matches!(judge_report(text, &h, &m), KaniVerdict::NotRun(_)));
        // NOT RUN wins even if a summary-like block follows.
        let mixed = format!("{text}{GOOD}");
        assert!(matches!(
            judge_report(&mixed, &h, &m),
            KaniVerdict::NotRun(_)
        ));
    }

    #[test]
    fn failing_reports_fail() {
        let (h, m) = names();
        let cases = [
            (
                GOOD.replace("h_two\tSUCCESSFUL\t12s", "h_two\tFAILED\t12s"),
                "harness h_two: FAILED",
            ),
            (
                GOOD.replace(
                    "outcome=killed\texpected=killed\tOK",
                    "outcome=survives\texpected=killed\tUNEXPECTED",
                ),
                "mutant M1",
            ),
            (
                GOOD.replace(
                    "mutant\tM2\th_two\tSUCCESSFUL\toutcome=survives\texpected=survives\tOK\t9s\n",
                    "",
                ),
                "mutant M2: missing",
            ),
            (
                GOOD.replace("harness\th_one\tSUCCESSFUL\t10s\n", ""),
                "harness h_one: missing",
            ),
            (
                GOOD.replace("overall exit status: 0", "overall exit status: 1"),
                "overall exit status 1",
            ),
            (GOOD.replace("===== SUMMARY =====", "no summary"), "SUMMARY"),
            (
                GOOD.replace(
                    "mutant\tM1\th_one\tFAILED\toutcome=killed\texpected=killed\tOK\t9s",
                    "mutant\tM1\tNOT-APPLIED\t-",
                ),
                "mutant M1",
            ),
            (String::new(), "SUMMARY"),
        ];
        for (text, needle) in cases {
            let v = judge_report(&text, &h, &m);
            assert!(
                matches!(&v, KaniVerdict::Fail(p) if p.iter().any(|x| x.contains(needle))),
                "{needle}: {v:?}"
            );
        }
        assert!(matches!(judge_report(GOOD, &[], &m), KaniVerdict::Fail(_)));
    }
}
