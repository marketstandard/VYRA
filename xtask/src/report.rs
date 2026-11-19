//! Gate results: console table, JSON and Markdown report.

use std::fmt::Write as _;
use std::time::Duration;

use serde_json::{Value, json};

/// Outcome of one gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// The pass condition held.
    Pass,
    /// The pass condition did not hold.
    Fail,
    /// The gate could not be evaluated (tool missing, or quick mode); never a pass.
    NotRun,
}

impl Status {
    /// Report spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Pass => "PASS",
            Status::Fail => "FAIL",
            Status::NotRun => "NOT_RUN",
        }
    }
}

/// The record of one gate.
#[derive(Debug, Clone)]
pub struct GateResult {
    /// Gate id, e.g. `F1`.
    pub id: String,
    /// What the gate checks.
    pub description: String,
    /// Command line(s) or method used.
    pub method: String,
    /// Outcome.
    pub status: Status,
    /// Exit code of the decisive command, if a command was run.
    pub exit_code: Option<i32>,
    /// Wall-clock duration.
    pub duration: Duration,
    /// Short evidence (output tail, findings).
    pub evidence: String,
}

/// Report-level metadata.
#[derive(Debug, Clone)]
pub struct Meta {
    /// `quick` or `full`.
    pub mode: String,
    /// Commit of the working tree, if known.
    pub commit: Option<String>,
    /// Date-time of the run (UTC).
    pub date_utc: String,
    /// Whether the working tree had uncommitted changes when verify started.
    pub dirty_at_start: Option<bool>,
}

/// Counts `(pass, fail, not_run)`.
pub fn counts(results: &[GateResult]) -> (usize, usize, usize) {
    let c = |s: Status| results.iter().filter(|r| r.status == s).count();
    (c(Status::Pass), c(Status::Fail), c(Status::NotRun))
}

/// The JSON report document.
pub fn to_json(meta: &Meta, results: &[GateResult]) -> Value {
    let (pass, fail, not_run) = counts(results);
    let gates: Vec<Value> = results
        .iter()
        .map(|r| {
            json!({
                "id": r.id,
                "description": r.description,
                "method": r.method,
                "status": r.status.as_str(),
                "exit_code": r.exit_code,
                "duration_s": (r.duration.as_secs_f64() * 10.0).round() / 10.0,
                "evidence": r.evidence,
            })
        })
        .collect();
    json!({
        "generator": "cargo xtask verify",
        "mode": meta.mode,
        "commit": meta.commit,
        "dirty_at_start": meta.dirty_at_start,
        "date_utc": meta.date_utc,
        "summary": {"pass": pass, "fail": fail, "not_run": not_run, "total": results.len()},
        "overall": if fail == 0 { "no gate FAIL" } else { "at least one gate FAIL" },
        "note": "PASS means the gate's command or check succeeded; it demonstrates functional correctness and hygiene properties only, not cryptographic security (docs/CHECKS.md).",
        "gates": gates,
    })
}

fn md_cell(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', "<br>")
}

/// The Markdown report.
pub fn to_markdown(meta: &Meta, results: &[GateResult]) -> String {
    let (pass, fail, not_run) = counts(results);
    let mut s = String::from("# VYRA verification report\n\n");
    let _ = writeln!(s, "- mode: {}", meta.mode);
    let _ = writeln!(
        s,
        "- commit: {}",
        meta.commit.as_deref().unwrap_or("unknown")
    );
    let _ = writeln!(
        s,
        "- working tree dirty at start: {}",
        meta.dirty_at_start
            .map_or("unknown".to_string(), |d| d.to_string())
    );
    let _ = writeln!(s, "- date (UTC): {}", meta.date_utc);
    let _ = writeln!(
        s,
        "- summary: {pass} PASS, {fail} FAIL, {not_run} NOT_RUN of {}",
        results.len()
    );
    s.push_str(
        "\nPASS demonstrates that a gate's command or check succeeded. It does not demonstrate \
         that VYRA is cryptographically secure (see docs/CHECKS.md). NOT_RUN is never a pass.\n\n\
         | gate | status | exit | time (s) | description |\n|---|---|---|---|---|\n",
    );
    for r in results {
        let _ = writeln!(
            s,
            "| {} | {} | {} | {:.1} | {} |",
            r.id,
            r.status.as_str(),
            r.exit_code.map_or("-".to_string(), |c| c.to_string()),
            r.duration.as_secs_f64(),
            md_cell(&r.description)
        );
    }
    s.push_str("\n## Details\n");
    for r in results {
        let _ = write!(
            s,
            "\n### {} — {}\n\n- description: {}\n- method: `{}`\n\n```text\n{}\n```\n",
            r.id,
            r.status.as_str(),
            r.description,
            r.method.replace('`', "'"),
            r.evidence.replace("```", "'''")
        );
    }
    s
}

/// A fixed-width console table.
pub fn console_table(results: &[GateResult]) -> String {
    let mut s = String::new();
    let _ = writeln!(
        s,
        "{:<5} {:<8} {:>5} {:>8}  description",
        "gate", "status", "exit", "time(s)"
    );
    for r in results {
        let first = r.evidence.lines().next().unwrap_or("");
        let short: String = first.chars().take(70).collect();
        let _ = writeln!(
            s,
            "{:<5} {:<8} {:>5} {:>8.1}  {} :: {}",
            r.id,
            r.status.as_str(),
            r.exit_code.map_or("-".to_string(), |c| c.to_string()),
            r.duration.as_secs_f64(),
            r.description,
            short
        );
    }
    let (pass, fail, not_run) = counts(results);
    let _ = writeln!(s, "\n{pass} PASS, {fail} FAIL, {not_run} NOT_RUN");
    s
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn sample() -> (Meta, Vec<GateResult>) {
        let meta = Meta {
            mode: "quick".into(),
            commit: Some("abc".into()),
            date_utc: "2026-01-01T00:00:00Z".into(),
            dirty_at_start: Some(true),
        };
        let r = |id: &str, status| GateResult {
            id: id.into(),
            description: "d|x".into(),
            method: "cargo `x`".into(),
            status,
            exit_code: Some(0),
            duration: Duration::from_millis(1234),
            evidence: "line1\nline2".into(),
        };
        (
            meta,
            vec![
                r("F1", Status::Pass),
                r("S12", Status::NotRun),
                r("C1", Status::Fail),
            ],
        )
    }

    #[test]
    fn json_report_shape() {
        let (meta, results) = sample();
        let v = to_json(&meta, &results);
        assert_eq!(v["summary"]["pass"], 1);
        assert_eq!(v["summary"]["fail"], 1);
        assert_eq!(v["summary"]["not_run"], 1);
        assert_eq!(v["gates"][1]["status"], "NOT_RUN");
        assert_eq!(v["gates"][0]["duration_s"], 1.2);
        assert_eq!(v["gates"][0]["exit_code"], 0);
        // Canonical serialisation is stable and parses back.
        let text = crate::json::to_canonical(&v);
        let back = crate::json::parse(&text, "report").unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn markdown_escapes_cells() {
        let (meta, results) = sample();
        let md = to_markdown(&meta, &results);
        assert!(md.contains("| F1 | PASS | 0 | 1.2 | d\\|x |"));
        assert!(md.contains("1 PASS, 1 FAIL, 1 NOT_RUN of 3"));
        assert!(md.contains("### S12 — NOT_RUN"));
    }
}
