//! Gates Y1 and Y2: yielding resistance (failure injection, `vyra-yield`).
//!
//! Y1 runs the crate's tests. Y2 regenerates the yield matrix into
//! `target/verify/yield-matrix/`, requires the JSON to be byte-identical to
//! the committed `results/yield-matrix.json` (the experiment is deterministic
//! and the committed evidence is current), and then checks the verdict
//! pattern the committed JSON records ([`evaluate`]).

use serde_json::Value;

use super::{Ctx, Finding, cargo, secs};
use crate::exec;
use crate::report::Status;

/// Verdict label of a cell where an implemented attack won significantly.
pub const BROKEN: &str = "BROKEN";
/// Verdict label of a cell where no implemented attack won.
pub const NO_ATTACK: &str = "NO ATTACK FOUND";
/// The failure model that means "component not failed".
const REAL: &str = "Real";

/// Y1: `cargo test -p vyra-yield --locked`.
pub fn y1(ctx: &mut Ctx, _id: &str) -> Finding {
    cargo::crate_tests(ctx, "vyra-yield")
}

/// What [`evaluate`] counted.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Tally {
    /// Cells per primitive family, in first-seen order.
    pub families: Vec<(String, usize)>,
    /// Cells whose verdict was compared with an `expected` field.
    pub with_expected: usize,
    /// KEM cells: real VYRA combiner, exactly one failed component.
    pub vyra_single_failure: usize,
    /// KEM cells: naive combiner, one Malleable component, BROKEN.
    pub naive_malleable_broken: usize,
    /// KEM groups (combiner x pattern) with both components
    /// confidentiality-broken that are BROKEN in IND-CCA2.
    pub positive_groups: usize,
    /// Signature-side (non-KEM) cells checked by the single-failure rule.
    pub other_single_failure: usize,
    /// Non-KEM cells that neither carry `expected` nor fit the rule.
    pub other_unchecked: usize,
    /// Controls and claim checks found (all must have passed).
    pub checks: usize,
}

fn text<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str)
}

/// Number of failed (non-`Real`) components of a cell, if it names its models.
fn failed_components(cell: &Value) -> Option<usize> {
    let m1 = text(cell, "model_1")?;
    let m2 = text(cell, "model_2")?;
    Some(usize::from(m1 != REAL) + usize::from(m2 != REAL))
}

/// Short label of a cell for messages.
fn label(cell: &Value) -> String {
    text(cell, "seed").map_or_else(
        || {
            format!(
                "{}/{}/{}x{}/{}/{}",
                text(cell, "primitive").unwrap_or("kem"),
                text(cell, "combiner").unwrap_or("?"),
                text(cell, "model_1").unwrap_or("?"),
                text(cell, "model_2").unwrap_or("?"),
                text(cell, "game").unwrap_or("?"),
                text(cell, "adversary").unwrap_or("?"),
            )
        },
        str::to_string,
    )
}

/// Check the verdict pattern recorded in a yield-matrix document.
///
/// Every cell: its verdict is BROKEN or NO ATTACK FOUND, and equals its
/// `expected` field when that field is one of those two verdicts (any other
/// value, e.g. `UNSPECIFIED`, states no expectation). KEM cells (`primitive`
/// `"kem"` or absent), always: every cell of the real `Vyra` combiner with
/// exactly one failed component is NO ATTACK FOUND (at least one such cell);
/// the `Naive` combiner has at least one BROKEN cell with one `Malleable`
/// component and one `Real` one; positive controls: for every combiner and
/// every pattern whose two components are both `Leaky` / `Constant`, some
/// IND-CCA2 cell is BROKEN (at least one such group). Other families
/// (signature rows): judged only by their `expected` field when the cells
/// carry one; cells without that field that name a `Vyra` combiner and
/// exactly one failed component must be NO ATTACK FOUND. Every recorded
/// control, claim check and expectation check must have `passed: true`,
/// every control described as a positive control among them, and the
/// calibration cells (`calibration`, and `sig_calibration` if present) must
/// be NO ATTACK FOUND.
///
/// # Errors
///
/// Every violated expectation, one message each.
pub fn evaluate(doc: &Value) -> Result<Tally, Vec<String>> {
    let mut problems = Vec::new();
    let mut t = Tally::default();
    match text(doc, "schema") {
        Some(s) if s.starts_with("vyra-yield-matrix/") => {}
        other => problems.push(format!("schema is {other:?}, expected vyra-yield-matrix/*")),
    }
    let cells = doc
        .get("cells")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if cells.is_empty() {
        problems.push("no cells".to_string());
    }

    let mut positive: Vec<(String, String, String, bool)> = Vec::new();
    let mut positive_controls = 0usize;
    for cell in &cells {
        let family = text(cell, "primitive").unwrap_or("kem").to_string();
        match t.families.iter_mut().find(|(f, _)| *f == family) {
            Some((_, n)) => *n += 1,
            None => t.families.push((family.clone(), 1)),
        }
        let verdict = text(cell, "verdict").unwrap_or("");
        if verdict != BROKEN && verdict != NO_ATTACK {
            problems.push(format!("{}: verdict {verdict:?}", label(cell)));
            continue;
        }
        // `expected` is the expectation the JSON itself encodes (schema 2).
        // Any value other than the two verdicts (e.g. "UNSPECIFIED") means
        // that the experiment states no expectation for that cell.
        let has_expected_field = cell.get("expected").is_some();
        let expected = text(cell, "expected").filter(|e| *e == BROKEN || *e == NO_ATTACK);
        if let Some(e) = expected {
            t.with_expected += 1;
            if e != verdict {
                problems.push(format!("{}: verdict {verdict}, expected {e}", label(cell)));
            }
        }
        let combiner = text(cell, "combiner").unwrap_or("");
        let failed = failed_components(cell);
        if family == "kem" {
            if combiner == "Vyra" && failed == Some(1) {
                t.vyra_single_failure += 1;
                if verdict != NO_ATTACK {
                    problems.push(format!(
                        "{}: real VYRA combiner with one failed component is {verdict}",
                        label(cell)
                    ));
                }
            }
            let models = (text(cell, "model_1"), text(cell, "model_2"));
            if combiner == "Naive"
                && matches!(
                    models,
                    (Some("Malleable"), Some(REAL)) | (Some(REAL), Some("Malleable"))
                )
                && verdict == BROKEN
            {
                t.naive_malleable_broken += 1;
            }
            let conf_broken = |m: Option<&str>| matches!(m, Some("Leaky" | "Constant"));
            if text(cell, "game") == Some("IND-CCA2")
                && conf_broken(models.0)
                && conf_broken(models.1)
            {
                let key = (
                    combiner.to_string(),
                    models.0.unwrap_or("").to_string(),
                    models.1.unwrap_or("").to_string(),
                );
                let hit = verdict == BROKEN;
                match positive
                    .iter_mut()
                    .find(|(c, a, b, _)| (c, a, b) == (&key.0, &key.1, &key.2))
                {
                    Some(g) => g.3 |= hit,
                    None => positive.push((key.0, key.1, key.2, hit)),
                }
            }
        } else if has_expected_field {
            // Signature rows of a JSON that encodes expectations: only those
            // are judged (some single-failure cells are expected BROKEN,
            // e.g. strong unforgeability with a malleable component).
            if expected.is_none() {
                t.other_unchecked += 1;
            }
        } else {
            if combiner.contains("Vyra") && failed == Some(1) {
                t.other_single_failure += 1;
                if verdict != NO_ATTACK {
                    problems.push(format!(
                        "{}: VYRA combiner with one failed component is {verdict}",
                        label(cell)
                    ));
                }
            } else {
                t.other_unchecked += 1;
            }
        }
    }
    if t.families.iter().any(|(f, _)| f == "kem") {
        if t.vyra_single_failure == 0 {
            problems
                .push("no KEM cell of the Vyra combiner with exactly one failed component".into());
        }
        if t.naive_malleable_broken == 0 {
            problems.push(
                "the Naive combiner has no BROKEN cell with a single Malleable component".into(),
            );
        }
        if positive.is_empty() {
            problems.push("no positive-control cells (both components Leaky/Constant)".into());
        }
        for (c, a, b, hit) in &positive {
            if *hit {
                t.positive_groups += 1;
            } else {
                problems.push(format!(
                    "positive control not BROKEN: {c} over {a} x {b} in IND-CCA2"
                ));
            }
        }
    } else {
        problems.push("no KEM cells".into());
    }

    // `expectation_checks` exists from schema 2 on; the other two always.
    for key in ["controls", "claim_checks", "expectation_checks"] {
        let list = doc
            .get(key)
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if list.is_empty() && key != "expectation_checks" {
            problems.push(format!("no {key}"));
        }
        for c in &list {
            t.checks += 1;
            let id = text(c, "id").unwrap_or("?");
            let passed = c.get("passed").and_then(Value::as_bool) == Some(true);
            if text(c, "description").is_some_and(|d| d.starts_with("Positive control")) {
                positive_controls += 1;
            }
            if !passed {
                problems.push(format!("{key} {id} did not pass"));
            }
        }
    }
    if positive_controls == 0 {
        problems.push("no control described as a positive control".into());
    }
    match doc.get("calibration").and_then(|c| text(c, "verdict")) {
        Some(NO_ATTACK) => {}
        other => problems.push(format!(
            "calibration verdict {other:?}, expected {NO_ATTACK}"
        )),
    }
    if let Some(c) = doc.get("sig_calibration")
        && text(c, "verdict") != Some(NO_ATTACK)
    {
        problems.push(format!(
            "sig_calibration verdict {:?}, expected {NO_ATTACK}",
            text(c, "verdict")
        ));
    }

    if problems.is_empty() {
        Ok(t)
    } else {
        Err(problems)
    }
}

/// One-line description of a tally.
pub fn describe(t: &Tally) -> String {
    let fam: Vec<String> = t.families.iter().map(|(f, n)| format!("{f} {n}")).collect();
    format!(
        "cells by primitive: {}; {} with `expected` (all equal); KEM: {} Vyra cells with one failed component all NO ATTACK FOUND, {} Naive single-Malleable cells BROKEN, {} positive-control groups BROKEN; other families: {} Vyra single-failure cells (no `expected` field) NO ATTACK FOUND, {} cells with no stated expectation (not judged); {} controls/claim/expectation checks all passed; calibration NO ATTACK FOUND",
        fam.join(", "),
        t.with_expected,
        t.vyra_single_failure,
        t.naive_malleable_broken,
        t.positive_groups,
        t.other_single_failure,
        t.other_unchecked,
        t.checks
    )
}

/// Y2: regenerate, byte-compare with the committed matrix, check the pattern.
pub fn y2(ctx: &mut Ctx, _id: &str) -> Finding {
    let scratch = ctx.target_dir().join("yield-matrix");
    let scratch_text = scratch.to_string_lossy().into_owned();
    let args = [
        "run",
        "-p",
        "vyra-yield",
        "--release",
        "--locked",
        "--bin",
        "yield-report",
        "--",
        "--out",
        scratch_text.as_str(),
    ];
    let method = format!(
        "cargo {} ; byte-compare yield-matrix.json with results/yield-matrix.json ; check the verdict pattern of the committed JSON",
        args.join(" ")
    );
    let committed_path = ctx.root.join("results/yield-matrix.json");
    let Ok(committed) = std::fs::read(&committed_path) else {
        return Finding::check(method, false, "results/yield-matrix.json does not exist");
    };
    let _ = std::fs::remove_dir_all(&scratch);
    let o = ctx.cargo(&args, &[]);
    let mut evidence = vec![format!(
        "$ cargo run -p vyra-yield --release --bin yield-report -> exit {:?} ({})",
        o.code,
        secs(o.duration)
    )];
    let mut ok = o.success();
    if !ok {
        evidence.push(exec::tail(&o.combined(), 15, 1500));
    }
    match std::fs::read(scratch.join("yield-matrix.json")) {
        Err(e) => {
            ok = false;
            evidence.push(format!("fresh yield-matrix.json not written: {e}"));
        }
        Ok(fresh) if fresh == committed => evidence.push(format!(
            "fresh yield-matrix.json is byte-identical to results/yield-matrix.json ({} bytes)",
            fresh.len()
        )),
        Ok(fresh) => {
            ok = false;
            let detail = crate::json::first_line_diff(
                &String::from_utf8_lossy(&committed),
                &String::from_utf8_lossy(&fresh),
            )
            .map_or_else(
                || "contents differ (line endings or trailing bytes)".to_string(),
                |(line, c, f)| {
                    format!("first difference at line {line}:\n  committed: {c}\n  fresh:     {f}")
                },
            );
            evidence.push(format!(
                "fresh yield-matrix.json differs from results/yield-matrix.json (regenerate with `cargo run -p vyra-yield --release --bin yield-report -- --out results/`): {detail}"
            ));
        }
    }
    let md_same = match (
        std::fs::read(scratch.join("yield-matrix.md")),
        std::fs::read(ctx.root.join("results/yield-matrix.md")),
    ) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    };
    evidence.push(format!(
        "yield-matrix.md {} the committed one (informational)",
        if md_same { "equals" } else { "DIFFERS FROM" }
    ));
    match crate::json::parse(
        &String::from_utf8_lossy(&committed),
        "results/yield-matrix.json",
    )
    .map_err(|e| vec![e])
    .and_then(|doc| evaluate(&doc))
    {
        Ok(t) => evidence.push(describe(&t)),
        Err(p) => {
            ok = false;
            evidence.push(format!(
                "verdict pattern violated ({}):\n{}",
                p.len(),
                p.iter().take(20).cloned().collect::<Vec<_>>().join("\n")
            ));
        }
    }
    Finding {
        method,
        status: if ok { Status::Pass } else { Status::Fail },
        exit_code: o.code,
        evidence: evidence.join("\n"),
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)] // serde_json::Value indexing on test fixtures
mod tests {
    use super::*;
    use serde_json::json;

    fn cell(prim: Option<&str>, comb: &str, m1: &str, m2: &str, game: &str, v: &str) -> Value {
        let mut c = json!({"combiner": comb, "model_1": m1, "model_2": m2, "game": game,
                           "adversary": "A", "verdict": v});
        if let (Some(p), Some(o)) = (prim, c.as_object_mut()) {
            o.insert("primitive".into(), json!(p));
        }
        c
    }

    fn doc(cells: Vec<Value>) -> Value {
        json!({
            "schema": "vyra-yield-matrix/1",
            "calibration": {"verdict": NO_ATTACK},
            "controls": [{"id": "A", "passed": true, "description": "Positive control: x"}],
            "claim_checks": [{"id": "V1", "passed": true, "description": "y"}],
            "cells": cells,
        })
    }

    fn good_cells() -> Vec<Value> {
        vec![
            cell(
                Some("kem"),
                "Vyra",
                "Malleable",
                "Real",
                "IND-CCA2",
                NO_ATTACK,
            ),
            cell(
                Some("kem"),
                "Vyra",
                "Real",
                "Leaky",
                "HON-BIND-K-CT",
                NO_ATTACK,
            ),
            cell(Some("kem"), "Vyra", "Real", "Real", "IND-CCA2", NO_ATTACK),
            cell(
                Some("kem"),
                "Naive",
                "Real",
                "Malleable",
                "IND-CCA2",
                BROKEN,
            ),
            cell(
                Some("kem"),
                "Naive",
                "Real",
                "Malleable",
                "IND-CCA2",
                NO_ATTACK,
            ),
            cell(
                Some("kem"),
                "Vyra",
                "Leaky",
                "Constant",
                "IND-CCA2",
                NO_ATTACK,
            ),
            cell(Some("kem"), "Vyra", "Leaky", "Constant", "IND-CCA2", BROKEN),
            cell(None, "Naive", "Leaky", "Leaky", "IND-CCA2", BROKEN),
        ]
    }

    #[test]
    fn accepts_the_expected_pattern() {
        let t = evaluate(&doc(good_cells())).unwrap_or_default();
        assert_eq!(t.vyra_single_failure, 2);
        assert_eq!(t.naive_malleable_broken, 1);
        assert_eq!(t.positive_groups, 2);
        assert_eq!(t.families, vec![("kem".to_string(), 8)]);
        assert_eq!(t.checks, 2);
    }

    #[test]
    fn rejects_a_broken_vyra_single_failure_cell() {
        let mut cells = good_cells();
        cells.push(cell(
            None,
            "Vyra",
            "Real",
            "Constant",
            "MAL-BIND-K-PK",
            BROKEN,
        ));
        let err = evaluate(&doc(cells)).err().unwrap_or_default();
        assert!(
            err.iter().any(|p| p.contains("real VYRA combiner")),
            "{err:?}"
        );
    }

    #[test]
    fn requires_naive_malleable_break_and_positive_controls() {
        // Every Naive cell becomes NO ATTACK FOUND: the D-01 counterexample
        // and the Naive positive-control group are then missing.
        let cells: Vec<Value> = good_cells()
            .into_iter()
            .map(|mut c| {
                if c["combiner"] == "Naive" {
                    c["verdict"] = json!(NO_ATTACK);
                }
                c
            })
            .collect();
        let err = evaluate(&doc(cells)).err().unwrap_or_default();
        assert!(
            err.iter()
                .any(|p| p.contains("Naive combiner has no BROKEN")),
            "{err:?}"
        );
        assert!(
            err.iter()
                .any(|p| p.contains("positive control not BROKEN")),
            "{err:?}"
        );
    }

    #[test]
    fn failed_control_and_bad_calibration_are_reported() {
        let mut d = doc(good_cells());
        d["controls"][0]["passed"] = json!(false);
        d["calibration"]["verdict"] = json!(BROKEN);
        let err = evaluate(&d).err().unwrap_or_default();
        assert!(
            err.iter().any(|p| p.contains("controls A did not pass")),
            "{err:?}"
        );
        assert!(err.iter().any(|p| p.contains("calibration")), "{err:?}");
        assert!(evaluate(&json!({"schema": "other"})).is_err());
    }

    #[test]
    fn signature_rows_use_expected_or_the_single_failure_rule() {
        let mut cells = good_cells();
        let mut with_expected = cell(Some("sig"), "Naive", "Forgeable", "Real", "EUF-CMA", BROKEN);
        with_expected["expected"] = json!(BROKEN);
        cells.push(with_expected);
        cells.push(cell(
            Some("sig"),
            "Vyra",
            "Real",
            "Forgeable",
            "EUF-CMA",
            NO_ATTACK,
        ));
        cells.push(cell(
            Some("sig"),
            "Naive",
            "Forgeable",
            "Forgeable",
            "EUF-CMA",
            BROKEN,
        ));
        let t = evaluate(&doc(cells.clone())).unwrap_or_default();
        assert_eq!(t.with_expected, 1);
        assert_eq!(t.other_single_failure, 1);
        assert_eq!(t.other_unchecked, 1);
        assert_eq!(t.families.last(), Some(&("sig".to_string(), 3)));

        // A mismatch with `expected` fails, and so does a broken Vyra signature cell.
        let mut bad = cells.clone();
        bad.push({
            let mut c = cell(Some("sig"), "Naive", "Real", "Real", "EUF-CMA", BROKEN);
            c["expected"] = json!(NO_ATTACK);
            c
        });
        bad.push(cell(
            Some("sig"),
            "Vyra",
            "Forgeable",
            "Real",
            "EUF-CMA",
            BROKEN,
        ));
        let err = evaluate(&doc(bad)).err().unwrap_or_default();
        assert_eq!(err.len(), 2, "{err:?}");
    }

    #[test]
    fn unspecified_expectation_is_not_judged() {
        let mut cells = good_cells();
        // Schema 2: signature cells carry `expected`; a single-failure Vyra
        // cell may be expected BROKEN (e.g. SUF-CMA with a malleable half) or
        // UNSPECIFIED; neither is judged by the KEM rule.
        for (v, e) in [
            (BROKEN, BROKEN),
            (BROKEN, "UNSPECIFIED"),
            (NO_ATTACK, "UNSPECIFIED"),
        ] {
            let mut c = cell(Some("sig"), "Vyra", "Malleable", "Real", "SUF-CMA", v);
            c["expected"] = json!(e);
            cells.push(c);
        }
        let mut d = doc(cells.clone());
        d["sig_calibration"] = json!({"verdict": NO_ATTACK});
        d["expectation_checks"] = json!([{"id": "claim:V1", "passed": true, "description": "z"}]);
        let t = evaluate(&d).unwrap_or_default();
        assert_eq!(t.with_expected, 1);
        assert_eq!(t.other_unchecked, 2);
        assert_eq!(t.other_single_failure, 0);
        assert_eq!(t.checks, 3);

        // A KEM cell's UNSPECIFIED does not exempt it from the KEM rule.
        let mut kem = cell(Some("kem"), "Vyra", "Leaky", "Real", "IND-CCA2", BROKEN);
        kem["expected"] = json!("UNSPECIFIED");
        let mut bad = cells;
        bad.push(kem);
        let mut d2 = doc(bad);
        d2["expectation_checks"] = json!([{"id": "x", "passed": false, "description": "z"}]);
        d2["sig_calibration"] = json!({"verdict": BROKEN});
        let err = evaluate(&d2).err().unwrap_or_default();
        assert!(
            err.iter().any(|p| p.contains("real VYRA combiner")),
            "{err:?}"
        );
        assert!(
            err.iter().any(|p| p.contains("expectation_checks x")),
            "{err:?}"
        );
        assert!(err.iter().any(|p| p.contains("sig_calibration")), "{err:?}");
    }

    #[test]
    fn committed_matrix_meets_the_pattern() {
        let path = crate::workspace_root().join("results/yield-matrix.json");
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        assert!(!text.is_empty(), "{} missing or empty", path.display());
        let d = crate::json::parse(&text, "yield-matrix.json").unwrap_or_default();
        let r = evaluate(&d);
        assert!(r.is_ok(), "{r:?}");
    }
}
