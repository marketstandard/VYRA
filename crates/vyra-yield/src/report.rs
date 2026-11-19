//! Report writers: `yield-matrix.json` and `yield-matrix.md`.
//!
//! # JSON schema `vyra-yield-matrix/2`
//!
//! Top level: `schema`, `master_seed`, `trials_per_cell` (KEM),
//! `trials_per_cell_sig` (transition-pair signature cells),
//! `trials_per_cell_sig_pq` (dual-PQ signature cells), `alpha`, `test`,
//! `caveat`, `calibration` (KEM CoinFlip cell), `sig_calibration`
//! (signature Garbage cell), `controls`, `claim_checks`,
//! `expectation_checks` (arrays of `{id, passed, cells_checked,
//! description, mismatches[]}`), and `cells`.
//!
//! Every element of `cells` has exactly these fields, in this order:
//! `primitive` (`"kem"` or `"sig"`), `combiner` (KEM combiner or signature
//! composition), `model_1`, `model_2`, `component_1`, `component_2`, `game`,
//! `adversary`, `trials`, `wins`, `baseline`, `success_rate`, `advantage`,
//! `ci_low`, `ci_high`, `ci_level`, `p_value`, `verdict` (`"BROKEN"` |
//! `"NO ATTACK FOUND"`), `expected` (`"BROKEN"` | `"NO ATTACK FOUND"` |
//! `"UNSPECIFIED"`), `expected_basis` (see [`crate::expected`] and
//! [`crate::sig::experiment`]), `seed`. KEM cells come first, then
//! signature cells (dual-PQ, then transition).
//!
//! Output is a pure function of the results: no timestamps, no host data,
//! fixed float formatting, so two runs with the same seed give byte-identical
//! files.

use core::fmt::Write as _;

use crate::adversaries::{AdversaryKind, BindingAdversary, IndCca2Adversary};
use crate::combiners::CombinerKind;
use crate::controls::Check;
use crate::expected::{Expected, kem_expected};
use crate::experiment::{CellResult, PRIMITIVE_KEM};
use crate::games::GameKind;
use crate::models::ModelKind;
use crate::scenario::{FIRST_BASE, SECOND_BASE};
use crate::sig::SigPair;
use crate::sig::adversaries::SigAdversary;
use crate::sig::compositions::CompositionKind;
use crate::sig::experiment::{PRIMITIVE_SIG, SigCellResult, sig_expected};
use crate::sig::games::SigGame;
use crate::sig::models::SigModel;
use crate::stats::{ALPHA, CI_LEVEL, Estimate, Verdict};

/// Schema identifier written to the JSON report.
pub const SCHEMA: &str = "vyra-yield-matrix/2";

/// What this evidence is and is not. Written into both reports.
pub const CAVEAT: &str = "This is falsification evidence, not a proof. Each cell runs a fixed, \
finite set of concrete attack strategies against deliberately broken toy components for a \
finite number of seeded trials. BROKEN means an implemented attack won significantly more \
often than chance (a concrete, reproducible attack). NO ATTACK FOUND means only that the \
implemented strategies did not; it is not a security statement, says nothing about attacks \
not implemented here (in particular generic or cryptanalytic attacks on ML-KEM, HQC, ML-DSA, \
SLH-DSA, Ed25519 or SHA3, quantum attacks, side channels, multi-user settings, and key-reuse \
settings beyond the one stripping game), and the failure models are idealised: a real \
component that fails will fail in its own way. The results complement, and do not replace, \
the cited GHP18 theorem and the unreviewed proof sketches in docs/SECURITY.md.";

/// Everything that goes into a report.
#[derive(Debug, Clone, Copy)]
pub struct Report<'a> {
    /// Master seed of the run.
    pub master_seed: &'a str,
    /// Trials per KEM cell.
    pub trials: u64,
    /// All KEM cells, in plan order.
    pub results: &'a [CellResult],
    /// The KEM CoinFlip calibration cell.
    pub calibration: &'a CellResult,
    /// KEM control outcomes.
    pub controls: &'a [Check],
    /// KEM Vyra claim-check outcomes.
    pub claims: &'a [Check],
    /// KEM per-basis expectation checks.
    pub expectations: &'a [Check],
    /// Trials per transition-pair signature cell.
    pub sig_trials: u64,
    /// Trials per dual-PQ signature cell.
    pub sig_pq_trials: u64,
    /// All signature cells.
    pub sig_results: &'a [SigCellResult],
    /// The signature Garbage calibration cell.
    pub sig_calibration: &'a SigCellResult,
    /// Signature control outcomes.
    pub sig_controls: &'a [Check],
    /// Signature Vyra claim-check outcomes.
    pub sig_claims: &'a [Check],
}

/// A report row, common to both primitives.
#[derive(Debug, Clone)]
struct Row<'a> {
    primitive: &'static str,
    combiner: &'static str,
    model_1: &'static str,
    model_2: &'static str,
    component_1: &'static str,
    component_2: &'static str,
    game: &'static str,
    adversary: &'static str,
    estimate: &'a Estimate,
    expected: Expected,
    basis: &'static str,
    seed: &'a str,
}

fn kem_row(r: &CellResult) -> Row<'_> {
    let s = r.spec.scenario;
    let (expected, basis) = kem_expected(&r.spec);
    Row {
        primitive: PRIMITIVE_KEM,
        combiner: s.combiner.name(),
        model_1: s.first.name(),
        model_2: s.second.name(),
        component_1: FIRST_BASE.name(),
        component_2: SECOND_BASE.name(),
        game: r.spec.game.name(),
        adversary: r.spec.adversary.name(),
        estimate: &r.estimate,
        expected,
        basis,
        seed: &r.seed_label,
    }
}

fn sig_row(r: &SigCellResult) -> Row<'_> {
    let s = r.spec.scenario;
    let (b1, b2) = s.bases();
    let (expected, basis) = sig_expected(&r.spec);
    Row {
        primitive: PRIMITIVE_SIG,
        combiner: s.composition.name(),
        model_1: s.first.name(),
        model_2: s.second.name(),
        component_1: b1.name(),
        component_2: b2.name(),
        game: r.spec.game.name(),
        adversary: r.spec.adversary.name(),
        estimate: &r.estimate,
        expected,
        basis,
        seed: &r.seed_label,
    }
}

fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len().saturating_add(2));
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Fixed six-decimal formatting; `-0` is printed as `0`.
fn num(x: f64) -> String {
    let s = format!("{x:.6}");
    if s == "-0.000000" {
        "0.000000".into()
    } else {
        s
    }
}

fn sci(x: f64) -> String {
    format!("{x:.3e}")
}

fn row_json(r: &Row<'_>) -> String {
    let e = r.estimate;
    format!(
        "{{\"primitive\": {}, \"combiner\": {}, \"model_1\": {}, \"model_2\": {}, \"component_1\": {}, \"component_2\": {}, \"game\": {}, \"adversary\": {}, \"trials\": {}, \"wins\": {}, \"baseline\": {}, \"success_rate\": {}, \"advantage\": {}, \"ci_low\": {}, \"ci_high\": {}, \"ci_level\": {}, \"p_value\": {}, \"verdict\": {}, \"expected\": {}, \"expected_basis\": {}, \"seed\": {}}}",
        json_str(r.primitive),
        json_str(r.combiner),
        json_str(r.model_1),
        json_str(r.model_2),
        json_str(r.component_1),
        json_str(r.component_2),
        json_str(r.game),
        json_str(r.adversary),
        e.trials,
        e.wins,
        sci(e.baseline),
        num(e.success_rate),
        num(e.advantage),
        num(e.ci_low),
        num(e.ci_high),
        num(CI_LEVEL),
        sci(e.p_value),
        json_str(e.verdict.label()),
        json_str(r.expected.label()),
        json_str(r.basis),
        json_str(r.seed)
    )
}

fn check_json(c: &Check) -> String {
    let mism: Vec<String> = c.mismatches.iter().map(|m| json_str(m)).collect();
    format!(
        "{{\"id\": {}, \"passed\": {}, \"cells_checked\": {}, \"description\": {}, \"mismatches\": [{}]}}",
        json_str(c.id),
        c.passed,
        c.cells_checked,
        json_str(c.description),
        mism.join(", ")
    )
}

fn checks_json(out: &mut String, key: &str, checks: &[&Check], last: bool) {
    let _ = writeln!(out, "  {}: [", json_str(key));
    let items: Vec<String> = checks
        .iter()
        .map(|c| format!("    {}", check_json(c)))
        .collect();
    out.push_str(&items.join(",\n"));
    out.push_str(if last { "\n  ]\n" } else { "\n  ],\n" });
}

fn all_rows<'a>(rep: &Report<'a>) -> Vec<Row<'a>> {
    rep.results
        .iter()
        .map(kem_row)
        .chain(rep.sig_results.iter().map(sig_row))
        .collect()
}

/// The JSON report.
pub fn to_json(rep: &Report<'_>) -> String {
    let mut out = String::new();
    out.push_str("{\n");
    let _ = writeln!(out, "  \"schema\": {},", json_str(SCHEMA));
    let _ = writeln!(out, "  \"master_seed\": {},", json_str(rep.master_seed));
    let _ = writeln!(out, "  \"trials_per_cell\": {},", rep.trials);
    let _ = writeln!(out, "  \"trials_per_cell_sig\": {},", rep.sig_trials);
    let _ = writeln!(out, "  \"trials_per_cell_sig_pq\": {},", rep.sig_pq_trials);
    let _ = writeln!(out, "  \"alpha\": {},", sci(ALPHA));
    let _ = writeln!(
        out,
        "  \"test\": {},",
        json_str(
            "one-sided exact binomial test H0: p <= baseline; BROKEN iff p_value < alpha; interval: Wilson score on p, mapped to advantage"
        )
    );
    let _ = writeln!(out, "  \"caveat\": {},", json_str(CAVEAT));
    let _ = writeln!(
        out,
        "  \"calibration\": {},",
        row_json(&kem_row(rep.calibration))
    );
    let _ = writeln!(
        out,
        "  \"sig_calibration\": {},",
        row_json(&sig_row(rep.sig_calibration))
    );
    let controls: Vec<&Check> = rep.controls.iter().chain(rep.sig_controls).collect();
    checks_json(&mut out, "controls", &controls, false);
    let claims: Vec<&Check> = rep.claims.iter().chain(rep.sig_claims).collect();
    checks_json(&mut out, "claim_checks", &claims, false);
    let exps: Vec<&Check> = rep.expectations.iter().collect();
    checks_json(&mut out, "expectation_checks", &exps, false);
    out.push_str("  \"cells\": [\n");
    let cells: Vec<String> = all_rows(rep)
        .iter()
        .map(|r| format!("    {}", row_json(r)))
        .collect();
    out.push_str(&cells.join(",\n"));
    out.push_str("\n  ]\n}\n");
    out
}

fn check_rows(out: &mut String, checks: &[&Check]) {
    out.push_str("| id | result | cells | description |\n|----|--------|-------|-------------|\n");
    for c in checks {
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} |",
            c.id,
            if c.passed { "PASS" } else { "FAIL" },
            c.cells_checked,
            c.description
        );
        for m in &c.mismatches {
            let _ = writeln!(out, "| | mismatch | | `{m}` |");
        }
    }
    out.push('\n');
}

fn kem_patterns(results: &[CellResult]) -> Vec<(ModelKind, ModelKind)> {
    let mut seen: Vec<(ModelKind, ModelKind)> = Vec::new();
    for r in results {
        let p = (r.spec.scenario.first, r.spec.scenario.second);
        if !seen.contains(&p) {
            seen.push(p);
        }
    }
    seen
}

fn summarise_group(group: &[Row<'_>]) -> String {
    if group.is_empty() {
        return "n/a".into();
    }
    let breakers: Vec<&Row<'_>> = group
        .iter()
        .filter(|r| r.estimate.verdict == Verdict::Broken)
        .collect();
    let mismatch = group
        .iter()
        .any(|r| r.expected.mismatches(r.estimate.verdict));
    let flag = if mismatch { " (!)" } else { "" };
    if breakers.is_empty() {
        let max = group
            .iter()
            .map(|r| r.estimate.advantage)
            .fold(f64::NEG_INFINITY, f64::max);
        format!("no attack found (max adv {max:.2}){flag}")
    } else {
        let names: Vec<&str> = breakers.iter().map(|r| r.adversary).collect();
        let max = breakers
            .iter()
            .map(|r| r.estimate.advantage)
            .fold(f64::NEG_INFINITY, f64::max);
        format!("**BROKEN** adv {:.2} [{}]{}", max, names.join(", "), flag)
    }
}

fn kem_section(out: &mut String, rep: &Report<'_>) {
    let rows: Vec<Row<'_>> = rep.results.iter().map(kem_row).collect();
    out.push_str("# Part 1: KEM\n\n");
    let _ = writeln!(
        out,
        "- Trials per cell: {}; cells: {}.",
        rep.trials,
        rep.results.len()
    );
    let _ = writeln!(
        out,
        "- Component 1 is built over {}, component 2 over {} (the components of VYRA-KEM-1), through VYRA's adapters.\n",
        FIRST_BASE.name(),
        SECOND_BASE.name()
    );
    out.push_str("## Legend (KEM)\n\n### Combiners\n\n| name | key |\n|------|-----|\n");
    for c in CombinerKind::ALL {
        let _ = writeln!(out, "| {} | `{}` |", c.name(), c.formula());
    }
    out.push_str("\n`Vyra` is the real `vyra_kem::combine`, run through `vyra_kem::CustomHybridKem` (the same composition code as `HybridKem`). `XWingStyle` is *in the style of* X-Wing (hashes only component 2's ciphertext and public key); it is not X-Wing. The others are comparison designs built for this experiment.\n\n");
    out.push_str("### Failure models (INTENTIONALLY INSECURE)\n\n| model | broken on purpose |\n|-------|-------------------|\n");
    for m in ModelKind::ALL {
        let _ = writeln!(out, "| {} | {} |", m.name(), m.broken_property());
    }
    out.push_str("\n### Games\n\n");
    out.push_str("- **IND-CCA2**: real-or-random key; decapsulation oracle refuses only the exact challenge ciphertext.\n");
    out.push_str("- **X-BIND-K-CT / X-BIND-K-PK** (Cremers-Dax-Medinger, as restated by Kraemer-Struck-Weishaeupl, CiC 2(2), Fig. 3): win iff two decapsulations give equal keys (neither an error) while the ciphertexts (K-CT) or public keys (K-PK) differ. HON: honest keys, public keys + oracles; LEAK: honest keys, secret keys leaked; MAL: adversary-chosen secret keys, scenario (I) Decaps-Decaps only.\n\n");
    out.push_str("### Adversaries\n\n| name | strategy |\n|------|----------|\n");
    for a in IndCca2Adversary::ALL {
        let _ = writeln!(
            out,
            "| {} | {} |",
            a.name(),
            AdversaryKind::IndCca2(a).description()
        );
    }
    for a in BindingAdversary::ALL {
        let _ = writeln!(
            out,
            "| {} | {} |",
            a.name(),
            AdversaryKind::Binding(a).description()
        );
    }
    out.push_str("\n## Controls (KEM)\n\n");
    check_rows(out, &rep.controls.iter().collect::<Vec<_>>());
    out.push_str("## Claim checks for the Vyra combiner (KEM)\n\n");
    check_rows(out, &rep.claims.iter().collect::<Vec<_>>());
    out.push_str("## Per-cell expectations (KEM)\n\n");
    check_rows(out, &rep.expectations.iter().collect::<Vec<_>>());
    out.push_str("## Calibration (KEM control D, larger sample)\n\n");
    let e = &rep.calibration.estimate;
    let _ = writeln!(
        out,
        "CoinFlip vs Vyra over Real x Real, {} trials: {} wins, advantage {} (99% CI [{}, {}]), p-value {}, verdict {}.\n",
        e.trials,
        e.wins,
        num(e.advantage),
        num(e.ci_low),
        num(e.ci_high),
        sci(e.p_value),
        e.verdict.label()
    );
    out.push_str("## Verdict matrix (KEM)\n\nRows: failure model of component 1 x component 2. Columns: combiner. A cell is BROKEN if any implemented adversary for that game is; the bracket names them. `(!)` marks a group containing a cell whose verdict contradicts its expected verdict.\n\n");
    let patterns = kem_patterns(rep.results);
    for game in GameKind::ALL {
        if !rep.results.iter().any(|r| r.spec.game == game) {
            continue;
        }
        let _ = writeln!(out, "### {}\n", game.name());
        out.push_str("| model 1 x model 2 |");
        for c in CombinerKind::ALL {
            let _ = write!(out, " {} |", c.name());
        }
        out.push_str("\n|---|");
        for _ in CombinerKind::ALL {
            out.push_str("---|");
        }
        out.push('\n');
        for p in &patterns {
            let _ = write!(out, "| {} x {} |", p.0.name(), p.1.name());
            for c in CombinerKind::ALL {
                let group: Vec<Row<'_>> = rows
                    .iter()
                    .filter(|r| {
                        r.game == game.name()
                            && r.combiner == c.name()
                            && r.model_1 == p.0.name()
                            && r.model_2 == p.1.name()
                    })
                    .cloned()
                    .collect();
                let _ = write!(out, " {} |", summarise_group(&group));
            }
            out.push('\n');
        }
        out.push('\n');
    }
}

fn sig_patterns(results: &[SigCellResult], pair: SigPair) -> Vec<(SigModel, SigModel)> {
    let mut seen: Vec<(SigModel, SigModel)> = Vec::new();
    for r in results.iter().filter(|r| r.spec.scenario.pair == pair) {
        let p = (r.spec.scenario.first, r.spec.scenario.second);
        if !seen.contains(&p) {
            seen.push(p);
        }
    }
    seen
}

fn sig_section(out: &mut String, rep: &Report<'_>) {
    let rows: Vec<(SigPair, Row<'_>)> = rep
        .sig_results
        .iter()
        .map(|r| (r.spec.scenario.pair, sig_row(r)))
        .collect();
    out.push_str("# Part 2: Signatures\n\n");
    let _ = writeln!(
        out,
        "- Transition pair (ML-DSA-44 + Ed25519, the components of VYRA-SIG-2): {} trials per cell. Dual-PQ pair (ML-DSA-44 + SLH-DSA-SHAKE-128s, the components of VYRA-SIG-PQ1): {} trials per cell, real SLH-DSA (no stand-in), Vyra and Concat only. Cells: {}.",
        rep.sig_trials,
        rep.sig_pq_trials,
        rep.sig_results.len()
    );
    out.push_str("- All signature games are search games: baseline 2^-128, BROKEN iff at least one challenger-verified win. With the dual-PQ N, NO ATTACK FOUND is weak evidence (the strategies are deterministic in effect, but N is small).\n");
    out.push_str("- `Vyra` runs the real `vyra_sig::CustomComposite` under descriptor id 0x7A (0x7B for the cross-suite target); named suite ids are rejected by that API, so equality with the named suites is shown by a test that rebuilds both from the same components (`tests/sig.rs`).\n\n");
    out.push_str("## Legend (signatures)\n\n### Compositions\n\n| name | construction |\n|------|--------------|\n");
    for c in CompositionKind::ALL {
        let _ = writeln!(out, "| {} | {} |", c.name(), c.formula());
    }
    out.push_str("\n### Failure models (INTENTIONALLY INSECURE)\n\n| model | broken on purpose |\n|-------|-------------------|\n");
    for m in SigModel::ALL {
        let _ = writeln!(out, "| {} | {} |", m.name(), m.broken_property());
    }
    out.push_str("\n### Games\n\nA message is the pair (M, ctx).\n\n");
    out.push_str("- **EUF-CMA / SUF-CMA**: standard (DFF SAC 2024 Fig. 1, verified).\n");
    out.push_str("- **STRIP-COMPOSITE** (ours): a half of an oracle composite signature accepted by some standalone verifier of that component (default mode; context variant with empty context; context variant with a foreign context) on any message.\n");
    out.push_str("- **STRIP-STANDALONE** (ours, key reuse): no composite oracle, but standalone signing oracles for both component keys in every mode a deployer could plausibly expose: default (Ed25519: PureEd25519; ML-DSA/SLH-DSA: empty context), the context variant with the empty context (Ed25519: Ed25519ph, ctx \"\"), and the context variant with any attacker-chosen context *except* the composite's own component context (that query is by definition the composite half and is refused). Adversaries: one per mode (foreign application context; another VYRA suite's context). Any valid composite output wins.\n");
    out.push_str("- **S-CEO** (BUFF, CDFFJ S&P 2021, as restated in DFF SAC 2024 Fig. 2, verified against the restatement): an oracle signature verifies the same message under pk' != pk.\n");
    out.push_str("- **MBS** (BUFF, same sources, Fig. 3): one signature verifies two different messages under an adversary-chosen key.\n");
    out.push_str(
        "- **MIX** (ours): halves of two honest signers verify under a mixed key pkA_1||pkB_2.\n",
    );
    out.push_str("- **CROSS-SUITE / CROSS-CONTEXT** (ours): a signature produced for suite byte X (context A) verifies for Y (context B).\n\n");
    out.push_str("### Adversaries\n\n| name | strategy |\n|------|----------|\n");
    let mut seen: Vec<SigAdversary> = Vec::new();
    for g in SigGame::ALL {
        for a in SigAdversary::for_game(g) {
            if !seen.contains(&a) {
                seen.push(a);
                let _ = writeln!(out, "| {} | {} |", a.name(), a.description());
            }
        }
    }
    out.push_str("\n## Controls (signatures)\n\n");
    check_rows(out, &rep.sig_controls.iter().collect::<Vec<_>>());
    out.push_str("## Claim checks for the Vyra composite (signatures)\n\n");
    check_rows(out, &rep.sig_claims.iter().collect::<Vec<_>>());
    out.push_str("## Calibration (signatures)\n\n");
    let e = &rep.sig_calibration.estimate;
    let _ = writeln!(
        out,
        "Garbage vs Vyra (transition, Real x Real) in EUF-CMA, {} trials: {} wins, verdict {}.\n",
        e.trials,
        e.wins,
        e.verdict.label()
    );

    let table = |out: &mut String, pair: SigPair, designs: &[CompositionKind]| {
        out.push_str("| pattern | design |");
        for g in SigGame::ALL {
            let _ = write!(out, " {} |", g.name());
        }
        out.push_str("\n|---|---|");
        for _ in SigGame::ALL {
            out.push_str("---|");
        }
        out.push('\n');
        for p in sig_patterns(rep.sig_results, pair) {
            if (p.0.is_real() as usize + p.1.is_real() as usize) == 0 {
                continue;
            }
            for d in designs {
                let _ = write!(out, "| {} x {} | {} |", p.0.name(), p.1.name(), d.name());
                for g in SigGame::ALL {
                    let group: Vec<Row<'_>> = rows
                        .iter()
                        .filter(|(pp, r)| {
                            *pp == pair
                                && r.combiner == d.name()
                                && r.game == g.name()
                                && r.model_1 == p.0.name()
                                && r.model_2 == p.1.name()
                        })
                        .map(|(_, r)| r.clone())
                        .collect();
                    let _ = write!(out, " {} |", summarise_group(&group));
                }
                out.push('\n');
            }
        }
        out.push('\n');
    };
    out.push_str("## Before / after vyra-sig U12-R1 (transition pair)\n\n`VyraPureEd` is the composite with the pre-U12-R1 PureEd25519 half; `Vyra` is the current design (Ed25519ph under the composite context). Rows: both real and each exactly-one-failure pattern. `(!)` marks a contradiction with the expected verdict; `n/a` means the game is not run for that pair.\n\n");
    table(
        out,
        SigPair::Transition,
        &[CompositionKind::VyraPureEd, CompositionKind::Vyra],
    );
    out.push_str("## Vyra in the dual-PQ pair\n\n");
    table(out, SigPair::DualPq, &[CompositionKind::Vyra]);

    for pair in [SigPair::DualPq, SigPair::Transition] {
        let _ = writeln!(out, "## Verdict matrix (signatures, {})\n", pair.name());
        let patterns = sig_patterns(rep.sig_results, pair);
        for g in SigGame::ALL {
            if !rows.iter().any(|(p, r)| *p == pair && r.game == g.name()) {
                continue;
            }
            let _ = writeln!(out, "### {} ({})\n", g.name(), pair.name());
            out.push_str("| model 1 x model 2 |");
            for c in CompositionKind::ALL {
                let _ = write!(out, " {} |", c.name());
            }
            out.push_str("\n|---|");
            for _ in CompositionKind::ALL {
                out.push_str("---|");
            }
            out.push('\n');
            for p in &patterns {
                let _ = write!(out, "| {} x {} |", p.0.name(), p.1.name());
                for c in CompositionKind::ALL {
                    let group: Vec<Row<'_>> = rows
                        .iter()
                        .filter(|(pp, r)| {
                            *pp == pair
                                && r.game == g.name()
                                && r.combiner == c.name()
                                && r.model_1 == p.0.name()
                                && r.model_2 == p.1.name()
                        })
                        .map(|(_, r)| r.clone())
                        .collect();
                    let _ = write!(out, " {} |", summarise_group(&group));
                }
                out.push('\n');
            }
            out.push('\n');
        }
    }
}

/// The Markdown report.
pub fn to_markdown(rep: &Report<'_>) -> String {
    let mut out = String::new();
    out.push_str("# VYRA yielding-resistance experiment: hybrid KEM and composite signatures under injected component failures\n\n");
    out.push_str("Generated by `cargo run -p vyra-yield --release --bin yield-report`. Do not edit by hand.\n\n");
    out.push_str("## What this is and is not\n\n");
    out.push_str(CAVEAT);
    out.push_str("\n\n## Method (both primitives)\n\n");
    let _ = writeln!(
        out,
        "- Master seed: `{}`. Every trial's randomness is derived from the cell's seed label (JSON `seed` field).",
        rep.master_seed
    );
    let _ = writeln!(
        out,
        "- Verdict: one-sided exact binomial test of H0 `p <= baseline` (IND-CCA2: 1/2; binding and signature games: 2^-128); **BROKEN** iff p-value < {}. Otherwise **NO ATTACK FOUND** (never \"secure\"). Intervals: Wilson score, {:.0}%, on the advantage scale.",
        sci(ALPHA),
        CI_LEVEL * 100.0
    );
    out.push_str("- Every cell carries `expected` (what VYRA's documented claims or a named control predict: BROKEN, NO ATTACK FOUND, or UNSPECIFIED) and `expected_basis`.\n\n");
    let rows = all_rows(rep);
    let mism: Vec<&Row<'_>> = rows
        .iter()
        .filter(|r| r.expected.mismatches(r.estimate.verdict))
        .collect();
    out.push_str("## Verdicts that contradict their expectation\n\n");
    if mism.is_empty() {
        out.push_str("None: every cell with an expected verdict shows it.\n\n");
    } else {
        out.push_str("| primitive | design | model 1 x model 2 | game | adversary | verdict | expected | basis |\n|---|---|---|---|---|---|---|---|\n");
        for r in mism {
            let _ = writeln!(
                out,
                "| {} | {} | {} x {} | {} | {} | {} | {} | {} |",
                r.primitive,
                r.combiner,
                r.model_1,
                r.model_2,
                r.game,
                r.adversary,
                r.estimate.verdict.label(),
                r.expected.label(),
                r.basis
            );
        }
        out.push('\n');
    }
    kem_section(&mut out, rep);
    sig_section(&mut out, rep);
    out
}
