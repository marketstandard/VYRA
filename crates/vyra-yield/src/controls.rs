//! Controls and claim checks, evaluated on a finished matrix.
//!
//! Controls show that the harness can detect attacks (positive), does not
//! invent them (negative), reproduces the known D-01 counterexample, and that
//! a trivial distinguisher scores no advantage. Claim checks state what the
//! project's "yielding resistance" claim predicts for the `Vyra` design.
//! Both are evaluated mechanically from the results; a failing control means
//! the harness (or the expectation) is wrong and must be investigated, never
//! tuned away.

use crate::adversaries::{AdversaryKind, IndCca2Adversary};
use crate::combiners::CombinerKind;
use crate::experiment::CellResult;
use crate::games::GameKind;
use crate::models::ModelKind;
use crate::scenario::Side;
use crate::stats::Verdict;

/// The outcome of one control or claim check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    /// Identifier, e.g. `"A"`.
    pub id: &'static str,
    /// What is checked.
    pub description: &'static str,
    /// Whether every asserted cell matched.
    pub passed: bool,
    /// Number of cells the check looked at.
    pub cells_checked: usize,
    /// The cells that did not match (seed labels).
    pub mismatches: Vec<String>,
}

fn broken(r: &CellResult) -> bool {
    r.estimate.verdict == Verdict::Broken
}

/// KEM expectation basis identifiers, in report order (see [`crate::expected`]).
pub const KEM_EXPECTATION_IDS: [&str; 8] = [
    "control:A",
    "control:A2",
    "control:B",
    "theory:XOR",
    "D-01",
    "control:D",
    "claim:V1",
    "claim:V2",
];

/// Description of a KEM expectation basis.
pub fn describe_kem(id: &str) -> &'static str {
    match id {
        "control:A" => {
            "Recompute wins IND-CCA2 when both components are confidentiality-broken (all non-Vyra combiners)"
        }
        "control:A2" => {
            "Naive over Constant x Constant: both-sides binding adversaries win every binding game"
        }
        "control:B" => {
            "Both components real: no adversary wins against Naive, CtBound, XWingStyle, Vyra"
        }
        "theory:XOR" => {
            "XOR over two real components: MixAndMatch wins IND-CCA2, nothing else wins"
        }
        "D-01" => "Naive with one Malleable component: MaulReplay on that side wins IND-CCA2",
        "control:D" => "CoinFlip never wins",
        "claim:V1" => "Vyra with exactly one broken component: no adversary wins any game",
        "claim:V2" => "Vyra with both components confidentiality-broken: Recompute wins IND-CCA2",
        _ => "unknown basis",
    }
}

/// Per-cell expectation checks for the KEM matrix (every cell whose
/// expected verdict is not UNSPECIFIED, grouped by basis).
pub fn evaluate_kem_expectations(results: &[CellResult]) -> Vec<Check> {
    let judged: Vec<Judged<'_>> = results
        .iter()
        .map(|r| {
            let (expected, basis) = crate::expected::kem_expected(&r.spec);
            Judged {
                expected,
                basis,
                verdict: r.estimate.verdict,
                label: &r.seed_label,
            }
        })
        .collect();
    expectation_checks(&judged, &KEM_EXPECTATION_IDS, describe_kem)
}

/// One cell as seen by [`expectation_checks`].
#[derive(Debug, Clone, Copy)]
pub struct Judged<'a> {
    /// Expected verdict.
    pub expected: crate::expected::Expected,
    /// Basis identifier (e.g. `"claim:V1"`).
    pub basis: &'static str,
    /// Observed verdict.
    pub verdict: Verdict,
    /// Seed label of the cell.
    pub label: &'a str,
}

/// Group cells by expectation basis (`ids`, in order) and check that every
/// cell with that basis shows its expected verdict. `describe` gives the
/// description of a basis.
pub fn expectation_checks<'a>(
    cells: &[Judged<'a>],
    ids: &[&'static str],
    describe: fn(&str) -> &'static str,
) -> Vec<Check> {
    ids.iter()
        .map(|id| {
            let group: Vec<&Judged<'a>> = cells.iter().filter(|c| c.basis == *id).collect();
            let mismatches: Vec<String> = group
                .iter()
                .filter(|c| c.expected.mismatches(c.verdict))
                .map(|c| c.label.to_string())
                .collect();
            Check {
                id,
                description: describe(id),
                passed: !group.is_empty() && mismatches.is_empty(),
                cells_checked: group.len(),
                mismatches,
            }
        })
        .collect()
}

fn check(
    id: &'static str,
    description: &'static str,
    cells: Vec<&CellResult>,
    expect: impl Fn(&CellResult) -> bool,
) -> Check {
    let mismatches: Vec<String> = cells
        .iter()
        .filter(|r| !expect(r))
        .map(|r| r.seed_label.clone())
        .collect();
    Check {
        id,
        description,
        passed: !cells.is_empty() && mismatches.is_empty(),
        cells_checked: cells.len(),
        mismatches,
    }
}

/// Check that for every scenario selected by `select`, at least one
/// adversary in `game` wins (BROKEN).
fn some_adversary_breaks(
    id: &'static str,
    description: &'static str,
    results: &[CellResult],
    game: GameKind,
    select: impl Fn(&CellResult) -> bool,
) -> Check {
    let mut scenarios: Vec<_> = results
        .iter()
        .filter(|r| r.spec.game == game && select(r))
        .map(|r| r.spec.scenario)
        .collect();
    scenarios.sort();
    scenarios.dedup();
    let mismatches: Vec<String> = scenarios
        .iter()
        .filter(|s| {
            !results
                .iter()
                .any(|r| r.spec.game == game && r.spec.scenario == **s && broken(r))
        })
        .map(|s| format!("{s} / {}", game.name()))
        .collect();
    Check {
        id,
        description,
        passed: !scenarios.is_empty() && mismatches.is_empty(),
        cells_checked: scenarios.len(),
        mismatches,
    }
}

/// Evaluate controls A, A2, B, B-XOR, C and D.
pub fn evaluate_controls(results: &[CellResult]) -> Vec<Check> {
    let mut out = Vec::new();
    out.push(some_adversary_breaks(
        "A",
        "Positive control: both components confidentiality-broken (Leaky/Constant) -> every combiner BROKEN in IND-CCA2 by some adversary",
        results,
        GameKind::IndCca2,
        |r| {
            r.spec.scenario.first.breaks_confidentiality()
                && r.spec.scenario.second.breaks_confidentiality()
        },
    ));
    for game in GameKind::ALL.iter().filter(|g| !g.is_distinguishing()) {
        out.push(some_adversary_breaks(
            "A2",
            "Positive control (binding games winnable): Naive over Constant x Constant -> BROKEN in every binding game",
            results,
            *game,
            |r| {
                r.spec.scenario.combiner == CombinerKind::Naive
                    && r.spec.scenario.first == ModelKind::Constant
                    && r.spec.scenario.second == ModelKind::Constant
            },
        ));
    }
    out.push(check(
        "B",
        "Negative control: both components real -> no adversary wins against Naive, CtBound, XWingStyle, Vyra in any game",
        results
            .iter()
            .filter(|r| {
                r.spec.scenario.broken_count() == 0 && r.spec.scenario.combiner != CombinerKind::Xor
            })
            .collect(),
        |r| !broken(r),
    ));
    out.push(check(
        "B-XOR",
        "Negative control, XOR combiner (theory: XOR is not IND-CCA2 even over two IND-CCA2 KEMs): both real -> BROKEN only by MixAndMatch in IND-CCA2, nothing else",
        results
            .iter()
            .filter(|r| {
                r.spec.scenario.broken_count() == 0 && r.spec.scenario.combiner == CombinerKind::Xor
            })
            .collect(),
        |r| {
            broken(r)
                == (r.spec.adversary == AdversaryKind::IndCca2(IndCca2Adversary::MixAndMatch))
        },
    ));
    out.push(check(
        "C",
        "D-01 counterexample: Naive with one Malleable component -> BROKEN in IND-CCA2 by mauling that side",
        results
            .iter()
            .filter(|r| {
                let s = r.spec.scenario;
                r.spec.game == GameKind::IndCca2
                    && s.combiner == CombinerKind::Naive
                    && s.broken_count() == 1
                    && ((s.first == ModelKind::Malleable
                        && r.spec.adversary
                            == AdversaryKind::IndCca2(IndCca2Adversary::MaulReplay(Side::First)))
                        || (s.second == ModelKind::Malleable
                            && r.spec.adversary
                                == AdversaryKind::IndCca2(IndCca2Adversary::MaulReplay(
                                    Side::Second,
                                ))))
            })
            .collect(),
        broken,
    ));
    out.push(check(
        "D",
        "Trivial distinguisher (CoinFlip) -> NO ATTACK FOUND in every IND-CCA2 cell",
        results
            .iter()
            .filter(|r| r.spec.adversary == AdversaryKind::IndCca2(IndCca2Adversary::CoinFlip))
            .collect(),
        |r| !broken(r),
    ));
    out
}

/// Evaluate what the yielding-resistance claim predicts for `Vyra`.
pub fn evaluate_vyra_claims(results: &[CellResult]) -> Vec<Check> {
    let vyra = |r: &&CellResult| r.spec.scenario.combiner == CombinerKind::Vyra;
    vec![
        check(
            "V1",
            "Vyra, exactly one component broken (any model) -> NO ATTACK FOUND under every implemented adversary in every game",
            results
                .iter()
                .filter(vyra)
                .filter(|r| r.spec.scenario.broken_count() == 1)
                .collect(),
            |r| !broken(r),
        ),
        some_adversary_breaks(
            "V2",
            "Vyra, both components confidentiality-broken -> BROKEN in IND-CCA2 (nothing left to protect)",
            results,
            GameKind::IndCca2,
            |r| {
                r.spec.scenario.combiner == CombinerKind::Vyra
                    && r.spec.scenario.first.breaks_confidentiality()
                    && r.spec.scenario.second.breaks_confidentiality()
            },
        ),
    ]
}
