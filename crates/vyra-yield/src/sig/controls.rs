//! Signature controls and Vyra claim checks, derived mechanically from the
//! per-cell expectations of [`super::experiment::sig_expected`].

use super::experiment::{SigCellResult, sig_expected};
use crate::controls::{Check, Judged, expectation_checks};

/// Control basis identifiers, in report order.
pub const SIG_CONTROL_IDS: [&str; 5] = [
    "control:S-A",
    "control:S-B",
    "control:S-C",
    "control:S-D",
    "control:S-E",
];

/// Vyra claim basis identifiers, in report order.
pub const SIG_CLAIM_IDS: [&str; 5] = [
    "claim:yield-forgeable",
    "claim:EUF",
    "claim:SUF-gap3",
    "claim:bindings",
    "claim:separation",
];

/// Description of a signature basis identifier.
pub fn describe(id: &str) -> &'static str {
    match id {
        "control:S-A" => {
            "Positive: both components Forgeable -> Forge wins EUF-CMA against every composition"
        }
        "control:S-B" => {
            "Negative: both real -> named expectation per composition/adversary (NO ATTACK FOUND for Vyra in every game; by-design weaknesses of VyraPureEd, Concat, ConcatCtx, Either named)"
        }
        "control:S-C" => {
            "Either (OR-verification) with one Forgeable component -> Forge wins EUF-CMA"
        }
        "control:S-D" => "Trivial adversary (Garbage) never wins",
        "control:S-E" => {
            "Regression: VyraPureEd (pre-U12-R1 PureEd25519 half) with Forgeable ML-DSA -> Recombine-Default wins STRIP-STANDALONE"
        }
        "claim:yield-forgeable" => {
            "Vyra, exactly one component Forgeable -> no win in EUF-CMA, STRIP-STANDALONE (all oracle modes), MIX, S-CEO, MBS, CROSS-SUITE, CROSS-CONTEXT"
        }
        "claim:EUF" => {
            "Vyra, one component broken under another model -> no EUF-CMA forgery (SECURITY.md composite sketch)"
        }
        "claim:SUF-gap3" => {
            "Vyra, one Malleable or Forgeable component -> SUF-CMA broken (SECURITY.md composite gap 3)"
        }
        "claim:bindings" => {
            "Vyra, one component broken under another model -> no S-CEO, MIX, CROSS-SUITE, CROSS-CONTEXT win (pk digest, suite, ctx in M')"
        }
        "claim:separation" => {
            "Vyra, stripping a real half: no standalone verifier (default, empty ctx, foreign ctx) accepts it"
        }
        _ => "unknown basis",
    }
}

fn judged(results: &[SigCellResult]) -> Vec<Judged<'_>> {
    results
        .iter()
        .map(|r| {
            let (expected, basis) = sig_expected(&r.spec);
            Judged {
                expected,
                basis,
                verdict: r.estimate.verdict,
                label: &r.seed_label,
            }
        })
        .collect()
}

/// Evaluate the signature controls.
pub fn evaluate_sig_controls(results: &[SigCellResult]) -> Vec<Check> {
    expectation_checks(&judged(results), &SIG_CONTROL_IDS, describe)
}

/// Evaluate the Vyra signature claim checks.
pub fn evaluate_sig_claims(results: &[SigCellResult]) -> Vec<Check> {
    expectation_checks(&judged(results), &SIG_CLAIM_IDS, describe)
}
