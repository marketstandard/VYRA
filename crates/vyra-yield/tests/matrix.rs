//! The full matrix at small N: controls and the expected verdict pattern for
//! the Vyra combiner. These assert *observed* attack outcomes for the
//! implemented adversaries only; they are not security proofs.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::sync::OnceLock;

use vyra_yield::adversaries::{AdversaryKind, IndCca2Adversary};
use vyra_yield::combiners::CombinerKind;
use vyra_yield::controls::{evaluate_controls, evaluate_kem_expectations, evaluate_vyra_claims};
use vyra_yield::experiment::{CellResult, coin_flip_calibration, default_plan, run_matrix};
use vyra_yield::games::GameKind;
use vyra_yield::models::ModelKind;
use vyra_yield::report::{Report, to_json};
use vyra_yield::sig::experiment::garbage_calibration;
use vyra_yield::stats::Verdict;

const TRIALS: u64 = 32;
const SEED: &str = "vyra-yield-integration-test";

fn results() -> &'static [CellResult] {
    static CELL: OnceLock<Vec<CellResult>> = OnceLock::new();
    CELL.get_or_init(|| {
        let threads = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);
        run_matrix(&default_plan(), SEED, TRIALS, threads).expect("matrix runs")
    })
}

fn broken(r: &CellResult) -> bool {
    r.estimate.verdict == Verdict::Broken
}

#[test]
fn every_control_passes() {
    for c in evaluate_controls(results()) {
        assert!(c.passed, "control {} failed: {:?}", c.id, c.mismatches);
    }
}

#[test]
fn vyra_claim_checks_pass() {
    for c in evaluate_vyra_claims(results()) {
        assert!(c.passed, "claim check {} failed: {:?}", c.id, c.mismatches);
    }
}

#[test]
fn positive_control_every_combiner_broken_when_both_confidentiality_broken() {
    let both = [
        (ModelKind::Leaky, ModelKind::Leaky),
        (ModelKind::Constant, ModelKind::Constant),
        (ModelKind::Leaky, ModelKind::Constant),
    ];
    for c in CombinerKind::ALL {
        for p in both {
            assert!(
                results().iter().any(|r| r.spec.game == GameKind::IndCca2
                    && r.spec.scenario.combiner == c
                    && (r.spec.scenario.first, r.spec.scenario.second) == p
                    && r.spec.adversary == AdversaryKind::IndCca2(IndCca2Adversary::Recompute)
                    && broken(r)),
                "{c:?} {p:?} not broken by Recompute"
            );
        }
    }
}

#[test]
fn naive_malleable_is_broken_by_mauling() {
    // DECISIONS D-01 in executable form.
    let hits: Vec<_> = results()
        .iter()
        .filter(|r| {
            r.spec.game == GameKind::IndCca2
                && r.spec.scenario.combiner == CombinerKind::Naive
                && r.spec.scenario.broken_count() == 1
                && (r.spec.scenario.first == ModelKind::Malleable
                    || r.spec.scenario.second == ModelKind::Malleable)
                && matches!(
                    r.spec.adversary,
                    AdversaryKind::IndCca2(IndCca2Adversary::MaulReplay(_))
                )
                && broken(r)
        })
        .collect();
    assert_eq!(hits.len(), 2, "one mauling win per malleable side");
    for r in hits {
        assert_eq!(r.estimate.wins, TRIALS, "mauling wins every trial");
    }
}

#[test]
fn vyra_one_broken_never_broken_and_both_real_never_broken() {
    for r in results()
        .iter()
        .filter(|r| r.spec.scenario.combiner == CombinerKind::Vyra)
    {
        if r.spec.scenario.broken_count() <= 1 {
            assert!(!broken(r), "Vyra cell broken: {}", r.seed_label);
        }
    }
}

#[test]
fn vyra_binding_holds_even_with_both_components_broken() {
    // Observed pattern (not a control): VYRA hashes c1, c2, pk1, pk2, so no
    // implemented binding adversary wins against it in any failure pattern.
    for r in results().iter().filter(|r| {
        r.spec.scenario.combiner == CombinerKind::Vyra && !r.spec.game.is_distinguishing()
    }) {
        assert!(!broken(r), "Vyra binding cell broken: {}", r.seed_label);
    }
}

#[test]
fn trivial_distinguisher_has_no_advantage() {
    let cal = coin_flip_calibration(SEED, 2000).unwrap();
    assert_eq!(cal.estimate.verdict, Verdict::NoAttackFound);
    assert!(cal.estimate.ci_low <= 0.0 && cal.estimate.ci_high >= 0.0);
    assert!(cal.estimate.advantage.abs() < 0.1);
}

#[test]
fn report_is_deterministic() {
    let cal = coin_flip_calibration(SEED, 64).unwrap();
    let sig_cal = garbage_calibration(SEED, 4).unwrap();
    let controls = evaluate_controls(results());
    let claims = evaluate_vyra_claims(results());
    let expectations = evaluate_kem_expectations(results());
    let rep = Report {
        master_seed: SEED,
        trials: TRIALS,
        results: results(),
        calibration: &cal,
        controls: &controls,
        claims: &claims,
        expectations: &expectations,
        sig_trials: 4,
        sig_pq_trials: 1,
        sig_results: &[],
        sig_calibration: &sig_cal,
        sig_controls: &[],
        sig_claims: &[],
    };
    let a = to_json(&rep);
    assert_eq!(a, to_json(&rep));
    // Re-run a slice of the matrix from scratch and compare its cells.
    let plan = default_plan();
    let again = run_matrix(&plan[..40], SEED, TRIALS, 3).unwrap();
    assert_eq!(&again[..], &results()[..40]);
    assert!(a.contains("\"primitive\": \"kem\""));
    assert!(a.contains("\"schema\": \"vyra-yield-matrix/2\""));
    assert!(a.contains("\"expected\": \"NO ATTACK FOUND\", \"expected_basis\": \"claim:V1\""));
}

#[test]
fn every_kem_expectation_holds() {
    for c in evaluate_kem_expectations(results()) {
        assert!(c.passed, "expectation {} failed: {:?}", c.id, c.mismatches);
    }
}
