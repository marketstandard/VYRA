//! Estimates, confidence intervals and the verdict rule.
//!
//! For each cell the harness counts `w` wins in `n` independent trials.
//!
//! - **Distinguishing games** (IND-CCA2): baseline success `p0 = 1/2`;
//!   advantage `2p̂ − 1`.
//! - **Search games** (binding): baseline success `p0 = 2^-128`, a generous
//!   upper bound on the chance of a 256-bit key collision by luck (the
//!   generic bound is `2^-256`); advantage `p̂`.
//!
//! **Verdict.** One-sided exact binomial test of `H0: p ≤ p0` against
//! `p > p0`: the p-value is `P[Bin(n, p0) ≥ w]`. A cell is `BROKEN` iff the
//! p-value is below [`ALPHA`] = 10^-6. With at most a few thousand cells per
//! run, a Bonferroni bound keeps the chance of *any* false `BROKEN` in a run
//! below 10^-2 (about 3.4·10^-3 for the default matrix of 3365 cells). For search games
//! with `p0 = 2^-128` the rule is equivalent to "at least one
//! challenger-verified win" for any `n` below about 10^30. Otherwise the
//! verdict is `NO ATTACK FOUND` — never "secure".
//!
//! **Interval.** Wilson score interval for `p` at 99% (`z = 2.5758`), mapped
//! to the advantage scale.

/// Significance level of the one-sided test.
pub const ALPHA: f64 = 1e-6;

/// Two-sided normal quantile for a 99% interval.
pub const Z_99: f64 = 2.575_829_303_548_901;

/// Confidence level of the reported interval.
pub const CI_LEVEL: f64 = 0.99;

/// Baseline success probability of a search game.
pub fn search_baseline() -> f64 {
    2f64.powi(-128)
}

/// The cell verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Verdict {
    /// Success significantly above baseline (see the module docs).
    Broken,
    /// Not significantly above baseline for the implemented adversaries.
    NoAttackFound,
}

impl Verdict {
    /// `"BROKEN"` or `"NO ATTACK FOUND"`.
    pub const fn label(self) -> &'static str {
        match self {
            Verdict::Broken => "BROKEN",
            Verdict::NoAttackFound => "NO ATTACK FOUND",
        }
    }
}

/// Statistics of one cell.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Estimate {
    /// Number of trials `n`.
    pub trials: u64,
    /// Number of wins `w`.
    pub wins: u64,
    /// Baseline success probability `p0`.
    pub baseline: f64,
    /// `w / n`.
    pub success_rate: f64,
    /// Advantage (`2p̂ − 1` or `p̂`).
    pub advantage: f64,
    /// Lower end of the 99% interval on the advantage scale.
    pub ci_low: f64,
    /// Upper end of the 99% interval on the advantage scale.
    pub ci_high: f64,
    /// One-sided p-value `P[Bin(n, p0) ≥ w]`.
    pub p_value: f64,
    /// The verdict.
    pub verdict: Verdict,
}

/// Wilson score interval for a binomial proportion.
pub fn wilson(wins: u64, trials: u64, z: f64) -> (f64, f64) {
    if trials == 0 {
        return (0.0, 1.0);
    }
    let n = trials as f64;
    let p = wins as f64 / n;
    let z2 = z * z;
    let denom = 1.0 + z2 / n;
    let center = (p + z2 / (2.0 * n)) / denom;
    let half = z / denom * (p * (1.0 - p) / n + z2 / (4.0 * n * n)).sqrt();
    ((center - half).max(0.0), (center + half).min(1.0))
}

/// `P[Bin(n, p0) ≥ w]`, computed in log space.
pub fn binomial_upper_tail(trials: u64, wins: u64, p0: f64) -> f64 {
    if wins == 0 {
        return 1.0;
    }
    if wins > trials {
        return 0.0;
    }
    let ln_p = p0.ln();
    let ln_q = (-p0).ln_1p();
    // ln k! for k = 0..=n, accumulated.
    let mut ln_fact = Vec::with_capacity(usize::try_from(trials).unwrap_or(0).saturating_add(1));
    let mut acc = 0.0f64;
    ln_fact.push(0.0);
    for k in 1..=trials {
        acc += (k as f64).ln();
        ln_fact.push(acc);
    }
    let lf = |k: u64| -> f64 {
        usize::try_from(k)
            .ok()
            .and_then(|i| ln_fact.get(i).copied())
            .unwrap_or(f64::NAN)
    };
    let terms: Vec<f64> = (wins..=trials)
        .map(|k| lf(trials) - lf(k) - lf(trials - k) + k as f64 * ln_p + (trials - k) as f64 * ln_q)
        .collect();
    let max = terms.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    if !max.is_finite() {
        return 0.0;
    }
    let sum: f64 = terms.iter().map(|t| (t - max).exp()).sum();
    (max + sum.ln()).exp().min(1.0)
}

fn verdict(p_value: f64) -> Verdict {
    if p_value < ALPHA {
        Verdict::Broken
    } else {
        Verdict::NoAttackFound
    }
}

/// Evaluate a distinguishing-game cell (baseline 1/2).
pub fn evaluate_distinguishing(wins: u64, trials: u64) -> Estimate {
    let p_hat = if trials == 0 {
        0.0
    } else {
        wins as f64 / trials as f64
    };
    let (lo, hi) = wilson(wins, trials, Z_99);
    let p_value = binomial_upper_tail(trials, wins, 0.5);
    Estimate {
        trials,
        wins,
        baseline: 0.5,
        success_rate: p_hat,
        advantage: 2.0 * p_hat - 1.0,
        ci_low: 2.0 * lo - 1.0,
        ci_high: 2.0 * hi - 1.0,
        p_value,
        verdict: verdict(p_value),
    }
}

/// Evaluate a search-game cell (baseline [`search_baseline`]).
pub fn evaluate_search(wins: u64, trials: u64) -> Estimate {
    let p_hat = if trials == 0 {
        0.0
    } else {
        wins as f64 / trials as f64
    };
    let (lo, hi) = wilson(wins, trials, Z_99);
    let p0 = search_baseline();
    let p_value = binomial_upper_tail(trials, wins, p0);
    Estimate {
        trials,
        wins,
        baseline: p0,
        success_rate: p_hat,
        advantage: p_hat,
        ci_low: lo,
        ci_high: hi,
        p_value,
        verdict: verdict(p_value),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::float_cmp)]
mod tests {
    use super::*;

    #[test]
    fn tail_matches_exact_small_cases() {
        // P[Bin(4, 1/2) >= 3] = 5/16
        assert!((binomial_upper_tail(4, 3, 0.5) - 5.0 / 16.0).abs() < 1e-12);
        assert!((binomial_upper_tail(10, 10, 0.5) - 1.0 / 1024.0).abs() < 1e-15);
        assert_eq!(binomial_upper_tail(10, 0, 0.5), 1.0);
    }

    #[test]
    fn verdicts() {
        assert_eq!(evaluate_distinguishing(200, 200).verdict, Verdict::Broken);
        assert_eq!(
            evaluate_distinguishing(110, 200).verdict,
            Verdict::NoAttackFound
        );
        assert_eq!(evaluate_search(1, 200).verdict, Verdict::Broken);
        assert_eq!(evaluate_search(0, 200).verdict, Verdict::NoAttackFound);
        let e = evaluate_distinguishing(100, 200);
        assert!(e.ci_low < 0.0 && e.ci_high > 0.0);
    }
}
