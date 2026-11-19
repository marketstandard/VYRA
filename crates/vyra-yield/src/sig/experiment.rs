//! The signature matrix: cells, trials, expectations.
//!
//! Seeding as on the KEM side: trial `t` of a cell draws challenger
//! randomness from `DeterministicEntropy(label/t/challenger)` (and
//! `label/t/challenger-b` for the second signer of MIX) and adversary
//! randomness from `label/t/adversary`, with
//! `label = master_seed/sig/pair/composition/model1/model2/game/adversary`.
//!
//! # Expected verdicts (basis identifiers)
//!
//! - `control:S-A` — both components Forgeable: `Forge` wins EUF-CMA against
//!   every composition.
//! - `control:S-B` — both components real: a named expectation for every
//!   (composition, pair, adversary). NO ATTACK FOUND except the designs'
//!   known, by-construction weaknesses: `Concat` (halves are default-mode
//!   standalone signatures on `M`; no key, suite or context binding),
//!   `ConcatCtx` (default-mode halves; no key binding), `Either`
//!   (OR-verification is not strongly unforgeable) and `VyraPureEd` (the
//!   pre-U12-R1 PureEd25519 half strips). For `Vyra` everything is NO ATTACK
//!   FOUND, including STRIP-COMPOSITE (vyra-sig U12-R1).
//! - `control:S-C` — `Either` with exactly one Forgeable component: `Forge`
//!   wins EUF-CMA.
//! - `control:S-D` — `Garbage` never wins.
//! - `control:S-E` — regression (history of U12-R1): `VyraPureEd` with a
//!   Forgeable ML-DSA component falls to `Recombine-Default` in
//!   STRIP-STANDALONE (the U11-S finding).
//! - `claim:yield-forgeable` — the claim after U12-R1: Vyra (both pairs)
//!   with exactly one component Forgeable is not broken in EUF-CMA,
//!   STRIP-STANDALONE (every standalone oracle mode), MIX, S-CEO, MBS,
//!   CROSS-SUITE or CROSS-CONTEXT.
//! - `claim:EUF` — Vyra with one component broken under another model: no
//!   EUF-CMA forgery (docs/SECURITY.md composite PROOF SKETCH).
//! - `claim:SUF-gap3` — Vyra with one Malleable or Forgeable component:
//!   `Maul` wins SUF-CMA (docs/SECURITY.md composite gap 3).
//! - `claim:bindings` — Vyra with one component broken under another model:
//!   no S-CEO, MIX, CROSS-SUITE or CROSS-CONTEXT win (public-key digest,
//!   suite byte and context inside `M'`; RULES 8).
//! - `claim:separation` — Vyra, stripping a half produced by a *real*
//!   component: no standalone verifier accepts it (RULES 9; Ed25519 since
//!   U12-R1).
//! - Everything else (other models in STRIP-STANDALONE and MBS, both-broken
//!   cells, non-Vyra designs outside the controls) is `UNSPECIFIED`.

use vyra_core::{DeterministicEntropy, Error, Result};

use super::adversaries::{SigAdversary, StandaloneMode};
use super::compositions::CompositionKind;
use super::games::{CmaGame, MixGame, SigGame, StandaloneGame, mbs_wins};
use super::models::SigModel;
use super::{SigContext, SigPair, SigScenario};
use crate::expected::Expected;
use crate::scenario::Side;
use crate::stats::{Estimate, evaluate_search};

/// Primitive label of signature cells.
pub const PRIMITIVE_SIG: &str = "sig";

/// Default trials per transition-pair cell.
pub const DEFAULT_SIG_TRIALS: u64 = 200;

/// Default trials per dual-PQ cell. SLH-DSA-SHAKE-128s signing is slow;
/// measured on the 32-thread build machine, each extra dual-PQ trial adds
/// about 14 s to the release report (N = 4: 148 s total; N = 10: 230 s);
/// N = 12 keeps the whole report under five minutes with headroom.
pub const DEFAULT_PQ_TRIALS: u64 = 12;

/// One signature cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SigCellSpec {
    /// Composition, pair and models.
    pub scenario: SigScenario,
    /// The game.
    pub game: SigGame,
    /// The strategy.
    pub adversary: SigAdversary,
}

impl SigCellSpec {
    /// Seed label under `master_seed`.
    pub fn seed_label(&self, master_seed: &str) -> String {
        let pair = match self.scenario.pair {
            SigPair::Transition => "transition",
            SigPair::DualPq => "dual-pq",
        };
        format!(
            "{}/sig/{}/{}/{}/{}/{}/{}",
            master_seed,
            pair,
            self.scenario.composition.name(),
            self.scenario.first.name(),
            self.scenario.second.name(),
            self.game.name(),
            self.adversary.name()
        )
    }
}

/// Outcome of one signature cell.
#[derive(Debug, Clone, PartialEq)]
pub struct SigCellResult {
    /// What was run.
    pub spec: SigCellSpec,
    /// Seed label.
    pub seed_label: String,
    /// Statistics and verdict (search game).
    pub estimate: Estimate,
}

/// Transition-pair failure patterns: both real; each broken model on one
/// side; each broken model on both sides.
pub fn transition_patterns() -> Vec<(SigModel, SigModel)> {
    let broken = [
        SigModel::Forgeable,
        SigModel::Malleable,
        SigModel::KeySubstitutable,
        SigModel::ContextIgnoring,
        SigModel::MessageCollapsing,
    ];
    let mut out = vec![(SigModel::Real, SigModel::Real)];
    for m in broken {
        out.push((m, SigModel::Real));
        out.push((SigModel::Real, m));
    }
    for m in broken {
        out.push((m, m));
    }
    out
}

/// The dual-PQ cell set: Vyra and Concat; Real × Real, Forgeable and
/// ContextIgnoring on either side; every game except SUF-CMA (its outcome is
/// a documented gap), every adversary except `Garbage` (calibrated on the
/// transition pair).
pub fn dual_pq_plan() -> Vec<SigCellSpec> {
    let patterns = [
        (SigModel::Real, SigModel::Real),
        (SigModel::Forgeable, SigModel::Real),
        (SigModel::Real, SigModel::Forgeable),
        (SigModel::ContextIgnoring, SigModel::Real),
        (SigModel::Real, SigModel::ContextIgnoring),
    ];
    let mut cells = Vec::new();
    for game in SigGame::ALL {
        if game == SigGame::SufCma {
            continue;
        }
        for (first, second) in patterns {
            for composition in [CompositionKind::Vyra, CompositionKind::Concat] {
                for adversary in SigAdversary::for_game(game) {
                    if adversary == SigAdversary::Garbage {
                        continue;
                    }
                    cells.push(SigCellSpec {
                        scenario: SigScenario {
                            composition,
                            pair: SigPair::DualPq,
                            first,
                            second,
                        },
                        game,
                        adversary,
                    });
                }
            }
        }
    }
    cells
}

/// The transition-pair matrix: every composition (including `VyraPureEd`),
/// pattern, game, adversary.
pub fn transition_plan() -> Vec<SigCellSpec> {
    let mut cells = Vec::new();
    for game in SigGame::ALL {
        for (first, second) in transition_patterns() {
            for composition in CompositionKind::ALL {
                for adversary in SigAdversary::for_game(game) {
                    cells.push(SigCellSpec {
                        scenario: SigScenario {
                            composition,
                            pair: SigPair::Transition,
                            first,
                            second,
                        },
                        game,
                        adversary,
                    });
                }
            }
        }
    }
    cells
}

/// Run one trial; `true` iff the adversary wins.
///
/// # Errors
///
/// Harness errors.
pub fn run_sig_trial(ctx: &SigContext, spec: &SigCellSpec, label: &str, t: u64) -> Result<bool> {
    let challenger =
        || DeterministicEntropy::from_seed(format!("{label}/{t}/challenger").as_bytes());
    let mut adv_rng = DeterministicEntropy::from_seed(format!("{label}/{t}/adversary").as_bytes());
    let adv = spec.adversary;
    match spec.game {
        SigGame::EufCma | SigGame::SufCma | SigGame::CrossSuite | SigGame::CrossContext => {
            let mut game = CmaGame::start(ctx.composite(), challenger())?;
            let (m, c, sig) = adv.forgery(ctx, &mut game, &mut adv_rng)?;
            Ok(match spec.game {
                SigGame::EufCma => game.euf_wins(&m, &c, &sig),
                SigGame::SufCma => game.suf_wins(&m, &c, &sig),
                SigGame::CrossSuite => game.cross_suite_wins(ctx.composite_alt(), &m, &c, &sig),
                _ => game.cross_context_wins(&m, &c, &sig),
            })
        }
        SigGame::StripComposite => {
            let SigAdversary::StripHalf(side) = adv else {
                return Err(Error::Internal("strip game needs StripHalf"));
            };
            let mut game = CmaGame::start(ctx.composite(), challenger())?;
            let (m_hat, half) = SigAdversary::strip(side, ctx, &mut game, &mut adv_rng)?;
            Ok(game.strip_wins(side, ctx.component(side), &m_hat, &half))
        }
        SigGame::StripStandalone => {
            let SigAdversary::Recombine(mode) = adv else {
                return Err(Error::Internal("standalone game needs Recombine"));
            };
            let mut game = StandaloneGame::start(
                ctx.composite(),
                ctx.component(Side::First),
                ctx.component(Side::Second),
                challenger(),
            )?;
            let (m, c, sig) = SigAdversary::recombine(mode, ctx, &mut game, &mut adv_rng)?;
            Ok(game.wins(&m, &c, &sig))
        }
        SigGame::Sceo => {
            let mut game = CmaGame::start(ctx.composite(), challenger())?;
            let (pk, m, c, sig) = SigAdversary::substitute(ctx, &mut game, &mut adv_rng)?;
            Ok(game.sceo_wins(&pk, &m, &c, &sig))
        }
        SigGame::Mbs => {
            let (pk, m1, m2, c, sig) = SigAdversary::collapse(ctx, &mut adv_rng)?;
            Ok(mbs_wins(ctx.composite(), &pk, (&m1, &c), (&m2, &c), &sig))
        }
        SigGame::Mix => {
            let b = DeterministicEntropy::from_seed(format!("{label}/{t}/challenger-b").as_bytes());
            let mut game = MixGame::start(ctx.composite(), challenger(), b)?;
            let (pk, m, c, sig) = SigAdversary::mix(ctx, &mut game, &mut adv_rng)?;
            Ok(game.wins(ctx.composite(), &pk, &m, &c, &sig))
        }
    }
}

/// Run one cell for `trials` trials.
///
/// # Errors
///
/// Harness errors.
pub fn run_sig_cell(spec: &SigCellSpec, master_seed: &str, trials: u64) -> Result<SigCellResult> {
    let ctx = SigContext::new(spec.scenario)?;
    let seed_label = spec.seed_label(master_seed);
    let mut wins = 0u64;
    for t in 0..trials {
        if run_sig_trial(&ctx, spec, &seed_label, t)? {
            wins = wins.saturating_add(1);
        }
    }
    Ok(SigCellResult {
        spec: *spec,
        seed_label,
        estimate: evaluate_search(wins, trials),
    })
}

/// Run the dual-PQ cells (first, since they are the slowest) and then the
/// transition cells, in parallel; results in the order dual-PQ, transition.
///
/// # Errors
///
/// Harness errors.
pub fn run_sig_matrix(
    master_seed: &str,
    trials: u64,
    pq_trials: u64,
    threads: usize,
) -> Result<Vec<SigCellResult>> {
    let mut cells: Vec<(SigCellSpec, u64)> =
        dual_pq_plan().into_iter().map(|c| (c, pq_trials)).collect();
    cells.extend(transition_plan().into_iter().map(|c| (c, trials)));
    crate::parallel::map(&cells, threads, |(spec, n)| {
        run_sig_cell(spec, master_seed, *n)
    })
}

/// The trivial-adversary calibration: `Garbage` in EUF-CMA against Vyra over
/// two real transition components.
///
/// # Errors
///
/// Harness errors.
pub fn garbage_calibration(master_seed: &str, trials: u64) -> Result<SigCellResult> {
    let spec = SigCellSpec {
        scenario: SigScenario {
            composition: CompositionKind::Vyra,
            pair: SigPair::Transition,
            first: SigModel::Real,
            second: SigModel::Real,
        },
        game: SigGame::EufCma,
        adversary: SigAdversary::Garbage,
    };
    run_sig_cell(&spec, &format!("{master_seed}/sig-calibration"), trials)
}

/// Expected verdict of the both-real control (S-B) for a transition or
/// dual-PQ scenario.
fn real_real_expected(composition: CompositionKind, pair: SigPair, adv: SigAdversary) -> Expected {
    use SigAdversary as A;
    use StandaloneMode as S;
    let transition = pair == SigPair::Transition;
    let broken = match composition {
        CompositionKind::Vyra => false,
        CompositionKind::VyraPureEd => matches!(adv, A::StripHalf(Side::Second)),
        // Default-mode halves: the default oracle completes them; the
        // empty-context oracle does too unless a half is Ed25519 (Ed25519ph
        // with empty context is not PureEd25519).
        CompositionKind::Concat => {
            matches!(
                adv,
                A::StripHalf(_)
                    | A::Recombine(S::Default)
                    | A::MixHalves
                    | A::Relabel
                    | A::SwapContext
            ) || (!transition && adv == A::Recombine(S::EmptyContext))
        }
        CompositionKind::ConcatCtx => {
            matches!(
                adv,
                A::StripHalf(_) | A::Recombine(S::Default) | A::MixHalves
            )
        }
        CompositionKind::Either => matches!(adv, A::Maul),
    };
    if broken {
        Expected::Broken
    } else {
        Expected::NoAttackFound
    }
}

/// Expected verdict and basis of a signature cell (see the module docs).
pub fn sig_expected(spec: &SigCellSpec) -> (Expected, &'static str) {
    let s = spec.scenario;
    let adv = spec.adversary;
    if adv == SigAdversary::Garbage {
        return (Expected::NoAttackFound, "control:S-D");
    }
    if spec.game == SigGame::EufCma
        && adv == SigAdversary::Forge
        && s.first == SigModel::Forgeable
        && s.second == SigModel::Forgeable
    {
        return (Expected::Broken, "control:S-A");
    }
    if s.composition == CompositionKind::Either
        && spec.game == SigGame::EufCma
        && adv == SigAdversary::Forge
        && s.broken_count() == 1
        && (s.first == SigModel::Forgeable || s.second == SigModel::Forgeable)
    {
        return (Expected::Broken, "control:S-C");
    }
    if s.composition == CompositionKind::VyraPureEd
        && s.first == SigModel::Forgeable
        && s.second == SigModel::Real
        && adv == SigAdversary::Recombine(StandaloneMode::Default)
    {
        return (Expected::Broken, "control:S-E");
    }
    if s.broken_count() == 0 {
        return (
            real_real_expected(s.composition, s.pair, adv),
            "control:S-B",
        );
    }
    if s.composition != CompositionKind::Vyra || s.broken_count() != 1 {
        return (Expected::Unspecified, "none");
    }
    let broken_model = if s.first.is_real() { s.second } else { s.first };
    if broken_model == SigModel::Forgeable
        && matches!(
            spec.game,
            SigGame::EufCma
                | SigGame::StripStandalone
                | SigGame::Mix
                | SigGame::Sceo
                | SigGame::Mbs
                | SigGame::CrossSuite
                | SigGame::CrossContext
        )
    {
        return (Expected::NoAttackFound, "claim:yield-forgeable");
    }
    match spec.game {
        SigGame::EufCma => (Expected::NoAttackFound, "claim:EUF"),
        SigGame::SufCma => match adv {
            SigAdversary::Maul
                if matches!(broken_model, SigModel::Malleable | SigModel::Forgeable) =>
            {
                (Expected::Broken, "claim:SUF-gap3")
            }
            SigAdversary::Forge => (Expected::NoAttackFound, "claim:EUF"),
            _ => (Expected::Unspecified, "none"),
        },
        SigGame::StripComposite => match adv {
            SigAdversary::StripHalf(side) if s.model(side).is_real() => (
                real_real_expected(CompositionKind::Vyra, s.pair, adv),
                "claim:separation",
            ),
            _ => (Expected::Unspecified, "none"),
        },
        SigGame::Sceo | SigGame::Mix | SigGame::CrossSuite | SigGame::CrossContext => {
            (Expected::NoAttackFound, "claim:bindings")
        }
        SigGame::StripStandalone | SigGame::Mbs => (Expected::Unspecified, "none"),
    }
}
