//! The experiment: which cells exist, how a cell is run, and the matrix.
//!
//! A *cell* is (combiner, model 1, model 2, game, adversary). It is run for
//! `n` independent trials; trial `t` draws all challenger randomness from
//! `DeterministicEntropy(seed_label ‖ "/" ‖ t ‖ "/challenger")` and all
//! adversary randomness from the same with `"/adversary"`, where
//! `seed_label = master_seed/combiner/model1/model2/game/adversary`. Results
//! are therefore reproducible bit for bit and independent of thread
//! scheduling.

use vyra_core::{DeterministicEntropy, Error, Result};

use crate::adversaries::{AdversaryKind, BindingAdversary, IndCca2Adversary};
use crate::combiners::CombinerKind;
use crate::games::{BindingModel, GameKind, HonestBindingGame, IndCca2Game, MaliciousBindingGame};
use crate::models::ModelKind;
use crate::scenario::{AttackContext, Scenario};
use crate::stats::{Estimate, evaluate_distinguishing, evaluate_search};

/// The primitive family a cell belongs to. Signature-side results can be
/// added later under another value with the same report schema.
pub const PRIMITIVE_KEM: &str = "kem";

/// Default master seed of the report binary.
pub const DEFAULT_SEED: &str = "VYRA-YIELD-U11";

/// Default number of trials per cell of the report binary.
pub const DEFAULT_TRIALS: u64 = 200;

/// One cell of the matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CellSpec {
    /// Combiner and failure models.
    pub scenario: Scenario,
    /// The game.
    pub game: GameKind,
    /// The strategy.
    pub adversary: AdversaryKind,
}

impl CellSpec {
    /// The seed label of this cell under `master_seed`.
    pub fn seed_label(&self, master_seed: &str) -> String {
        format!(
            "{}/{}/{}/{}/{}/{}",
            master_seed,
            self.scenario.combiner.name(),
            self.scenario.first.name(),
            self.scenario.second.name(),
            self.game.name(),
            self.adversary.name()
        )
    }
}

/// The outcome of one cell.
#[derive(Debug, Clone, PartialEq)]
pub struct CellResult {
    /// What was run.
    pub spec: CellSpec,
    /// The seed label (see the module docs).
    pub seed_label: String,
    /// Statistics and verdict.
    pub estimate: Estimate,
}

/// The failure-model pairs of the default matrix: both real; each broken
/// model on one side with the other real; each broken model on both sides;
/// and the mixed confidentiality-broken pair Leaky × Constant.
pub fn default_patterns() -> Vec<(ModelKind, ModelKind)> {
    let broken = [
        ModelKind::Leaky,
        ModelKind::Malleable,
        ModelKind::KeySubstitutable,
        ModelKind::Constant,
        ModelKind::SenderKeyed,
    ];
    let mut out = vec![(ModelKind::Real, ModelKind::Real)];
    for m in broken {
        out.push((m, ModelKind::Real));
        out.push((ModelKind::Real, m));
    }
    for m in broken {
        out.push((m, m));
    }
    out.push((ModelKind::Leaky, ModelKind::Constant));
    out
}

/// The adversaries run in `game`.
pub fn adversaries_for(game: GameKind) -> Vec<AdversaryKind> {
    match game {
        GameKind::IndCca2 => IndCca2Adversary::ALL
            .iter()
            .map(|a| AdversaryKind::IndCca2(*a))
            .collect(),
        GameKind::Binding { target, .. } => BindingAdversary::ALL
            .iter()
            .filter(|a| a.applies_to(target))
            .map(|a| AdversaryKind::Binding(*a))
            .collect(),
    }
}

/// Every cell for the given combiners, patterns and games, in report order.
pub fn plan(
    combiners: &[CombinerKind],
    patterns: &[(ModelKind, ModelKind)],
    games: &[GameKind],
) -> Vec<CellSpec> {
    let mut cells = Vec::new();
    for game in games {
        for &(first, second) in patterns {
            for &combiner in combiners {
                for adversary in adversaries_for(*game) {
                    cells.push(CellSpec {
                        scenario: Scenario {
                            combiner,
                            first,
                            second,
                        },
                        game: *game,
                        adversary,
                    });
                }
            }
        }
    }
    cells
}

/// The full default matrix.
pub fn default_plan() -> Vec<CellSpec> {
    plan(&CombinerKind::ALL, &default_patterns(), &GameKind::ALL)
}

/// Run one trial of `spec` in `ctx`; `true` iff the adversary wins.
///
/// # Errors
///
/// Harness errors (a game/adversary mismatch, or an operation failing on
/// input the harness built itself).
pub fn run_trial(
    ctx: &AttackContext,
    spec: &CellSpec,
    seed_label: &str,
    trial: u64,
) -> Result<bool> {
    let mut challenger =
        DeterministicEntropy::from_seed(format!("{seed_label}/{trial}/challenger").as_bytes());
    let mut adversary =
        DeterministicEntropy::from_seed(format!("{seed_label}/{trial}/adversary").as_bytes());
    match (spec.game, spec.adversary) {
        (GameKind::IndCca2, AdversaryKind::IndCca2(adv)) => {
            let (mut game, challenge) = IndCca2Game::start(ctx.hybrid(), &mut challenger)?;
            let guess = adv.play(ctx, &mut game, &challenge, &mut adversary)?;
            Ok(game.finish(guess))
        }
        (GameKind::Binding { model, target }, AdversaryKind::Binding(adv)) => match model {
            BindingModel::Hon | BindingModel::Leak => {
                let (game, view) =
                    HonestBindingGame::start(ctx.hybrid(), model, target, &mut challenger)?;
                let claim = adv.play_honest(ctx, &view, &mut adversary)?;
                Ok(game.finish(&claim))
            }
            BindingModel::Mal => {
                let game = MaliciousBindingGame::new(ctx.hybrid(), target);
                let claim = adv.play_malicious(ctx, &mut adversary)?;
                Ok(game.finish(&claim))
            }
        },
        _ => Err(Error::Internal("adversary does not match game")),
    }
}

/// Run `spec` for `trials` trials under `master_seed`.
///
/// # Errors
///
/// As [`run_trial`].
pub fn run_cell(spec: &CellSpec, master_seed: &str, trials: u64) -> Result<CellResult> {
    let ctx = AttackContext::new(spec.scenario);
    let seed_label = spec.seed_label(master_seed);
    let mut wins = 0u64;
    for t in 0..trials {
        if run_trial(&ctx, spec, &seed_label, t)? {
            wins = wins.saturating_add(1);
        }
    }
    let estimate = if spec.game.is_distinguishing() {
        evaluate_distinguishing(wins, trials)
    } else {
        evaluate_search(wins, trials)
    };
    Ok(CellResult {
        spec: *spec,
        seed_label,
        estimate,
    })
}

/// Run every cell, spread over `threads` worker threads (at least one).
/// The result order equals the order of `cells` regardless of scheduling.
///
/// # Errors
///
/// The first harness error of any cell, or `Error::Internal` if a worker
/// thread panicked.
pub fn run_matrix(
    cells: &[CellSpec],
    master_seed: &str,
    trials: u64,
    threads: usize,
) -> Result<Vec<CellResult>> {
    crate::parallel::map(cells, threads, |spec| run_cell(spec, master_seed, trials))
}

/// A larger-sample self-test of the trivial distinguisher (control (d)):
/// [`IndCca2Adversary::CoinFlip`] against the `Vyra` design over two real
/// components, `trials` trials.
///
/// # Errors
///
/// As [`run_cell`].
pub fn coin_flip_calibration(master_seed: &str, trials: u64) -> Result<CellResult> {
    let spec = CellSpec {
        scenario: Scenario {
            combiner: CombinerKind::Vyra,
            first: ModelKind::Real,
            second: ModelKind::Real,
        },
        game: GameKind::IndCca2,
        adversary: AdversaryKind::IndCca2(IndCca2Adversary::CoinFlip),
    };
    run_cell(&spec, &format!("{master_seed}/calibration"), trials)
}
