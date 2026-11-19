//! IND-CCA2 adversaries.

use vyra_core::{EntropySource, Result};

use super::{flip_last, join, xor};
use crate::combiners::CombinerInputs;
use crate::games::{IndCca2Challenge, IndCca2Game, OracleAnswer};
use crate::models::{ModelKind, constant::CONSTANT_SECRET, leaky::leak};
use crate::scenario::{AttackContext, Side};

/// An IND-CCA2 strategy. Each returns the guess "the challenge key is real".
///
/// Strategies that obtain no information fall back to guessing "random",
/// which wins exactly when the challenger's coin chose the random key, so
/// their success rate is 1/2 in expectation; they never bias towards a win.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum IndCca2Adversary {
    /// Trivial distinguisher: a seeded fair coin. Control (d): advantage ≈ 0.
    CoinFlip,
    /// GHP18 mauling attack on one side: flip the last byte of that side's
    /// half of `c*`, query the oracle on the result, guess "real" iff the
    /// answer equals the challenge key.
    MaulReplay(Side),
    /// Mix-and-match: encapsulate fresh `(c1', k1')`, `(c2', k2')`; query
    /// `(c1*, c2')` and `(c1', c2*)`; candidate key `a ⊕ k2' ⊕ b ⊕ k1'`
    /// (correct for the XOR combiner); guess "real" iff it equals the
    /// challenge key.
    MixAndMatch,
    /// Recompute: predict each component key from the failure model
    /// (Leaky: [`leak`]; Constant: the constant); if both are predictable,
    /// evaluate the public combiner and compare with the challenge key.
    Recompute,
}

impl IndCca2Adversary {
    /// Every IND-CCA2 strategy.
    pub const ALL: [IndCca2Adversary; 5] = [
        IndCca2Adversary::CoinFlip,
        IndCca2Adversary::MaulReplay(Side::First),
        IndCca2Adversary::MaulReplay(Side::Second),
        IndCca2Adversary::MixAndMatch,
        IndCca2Adversary::Recompute,
    ];

    /// Short name.
    pub const fn name(self) -> &'static str {
        match self {
            IndCca2Adversary::CoinFlip => "CoinFlip",
            IndCca2Adversary::MaulReplay(Side::First) => "MaulReplay-1",
            IndCca2Adversary::MaulReplay(Side::Second) => "MaulReplay-2",
            IndCca2Adversary::MixAndMatch => "MixAndMatch",
            IndCca2Adversary::Recompute => "Recompute",
        }
    }

    /// One-line description.
    pub const fn description(self) -> &'static str {
        match self {
            IndCca2Adversary::CoinFlip => "trivial distinguisher: seeded fair coin",
            IndCca2Adversary::MaulReplay(_) => {
                "maul one side of c*, query Dec, guess real iff answer = challenge key"
            }
            IndCca2Adversary::MixAndMatch => {
                "query (c1*,c2') and (c1',c2*) with self-made c1',c2'; XOR-combine; compare"
            }
            IndCca2Adversary::Recompute => {
                "predict both component keys from the failure models, evaluate the combiner, compare"
            }
        }
    }

    /// Play one game. Returns the guess "the challenge key is real".
    ///
    /// # Errors
    ///
    /// Harness errors (malformed objects built by the adversary itself, RNG).
    pub fn play(
        self,
        ctx: &AttackContext,
        game: &mut IndCca2Game<'_>,
        ch: &IndCca2Challenge,
        rng: &mut dyn EntropySource,
    ) -> Result<bool> {
        match self {
            IndCca2Adversary::CoinFlip => {
                let mut b = [0u8; 1];
                rng.fill(&mut b)?;
                Ok(b.iter().any(|v| v & 1 == 1))
            }
            IndCca2Adversary::MaulReplay(side) => {
                let (c1, c2) = ctx.split_ciphertext(&ch.ciphertext)?;
                let query = match side {
                    Side::First => join(&flip_last(c1), c2),
                    Side::Second => join(c1, &flip_last(c2)),
                };
                Ok(match game.decapsulate(&query) {
                    OracleAnswer::Key(k) => k.ct_eq(&ch.key),
                    OracleAnswer::Rejected | OracleAnswer::Refused => false,
                })
            }
            IndCca2Adversary::MixAndMatch => {
                let (pk1, pk2) = ctx.split_public_key(&ch.public_key)?;
                let (c1, c2) = ctx.split_ciphertext(&ch.ciphertext)?;
                let (c1p, k1p) = ctx.component(Side::First).encapsulate(pk1, rng)?;
                let (c2p, k2p) = ctx.component(Side::Second).encapsulate(pk2, rng)?;
                let a = game.decapsulate(&join(c1, &c2p));
                let b = game.decapsulate(&join(&c1p, c2));
                Ok(match (a, b) {
                    (OracleAnswer::Key(a), OracleAnswer::Key(b)) => {
                        let cand = xor(
                            &xor(a.expose(), k2p.expose()),
                            &xor(b.expose(), k1p.expose()),
                        );
                        cand.as_slice() == ch.key.expose()
                    }
                    _ => false,
                })
            }
            IndCca2Adversary::Recompute => {
                let (pk1, pk2) = ctx.split_public_key(&ch.public_key)?;
                let (c1, c2) = ctx.split_ciphertext(&ch.ciphertext)?;
                let k1 = predict(ctx.scenario.model(Side::First), pk1, c1);
                let k2 = predict(ctx.scenario.model(Side::Second), pk2, c2);
                Ok(match (k1, k2) {
                    (Some(k1), Some(k2)) => {
                        let key = ctx.scenario.combiner.combine(&CombinerInputs {
                            ss1: &k1,
                            ss2: &k2,
                            ct1: c1,
                            ct2: c2,
                            pk1,
                            pk2,
                        });
                        key.ct_eq(&ch.key)
                    }
                    _ => false,
                })
            }
        }
    }
}

/// The component key, if the failure model makes it public.
fn predict(model: ModelKind, pk: &[u8], ct: &[u8]) -> Option<[u8; 32]> {
    match model {
        ModelKind::Leaky => Some(leak(pk, ct)),
        ModelKind::Constant => Some(CONSTANT_SECRET),
        ModelKind::Real
        | ModelKind::Malleable
        | ModelKind::KeySubstitutable
        | ModelKind::SenderKeyed => None,
    }
}
