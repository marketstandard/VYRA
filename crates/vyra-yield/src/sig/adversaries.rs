//! Signature adversaries: concrete, seeded strategies. Each knows the
//! scenario (composition and failure models) and uses what the failure model
//! it faces makes possible.

use vyra_core::{EntropySource, Result};

use super::SigContext;
use super::compositions::VYRA_ALT_ID;
use super::games::{CmaGame, FOREIGN_CONTEXT, MixGame, OracleMode, SigGame, StandaloneGame};
use super::models::SigModel;
use super::models::forgeable::forge;
use super::models::key_substitutable::substitute_public_key;
use super::models::malleable::maul;
use super::models::message_collapsing::collapse;
use crate::adversaries::flip_last;
use crate::scenario::Side;
use vyra_sig::composite_context;

/// Application context used for signing queries.
pub const CTX_A: &[u8] = b"yield-app-ctx-A";
/// A second application context (cross-context game).
pub const CTX_B: &[u8] = b"yield-app-ctx-B";

/// Maximum number of candidates tried in a collision search (the expected
/// number for a 12-bit digest is 4096).
pub const COLLISION_TRIES: u32 = 1 << 16;

/// An adversary output `(public key, M, ctx, σ)`.
pub type KeyedForgery = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

/// An MBS output `(public key, M1, M2, ctx, σ)`.
pub type DoubleMessage = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

/// A signature strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SigAdversary {
    /// Trivial: a random byte string as a signature on a fresh message.
    Garbage,
    /// Query `m0`; on a fresh `m1`, forge every Forgeable half
    /// ([`forge`] on the composition's input for `m1`); keep the other halves
    /// from the signature on `m0`.
    Forge,
    /// Query `m0`; search `m1 ≠ m0` whose composition input has the same
    /// collapsing digest as `m0`'s; output the signature on `m0` for `m1`.
    Collide,
    /// Query `m0`; output a different signature on `m0`: maul Malleable
    /// halves, replace Forgeable halves by forged tags; if nothing applies,
    /// flip the last byte of half 2.
    Maul,
    /// Query `m0`; output the given half of the signature as a standalone
    /// signature on the composition's input string for `m0`.
    StripHalf(Side),
    /// Standalone oracles only: build the composition input for a message,
    /// get each half from the standalone oracle in the given mode (or forge
    /// it if Forgeable), output the concatenation.
    Recombine(StandaloneMode),
    /// Query `m0`; output the same signature under `pk'` with every
    /// KeySubstitutable half substituted (or, if none, the last byte of `pk`
    /// flipped).
    SubstituteKey,
    /// Own key: sign `m0`, find a colliding `m1` as in `Collide`, output both
    /// messages with one signature.
    Collapse,
    /// Two honest signers sign the same `(m, ctx)`; output `σA_1 ‖ σB_2`
    /// under `pkA_1 ‖ pkB_2`.
    MixHalves,
    /// Query under suite byte X; output the same signature for suite byte Y.
    Relabel,
    /// Query `(m0, ctx A)`; output the same signature for `(m0, ctx B)`.
    SwapContext,
}

impl SigAdversary {
    /// Report name.
    pub const fn name(self) -> &'static str {
        match self {
            SigAdversary::Garbage => "Garbage",
            SigAdversary::Forge => "Forge",
            SigAdversary::Collide => "Collide",
            SigAdversary::Maul => "Maul",
            SigAdversary::StripHalf(Side::First) => "StripHalf-1",
            SigAdversary::StripHalf(Side::Second) => "StripHalf-2",
            SigAdversary::Recombine(StandaloneMode::Default) => "Recombine-Default",
            SigAdversary::Recombine(StandaloneMode::EmptyContext) => "Recombine-EmptyCtx",
            SigAdversary::Recombine(StandaloneMode::ForeignContext) => "Recombine-ForeignCtx",
            SigAdversary::Recombine(StandaloneMode::OtherSuiteContext) => "Recombine-SuiteCtx",
            SigAdversary::SubstituteKey => "SubstituteKey",
            SigAdversary::Collapse => "Collapse",
            SigAdversary::MixHalves => "MixHalves",
            SigAdversary::Relabel => "Relabel",
            SigAdversary::SwapContext => "SwapContext",
        }
    }

    /// One-line description.
    pub const fn description(self) -> &'static str {
        match self {
            SigAdversary::Garbage => "trivial: random bytes as a signature on a fresh message",
            SigAdversary::Forge => "forge Forgeable halves on a fresh message, reuse the others",
            SigAdversary::Collide => {
                "find a message whose input collides under the 12-bit collapsing digest; reuse the signature"
            }
            SigAdversary::Maul => {
                "new signature on a signed message: maul Malleable halves / re-forge Forgeable halves"
            }
            SigAdversary::StripHalf(_) => {
                "present one half of a composite signature to the standalone component verifier"
            }
            SigAdversary::Recombine(StandaloneMode::Default) => {
                "assemble a composite from standalone default-mode signatures (Ed25519: PureEd25519; ML-DSA/SLH-DSA: empty ctx)"
            }
            SigAdversary::Recombine(StandaloneMode::EmptyContext) => {
                "assemble a composite from context-variant signatures with the empty context (Ed25519: Ed25519ph, ctx \"\")"
            }
            SigAdversary::Recombine(StandaloneMode::ForeignContext) => {
                "assemble a composite from context-variant signatures under a foreign application context"
            }
            SigAdversary::Recombine(StandaloneMode::OtherSuiteContext) => {
                "assemble a composite from context-variant signatures under another VYRA suite's composite context"
            }
            SigAdversary::SubstituteKey => {
                "same signature under a substituted public key (KeySubstitutable halves)"
            }
            SigAdversary::Collapse => "one signature on two colliding messages under an own key",
            SigAdversary::MixHalves => "splice halves of two honest signers under a mixed key",
            SigAdversary::Relabel => "reuse a suite-X signature under suite Y",
            SigAdversary::SwapContext => "reuse a ctx-A signature under ctx B",
        }
    }

    /// The adversaries run in `game`.
    pub fn for_game(game: SigGame) -> Vec<SigAdversary> {
        match game {
            SigGame::EufCma => vec![
                SigAdversary::Garbage,
                SigAdversary::Forge,
                SigAdversary::Collide,
            ],
            SigGame::SufCma => vec![SigAdversary::Maul, SigAdversary::Forge],
            SigGame::StripComposite => vec![
                SigAdversary::StripHalf(Side::First),
                SigAdversary::StripHalf(Side::Second),
            ],
            SigGame::StripStandalone => StandaloneMode::ALL
                .iter()
                .map(|m| SigAdversary::Recombine(*m))
                .collect(),
            SigGame::Sceo => vec![SigAdversary::SubstituteKey],
            SigGame::Mbs => vec![SigAdversary::Collapse],
            SigGame::Mix => vec![SigAdversary::MixHalves],
            SigGame::CrossSuite => vec![SigAdversary::Relabel],
            SigGame::CrossContext => vec![SigAdversary::SwapContext],
        }
    }
}

/// Which standalone oracle mode a [`SigAdversary::Recombine`] uses (see
/// [`OracleMode`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum StandaloneMode {
    /// [`OracleMode::Default`].
    Default,
    /// [`OracleMode::EmptyContext`].
    EmptyContext,
    /// [`OracleMode::Context`] with [`FOREIGN_CONTEXT`].
    ForeignContext,
    /// [`OracleMode::Context`] with the composite context of another VYRA
    /// suite byte ([`VYRA_ALT_ID`]).
    OtherSuiteContext,
}

impl StandaloneMode {
    /// Every mode.
    pub const ALL: [StandaloneMode; 4] = [
        StandaloneMode::Default,
        StandaloneMode::EmptyContext,
        StandaloneMode::ForeignContext,
        StandaloneMode::OtherSuiteContext,
    ];

    /// The oracle request.
    pub fn oracle_mode(self) -> OracleMode {
        match self {
            StandaloneMode::Default => OracleMode::Default,
            StandaloneMode::EmptyContext => OracleMode::EmptyContext,
            StandaloneMode::ForeignContext => OracleMode::Context(FOREIGN_CONTEXT.to_vec()),
            StandaloneMode::OtherSuiteContext => {
                OracleMode::Context(composite_context(VYRA_ALT_ID).to_vec())
            }
        }
    }
}

/// A fresh query message: a fixed prefix plus 8 random bytes.
pub(crate) fn fresh_message(rng: &mut dyn EntropySource) -> Result<Vec<u8>> {
    let mut r = [0u8; 8];
    rng.fill(&mut r)?;
    Ok([&b"vyra-yield message "[..], &r[..]].concat())
}

/// Search `m1 = m0 ‖ counter` (counter little-endian) whose composition input
/// under `pk` has the same collapsing digest as `m0`'s, if any side is
/// MessageCollapsing; otherwise the first candidate. Returns the last
/// candidate tried if the search fails (the attack then loses).
pub(crate) fn colliding_message(
    ctx: &SigContext,
    pk: &[u8],
    m0: &[u8],
    c: &[u8],
) -> Result<Vec<u8>> {
    let any = Side::BOTH
        .iter()
        .any(|s| ctx.scenario.model(*s) == SigModel::MessageCollapsing);
    let target = collapse(&ctx.signed_input(pk, m0, c)?.0);
    let mut candidate = Vec::new();
    for counter in 0..COLLISION_TRIES {
        candidate = [m0, &counter.to_le_bytes()[..]].concat();
        if !any || collapse(&ctx.signed_input(pk, &candidate, c)?.0) == target {
            break;
        }
    }
    Ok(candidate)
}

fn halves_with<F>(ctx: &SigContext, sig: &[u8], mut f: F) -> Result<Vec<u8>>
where
    F: FnMut(Side, &[u8]) -> Result<Vec<u8>>,
{
    let (h1, h2) = ctx.split_sig(sig)?;
    let mut out = f(Side::First, h1)?;
    out.extend_from_slice(&f(Side::Second, h2)?);
    Ok(out)
}

fn side_pk<'a>(ctx: &SigContext, pk: &'a [u8], side: Side) -> Result<&'a [u8]> {
    let (a, b) = ctx.split_pk(pk)?;
    Ok(match side {
        Side::First => a,
        Side::Second => b,
    })
}

impl SigAdversary {
    /// Play a game whose output is a forgery `(M, ctx, σ)` against `game`'s
    /// key (EUF-CMA, SUF-CMA, CROSS-SUITE, CROSS-CONTEXT).
    ///
    /// # Errors
    ///
    /// Harness errors; `Internal` for an adversary that does not output a
    /// forgery.
    pub fn forgery(
        self,
        ctx: &SigContext,
        game: &mut CmaGame<'_>,
        rng: &mut dyn EntropySource,
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        let m0 = fresh_message(rng)?;
        let sig0 = game.sign(&m0, CTX_A)?;
        let pk = game.public_key.clone();
        match self {
            SigAdversary::Garbage => {
                let mut sig = vec![0u8; sig0.len()];
                rng.fill(&mut sig)?;
                Ok(([&m0[..], b"!"].concat(), CTX_A.to_vec(), sig))
            }
            SigAdversary::Forge => {
                let m1 = [&m0[..], b"!"].concat();
                let (input, cctx) = ctx.signed_input(&pk, &m1, CTX_A)?;
                let sig = halves_with(ctx, &sig0, |side, half| {
                    Ok(match ctx.scenario.model(side) {
                        SigModel::Forgeable => {
                            forge(side_pk(ctx, &pk, side)?, &cctx, &input, half.len())
                        }
                        _ => half.to_vec(),
                    })
                })?;
                Ok((m1, CTX_A.to_vec(), sig))
            }
            SigAdversary::Collide => {
                let m1 = colliding_message(ctx, &pk, &m0, CTX_A)?;
                Ok((m1, CTX_A.to_vec(), sig0))
            }
            SigAdversary::Maul => {
                let (input, cctx) = ctx.signed_input(&pk, &m0, CTX_A)?;
                let mut changed = false;
                let mut sig = halves_with(ctx, &sig0, |side, half| {
                    Ok(match ctx.scenario.model(side) {
                        SigModel::Malleable => {
                            changed = true;
                            maul(half)
                        }
                        SigModel::Forgeable => {
                            let f = forge(side_pk(ctx, &pk, side)?, &cctx, &input, half.len());
                            changed |= f.as_slice() != half;
                            f
                        }
                        _ => half.to_vec(),
                    })
                })?;
                if !changed {
                    sig = flip_last(&sig);
                }
                Ok((m0, CTX_A.to_vec(), sig))
            }
            SigAdversary::Relabel => Ok((m0, CTX_A.to_vec(), sig0)),
            SigAdversary::SwapContext => Ok((m0, CTX_B.to_vec(), sig0)),
            _ => Err(vyra_core::Error::Internal("not a forgery adversary")),
        }
    }

    /// STRIP-COMPOSITE: `(side, m̂, σ̂)`.
    ///
    /// # Errors
    ///
    /// Harness errors.
    pub fn strip(
        side: Side,
        ctx: &SigContext,
        game: &mut CmaGame<'_>,
        rng: &mut dyn EntropySource,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let m0 = fresh_message(rng)?;
        let sig0 = game.sign(&m0, CTX_A)?;
        let (input, _) = ctx.signed_input(&game.public_key, &m0, CTX_A)?;
        let (h1, h2) = ctx.split_sig(&sig0)?;
        let half = match side {
            Side::First => h1,
            Side::Second => h2,
        };
        Ok((input, half.to_vec()))
    }

    /// STRIP-STANDALONE: a composite `(M, ctx, σ)` from standalone oracles.
    ///
    /// # Errors
    ///
    /// Harness errors.
    pub fn recombine(
        mode: StandaloneMode,
        ctx: &SigContext,
        game: &mut StandaloneGame<'_>,
        rng: &mut dyn EntropySource,
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        let m = fresh_message(rng)?;
        let pk = game.public_key.clone();
        let (input, cctx) = ctx.signed_input(&pk, &m, CTX_A)?;
        let oracle = mode.oracle_mode();
        let mut sig = Vec::new();
        for side in Side::BOTH {
            let len = ctx.component(side).signature_len();
            let half = match ctx.scenario.model(side) {
                SigModel::Forgeable => forge(side_pk(ctx, &pk, side)?, &cctx, &input, len),
                // A refused query (the composite's own context) yields nothing
                // usable; the adversary submits zeros for that half.
                _ => game
                    .sign_component(side, &oracle, &input)?
                    .unwrap_or_else(|| vec![0u8; len]),
            };
            sig.extend_from_slice(&half);
        }
        Ok((m, CTX_A.to_vec(), sig))
    }

    /// S-CEO: `(pk', M, ctx, σ)`.
    ///
    /// # Errors
    ///
    /// Harness errors.
    pub fn substitute(
        ctx: &SigContext,
        game: &mut CmaGame<'_>,
        rng: &mut dyn EntropySource,
    ) -> Result<KeyedForgery> {
        let m0 = fresh_message(rng)?;
        let sig0 = game.sign(&m0, CTX_A)?;
        let (p1, p2) = ctx.split_pk(&game.public_key)?;
        let sub = |side: Side, p: &[u8]| match ctx.scenario.model(side) {
            SigModel::KeySubstitutable => substitute_public_key(p),
            _ => p.to_vec(),
        };
        let mut pk_prime = [sub(Side::First, p1), sub(Side::Second, p2)].concat();
        if pk_prime == game.public_key {
            pk_prime = flip_last(&pk_prime);
        }
        Ok((pk_prime, m0, CTX_A.to_vec(), sig0))
    }

    /// MBS: `(pk, m1, m2, ctx, σ)` under an own key.
    ///
    /// # Errors
    ///
    /// Harness errors.
    pub fn collapse(ctx: &SigContext, rng: &mut dyn EntropySource) -> Result<DoubleMessage> {
        let (pk, sk) = ctx.composite().generate(rng)?;
        let m0 = fresh_message(rng)?;
        let sig = ctx.composite().sign(sk.expose(), &m0, CTX_A, rng)?;
        let m1 = colliding_message(ctx, &pk, &m0, CTX_A)?;
        Ok((pk, m0, m1, CTX_A.to_vec(), sig))
    }

    /// MIX: `(pk*, M, ctx, σ)`.
    ///
    /// # Errors
    ///
    /// Harness errors.
    pub fn mix(
        ctx: &SigContext,
        game: &mut MixGame<'_>,
        rng: &mut dyn EntropySource,
    ) -> Result<KeyedForgery> {
        let m0 = fresh_message(rng)?;
        let sa = game.a.sign(&m0, CTX_A)?;
        let sb = game.b.sign(&m0, CTX_A)?;
        let (pk_mixed, _) = game.mixed_keys(ctx.composite())?;
        let (a1, _) = ctx.split_sig(&sa)?;
        let (_, b2) = ctx.split_sig(&sb)?;
        Ok((pk_mixed, m0, CTX_A.to_vec(), [a1, b2].concat()))
    }
}
