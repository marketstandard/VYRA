//! Signature security games as explicit state machines.
//!
//! All games here are **search games**: a win is a concrete, challenger-
//! verified event, and the baseline success probability is negligible. A
//! "message" is always the pair `(M, ctx)` of message and application
//! context (the convention of context-taking schemes such as FIPS 204; ours
//! for this experiment).
//!
//! # Definitions
//!
//! Notation: `Q` is the list of signing-oracle transcripts `((M, ctx), σ)`.
//!
//! - **EUF-CMA** (standard; as written in Düzlü–Fiedler–Fischlin, SAC 2024,
//!   Fig. 1 — verified): `(pk, sk) ← KGen`; `(M*, ctx*, σ*) ← A^{Sign}(pk)`;
//!   win iff `Verify(pk, M*, ctx*, σ*)` and `(M*, ctx*)` ∉ messages of `Q`.
//! - **SUF-CMA** (standard): as EUF-CMA, win iff valid and
//!   `((M*, ctx*), σ*) ∉ Q`.
//! - **STRIP-COMPOSITE** (ours; in the spirit of the non-separability notions
//!   of Bindel–Herath–McKague–Stebila, PQCrypto 2017 — *their definitions are
//!   to be verified*): composite key and composite signing oracle only;
//!   `A` outputs `(i, m̂, σ̂)`; win iff `σ̂` is the component-`i` half of some
//!   oracle signature **and** some standalone verifier of component `i`
//!   accepts `σ̂` on `m̂` under `pk_i`: the default verifier, or the
//!   context-taking verifier with the empty context or with a foreign
//!   context ([`standalone_accepts`]). Any `m̂` counts.
//! - **STRIP-STANDALONE** (ours; key reuse): composite key, **no** composite
//!   oracle, but standalone signing oracles for each component key in every
//!   [`OracleMode`] (default mode; context-taking variant with the empty
//!   context; with any attacker-chosen context except the composite's own
//!   component context, which is the composite half by definition); win
//!   iff `A` outputs any composite-valid `(M, ctx, σ)`.
//! - **S-CEO** (strong conservative exclusive ownership, Cremers–Düzlü–
//!   Fiedler–Fischlin–Janson, S&P 2021, as restated in Düzlü–Fiedler–Fischlin
//!   SAC 2024 Fig. 2 — verified against the restatement): win iff
//!   `A` outputs `(pk', M, ctx, σ)` with `Verify(pk', M, ctx, σ)`,
//!   `((M, ctx), σ) ∈ Q` and `pk' ≠ pk`.
//! - **MBS** (message-bound signatures, same sources, Fig. 3 — verified
//!   against the restatement): no oracle; `A` outputs
//!   `(pk, (M1, ctx1), (M2, ctx2), σ)`; win iff `σ` verifies both under `pk`
//!   and `(M1, ctx1) ≠ (M2, ctx2)`.
//! - **MIX** (ours; cross-key splicing, the attack RULES 8 addresses): two
//!   honest composite key pairs `A`, `B` with signing oracles; win iff the
//!   adversary outputs `(pk*, M, ctx, σ)` with `pk* ∈ {pkA_1 ‖ pkB_2,
//!   pkB_1 ‖ pkA_2}` (component keys of two different honest signers) and
//!   `Verify(pk*, M, ctx, σ)`.
//! - **CROSS-SUITE** (ours): the same components and keys under suite bytes
//!   `X` and `Y ≠ X`; signing oracle for `X` only; win iff `A` outputs any
//!   `(M, ctx, σ)` valid under `Y` (an EUF-CMA forgery against `Y` using an
//!   `X` oracle).
//! - **CROSS-CONTEXT** (ours; an EUF-CMA restriction): win iff `A` outputs
//!   `(M, ctx', σ)` valid with `(M, ctx')` never queried while `(M, ctx)`
//!   was queried for some `ctx ≠ ctx'`.

use vyra_core::{DeterministicEntropy, Result, SecretBytes, SignatureScheme};
use vyra_sig::CompositeComponent;

use super::compositions::{SigComposite, split2};
use crate::scenario::Side;

/// A signature game.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SigGame {
    /// EUF-CMA.
    EufCma,
    /// SUF-CMA.
    SufCma,
    /// Composite half accepted by the standalone component verifier.
    StripComposite,
    /// Standalone component signatures assembled into a composite.
    StripStandalone,
    /// Strong conservative exclusive ownership.
    Sceo,
    /// Message-bound signatures.
    Mbs,
    /// Halves of two honest signers recombined under a mixed key.
    Mix,
    /// Signature for suite byte X accepted under suite byte Y.
    CrossSuite,
    /// Signature for context ctx accepted under ctx'.
    CrossContext,
}

impl SigGame {
    /// Every game, in report order.
    pub const ALL: [SigGame; 9] = [
        SigGame::EufCma,
        SigGame::SufCma,
        SigGame::StripComposite,
        SigGame::StripStandalone,
        SigGame::Sceo,
        SigGame::Mbs,
        SigGame::Mix,
        SigGame::CrossSuite,
        SigGame::CrossContext,
    ];

    /// Report name.
    pub const fn name(self) -> &'static str {
        match self {
            SigGame::EufCma => "EUF-CMA",
            SigGame::SufCma => "SUF-CMA",
            SigGame::StripComposite => "STRIP-COMPOSITE",
            SigGame::StripStandalone => "STRIP-STANDALONE",
            SigGame::Sceo => "S-CEO",
            SigGame::Mbs => "MBS",
            SigGame::Mix => "MIX",
            SigGame::CrossSuite => "CROSS-SUITE",
            SigGame::CrossContext => "CROSS-CONTEXT",
        }
    }
}

/// One signing-oracle transcript entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signed {
    /// The message `M`.
    pub message: Vec<u8>,
    /// The context `ctx`.
    pub context: Vec<u8>,
    /// The signature returned.
    pub signature: Vec<u8>,
}

/// An honest composite key pair with a signing oracle (the core of every
/// CMA-style game here).
pub struct CmaGame<'s> {
    scheme: &'s dyn SigComposite,
    /// The honest public key.
    pub public_key: Vec<u8>,
    secret_key: SecretBytes,
    rng: DeterministicEntropy,
    queries: Vec<Signed>,
}

impl core::fmt::Debug for CmaGame<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CmaGame")
            .field("queries", &self.queries.len())
            .finish_non_exhaustive()
    }
}

impl<'s> CmaGame<'s> {
    /// Challenger setup; `rng` is the challenger's own randomness (key
    /// generation and signing).
    ///
    /// # Errors
    ///
    /// Key-generation errors.
    pub fn start(scheme: &'s dyn SigComposite, mut rng: DeterministicEntropy) -> Result<Self> {
        let (public_key, secret_key) = scheme.generate(&mut rng)?;
        Ok(CmaGame {
            scheme,
            public_key,
            secret_key,
            rng,
            queries: Vec::new(),
        })
    }

    /// The composite signing oracle.
    ///
    /// # Errors
    ///
    /// Signing errors (e.g. a context longer than 255 bytes).
    pub fn sign(&mut self, message: &[u8], context: &[u8]) -> Result<Vec<u8>> {
        let sig = self
            .scheme
            .sign(self.secret_key.expose(), message, context, &mut self.rng)?;
        self.queries.push(Signed {
            message: message.to_vec(),
            context: context.to_vec(),
            signature: sig.clone(),
        });
        Ok(sig)
    }

    /// The oracle transcript so far.
    pub fn queries(&self) -> &[Signed] {
        &self.queries
    }

    fn queried(&self, m: &[u8], ctx: &[u8]) -> bool {
        self.queries
            .iter()
            .any(|q| q.message == m && q.context == ctx)
    }

    /// EUF-CMA win condition.
    pub fn euf_wins(&self, m: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
        !self.queried(m, ctx) && self.scheme.verify(&self.public_key, m, ctx, sig)
    }

    /// SUF-CMA win condition.
    pub fn suf_wins(&self, m: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
        let seen = self
            .queries
            .iter()
            .any(|q| q.message == m && q.context == ctx && q.signature == sig);
        !seen && self.scheme.verify(&self.public_key, m, ctx, sig)
    }

    /// CROSS-CONTEXT win condition.
    pub fn cross_context_wins(&self, m: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
        let other_ctx = self
            .queries
            .iter()
            .any(|q| q.message == m && q.context != ctx);
        other_ctx && self.euf_wins(m, ctx, sig)
    }

    /// S-CEO win condition.
    pub fn sceo_wins(&self, pk_prime: &[u8], m: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
        let in_q = self
            .queries
            .iter()
            .any(|q| q.message == m && q.context == ctx && q.signature == sig);
        in_q && pk_prime != self.public_key.as_slice() && self.scheme.verify(pk_prime, m, ctx, sig)
    }

    /// STRIP-COMPOSITE win condition: `half` is the `side` half of an oracle
    /// signature and `component.verify(pk_side, m_hat, half)` accepts.
    pub fn strip_wins(
        &self,
        side: Side,
        component: &dyn CompositeComponent,
        m_hat: &[u8],
        half: &[u8],
    ) -> bool {
        let lens = self.scheme.lens();
        let is_half = self.queries.iter().any(|q| {
            split2(&q.signature, lens.first.2, lens.second.2)
                .map(|(a, b)| match side {
                    Side::First => a == half,
                    Side::Second => b == half,
                })
                .unwrap_or(false)
        });
        let Ok((pk1, pk2)) = split2(&self.public_key, lens.first.0, lens.second.0) else {
            return false;
        };
        let pk = match side {
            Side::First => pk1,
            Side::Second => pk2,
        };
        is_half && standalone_accepts(component, pk, m_hat, half)
    }

    /// CROSS-SUITE win condition: valid under `other` (same keys, another
    /// suite byte), for which no oracle exists.
    pub fn cross_suite_wins(
        &self,
        other: &dyn SigComposite,
        m: &[u8],
        ctx: &[u8],
        sig: &[u8],
    ) -> bool {
        other.id() != self.scheme.id() && other.verify(&self.public_key, m, ctx, sig)
    }
}

/// A standalone use of a component key (STRIP-STANDALONE oracle modes and
/// STRIP-COMPOSITE verifier modes).
///
/// - `Default`: the component's own `SignatureScheme::sign` / `verify`
///   (ML-DSA, SLH-DSA: empty context; Ed25519: PureEd25519).
/// - `EmptyContext`: the context-taking variant with the empty context
///   (`sign_half` / `verify_half` with `ctx = ""`; Ed25519: Ed25519ph with
///   empty context; ML-DSA, SLH-DSA: identical to `Default`).
/// - `Context(c)`: the context-taking variant with an attacker-chosen
///   context `c` (Ed25519: Ed25519ph with context `c`). Excluded: `c` equal to
///   the composite's own component context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OracleMode {
    /// Default standalone mode.
    Default,
    /// Context-taking variant, empty context.
    EmptyContext,
    /// Context-taking variant, chosen context.
    Context(Vec<u8>),
}

/// A context a deployer might reuse the key under in another application.
pub const FOREIGN_CONTEXT: &[u8] = b"another-application-v1";

/// Whether some standalone verifier of `component` accepts `sig` on `m`:
/// the default verifier, the context-taking verifier with the empty context,
/// or with [`FOREIGN_CONTEXT`].
pub fn standalone_accepts(
    component: &dyn CompositeComponent,
    pk: &[u8],
    m: &[u8],
    sig: &[u8],
) -> bool {
    SignatureScheme::verify(component, pk, m, sig).is_ok()
        || component.verify_half(pk, m, &[], sig).is_ok()
        || component.verify_half(pk, m, FOREIGN_CONTEXT, sig).is_ok()
}

/// STRIP-STANDALONE: composite key, standalone component signing oracles
/// (every [`OracleMode`]) only.
pub struct StandaloneGame<'s> {
    scheme: &'s dyn SigComposite,
    first: &'s dyn CompositeComponent,
    second: &'s dyn CompositeComponent,
    /// The honest composite public key.
    pub public_key: Vec<u8>,
    secret_key: SecretBytes,
    rng: DeterministicEntropy,
}

impl core::fmt::Debug for StandaloneGame<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StandaloneGame").finish_non_exhaustive()
    }
}

impl<'s> StandaloneGame<'s> {
    /// Challenger setup.
    ///
    /// # Errors
    ///
    /// Key-generation errors.
    pub fn start(
        scheme: &'s dyn SigComposite,
        first: &'s dyn CompositeComponent,
        second: &'s dyn CompositeComponent,
        mut rng: DeterministicEntropy,
    ) -> Result<Self> {
        let (public_key, secret_key) = scheme.generate(&mut rng)?;
        Ok(StandaloneGame {
            scheme,
            first,
            second,
            public_key,
            secret_key,
            rng,
        })
    }

    /// Standalone signing oracle of component `side` in `mode`.
    ///
    /// Returns `Ok(None)` (refused) for [`OracleMode::Context`] with exactly
    /// the composite's own non-empty component context: that "standalone"
    /// mode is by definition the composite's half and is excluded.
    ///
    /// # Errors
    ///
    /// Signing errors (e.g. an over-long context).
    pub fn sign_component(
        &mut self,
        side: Side,
        mode: &OracleMode,
        message: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        let lens = self.scheme.lens();
        let (sk1, sk2) = split2(self.secret_key.expose(), lens.first.1, lens.second.1)?;
        let (c, sk) = match side {
            Side::First => (self.first, sk1),
            Side::Second => (self.second, sk2),
        };
        match mode {
            OracleMode::Default => Ok(Some(SignatureScheme::sign(c, sk, message, &mut self.rng)?)),
            OracleMode::EmptyContext => Ok(Some(c.sign_half(sk, message, &[], &mut self.rng)?)),
            OracleMode::Context(ctx) => {
                let own = self.scheme.component_context();
                if !own.is_empty() && *ctx == own {
                    return Ok(None);
                }
                Ok(Some(c.sign_half(sk, message, ctx, &mut self.rng)?))
            }
        }
    }

    /// Win condition: any composite-valid output.
    pub fn wins(&self, m: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
        self.scheme.verify(&self.public_key, m, ctx, sig)
    }
}

/// MBS win condition (no challenger state).
pub fn mbs_wins(
    scheme: &dyn SigComposite,
    pk: &[u8],
    first: (&[u8], &[u8]),
    second: (&[u8], &[u8]),
    sig: &[u8],
) -> bool {
    first != second
        && scheme.verify(pk, first.0, first.1, sig)
        && scheme.verify(pk, second.0, second.1, sig)
}

/// MIX: two honest signers.
#[derive(Debug)]
pub struct MixGame<'s> {
    /// Signer A.
    pub a: CmaGame<'s>,
    /// Signer B.
    pub b: CmaGame<'s>,
}

impl<'s> MixGame<'s> {
    /// Two independent honest signers.
    ///
    /// # Errors
    ///
    /// Key-generation errors.
    pub fn start(
        scheme: &'s dyn SigComposite,
        rng_a: DeterministicEntropy,
        rng_b: DeterministicEntropy,
    ) -> Result<Self> {
        Ok(MixGame {
            a: CmaGame::start(scheme, rng_a)?,
            b: CmaGame::start(scheme, rng_b)?,
        })
    }

    /// The two mixed public keys `(pkA_1 ‖ pkB_2, pkB_1 ‖ pkA_2)`.
    ///
    /// # Errors
    ///
    /// Malformed honest keys (harness error).
    pub fn mixed_keys(&self, scheme: &dyn SigComposite) -> Result<(Vec<u8>, Vec<u8>)> {
        let lens = scheme.lens();
        let (a1, a2) = split2(&self.a.public_key, lens.first.0, lens.second.0)?;
        let (b1, b2) = split2(&self.b.public_key, lens.first.0, lens.second.0)?;
        Ok(([a1, b2].concat(), [b1, a2].concat()))
    }

    /// Win condition.
    pub fn wins(
        &self,
        scheme: &dyn SigComposite,
        pk: &[u8],
        m: &[u8],
        ctx: &[u8],
        sig: &[u8],
    ) -> bool {
        let Ok((x, y)) = self.mixed_keys(scheme) else {
            return false;
        };
        (pk == x.as_slice() || pk == y.as_slice()) && scheme.verify(pk, m, ctx, sig)
    }
}
