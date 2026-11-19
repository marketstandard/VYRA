//! The signature side of the experiment (unit U11-S).
//!
//! Mirrors the KEM side: failure models ([`models`], **intentionally
//! insecure**), compositions under test ([`compositions`]), games
//! ([`games`]), adversaries ([`adversaries`]), the cell matrix and its
//! expectations ([`experiment`]) and controls ([`controls`]).
//!
//! Two component pairs are used:
//!
//! - **Transition** (ML-DSA-44 + Ed25519, the components of `VYRA-SIG-2`):
//!   the main matrix, every model, every game, every composition (including
//!   the historical `VyraPureEd`), N = 200 per cell by default.
//! - **Dual-PQ** (ML-DSA-44 + SLH-DSA-SHAKE-128s, the components of
//!   `VYRA-SIG-PQ1`): Vyra and Concat; Real, Forgeable and ContextIgnoring
//!   on one side; every game; a smaller N because SLH-DSA-SHAKE-128s signing
//!   takes about a second. No stand-in is used: these cells run the real
//!   SLH-DSA adapter.

pub mod adversaries;
pub mod compositions;
pub mod controls;
pub mod experiment;
pub mod games;
pub mod legacy;
pub mod models;

use core::fmt;

use vyra_core::Result;
use vyra_sig::CompositeComponent;

use crate::scenario::Side;
use compositions::{CompositionKind, SideLens, SigComposite, VYRA_ALT_ID, VYRA_ID, split2};
use models::{SigBase, SigModel};

/// Which pair of real components the two slots wrap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SigPair {
    /// ML-DSA-44 + Ed25519 (`VYRA-SIG-2`'s components).
    Transition,
    /// ML-DSA-44 + SLH-DSA-SHAKE-128s (`VYRA-SIG-PQ1`'s components).
    DualPq,
}

impl SigPair {
    /// The real components of slot 1 and slot 2.
    pub const fn bases(self) -> (SigBase, SigBase) {
        match self {
            SigPair::Transition => (SigBase::MlDsa44, SigBase::Ed25519),
            SigPair::DualPq => (SigBase::MlDsa44, SigBase::SlhDsaShake128s),
        }
    }

    /// Report name.
    pub const fn name(self) -> &'static str {
        match self {
            SigPair::Transition => "transition (ML-DSA-44 + Ed25519)",
            SigPair::DualPq => "dual-PQ (ML-DSA-44 + SLH-DSA-SHAKE-128s)",
        }
    }
}

/// Composition, component pair and the failure model of each slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SigScenario {
    /// The composition design.
    pub composition: CompositionKind,
    /// The real component pair.
    pub pair: SigPair,
    /// Model of slot 1.
    pub first: SigModel,
    /// Model of slot 2.
    pub second: SigModel,
}

impl SigScenario {
    /// The model in slot `side`.
    pub const fn model(&self, side: Side) -> SigModel {
        match side {
            Side::First => self.first,
            Side::Second => self.second,
        }
    }

    /// The real components under the two slots. For `VyraPureEd` the Ed25519
    /// slot uses the pre-U12-R1 PureEd25519 half.
    pub const fn bases(&self) -> (SigBase, SigBase) {
        let (a, b) = self.pair.bases();
        match (self.composition, b) {
            (CompositionKind::VyraPureEd, SigBase::Ed25519) => (a, SigBase::Ed25519PureHalf),
            _ => (a, b),
        }
    }

    /// Number of slots that are not [`SigModel::Real`].
    pub const fn broken_count(&self) -> usize {
        (!self.first.is_real()) as usize + (!self.second.is_real()) as usize
    }
}

impl fmt::Display for SigScenario {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (a, b) = self.bases();
        write!(
            f,
            "{} over {}({}) x {}({})",
            self.composition.name(),
            self.first.name(),
            a.name(),
            self.second.name(),
            b.name()
        )
    }
}

/// What a signature adversary may know: the scenario, fresh component
/// instances, and the composition under suite bytes X and Y.
pub struct SigContext {
    /// The scenario.
    pub scenario: SigScenario,
    first: Box<dyn CompositeComponent>,
    second: Box<dyn CompositeComponent>,
    composite: Box<dyn SigComposite>,
    composite_alt: Box<dyn SigComposite>,
}

impl fmt::Debug for SigContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigContext")
            .field("scenario", &self.scenario)
            .finish_non_exhaustive()
    }
}

impl SigContext {
    /// Build components and compositions for `scenario`.
    ///
    /// # Errors
    ///
    /// If the composition cannot be assembled (harness error).
    pub fn new(scenario: SigScenario) -> Result<Self> {
        let (b1, b2) = scenario.bases();
        let make = |id: u8| -> Result<Box<dyn SigComposite>> {
            let first = scenario.first.instantiate(b1);
            let second = scenario.second.instantiate(b2);
            let lens = SideLens::of(first.as_ref(), second.as_ref());
            scenario.composition.assemble(id, first, second, lens)
        };
        Ok(SigContext {
            scenario,
            first: scenario.first.instantiate(b1),
            second: scenario.second.instantiate(b2),
            composite: make(VYRA_ID)?,
            composite_alt: make(VYRA_ALT_ID)?,
        })
    }

    /// The composition under test (suite byte X).
    pub fn composite(&self) -> &dyn SigComposite {
        self.composite.as_ref()
    }

    /// The same composition under suite byte Y (cross-suite game only).
    pub fn composite_alt(&self) -> &dyn SigComposite {
        self.composite_alt.as_ref()
    }

    /// The component in slot `side`.
    pub fn component(&self, side: Side) -> &dyn CompositeComponent {
        match side {
            Side::First => self.first.as_ref(),
            Side::Second => self.second.as_ref(),
        }
    }

    /// Split a composite public key.
    ///
    /// # Errors
    ///
    /// Wrong length.
    pub fn split_pk<'a>(&self, pk: &'a [u8]) -> Result<(&'a [u8], &'a [u8])> {
        let l = self.composite.lens();
        split2(pk, l.first.0, l.second.0)
    }

    /// Split a composite secret key.
    ///
    /// # Errors
    ///
    /// Wrong length.
    pub fn split_sk<'a>(&self, sk: &'a [u8]) -> Result<(&'a [u8], &'a [u8])> {
        let l = self.composite.lens();
        split2(sk, l.first.1, l.second.1)
    }

    /// Split a composite signature.
    ///
    /// # Errors
    ///
    /// Wrong length.
    pub fn split_sig<'a>(&self, sig: &'a [u8]) -> Result<(&'a [u8], &'a [u8])> {
        let l = self.composite.lens();
        split2(sig, l.first.2, l.second.2)
    }

    /// The input and component context both slots sign for `(m, ctx)` under
    /// `pk` (see [`CompositionKind::signed_input`]).
    ///
    /// # Errors
    ///
    /// Malformed `pk` or overlong context.
    pub fn signed_input(&self, pk: &[u8], m: &[u8], ctx: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let (pk1, pk2) = self.split_pk(pk)?;
        self.scenario
            .composition
            .signed_input(self.composite.id(), pk1, pk2, m, ctx)
    }
}
