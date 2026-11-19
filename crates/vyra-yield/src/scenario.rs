//! A scenario: one combiner design over two component slots, each with a
//! failure model. Component 1 is always built over ML-KEM-512 and component 2
//! over HQC-128 (the components of VYRA-KEM-1).

use core::fmt;

use vyra_core::{Error, Result};
use vyra_kem::ComponentKem;

use crate::combiners::CombinerKind;
use crate::models::{Base, ModelKind};

/// The real component under slot 1.
pub const FIRST_BASE: Base = Base::MlKem512;
/// The real component under slot 2.
pub const SECOND_BASE: Base = Base::Hqc128;

/// One component slot of a hybrid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Side {
    /// Component 1 (ML-KEM-512 based).
    First,
    /// Component 2 (HQC-128 based).
    Second,
}

impl Side {
    /// Both sides, in order.
    pub const BOTH: [Side; 2] = [Side::First, Side::Second];

    /// `"1"` or `"2"`.
    pub const fn label(self) -> &'static str {
        match self {
            Side::First => "1",
            Side::Second => "2",
        }
    }
}

/// Combiner plus the failure model of each component.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Scenario {
    /// The combiner design.
    pub combiner: CombinerKind,
    /// Model of component 1.
    pub first: ModelKind,
    /// Model of component 2.
    pub second: ModelKind,
}

impl Scenario {
    /// The model in slot `side`.
    pub const fn model(&self, side: Side) -> ModelKind {
        match side {
            Side::First => self.first,
            Side::Second => self.second,
        }
    }

    /// Number of components that are not [`ModelKind::Real`].
    pub const fn broken_count(&self) -> usize {
        (!self.first.is_real()) as usize + (!self.second.is_real()) as usize
    }
}

impl fmt::Display for Scenario {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} over {} x {}",
            self.combiner.name(),
            self.first.name(),
            self.second.name()
        )
    }
}

/// Everything an adversary may know (Kerckhoffs): the scenario, fresh
/// instances of both components, and the assembled hybrid (public algorithms
/// only; no secret key of the challenger).
pub struct AttackContext {
    /// The scenario.
    pub scenario: Scenario,
    first: Box<dyn ComponentKem>,
    second: Box<dyn ComponentKem>,
    hybrid: Box<dyn ComponentKem>,
}

impl fmt::Debug for AttackContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AttackContext")
            .field("scenario", &self.scenario)
            .finish_non_exhaustive()
    }
}

fn split(bytes: &[u8], mid: usize) -> Result<(&[u8], &[u8])> {
    bytes
        .split_at_checked(mid)
        .ok_or(Error::Internal("context split"))
}

impl AttackContext {
    /// Build the components and the hybrid for `scenario`.
    pub fn new(scenario: Scenario) -> Self {
        let hybrid = scenario.combiner.assemble(
            scenario.first.instantiate(FIRST_BASE),
            scenario.second.instantiate(SECOND_BASE),
        );
        AttackContext {
            scenario,
            first: scenario.first.instantiate(FIRST_BASE),
            second: scenario.second.instantiate(SECOND_BASE),
            hybrid,
        }
    }

    /// The assembled hybrid KEM (the object under test).
    pub fn hybrid(&self) -> &dyn ComponentKem {
        self.hybrid.as_ref()
    }

    /// The component in slot `side`.
    pub fn component(&self, side: Side) -> &dyn ComponentKem {
        match side {
            Side::First => self.first.as_ref(),
            Side::Second => self.second.as_ref(),
        }
    }

    /// Split a hybrid public key into `(pk1, pk2)`.
    ///
    /// # Errors
    ///
    /// `Error::Internal` if it is too short.
    pub fn split_public_key<'a>(&self, pk: &'a [u8]) -> Result<(&'a [u8], &'a [u8])> {
        split(pk, self.first.public_key_len())
    }

    /// Split a hybrid secret key into `(sk1, sk2)`.
    ///
    /// # Errors
    ///
    /// `Error::Internal` if it is too short.
    pub fn split_secret_key<'a>(&self, sk: &'a [u8]) -> Result<(&'a [u8], &'a [u8])> {
        split(sk, self.first.secret_key_len())
    }

    /// Split a hybrid ciphertext into `(c1, c2)`.
    ///
    /// # Errors
    ///
    /// `Error::Internal` if it is too short.
    pub fn split_ciphertext<'a>(&self, ct: &'a [u8]) -> Result<(&'a [u8], &'a [u8])> {
        split(ct, self.first.ciphertext_len())
    }
}
