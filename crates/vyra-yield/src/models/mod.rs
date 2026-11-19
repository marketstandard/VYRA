//! **WARNING — INTENTIONALLY INSECURE CODE. NEVER USE OUTSIDE THIS EXPERIMENT.**
//!
//! Failure models: KEM components that implement the same traits as VYRA's
//! real components ([`Kem`] + [`ComponentKem`]), each wrapping a *real*
//! component (ML-KEM-512 or HQC-128 through VYRA's own adapters) and breaking
//! one stated property on purpose. They exist only so that the security
//! games in [`crate::games`] can be run against hybrids in which one or both
//! components have "yielded".
//!
//! None of these types is re-exported by any other crate, and this crate is
//! `publish = false`. Every model's documentation states precisely which
//! property is broken and which are intended to remain.
//!
//! | model | broken on purpose | intended to remain |
//! |-------|-------------------|--------------------|
//! | [`Real`](ModelKind::Real) | nothing (the real adapter) | everything the real component has |
//! | [`Leaky`] | confidentiality (key is a public function of `(pk, ct)`) | correctness, key binding to `ct` and `pk` |
//! | [`Malleable`] | ciphertext non-malleability / HON-BIND-K-CT | IND-CPA of the real component, K-PK binding |
//! | [`KeySubstitutable`] | MAL-BIND-K-PK (keys differing only in an ignored tag) | IND-CCA2, honest-key binding |
//! | [`Constant`] | everything (key is a public constant) | correctness only |
//! | [`SenderKeyed`] | HON-BIND-K-CT and HON-BIND-K-PK (sender chooses the key) | IND-CCA2 (heuristic, to be verified) |
//!
//! A "validity oracle" model (decapsulation revealing whether a ciphertext is
//! valid) is deliberately not included; see the crate documentation.
//!
//! [`Kem`]: vyra_core::Kem

pub mod constant;
pub mod key_substitutable;
pub mod leaky;
pub mod malleable;
pub mod sender_keyed;

pub use constant::Constant;
pub use key_substitutable::KeySubstitutable;
pub use leaky::Leaky;
pub use malleable::Malleable;
pub use sender_keyed::SenderKeyed;

use vyra_kem::{ComponentKem, Hqc128, MlKem512};

/// The real component a model wraps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Base {
    /// ML-KEM-512 through `vyra_kem::MlKem512` (component 1 of VYRA-KEM-1).
    MlKem512,
    /// HQC-128 (v5.1) through `vyra_kem::Hqc128` (component 2 of VYRA-KEM-1).
    Hqc128,
}

impl Base {
    /// A fresh instance of the real, unmodified component.
    pub fn real(self) -> Box<dyn ComponentKem> {
        match self {
            Base::MlKem512 => Box::new(MlKem512),
            Base::Hqc128 => Box::new(Hqc128),
        }
    }

    /// The real component's name.
    pub const fn name(self) -> &'static str {
        match self {
            Base::MlKem512 => MlKem512::NAME,
            Base::Hqc128 => Hqc128::NAME,
        }
    }
}

/// Which failure model a component slot uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ModelKind {
    /// The real component, unmodified.
    Real,
    /// [`Leaky`]: confidentiality lost.
    Leaky,
    /// [`Malleable`]: ciphertext non-malleability lost.
    Malleable,
    /// [`KeySubstitutable`]: key binding against chosen keys lost.
    KeySubstitutable,
    /// [`Constant`]: degenerate, key is a public constant.
    Constant,
    /// [`SenderKeyed`]: binding lost even for honest keys.
    SenderKeyed,
}

impl ModelKind {
    /// Every model, in report order.
    pub const ALL: [ModelKind; 6] = [
        ModelKind::Real,
        ModelKind::Leaky,
        ModelKind::Malleable,
        ModelKind::KeySubstitutable,
        ModelKind::Constant,
        ModelKind::SenderKeyed,
    ];

    /// Short name used in reports and seeds.
    pub const fn name(self) -> &'static str {
        match self {
            ModelKind::Real => "Real",
            ModelKind::Leaky => "Leaky",
            ModelKind::Malleable => "Malleable",
            ModelKind::KeySubstitutable => "KeySubstitutable",
            ModelKind::Constant => "Constant",
            ModelKind::SenderKeyed => "SenderKeyed",
        }
    }

    /// One line: the property this model breaks.
    pub const fn broken_property(self) -> &'static str {
        match self {
            ModelKind::Real => "none (real component)",
            ModelKind::Leaky => "confidentiality: key = SHA3(label, pk, ct), public",
            ModelKind::Malleable => {
                "non-malleability: an extra ciphertext byte is ignored by decapsulation"
            }
            ModelKind::KeySubstitutable => {
                "MAL-BIND-K-PK: keys carry a tag that decapsulation ignores"
            }
            ModelKind::Constant => "everything: the key is a fixed public constant",
            ModelKind::SenderKeyed => {
                "HON-BIND-K-CT/K-PK: the encapsulator chooses the key and can re-encapsulate it"
            }
        }
    }

    /// Whether the model destroys the confidentiality of the component key
    /// (the adversary can compute it). These are the models for which a
    /// hybrid with *both* components so broken has no secret left.
    pub const fn breaks_confidentiality(self) -> bool {
        matches!(self, ModelKind::Leaky | ModelKind::Constant)
    }

    /// Whether the model is the real component.
    pub const fn is_real(self) -> bool {
        matches!(self, ModelKind::Real)
    }

    /// Instantiate this model over `base`.
    pub fn instantiate(self, base: Base) -> Box<dyn ComponentKem> {
        match self {
            ModelKind::Real => base.real(),
            ModelKind::Leaky => Box::new(Leaky::new(base)),
            ModelKind::Malleable => Box::new(Malleable::new(base)),
            ModelKind::KeySubstitutable => Box::new(KeySubstitutable::new(base)),
            ModelKind::Constant => Box::new(Constant::new(base)),
            ModelKind::SenderKeyed => Box::new(SenderKeyed::new(base)),
        }
    }
}

/// `InvalidLength` unless `bytes.len() == expected`.
pub(crate) fn require_len(
    what: &'static str,
    bytes: &[u8],
    expected: usize,
) -> vyra_core::Result<()> {
    if bytes.len() == expected {
        Ok(())
    } else {
        Err(vyra_core::Error::InvalidLength {
            what,
            expected,
            actual: bytes.len(),
        })
    }
}

/// Split at `mid`, or an internal error.
pub(crate) fn split_at(bytes: &[u8], mid: usize) -> vyra_core::Result<(&[u8], &[u8])> {
    bytes
        .split_at_checked(mid)
        .ok_or(vyra_core::Error::Internal("model split"))
}

/// `a ‖ b`.
pub(crate) fn concat(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(a.len().saturating_add(b.len()));
    v.extend_from_slice(a);
    v.extend_from_slice(b);
    v
}
