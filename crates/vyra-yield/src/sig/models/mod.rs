//! **WARNING — INTENTIONALLY INSECURE CODE. NEVER USE OUTSIDE THIS EXPERIMENT.**
//!
//! Signature failure models: components that implement the same traits as
//! VYRA's real signature components ([`SignatureScheme`] +
//! [`CompositeComponent`]), each wrapping a *real* component (ML-DSA-44,
//! Ed25519 or SLH-DSA-SHAKE-128s through `vyra-sig`'s adapters) and breaking
//! one stated property on purpose.
//!
//! | model | broken on purpose | intended to remain |
//! |-------|-------------------|--------------------|
//! | [`Real`](SigModel::Real) | nothing | everything the real component has |
//! | [`Forgeable`] | EUF-CMA: a publicly computable tag verifies for any `(pk, ctx, m)` | honest signatures are real |
//! | [`Malleable`] | SUF-CMA: an ignored extra signature byte | EUF-CMA, key and message binding |
//! | [`KeySubstitutable`] | S-CEO / exclusive ownership: public keys carry an ignored tag | EUF-CMA, SUF-CMA |
//! | [`ContextIgnoring`] | context binding: the composite half is the component's *default standalone* signature (ML-DSA/SLH-DSA: empty context; Ed25519: PureEd25519) | EUF-CMA on the message it signs |
//! | [`MessageCollapsing`] | message binding (MBS) and hence EUF-CMA: signs a 12-bit digest of the message | key binding; no forgery without a signing query |
//!
//! Every model's key generation draws its randomness in **one** request of
//! exactly the secret-key length, because the VYRA composite re-derives
//! component public keys from secret keys by replaying the secret key as the
//! key-generation randomness.
//!
//! [`SignatureScheme`]: vyra_core::SignatureScheme

pub mod context_ignoring;
pub mod forgeable;
pub mod key_substitutable;
pub mod malleable;
pub mod message_collapsing;

pub use context_ignoring::ContextIgnoring;
pub use forgeable::Forgeable;
pub use key_substitutable::KeySubstitutable;
pub use malleable::Malleable;
pub use message_collapsing::MessageCollapsing;

use vyra_core::{EntropySource, Error, Result};
use vyra_sig::{CompositeComponent, Ed25519, MlDsa44, SlhDsaShake128s};

/// The real signature component a model wraps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SigBase {
    /// ML-DSA-44 (FIPS 204), context-bound in the composite.
    MlDsa44,
    /// Ed25519 (RFC 8032) as in vyra-sig after U12-R1: standalone interface
    /// PureEd25519; composite half Ed25519ph under the composite context
    /// (context-bound).
    Ed25519,
    /// The pre-U12-R1 Ed25519 composite half: PureEd25519 over `M'`, no
    /// context ([`crate::sig::legacy::PureEd25519Half`]). Used only by the
    /// `VyraPureEd` regression composition.
    Ed25519PureHalf,
    /// SLH-DSA-SHAKE-128s (FIPS 205), context-bound in the composite. Slow to
    /// sign (seconds); used only in the dual-PQ cell set.
    SlhDsaShake128s,
}

impl SigBase {
    /// A fresh instance of the real component.
    pub fn real(self) -> Box<dyn CompositeComponent> {
        match self {
            SigBase::MlDsa44 => Box::new(MlDsa44),
            SigBase::Ed25519 => Box::new(Ed25519),
            SigBase::Ed25519PureHalf => Box::new(crate::sig::legacy::PureEd25519Half),
            SigBase::SlhDsaShake128s => Box::new(SlhDsaShake128s),
        }
    }

    /// The real component's name.
    pub const fn name(self) -> &'static str {
        match self {
            SigBase::MlDsa44 => "ML-DSA-44",
            SigBase::Ed25519 => "Ed25519",
            SigBase::Ed25519PureHalf => "Ed25519-pure-half",
            SigBase::SlhDsaShake128s => "SLH-DSA-SHAKE-128s",
        }
    }
}

/// Which failure model a signature component slot uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SigModel {
    /// The real component.
    Real,
    /// [`Forgeable`].
    Forgeable,
    /// [`Malleable`].
    Malleable,
    /// [`KeySubstitutable`].
    KeySubstitutable,
    /// [`ContextIgnoring`].
    ContextIgnoring,
    /// [`MessageCollapsing`].
    MessageCollapsing,
}

impl SigModel {
    /// Every model, in report order.
    pub const ALL: [SigModel; 6] = [
        SigModel::Real,
        SigModel::Forgeable,
        SigModel::Malleable,
        SigModel::KeySubstitutable,
        SigModel::ContextIgnoring,
        SigModel::MessageCollapsing,
    ];

    /// Short name.
    pub const fn name(self) -> &'static str {
        match self {
            SigModel::Real => "Real",
            SigModel::Forgeable => "Forgeable",
            SigModel::Malleable => "Malleable",
            SigModel::KeySubstitutable => "KeySubstitutable",
            SigModel::ContextIgnoring => "ContextIgnoring",
            SigModel::MessageCollapsing => "MessageCollapsing",
        }
    }

    /// One line: the property this model breaks.
    pub const fn broken_property(self) -> &'static str {
        match self {
            SigModel::Real => "none (real component)",
            SigModel::Forgeable => "EUF-CMA: a public tag XOF(label, pk, ctx, m) always verifies",
            SigModel::Malleable => "SUF-CMA: one extra signature byte is ignored by verification",
            SigModel::KeySubstitutable => {
                "exclusive ownership (S-CEO): public keys carry a 16-byte tag that verification ignores"
            }
            SigModel::ContextIgnoring => {
                "context binding: the half is the default standalone signature (ML-DSA/SLH-DSA empty context, Ed25519 PureEd25519)"
            }
            SigModel::MessageCollapsing => {
                "message binding (MBS): signs a 12-bit digest of the message, so collisions are cheap"
            }
        }
    }

    /// Whether this is the real component.
    pub const fn is_real(self) -> bool {
        matches!(self, SigModel::Real)
    }

    /// Instantiate this model over `base`.
    pub fn instantiate(self, base: SigBase) -> Box<dyn CompositeComponent> {
        match self {
            SigModel::Real => base.real(),
            SigModel::Forgeable => Box::new(Forgeable::new(base)),
            SigModel::Malleable => Box::new(Malleable::new(base)),
            SigModel::KeySubstitutable => Box::new(KeySubstitutable::new(base)),
            SigModel::ContextIgnoring => Box::new(ContextIgnoring::new(base)),
            SigModel::MessageCollapsing => Box::new(MessageCollapsing::new(base)),
        }
    }
}

/// Serves one fixed byte string to exactly one request of exactly its length
/// (replays a secret key as key-generation randomness).
pub(crate) struct OneShot<'a> {
    pub(crate) bytes: &'a [u8],
    pub(crate) used: bool,
}

impl EntropySource for OneShot<'_> {
    fn fill(&mut self, dest: &mut [u8]) -> Result<()> {
        if self.used || dest.len() != self.bytes.len() {
            return Err(Error::Internal("one-shot seed replay"));
        }
        dest.copy_from_slice(self.bytes);
        self.used = true;
        Ok(())
    }
}

/// The public key belonging to `secret_key` under `component`, by replaying
/// the secret key as key-generation randomness (the VYRA composite's rule).
///
/// # Errors
///
/// If the component's key generation does not draw exactly one request of
/// the secret-key length.
pub fn derive_public_key(component: &dyn CompositeComponent, secret_key: &[u8]) -> Result<Vec<u8>> {
    let (pk, _) = component.generate_keypair(&mut OneShot {
        bytes: secret_key,
        used: false,
    })?;
    Ok(pk)
}

/// `InvalidLength` unless `bytes.len() == expected`.
pub(crate) fn require_len(what: &'static str, bytes: &[u8], expected: usize) -> Result<()> {
    if bytes.len() == expected {
        Ok(())
    } else {
        Err(Error::InvalidLength {
            what,
            expected,
            actual: bytes.len(),
        })
    }
}

/// Model name for `(model, base)` as a static string.
pub(crate) fn model_name(model: SigModel, base: SigBase) -> &'static str {
    use SigBase::{Ed25519 as E, Ed25519PureHalf as P, MlDsa44 as M, SlhDsaShake128s as S};
    match (model, base) {
        (SigModel::Real, b) => b.name(),
        (SigModel::Forgeable, M) => "Forgeable(ML-DSA-44)",
        (SigModel::Forgeable, E) => "Forgeable(Ed25519)",
        (SigModel::Forgeable, P) => "Forgeable(Ed25519-pure-half)",
        (SigModel::Forgeable, S) => "Forgeable(SLH-DSA-SHAKE-128s)",
        (SigModel::Malleable, M) => "Malleable(ML-DSA-44)",
        (SigModel::Malleable, E) => "Malleable(Ed25519)",
        (SigModel::Malleable, P) => "Malleable(Ed25519-pure-half)",
        (SigModel::Malleable, S) => "Malleable(SLH-DSA-SHAKE-128s)",
        (SigModel::KeySubstitutable, M) => "KeySubstitutable(ML-DSA-44)",
        (SigModel::KeySubstitutable, E) => "KeySubstitutable(Ed25519)",
        (SigModel::KeySubstitutable, P) => "KeySubstitutable(Ed25519-pure-half)",
        (SigModel::KeySubstitutable, S) => "KeySubstitutable(SLH-DSA-SHAKE-128s)",
        (SigModel::ContextIgnoring, M) => "ContextIgnoring(ML-DSA-44)",
        (SigModel::ContextIgnoring, E) => "ContextIgnoring(Ed25519)",
        (SigModel::ContextIgnoring, P) => "ContextIgnoring(Ed25519-pure-half)",
        (SigModel::ContextIgnoring, S) => "ContextIgnoring(SLH-DSA-SHAKE-128s)",
        (SigModel::MessageCollapsing, M) => "MessageCollapsing(ML-DSA-44)",
        (SigModel::MessageCollapsing, E) => "MessageCollapsing(Ed25519)",
        (SigModel::MessageCollapsing, P) => "MessageCollapsing(Ed25519-pure-half)",
        (SigModel::MessageCollapsing, S) => "MessageCollapsing(SLH-DSA-SHAKE-128s)",
    }
}
