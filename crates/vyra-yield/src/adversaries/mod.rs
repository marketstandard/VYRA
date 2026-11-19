//! Concrete, deterministic attack strategies.
//!
//! Every adversary is Kerckhoffs-aware: it knows the scenario (combiner and
//! both failure models) through [`AttackContext`] and uses whatever the
//! failure model it faces makes possible. All its randomness comes from the
//! seeded source it is handed, so every trial is reproducible.
//!
//! "No attack found" for a cell means only that *these* strategies did not
//! win significantly often. It is not evidence against strategies that are
//! not implemented here.

pub mod binding;
pub mod ind_cca2;

pub use binding::BindingAdversary;
pub use ind_cca2::IndCca2Adversary;

use vyra_core::{EntropySource, Result, SecretBytes};

use crate::models::sender_keyed::PAD_LEN;
use crate::models::{ModelKind, SenderKeyed};
use crate::scenario::{AttackContext, FIRST_BASE, SECOND_BASE, Side};

/// Any adversary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AdversaryKind {
    /// An IND-CCA2 adversary.
    IndCca2(IndCca2Adversary),
    /// A binding-game adversary.
    Binding(BindingAdversary),
}

impl AdversaryKind {
    /// Short name used in reports and seeds.
    pub const fn name(self) -> &'static str {
        match self {
            AdversaryKind::IndCca2(a) => a.name(),
            AdversaryKind::Binding(a) => a.name(),
        }
    }

    /// One-line description of the strategy.
    pub const fn description(self) -> &'static str {
        match self {
            AdversaryKind::IndCca2(a) => a.description(),
            AdversaryKind::Binding(a) => a.description(),
        }
    }
}

/// `bytes` with the low bit of its last byte flipped (blind mauling: for
/// [`Malleable`](crate::models::Malleable) this is the ignored byte; for every
/// other model it changes a meaningful byte).
pub fn flip_last(bytes: &[u8]) -> Vec<u8> {
    let mut out = bytes.to_vec();
    if let Some(last) = out.last_mut() {
        *last ^= 0x01;
    }
    out
}

/// `a ‖ b`.
pub fn join(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(a.len().saturating_add(b.len()));
    v.extend_from_slice(a);
    v.extend_from_slice(b);
    v
}

/// `a ‖ b` as a secret.
pub fn join_secret(a: &[u8], b: &[u8]) -> SecretBytes {
    SecretBytes::new(join(a, b))
}

/// Byte-wise XOR over the shorter length.
pub fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b).map(|(x, y)| x ^ y).collect()
}

fn sender_keyed(side: Side) -> SenderKeyed {
    match side {
        Side::First => SenderKeyed::new(FIRST_BASE),
        Side::Second => SenderKeyed::new(SECOND_BASE),
    }
}

/// Fresh 32 random bytes from `rng`.
pub(crate) fn random32(rng: &mut dyn EntropySource) -> Result<[u8; PAD_LEN]> {
    let mut x = [0u8; PAD_LEN];
    rng.fill(&mut x)?;
    Ok(x)
}

/// Encapsulate on `side` to the component key `pk`. For a
/// [`SenderKeyed`] component the key is chosen as `x`; otherwise `x` is unused.
pub(crate) fn encapsulate_side(
    ctx: &AttackContext,
    side: Side,
    pk: &[u8],
    x: &[u8; PAD_LEN],
    rng: &mut dyn EntropySource,
) -> Result<Vec<u8>> {
    match ctx.scenario.model(side) {
        ModelKind::SenderKeyed => sender_keyed(side).encapsulate_chosen(pk, x, rng),
        _ => Ok(ctx.component(side).encapsulate(pk, rng)?.0),
    }
}

/// A second ciphertext on `side` intended to decapsulate to the same
/// component key as `c` (which [`encapsulate_side`] made with the same `x`),
/// using the best strategy the side's model offers: maul (Malleable),
/// re-encapsulate the chosen key (SenderKeyed), or a fresh encapsulation
/// (all others; succeeds only if the key ignores the ciphertext, as for
/// Constant).
pub(crate) fn second_ciphertext_side(
    ctx: &AttackContext,
    side: Side,
    pk: &[u8],
    c: &[u8],
    x: &[u8; PAD_LEN],
    rng: &mut dyn EntropySource,
) -> Result<Vec<u8>> {
    match ctx.scenario.model(side) {
        ModelKind::Malleable => Ok(flip_last(c)),
        ModelKind::SenderKeyed => sender_keyed(side).encapsulate_chosen(pk, x, rng),
        _ => Ok(ctx.component(side).encapsulate(pk, rng)?.0),
    }
}
