//! Binding-game adversaries.

use vyra_core::{EntropySource, Result, SecretBytes};

use super::{encapsulate_side, join_secret, random32, second_ciphertext_side};
use crate::games::{BindingTarget, HonestBindingClaim, HonestBindingView, MaliciousBindingClaim};
use crate::models::ModelKind;
use crate::models::key_substitutable::substitute_secret_key;
use crate::scenario::{AttackContext, Side};

/// Which sides a [`BindingAdversary::SecondCiphertext`] changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SideSelection {
    /// Change component 1's ciphertext only.
    First,
    /// Change component 2's ciphertext only.
    Second,
    /// Change both.
    Both,
}

impl SideSelection {
    fn changes(self, side: Side) -> bool {
        matches!(
            (self, side),
            (SideSelection::Both, _)
                | (SideSelection::First, Side::First)
                | (SideSelection::Second, Side::Second)
        )
    }
}

/// A binding-game strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum BindingAdversary {
    /// For Q = {CT}: one key pair (HON/LEAK: `b = 0`; MAL: an honestly
    /// generated pair used twice). Build `c = c1 ‖ c2`, then `c'` by
    /// replacing the selected sides with a second ciphertext that the side's
    /// failure model lets decapsulate to the same component key (Malleable:
    /// maul; SenderKeyed: re-encapsulate the chosen key; otherwise a fresh
    /// encapsulation, which only helps if the key ignores the ciphertext).
    /// Output `(c, c')`.
    SecondCiphertext(SideSelection),
    /// For Q = {PK}: two different public keys, ciphertexts meant to give the
    /// same key. HON/LEAK (two honest keys): per side, SenderKeyed
    /// re-encapsulates one chosen key under each key; every other model
    /// reuses the same component ciphertext under both keys. MAL: from one
    /// honest pair, per selected side: KeySubstitutable → substituted secret
    /// key, same ciphertext; SenderKeyed → fresh key pair, chosen key
    /// re-encapsulated; any other model → fresh secret key, same ciphertext
    /// (wins only if the key ignores the secret key, as for Constant). In MAL
    /// only the *selected* sides are changed; the
    /// others keep the identical component key and ciphertext (so one
    /// substitutable side suffices, and a combiner that hashes only one
    /// side's public key can be targeted on the other side). In HON/LEAK the
    /// keys differ on both sides anyway; unselected sides reuse the same
    /// component ciphertext.
    CrossKey(SideSelection),
}

impl BindingAdversary {
    /// Every binding strategy.
    pub const ALL: [BindingAdversary; 6] = [
        BindingAdversary::SecondCiphertext(SideSelection::First),
        BindingAdversary::SecondCiphertext(SideSelection::Second),
        BindingAdversary::SecondCiphertext(SideSelection::Both),
        BindingAdversary::CrossKey(SideSelection::First),
        BindingAdversary::CrossKey(SideSelection::Second),
        BindingAdversary::CrossKey(SideSelection::Both),
    ];

    /// Short name.
    pub const fn name(self) -> &'static str {
        match self {
            BindingAdversary::SecondCiphertext(SideSelection::First) => "SecondCiphertext-1",
            BindingAdversary::SecondCiphertext(SideSelection::Second) => "SecondCiphertext-2",
            BindingAdversary::SecondCiphertext(SideSelection::Both) => "SecondCiphertext-12",
            BindingAdversary::CrossKey(SideSelection::First) => "CrossKey-1",
            BindingAdversary::CrossKey(SideSelection::Second) => "CrossKey-2",
            BindingAdversary::CrossKey(SideSelection::Both) => "CrossKey-12",
        }
    }

    /// One-line description.
    pub const fn description(self) -> &'static str {
        match self {
            BindingAdversary::SecondCiphertext(_) => {
                "same key pair; second ciphertext with the same component key(s) via maul / re-encapsulation / fresh encapsulation"
            }
            BindingAdversary::CrossKey(_) => {
                "two different public keys; same or re-encapsulated component ciphertexts (MAL: selected sides substituted / fresh, others identical)"
            }
        }
    }

    /// Whether the strategy is meant for bound value `target`.
    pub const fn applies_to(self, target: BindingTarget) -> bool {
        matches!(
            (self, target),
            (
                BindingAdversary::SecondCiphertext(_),
                BindingTarget::Ciphertext
            ) | (BindingAdversary::CrossKey(_), BindingTarget::PublicKey)
        )
    }

    /// Two ciphertexts under one hybrid public key, per
    /// [`SecondCiphertext`](Self::SecondCiphertext).
    fn ciphertext_pair(
        ctx: &AttackContext,
        sel: SideSelection,
        pk: &[u8],
        rng: &mut dyn EntropySource,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let (pk1, pk2) = ctx.split_public_key(pk)?;
        let mut first = Vec::new();
        let mut second = Vec::new();
        for (side, pki) in [(Side::First, pk1), (Side::Second, pk2)] {
            let x = random32(rng)?;
            let c = encapsulate_side(ctx, side, pki, &x, rng)?;
            let c2 = if sel.changes(side) {
                second_ciphertext_side(ctx, side, pki, &c, &x, rng)?
            } else {
                c.clone()
            };
            first.extend_from_slice(&c);
            second.extend_from_slice(&c2);
        }
        Ok((first, second))
    }

    /// Play a HON or LEAK game (the oracles are not needed by these
    /// strategies; leaked secret keys are not used either).
    ///
    /// # Errors
    ///
    /// Harness errors.
    pub fn play_honest(
        self,
        ctx: &AttackContext,
        view: &HonestBindingView,
        rng: &mut dyn EntropySource,
    ) -> Result<HonestBindingClaim> {
        let (pk_a, pk_b) = &view.public_keys;
        match self {
            BindingAdversary::SecondCiphertext(sel) => {
                let ciphertexts = Self::ciphertext_pair(ctx, sel, pk_a, rng)?;
                Ok(HonestBindingClaim {
                    same_key_pair: true,
                    ciphertexts,
                })
            }
            BindingAdversary::CrossKey(sel) => {
                let (a1, a2) = ctx.split_public_key(pk_a)?;
                let (b1, b2) = ctx.split_public_key(pk_b)?;
                let mut ca = Vec::new();
                let mut cb = Vec::new();
                for (side, pa, pb) in [(Side::First, a1, b1), (Side::Second, a2, b2)] {
                    let x = random32(rng)?;
                    let c = encapsulate_side(ctx, side, pa, &x, rng)?;
                    let c_other = match ctx.scenario.model(side) {
                        ModelKind::SenderKeyed if sel.changes(side) => {
                            encapsulate_side(ctx, side, pb, &x, rng)?
                        }
                        _ => c.clone(),
                    };
                    ca.extend_from_slice(&c);
                    cb.extend_from_slice(&c_other);
                }
                Ok(HonestBindingClaim {
                    same_key_pair: false,
                    ciphertexts: (ca, cb),
                })
            }
        }
    }

    /// Play a MAL game (scenario I): choose both secret keys and ciphertexts.
    ///
    /// # Errors
    ///
    /// Harness errors.
    pub fn play_malicious(
        self,
        ctx: &AttackContext,
        rng: &mut dyn EntropySource,
    ) -> Result<MaliciousBindingClaim> {
        let (pk, sk) = ctx.hybrid().generate_keypair(rng)?;
        match self {
            BindingAdversary::SecondCiphertext(sel) => {
                let ciphertexts = Self::ciphertext_pair(ctx, sel, &pk, rng)?;
                Ok(MaliciousBindingClaim {
                    secret_keys: (sk.clone(), sk),
                    ciphertexts,
                })
            }
            BindingAdversary::CrossKey(sel) => {
                let (pk1, pk2) = ctx.split_public_key(&pk)?;
                let (sk1, sk2) = ctx.split_secret_key(sk.expose())?;
                let mut ca = Vec::new();
                let mut cb = Vec::new();
                let mut sk_other: Vec<SecretBytes> = Vec::with_capacity(2);
                for (side, pki, ski) in [(Side::First, pk1, sk1), (Side::Second, pk2, sk2)] {
                    let x = random32(rng)?;
                    let c = encapsulate_side(ctx, side, pki, &x, rng)?;
                    let (sk_b, c_b) = if !sel.changes(side) {
                        (SecretBytes::from_slice(ski), c.clone())
                    } else {
                        match ctx.scenario.model(side) {
                            ModelKind::KeySubstitutable => {
                                (SecretBytes::new(substitute_secret_key(ski)), c.clone())
                            }
                            ModelKind::SenderKeyed => {
                                let (pk_b, fresh) = ctx.component(side).generate_keypair(rng)?;
                                let c_b = encapsulate_side(ctx, side, &pk_b, &x, rng)?;
                                (fresh, c_b)
                            }
                            // Constant: any key decapsulates `c` to the constant.
                            // Real / Leaky / Malleable: the honest attempt, which
                            // fails unless the key ignores the secret key.
                            ModelKind::Constant
                            | ModelKind::Real
                            | ModelKind::Leaky
                            | ModelKind::Malleable => {
                                let (_, fresh) = ctx.component(side).generate_keypair(rng)?;
                                (fresh, c.clone())
                            }
                        }
                    };
                    ca.extend_from_slice(&c);
                    cb.extend_from_slice(&c_b);
                    sk_other.push(sk_b);
                }
                let sk_b = match sk_other.as_slice() {
                    [a, b] => join_secret(a.expose(), b.expose()),
                    _ => return Err(vyra_core::Error::Internal("cross-key assembly")),
                };
                Ok(MaliciousBindingClaim {
                    secret_keys: (sk, sk_b),
                    ciphertexts: (ca, cb),
                })
            }
        }
    }
}
