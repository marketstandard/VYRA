//! What each cell is *expected* to show, and why.
//!
//! Every cell of the report carries an `expected` verdict and an
//! `expected_basis`: the project claim or named control that predicts it.
//! `UNSPECIFIED` means neither VYRA's documented claims nor a control say
//! anything about that cell; its observed verdict is reported, not judged.
//! A gate can compare `verdict` with `expected` mechanically wherever
//! `expected ≠ UNSPECIFIED`.
//!
//! Basis identifiers (KEM):
//!
//! - `control:A` — both components confidentiality-broken: the `Recompute`
//!   adversary must win IND-CCA2 against every combiner.
//! - `control:A2` — Naive over Constant × Constant: the both-sides binding
//!   adversaries must win every binding game.
//! - `control:B` — both components real: no adversary wins against Naive,
//!   CtBound, XWingStyle or Vyra.
//! - `theory:XOR` — XOR combiner over two real components: only MixAndMatch
//!   wins (IND-CCA2), nothing else.
//! - `D-01` — Naive with one Malleable component: mauling that side wins
//!   IND-CCA2 (docs/DECISIONS.md D-01).
//! - `control:D` — CoinFlip never wins.
//! - `claim:V1` — Vyra with exactly one broken component: nothing wins
//!   (the yielding-resistance claim, docs/SECURITY.md combiner argument).
//! - `claim:V2` — Vyra with both components confidentiality-broken:
//!   `Recompute` wins IND-CCA2.
//!
//! Signature bases are documented in [`crate::sig::experiment`].

use crate::adversaries::binding::SideSelection;
use crate::adversaries::{AdversaryKind, BindingAdversary, IndCca2Adversary};
use crate::combiners::CombinerKind;
use crate::experiment::CellSpec;
use crate::games::GameKind;
use crate::models::ModelKind;
use crate::scenario::Side;
use crate::stats::Verdict;

/// An expected verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Expected {
    /// The cell must be BROKEN.
    Broken,
    /// The cell must be NO ATTACK FOUND.
    NoAttackFound,
    /// No claim or control speaks about this cell.
    Unspecified,
}

impl Expected {
    /// `"BROKEN"`, `"NO ATTACK FOUND"` or `"UNSPECIFIED"`.
    pub const fn label(self) -> &'static str {
        match self {
            Expected::Broken => "BROKEN",
            Expected::NoAttackFound => "NO ATTACK FOUND",
            Expected::Unspecified => "UNSPECIFIED",
        }
    }

    /// Whether `verdict` contradicts this expectation.
    pub fn mismatches(self, verdict: Verdict) -> bool {
        match self {
            Expected::Broken => verdict != Verdict::Broken,
            Expected::NoAttackFound => verdict != Verdict::NoAttackFound,
            Expected::Unspecified => false,
        }
    }
}

/// Expected verdict and basis of a KEM cell.
pub fn kem_expected(spec: &CellSpec) -> (Expected, &'static str) {
    let s = spec.scenario;
    let adv = spec.adversary;
    if adv == AdversaryKind::IndCca2(IndCca2Adversary::CoinFlip) {
        return (Expected::NoAttackFound, "control:D");
    }
    let both_conf = s.first.breaks_confidentiality() && s.second.breaks_confidentiality();
    if spec.game == GameKind::IndCca2
        && both_conf
        && adv == AdversaryKind::IndCca2(IndCca2Adversary::Recompute)
    {
        return if s.combiner == CombinerKind::Vyra {
            (Expected::Broken, "claim:V2")
        } else {
            (Expected::Broken, "control:A")
        };
    }
    if s.combiner == CombinerKind::Naive
        && s.first == ModelKind::Constant
        && s.second == ModelKind::Constant
        && matches!(
            adv,
            AdversaryKind::Binding(BindingAdversary::SecondCiphertext(SideSelection::Both))
                | AdversaryKind::Binding(BindingAdversary::CrossKey(SideSelection::Both))
        )
    {
        return (Expected::Broken, "control:A2");
    }
    if s.broken_count() == 0 {
        return match s.combiner {
            CombinerKind::Xor => {
                if adv == AdversaryKind::IndCca2(IndCca2Adversary::MixAndMatch) {
                    (Expected::Broken, "theory:XOR")
                } else {
                    (Expected::NoAttackFound, "theory:XOR")
                }
            }
            _ => (Expected::NoAttackFound, "control:B"),
        };
    }
    if s.combiner == CombinerKind::Naive && spec.game == GameKind::IndCca2 && s.broken_count() == 1
    {
        let maul_side = if s.first == ModelKind::Malleable {
            Some(Side::First)
        } else if s.second == ModelKind::Malleable {
            Some(Side::Second)
        } else {
            None
        };
        if maul_side.map(|side| AdversaryKind::IndCca2(IndCca2Adversary::MaulReplay(side)))
            == Some(adv)
        {
            return (Expected::Broken, "D-01");
        }
    }
    if s.combiner == CombinerKind::Vyra && s.broken_count() == 1 {
        return (Expected::NoAttackFound, "claim:V1");
    }
    (Expected::Unspecified, "none")
}
