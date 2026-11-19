//! Security games as explicit state machines.
//!
//! Each game is a value created by a `start` function (the challenger's
//! setup), exposes oracle methods, and is consumed by `finish`, which applies
//! the win condition. The adversary never sees the challenger's secrets
//! except where the game definition hands them over (LEAK).
//!
//! - [`ind_cca2`]: IND-CCA2 for a KEM, real-or-random key.
//! - [`binding`]: the X-BIND-K-CT and X-BIND-K-PK games of Cremers, Dax and
//!   Medinger, for X ∈ {HON, LEAK} ([`binding::HonestBindingGame`]) and
//!   MAL scenario (I) ([`binding::MaliciousBindingGame`]).
//!
//! The games are generic over any [`vyra_kem::ComponentKem`]; here they are
//! always run against a *hybrid* assembled from two (possibly broken)
//! components.

pub mod binding;
pub mod ind_cca2;

pub use binding::{
    BindingModel, BindingTarget, HonestBindingClaim, HonestBindingGame, HonestBindingView,
    KeyIndex, MaliciousBindingClaim, MaliciousBindingGame,
};
pub use ind_cca2::{IndCca2Challenge, IndCca2Game, OracleAnswer};

/// Which game a result belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum GameKind {
    /// [`IndCca2Game`].
    IndCca2,
    /// A binding game: attack model and bound value (the binding source is
    /// always the key `K`).
    Binding {
        /// HON, LEAK or MAL.
        model: BindingModel,
        /// `CT` or `PK`.
        target: BindingTarget,
    },
}

impl GameKind {
    /// Every game, in report order.
    pub const ALL: [GameKind; 7] = [
        GameKind::IndCca2,
        GameKind::Binding {
            model: BindingModel::Hon,
            target: BindingTarget::Ciphertext,
        },
        GameKind::Binding {
            model: BindingModel::Leak,
            target: BindingTarget::Ciphertext,
        },
        GameKind::Binding {
            model: BindingModel::Mal,
            target: BindingTarget::Ciphertext,
        },
        GameKind::Binding {
            model: BindingModel::Hon,
            target: BindingTarget::PublicKey,
        },
        GameKind::Binding {
            model: BindingModel::Leak,
            target: BindingTarget::PublicKey,
        },
        GameKind::Binding {
            model: BindingModel::Mal,
            target: BindingTarget::PublicKey,
        },
    ];

    /// Name as used in the literature, e.g. `"HON-BIND-K-CT"`.
    pub const fn name(self) -> &'static str {
        match self {
            GameKind::IndCca2 => "IND-CCA2",
            GameKind::Binding { model, target } => match (model, target) {
                (BindingModel::Hon, BindingTarget::Ciphertext) => "HON-BIND-K-CT",
                (BindingModel::Leak, BindingTarget::Ciphertext) => "LEAK-BIND-K-CT",
                (BindingModel::Mal, BindingTarget::Ciphertext) => "MAL-BIND-K-CT",
                (BindingModel::Hon, BindingTarget::PublicKey) => "HON-BIND-K-PK",
                (BindingModel::Leak, BindingTarget::PublicKey) => "LEAK-BIND-K-PK",
                (BindingModel::Mal, BindingTarget::PublicKey) => "MAL-BIND-K-PK",
            },
        }
    }

    /// Whether the game is a distinguishing game (baseline success 1/2) as
    /// opposed to a search game (baseline success negligible).
    pub const fn is_distinguishing(self) -> bool {
        matches!(self, GameKind::IndCca2)
    }
}
