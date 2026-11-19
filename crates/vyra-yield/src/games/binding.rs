//! Binding games X-BIND-K-CT and X-BIND-K-PK.
//!
//! # Source
//!
//! Cremers, Dax, Medinger, "Keeping Up with the KEMs: Stronger Security
//! Notions for KEMs and automated analysis of KEM-based protocols", ACM CCS
//! 2024 (ePrint 2023/1933) define the family X-BIND-P-Q. The games below
//! follow the generic pseudo-code as restated in Krämer, Struck, Weishäupl,
//! "Binding Security of Implicitly-Rejecting KEMs and Application to BIKE and
//! HQC", IACR Communications in Cryptology 2(2), Figure 3 — **verified
//! against that restatement**; the CDM paper itself could not be fetched while
//! this crate was written, so agreement with CDM's own figure is **to be
//! verified**.
//!
//! # Definition (P = {K}, Q ∈ {{CT}, {PK}})
//!
//! HON and LEAK:
//!
//! ```text
//! (pk0, sk0) ←$ KeyGen();  (pk1, sk1) ←$ KeyGen()
//! if Q = {CT}:  b ← A();  if b = 0: (pk1, sk1) ← (pk0, sk0)     // PK ∉ P ∪ Q
//! HON:  (c0, c1) ← A^{Dec(sk0,·), Dec(sk1,·)}(pk0, pk1)
//! LEAK: (c0, c1) ← A(pk0, sk0, pk1, sk1)
//! k0 ← Decaps(sk0, c0);  k1 ← Decaps(sk1, c1)
//! if k0 = ⊥ or k1 = ⊥: return 0
//! return [k0 = k1] ∧ [x0 ≠ x1]            x = c for Q = {CT}, x = pk for Q = {PK}
//! ```
//!
//! For Q = {PK}, the two key pairs are always independent (no `b`). The
//! adversary's choice of `b` is [`HonestBindingClaim::same_key_pair`]; it is
//! ignored when Q = {PK}. A LEAK adversary may also use the oracles (they add
//! nothing to the leaked secret keys).
//!
//! MAL, scenario (I) "Decaps–Decaps" only:
//!
//! ```text
//! (sk0, sk1, c0, c1) ← A()
//! k0 ← Decaps(sk0, c0);  k1 ← Decaps(sk1, c1);  pk_i ← PK(sk_i)
//! if k0 = ⊥ or k1 = ⊥: return 0
//! return [k0 = k1] ∧ [x0 ≠ x1]
//! ```
//!
//! Following Krämer–Struck–Weishäupl Remark 1, the secret key determines the
//! public key; here `PK(sk)` is
//! [`ComponentKem::public_key_from_secret`], which is also what VYRA's
//! decapsulation feeds to its combiner. Scenarios (II) Encaps–Decaps and (III)
//! Encaps–Encaps of the MAL game are **not implemented**, so "MAL" results
//! here cover scenario (I) only.
//!
//! `⊥` is an `Err` from decapsulation (implicitly rejecting KEMs never
//! output `⊥` for well-formed input).

use vyra_core::{EntropySource, Kem, Result, SecretBytes};
use vyra_kem::ComponentKem;

use super::ind_cca2::OracleAnswer;

/// The attack model X.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum BindingModel {
    /// Honest keys, adversary gets public keys and decapsulation oracles.
    Hon,
    /// Honest keys, adversary also gets the secret keys.
    Leak,
    /// Adversary chooses the secret keys (scenario I only).
    Mal,
}

/// The bound value Q (the binding source P is always the key K).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum BindingTarget {
    /// Q = {CT}: equal keys must imply equal ciphertexts.
    Ciphertext,
    /// Q = {PK}: equal keys must imply equal public keys.
    PublicKey,
}

/// Which of the two honest key pairs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyIndex {
    /// Key pair 0.
    Zero,
    /// Key pair 1.
    One,
}

/// The adversary's view in a HON or LEAK game.
#[derive(Debug)]
pub struct HonestBindingView {
    /// `(pk0, pk1)`. For Q = {CT} both pairs are generated; whether the
    /// second is used is the adversary's choice `b`.
    pub public_keys: (Vec<u8>, Vec<u8>),
    /// `(sk0, sk1)` in the LEAK model, `None` in HON.
    pub leaked_secret_keys: Option<(SecretBytes, SecretBytes)>,
}

/// The adversary's output in a HON or LEAK game.
#[derive(Debug)]
pub struct HonestBindingClaim {
    /// `b = 0` (use key pair 0 for both decapsulations). Only meaningful for
    /// Q = {CT}; ignored for Q = {PK}.
    pub same_key_pair: bool,
    /// `(c0, c1)`.
    pub ciphertexts: (Vec<u8>, Vec<u8>),
}

/// HON / LEAK binding game state after setup.
pub struct HonestBindingGame<'k> {
    kem: &'k dyn Kem,
    target: BindingTarget,
    pk0: Vec<u8>,
    sk0: SecretBytes,
    pk1: Vec<u8>,
    sk1: SecretBytes,
}

impl core::fmt::Debug for HonestBindingGame<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HonestBindingGame")
            .field("kem", &self.kem.name())
            .field("target", &self.target)
            .finish_non_exhaustive()
    }
}

impl<'k> HonestBindingGame<'k> {
    /// Challenger setup for X ∈ {HON, LEAK}.
    ///
    /// # Errors
    ///
    /// `Error::Internal` if `model` is `Mal` (use [`MaliciousBindingGame`]);
    /// key-generation errors.
    pub fn start(
        kem: &'k dyn Kem,
        model: BindingModel,
        target: BindingTarget,
        rng: &mut dyn EntropySource,
    ) -> Result<(Self, HonestBindingView)> {
        if model == BindingModel::Mal {
            return Err(vyra_core::Error::Internal(
                "MAL binding uses MaliciousBindingGame",
            ));
        }
        let (pk0, sk0) = kem.generate_keypair(rng)?;
        let (pk1, sk1) = kem.generate_keypair(rng)?;
        let leaked_secret_keys = match model {
            BindingModel::Leak => Some((sk0.clone(), sk1.clone())),
            BindingModel::Hon | BindingModel::Mal => None,
        };
        let view = HonestBindingView {
            public_keys: (pk0.clone(), pk1.clone()),
            leaked_secret_keys,
        };
        Ok((
            HonestBindingGame {
                kem,
                target,
                pk0,
                sk0,
                pk1,
                sk1,
            },
            view,
        ))
    }

    /// The decapsulation oracle for key pair `which`.
    pub fn decapsulate(&mut self, which: KeyIndex, ciphertext: &[u8]) -> OracleAnswer {
        let sk = match which {
            KeyIndex::Zero => &self.sk0,
            KeyIndex::One => &self.sk1,
        };
        match self.kem.decapsulate(sk.expose(), ciphertext) {
            Ok(k) => OracleAnswer::Key(k),
            Err(_) => OracleAnswer::Rejected,
        }
    }

    /// Apply the win condition.
    pub fn finish(self, claim: &HonestBindingClaim) -> bool {
        let use_same = claim.same_key_pair && self.target == BindingTarget::Ciphertext;
        let (pk_b, sk_b) = if use_same {
            (&self.pk0, &self.sk0)
        } else {
            (&self.pk1, &self.sk1)
        };
        let (c0, c1) = &claim.ciphertexts;
        let k0 = self.kem.decapsulate(self.sk0.expose(), c0);
        let k1 = self.kem.decapsulate(sk_b.expose(), c1);
        let (Ok(k0), Ok(k1)) = (k0, k1) else {
            return false;
        };
        let differs = match self.target {
            BindingTarget::Ciphertext => c0 != c1,
            BindingTarget::PublicKey => self.pk0 != *pk_b,
        };
        k0.ct_eq(&k1) && differs
    }
}

/// The adversary's output in a MAL game (scenario I).
#[derive(Debug)]
pub struct MaliciousBindingClaim {
    /// `(sk0, sk1)`, chosen by the adversary.
    pub secret_keys: (SecretBytes, SecretBytes),
    /// `(c0, c1)`.
    pub ciphertexts: (Vec<u8>, Vec<u8>),
}

/// MAL binding game (scenario I). The challenger has no setup.
pub struct MaliciousBindingGame<'k> {
    kem: &'k dyn ComponentKem,
    target: BindingTarget,
}

impl core::fmt::Debug for MaliciousBindingGame<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MaliciousBindingGame")
            .field("kem", &self.kem.name())
            .field("target", &self.target)
            .finish()
    }
}

impl<'k> MaliciousBindingGame<'k> {
    /// The game for `kem` and bound value `target`.
    pub fn new(kem: &'k dyn ComponentKem, target: BindingTarget) -> Self {
        MaliciousBindingGame { kem, target }
    }

    /// Apply the win condition. Errors from decapsulation or public-key
    /// derivation count as `⊥` (loss).
    pub fn finish(self, claim: &MaliciousBindingClaim) -> bool {
        let (sk0, sk1) = &claim.secret_keys;
        let (c0, c1) = &claim.ciphertexts;
        let k0 = self.kem.decapsulate(sk0.expose(), c0);
        let k1 = self.kem.decapsulate(sk1.expose(), c1);
        let (Ok(k0), Ok(k1)) = (k0, k1) else {
            return false;
        };
        let differs = match self.target {
            BindingTarget::Ciphertext => c0 != c1,
            BindingTarget::PublicKey => {
                let pk0 = self.kem.public_key_from_secret(sk0.expose());
                let pk1 = self.kem.public_key_from_secret(sk1.expose());
                match (pk0, pk1) {
                    (Ok(a), Ok(b)) => a != b,
                    _ => return false,
                }
            }
        };
        k0.ct_eq(&k1) && differs
    }
}
