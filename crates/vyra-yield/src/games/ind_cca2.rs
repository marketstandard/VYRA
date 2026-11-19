//! IND-CCA2 for a KEM (real-or-random key).
//!
//! # Definition (standard; e.g. Cramer–Shoup 2003, the GHP18 combiner paper)
//!
//! For a KEM `(KeyGen, Encaps, Decaps)` and adversary `A`:
//!
//! ```text
//! (pk, sk) ← KeyGen()
//! (c*, K0) ← Encaps(pk);  K1 ←$ {0,1}^{|K0|};  b ←$ {0,1}
//! b' ← A^{Dec}(pk, c*, K_b)      Dec(c) = ⊥ if c = c*, else Decaps(sk, c)
//! A wins iff b' = b.             Adv = 2·Pr[win] − 1
//! ```
//!
//! In this implementation `b = 0` is the *real* key (`K0`) and `b = 1` the
//! random one; [`IndCca2Game::finish`] takes the adversary's guess as
//! "the key is real" (`true`) or "random" (`false`). The oracle refuses
//! exactly the challenge ciphertext and nothing else (byte equality); every
//! other ciphertext, including malformed ones, is answered (`Err` from
//! `Decaps` is passed on as [`OracleAnswer::Rejected`], which reveals only
//! public length/encoding information, as in docs/DECISIONS.md D-02).
//!
//! The challenger draws the random key from its own randomness *before*
//! choosing `b`, so the amount of randomness consumed does not depend on `b`.

use vyra_core::{EntropySource, Kem, Result, SecretBytes};

/// The adversary's view at the start of the game.
#[derive(Debug)]
pub struct IndCca2Challenge {
    /// The target public key.
    pub public_key: Vec<u8>,
    /// The challenge ciphertext `c*`.
    pub ciphertext: Vec<u8>,
    /// `K_b`: the real key of `c*` or an independent random key.
    pub key: SecretBytes,
}

/// An answer of the decapsulation oracle.
#[derive(Debug)]
pub enum OracleAnswer {
    /// `Decaps(sk, c)`.
    Key(SecretBytes),
    /// `Decaps` returned an error (malformed input).
    Rejected,
    /// The query was the challenge ciphertext.
    Refused,
}

/// IND-CCA2 game state after setup.
pub struct IndCca2Game<'k> {
    kem: &'k dyn Kem,
    secret_key: SecretBytes,
    challenge: Vec<u8>,
    real: bool,
    queries: u64,
}

impl core::fmt::Debug for IndCca2Game<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IndCca2Game")
            .field("kem", &self.kem.name())
            .field("queries", &self.queries)
            .finish_non_exhaustive()
    }
}

impl<'k> IndCca2Game<'k> {
    /// Challenger setup: key pair, challenge, coin.
    ///
    /// # Errors
    ///
    /// If key generation or encapsulation fails.
    pub fn start(
        kem: &'k dyn Kem,
        rng: &mut dyn EntropySource,
    ) -> Result<(Self, IndCca2Challenge)> {
        let (public_key, secret_key) = kem.generate_keypair(rng)?;
        let (ciphertext, real_key) = kem.encapsulate(&public_key, rng)?;
        let mut random_key = SecretBytes::zeroed(real_key.len());
        rng.fill(random_key.expose_mut())?;
        let mut coin = [0u8; 1];
        rng.fill(&mut coin)?;
        let real = coin.iter().any(|c| c & 1 == 0);
        let key = if real { real_key } else { random_key };
        Ok((
            IndCca2Game {
                kem,
                secret_key,
                challenge: ciphertext.clone(),
                real,
                queries: 0,
            },
            IndCca2Challenge {
                public_key,
                ciphertext,
                key,
            },
        ))
    }

    /// The decapsulation oracle.
    pub fn decapsulate(&mut self, ciphertext: &[u8]) -> OracleAnswer {
        self.queries = self.queries.saturating_add(1);
        if ciphertext == self.challenge.as_slice() {
            return OracleAnswer::Refused;
        }
        match self.kem.decapsulate(self.secret_key.expose(), ciphertext) {
            Ok(k) => OracleAnswer::Key(k),
            Err(_) => OracleAnswer::Rejected,
        }
    }

    /// Number of oracle queries made so far.
    pub const fn queries(&self) -> u64 {
        self.queries
    }

    /// Apply the win condition to the guess "the challenge key is real".
    pub fn finish(self, guess_real: bool) -> bool {
        guess_real == self.real
    }
}
