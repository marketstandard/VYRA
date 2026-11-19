//! **INTENTIONALLY INSECURE.** [`Malleable`]: loss of ciphertext
//! non-malleability.

use vyra_core::{EntropySource, Kem, Result, SecretBytes, SecurityLevel};
use vyra_kem::ComponentKem;

use super::{Base, require_len, split_at};

/// Number of extra ciphertext bytes that decapsulation ignores.
pub const MALLEABLE_EXTRA_LEN: usize = 1;

/// **INTENTIONALLY INSECURE** failure model: ciphertexts are `ct_real ‖ m`
/// with one extra byte `m` (0x00 on encapsulation) that decapsulation
/// ignores, so `ct_real ‖ m` and `ct_real ‖ m'` (`m ≠ m'`) decapsulate to the
/// same component key.
///
/// This is the counterexample of Giacon, Heuer and Poettering ("KEM
/// Combiners", PKC 2018) and docs/DECISIONS.md D-01: a component whose
/// ciphertexts can be mauled without changing the key breaks every combiner
/// that hashes only the component keys.
///
/// - **Broken:** IND-CCA2 (maul the challenge, ask the decapsulation oracle)
///   and HON-BIND-K-CT (two different ciphertexts, same key).
/// - **Kept:** IND-CPA confidentiality of the real component (the key is the
///   real component's key); the real component's key-to-public-key binding;
///   correctness.
pub struct Malleable {
    inner: Box<dyn ComponentKem>,
    name: &'static str,
}

impl Malleable {
    /// Wrap the real `base` component.
    pub fn new(base: Base) -> Self {
        let name = match base {
            Base::MlKem512 => "Malleable(ML-KEM-512)",
            Base::Hqc128 => "Malleable(HQC-128)",
        };
        Malleable {
            inner: base.real(),
            name,
        }
    }
}

impl Kem for Malleable {
    fn name(&self) -> &'static str {
        self.name
    }

    fn level(&self) -> SecurityLevel {
        self.inner.level()
    }

    fn public_key_len(&self) -> usize {
        self.inner.public_key_len()
    }

    fn secret_key_len(&self) -> usize {
        self.inner.secret_key_len()
    }

    fn ciphertext_len(&self) -> usize {
        self.inner
            .ciphertext_len()
            .saturating_add(MALLEABLE_EXTRA_LEN)
    }

    fn shared_secret_len(&self) -> usize {
        self.inner.shared_secret_len()
    }

    fn generate_keypair(&self, rng: &mut dyn EntropySource) -> Result<(Vec<u8>, SecretBytes)> {
        self.inner.generate_keypair(rng)
    }

    fn encapsulate(
        &self,
        public_key: &[u8],
        rng: &mut dyn EntropySource,
    ) -> Result<(Vec<u8>, SecretBytes)> {
        let (mut ct, ss) = self.inner.encapsulate(public_key, rng)?;
        ct.push(0x00);
        Ok((ct, ss))
    }

    fn decapsulate(&self, secret_key: &[u8], ciphertext: &[u8]) -> Result<SecretBytes> {
        require_len("malleable ciphertext", ciphertext, self.ciphertext_len())?;
        let (real, _ignored) = split_at(ciphertext, self.inner.ciphertext_len())?;
        self.inner.decapsulate(secret_key, real)
    }
}

impl ComponentKem for Malleable {
    fn validate_public_key(&self, public_key: &[u8]) -> Result<()> {
        self.inner.validate_public_key(public_key)
    }

    fn public_key_from_secret(&self, secret_key: &[u8]) -> Result<Vec<u8>> {
        self.inner.public_key_from_secret(secret_key)
    }
}
