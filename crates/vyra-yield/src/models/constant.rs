//! **INTENTIONALLY INSECURE.** [`Constant`]: a degenerate component.

use vyra_core::{EntropySource, Kem, Result, SecretBytes, SecurityLevel};
use vyra_kem::ComponentKem;

use super::Base;

/// The fixed, public shared secret of every [`Constant`] component.
pub const CONSTANT_SECRET: [u8; 32] = [0x5A; 32];

/// **INTENTIONALLY INSECURE** failure model: ciphertexts and keys are those
/// of the real component, but the shared secret is always
/// [`CONSTANT_SECRET`].
///
/// - **Broken:** everything that concerns the key: confidentiality, and
///   every X-BIND-K-CT / X-BIND-K-PK notion (any two decapsulations agree).
/// - **Kept:** correctness (trivially), and malformed-input rejection of the
///   real component (decapsulation still runs the real one first).
pub struct Constant {
    inner: Box<dyn ComponentKem>,
    name: &'static str,
}

impl Constant {
    /// Wrap the real `base` component.
    pub fn new(base: Base) -> Self {
        let name = match base {
            Base::MlKem512 => "Constant(ML-KEM-512)",
            Base::Hqc128 => "Constant(HQC-128)",
        };
        Constant {
            inner: base.real(),
            name,
        }
    }
}

impl Kem for Constant {
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
        self.inner.ciphertext_len()
    }

    fn shared_secret_len(&self) -> usize {
        CONSTANT_SECRET.len()
    }

    fn generate_keypair(&self, rng: &mut dyn EntropySource) -> Result<(Vec<u8>, SecretBytes)> {
        self.inner.generate_keypair(rng)
    }

    fn encapsulate(
        &self,
        public_key: &[u8],
        rng: &mut dyn EntropySource,
    ) -> Result<(Vec<u8>, SecretBytes)> {
        let (ct, _real) = self.inner.encapsulate(public_key, rng)?;
        Ok((ct, SecretBytes::from_slice(&CONSTANT_SECRET)))
    }

    fn decapsulate(&self, secret_key: &[u8], ciphertext: &[u8]) -> Result<SecretBytes> {
        let _real = self.inner.decapsulate(secret_key, ciphertext)?;
        Ok(SecretBytes::from_slice(&CONSTANT_SECRET))
    }
}

impl ComponentKem for Constant {
    fn validate_public_key(&self, public_key: &[u8]) -> Result<()> {
        self.inner.validate_public_key(public_key)
    }

    fn public_key_from_secret(&self, secret_key: &[u8]) -> Result<Vec<u8>> {
        self.inner.public_key_from_secret(secret_key)
    }
}
