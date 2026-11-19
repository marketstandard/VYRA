//! **INTENTIONALLY INSECURE.** [`Leaky`]: total loss of confidentiality.

use vyra_core::{EntropySource, Kem, Result, SecretBytes, SecurityLevel, Transcript};
use vyra_kem::ComponentKem;

use super::Base;

/// Domain label of the public key-derivation function [`leak`].
pub const LEAKY_LABEL: &[u8] = b"VYRA-YIELD-LEAKY-v1";

/// The shared secret of a [`Leaky`] component, computable by anyone:
/// `SHA3-256(frame(LEAKY_LABEL) ‖ frame(pk) ‖ frame(ct))` (framing as in
/// [`vyra_core::Transcript`]).
pub fn leak(public_key: &[u8], ciphertext: &[u8]) -> [u8; 32] {
    let mut t = Transcript::new(LEAKY_LABEL);
    t.append(public_key).append(ciphertext);
    t.finalize()
}

/// **INTENTIONALLY INSECURE** failure model: the component shared secret is a
/// public function of the public key and ciphertext ([`leak`]).
///
/// Models "this component's hardness assumption is broken": the adversary
/// learns the component key of every ciphertext, including the challenge.
///
/// - **Broken:** confidentiality (IND-CPA, hence IND-CCA2), totally.
/// - **Kept:** correctness; keys, ciphertexts and key generation are those of
///   the wrapped real component; the key binds `(pk, ct)` (it is a
///   collision-resistant hash of both), so HON/LEAK/MAL-BIND-K-CT and
///   -K-PK hold up to SHA3-256 collisions; distinct ciphertexts give
///   unrelated keys (no malleability beyond what confidentiality loss implies).
///
/// Decapsulation still runs the real decapsulation (so malformed input is
/// rejected exactly as before) and then discards its result.
pub struct Leaky {
    inner: Box<dyn ComponentKem>,
    name: &'static str,
}

impl Leaky {
    /// Wrap the real `base` component.
    pub fn new(base: Base) -> Self {
        let name = match base {
            Base::MlKem512 => "Leaky(ML-KEM-512)",
            Base::Hqc128 => "Leaky(HQC-128)",
        };
        Leaky {
            inner: base.real(),
            name,
        }
    }
}

impl Kem for Leaky {
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
        32
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
        let key = leak(public_key, &ct);
        Ok((ct, SecretBytes::from_slice(&key)))
    }

    fn decapsulate(&self, secret_key: &[u8], ciphertext: &[u8]) -> Result<SecretBytes> {
        let (_real, pk) = self
            .inner
            .decapsulate_with_public_key(secret_key, ciphertext)?;
        Ok(SecretBytes::from_slice(&leak(&pk, ciphertext)))
    }
}

impl ComponentKem for Leaky {
    fn validate_public_key(&self, public_key: &[u8]) -> Result<()> {
        self.inner.validate_public_key(public_key)
    }

    fn public_key_from_secret(&self, secret_key: &[u8]) -> Result<Vec<u8>> {
        self.inner.public_key_from_secret(secret_key)
    }
}
