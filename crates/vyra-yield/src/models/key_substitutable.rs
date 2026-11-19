//! **INTENTIONALLY INSECURE.** [`KeySubstitutable`]: loss of key binding
//! against adversarially chosen keys.

use vyra_core::{EntropySource, Kem, Result, SecretBytes, SecurityLevel};
use vyra_kem::ComponentKem;

use super::{Base, concat, require_len, split_at};

/// Length of the tag appended to public and secret keys.
pub const KEY_TAG_LEN: usize = 16;

/// A different secret key for the same real key pair: the input with every
/// bit of its last byte (the end of the tag) inverted. Under the result, every
/// ciphertext decapsulates to the same key as under the input, while the
/// public key derived from it differs.
pub fn substitute_secret_key(secret_key: &[u8]) -> Vec<u8> {
    let mut out = secret_key.to_vec();
    if let Some(last) = out.last_mut() {
        *last ^= 0xFF;
    }
    out
}

/// **INTENTIONALLY INSECURE** failure model: public key `pk_real ‖ tag`,
/// secret key `sk_real ‖ tag` (a random 16-byte tag), and every operation
/// ignores the tag. Two key pairs that differ only in the tag are different
/// public keys under which the same ciphertext decapsulates to the same key.
///
/// - **Broken:** MAL-BIND-K-PK (Cremers–Dax–Medinger): an adversary that
///   chooses the secret keys gets `Decaps(sk, c) = Decaps(sk', c)` with
///   `pk ≠ pk'` ([`substitute_secret_key`]).
/// - **Kept:** IND-CCA2 of the real component (the tag is public and carries
///   no secret); with honestly generated keys the real parts differ, so the
///   HON (and LEAK) binding properties of the real component are unchanged;
///   correctness.
pub struct KeySubstitutable {
    inner: Box<dyn ComponentKem>,
    name: &'static str,
}

impl KeySubstitutable {
    /// Wrap the real `base` component.
    pub fn new(base: Base) -> Self {
        let name = match base {
            Base::MlKem512 => "KeySubstitutable(ML-KEM-512)",
            Base::Hqc128 => "KeySubstitutable(HQC-128)",
        };
        KeySubstitutable {
            inner: base.real(),
            name,
        }
    }
}

impl Kem for KeySubstitutable {
    fn name(&self) -> &'static str {
        self.name
    }

    fn level(&self) -> SecurityLevel {
        self.inner.level()
    }

    fn public_key_len(&self) -> usize {
        self.inner.public_key_len().saturating_add(KEY_TAG_LEN)
    }

    fn secret_key_len(&self) -> usize {
        self.inner.secret_key_len().saturating_add(KEY_TAG_LEN)
    }

    fn ciphertext_len(&self) -> usize {
        self.inner.ciphertext_len()
    }

    fn shared_secret_len(&self) -> usize {
        self.inner.shared_secret_len()
    }

    fn generate_keypair(&self, rng: &mut dyn EntropySource) -> Result<(Vec<u8>, SecretBytes)> {
        let (pk, sk) = self.inner.generate_keypair(rng)?;
        let mut tag = [0u8; KEY_TAG_LEN];
        rng.fill(&mut tag)?;
        Ok((
            concat(&pk, &tag),
            SecretBytes::new(concat(sk.expose(), &tag)),
        ))
    }

    fn encapsulate(
        &self,
        public_key: &[u8],
        rng: &mut dyn EntropySource,
    ) -> Result<(Vec<u8>, SecretBytes)> {
        require_len(
            "substitutable public key",
            public_key,
            self.public_key_len(),
        )?;
        let (real, _tag) = split_at(public_key, self.inner.public_key_len())?;
        self.inner.encapsulate(real, rng)
    }

    fn decapsulate(&self, secret_key: &[u8], ciphertext: &[u8]) -> Result<SecretBytes> {
        require_len(
            "substitutable secret key",
            secret_key,
            self.secret_key_len(),
        )?;
        let (real, _tag) = split_at(secret_key, self.inner.secret_key_len())?;
        self.inner.decapsulate(real, ciphertext)
    }
}

impl ComponentKem for KeySubstitutable {
    fn validate_public_key(&self, public_key: &[u8]) -> Result<()> {
        require_len(
            "substitutable public key",
            public_key,
            self.public_key_len(),
        )?;
        let (real, _tag) = split_at(public_key, self.inner.public_key_len())?;
        self.inner.validate_public_key(real)
    }

    fn public_key_from_secret(&self, secret_key: &[u8]) -> Result<Vec<u8>> {
        require_len(
            "substitutable secret key",
            secret_key,
            self.secret_key_len(),
        )?;
        let (real, tag) = split_at(secret_key, self.inner.secret_key_len())?;
        Ok(concat(&self.inner.public_key_from_secret(real)?, tag))
    }
}
