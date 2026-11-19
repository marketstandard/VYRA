//! The interface a hybrid component must offer beyond [`Kem`].

use vyra_core::{Kem, Result, SecretBytes};

/// A KEM usable as a component of [`HybridKem`](crate::HybridKem).
///
/// Besides the raw [`Kem`] operations, a component can
///
/// - check that a public key is canonically encoded, so that typed keys are
///   validated when parsed rather than when first used, and
/// - recover its public key from its secret key, so that the hybrid secret key
///   need not store (and cannot contradict) the public keys that the combiner
///   hashes.
///
/// [`HybridKem`](crate::HybridKem) holds its components as
/// `Box<dyn ComponentKem>`, so any implementation can be substituted.
pub trait ComponentKem: Kem {
    /// Check that `public_key` is a well-formed public key for this scheme.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`](vyra_core::Error::InvalidLength) for a wrong
    /// length, [`Error::InvalidEncoding`](vyra_core::Error::InvalidEncoding)
    /// for a non-canonical encoding.
    fn validate_public_key(&self, public_key: &[u8]) -> Result<()>;

    /// The public key that belongs to `secret_key`, as returned by
    /// [`Kem::generate_keypair`] alongside it.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`](vyra_core::Error::InvalidLength) for a wrong
    /// length, [`Error::InvalidEncoding`](vyra_core::Error::InvalidEncoding)
    /// if the key is malformed.
    fn public_key_from_secret(&self, secret_key: &[u8]) -> Result<Vec<u8>>;

    /// Decapsulate and also return the public key of `secret_key`.
    ///
    /// The default calls [`Kem::decapsulate`] and
    /// [`public_key_from_secret`](Self::public_key_from_secret), always both;
    /// implementations may override it to share work.
    ///
    /// # Errors
    ///
    /// As [`Kem::decapsulate`] and
    /// [`public_key_from_secret`](Self::public_key_from_secret).
    fn decapsulate_with_public_key(
        &self,
        secret_key: &[u8],
        ciphertext: &[u8],
    ) -> Result<(SecretBytes, Vec<u8>)> {
        let ss = self.decapsulate(secret_key, ciphertext);
        let pk = self.public_key_from_secret(secret_key);
        Ok((ss?, pk?))
    }
}
