//! The key-encapsulation mechanism trait.

use crate::entropy::EntropySource;
use crate::error::Result;
use crate::level::SecurityLevel;
use crate::secret::SecretBytes;

/// A key-encapsulation mechanism. Object safe: use as `&dyn Kem` / `Box<dyn Kem>`.
///
/// Keys and ciphertexts are raw byte strings of the fixed lengths reported by
/// the length methods. Implementations follow the implicit-rejection
/// convention of ML-KEM and HQC (docs/DECISIONS.md D-02): `decapsulate` of a
/// well-formed but invalid ciphertext returns a pseudorandom shared secret,
/// not an error. `Err` is reserved for malformed input (wrong length or
/// encoding) and entropy failure, which are public conditions.
pub trait Kem: Send + Sync {
    /// Algorithm name, e.g. `"ML-KEM-768"`.
    fn name(&self) -> &'static str;

    /// Claimed NIST security category.
    fn level(&self) -> SecurityLevel;

    /// Public (encapsulation) key length in bytes.
    fn public_key_len(&self) -> usize;

    /// Secret (decapsulation) key length in bytes.
    fn secret_key_len(&self) -> usize;

    /// Ciphertext length in bytes.
    fn ciphertext_len(&self) -> usize;

    /// Shared secret length in bytes.
    fn shared_secret_len(&self) -> usize;

    /// Generate a key pair `(public_key, secret_key)`.
    ///
    /// # Errors
    ///
    /// [`Error::EntropyFailure`](crate::Error::EntropyFailure) if `rng` fails.
    fn generate_keypair(&self, rng: &mut dyn EntropySource) -> Result<(Vec<u8>, SecretBytes)>;

    /// Encapsulate to `public_key`, returning `(ciphertext, shared_secret)`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`](crate::Error::InvalidLength) /
    /// [`Error::InvalidEncoding`](crate::Error::InvalidEncoding) for a
    /// malformed public key; [`Error::EntropyFailure`](crate::Error::EntropyFailure)
    /// if `rng` fails.
    fn encapsulate(
        &self,
        public_key: &[u8],
        rng: &mut dyn EntropySource,
    ) -> Result<(Vec<u8>, SecretBytes)>;

    /// Decapsulate `ciphertext` with `secret_key`, returning the shared secret.
    ///
    /// # Errors
    ///
    /// Only for malformed input (wrong length or encoding). An invalid but
    /// well-formed ciphertext yields an implicit-rejection key, not an error.
    fn decapsulate(&self, secret_key: &[u8], ciphertext: &[u8]) -> Result<SecretBytes>;
}
