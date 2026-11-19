//! The signature scheme trait.

use crate::entropy::EntropySource;
use crate::error::Result;
use crate::level::SecurityLevel;
use crate::secret::SecretBytes;

/// A digital signature scheme. Object safe: use as `&dyn SignatureScheme`.
///
/// Keys and signatures are raw byte strings of the fixed lengths reported by
/// the length methods.
pub trait SignatureScheme: Send + Sync {
    /// Algorithm name, e.g. `"ML-DSA-65"`.
    fn name(&self) -> &'static str;

    /// Claimed NIST security category.
    fn level(&self) -> SecurityLevel;

    /// Public (verifying) key length in bytes.
    fn public_key_len(&self) -> usize;

    /// Secret (signing) key length in bytes.
    fn secret_key_len(&self) -> usize;

    /// Signature length in bytes.
    fn signature_len(&self) -> usize;

    /// Generate a key pair `(public_key, secret_key)`.
    ///
    /// # Errors
    ///
    /// [`Error::EntropyFailure`](crate::Error::EntropyFailure) if `rng` fails.
    fn generate_keypair(&self, rng: &mut dyn EntropySource) -> Result<(Vec<u8>, SecretBytes)>;

    /// Sign `message` with `secret_key`. `rng` supplies hedging randomness for
    /// schemes that use it; deterministic schemes may ignore it.
    ///
    /// # Errors
    ///
    /// Malformed secret key, or entropy failure.
    fn sign(
        &self,
        secret_key: &[u8],
        message: &[u8],
        rng: &mut dyn EntropySource,
    ) -> Result<Vec<u8>>;

    /// Verify `signature` on `message` under `public_key`.
    ///
    /// # Errors
    ///
    /// [`Error::VerificationFailed`](crate::Error::VerificationFailed) if the
    /// signature is invalid. Malformed public keys or signatures may be
    /// reported as `InvalidLength`/`InvalidEncoding`; callers must treat any
    /// `Err` as "not verified".
    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<()>;
}
