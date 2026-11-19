//! What a composite needs from a component signature scheme.
//!
//! - [`ContextSignatureScheme`]: a [`SignatureScheme`] whose algorithm has a
//!   context-string input (FIPS 204 ML-DSA, FIPS 205 SLH-DSA).
//! - [`CompositeComponent`]: a [`SignatureScheme`] together with the rules a
//!   composite applies to it: whether it signs the message representative
//!   under the composite context, and how its public key is validated before
//!   the key is hashed into the binding (RULES 12, 18).
//!
//! The named suites use the adapters in this crate ([`crate::MlDsa44`] …,
//! [`crate::SlhDsaShake128s`] …, [`crate::Ed25519`]); a caller can assemble a
//! custom composite from its own implementations with
//! [`CustomComposite::from_components`](crate::CustomComposite::from_components).

use vyra_core::{EntropySource, Result, SignatureScheme};

/// A signature scheme that also accepts an algorithm-level context string
/// (the `ctx` input of FIPS 204 `ML-DSA.Sign` / `ML-DSA.Verify` and of FIPS
/// 205 `slh_sign` / `slh_verify`).
///
/// [`SignatureScheme::sign`] / [`SignatureScheme::verify`] are the same
/// operations with the empty context.
pub trait ContextSignatureScheme: SignatureScheme {
    /// Sign `message` with context string `context`.
    ///
    /// # Errors
    ///
    /// `InvalidLength` for a wrong-length secret key or a context longer than
    /// 255 bytes; `EntropyFailure` if `rng` fails.
    fn sign_with_context(
        &self,
        secret_key: &[u8],
        message: &[u8],
        context: &[u8],
        rng: &mut dyn EntropySource,
    ) -> Result<Vec<u8>>;

    /// Verify `signature` on `message` with context string `context`.
    ///
    /// # Errors
    ///
    /// `InvalidLength` for wrong-length inputs or a context longer than 255
    /// bytes; [`vyra_core::Error::VerificationFailed`] if the signature is
    /// invalid.
    fn verify_with_context(
        &self,
        public_key: &[u8],
        message: &[u8],
        context: &[u8],
        signature: &[u8],
    ) -> Result<()>;
}

/// A component of a composite signature: a [`SignatureScheme`] plus the
/// composite's rules for it.
///
/// A composite calls [`sign_half`](Self::sign_half) and
/// [`verify_half`](Self::verify_half) on the message representative `M'` with
/// the composite context `"VYRA-SIG-v1" ‖ suite_id`
/// ([`composite_context`](crate::composite_context)).
///
/// Contract for implementers:
///
/// - If the algorithm has a context input, [`context_bound`](Self::context_bound)
///   returns `true` and both halves pass `context` to it unchanged (RULES 9:
///   the half is then not a valid standalone default-mode signature). All
///   adapters in this crate are context-bound; Ed25519 uses Ed25519ph with
///   the context ([`crate::ed25519`]).
/// - If it has none, `context_bound` returns `false`, the context is
///   ignored, and the half **is** a valid standalone signature on `M'`
///   (custom components only; no named suite has such a component).
/// - [`validate_public_key`](Self::validate_public_key) accepts exactly the
///   canonical encodings of valid public keys (RULES 12, 18), because the
///   composite hashes the raw public-key bytes into `M'`.
pub trait CompositeComponent: SignatureScheme {
    /// Whether the algorithm takes a context string that the composite uses.
    fn context_bound(&self) -> bool;

    /// Sign `message` (the composite's `M'`) as one half of a composite.
    ///
    /// # Errors
    ///
    /// As [`SignatureScheme::sign`]; `InvalidLength` for a context longer
    /// than 255 bytes when the context is used.
    fn sign_half(
        &self,
        secret_key: &[u8],
        message: &[u8],
        context: &[u8],
        rng: &mut dyn EntropySource,
    ) -> Result<Vec<u8>>;

    /// Verify one half of a composite signature on `message` (`M'`).
    ///
    /// # Errors
    ///
    /// As [`SignatureScheme::verify`]; treat any `Err` as "not verified".
    fn verify_half(
        &self,
        public_key: &[u8],
        message: &[u8],
        context: &[u8],
        signature: &[u8],
    ) -> Result<()>;

    /// Strict validation of a component public key: exact length, canonical
    /// encoding and, where the scheme has one, group membership.
    ///
    /// # Errors
    ///
    /// `InvalidLength` for a wrong length; `InvalidEncoding` for any other
    /// rejected key.
    fn validate_public_key(&self, public_key: &[u8]) -> Result<()>;
}
