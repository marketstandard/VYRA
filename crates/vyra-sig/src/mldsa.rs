//! ML-DSA (FIPS 204) adapters over the RustCrypto `ml-dsa` crate. ESTABLISHED.
//!
//! The adapters run **unmodified pure ML-DSA** (FIPS 204 Algorithm 2
//! `ML-DSA.Sign` / Algorithm 3 `ML-DSA.Verify`) with **hedged** signing: the
//! 32-byte `rnd` value is drawn from the caller's [`EntropySource`].
//!
//! - The [`SignatureScheme`] implementation (standalone use) passes an
//!   **empty** FIPS 204 context string.
//! - [`ContextSignatureScheme`] passes a caller-chosen FIPS 204 context string
//!   (at most 255 bytes). The composite scheme uses it (through
//!   [`CompositeComponent`]) with the context `"VYRA-SIG-v1" ‖ suite_id`, so
//!   an ML-DSA half taken out of a composite signature does not verify as a
//!   standalone empty-context ML-DSA signature.
//!
//! # Key encodings
//!
//! - Public key: the FIPS 204 `pkEncode` encoding (1312 / 1952 / 2592 bytes):
//!   `ρ (32 bytes) ‖ t1` with each `t1` coefficient packed in 10 bits. Every
//!   bit pattern of that length is a valid and canonical encoding (any 10-bit
//!   value is a legal `t1` coefficient and `ρ` is an arbitrary seed), so a
//!   length check is the complete validity check.
//! - Secret key: the **32-byte seed ξ** of FIPS 204 Algorithm 6
//!   (`ML-DSA.KeyGen_internal`), not the expanded `skEncode` form. The signing
//!   key is re-expanded from the seed on every call. Every 32-byte string is a
//!   valid seed, so no malformed secret key can reach the upstream code.
//! - Signature: the FIPS 204 `sigEncode` encoding (2420 / 3309 / 4627 bytes).
//!
//! # Conformance evidence (tests in `tests/`)
//!
//! - Key generation: all 75 NIST ACVP `ML-DSA-keyGen-FIPS204` vectors (25 per
//!   parameter set): seed ξ → public key through this adapter; the upstream
//!   expanded secret key also matches.
//! - Signing: all 90 NIST ACVP `ML-DSA-sigGen-FIPS204` vectors of the external,
//!   pure, non-external-μ interface (15 deterministic + 15 hedged per parameter
//!   set, contexts 0..=255 bytes) reproduce byte for byte. The vectors give the
//!   *expanded* secret key, which VYRA does not store, so signing is driven
//!   through the upstream `ml-dsa` crate; every expected signature is then
//!   accepted by this adapter's [`ContextSignatureScheme::verify_with_context`].
//! - Verification: all 45 NIST ACVP `ML-DSA-sigVer-FIPS204` vectors of the
//!   same interface (3 valid + 12 invalid per parameter set): this adapter's
//!   verdict equals the expected result.
//! - Differential: same seed and `rnd` give byte-identical keys and signatures
//!   in the independent `fips204` crate, with empty and non-empty context.
//! - Not covered: HashML-DSA and the internal / external-μ interfaces (VYRA
//!   does not use them).
//!
//! # Randomness use
//!
//! Key generation draws exactly 32 bytes (ξ). Signing draws exactly 32 bytes
//! (`rnd`) before calling the upstream signer.

use core::marker::PhantomData;

use ml_dsa::signature::Keypair;
use ml_dsa::{
    EncodedVerifyingKey, ExpandedSigningKey, MlDsaParams, Seed, SigningKey, VerifyingKey,
};
use vyra_core::{
    EntropySource, Error, RandCoreTryRng, Result, SecretBytes, SecurityLevel, SignatureScheme,
};
use zeroize::Zeroize;

use crate::component::CompositeComponent;
/// Re-exported from [`crate::component`] (it was defined here before the
/// SLH-DSA adapters shared it).
pub use crate::component::ContextSignatureScheme;

/// Length of an ML-DSA secret key as stored by VYRA: the FIPS 204 seed ξ.
pub const MLDSA_SEED_LEN: usize = 32;

/// Maximum FIPS 204 context string length in bytes.
pub const MAX_FIPS204_CONTEXT_LEN: usize = 255;

fn check_context(context: &[u8]) -> Result<()> {
    if context.len() > MAX_FIPS204_CONTEXT_LEN {
        Err(Error::InvalidLength {
            what: "FIPS 204 context",
            expected: MAX_FIPS204_CONTEXT_LEN,
            actual: context.len(),
        })
    } else {
        Ok(())
    }
}

/// Length of the per-signature hedging randomness `rnd` (FIPS 204 Algorithm 2).
const RND_LEN: usize = 32;

/// ML-DSA-44 (FIPS 204, NIST category 2).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MlDsa44;

/// ML-DSA-65 (FIPS 204, NIST category 3).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MlDsa65;

/// ML-DSA-87 (FIPS 204, NIST category 5).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MlDsa87;

impl MlDsa44 {
    /// Public key length in bytes (FIPS 204 Table 2).
    pub const PUBLIC_KEY_LEN: usize = 1312;
    /// Secret key length in bytes (the 32-byte seed ξ).
    pub const SECRET_KEY_LEN: usize = MLDSA_SEED_LEN;
    /// Signature length in bytes (FIPS 204 Table 2).
    pub const SIGNATURE_LEN: usize = 2420;
}

impl MlDsa65 {
    /// Public key length in bytes (FIPS 204 Table 2).
    pub const PUBLIC_KEY_LEN: usize = 1952;
    /// Secret key length in bytes (the 32-byte seed ξ).
    pub const SECRET_KEY_LEN: usize = MLDSA_SEED_LEN;
    /// Signature length in bytes (FIPS 204 Table 2).
    pub const SIGNATURE_LEN: usize = 3309;
}

impl MlDsa87 {
    /// Public key length in bytes (FIPS 204 Table 2).
    pub const PUBLIC_KEY_LEN: usize = 2592;
    /// Secret key length in bytes (the 32-byte seed ξ).
    pub const SECRET_KEY_LEN: usize = MLDSA_SEED_LEN;
    /// Signature length in bytes (FIPS 204 Table 2).
    pub const SIGNATURE_LEN: usize = 4627;
}

/// Generic implementation shared by the three parameter sets.
struct Impl<P> {
    pk_len: usize,
    sig_len: usize,
    _params: PhantomData<P>,
}

impl<P: MlDsaParams> Impl<P> {
    const fn new(pk_len: usize, sig_len: usize) -> Self {
        Impl {
            pk_len,
            sig_len,
            _params: PhantomData,
        }
    }

    fn check_len(what: &'static str, expected: usize, actual: usize) -> Result<()> {
        if expected == actual {
            Ok(())
        } else {
            Err(Error::InvalidLength {
                what,
                expected,
                actual,
            })
        }
    }

    fn generate_keypair(&self, rng: &mut dyn EntropySource) -> Result<(Vec<u8>, SecretBytes)> {
        let mut seed = SecretBytes::zeroed(MLDSA_SEED_LEN);
        rng.fill(seed.expose_mut())?;
        let xi =
            <&Seed>::try_from(seed.expose()).map_err(|_| Error::Internal("ML-DSA seed length"))?;
        let signing_key = SigningKey::<P>::from_seed(xi);
        let public_key = signing_key.verifying_key().encode().to_vec();
        Self::check_len("ML-DSA public key", self.pk_len, public_key.len())
            .map_err(|_| Error::Internal("ML-DSA public key length"))?;
        Ok((public_key, seed))
    }

    fn sign(
        &self,
        secret_key: &[u8],
        message: &[u8],
        context: &[u8],
        rng: &mut dyn EntropySource,
    ) -> Result<Vec<u8>> {
        Self::check_len("ML-DSA secret key", MLDSA_SEED_LEN, secret_key.len())?;
        check_context(context)?;
        let xi =
            <&Seed>::try_from(secret_key).map_err(|_| Error::Internal("ML-DSA seed length"))?;

        // Draw the FIPS 204 hedging value `rnd` ourselves so that an entropy
        // failure is reported as such, then hand exactly those bytes to the
        // upstream randomized signer (which reads exactly 32 bytes).
        let mut rnd = OneShot::new();
        rng.fill(&mut rnd.bytes)?;

        let expanded = ExpandedSigningKey::<P>::from_seed(xi);
        let signature = expanded
            .sign_randomized(message, context, &mut RandCoreTryRng::new(&mut rnd))
            .map_err(|_| Error::Internal("ML-DSA signing failed"))?;
        let encoded = signature.encode().to_vec();
        Self::check_len("ML-DSA signature", self.sig_len, encoded.len())
            .map_err(|_| Error::Internal("ML-DSA signature length"))?;
        Ok(encoded)
    }

    fn verify(
        &self,
        public_key: &[u8],
        message: &[u8],
        context: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        check_context(context)?;
        Self::check_len("ML-DSA public key", self.pk_len, public_key.len())?;
        Self::check_len("ML-DSA signature", self.sig_len, signature.len())?;
        let encoded_vk = <&EncodedVerifyingKey<P>>::try_from(public_key)
            .map_err(|_| Error::Internal("ML-DSA public key length"))?;
        let verifying_key = VerifyingKey::<P>::decode(encoded_vk);
        // A signature that fails to decode (malformed hint, z out of range)
        // is simply not a valid signature.
        let Ok(sig) = ml_dsa::Signature::<P>::try_from(signature) else {
            return Err(Error::VerificationFailed);
        };
        if verifying_key.verify_with_context(message, context, &sig) {
            Ok(())
        } else {
            Err(Error::VerificationFailed)
        }
    }
}

/// An entropy source that serves one pre-drawn 32-byte `rnd` value exactly
/// once and fails afterwards. Zeroized on drop.
struct OneShot {
    bytes: [u8; RND_LEN],
    used: bool,
}

impl OneShot {
    fn new() -> Self {
        OneShot {
            bytes: [0u8; RND_LEN],
            used: false,
        }
    }
}

impl EntropySource for OneShot {
    fn fill(&mut self, dest: &mut [u8]) -> Result<()> {
        if self.used || dest.len() != RND_LEN {
            return Err(Error::EntropyFailure);
        }
        dest.copy_from_slice(&self.bytes);
        self.used = true;
        Ok(())
    }
}

impl Drop for OneShot {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

const IMPL44: Impl<ml_dsa::MlDsa44> = Impl::new(MlDsa44::PUBLIC_KEY_LEN, MlDsa44::SIGNATURE_LEN);
const IMPL65: Impl<ml_dsa::MlDsa65> = Impl::new(MlDsa65::PUBLIC_KEY_LEN, MlDsa65::SIGNATURE_LEN);
const IMPL87: Impl<ml_dsa::MlDsa87> = Impl::new(MlDsa87::PUBLIC_KEY_LEN, MlDsa87::SIGNATURE_LEN);

macro_rules! impl_scheme {
    ($ty:ident, $imp:ident, $name:literal, $level:expr) => {
        impl SignatureScheme for $ty {
            fn name(&self) -> &'static str {
                $name
            }

            fn level(&self) -> SecurityLevel {
                $level
            }

            fn public_key_len(&self) -> usize {
                $ty::PUBLIC_KEY_LEN
            }

            fn secret_key_len(&self) -> usize {
                $ty::SECRET_KEY_LEN
            }

            fn signature_len(&self) -> usize {
                $ty::SIGNATURE_LEN
            }

            fn generate_keypair(
                &self,
                rng: &mut dyn EntropySource,
            ) -> Result<(Vec<u8>, SecretBytes)> {
                $imp.generate_keypair(rng)
            }

            fn sign(
                &self,
                secret_key: &[u8],
                message: &[u8],
                rng: &mut dyn EntropySource,
            ) -> Result<Vec<u8>> {
                $imp.sign(secret_key, message, &[], rng)
            }

            fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
                $imp.verify(public_key, message, &[], signature)
            }
        }

        impl ContextSignatureScheme for $ty {
            fn sign_with_context(
                &self,
                secret_key: &[u8],
                message: &[u8],
                context: &[u8],
                rng: &mut dyn EntropySource,
            ) -> Result<Vec<u8>> {
                $imp.sign(secret_key, message, context, rng)
            }

            fn verify_with_context(
                &self,
                public_key: &[u8],
                message: &[u8],
                context: &[u8],
                signature: &[u8],
            ) -> Result<()> {
                $imp.verify(public_key, message, context, signature)
            }
        }

        /// Signs `M'` under the composite context; public keys are checked
        /// by length only (every byte string of that length is a valid,
        /// canonical FIPS 204 public key: module docs).
        impl CompositeComponent for $ty {
            fn context_bound(&self) -> bool {
                true
            }

            fn sign_half(
                &self,
                secret_key: &[u8],
                message: &[u8],
                context: &[u8],
                rng: &mut dyn EntropySource,
            ) -> Result<Vec<u8>> {
                $imp.sign(secret_key, message, context, rng)
            }

            fn verify_half(
                &self,
                public_key: &[u8],
                message: &[u8],
                context: &[u8],
                signature: &[u8],
            ) -> Result<()> {
                $imp.verify(public_key, message, context, signature)
            }

            fn validate_public_key(&self, public_key: &[u8]) -> Result<()> {
                if public_key.len() == $ty::PUBLIC_KEY_LEN {
                    Ok(())
                } else {
                    Err(Error::InvalidLength {
                        what: "ML-DSA public key",
                        expected: $ty::PUBLIC_KEY_LEN,
                        actual: public_key.len(),
                    })
                }
            }
        }
    };
}

impl_scheme!(MlDsa44, IMPL44, "ML-DSA-44", SecurityLevel::L2);
impl_scheme!(MlDsa65, IMPL65, "ML-DSA-65", SecurityLevel::L3);
impl_scheme!(MlDsa87, IMPL87, "ML-DSA-87", SecurityLevel::L5);
