//! Ed25519 (RFC 8032) adapter over `ed25519-dalek`. ESTABLISHED.
//!
//! Two RFC 8032 variants, both used unmodified through `ed25519-dalek`'s
//! public API:
//!
//! - **Standalone** ([`SignatureScheme`]): **PureEd25519** (RFC 8032 §5.1,
//!   no context, no pre-hash), verified with `verify_strict`.
//! - **Composite half** ([`CompositeComponent`], U12-R1): **Ed25519ph**
//!   (RFC 8032 §5.1, `PH = SHA-512`, `phflag = 1`) with context string =
//!   the composite context `"VYRA-SIG-v1" ‖ suite_id`, signed with
//!   `SigningKey::sign_prehashed` and verified with
//!   `VerifyingKey::verify_prehashed_strict` (the same extra checks as
//!   `verify_strict`: small-order `R` and small-order keys rejected). The
//!   `dom2(1, ctx)` prefix makes an Ed25519ph signature never a valid
//!   PureEd25519 signature on any message (RFC 8032 §5.1 domain separation),
//!   so the Ed25519 half of a composite is **not** a valid standalone
//!   (PureEd25519) signature on `M'`, and a standalone PureEd25519 signature
//!   on `M'` does not complete a composite.
//!
//! Why Ed25519ph and not Ed25519ctx (pure, with context, which would avoid
//! the prehash): `ed25519-dalek` 3.0 exposes no Ed25519ctx API. Its internal
//! verifier (`RCompute`) hard-codes `phflag = 1` whenever a context is given,
//! and Ed25519ctx would only be reachable by writing a custom `Digest` type
//! that injects `dom2(0, ctx)` into the `hazmat::raw_sign` hashes and by
//! re-adding `verify_strict`'s small-order checks around `hazmat::raw_verify`
//! by hand. That was judged not sound enough (RULES 2). **Assumption delta:**
//! the Ed25519 half signs `SHA-512(M')`, so an existential forgery of that
//! half also follows from a SHA-512 collision on two representatives `M'`
//! (PureEd25519 did not need SHA-512 collision resistance for this). `M'`
//! starts with a fixed domain label, the suite id and a 32-byte SHA3-256
//! digest of the composite public key, and the ML-DSA / SLH-DSA half signs
//! `M'` itself without any prehash, so a SHA-512 collision alone does not
//! forge a composite: the other half must still be forged on the second
//! representative.
//!
//! Common to both variants:
//!
//! - Signing is deterministic. The entropy source passed to signing is
//!   ignored and no bytes are drawn from it.
//! - Verification uses `ed25519-dalek`'s `verify_strict`, which in addition to
//!   the RFC 8032 checks rejects small-order public keys and small-order `R`
//!   values, and (like every dalek verifier) rejects non-canonical `S`.
//! - Public keys must be **canonical** encodings (RFC 8032 §5.1.3: `y < p`,
//!   and no sign bit set when `x = 0`). `ed25519-dalek` 3.0's
//!   `VerifyingKey::from_bytes` does *not* check this (it reduces `y` mod `p`
//!   and negates `x = 0` to itself), so the adapter re-encodes the decoded
//!   point and requires the exact input bytes back.
//! - Both parse-time validation ([`Ed25519::validate_public_key`]) and the
//!   standalone [`SignatureScheme::verify`] additionally require the point to
//!   lie in the **prime-order subgroup** (torsion-free, and not the
//!   identity). Honest keys always do (clamped scalar × base point). This
//!   rejects small-order and mixed-order keys, under which cofactored and
//!   cofactorless verifiers could disagree. `verify` reports a malformed
//!   encoding (not a point, non-canonical) as `InvalidEncoding` and a
//!   small-order or mixed-order key as `VerificationFailed`.
//! - Secret key encoding: the 32-byte RFC 8032 private key (seed).
//!
//! **Security:** Ed25519 gives roughly 128-bit security against classical
//! attackers and **none** against an attacker with a large quantum computer.
//! [`SignatureScheme::level`] reports [`SecurityLevel::L1`] only because the
//! trait requires a value; that label is a classical-strength label, not a
//! post-quantum claim.

use ed25519_dalek::{Digest, Sha512, Signer, SigningKey, VerifyingKey};
use vyra_core::{EntropySource, Error, Result, SecretBytes, SecurityLevel, SignatureScheme};
use zeroize::Zeroize;

use crate::component::CompositeComponent;

/// Ed25519 (RFC 8032), deterministic signing, strict verification.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Ed25519;

impl Ed25519 {
    /// Public key length in bytes (RFC 8032 §5.1.5).
    pub const PUBLIC_KEY_LEN: usize = 32;
    /// Secret key length in bytes: the 32-byte RFC 8032 private key.
    pub const SECRET_KEY_LEN: usize = 32;
    /// Signature length in bytes (RFC 8032 §5.1.6).
    pub const SIGNATURE_LEN: usize = 64;

    /// Strict public-key validation, as used when parsing composite keys.
    ///
    /// Checks, in order:
    /// 1. length is 32 bytes;
    /// 2. the encoding decompresses to a curve point;
    /// 3. the encoding is canonical: re-compressing the point gives exactly
    ///    the input bytes (rejects `y ≥ p` and the sign-bit-set variants of
    ///    the two `x = 0` points, as RFC 8032 §5.1.3 decoding does);
    /// 4. the point is not of small order (rejects the identity and the other
    ///    7 points of the 8-torsion subgroup; consistent with `verify_strict`);
    /// 5. the point is torsion-free, i.e. in the prime-order subgroup
    ///    (`[ℓ]A = O`); rejects canonical mixed-order points `A + T` with a
    ///    non-trivial torsion component `T`. Together with 4 this means the
    ///    key is a non-identity element of the prime-order subgroup.
    ///
    /// # Errors
    ///
    /// `InvalidLength` for a wrong length; `InvalidEncoding` for each other
    /// failed check (the label names it).
    pub fn validate_public_key(public_key: &[u8]) -> Result<()> {
        let key = decode_canonical(public_key)?;
        subgroup_check(&key).map_err(Error::InvalidEncoding)
    }
}

/// The group checks of [`Ed25519::validate_public_key`] on a decoded,
/// canonical key: not small-order (in particular not the identity) and
/// torsion-free. Returns the failure label.
fn subgroup_check(key: &VerifyingKey) -> core::result::Result<(), &'static str> {
    if key.is_weak() {
        return Err("Ed25519 public key (small order)");
    }
    if !key.to_edwards().is_torsion_free() {
        return Err("Ed25519 public key (not in prime-order subgroup)");
    }
    Ok(())
}

/// Length check, decompression, and canonical re-encoding check.
fn decode_canonical(public_key: &[u8]) -> Result<VerifyingKey> {
    check_len(
        "Ed25519 public key",
        Ed25519::PUBLIC_KEY_LEN,
        public_key.len(),
    )?;
    let pk: &[u8; Ed25519::PUBLIC_KEY_LEN] = public_key
        .try_into()
        .map_err(|_| Error::Internal("Ed25519 public key length"))?;
    let key =
        VerifyingKey::from_bytes(pk).map_err(|_| Error::InvalidEncoding("Ed25519 public key"))?;
    // Public data: an ordinary comparison is fine.
    if key.to_edwards().compress().as_bytes() != pk {
        return Err(Error::InvalidEncoding("Ed25519 public key (non-canonical)"));
    }
    Ok(key)
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

/// Rebuild a dalek signing key from a 32-byte secret, zeroizing the stack copy.
fn signing_key(secret_key: &[u8]) -> Result<SigningKey> {
    check_len(
        "Ed25519 secret key",
        Ed25519::SECRET_KEY_LEN,
        secret_key.len(),
    )?;
    let mut seed: [u8; Ed25519::SECRET_KEY_LEN] = secret_key
        .try_into()
        .map_err(|_| Error::Internal("Ed25519 secret key length"))?;
    let key = SigningKey::from_bytes(&seed);
    seed.zeroize();
    Ok(key)
}

impl SignatureScheme for Ed25519 {
    fn name(&self) -> &'static str {
        "Ed25519"
    }

    /// Reports [`SecurityLevel::L1`]: ~128-bit classical security only. Ed25519
    /// offers no security against a quantum attacker.
    fn level(&self) -> SecurityLevel {
        SecurityLevel::L1
    }

    fn public_key_len(&self) -> usize {
        Self::PUBLIC_KEY_LEN
    }

    fn secret_key_len(&self) -> usize {
        Self::SECRET_KEY_LEN
    }

    fn signature_len(&self) -> usize {
        Self::SIGNATURE_LEN
    }

    fn generate_keypair(&self, rng: &mut dyn EntropySource) -> Result<(Vec<u8>, SecretBytes)> {
        let mut secret = SecretBytes::zeroed(Self::SECRET_KEY_LEN);
        rng.fill(secret.expose_mut())?;
        let key = signing_key(secret.expose())?;
        let public_key = key.verifying_key().to_bytes().to_vec();
        Ok((public_key, secret))
    }

    fn sign(
        &self,
        secret_key: &[u8],
        message: &[u8],
        _rng: &mut dyn EntropySource,
    ) -> Result<Vec<u8>> {
        let key = signing_key(secret_key)?;
        Ok(key.sign(message).to_bytes().to_vec())
    }

    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
        let (verifying_key, sig) = verify_inputs(public_key, signature)?;
        verifying_key
            .verify_strict(message, &sig)
            .map_err(|_| Error::VerificationFailed)
    }
}

/// Length checks, then the full `validate_public_key` checks, for both
/// verification paths.
///
/// Error mapping: a key that is not a well-formed encoding (not a point, or
/// non-canonical) is `InvalidEncoding`; a well-formed encoding of a point no
/// honest key can be (small-order, including the identity, or outside the
/// prime-order subgroup) is `VerificationFailed`, like any other signature
/// that does not verify.
fn verify_inputs(
    public_key: &[u8],
    signature: &[u8],
) -> Result<(VerifyingKey, ed25519_dalek::Signature)> {
    check_len(
        "Ed25519 public key",
        Ed25519::PUBLIC_KEY_LEN,
        public_key.len(),
    )?;
    check_len("Ed25519 signature", Ed25519::SIGNATURE_LEN, signature.len())?;
    let sig: &[u8; Ed25519::SIGNATURE_LEN] = signature
        .try_into()
        .map_err(|_| Error::Internal("Ed25519 signature length"))?;
    let verifying_key = decode_canonical(public_key)?;
    if subgroup_check(&verifying_key).is_err() {
        return Err(Error::VerificationFailed);
    }
    Ok((verifying_key, ed25519_dalek::Signature::from_bytes(sig)))
}

/// Maximum Ed25519ph context length (RFC 8032 §5.1).
pub const MAX_ED25519PH_CONTEXT_LEN: usize = 255;

fn check_ph_context(context: &[u8]) -> Result<()> {
    if context.len() > MAX_ED25519PH_CONTEXT_LEN {
        Err(Error::InvalidLength {
            what: "Ed25519ph context",
            expected: MAX_ED25519PH_CONTEXT_LEN,
            actual: context.len(),
        })
    } else {
        Ok(())
    }
}

/// SHA-512 state holding `message`: the Ed25519ph prehash `PH(M)`.
fn prehash(message: &[u8]) -> Sha512 {
    let mut h = Sha512::new();
    h.update(message);
    h
}

/// The composite half is **Ed25519ph** (RFC 8032 §5.1) with the composite
/// context, so it is context-bound (module docs). Public keys get the full
/// [`Ed25519::validate_public_key`] check, before verification as well.
/// Signing stays deterministic and draws no entropy.
impl CompositeComponent for Ed25519 {
    fn context_bound(&self) -> bool {
        true
    }

    fn sign_half(
        &self,
        secret_key: &[u8],
        message: &[u8],
        context: &[u8],
        _rng: &mut dyn EntropySource,
    ) -> Result<Vec<u8>> {
        check_ph_context(context)?;
        let key = signing_key(secret_key)?;
        let sig = key
            .sign_prehashed(prehash(message), Some(context))
            .map_err(|_| Error::Internal("Ed25519ph signing failed"))?;
        Ok(sig.to_bytes().to_vec())
    }

    fn verify_half(
        &self,
        public_key: &[u8],
        message: &[u8],
        context: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        check_ph_context(context)?;
        let (verifying_key, sig) = verify_inputs(public_key, signature)?;
        verifying_key
            .verify_prehashed_strict(prehash(message), Some(context), &sig)
            .map_err(|_| Error::VerificationFailed)
    }

    fn validate_public_key(&self, public_key: &[u8]) -> Result<()> {
        Ed25519::validate_public_key(public_key)
    }
}
