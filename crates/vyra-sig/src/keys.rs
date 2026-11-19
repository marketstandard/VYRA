//! Typed composite keys and signatures with VYRA wire encodings.
//!
//! Each type carries its [`SigSuite`]. Raw encodings are fixed-length
//! concatenations (VYRA-ORIGINAL), first component (ML-DSA) first:
//!
//! | object | transition suites (2, 3, 5) | dual-PQ suites (PQ1, PQ3, PQ5) |
//! |--------|-----------------------------|--------------------------------|
//! | public key | `pk_mldsa ‖ pk_ed25519` | `pk_mldsa ‖ PK.seed ‖ PK.root` |
//! | secret key | `seed_mldsa (32) ‖ seed_ed25519 (32)` | `seed_mldsa (32) ‖ SK.seed ‖ SK.prf ‖ PK.seed (3n)` |
//! | signature  | `sig_mldsa ‖ sig_ed25519` | `sig_mldsa ‖ sig_slhdsa` |
//!
//! The wire encoding is the `vyra_core::wire` 7-byte header (object type
//! `SigPublicKey`, `SigSecretKey` or `Signature`; suite byte = suite id)
//! followed by the raw bytes, except that a secret key's payload is
//! `sk_raw ‖ check (16)` (see below). Parsing is strict: the payload must be
//! exactly the expected length.
//!
//! # Secret-key check value
//!
//! ```text
//! check = first 16 bytes of
//!         Transcript::new("VYRA-SIG-SK-v1").append([suite_id]).append(sk_raw).finalize()
//! ```
//!
//! [`CompositeSecretKey::from_bytes`] recomputes it and compares in constant
//! time. It is a **key check value**: it detects a secret key whose header was
//! relabelled with another suite id (secret keys are 64 bytes in every
//! transition suite, so the length alone cannot; dual-PQ secret keys have
//! lengths of their own, 80 / 104 / 128 bytes, and a relabelling between
//! families is already a length error) and accidental corruption of the key
//! bytes.
//! It is **not a MAC**: it has no secret key of its own, so anyone able to
//! rewrite the whole file can recompute it. It reveals nothing beyond what the
//! file already contains (it is a function of the suite id and the key bytes
//! stored next to it).
//!
//! # Parse-time public-key validation
//!
//! [`CompositePublicKey::from_raw`] and [`CompositePublicKey::from_bytes`] run
//! [`validate_public_key`], which checks exactly:
//!
//! - the raw length is [`SigSuite::public_key_len`];
//! - then each component's
//!   [`CompositeComponent::validate_public_key`](crate::CompositeComponent::validate_public_key):
//! - **ML-DSA part:** length only. FIPS 204 `pkEncode` is `ρ (32 bytes) ‖
//!   SimpleBitPack(t1, 10 bits per coefficient)`; every 32-byte `ρ` is valid
//!   and every 10-bit value `0..=1023` is a valid `t1` coefficient, so every
//!   byte string of the right length is a valid, canonical encoding
//!   (`pkDecode` then `pkEncode` is the identity; tested on random strings);
//! - **Ed25519 part** (transition suites):
//!   [`Ed25519::validate_public_key`](crate::Ed25519::validate_public_key):
//!   decompresses to a curve point, is the canonical encoding of that point,
//!   and lies in the prime-order subgroup (torsion-free and not the identity,
//!   hence not of small order and not mixed-order);
//! - **SLH-DSA part** (dual-PQ suites): length only. A FIPS 205 public key is
//!   `PK.seed ‖ PK.root`, two unstructured n-byte strings, so every byte
//!   string of the right length is a valid, canonical encoding (see
//!   [`crate::slhdsa`]; tested on random strings in two implementations).
//!
//! [`CompositeSignature::verify`](crate::CompositeSignature::verify) and
//! `verify_raw` run the same validation and report a failure as
//! `VerificationFailed`. Signatures are length-checked only; wire secret keys
//! are length-checked and carry the check value above.

use core::fmt;

use subtle::ConstantTimeEq;
use vyra_core::wire::{self, ObjectType, Reader};
use vyra_core::{Error, Result, SecretBytes, Transcript};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::suite::SigSuite;

/// Strict validation of a raw composite public key `pk_mldsa ‖ pk_second`
/// (see the [module docs](self) for exactly what is checked).
///
/// # Errors
///
/// `InvalidLength` for a wrong length; `InvalidEncoding` for an Ed25519 part
/// that is not a point, not canonical, of small order, or not in the
/// prime-order subgroup. (ML-DSA and SLH-DSA parts of the right length are
/// always valid.)
pub fn validate_public_key(suite: SigSuite, public_key: &[u8]) -> Result<()> {
    exact("composite public key", suite.public_key_len(), public_key)?;
    let (first, second) = split(public_key, suite.mldsa_public_key_len());
    suite.first().validate_public_key(first)?;
    suite.second().validate_public_key(second)
}

/// Transcript label of the secret-key check value.
pub const SECRET_KEY_CHECK_LABEL: &[u8] = b"VYRA-SIG-SK-v1";

/// Length in bytes of the secret-key check value appended to a wire secret key.
pub const SECRET_KEY_CHECK_LEN: usize = 16;

/// Compute the check value for `sk_raw` under `suite` into `out`.
fn secret_key_check(suite: SigSuite, sk_raw: &[u8], out: &mut [u8; SECRET_KEY_CHECK_LEN]) {
    let mut t = Transcript::new(SECRET_KEY_CHECK_LABEL);
    t.append(&[suite.id()]).append(sk_raw);
    let mut digest = t.finalize();
    let (head, _) = digest.split_at(SECRET_KEY_CHECK_LEN);
    out.copy_from_slice(head);
    digest.zeroize();
}

/// Wire payload length of a secret key: raw key plus check value.
fn secret_key_payload_len(suite: SigSuite) -> usize {
    suite.secret_key_len() + SECRET_KEY_CHECK_LEN
}

/// Check an exact-length raw encoding.
fn exact(what: &'static str, expected: usize, bytes: &[u8]) -> Result<()> {
    let mut r = Reader::new(bytes);
    r.take(expected, what)?;
    r.finish()
}

/// Parse a wire object of type `ty`; return its suite and exact-length payload.
fn parse<'a>(
    bytes: &'a [u8],
    ty: ObjectType,
    what: &'static str,
    len: fn(SigSuite) -> usize,
) -> Result<(SigSuite, &'a [u8])> {
    let (suite_id, payload) = wire::decode(bytes, ty)?;
    let suite = SigSuite::from_id(suite_id)?;
    let mut r = Reader::new(payload);
    let raw = r.take(len(suite), what)?;
    r.finish()?;
    Ok((suite, raw))
}

/// Split `bytes` at `mid`; `None` never happens for values built by this crate.
fn split(bytes: &[u8], mid: usize) -> (&[u8], &[u8]) {
    bytes.split_at_checked(mid).unwrap_or((bytes, &[]))
}

/// A composite public (verifying) key.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CompositePublicKey {
    suite: SigSuite,
    bytes: Vec<u8>,
}

impl CompositePublicKey {
    /// Wrap a raw `pk_mldsa ‖ pk_second` encoding for `suite`.
    ///
    /// # Errors
    ///
    /// [`vyra_core::Error::InvalidLength`] unless `bytes` is exactly
    /// [`SigSuite::public_key_len`] long; `InvalidEncoding` if
    /// [`validate_public_key`] rejects the key.
    pub fn from_raw(suite: SigSuite, bytes: &[u8]) -> Result<Self> {
        validate_public_key(suite, bytes)?;
        Ok(CompositePublicKey {
            suite,
            bytes: bytes.to_vec(),
        })
    }

    /// The suite this key belongs to.
    pub fn suite(&self) -> SigSuite {
        self.suite
    }

    /// The raw `pk_mldsa ‖ pk_second` bytes.
    pub fn as_raw(&self) -> &[u8] {
        &self.bytes
    }

    /// The ML-DSA (first) component public key.
    pub fn mldsa_part(&self) -> &[u8] {
        split(&self.bytes, self.suite.mldsa_public_key_len()).0
    }

    /// The second component public key (Ed25519 or SLH-DSA).
    pub fn second_part(&self) -> &[u8] {
        split(&self.bytes, self.suite.mldsa_public_key_len()).1
    }

    /// The Ed25519 component public key: `None` in a dual-PQ suite.
    pub fn ed25519_part(&self) -> Option<&[u8]> {
        self.suite.ed25519().map(|_| self.second_part())
    }

    /// The SLH-DSA component public key: `None` in a transition suite.
    pub fn slhdsa_part(&self) -> Option<&[u8]> {
        self.suite.slhdsa().map(|_| self.second_part())
    }

    /// Wire encoding: header (type `SigPublicKey`, suite id) ‖ raw key.
    pub fn to_bytes(&self) -> Vec<u8> {
        wire::encode(ObjectType::SigPublicKey, self.suite.id(), &self.bytes)
    }

    /// Parse a wire encoding.
    ///
    /// # Errors
    ///
    /// `InvalidLength` / `InvalidEncoding` for a bad header or a payload of the
    /// wrong length; `UnknownSuite` for an unassigned suite id.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let (suite, raw) = parse(
            bytes,
            ObjectType::SigPublicKey,
            "composite public key",
            SigSuite::public_key_len,
        )?;
        Self::from_raw(suite, raw)
    }
}

impl fmt::Debug for CompositePublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompositePublicKey")
            .field("suite", &self.suite)
            .field("len", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

/// A composite secret (signing) key: the ML-DSA seed and the second
/// component's seed (Ed25519 private key, or SLH-DSA `SK.seed ‖ SK.prf ‖
/// PK.seed`).
///
/// Zeroized on drop (it holds a [`SecretBytes`]), prints `[REDACTED]` under
/// `Debug`, and has no `PartialEq`; use [`ct_eq`](Self::ct_eq).
#[derive(Clone)]
pub struct CompositeSecretKey {
    suite: SigSuite,
    bytes: SecretBytes,
}

impl CompositeSecretKey {
    /// Wrap a raw `seed_mldsa ‖ seed_second` encoding for `suite`. The bytes
    /// are copied; the caller remains responsible for its own copy.
    ///
    /// # Errors
    ///
    /// [`vyra_core::Error::InvalidLength`] unless `bytes` is exactly
    /// [`SigSuite::secret_key_len`] long.
    pub fn from_raw(suite: SigSuite, bytes: &[u8]) -> Result<Self> {
        exact("composite secret key", suite.secret_key_len(), bytes)?;
        Ok(CompositeSecretKey {
            suite,
            bytes: SecretBytes::from_slice(bytes),
        })
    }

    /// Take ownership of raw secret bytes without copying.
    ///
    /// # Errors
    ///
    /// [`vyra_core::Error::InvalidLength`] for the wrong length (the bytes are
    /// zeroized when dropped).
    pub fn from_secret(suite: SigSuite, bytes: SecretBytes) -> Result<Self> {
        exact(
            "composite secret key",
            suite.secret_key_len(),
            bytes.expose(),
        )?;
        Ok(CompositeSecretKey { suite, bytes })
    }

    /// The suite this key belongs to.
    pub fn suite(&self) -> SigSuite {
        self.suite
    }

    /// Borrow the raw secret bytes (`seed_mldsa ‖ seed_second`).
    ///
    /// There are deliberately no accessors for the individual component
    /// seeds: component keys must never be used outside the composite.
    pub fn expose_raw(&self) -> &[u8] {
        self.bytes.expose()
    }

    /// Constant-time equality (suite ids are public and compared directly).
    pub fn ct_eq(&self, other: &CompositeSecretKey) -> bool {
        let same_suite = self.suite == other.suite;
        let same_bytes = self.bytes.ct_eq(&other.bytes);
        same_suite & same_bytes
    }

    /// Wire encoding: header (type `SigSecretKey`, suite id) ‖ raw key ‖
    /// check value (see the [module docs](self)), returned as zeroizing
    /// [`SecretBytes`].
    pub fn to_bytes(&self) -> SecretBytes {
        let mut check = [0u8; SECRET_KEY_CHECK_LEN];
        secret_key_check(self.suite, self.bytes.expose(), &mut check);
        // Exact capacity: no reallocation, so no unzeroized copy is left behind.
        let mut payload = Vec::with_capacity(secret_key_payload_len(self.suite));
        payload.extend_from_slice(self.bytes.expose());
        payload.extend_from_slice(&check);
        check.zeroize();
        let payload = SecretBytes::new(payload);
        SecretBytes::new(wire::encode(
            ObjectType::SigSecretKey,
            self.suite.id(),
            payload.expose(),
        ))
    }

    /// Parse a wire encoding and verify its check value.
    ///
    /// # Errors
    ///
    /// `InvalidLength` / `InvalidEncoding` for a bad header or a payload of the
    /// wrong length; `UnknownSuite` for an unassigned suite id;
    /// `InvalidEncoding("secret key check value mismatch")` if the check value
    /// does not match the suite id and key bytes (relabelled or corrupted).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let (suite, payload) = parse(
            bytes,
            ObjectType::SigSecretKey,
            "composite secret key",
            secret_key_payload_len,
        )?;
        let (raw, check) = payload
            .split_at_checked(suite.secret_key_len())
            .ok_or(Error::Internal("secret key split"))?;
        let mut expected = [0u8; SECRET_KEY_CHECK_LEN];
        secret_key_check(suite, raw, &mut expected);
        let ok: bool = expected.as_slice().ct_eq(check).into();
        expected.zeroize();
        if !ok {
            return Err(Error::InvalidEncoding("secret key check value mismatch"));
        }
        Self::from_raw(suite, raw)
    }
}

/// The only field holding secret data is a [`SecretBytes`], which zeroizes
/// its buffer on drop.
impl ZeroizeOnDrop for CompositeSecretKey {}

impl fmt::Debug for CompositeSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompositeSecretKey")
            .field("suite", &self.suite)
            .field("bytes", &self.bytes)
            .finish()
    }
}

/// A composite signature: `sig_mldsa ‖ sig_second`.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CompositeSig {
    suite: SigSuite,
    bytes: Vec<u8>,
}

impl CompositeSig {
    /// Wrap a raw `sig_mldsa ‖ sig_second` encoding for `suite`.
    ///
    /// # Errors
    ///
    /// [`vyra_core::Error::InvalidLength`] unless `bytes` is exactly
    /// [`SigSuite::signature_len`] long.
    pub fn from_raw(suite: SigSuite, bytes: &[u8]) -> Result<Self> {
        exact("composite signature", suite.signature_len(), bytes)?;
        Ok(CompositeSig {
            suite,
            bytes: bytes.to_vec(),
        })
    }

    /// The suite this signature claims to belong to.
    pub fn suite(&self) -> SigSuite {
        self.suite
    }

    /// The raw `sig_mldsa ‖ sig_second` bytes.
    pub fn as_raw(&self) -> &[u8] {
        &self.bytes
    }

    /// The ML-DSA (first) component signature.
    pub fn mldsa_part(&self) -> &[u8] {
        split(&self.bytes, self.suite.mldsa_signature_len()).0
    }

    /// The second component signature (Ed25519 or SLH-DSA).
    pub fn second_part(&self) -> &[u8] {
        split(&self.bytes, self.suite.mldsa_signature_len()).1
    }

    /// The Ed25519 component signature: `None` in a dual-PQ suite.
    pub fn ed25519_part(&self) -> Option<&[u8]> {
        self.suite.ed25519().map(|_| self.second_part())
    }

    /// The SLH-DSA component signature: `None` in a transition suite.
    pub fn slhdsa_part(&self) -> Option<&[u8]> {
        self.suite.slhdsa().map(|_| self.second_part())
    }

    /// Wire encoding: header (type `Signature`, suite id) ‖ raw signature.
    pub fn to_bytes(&self) -> Vec<u8> {
        wire::encode(ObjectType::Signature, self.suite.id(), &self.bytes)
    }

    /// Parse a wire encoding.
    ///
    /// # Errors
    ///
    /// `InvalidLength` / `InvalidEncoding` for a bad header or a payload of the
    /// wrong length; `UnknownSuite` for an unassigned suite id.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let (suite, raw) = parse(
            bytes,
            ObjectType::Signature,
            "composite signature",
            SigSuite::signature_len,
        )?;
        Self::from_raw(suite, raw)
    }
}

impl fmt::Debug for CompositeSig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompositeSig")
            .field("suite", &self.suite)
            .field("len", &self.bytes.len())
            .finish_non_exhaustive()
    }
}
