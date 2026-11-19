//! Typed hybrid keys and ciphertexts with wire encoding. VYRA-ORIGINAL format.
//!
//! Each object serializes as the `vyra_core::wire` header followed by its
//! payload:
//!
//! ```text
//! public key   "VYRA" ‖ 0x01 ‖ 0x01 ‖ suite id ‖ pk1 ‖ pk2
//! secret key   "VYRA" ‖ 0x01 ‖ 0x02 ‖ suite id ‖ sk1 ‖ sk2 ‖ check (16 bytes)
//! ciphertext   "VYRA" ‖ 0x01 ‖ 0x03 ‖ suite id ‖ ct1 ‖ ct2
//! ```
//!
//! Parsing is strict: the header must match exactly, the suite id must be
//! known, the payload must have exactly the suite's length, and public keys
//! must pass the components' checks ([`ComponentKem::validate_public_key`]).
//!
//! # Secret-key check value
//!
//! A secret key is `sk1 ‖ sk2`, the two components' key-generation seeds
//! (96 bytes for every suite). Any 96 bytes are valid seeds for any suite, so
//! length alone cannot tell suites apart. The wire form therefore appends
//!
//! ```text
//! check = first 16 bytes of SHA3-256 transcript
//!         Transcript::new("VYRA-KEM-SK-v1").append([suite_id]).append(sk1 ‖ sk2)
//! ```
//!
//! which [`HybridSecretKey::from_bytes`] recomputes and compares in constant
//! time. What it does: it detects a relabelled suite id and accidental
//! corruption of a stored key. What it does not do: it is not a MAC (it has no
//! key), so it gives no protection against anyone who can rewrite the whole
//! file, who can simply recompute it; and it reveals nothing that a holder of
//! the file does not already have, since the seeds are in the same file. The
//! raw form ([`HybridSecretKey::expose_raw`], [`HybridSecretKey::from_raw`])
//! has no check value; there the suite is carried by the typed value.

use core::fmt;

use subtle::ConstantTimeEq;
use vyra_core::wire::{self, ObjectType, Reader};
use vyra_core::{EntropySource, Error, Kem, Result, SecretBytes, Transcript};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::component::ComponentKem;
use crate::hybrid::HybridKem;
use crate::suite::KemSuite;

/// Parse a wire object of `object_type`, returning its suite and exact-length payload.
fn decode_object<'a>(
    bytes: &'a [u8],
    object_type: ObjectType,
    what: &'static str,
    raw_len: fn(KemSuite) -> usize,
) -> Result<(KemSuite, &'a [u8])> {
    let (suite_id, payload) = wire::decode(bytes, object_type)?;
    let suite = KemSuite::from_id(suite_id)?;
    let mut reader = Reader::new(payload);
    let raw = reader.take(raw_len(suite), what)?;
    reader.finish()?;
    Ok((suite, raw))
}

/// Return `InvalidLength` unless `bytes.len() == expected`.
fn require_len(what: &'static str, bytes: &[u8], expected: usize) -> Result<()> {
    if bytes.len() == expected {
        Ok(())
    } else {
        Err(Error::InvalidLength {
            what,
            expected,
            actual: bytes.len(),
        })
    }
}

/// Error for an object whose suite differs from the KEM's suite.
const SUITE_MISMATCH: Error = Error::InvalidEncoding("object suite does not match KEM suite");

/// A hybrid public (encapsulation) key, tagged with its suite.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct HybridPublicKey {
    suite: KemSuite,
    bytes: Vec<u8>,
}

impl HybridPublicKey {
    /// Wrap a raw public key `pk1 ‖ pk2` after validating both components
    /// (ML-KEM: FIPS 203 §7.2 modulus check; HQC: zero padding bits).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`] unless `raw` has the suite's public key length;
    /// [`Error::InvalidEncoding`] if a component key is non-canonical.
    pub fn from_raw(suite: KemSuite, raw: &[u8]) -> Result<Self> {
        require_len("hybrid public key", raw, suite.public_key_len())?;
        HybridKem::new(suite).validate_public_key(raw)?;
        Ok(HybridPublicKey {
            suite,
            bytes: raw.to_vec(),
        })
    }

    /// The suite this key belongs to.
    pub const fn suite(&self) -> KemSuite {
        self.suite
    }

    /// The raw public key `pk1 ‖ pk2`.
    pub fn as_raw(&self) -> &[u8] {
        &self.bytes
    }

    /// Wire encoding: header (type `KemPublicKey`) ‖ raw key.
    pub fn to_bytes(&self) -> Vec<u8> {
        wire::encode(ObjectType::KemPublicKey, self.suite.id(), &self.bytes)
    }

    /// Parse a wire-encoded public key.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`] for a short header or wrong payload length,
    /// [`Error::InvalidEncoding`] for a wrong magic, version or object type,
    /// [`Error::UnknownSuite`] for an unknown suite id.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let (suite, raw) = decode_object(
            bytes,
            ObjectType::KemPublicKey,
            "hybrid public key",
            KemSuite::public_key_len,
        )?;
        Self::from_raw(suite, raw)
    }
}

impl fmt::Debug for HybridPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HybridPublicKey")
            .field("suite", &self.suite)
            .field("len", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

/// A hybrid secret (decapsulation) key, tagged with its suite.
///
/// Zeroized on drop; `Debug` is redacted; there is deliberately no
/// `PartialEq`.
#[derive(Clone)]
pub struct HybridSecretKey {
    suite: KemSuite,
    bytes: SecretBytes,
}

impl HybridSecretKey {
    /// Wrap a raw secret key `sk1 ‖ sk2` (ML-KEM seed `d ‖ z`, HQC seed
    /// `seed_kem`).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`] unless `raw` has the suite's secret key length.
    pub fn from_raw(suite: KemSuite, raw: &[u8]) -> Result<Self> {
        require_len("hybrid secret key", raw, suite.secret_key_len())?;
        Ok(HybridSecretKey {
            suite,
            bytes: SecretBytes::from_slice(raw),
        })
    }

    /// The suite this key belongs to.
    pub const fn suite(&self) -> KemSuite {
        self.suite
    }

    /// Borrow the raw secret key `sk1 ‖ sk2`.
    pub fn expose_raw(&self) -> &[u8] {
        self.bytes.expose()
    }

    /// Wire encoding: header (type `KemSecretKey`) ‖ raw key ‖ check value
    /// (see the [module docs](self)), as zeroizing bytes.
    pub fn to_bytes(&self) -> SecretBytes {
        let raw = self.bytes.expose();
        let mut payload = Vec::with_capacity(raw.len().saturating_add(SECRET_KEY_CHECK_LEN));
        payload.extend_from_slice(raw);
        let mut check = secret_key_check(self.suite, raw);
        payload.extend_from_slice(&check);
        check.zeroize();
        let payload = SecretBytes::new(payload);
        SecretBytes::new(wire::encode(
            ObjectType::KemSecretKey,
            self.suite.id(),
            payload.expose(),
        ))
    }

    /// Parse a wire-encoded secret key and verify its check value.
    ///
    /// # Errors
    ///
    /// As [`HybridPublicKey::from_bytes`], and
    /// [`Error::InvalidEncoding`]`("secret key check value mismatch")` if the
    /// check value does not match the suite id and seeds.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let (suite, payload) = decode_object(
            bytes,
            ObjectType::KemSecretKey,
            "hybrid secret key",
            secret_key_payload_len,
        )?;
        let (raw, stored) = payload
            .split_at_checked(suite.secret_key_len())
            .ok_or(Error::Internal("secret key payload split"))?;
        let mut expected = secret_key_check(suite, raw);
        let ok: bool = expected.as_slice().ct_eq(stored).into();
        expected.zeroize();
        if !ok {
            return Err(Error::InvalidEncoding("secret key check value mismatch"));
        }
        Self::from_raw(suite, raw)
    }
}

/// Domain label of the secret-key check value.
pub const SECRET_KEY_CHECK_LABEL: &[u8] = b"VYRA-KEM-SK-v1";

/// Length of the secret-key check value in bytes.
pub const SECRET_KEY_CHECK_LEN: usize = 16;

/// Wire payload length of a secret key: raw key + check value.
fn secret_key_payload_len(suite: KemSuite) -> usize {
    suite.secret_key_len().saturating_add(SECRET_KEY_CHECK_LEN)
}

/// The first 16 bytes of
/// `Transcript::new("VYRA-KEM-SK-v1").append([suite_id]).append(raw).finalize()`.
fn secret_key_check(suite: KemSuite, raw: &[u8]) -> [u8; SECRET_KEY_CHECK_LEN] {
    let mut t = Transcript::new(SECRET_KEY_CHECK_LABEL);
    t.append(&[suite.id()]).append(raw);
    let mut digest = t.finalize();
    let mut check = [0u8; SECRET_KEY_CHECK_LEN];
    for (c, d) in check.iter_mut().zip(digest.iter()) {
        *c = *d;
    }
    digest.zeroize();
    check
}

impl ZeroizeOnDrop for HybridSecretKey {}

impl fmt::Debug for HybridSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HybridSecretKey")
            .field("suite", &self.suite)
            .field("bytes", &self.bytes)
            .finish()
    }
}

/// A hybrid ciphertext, tagged with its suite.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct HybridCiphertext {
    suite: KemSuite,
    bytes: Vec<u8>,
}

impl HybridCiphertext {
    /// Wrap a raw ciphertext `ct1 ‖ ct2`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`] unless `raw` has the suite's ciphertext length.
    pub fn from_raw(suite: KemSuite, raw: &[u8]) -> Result<Self> {
        require_len("hybrid ciphertext", raw, suite.ciphertext_len())?;
        Ok(HybridCiphertext {
            suite,
            bytes: raw.to_vec(),
        })
    }

    /// The suite this ciphertext belongs to.
    pub const fn suite(&self) -> KemSuite {
        self.suite
    }

    /// The raw ciphertext `ct1 ‖ ct2`.
    pub fn as_raw(&self) -> &[u8] {
        &self.bytes
    }

    /// Wire encoding: header (type `KemCiphertext`) ‖ raw ciphertext.
    pub fn to_bytes(&self) -> Vec<u8> {
        wire::encode(ObjectType::KemCiphertext, self.suite.id(), &self.bytes)
    }

    /// Parse a wire-encoded ciphertext.
    ///
    /// # Errors
    ///
    /// As [`HybridPublicKey::from_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let (suite, raw) = decode_object(
            bytes,
            ObjectType::KemCiphertext,
            "hybrid ciphertext",
            KemSuite::ciphertext_len,
        )?;
        Self::from_raw(suite, raw)
    }
}

impl fmt::Debug for HybridCiphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HybridCiphertext")
            .field("suite", &self.suite)
            .field("len", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

impl HybridKem {
    /// Generate a typed key pair for this KEM's suite.
    ///
    /// # Errors
    ///
    /// [`Error::EntropyFailure`] if `rng` fails.
    pub fn generate(
        &self,
        rng: &mut dyn EntropySource,
    ) -> Result<(HybridPublicKey, HybridSecretKey)> {
        let (pk, sk) = self.generate_keypair(rng)?;
        let suite = self.suite();
        require_len("hybrid public key", &pk, suite.public_key_len())?;
        require_len("hybrid secret key", sk.expose(), suite.secret_key_len())?;
        Ok((
            HybridPublicKey { suite, bytes: pk },
            HybridSecretKey { suite, bytes: sk },
        ))
    }

    /// Encapsulate to a typed public key.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidEncoding`] if `pk` belongs to another suite or a
    /// component rejects it; [`Error::EntropyFailure`] if `rng` fails.
    pub fn encapsulate_to(
        &self,
        pk: &HybridPublicKey,
        rng: &mut dyn EntropySource,
    ) -> Result<(HybridCiphertext, SecretBytes)> {
        if pk.suite != self.suite() {
            return Err(SUITE_MISMATCH);
        }
        let (ct, key) = self.encapsulate(&pk.bytes, rng)?;
        let ct = HybridCiphertext::from_raw(self.suite(), &ct)?;
        Ok((ct, key))
    }

    /// Decapsulate a typed ciphertext with a typed secret key.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidEncoding`] if `sk` or `ct` belongs to another suite.
    /// An invalid ciphertext of the right suite yields an implicit-rejection
    /// key, not an error.
    pub fn decapsulate_with(
        &self,
        sk: &HybridSecretKey,
        ct: &HybridCiphertext,
    ) -> Result<SecretBytes> {
        if sk.suite != self.suite() || ct.suite != self.suite() {
            return Err(SUITE_MISMATCH);
        }
        self.decapsulate(sk.bytes.expose(), &ct.bytes)
    }
}
