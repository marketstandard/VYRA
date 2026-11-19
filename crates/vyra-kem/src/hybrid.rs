//! The hybrid KEM. VYRA-ORIGINAL composition of two ESTABLISHED KEMs.
//!
//! Raw encodings (component 1 = ML-KEM, component 2 = HQC):
//!
//! ```text
//! public key  = pk1 ‖ pk2
//! secret key  = sk1 ‖ sk2
//! ciphertext  = ct1 ‖ ct2
//! shared key  = combine(suite, ss1, ss2, ct1, ct2, pk1, pk2)   (see combiner)
//! ```
//!
//! The combiner hashes both public keys. On decapsulation they are not read
//! from storage but derived from the secret keys
//! ([`ComponentKem::public_key_from_secret`]): ML-KEM re-derives `ek` from its
//! 64-byte seed `d ‖ z`, HQC re-derives its key pair from its 32-byte seed
//! `seed_kem`. Both component secret keys are key-generation seeds, so a
//! secret key cannot carry public keys that contradict it.
//!
//! Decapsulation uses implicit rejection (docs/DECISIONS.md D-02): it returns
//! `Err` only for malformed input (wrong length; every seed of the right
//! length is a valid secret key), and it always runs both component
//! decapsulations before inspecting either result.
//!
//! The composition logic lives in one private type shared by [`HybridKem`]
//! (the named suites) and [`CustomHybridKem`](crate::CustomHybridKem)
//! (caller-supplied components), so both run exactly the same code.

use core::fmt;

use vyra_core::{EntropySource, Error, Kem, Result, SecretBytes, SecurityLevel};

use crate::combiner::combine;
use crate::component::ComponentKem;
use crate::mlkem::check_len;
use crate::suite::KemSuite;

/// Hybrid ML-KEM + HQC key encapsulation for one [`KemSuite`].
///
/// Implements [`Kem`] over raw byte encodings; the typed API
/// ([`generate`](Self::generate), [`encapsulate_to`](Self::encapsulate_to),
/// [`decapsulate_with`](Self::decapsulate_with)) lives in the `keys` module.
/// The two components are held as `Box<dyn ComponentKem>`, so the composition
/// logic is independent of the concrete component algorithms.
pub struct HybridKem {
    suite: KemSuite,
    parts: Composition,
}

impl HybridKem {
    /// The hybrid KEM for `suite`.
    pub fn new(suite: KemSuite) -> Self {
        let (first, second) = suite.components();
        HybridKem {
            suite,
            parts: Composition::new(first, second),
        }
    }

    /// The suite this instance implements.
    pub const fn suite(&self) -> KemSuite {
        self.suite
    }
}

impl fmt::Debug for HybridKem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HybridKem")
            .field("suite", &self.suite)
            .field("first", &self.parts.first.name())
            .field("second", &self.parts.second.name())
            .finish()
    }
}

/// Split `bytes` at `mid`, reporting an internal error if it is too short
/// (callers check the total length first).
fn split(bytes: &[u8], mid: usize) -> Result<(&[u8], &[u8])> {
    bytes
        .split_at_checked(mid)
        .ok_or(Error::Internal("hybrid split"))
}

/// Two components and the parallel composition over them. The combiner's
/// suite input (`combiner_id`) is passed in by the owning type.
pub(crate) struct Composition {
    pub(crate) first: Box<dyn ComponentKem>,
    pub(crate) second: Box<dyn ComponentKem>,
}

impl Composition {
    pub(crate) fn new(first: Box<dyn ComponentKem>, second: Box<dyn ComponentKem>) -> Self {
        Composition { first, second }
    }

    pub(crate) fn level(&self) -> SecurityLevel {
        self.first.level().min(self.second.level())
    }

    pub(crate) fn public_key_len(&self) -> usize {
        self.first
            .public_key_len()
            .saturating_add(self.second.public_key_len())
    }

    pub(crate) fn secret_key_len(&self) -> usize {
        self.first
            .secret_key_len()
            .saturating_add(self.second.secret_key_len())
    }

    pub(crate) fn ciphertext_len(&self) -> usize {
        self.first
            .ciphertext_len()
            .saturating_add(self.second.ciphertext_len())
    }

    pub(crate) fn generate_keypair(
        &self,
        rng: &mut dyn EntropySource,
    ) -> Result<(Vec<u8>, SecretBytes)> {
        let (pk1, sk1) = self.first.generate_keypair(rng)?;
        let (pk2, sk2) = self.second.generate_keypair(rng)?;

        let mut pk = Vec::with_capacity(self.public_key_len());
        pk.extend_from_slice(&pk1);
        pk.extend_from_slice(&pk2);

        // Exact capacity: the buffer never reallocates, so no partial copy of
        // the secret is left behind in a freed allocation.
        let mut sk = Vec::with_capacity(self.secret_key_len());
        sk.extend_from_slice(sk1.expose());
        sk.extend_from_slice(sk2.expose());
        let sk = SecretBytes::new(sk);

        check_len("hybrid public key", &pk, self.public_key_len())?;
        check_len("hybrid secret key", sk.expose(), self.secret_key_len())?;
        Ok((pk, sk))
    }

    pub(crate) fn encapsulate(
        &self,
        combiner_id: u8,
        public_key: &[u8],
        rng: &mut dyn EntropySource,
    ) -> Result<(Vec<u8>, SecretBytes)> {
        check_len("hybrid public key", public_key, self.public_key_len())?;
        let (pk1, pk2) = split(public_key, self.first.public_key_len())?;

        let (ct1, ss1) = self.first.encapsulate(pk1, rng)?;
        let (ct2, ss2) = self.second.encapsulate(pk2, rng)?;
        let key = combine(
            combiner_id,
            ss1.expose(),
            ss2.expose(),
            &ct1,
            &ct2,
            pk1,
            pk2,
        );

        let mut ct = Vec::with_capacity(self.ciphertext_len());
        ct.extend_from_slice(&ct1);
        ct.extend_from_slice(&ct2);
        Ok((ct, key))
    }

    pub(crate) fn decapsulate(
        &self,
        combiner_id: u8,
        secret_key: &[u8],
        ciphertext: &[u8],
    ) -> Result<SecretBytes> {
        check_len("hybrid secret key", secret_key, self.secret_key_len())?;
        check_len("hybrid ciphertext", ciphertext, self.ciphertext_len())?;

        let (sk1, sk2) = split(secret_key, self.first.secret_key_len())?;
        let (ct1, ct2) = split(ciphertext, self.first.ciphertext_len())?;

        // Run both components unconditionally, then inspect the results.
        let r1 = self.first.decapsulate_with_public_key(sk1, ct1);
        let r2 = self.second.decapsulate_with_public_key(sk2, ct2);
        let ((ss1, pk1), (ss2, pk2)) = (r1?, r2?);

        Ok(combine(
            combiner_id,
            ss1.expose(),
            ss2.expose(),
            ct1,
            ct2,
            &pk1,
            &pk2,
        ))
    }

    pub(crate) fn validate_public_key(&self, public_key: &[u8]) -> Result<()> {
        check_len("hybrid public key", public_key, self.public_key_len())?;
        let (pk1, pk2) = split(public_key, self.first.public_key_len())?;
        let r1 = self.first.validate_public_key(pk1);
        let r2 = self.second.validate_public_key(pk2);
        r1.and(r2)
    }

    pub(crate) fn public_key_from_secret(&self, secret_key: &[u8]) -> Result<Vec<u8>> {
        check_len("hybrid secret key", secret_key, self.secret_key_len())?;
        let (sk1, sk2) = split(secret_key, self.first.secret_key_len())?;
        let pk1 = self.first.public_key_from_secret(sk1)?;
        let pk2 = self.second.public_key_from_secret(sk2)?;
        let mut pk = Vec::with_capacity(self.public_key_len());
        pk.extend_from_slice(&pk1);
        pk.extend_from_slice(&pk2);
        Ok(pk)
    }
}

impl Kem for HybridKem {
    fn name(&self) -> &'static str {
        self.suite.name()
    }

    fn level(&self) -> SecurityLevel {
        self.parts.level()
    }

    fn public_key_len(&self) -> usize {
        self.parts.public_key_len()
    }

    fn secret_key_len(&self) -> usize {
        self.parts.secret_key_len()
    }

    fn ciphertext_len(&self) -> usize {
        self.parts.ciphertext_len()
    }

    fn shared_secret_len(&self) -> usize {
        self.suite.shared_secret_len()
    }

    fn generate_keypair(&self, rng: &mut dyn EntropySource) -> Result<(Vec<u8>, SecretBytes)> {
        self.parts.generate_keypair(rng)
    }

    fn encapsulate(
        &self,
        public_key: &[u8],
        rng: &mut dyn EntropySource,
    ) -> Result<(Vec<u8>, SecretBytes)> {
        self.parts.encapsulate(self.suite.id(), public_key, rng)
    }

    /// Raw decapsulation. The raw secret key `sk1 ‖ sk2` (two seeds, 96 bytes
    /// for every suite) carries no suite: a raw key of another suite is
    /// accepted and yields an unrelated key. Use
    /// [`decapsulate_with`](HybridKem::decapsulate_with) with a typed
    /// [`HybridSecretKey`](crate::HybridSecretKey) to have the suite checked.
    fn decapsulate(&self, secret_key: &[u8], ciphertext: &[u8]) -> Result<SecretBytes> {
        self.parts
            .decapsulate(self.suite.id(), secret_key, ciphertext)
    }
}

impl ComponentKem for HybridKem {
    /// Validates both component public keys.
    fn validate_public_key(&self, public_key: &[u8]) -> Result<()> {
        self.parts.validate_public_key(public_key)
    }

    /// `pk1 ‖ pk2`, each derived from its component secret key.
    fn public_key_from_secret(&self, secret_key: &[u8]) -> Result<Vec<u8>> {
        self.parts.public_key_from_secret(secret_key)
    }
}
