//! The composite signature scheme for the named suites. VYRA-ORIGINAL
//! composition of ESTABLISHED components.
//!
//! - **Sign:** derive the composite public key `pk` from the stored seeds;
//!   build `M' = message_representative(suite, pk, ctx, M)`; sign `M'` with
//!   the first component (ML-DSA, hedged, context [`composite_context`]`(id)`
//!   = `"VYRA-SIG-v1" ‖ suite_id`) and then with the second component
//!   (Ed25519 as Ed25519ph, SHA-512 prehash, under the same composite
//!   context, deterministic; or SLH-DSA, hedged, under the same composite
//!   context); output `sig_first ‖ sig_second`.
//! - **Verify:** rebuild `M'` from the given public key; run public-key
//!   validation and **both** component verifications unconditionally (no
//!   short-circuit); accept only if all accept. A failure is reported as
//!   [`Error::VerificationFailed`] without saying which component rejected.
//!
//! The same engine runs custom assemblies
//! ([`CustomComposite`](crate::CustomComposite)).
//!
//! Not the IETF LAMPS composite-signature format and not interoperable with it.

use core::fmt;

use vyra_core::{EntropySource, Error, Result, SecretBytes, SecurityLevel, SignatureScheme};

use crate::component::CompositeComponent;
use crate::keys::{CompositePublicKey, CompositeSecretKey, CompositeSig};
use crate::message::{
    composite_context, message_representative_with_digest, public_key_digest_parts,
};
use crate::suite::SigSuite;

/// A component held by an [`Engine`]: a `'static` adapter of a named suite,
/// or a caller-supplied boxed implementation.
pub(crate) enum Handle {
    Static(&'static dyn CompositeComponent),
    Owned(Box<dyn CompositeComponent>),
}

impl Handle {
    fn get(&self) -> &dyn CompositeComponent {
        match self {
            Handle::Static(c) => *c,
            Handle::Owned(c) => c.as_ref(),
        }
    }
}

/// Split `bytes` into exactly `first` and `second` bytes.
fn split_exact<'a>(
    bytes: &'a [u8],
    first: usize,
    second: usize,
    what: &'static str,
) -> Result<(&'a [u8], &'a [u8])> {
    let total = first.saturating_add(second);
    if bytes.len() != total {
        return Err(Error::InvalidLength {
            what,
            expected: total,
            actual: bytes.len(),
        });
    }
    bytes
        .split_at_checked(first)
        .ok_or(Error::Internal("composite split"))
}

/// Serves one fixed seed to a component's key generation, exactly once and
/// only for a request of exactly its length.
struct SeedSource<'a> {
    seed: &'a [u8],
    used: bool,
}

impl EntropySource for SeedSource<'_> {
    fn fill(&mut self, dest: &mut [u8]) -> Result<()> {
        if self.used || dest.len() != self.seed.len() {
            return Err(Error::Internal("seed re-derivation"));
        }
        dest.copy_from_slice(self.seed);
        self.used = true;
        Ok(())
    }
}

/// The composite algorithms over a suite id and two components.
pub(crate) struct Engine {
    id: u8,
    first: Handle,
    second: Handle,
}

impl Engine {
    pub(crate) fn new(id: u8, first: Handle, second: Handle) -> Self {
        Engine { id, first, second }
    }

    pub(crate) fn first(&self) -> &dyn CompositeComponent {
        self.first.get()
    }

    pub(crate) fn second(&self) -> &dyn CompositeComponent {
        self.second.get()
    }

    pub(crate) fn public_key_len(&self) -> usize {
        self.first()
            .public_key_len()
            .saturating_add(self.second().public_key_len())
    }

    pub(crate) fn secret_key_len(&self) -> usize {
        self.first()
            .secret_key_len()
            .saturating_add(self.second().secret_key_len())
    }

    pub(crate) fn signature_len(&self) -> usize {
        self.first()
            .signature_len()
            .saturating_add(self.second().signature_len())
    }

    /// Exact length, then each component's own public-key validation.
    pub(crate) fn validate_public_key(&self, public_key: &[u8]) -> Result<()> {
        let (pk1, pk2) = split_exact(
            public_key,
            self.first().public_key_len(),
            self.second().public_key_len(),
            "composite public key",
        )?;
        self.first().validate_public_key(pk1)?;
        self.second().validate_public_key(pk2)
    }

    pub(crate) fn generate_raw(
        &self,
        rng: &mut dyn EntropySource,
    ) -> Result<(Vec<u8>, SecretBytes)> {
        let (pk1, sk1) = self.first().generate_keypair(rng)?;
        let (pk2, sk2) = self.second().generate_keypair(rng)?;

        let mut pk = Vec::with_capacity(self.public_key_len());
        pk.extend_from_slice(&pk1);
        pk.extend_from_slice(&pk2);

        // Exact capacity: no reallocation, so no unzeroized copy is left behind.
        let mut sk = Vec::with_capacity(self.secret_key_len());
        sk.extend_from_slice(sk1.expose());
        sk.extend_from_slice(sk2.expose());
        let sk = SecretBytes::new(sk);

        if pk.len() != self.public_key_len() || sk.len() != self.secret_key_len() {
            return Err(Error::Internal("composite key length"));
        }
        Ok((pk, sk))
    }

    pub(crate) fn sign_raw(
        &self,
        secret_key: &[u8],
        message: &[u8],
        context: &[u8],
        rng: &mut dyn EntropySource,
    ) -> Result<Vec<u8>> {
        let (sk1, sk2) = split_exact(
            secret_key,
            self.first().secret_key_len(),
            self.second().secret_key_len(),
            "composite secret key",
        )?;
        // Re-derive the composite public key from the seeds; it is bound into M'.
        let (pk1, _) = self.first().generate_keypair(&mut SeedSource {
            seed: sk1,
            used: false,
        })?;
        let (pk2, _) = self.second().generate_keypair(&mut SeedSource {
            seed: sk2,
            used: false,
        })?;
        let digest = public_key_digest_parts(self.id, &pk1, &pk2);
        let m = message_representative_with_digest(self.id, &digest, context, message)?;
        let ctx = composite_context(self.id);
        let sig1 = self.first().sign_half(sk1, &m, &ctx, rng)?;
        let sig2 = self.second().sign_half(sk2, &m, &ctx, rng)?;

        let mut sig = Vec::with_capacity(self.signature_len());
        sig.extend_from_slice(&sig1);
        sig.extend_from_slice(&sig2);
        if sig.len() != self.signature_len() {
            return Err(Error::Internal("composite signature length"));
        }
        Ok(sig)
    }

    pub(crate) fn verify_raw(
        &self,
        public_key: &[u8],
        message: &[u8],
        context: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        let (pk1, pk2) = split_exact(
            public_key,
            self.first().public_key_len(),
            self.second().public_key_len(),
            "composite public key",
        )?;
        let (sig1, sig2) = split_exact(
            signature,
            self.first().signature_len(),
            self.second().signature_len(),
            "composite signature",
        )?;
        let digest = public_key_digest_parts(self.id, pk1, pk2);
        let m = message_representative_with_digest(self.id, &digest, context, message)?;
        let ctx = composite_context(self.id);

        // Strict public-key validation and both components are evaluated
        // unconditionally, then combined with a non-short-circuiting `&`.
        // Every failure is the same VerificationFailed.
        let pk_ok = self.validate_public_key(public_key).is_ok();
        let first_ok = self.first().verify_half(pk1, &m, &ctx, sig1).is_ok();
        let second_ok = self.second().verify_half(pk2, &m, &ctx, sig2).is_ok();
        if pk_ok & first_ok & second_ok {
            Ok(())
        } else {
            Err(Error::VerificationFailed)
        }
    }
}

/// A composite signature scheme for one named [`SigSuite`].
///
/// Holds its two components as `&'static` adapters obtained from
/// [`SigSuite::first`] and [`SigSuite::second`], which go through the single
/// suite → component mapping (components are stateless). The typed methods
/// ([`generate`](Self::generate), [`sign`](Self::sign),
/// [`verify`](Self::verify)) take a context string; the
/// [`SignatureScheme`] implementation works on raw bytes with an **empty**
/// context.
pub struct CompositeSignature {
    suite: SigSuite,
    engine: Engine,
}

impl fmt::Debug for CompositeSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompositeSignature")
            .field("suite", &self.suite)
            .field("first", &self.engine.first().name())
            .field("second", &self.engine.second().name())
            .finish()
    }
}

fn suite_matches(scheme: SigSuite, object: SigSuite) -> Result<()> {
    if scheme == object {
        Ok(())
    } else {
        Err(Error::InvalidEncoding("suite mismatch"))
    }
}

impl CompositeSignature {
    /// The scheme for `suite`.
    pub fn new(suite: SigSuite) -> Self {
        CompositeSignature {
            suite,
            engine: Engine::new(
                suite.id(),
                Handle::Static(suite.first()),
                Handle::Static(suite.second()),
            ),
        }
    }

    /// The suite this scheme implements.
    pub fn suite(&self) -> SigSuite {
        self.suite
    }

    /// Generate a key pair. Draws the ML-DSA seed (32 bytes) and then the
    /// second component's seed (Ed25519: 32 bytes; SLH-DSA: 3n bytes) from
    /// `rng`.
    ///
    /// # Errors
    ///
    /// [`Error::EntropyFailure`] if `rng` fails.
    pub fn generate(
        &self,
        rng: &mut dyn EntropySource,
    ) -> Result<(CompositePublicKey, CompositeSecretKey)> {
        let (pk, sk) = self.generate_raw(rng)?;
        Ok((
            CompositePublicKey::from_raw(self.suite, &pk)?,
            CompositeSecretKey::from_secret(self.suite, sk)?,
        ))
    }

    /// Sign `message` under `context` (at most 255 bytes).
    ///
    /// `rng` supplies the 32-byte ML-DSA hedging value and, in the dual-PQ
    /// suites, then the n-byte SLH-DSA `addrnd`; the Ed25519 half is
    /// deterministic.
    ///
    /// # Errors
    ///
    /// `InvalidLength` for a context longer than 255 bytes, `InvalidEncoding`
    /// if the key belongs to another suite, `EntropyFailure` if `rng` fails.
    pub fn sign(
        &self,
        secret_key: &CompositeSecretKey,
        message: &[u8],
        context: &[u8],
        rng: &mut dyn EntropySource,
    ) -> Result<CompositeSig> {
        suite_matches(self.suite, secret_key.suite())?;
        let sig = self.sign_raw(secret_key.expose_raw(), message, context, rng)?;
        CompositeSig::from_raw(self.suite, &sig)
    }

    /// Verify `signature` on `message` under `context`.
    ///
    /// Both component signatures are always checked.
    ///
    /// # Errors
    ///
    /// [`Error::VerificationFailed`] unless both components accept;
    /// `InvalidLength` for a context longer than 255 bytes; `InvalidEncoding`
    /// if the key or signature belongs to another suite. Treat any `Err` as
    /// "not verified".
    pub fn verify(
        &self,
        public_key: &CompositePublicKey,
        message: &[u8],
        context: &[u8],
        signature: &CompositeSig,
    ) -> Result<()> {
        suite_matches(self.suite, public_key.suite())?;
        suite_matches(self.suite, signature.suite())?;
        self.verify_raw(public_key.as_raw(), message, context, signature.as_raw())
    }

    /// [`generate`](Self::generate) on raw encodings.
    ///
    /// # Errors
    ///
    /// [`Error::EntropyFailure`] if `rng` fails.
    pub fn generate_raw(&self, rng: &mut dyn EntropySource) -> Result<(Vec<u8>, SecretBytes)> {
        self.engine.generate_raw(rng)
    }

    /// [`sign`](Self::sign) on a raw `seed_mldsa ‖ seed_second` secret key.
    ///
    /// # Errors
    ///
    /// `InvalidLength` for a wrong-length key or a context longer than 255
    /// bytes; `EntropyFailure` if `rng` fails.
    pub fn sign_raw(
        &self,
        secret_key: &[u8],
        message: &[u8],
        context: &[u8],
        rng: &mut dyn EntropySource,
    ) -> Result<Vec<u8>> {
        self.engine.sign_raw(secret_key, message, context, rng)
    }

    /// [`verify`](Self::verify) on raw encodings.
    ///
    /// # Errors
    ///
    /// `InvalidLength` for a wrong-length key or signature or a context longer
    /// than 255 bytes; otherwise [`Error::VerificationFailed`] unless the
    /// public key passes [`validate_public_key`](crate::validate_public_key)
    /// and both components accept.
    pub fn verify_raw(
        &self,
        public_key: &[u8],
        message: &[u8],
        context: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        self.engine
            .verify_raw(public_key, message, context, signature)
    }
}

/// Raw-bytes interface with an **empty** context string.
impl SignatureScheme for CompositeSignature {
    fn name(&self) -> &'static str {
        self.suite.name()
    }

    /// The suite's category label (see [`SigSuite`]).
    fn level(&self) -> SecurityLevel {
        self.suite.level()
    }

    fn public_key_len(&self) -> usize {
        self.suite.public_key_len()
    }

    fn secret_key_len(&self) -> usize {
        self.suite.secret_key_len()
    }

    fn signature_len(&self) -> usize {
        self.suite.signature_len()
    }

    fn generate_keypair(&self, rng: &mut dyn EntropySource) -> Result<(Vec<u8>, SecretBytes)> {
        self.generate_raw(rng)
    }

    fn sign(
        &self,
        secret_key: &[u8],
        message: &[u8],
        rng: &mut dyn EntropySource,
    ) -> Result<Vec<u8>> {
        self.sign_raw(secret_key, message, &[], rng)
    }

    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
        self.verify_raw(public_key, message, &[], signature)
    }
}
