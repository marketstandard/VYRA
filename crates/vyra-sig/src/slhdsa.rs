//! SLH-DSA (FIPS 205) adapters over the `fips205` crate. ESTABLISHED.
//!
//! Parameter sets: **SLH-DSA-SHAKE-128s, -192s, -256s** (FIPS 205 Table 2,
//! the "small signature" sets). The adapters run **unmodified pure SLH-DSA**
//! (FIPS 205 Algorithm 22 `slh_sign` / Algorithm 24 `slh_verify`, not
//! HashSLH-DSA) with **hedged** signing: the n-byte `addrnd` is drawn from the
//! caller's [`EntropySource`].
//!
//! - The [`SignatureScheme`] implementation (standalone use) passes an
//!   **empty** FIPS 205 context string.
//! - [`ContextSignatureScheme`] passes a caller-chosen FIPS 205 context
//!   string (at most 255 bytes). The dual-PQ composite suites use it (through
//!   [`CompositeComponent`]) with the context `"VYRA-SIG-v1" ‖ suite_id`, so
//!   an SLH-DSA half taken out of a composite signature does not verify as a
//!   standalone empty-context SLH-DSA signature (RULES 9).
//!
//! # Why the SHAKE "s" sets
//!
//! SHAKE: the security of SLH-DSA rests only on properties of its hash
//! function, and VYRA already relies on SHA-3/SHAKE (FIPS 202) for its own
//! transcript hashing, so the dual-PQ suites add no second hash family. "s"
//! (small): signatures are about half the size of the "f" (fast) sets (7856 /
//! 16224 / 29792 bytes versus 17088 / 35664 / 49856) at the price of slower
//! signing. Signing cost is reported below; it is acceptable for the
//! long-lived, low-rate signatures (releases, certificates, archives) the
//! dual-PQ suites are meant for, and unsuitable for high-rate signing.
//!
//! # Key encodings and the secret-key form (RULES 7, D-12)
//!
//! - Public key: FIPS 205 `PK.seed ‖ PK.root` (2n bytes: 32 / 48 / 64).
//! - Secret key **as stored by VYRA: `SK.seed ‖ SK.prf ‖ PK.seed`** (3n bytes:
//!   48 / 72 / 96), i.e. exactly the key-generation randomness of FIPS 205
//!   Algorithm 21 `slh_keygen`. The standard secret key (4n bytes) also
//!   stores `PK.root`, which is public data that the other three fields
//!   determine; VYRA does not store it but recomputes it with
//!   `slh_keygen_internal` (Algorithm 18) on every signing call, so a stored
//!   copy can never disagree with the seeds. Every 3n-byte string is a valid
//!   seed triple, so no malformed secret key can reach the upstream code.
//!   Cost: one key generation (the top XMSS tree, 2^h' WOTS+ leaves) per
//!   signature. Measured in release through this adapter on the development
//!   machine (a shared, noisy machine; best of three runs): key generation
//!   about 0.13 s (128s), 0.21 s (192s), 0.15 s (256s); a whole signature,
//!   derivation included, about 1.2 s / 2.4 s / 2.1 s. The derivation adds
//!   roughly 10 % per signature, which was judged not prohibitive. (Storing
//!   the 4n-byte form and checking `PK.root` on load would cost the same key
//!   generation once per load instead.) Verification: about 1–3 ms.
//! - Signature: FIPS 205 encoding `R ‖ SIG_FORS ‖ SIG_HT` (7856 / 16224 /
//!   29792 bytes).
//!
//! # Public-key validation
//!
//! A FIPS 205 public key is two n-byte strings, `PK.seed` and `PK.root`, with
//! no further structure: `slh_verify` uses `PK.seed` as a hash input and
//! compares a recomputed root with `PK.root`. Every 2n-byte string is
//! therefore a valid public key and its own unique (canonical) encoding:
//! decoding is a split, encoding a concatenation. The length check is the
//! complete validity check (tested: decode/encode identity in both `fips205`
//! and `slh-dsa` on random strings and the all-0 / all-1 patterns).
//!
//! # Implementation choice and version evidence (RULES 4, 5, 17)
//!
//! Two pure-Rust implementations were evaluated against the official NIST
//! ACVP-Server vectors (tag `v1.1.0.43`, commit `975de31e…`,
//! `SLH-DSA-{keyGen,sigGen,sigVer}-FIPS205`, SHAKE-128s/192s/256s, external
//! pure interface): `fips205` 0.5.0 and RustCrypto `slh-dsa` 0.2.0-rc.5. Both
//! reproduced all 114 selected cases. `fips205` 0.5.0 states that it
//! "corresponds to the final released FIPS 205 (August 13, 2024)" (README) and
//! `slh-dsa` records "Implement changes from FIPS 205 Initial Public Draft ->
//! FIPS 205 Final" for 0.1.0 (CHANGELOG); both therefore target the same
//! (final) FIPS 205, and the passing official vectors (revision `FIPS205`)
//! confirm it. `fips205` is used because it is a stable release (`slh-dsa`
//! is a release candidate), documents a constant-time design for key
//! generation and signing, exposes seed-based key generation as stable public
//! API (`slh-dsa`'s `slh_keygen_internal` is `#[doc(hidden)]`, "not intended
//! for general use"), and adds fewer new dependencies. `slh-dsa` is the
//! differential partner in the tests.
//!
//! Upstream statements (quoted, not verified by VYRA):
//!
//! - `fips205-0.5.0/README.md`: "Key generation and signing are
//!   constant-time: every branch, loop bound and memory index depends only on
//!   public data" and "Verify uses only public data and makes no constant-time
//!   claim."
//! - `slh-dsa-0.2.0-rc.5/README.md`: "The implementation contained in this
//!   crate has never been independently audited!"
//!
//! # Conformance evidence (tests in `tests/`)
//!
//! `conformance_slhdsa.rs`: NIST ACVP keyGen (30 vectors, through this
//! adapter), sigGen (42 vectors, deterministic and hedged, with and without
//! context, byte-exact through this adapter: the vector's 4n-byte secret key
//! minus `PK.root` is the adapter's key, and the deterministic variant is the
//! hedged computation with `addrnd = PK.seed`), sigVer (42 vectors, adapter
//! verdict equals `testPassed`); differential tests against `slh-dsa`.
//!
//! # Randomness use
//!
//! Key generation draws exactly 3n bytes (one request). Signing draws exactly
//! n bytes (`addrnd`, one request) before calling the upstream signer.
//! Verification draws nothing.

use fips205::traits::{KeyGen, SerDes, Signer, Verifier};
use fips205::{CryptoRng, RngCore, RngError};
use vyra_core::{EntropySource, Error, Result, SecretBytes, SecurityLevel, SignatureScheme};
use zeroize::Zeroizing;

use crate::component::{CompositeComponent, ContextSignatureScheme};

/// Maximum FIPS 205 context string length in bytes.
pub const MAX_FIPS205_CONTEXT_LEN: usize = 255;

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

fn check_context(context: &[u8]) -> Result<()> {
    if context.len() > MAX_FIPS205_CONTEXT_LEN {
        Err(Error::InvalidLength {
            what: "FIPS 205 context",
            expected: MAX_FIPS205_CONTEXT_LEN,
            actual: context.len(),
        })
    } else {
        Ok(())
    }
}

/// `(SK.seed, SK.prf, PK.seed)`, each zeroized on drop.
type SeedTriple<const N: usize> = (Zeroizing<[u8; N]>, Zeroizing<[u8; N]>, Zeroizing<[u8; N]>);

/// Split a 3n-byte stored secret key into the three n-byte seeds.
fn seeds<const N: usize>(secret_key: &[u8]) -> Result<SeedTriple<N>> {
    check_len("SLH-DSA secret key", 3 * N, secret_key.len())?;
    match secret_key.as_chunks::<N>() {
        ([sk_seed, sk_prf, pk_seed], []) => Ok((
            Zeroizing::new(*sk_seed),
            Zeroizing::new(*sk_prf),
            Zeroizing::new(*pk_seed),
        )),
        _ => Err(Error::Internal("SLH-DSA seed split")),
    }
}

/// The pre-drawn `addrnd` served to the upstream hedged signer, which reads
/// exactly n bytes in one `try_fill_bytes` call. Any other use is recorded
/// (and served zeros), and the signature is then discarded by the caller.
/// Zeroized on drop.
struct AddRnd<const N: usize> {
    bytes: Zeroizing<[u8; N]>,
    used: bool,
    misused: bool,
}

impl<const N: usize> AddRnd<N> {
    fn draw(rng: &mut dyn EntropySource) -> Result<Self> {
        let mut bytes = Zeroizing::new([0u8; N]);
        rng.fill(bytes.as_mut_slice())?;
        Ok(AddRnd {
            bytes,
            used: false,
            misused: false,
        })
    }

    /// `Ok` only if the upstream signer read exactly the n bytes, once.
    fn finish(&self) -> Result<()> {
        if self.used && !self.misused {
            Ok(())
        } else {
            Err(Error::Internal("SLH-DSA randomness use"))
        }
    }
}

impl<const N: usize> RngCore for AddRnd<N> {
    fn next_u32(&mut self) -> u32 {
        self.misused = true;
        0
    }

    fn next_u64(&mut self) -> u64 {
        self.misused = true;
        0
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.misused = true;
        dest.fill(0);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), RngError> {
        if self.used || dest.len() != N {
            self.misused = true;
            dest.fill(0);
        } else {
            dest.copy_from_slice(self.bytes.as_slice());
            self.used = true;
        }
        Ok(())
    }
}

impl<const N: usize> CryptoRng for AddRnd<N> {}

macro_rules! slh_dsa {
    (
        $ty:ident, $m:ident, $name:literal, $level:expr,
        n = $n:literal, pk = $pk:literal, sig = $sig:literal, doc = $doc:literal
    ) => {
        #[doc = $doc]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
        pub struct $ty;

        impl $ty {
            /// The FIPS 205 security parameter n in bytes.
            pub const N: usize = $n;
            /// Public key length in bytes (2n, FIPS 205 Table 2).
            pub const PUBLIC_KEY_LEN: usize = $pk;
            /// Secret key length in bytes **as stored by VYRA**: 3n
            /// (`SK.seed ‖ SK.prf ‖ PK.seed`, module docs).
            pub const SECRET_KEY_LEN: usize = 3 * $n;
            /// Length of the standard FIPS 205 secret key (4n, with
            /// `PK.root`), which VYRA does not store.
            pub const STANDARD_SECRET_KEY_LEN: usize = 4 * $n;
            /// Signature length in bytes (FIPS 205 Table 2).
            pub const SIGNATURE_LEN: usize = $sig;

            /// Upstream key pair from the stored 3n-byte secret key; this
            /// recomputes `PK.root` (FIPS 205 `slh_keygen_internal`).
            fn derive(
                secret_key: &[u8],
            ) -> Result<(fips205::$m::PublicKey, fips205::$m::PrivateKey)> {
                let (sk_seed, sk_prf, pk_seed) = seeds::<{ fips205::$m::N }>(secret_key)?;
                Ok(fips205::$m::KG::keygen_from_seed(
                    &sk_seed, &sk_prf, &pk_seed,
                ))
            }

            fn sign_impl(
                secret_key: &[u8],
                message: &[u8],
                context: &[u8],
                rng: &mut dyn EntropySource,
            ) -> Result<Vec<u8>> {
                check_len("SLH-DSA secret key", Self::SECRET_KEY_LEN, secret_key.len())?;
                check_context(context)?;
                // Draw addrnd ourselves so that an entropy failure is reported
                // as such, then serve exactly those n bytes to the upstream
                // hedged signer.
                let mut addrnd = AddRnd::<{ fips205::$m::N }>::draw(rng)?;
                let (_, private) = Self::derive(secret_key)?;
                let signature = private
                    .try_sign_with_rng(&mut addrnd, message, context, true)
                    .map_err(|_| Error::Internal("SLH-DSA signing failed"))?;
                addrnd.finish()?;
                let encoded = signature.to_vec();
                check_len("SLH-DSA signature", Self::SIGNATURE_LEN, encoded.len())
                    .map_err(|_| Error::Internal("SLH-DSA signature length"))?;
                Ok(encoded)
            }

            fn verify_impl(
                public_key: &[u8],
                message: &[u8],
                context: &[u8],
                signature: &[u8],
            ) -> Result<()> {
                check_context(context)?;
                check_len("SLH-DSA public key", Self::PUBLIC_KEY_LEN, public_key.len())?;
                check_len("SLH-DSA signature", Self::SIGNATURE_LEN, signature.len())?;
                let pk = <[u8; fips205::$m::PK_LEN]>::try_from(public_key)
                    .map_err(|_| Error::Internal("SLH-DSA public key length"))?;
                let sig = <&[u8; fips205::$m::SIG_LEN]>::try_from(signature)
                    .map_err(|_| Error::Internal("SLH-DSA signature length"))?;
                // Infallible for public keys (every 2n-byte string decodes).
                let pk = fips205::$m::PublicKey::try_from_bytes(pk)
                    .map_err(|_| Error::Internal("SLH-DSA public key decode"))?;
                if pk.verify(message, sig, context) {
                    Ok(())
                } else {
                    Err(Error::VerificationFailed)
                }
            }
        }

        impl SignatureScheme for $ty {
            fn name(&self) -> &'static str {
                $name
            }

            fn level(&self) -> SecurityLevel {
                $level
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

            /// Draws `SK.seed ‖ SK.prf ‖ PK.seed` (3n bytes, one request) and
            /// returns `(PK.seed ‖ PK.root, SK.seed ‖ SK.prf ‖ PK.seed)`.
            fn generate_keypair(
                &self,
                rng: &mut dyn EntropySource,
            ) -> Result<(Vec<u8>, SecretBytes)> {
                let mut seed = SecretBytes::zeroed(Self::SECRET_KEY_LEN);
                rng.fill(seed.expose_mut())?;
                let (public, _private) = Self::derive(seed.expose())?;
                let public_key = public.into_bytes().to_vec();
                check_len("SLH-DSA public key", Self::PUBLIC_KEY_LEN, public_key.len())
                    .map_err(|_| Error::Internal("SLH-DSA public key length"))?;
                Ok((public_key, seed))
            }

            fn sign(
                &self,
                secret_key: &[u8],
                message: &[u8],
                rng: &mut dyn EntropySource,
            ) -> Result<Vec<u8>> {
                Self::sign_impl(secret_key, message, &[], rng)
            }

            fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
                Self::verify_impl(public_key, message, &[], signature)
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
                Self::sign_impl(secret_key, message, context, rng)
            }

            fn verify_with_context(
                &self,
                public_key: &[u8],
                message: &[u8],
                context: &[u8],
                signature: &[u8],
            ) -> Result<()> {
                Self::verify_impl(public_key, message, context, signature)
            }
        }

        /// Signs `M'` under the composite context; public keys are checked
        /// by length only (every 2n-byte string is a valid, canonical FIPS
        /// 205 public key: module docs).
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
                Self::sign_impl(secret_key, message, context, rng)
            }

            fn verify_half(
                &self,
                public_key: &[u8],
                message: &[u8],
                context: &[u8],
                signature: &[u8],
            ) -> Result<()> {
                Self::verify_impl(public_key, message, context, signature)
            }

            fn validate_public_key(&self, public_key: &[u8]) -> Result<()> {
                check_len("SLH-DSA public key", Self::PUBLIC_KEY_LEN, public_key.len())
            }
        }
    };
}

slh_dsa!(
    SlhDsaShake128s,
    slh_dsa_shake_128s,
    "SLH-DSA-SHAKE-128s",
    SecurityLevel::L1,
    n = 16,
    pk = 32,
    sig = 7856,
    doc = "SLH-DSA-SHAKE-128s (FIPS 205, NIST category 1)."
);
slh_dsa!(
    SlhDsaShake192s,
    slh_dsa_shake_192s,
    "SLH-DSA-SHAKE-192s",
    SecurityLevel::L3,
    n = 24,
    pk = 48,
    sig = 16224,
    doc = "SLH-DSA-SHAKE-192s (FIPS 205, NIST category 3)."
);
slh_dsa!(
    SlhDsaShake256s,
    slh_dsa_shake_256s,
    "SLH-DSA-SHAKE-256s",
    SecurityLevel::L5,
    n = 32,
    pk = 64,
    sig = 29792,
    doc = "SLH-DSA-SHAKE-256s (FIPS 205, NIST category 5)."
);
