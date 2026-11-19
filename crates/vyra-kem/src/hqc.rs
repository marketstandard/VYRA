//! HQC components over the in-tree `vyra-hqc` crate. ESTABLISHED.
//!
//! Implemented version: the HQC v5.1 specification (version 5.1, dated
//! 2026-11-09, <https://pqc-hqc.org/doc/hqc_specifications_v5.1.pdf>) and the
//! HQC team's reference implementation at tag `v5.1.0` (commit
//! `06567ccbad10580d78dd7863b15d23f41076d57f`,
//! <https://gitlab.com/pqc-hqc/hqc>). HQC is not yet a published NIST
//! standard: FIPS 207 is unpublished, and nothing here claims conformance to
//! it.
//!
//! The implementation is `vyra-hqc`, an in-tree port of the `hqc-kem`
//! 0.1.0-rc.0 crate (which implements the reference code between the v5.0.0
//! and v5.1.0 releases) to v5.1, modified by the VYRA authors; its
//! `NOTICE.md` lists the modifications. VYRA's tests check it against all
//! official v5.1 known-answer vectors (100 per parameter set, in `vyra-hqc`
//! and again through this adapter). No second, independent
//! implementation of v5.1 was available when this was written, so the
//! conformance evidence is the official known answers only.
//!
//! The parameter-set names HQC-128/192/256 are VYRA's; the specification calls
//! them HQC-1/3/5. The NIST categories are the designers' claims.
//!
//! Public keys, ciphertexts and shared secrets are the raw byte encodings
//! defined by the HQC specification. Decapsulation uses implicit rejection.
//!
//! # Secret key: the key-generation seed
//!
//! VYRA stores only `seed_KEM`, the 32 bytes that `HQC-KEM.Keygen` draws from
//! its RNG. In HQC v5.1 this is exactly the specification's (default,
//! compressed) decapsulation key: `dk_KEM = seed_KEM` (specification
//! Section 3.7, Table 9; reference `hqc_kem_keygen`). Everything else is
//! re-derived from it on use (`seed_PKE = XOF(seed_KEM ‖ k/8)`, then the PKE
//! key pair; decapsulation also squeezes `sigma` from the same XOF), so the
//! public key, the decryption seed and the rejection secret `sigma` always
//! belong together. The official known-answer tests confirm that VYRA's
//! secret key is byte-identical to the KAT `sk`.
//!
//! # Public-key strictness (VYRA addition)
//!
//! A public key is `seed_ek (32 bytes) ‖ s`, where `s` is a vector of `n` bits
//! packed little-endian into `ceil(n / 8)` bytes (unchanged in v5.1). The bits
//! of the last byte above bit `n - 1` are always zero in honestly generated
//! keys. Neither the HQC specification nor `vyra-hqc` checks them; VYRA
//! rejects a key with any of them set
//! ([`ComponentKem::validate_public_key`]), so every accepted public key has
//! exactly one encoding. This does not affect honest keys.

use subtle::ConstantTimeEq;
use vyra_core::{EntropySource, Error, Kem, RandCoreRng, Result, SecretBytes, SecurityLevel};
use vyra_hqc::{Hqc128Params, Hqc192Params, Hqc256Params};
use zeroize::Zeroize;

use crate::component::ComponentKem;
use crate::mlkem::check_len;

/// Length of every HQC shared secret.
pub const HQC_SHARED_SECRET_LEN: usize = 32;

/// Length of an HQC secret key in VYRA: the key-generation seed `seed_kem`,
/// which is the HQC v5.1 decapsulation key `dk_KEM`.
pub const HQC_SEED_LEN: usize = 32;

/// Mask of the unused high bits in the last byte of an `n`-bit vector.
const fn padding_mask(n: usize) -> u8 {
    let used = n % 8;
    if used == 0 { 0 } else { 0xFF << used }
}

macro_rules! hqc_component {
    (
        $(#[$doc:meta])*
        $name:ident, $params:ty, $upstream:path, $label:literal, $level:expr,
        n = $n:literal, pk = $pk:literal, ct = $ct:literal
    ) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct $name;

        impl $name {
            /// Algorithm name.
            pub const NAME: &'static str = $label;
            /// Claimed NIST security category (the designers' claim).
            pub const LEVEL: SecurityLevel = $level;
            /// Public key length in bytes (HQC v5.1, specification Table 9).
            pub const PUBLIC_KEY_LEN: usize = $pk;
            /// Secret key length in bytes in VYRA: the 32-byte key-generation
            /// seed `seed_kem`, equal to the HQC v5.1 `dk_KEM`.
            pub const SECRET_KEY_LEN: usize = HQC_SEED_LEN;
            /// Ciphertext length in bytes (HQC v5.1, specification Table 9).
            pub const CIPHERTEXT_LEN: usize = $ct;
            /// Shared secret length in bytes.
            pub const SHARED_SECRET_LEN: usize = HQC_SHARED_SECRET_LEN;
            /// Ring dimension `n`: the public vector `s` has `n` bits.
            pub const N: usize = $n;
            /// Bits of the last public-key byte above bit `n - 1` (must be zero).
            pub const PUBLIC_KEY_PADDING_MASK: u8 = padding_mask($n);

            /// Length and canonical-encoding check of a public key.
            fn check_public_key(public_key: &[u8]) -> Result<()> {
                check_len(concat!($label, " public key"), public_key, Self::PUBLIC_KEY_LEN)?;
                match public_key.last() {
                    Some(last) if last & Self::PUBLIC_KEY_PADDING_MASK == 0 => Ok(()),
                    _ => Err(Error::InvalidEncoding(concat!(
                        $label,
                        " public key has padding bits set"
                    ))),
                }
            }

            /// Derive the key pair from a seed of checked length, exactly as
            /// the reference key generation does after drawing the seed.
            fn expand(
                seed_bytes: &[u8],
            ) -> Result<(
                vyra_hqc::EncapsulationKey<$params>,
                vyra_hqc::DecapsulationKey<$params>,
            )> {
                check_len(concat!($label, " secret key"), seed_bytes, HQC_SEED_LEN)?;
                let mut seed: [u8; HQC_SEED_LEN] = seed_bytes
                    .try_into()
                    .map_err(|_| Error::Internal("HQC seed conversion"))?;
                // `dk` (the seed) zeroizes itself on drop.
                let pair = <$upstream>::generate_key_deterministic(&seed);
                seed.zeroize();
                Ok(pair)
            }

            /// Decapsulate from the seed; returns the shared secret and the
            /// public key that decapsulation re-derives (key generation runs
            /// once, inside the reference decapsulation).
            fn decapsulate_inner(
                secret_key: &[u8],
                ciphertext: &[u8],
            ) -> Result<(SecretBytes, Vec<u8>)> {
                check_len(concat!($label, " secret key"), secret_key, HQC_SEED_LEN)?;
                check_len(concat!($label, " ciphertext"), ciphertext, Self::CIPHERTEXT_LEN)?;
                let ct = vyra_hqc::Ciphertext::<$params>::try_from(ciphertext)
                    .map_err(|_| Error::InvalidEncoding(concat!($label, " ciphertext")))?;
                let mut seed: [u8; HQC_SEED_LEN] = secret_key
                    .try_into()
                    .map_err(|_| Error::Internal("HQC seed conversion"))?;
                // `ss` zeroizes itself on drop.
                let (ss, ek) = <$upstream>::decapsulate_from_seed(&seed, &ct);
                seed.zeroize();
                Ok((SecretBytes::from_slice(ss.as_ref()), ek.as_ref().to_vec()))
            }
        }

        impl ComponentKem for $name {
            fn validate_public_key(&self, public_key: &[u8]) -> Result<()> {
                Self::check_public_key(public_key)
            }

            /// Re-derives the key pair from the seed and returns its public key.
            fn public_key_from_secret(&self, secret_key: &[u8]) -> Result<Vec<u8>> {
                let (ek, _dk) = Self::expand(secret_key)?;
                Ok(ek.as_ref().to_vec())
            }

            /// Derives the key pair once, inside decapsulation, and returns
            /// the public key it re-derived.
            fn decapsulate_with_public_key(
                &self,
                secret_key: &[u8],
                ciphertext: &[u8],
            ) -> Result<(SecretBytes, Vec<u8>)> {
                Self::decapsulate_inner(secret_key, ciphertext)
            }
        }

        impl Kem for $name {
            fn name(&self) -> &'static str {
                Self::NAME
            }

            fn level(&self) -> SecurityLevel {
                Self::LEVEL
            }

            fn public_key_len(&self) -> usize {
                Self::PUBLIC_KEY_LEN
            }

            fn secret_key_len(&self) -> usize {
                Self::SECRET_KEY_LEN
            }

            fn ciphertext_len(&self) -> usize {
                Self::CIPHERTEXT_LEN
            }

            fn shared_secret_len(&self) -> usize {
                Self::SHARED_SECRET_LEN
            }

            fn generate_keypair(
                &self,
                rng: &mut dyn EntropySource,
            ) -> Result<(Vec<u8>, SecretBytes)> {
                // The reference key generation draws exactly this seed (one
                // 32-byte request) and derives everything else from it.
                let mut seed = SecretBytes::zeroed(HQC_SEED_LEN);
                rng.fill(seed.expose_mut())?;
                let (ek, dk) = Self::expand(seed.expose())?;
                let pk = ek.as_ref().to_vec();
                check_len(concat!($label, " public key"), &pk, Self::PUBLIC_KEY_LEN)?;
                // v5.1: the decapsulation key is the seed itself.
                if !bool::from(dk.as_ref().ct_eq(seed.expose())) {
                    return Err(Error::Internal("HQC dk is not the seed"));
                }
                Ok((pk, seed))
            }

            fn encapsulate(
                &self,
                public_key: &[u8],
                rng: &mut dyn EntropySource,
            ) -> Result<(Vec<u8>, SecretBytes)> {
                Self::check_public_key(public_key)?;
                let ek = vyra_hqc::EncapsulationKey::<$params>::try_from(public_key)
                    .map_err(|_| Error::InvalidEncoding(concat!($label, " public key")))?;
                let mut adapter = RandCoreRng::new(rng);
                // `ss` zeroizes itself on drop, including on the error path.
                // The draws are m (k bytes) then salt (16 bytes), two requests.
                let (ct, ss) = ek.encapsulate(&mut adapter);
                adapter.finish()?;
                Ok((ct.as_ref().to_vec(), SecretBytes::from_slice(ss.as_ref())))
            }

            fn decapsulate(&self, secret_key: &[u8], ciphertext: &[u8]) -> Result<SecretBytes> {
                Self::decapsulate_inner(secret_key, ciphertext).map(|(ss, _pk)| ss)
            }
        }
    };
}

hqc_component!(
    /// HQC-128: HQC-1 of the HQC v5.1 specification (reference tag v5.1.0),
    /// NIST category 1 (designers' claim).
    Hqc128,
    Hqc128Params,
    vyra_hqc::Hqc128,
    "HQC-128",
    SecurityLevel::L1,
    n = 17669,
    pk = 2241,
    ct = 4433
);

hqc_component!(
    /// HQC-192: HQC-3 of the HQC v5.1 specification (reference tag v5.1.0),
    /// NIST category 3 (designers' claim).
    Hqc192,
    Hqc192Params,
    vyra_hqc::Hqc192,
    "HQC-192",
    SecurityLevel::L3,
    n = 35851,
    pk = 4514,
    ct = 8978
);

hqc_component!(
    /// HQC-256: HQC-5 of the HQC v5.1 specification (reference tag v5.1.0),
    /// NIST category 5 (designers' claim).
    Hqc256,
    Hqc256Params,
    vyra_hqc::Hqc256,
    "HQC-256",
    SecurityLevel::L5,
    n = 57637,
    pk = 7237,
    ct = 14421
);
