//! ML-KEM (FIPS 203) components over the `ml-kem` crate. ESTABLISHED.
//!
//! The primitive is used unmodified. VYRA only converts between byte strings
//! and the upstream types and checks lengths.
//!
//! # Encodings
//!
//! | item          | encoding                                                      |
//! |---------------|---------------------------------------------------------------|
//! | public key    | FIPS 203 encapsulation key `ek` (384k + 32 bytes)             |
//! | secret key    | FIPS 203 seed `d ‖ z` (64 bytes), see below                   |
//! | ciphertext    | FIPS 203 ciphertext `c`                                       |
//! | shared secret | FIPS 203 shared key `K` (32 bytes)                            |
//!
//! The secret key is the 64-byte seed `(d, z)` from which FIPS 203
//! `ML-KEM.KeyGen_internal` derives the key pair (FIPS 203 §3.3 permits storing
//! the seed in place of the expanded decapsulation key). It is the format the
//! `ml-kem` crate recommends; the expanded 1632/2400/3168-byte form is
//! deprecated upstream. A seed is always a valid key, so no decapsulation-key
//! check is needed; the key pair is re-derived on every decapsulation.
//!
//! Public keys pass the FIPS 203 §7.2 encapsulation-key check (type and
//! modulus check), which `ml-kem` performs in `EncapsulationKey::new`.

use ml_kem::kem::{Decapsulate, Encapsulate, KeyExport};
use vyra_core::{EntropySource, Error, Kem, RandCoreRng, Result, SecretBytes, SecurityLevel};
use zeroize::Zeroize;

use crate::component::ComponentKem;

/// Length of an ML-KEM secret key in VYRA: the FIPS 203 seed `d ‖ z`.
pub const ML_KEM_SEED_LEN: usize = 64;

/// Length of every ML-KEM shared secret.
pub const ML_KEM_SHARED_SECRET_LEN: usize = 32;

/// Return `InvalidLength` unless `bytes.len() == expected`.
pub(crate) fn check_len(what: &'static str, bytes: &[u8], expected: usize) -> Result<()> {
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

macro_rules! ml_kem_component {
    (
        $(#[$doc:meta])*
        $name:ident, $module:ident, $label:literal, $level:expr, pk = $pk:literal, ct = $ct:literal
    ) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
        pub struct $name;

        impl $name {
            /// Algorithm name.
            pub const NAME: &'static str = $label;
            /// Claimed NIST security category.
            pub const LEVEL: SecurityLevel = $level;
            /// Public (encapsulation) key length in bytes (FIPS 203 Table 3).
            pub const PUBLIC_KEY_LEN: usize = $pk;
            /// Secret key length in bytes: the 64-byte seed `d ‖ z`.
            pub const SECRET_KEY_LEN: usize = ML_KEM_SEED_LEN;
            /// Ciphertext length in bytes (FIPS 203 Table 3).
            pub const CIPHERTEXT_LEN: usize = $ct;
            /// Shared secret length in bytes.
            pub const SHARED_SECRET_LEN: usize = ML_KEM_SHARED_SECRET_LEN;

            /// Rebuild the upstream decapsulation key from a seed of checked length.
            fn decapsulation_key(seed_bytes: &[u8]) -> Result<ml_kem::$module::DecapsulationKey> {
                check_len(concat!($label, " secret key"), seed_bytes, ML_KEM_SEED_LEN)?;
                let mut seed = ml_kem::Seed::try_from(seed_bytes)
                    .map_err(|_| Error::Internal("ML-KEM seed conversion"))?;
                let dk = ml_kem::$module::DecapsulationKey::from_seed(seed);
                seed.as_mut_slice().zeroize();
                Ok(dk)
            }

            /// Parse a public key, running the FIPS 203 §7.2 encapsulation-key
            /// check (type check = length; modulus check in `EncapsulationKey::new`).
            fn encapsulation_key(public_key: &[u8]) -> Result<ml_kem::$module::EncapsulationKey> {
                check_len(concat!($label, " public key"), public_key, Self::PUBLIC_KEY_LEN)?;
                let encoded = ml_kem::Key::<ml_kem::$module::EncapsulationKey>::try_from(public_key)
                    .map_err(|_| Error::Internal("ML-KEM public key conversion"))?;
                ml_kem::$module::EncapsulationKey::new(&encoded).map_err(|_| {
                    Error::InvalidEncoding("ML-KEM public key failed the FIPS 203 modulus check")
                })
            }

            /// Decapsulate with an already rebuilt key.
            fn decapsulate_inner(
                dk: &ml_kem::$module::DecapsulationKey,
                ciphertext: &[u8],
            ) -> Result<SecretBytes> {
                check_len(concat!($label, " ciphertext"), ciphertext, Self::CIPHERTEXT_LEN)?;
                let ct = ml_kem::$module::Ciphertext::try_from(ciphertext)
                    .map_err(|_| Error::Internal("ML-KEM ciphertext conversion"))?;
                let mut ss = dk.decapsulate(&ct);
                let shared = SecretBytes::from_slice(ss.as_slice());
                ss.as_mut_slice().zeroize();
                Ok(shared)
            }
        }

        impl ComponentKem for $name {
            fn validate_public_key(&self, public_key: &[u8]) -> Result<()> {
                Self::encapsulation_key(public_key).map(drop)
            }

            /// Re-derives `ek` from the seed with `ML-KEM.KeyGen_internal(d, z)`.
            fn public_key_from_secret(&self, secret_key: &[u8]) -> Result<Vec<u8>> {
                let dk = Self::decapsulation_key(secret_key)?;
                Ok(dk.encapsulation_key().to_bytes().to_vec())
            }

            /// Derives the key pair once and uses it for both results.
            fn decapsulate_with_public_key(
                &self,
                secret_key: &[u8],
                ciphertext: &[u8],
            ) -> Result<(SecretBytes, Vec<u8>)> {
                check_len(concat!($label, " secret key"), secret_key, Self::SECRET_KEY_LEN)?;
                check_len(concat!($label, " ciphertext"), ciphertext, Self::CIPHERTEXT_LEN)?;
                let dk = Self::decapsulation_key(secret_key)?;
                let ss = Self::decapsulate_inner(&dk, ciphertext)?;
                Ok((ss, dk.encapsulation_key().to_bytes().to_vec()))
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
                // Same byte order as upstream key generation: d, then z.
                let mut seed = SecretBytes::zeroed(ML_KEM_SEED_LEN);
                rng.fill(seed.expose_mut())?;
                let dk = Self::decapsulation_key(seed.expose())?;
                let pk = dk.encapsulation_key().to_bytes().to_vec();
                check_len(concat!($label, " public key"), &pk, Self::PUBLIC_KEY_LEN)?;
                Ok((pk, seed))
            }

            fn encapsulate(
                &self,
                public_key: &[u8],
                rng: &mut dyn EntropySource,
            ) -> Result<(Vec<u8>, SecretBytes)> {
                let ek = Self::encapsulation_key(public_key)?;
                let mut adapter = RandCoreRng::new(rng);
                let (ct, mut ss) = ek.encapsulate_with_rng(&mut adapter);
                if let Err(e) = adapter.finish() {
                    ss.as_mut_slice().zeroize();
                    return Err(e);
                }
                let shared = SecretBytes::from_slice(ss.as_slice());
                ss.as_mut_slice().zeroize();
                Ok((ct.to_vec(), shared))
            }

            fn decapsulate(&self, secret_key: &[u8], ciphertext: &[u8]) -> Result<SecretBytes> {
                check_len(concat!($label, " secret key"), secret_key, Self::SECRET_KEY_LEN)?;
                check_len(concat!($label, " ciphertext"), ciphertext, Self::CIPHERTEXT_LEN)?;
                let dk = Self::decapsulation_key(secret_key)?;
                Self::decapsulate_inner(&dk, ciphertext)
            }
        }
    };
}

ml_kem_component!(
    /// ML-KEM-512 (FIPS 203), NIST category 1.
    MlKem512,
    ml_kem_512,
    "ML-KEM-512",
    SecurityLevel::L1,
    pk = 800,
    ct = 768
);

ml_kem_component!(
    /// ML-KEM-768 (FIPS 203), NIST category 3.
    MlKem768,
    ml_kem_768,
    "ML-KEM-768",
    SecurityLevel::L3,
    pk = 1184,
    ct = 1088
);

ml_kem_component!(
    /// ML-KEM-1024 (FIPS 203), NIST category 5.
    MlKem1024,
    ml_kem_1024,
    "ML-KEM-1024",
    SecurityLevel::L5,
    pk = 1568,
    ct = 1568
);
