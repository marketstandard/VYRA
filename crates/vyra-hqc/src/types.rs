//! Generic HQC-KEM types parameterized by security level.

use crate::error::Error;
use crate::params::{Buffer, HqcParams, SEED_BYTES, SS_BYTES};
use core::marker::PhantomData;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Write bytes as lowercase hex without allocating.
fn write_hex(f: &mut core::fmt::Formatter<'_>, bytes: &[u8]) -> core::fmt::Result {
    for b in bytes {
        write!(f, "{b:02x}")?;
    }
    Ok(())
}

macro_rules! from_bytes {
    ($name:ident, $buf:ty, $bytes:expr, $err:ident) => {
        impl<P: HqcParams> TryFrom<&[u8]> for $name<P> {
            type Error = Error;

            fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
                if bytes.len() != $bytes {
                    return Err(Error::$err {
                        expected: $bytes,
                        got: bytes.len(),
                    });
                }
                let mut buf = <$buf>::zeroed();
                buf.as_mut().copy_from_slice(bytes);
                Ok(Self {
                    bytes: buf,
                    _marker: PhantomData,
                })
            }
        }

        basic_bytes!($name, $bytes, $err);
    };
}

macro_rules! basic_bytes {
    ($name:ident, $bytes:expr, $err:ident) => {
        #[cfg(feature = "alloc")]
        impl<P: HqcParams> TryFrom<alloc::vec::Vec<u8>> for $name<P> {
            type Error = Error;

            fn try_from(bytes: alloc::vec::Vec<u8>) -> Result<Self, Self::Error> {
                Self::try_from(bytes.as_slice())
            }
        }

        #[cfg(feature = "alloc")]
        impl<P: HqcParams> TryFrom<&alloc::vec::Vec<u8>> for $name<P> {
            type Error = Error;

            fn try_from(bytes: &alloc::vec::Vec<u8>) -> Result<Self, Self::Error> {
                Self::try_from(bytes.as_slice())
            }
        }

        #[cfg(feature = "alloc")]
        impl<P: HqcParams> TryFrom<alloc::boxed::Box<[u8]>> for $name<P> {
            type Error = Error;

            fn try_from(bytes: alloc::boxed::Box<[u8]>) -> Result<Self, Self::Error> {
                Self::try_from(bytes.as_ref())
            }
        }

        impl<P: HqcParams> AsRef<[u8]> for $name<P> {
            fn as_ref(&self) -> &[u8] {
                self.bytes.as_ref()
            }
        }
    };
}

/// HQC encapsulation key (public key).
#[derive(Clone)]
pub struct EncapsulationKey<P: HqcParams> {
    pub(crate) bytes: P::PkBuf,
    pub(crate) _marker: PhantomData<P>,
}

/// HQC decapsulation key (secret key): the HQC v5.1 compressed format
/// `dk_KEM = seed_KEM` (32 bytes), together with the encapsulation key
/// derived from it.
#[derive(Clone)]
pub struct DecapsulationKey<P: HqcParams> {
    pub(crate) bytes: P::SkBuf,
    pub(crate) ek: EncapsulationKey<P>,
    pub(crate) _marker: PhantomData<P>,
}

/// HQC ciphertext.
#[derive(Clone)]
pub struct Ciphertext<P: HqcParams> {
    pub(crate) bytes: P::CtBuf,
    pub(crate) _marker: PhantomData<P>,
}

/// HQC shared secret.
#[derive(Clone)]
pub struct SharedSecret<P: HqcParams> {
    pub(crate) bytes: [u8; SS_BYTES],
    pub(crate) _marker: PhantomData<P>,
}

from_bytes!(
    EncapsulationKey,
    P::PkBuf,
    P::PK_BYTES,
    InvalidPublicKeySize
);
from_bytes!(Ciphertext, P::CtBuf, P::CT_BYTES, InvalidCiphertextSize);
from_bytes!(
    SharedSecret,
    [u8; SS_BYTES],
    P::SS_BYTES,
    InvalidSharedSecretSize
);

/// HQC Key Encapsulation Mechanism parameterized by security level.
///
/// Zero-sized marker type providing [`generate_key`](HqcKem::generate_key).
/// Use the type aliases [`Hqc128`](crate::Hqc128),
/// [`Hqc192`](crate::Hqc192), [`Hqc256`](crate::Hqc256).
#[derive(Debug, Clone, Copy)]
pub struct HqcKem<P: HqcParams>(PhantomData<P>);

impl<P: HqcParams> DecapsulationKey<P> {
    /// Get the encapsulation (public) key corresponding to this decapsulation key.
    pub fn encapsulation_key(&self) -> &EncapsulationKey<P> {
        &self.ek
    }
}

/// Parses the 32-byte v5.1 compressed decapsulation key `seed_KEM` and
/// derives its encapsulation key (every 32-byte string is a valid key).
#[cfg(feature = "kgen")]
impl<P: HqcParams> TryFrom<&[u8]> for DecapsulationKey<P> {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let seed: &[u8; SEED_BYTES] =
            bytes.try_into().map_err(|_| Error::InvalidSecretKeySize {
                expected: P::SK_BYTES,
                got: bytes.len(),
            })?;
        Ok(HqcKem::<P>::generate_key_deterministic(seed).1)
    }
}

#[cfg(feature = "kgen")]
basic_bytes!(DecapsulationKey, P::SK_BYTES, InvalidSecretKeySize);

// ---------------------------------------------------------------------------
// Debug
// ---------------------------------------------------------------------------

impl<P: HqcParams> core::fmt::Debug for EncapsulationKey<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{}::EncapsulationKey {{ len: {}, bytes: ",
            P::NAME,
            P::PK_BYTES
        )?;
        write_hex(f, self.bytes.as_ref())?;
        f.write_str(" }")
    }
}

impl<P: HqcParams> core::fmt::Debug for DecapsulationKey<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}::DecapsulationKey", P::NAME)
    }
}

impl<P: HqcParams> core::fmt::Debug for Ciphertext<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{}::Ciphertext {{ len: {}, bytes: ",
            P::NAME,
            P::CT_BYTES
        )?;
        write_hex(f, self.bytes.as_ref())?;
        f.write_str(" }")
    }
}

impl<P: HqcParams> core::fmt::Debug for SharedSecret<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}::SharedSecret", P::NAME)
    }
}

// ---------------------------------------------------------------------------
// PartialEq / Eq (EncapsulationKey, Ciphertext)
// ---------------------------------------------------------------------------

impl<P: HqcParams> PartialEq for EncapsulationKey<P> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes.as_ref() == other.bytes.as_ref()
    }
}

impl<P: HqcParams> Eq for EncapsulationKey<P> {}

impl<P: HqcParams> PartialEq for Ciphertext<P> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes.as_ref() == other.bytes.as_ref()
    }
}

impl<P: HqcParams> Eq for Ciphertext<P> {}

// ---------------------------------------------------------------------------
// ConstantTimeEq / PartialEq / Eq (SharedSecret only)
// ---------------------------------------------------------------------------

impl<P: HqcParams> ConstantTimeEq for SharedSecret<P> {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.bytes.as_slice().ct_eq(other.bytes.as_slice())
    }
}

impl<P: HqcParams> PartialEq for SharedSecret<P> {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl<P: HqcParams> Eq for SharedSecret<P> {}

// ---------------------------------------------------------------------------
// Zeroize + Drop (secret types)
// ---------------------------------------------------------------------------

impl<P: HqcParams> Zeroize for DecapsulationKey<P> {
    fn zeroize(&mut self) {
        self.bytes.as_mut().zeroize();
    }
}

impl<P: HqcParams> Drop for DecapsulationKey<P> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<P: HqcParams> Zeroize for SharedSecret<P> {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl<P: HqcParams> Drop for SharedSecret<P> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// ---------------------------------------------------------------------------
// KEM operations (feature-gated)
// ---------------------------------------------------------------------------

#[cfg(feature = "kgen")]
impl<P: HqcParams> HqcKem<P> {
    /// Generate an HQC key pair.
    pub fn generate_key(
        rng: &mut impl rand_core::CryptoRng,
    ) -> (EncapsulationKey<P>, DecapsulationKey<P>) {
        let (pk, sk) = crate::kem::keygen::<P>(rng);
        let ek = EncapsulationKey {
            bytes: pk.clone(),
            _marker: PhantomData,
        };
        (
            EncapsulationKey {
                bytes: pk,
                _marker: PhantomData,
            },
            DecapsulationKey {
                bytes: sk,
                ek,
                _marker: PhantomData,
            },
        )
    }

    /// Generate an HQC key pair deterministically from a 32-byte seed.
    ///
    /// The seed is `seed_KEM` of HQC v5.1 `HQC-KEM.Keygen` (the bytes the
    /// randomized key generation draws) and is also the decapsulation key.
    /// It is expanded as `XOF(seed_KEM || k/8)` to derive the PKE key pair.
    /// Identical seeds always produce identical key pairs.
    pub fn generate_key_deterministic(
        seed: &[u8; 32],
    ) -> (EncapsulationKey<P>, DecapsulationKey<P>) {
        let (pk, sk) = crate::kem::keygen_deterministic::<P>(seed);
        let ek = EncapsulationKey {
            bytes: pk.clone(),
            _marker: PhantomData,
        };
        (
            EncapsulationKey {
                bytes: pk,
                _marker: PhantomData,
            },
            DecapsulationKey {
                bytes: sk,
                ek,
                _marker: PhantomData,
            },
        )
    }
}

#[cfg(feature = "ecap")]
impl<P: HqcParams> EncapsulationKey<P> {
    /// Encapsulate: produce a ciphertext and shared secret.
    pub fn encapsulate(
        &self,
        rng: &mut impl rand_core::CryptoRng,
    ) -> (Ciphertext<P>, SharedSecret<P>) {
        let (ss, ct) = crate::kem::encaps::<P>(self.bytes.as_ref(), rng);
        (
            Ciphertext {
                bytes: ct,
                _marker: PhantomData,
            },
            SharedSecret {
                bytes: ss,
                _marker: PhantomData,
            },
        )
    }

    /// Encapsulate deterministically from a message and salt.
    ///
    /// `m` must be exactly the message size for this security level
    /// (16 bytes for HQC-128, 24 for HQC-192, 32 for HQC-256).
    /// `salt` is always 16 bytes.
    ///
    /// Identical inputs always produce identical ciphertext and shared secret.
    pub fn encapsulate_deterministic(
        &self,
        m: &[u8],
        salt: &[u8; 16],
    ) -> Result<(Ciphertext<P>, SharedSecret<P>), Error> {
        let p = P::params();
        if m.len() != p.k {
            return Err(Error::InvalidMessageSize {
                expected: p.k,
                got: m.len(),
            });
        }
        let (ss, ct) = crate::kem::encaps_deterministic::<P>(self.bytes.as_ref(), m, salt);
        Ok((
            Ciphertext {
                bytes: ct,
                _marker: PhantomData,
            },
            SharedSecret {
                bytes: ss,
                _marker: PhantomData,
            },
        ))
    }
}

#[cfg(feature = "dcap")]
impl<P: HqcParams> DecapsulationKey<P> {
    /// Decapsulate: recover shared secret from ciphertext.
    pub fn decapsulate(&self, ct: &Ciphertext<P>) -> SharedSecret<P> {
        let ss = crate::kem::decaps::<P>(self.bytes.as_ref(), ct.bytes.as_ref());
        SharedSecret {
            bytes: ss,
            _marker: PhantomData,
        }
    }
}

#[cfg(feature = "dcap")]
impl<P: HqcParams> HqcKem<P> {
    /// Decapsulate directly from the 32-byte v5.1 decapsulation key
    /// `seed_KEM`, returning the shared secret and the encapsulation key that
    /// decapsulation re-derives from the seed.
    ///
    /// Key generation runs once (inside decapsulation, as in the reference
    /// `hqc_kem_decaps`); the result equals
    /// `(DecapsulationKey::try_from(seed)?.decapsulate(ct), its encapsulation key)`.
    pub fn decapsulate_from_seed(
        seed: &[u8; SEED_BYTES],
        ct: &Ciphertext<P>,
    ) -> (SharedSecret<P>, EncapsulationKey<P>) {
        let (ss, ek) = crate::kem::decaps_with_ek::<P>(seed, ct.bytes.as_ref());
        (
            SharedSecret {
                bytes: ss,
                _marker: PhantomData,
            },
            EncapsulationKey {
                bytes: ek,
                _marker: PhantomData,
            },
        )
    }
}
