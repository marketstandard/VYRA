//! Hybrid KEM suite identifiers. VYRA-ORIGINAL (the identifiers and pairing).

use core::fmt;

use vyra_core::wire::HEADER_LEN;
use vyra_core::{Error, Result, SecurityLevel};

use crate::combiner::COMBINED_SECRET_LEN;
use crate::component::ComponentKem;
use crate::hqc::{Hqc128, Hqc192, Hqc256};
use crate::keys::SECRET_KEY_CHECK_LEN;
use crate::mlkem::{MlKem512, MlKem768, MlKem1024};

/// A hybrid KEM suite: one ML-KEM and one HQC parameter set at the same NIST
/// category. The discriminant is the suite id written to the wire header and
/// hashed by the combiner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum KemSuite {
    /// VYRA-KEM-1: ML-KEM-512 + HQC-128 (NIST category 1).
    Vyra1 = 1,
    /// VYRA-KEM-3: ML-KEM-768 + HQC-192 (NIST category 3).
    Vyra3 = 3,
    /// VYRA-KEM-5: ML-KEM-1024 + HQC-256 (NIST category 5).
    Vyra5 = 5,
}

/// Raw byte sizes of a suite's two components (1 = ML-KEM, 2 = HQC).
struct ComponentSizes {
    pk1: usize,
    sk1: usize,
    ct1: usize,
    pk2: usize,
    sk2: usize,
    ct2: usize,
}

impl KemSuite {
    /// Every suite, in id order.
    pub const fn all() -> [KemSuite; 3] {
        [KemSuite::Vyra1, KemSuite::Vyra3, KemSuite::Vyra5]
    }

    /// The suite id byte.
    pub const fn id(self) -> u8 {
        self as u8
    }

    /// Parse a suite id byte.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSuite`] for an unassigned id.
    pub const fn from_id(id: u8) -> Result<Self> {
        match id {
            1 => Ok(KemSuite::Vyra1),
            3 => Ok(KemSuite::Vyra3),
            5 => Ok(KemSuite::Vyra5),
            other => Err(Error::UnknownSuite(other)),
        }
    }

    /// Suite name, e.g. `"VYRA-KEM-3"`.
    pub const fn name(self) -> &'static str {
        match self {
            KemSuite::Vyra1 => "VYRA-KEM-1",
            KemSuite::Vyra3 => "VYRA-KEM-3",
            KemSuite::Vyra5 => "VYRA-KEM-5",
        }
    }

    /// Claimed NIST category: the minimum of the two components' categories
    /// (both components of a suite claim the same category).
    pub const fn level(self) -> SecurityLevel {
        match self {
            KemSuite::Vyra1 => SecurityLevel::L1,
            KemSuite::Vyra3 => SecurityLevel::L3,
            KemSuite::Vyra5 => SecurityLevel::L5,
        }
    }

    /// Names of the two components, `(ML-KEM, HQC)`.
    pub const fn component_names(self) -> (&'static str, &'static str) {
        match self {
            KemSuite::Vyra1 => (MlKem512::NAME, Hqc128::NAME),
            KemSuite::Vyra3 => (MlKem768::NAME, Hqc192::NAME),
            KemSuite::Vyra5 => (MlKem1024::NAME, Hqc256::NAME),
        }
    }

    /// Fresh instances of the two components, `(ML-KEM, HQC)`.
    pub(crate) fn components(self) -> (Box<dyn ComponentKem>, Box<dyn ComponentKem>) {
        match self {
            KemSuite::Vyra1 => (Box::new(MlKem512), Box::new(Hqc128)),
            KemSuite::Vyra3 => (Box::new(MlKem768), Box::new(Hqc192)),
            KemSuite::Vyra5 => (Box::new(MlKem1024), Box::new(Hqc256)),
        }
    }

    const fn sizes(self) -> ComponentSizes {
        match self {
            KemSuite::Vyra1 => ComponentSizes {
                pk1: MlKem512::PUBLIC_KEY_LEN,
                sk1: MlKem512::SECRET_KEY_LEN,
                ct1: MlKem512::CIPHERTEXT_LEN,
                pk2: Hqc128::PUBLIC_KEY_LEN,
                sk2: Hqc128::SECRET_KEY_LEN,
                ct2: Hqc128::CIPHERTEXT_LEN,
            },
            KemSuite::Vyra3 => ComponentSizes {
                pk1: MlKem768::PUBLIC_KEY_LEN,
                sk1: MlKem768::SECRET_KEY_LEN,
                ct1: MlKem768::CIPHERTEXT_LEN,
                pk2: Hqc192::PUBLIC_KEY_LEN,
                sk2: Hqc192::SECRET_KEY_LEN,
                ct2: Hqc192::CIPHERTEXT_LEN,
            },
            KemSuite::Vyra5 => ComponentSizes {
                pk1: MlKem1024::PUBLIC_KEY_LEN,
                sk1: MlKem1024::SECRET_KEY_LEN,
                ct1: MlKem1024::CIPHERTEXT_LEN,
                pk2: Hqc256::PUBLIC_KEY_LEN,
                sk2: Hqc256::SECRET_KEY_LEN,
                ct2: Hqc256::CIPHERTEXT_LEN,
            },
        }
    }

    /// Raw hybrid public key length: `len(pk1) + len(pk2)`.
    pub const fn public_key_len(self) -> usize {
        let s = self.sizes();
        s.pk1 + s.pk2
    }

    /// Raw hybrid secret key length: `len(sk1) + len(sk2)`.
    pub const fn secret_key_len(self) -> usize {
        let s = self.sizes();
        s.sk1 + s.sk2
    }

    /// Raw hybrid ciphertext length: `len(ct1) + len(ct2)`.
    pub const fn ciphertext_len(self) -> usize {
        let s = self.sizes();
        s.ct1 + s.ct2
    }

    /// Hybrid shared secret length (32 bytes).
    pub const fn shared_secret_len(self) -> usize {
        COMBINED_SECRET_LEN
    }

    /// Wire-encoded public key length: header + raw public key.
    pub const fn encoded_public_key_len(self) -> usize {
        HEADER_LEN + self.public_key_len()
    }

    /// Wire-encoded secret key length: header + raw secret key + check value
    /// ([`SECRET_KEY_CHECK_LEN`] bytes).
    pub const fn encoded_secret_key_len(self) -> usize {
        HEADER_LEN + self.secret_key_len() + SECRET_KEY_CHECK_LEN
    }

    /// Wire-encoded ciphertext length: header + raw ciphertext.
    pub const fn encoded_ciphertext_len(self) -> usize {
        HEADER_LEN + self.ciphertext_len()
    }
}

impl TryFrom<u8> for KemSuite {
    type Error = Error;

    fn try_from(id: u8) -> Result<Self> {
        KemSuite::from_id(id)
    }
}

impl fmt::Display for KemSuite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}
