//! Composite signature suites.
//!
//! Two families, one mapping function ([`SigSuite`]'s private `components`,
//! RULES 13):
//!
//! | suite | id | first | second | category label |
//! |-------|----|-------|--------|----------------|
//! | `VYRA-SIG-2` | 0x02 | ML-DSA-44 | Ed25519 | 2 (ML-DSA only) |
//! | `VYRA-SIG-3` | 0x03 | ML-DSA-65 | Ed25519 | 3 (ML-DSA only) |
//! | `VYRA-SIG-5` | 0x05 | ML-DSA-87 | Ed25519 | 5 (ML-DSA only) |
//! | `VYRA-SIG-PQ1` | 0x11 | ML-DSA-44 | SLH-DSA-SHAKE-128s | 1 = min(2, 1) |
//! | `VYRA-SIG-PQ3` | 0x13 | ML-DSA-65 | SLH-DSA-SHAKE-192s | 3 = min(3, 3) |
//! | `VYRA-SIG-PQ5` | 0x15 | ML-DSA-87 | SLH-DSA-SHAKE-256s | 5 = min(5, 5) |

use vyra_core::wire::HEADER_LEN;
use vyra_core::{Error, Result, SecurityLevel, SignatureScheme};

use crate::component::{CompositeComponent, ContextSignatureScheme};
use crate::ed25519::Ed25519;
use crate::mldsa::{MlDsa44, MlDsa65, MlDsa87};
use crate::slhdsa::{SlhDsaShake128s, SlhDsaShake192s, SlhDsaShake256s};

/// A VYRA composite signature suite: one ML-DSA parameter set paired with a
/// second component, Ed25519 (**transition** suites) or SLH-DSA (**dual
/// post-quantum** suites). Both component signatures must verify.
///
/// # Families
///
/// - **Transition** ([`Vyra2`](Self::Vyra2), [`Vyra3`](Self::Vyra3),
///   [`Vyra5`](Self::Vyra5)): ML-DSA + Ed25519. Small (≈ 2.5–4.7 KB
///   signatures) and fast. The classical Ed25519 half is intended to keep the composite
///   unforgeable against classical attackers if ML-DSA is broken; against a
///   quantum adversary (which breaks Ed25519) security rests on ML-DSA
///   alone. For deployments that must keep a well-studied classical
///   fallback while moving to post-quantum signatures.
/// - **Dual post-quantum** ([`Pq1`](Self::Pq1), [`Pq3`](Self::Pq3),
///   [`Pq5`](Self::Pq5)): ML-DSA + SLH-DSA (SHAKE "s" sets). Two independent
///   post-quantum assumptions (module lattices; hash-function properties
///   only), so the composite is intended to stay unforgeable even against a
///   quantum adversary if one of them fails. Costs: 10–34 KB signatures and
///   about 1.3–2.7 s per signature in release (SLH-DSA "s" signing);
///   verification takes 1–3 ms. For long-lived, low-rate signatures.
///
/// # Security
///
/// - **Intended claim (not proven here):** a forger must produce valid
///   signatures from *both* components on the same message representative
///   `M'`, which binds the suite and a SHA3-256 digest of the whole composite
///   public key (see [`crate::message`]). The composite is therefore intended
///   to stay unforgeable as long as at least one component is unforgeable
///   and SHA3-256 is collision resistant. VYRA has no proof of this for its
///   concrete encoding.
/// - **Component separation:** in every suite both halves are made under the
///   composite context (ML-DSA and SLH-DSA through their context input,
///   Ed25519 as Ed25519ph with that context since U12-R1), so neither half is
///   a valid standalone default-mode signature (empty-context ML-DSA /
///   SLH-DSA, PureEd25519) on `M'`.
/// - **Component keys should never be used outside the composite** (defence
///   in depth): the claim above assumes each component key only signs
///   through the composite; a component key used elsewhere *with the VYRA
///   context* could still be made to sign values that complete composite
///   signatures.
/// - **Category labels** ([`level`](Self::level), the digit in the name):
///   for the transition suites the label describes the **ML-DSA component**
///   only (Ed25519 has no post-quantum category; pairing ML-DSA-65/87 with
///   Ed25519 is a deliberate category mismatch). For the dual-PQ suites it is
///   the **minimum** of the two components' NIST categories (ML-DSA-44 is
///   category 2, SLH-DSA-SHAKE-128s category 1, so `VYRA-SIG-PQ1` is 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum SigSuite {
    /// `VYRA-SIG-2`: ML-DSA-44 + Ed25519 (transition).
    Vyra2 = 0x02,
    /// `VYRA-SIG-3`: ML-DSA-65 + Ed25519 (transition).
    Vyra3 = 0x03,
    /// `VYRA-SIG-5`: ML-DSA-87 + Ed25519 (transition).
    Vyra5 = 0x05,
    /// `VYRA-SIG-PQ1`: ML-DSA-44 + SLH-DSA-SHAKE-128s (dual post-quantum).
    Pq1 = 0x11,
    /// `VYRA-SIG-PQ3`: ML-DSA-65 + SLH-DSA-SHAKE-192s (dual post-quantum).
    Pq3 = 0x13,
    /// `VYRA-SIG-PQ5`: ML-DSA-87 + SLH-DSA-SHAKE-256s (dual post-quantum).
    Pq5 = 0x15,
}

static MLDSA44: MlDsa44 = MlDsa44;
static MLDSA65: MlDsa65 = MlDsa65;
static MLDSA87: MlDsa87 = MlDsa87;
static ED25519: Ed25519 = Ed25519;
static SLH128S: SlhDsaShake128s = SlhDsaShake128s;
static SLH192S: SlhDsaShake192s = SlhDsaShake192s;
static SLH256S: SlhDsaShake256s = SlhDsaShake256s;

/// The ML-DSA parameter set of a suite.
#[derive(Clone, Copy)]
enum First {
    MlDsa44,
    MlDsa65,
    MlDsa87,
}

/// The second component of a suite.
#[derive(Clone, Copy)]
enum Second {
    Ed25519,
    SlhShake128s,
    SlhShake192s,
    SlhShake256s,
}

impl First {
    fn scheme(self) -> &'static dyn ContextSignatureScheme {
        match self {
            First::MlDsa44 => &MLDSA44,
            First::MlDsa65 => &MLDSA65,
            First::MlDsa87 => &MLDSA87,
        }
    }

    fn component(self) -> &'static dyn CompositeComponent {
        match self {
            First::MlDsa44 => &MLDSA44,
            First::MlDsa65 => &MLDSA65,
            First::MlDsa87 => &MLDSA87,
        }
    }

    const fn lens(self) -> (usize, usize, usize) {
        match self {
            First::MlDsa44 => (
                MlDsa44::PUBLIC_KEY_LEN,
                MlDsa44::SECRET_KEY_LEN,
                MlDsa44::SIGNATURE_LEN,
            ),
            First::MlDsa65 => (
                MlDsa65::PUBLIC_KEY_LEN,
                MlDsa65::SECRET_KEY_LEN,
                MlDsa65::SIGNATURE_LEN,
            ),
            First::MlDsa87 => (
                MlDsa87::PUBLIC_KEY_LEN,
                MlDsa87::SECRET_KEY_LEN,
                MlDsa87::SIGNATURE_LEN,
            ),
        }
    }
}

impl Second {
    fn component(self) -> &'static dyn CompositeComponent {
        match self {
            Second::Ed25519 => &ED25519,
            Second::SlhShake128s => &SLH128S,
            Second::SlhShake192s => &SLH192S,
            Second::SlhShake256s => &SLH256S,
        }
    }

    fn slhdsa(self) -> Option<&'static dyn ContextSignatureScheme> {
        match self {
            Second::Ed25519 => None,
            Second::SlhShake128s => Some(&SLH128S),
            Second::SlhShake192s => Some(&SLH192S),
            Second::SlhShake256s => Some(&SLH256S),
        }
    }

    const fn lens(self) -> (usize, usize, usize) {
        match self {
            Second::Ed25519 => (
                Ed25519::PUBLIC_KEY_LEN,
                Ed25519::SECRET_KEY_LEN,
                Ed25519::SIGNATURE_LEN,
            ),
            Second::SlhShake128s => (
                SlhDsaShake128s::PUBLIC_KEY_LEN,
                SlhDsaShake128s::SECRET_KEY_LEN,
                SlhDsaShake128s::SIGNATURE_LEN,
            ),
            Second::SlhShake192s => (
                SlhDsaShake192s::PUBLIC_KEY_LEN,
                SlhDsaShake192s::SECRET_KEY_LEN,
                SlhDsaShake192s::SIGNATURE_LEN,
            ),
            Second::SlhShake256s => (
                SlhDsaShake256s::PUBLIC_KEY_LEN,
                SlhDsaShake256s::SECRET_KEY_LEN,
                SlhDsaShake256s::SIGNATURE_LEN,
            ),
        }
    }
}

impl SigSuite {
    /// Every suite, in ascending id order: the three transition suites, then
    /// the three dual-PQ suites.
    pub const fn all() -> [SigSuite; 6] {
        [
            SigSuite::Vyra2,
            SigSuite::Vyra3,
            SigSuite::Vyra5,
            SigSuite::Pq1,
            SigSuite::Pq3,
            SigSuite::Pq5,
        ]
    }

    /// The transition suites (ML-DSA + Ed25519), ascending id order.
    pub const fn transition() -> [SigSuite; 3] {
        [SigSuite::Vyra2, SigSuite::Vyra3, SigSuite::Vyra5]
    }

    /// The dual post-quantum suites (ML-DSA + SLH-DSA), ascending id order.
    pub const fn dual_pq() -> [SigSuite; 3] {
        [SigSuite::Pq1, SigSuite::Pq3, SigSuite::Pq5]
    }

    /// Whether this is a dual post-quantum suite (second component SLH-DSA).
    pub const fn is_dual_pq(self) -> bool {
        matches!(self, SigSuite::Pq1 | SigSuite::Pq3 | SigSuite::Pq5)
    }

    /// The one-byte suite identifier used in the wire header and in the
    /// message representative.
    pub const fn id(self) -> u8 {
        self as u8
    }

    /// Parse a suite identifier.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSuite`] for any value other than 0x02, 0x03, 0x05,
    /// 0x11, 0x13 or 0x15.
    pub const fn from_id(id: u8) -> Result<Self> {
        match id {
            0x02 => Ok(SigSuite::Vyra2),
            0x03 => Ok(SigSuite::Vyra3),
            0x05 => Ok(SigSuite::Vyra5),
            0x11 => Ok(SigSuite::Pq1),
            0x13 => Ok(SigSuite::Pq3),
            0x15 => Ok(SigSuite::Pq5),
            other => Err(Error::UnknownSuite(other)),
        }
    }

    /// Suite name: `"VYRA-SIG-2"`, `"VYRA-SIG-3"`, `"VYRA-SIG-5"`,
    /// `"VYRA-SIG-PQ1"`, `"VYRA-SIG-PQ3"` or `"VYRA-SIG-PQ5"`.
    pub const fn name(self) -> &'static str {
        match self {
            SigSuite::Vyra2 => "VYRA-SIG-2",
            SigSuite::Vyra3 => "VYRA-SIG-3",
            SigSuite::Vyra5 => "VYRA-SIG-5",
            SigSuite::Pq1 => "VYRA-SIG-PQ1",
            SigSuite::Pq3 => "VYRA-SIG-PQ3",
            SigSuite::Pq5 => "VYRA-SIG-PQ5",
        }
    }

    /// The security category label (see the type documentation): the ML-DSA
    /// component's category for the transition suites (Ed25519 is
    /// classical-only), the minimum of both components' categories for the
    /// dual-PQ suites.
    pub const fn level(self) -> SecurityLevel {
        match self {
            SigSuite::Vyra2 => SecurityLevel::L2,
            SigSuite::Vyra3 | SigSuite::Pq3 => SecurityLevel::L3,
            SigSuite::Vyra5 | SigSuite::Pq5 => SecurityLevel::L5,
            SigSuite::Pq1 => SecurityLevel::L1,
        }
    }

    /// **The** suite → component mapping (RULES 13): every accessor below
    /// and every constructor of [`CompositeSignature`](crate::CompositeSignature)
    /// goes through it.
    const fn components(self) -> (First, Second) {
        match self {
            SigSuite::Vyra2 => (First::MlDsa44, Second::Ed25519),
            SigSuite::Vyra3 => (First::MlDsa65, Second::Ed25519),
            SigSuite::Vyra5 => (First::MlDsa87, Second::Ed25519),
            SigSuite::Pq1 => (First::MlDsa44, Second::SlhShake128s),
            SigSuite::Pq3 => (First::MlDsa65, Second::SlhShake192s),
            SigSuite::Pq5 => (First::MlDsa87, Second::SlhShake256s),
        }
    }

    /// The ML-DSA (first) component of this suite.
    pub fn mldsa(self) -> &'static dyn ContextSignatureScheme {
        self.components().0.scheme()
    }

    /// The Ed25519 component: `Some` for the transition suites, `None` for
    /// the dual-PQ suites.
    pub fn ed25519(self) -> Option<&'static dyn SignatureScheme> {
        match self.components().1 {
            Second::Ed25519 => Some(&ED25519),
            _ => None,
        }
    }

    /// The SLH-DSA component: `Some` for the dual-PQ suites, `None` for the
    /// transition suites.
    pub fn slhdsa(self) -> Option<&'static dyn ContextSignatureScheme> {
        self.components().1.slhdsa()
    }

    /// The first component (ML-DSA) with the composite's rules for it.
    pub fn first(self) -> &'static dyn CompositeComponent {
        self.components().0.component()
    }

    /// The second component (Ed25519 or SLH-DSA) with the composite's rules
    /// for it. Its [`name`](SignatureScheme::name) is the component name.
    pub fn second(self) -> &'static dyn CompositeComponent {
        self.components().1.component()
    }

    /// ML-DSA public key length in bytes.
    pub const fn mldsa_public_key_len(self) -> usize {
        self.components().0.lens().0
    }

    /// ML-DSA secret key length in bytes (the 32-byte seed).
    pub const fn mldsa_secret_key_len(self) -> usize {
        self.components().0.lens().1
    }

    /// ML-DSA signature length in bytes.
    pub const fn mldsa_signature_len(self) -> usize {
        self.components().0.lens().2
    }

    /// Second-component public key length in bytes (Ed25519 32; SLH-DSA 2n).
    pub const fn second_public_key_len(self) -> usize {
        self.components().1.lens().0
    }

    /// Second-component secret key length in bytes as stored (Ed25519 32;
    /// SLH-DSA 3n, see [`crate::slhdsa`]).
    pub const fn second_secret_key_len(self) -> usize {
        self.components().1.lens().1
    }

    /// Second-component signature length in bytes.
    pub const fn second_signature_len(self) -> usize {
        self.components().1.lens().2
    }

    /// Raw composite public key length: `pk_mldsa ‖ pk_second`.
    pub const fn public_key_len(self) -> usize {
        self.mldsa_public_key_len() + self.second_public_key_len()
    }

    /// Raw composite secret key length: `sk_mldsa ‖ sk_second` (seeds).
    pub const fn secret_key_len(self) -> usize {
        self.mldsa_secret_key_len() + self.second_secret_key_len()
    }

    /// Raw composite signature length: `sig_mldsa ‖ sig_second`.
    pub const fn signature_len(self) -> usize {
        self.mldsa_signature_len() + self.second_signature_len()
    }

    /// Wire-encoded public key length (header + raw key).
    pub const fn encoded_public_key_len(self) -> usize {
        HEADER_LEN + self.public_key_len()
    }

    /// Wire-encoded secret key length (header + raw key + 16-byte check
    /// value, see [`crate::keys`]): 87 bytes in every transition suite; 103,
    /// 127 and 151 bytes in `VYRA-SIG-PQ1/3/5`.
    pub const fn encoded_secret_key_len(self) -> usize {
        HEADER_LEN + self.secret_key_len() + crate::keys::SECRET_KEY_CHECK_LEN
    }

    /// Wire-encoded signature length (header + raw signature).
    pub const fn encoded_signature_len(self) -> usize {
        HEADER_LEN + self.signature_len()
    }
}

impl TryFrom<u8> for SigSuite {
    type Error = Error;

    fn try_from(id: u8) -> Result<Self> {
        SigSuite::from_id(id)
    }
}
