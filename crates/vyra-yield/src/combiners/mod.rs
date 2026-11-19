//! Combiner designs under test, all assembled over the same component
//! interface ([`ComponentKem`]).
//!
//! | design | key | source |
//! |--------|-----|--------|
//! | [`Naive`](CombinerKind::Naive) | `SHA3-256(k1 ‖ k2)` | the research report's combiner (docs/DECISIONS.md D-01) |
//! | [`Xor`](CombinerKind::Xor) | `k1 ⊕ k2` | folklore XOR combiner |
//! | [`CtBound`](CombinerKind::CtBound) | `H(k1, k2, c1, c2)` | GHP18-style hash core over keys and ciphertexts; no public keys, no suite |
//! | [`XWingStyle`](CombinerKind::XWingStyle) | `H(k1, k2, c2, pk2)` | *in the style of* X-Wing: hashes only the second component's ciphertext and key. **It is not X-Wing** |
//! | [`Vyra`](CombinerKind::Vyra) | `vyra_kem::combine` | the real VYRA combiner, run through [`vyra_kem::CustomHybridKem`] (the same code as `HybridKem`) |
//!
//! `H` is SHA3-256 over [`Transcript`] framing with a design-specific label.
//! Only `Vyra` is VYRA's design; the others are comparison points built for
//! this experiment.

pub mod parallel;

pub use parallel::ParallelHybrid;

use sha3::{Digest, Sha3_256};
use vyra_core::{SecretBytes, Transcript};
use vyra_kem::{ComponentKem, CustomHybridKem, CustomSuite, KemSuite};

/// The combiner id byte under which the `Vyra` design is assembled: that of
/// VYRA-KEM-1, whose real components (ML-KEM-512, HQC-128) the failure
/// models wrap. With two real components the `Vyra` assembly is therefore
/// byte-identical to VYRA-KEM-1 (tested).
pub const VYRA_COMBINER_ID: u8 = KemSuite::Vyra1.id();

/// Descriptor of the `Vyra` custom assembly.
pub const VYRA_EXPERIMENT_SUITE: CustomSuite = CustomSuite::new(
    "VYRA combiner (custom assembly, experiment)",
    VYRA_COMBINER_ID,
);

/// Inputs available to a combiner.
#[derive(Debug, Clone, Copy)]
pub struct CombinerInputs<'a> {
    /// Component 1 shared secret.
    pub ss1: &'a [u8],
    /// Component 2 shared secret.
    pub ss2: &'a [u8],
    /// Component 1 ciphertext.
    pub ct1: &'a [u8],
    /// Component 2 ciphertext.
    pub ct2: &'a [u8],
    /// Component 1 public key.
    pub pk1: &'a [u8],
    /// Component 2 public key.
    pub pk2: &'a [u8],
}

/// A combiner design.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CombinerKind {
    /// `SHA3-256(k1 ‖ k2)`.
    Naive,
    /// `k1 ⊕ k2` (over the shorter length; both components here give 32 bytes).
    Xor,
    /// `SHA3-256(frame(label) ‖ frame(k1) ‖ frame(k2) ‖ frame(c1) ‖ frame(c2))`.
    CtBound,
    /// `SHA3-256(frame(label) ‖ frame(k1) ‖ frame(k2) ‖ frame(c2) ‖ frame(pk2))`.
    XWingStyle,
    /// The real `vyra_kem::combine` with id [`VYRA_COMBINER_ID`].
    Vyra,
}

const CTBOUND_LABEL: &[u8] = b"VYRA-YIELD-CTBOUND-v1";
const XWING_STYLE_LABEL: &[u8] = b"VYRA-YIELD-XWING-STYLE-v1";

impl CombinerKind {
    /// Every design, in report order.
    pub const ALL: [CombinerKind; 5] = [
        CombinerKind::Naive,
        CombinerKind::Xor,
        CombinerKind::CtBound,
        CombinerKind::XWingStyle,
        CombinerKind::Vyra,
    ];

    /// Short name used in reports and seeds.
    pub const fn name(self) -> &'static str {
        match self {
            CombinerKind::Naive => "Naive",
            CombinerKind::Xor => "Xor",
            CombinerKind::CtBound => "CtBound",
            CombinerKind::XWingStyle => "XWingStyle",
            CombinerKind::Vyra => "Vyra",
        }
    }

    /// One-line formula.
    pub const fn formula(self) -> &'static str {
        match self {
            CombinerKind::Naive => "SHA3-256(k1 || k2)",
            CombinerKind::Xor => "k1 XOR k2",
            CombinerKind::CtBound => "H(k1, k2, c1, c2)",
            CombinerKind::XWingStyle => "H(k1, k2, c2, pk2) (in the style of X-Wing; not X-Wing)",
            CombinerKind::Vyra => "vyra_kem::combine(suite, k1, k2, c1, c2, pk1, pk2)",
        }
    }

    /// Compute the combined key from public and component-secret inputs.
    /// Adversaries use this too: every combiner is a public function.
    pub fn combine(self, i: &CombinerInputs<'_>) -> SecretBytes {
        match self {
            CombinerKind::Naive => {
                let mut h = Sha3_256::new();
                h.update(i.ss1);
                h.update(i.ss2);
                let out: [u8; 32] = h.finalize().into();
                SecretBytes::from_slice(&out)
            }
            CombinerKind::Xor => {
                SecretBytes::new(i.ss1.iter().zip(i.ss2).map(|(a, b)| a ^ b).collect())
            }
            CombinerKind::CtBound => {
                let mut t = Transcript::new(CTBOUND_LABEL);
                t.append(i.ss1).append(i.ss2).append(i.ct1).append(i.ct2);
                SecretBytes::from_slice(&t.finalize())
            }
            CombinerKind::XWingStyle => {
                let mut t = Transcript::new(XWING_STYLE_LABEL);
                t.append(i.ss1).append(i.ss2).append(i.ct2).append(i.pk2);
                SecretBytes::from_slice(&t.finalize())
            }
            CombinerKind::Vyra => {
                vyra_kem::combine(VYRA_COMBINER_ID, i.ss1, i.ss2, i.ct1, i.ct2, i.pk1, i.pk2)
            }
        }
    }

    /// Assemble a hybrid KEM over `first` and `second` with this combiner.
    ///
    /// `Vyra` goes through [`CustomHybridKem::from_components`] (VYRA's own
    /// composition code); the other designs through [`ParallelHybrid`].
    pub fn assemble(
        self,
        first: Box<dyn ComponentKem>,
        second: Box<dyn ComponentKem>,
    ) -> Box<dyn ComponentKem> {
        match self {
            CombinerKind::Vyra => Box::new(CustomHybridKem::from_components(
                VYRA_EXPERIMENT_SUITE,
                first,
                second,
            )),
            other => Box::new(ParallelHybrid::new(other, first, second)),
        }
    }
}
