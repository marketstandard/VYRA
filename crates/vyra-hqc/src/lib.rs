//! Pure Rust implementation of HQC-KEM, HQC specification version 5.1
//! (2026-11-09), as an in-tree port for VYRA.
//!
//! This crate is derived from `hqc-kem` 0.1.0-rc.0 (RustCrypto, MIT OR
//! Apache-2.0), which implements the HQC reference code between the v5.0.0
//! and v5.1.0 releases, and is modified by the VYRA authors to the HQC v5.1
//! specification and the reference implementation tag `v5.1.0` (commit
//! `06567ccbad10580d78dd7863b15d23f41076d57f`,
//! <https://gitlab.com/pqc-hqc/hqc>). It reproduces all 100 official v5.1
//! known-answer vectors of each parameter set (see `tests/kat.rs` and
//! `NOTICE.md`). HQC is not yet a published NIST standard (FIPS 207 is
//! pending); this crate does not claim conformance to FIPS 207.
//!
//! HQC is a code-based Key Encapsulation Mechanism using quasi-cyclic codes
//! over the ring Z_2\[X\]/(X^n-1). Uses concatenated Reed-Solomon + Reed-Muller
//! error correction with Fujisaki-Okamoto transform for IND-CCA2 security.
//!
//! # Usage
//!
//! ```rust
//! # #[cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]
//! # {
//! use vyra_hqc::{Hqc128, HqcKem};
//!
//! let (ek, dk) = Hqc128::generate_key_deterministic(&[7u8; 32]);
//! let (ct, ss1) = ek
//!     .encapsulate_deterministic(&[1u8; 16], &[2u8; 16])
//!     .expect("16-byte message for HQC-1");
//! let ss2 = dk.decapsulate(&ct);
//! assert_eq!(ss1, ss2);
//! # }
//! ```
//!
//! # Parameter sets
//!
//! The specification names them HQC-1, HQC-3 and HQC-5; this crate keeps the
//! upstream names. The NIST categories are the designers' claims.
//!
//! - [`Hqc128`] / [`hqc128`]: HQC-1, NIST category 1
//! - [`Hqc192`] / [`hqc192`]: HQC-3, NIST category 3
//! - [`Hqc256`] / [`hqc256`]: HQC-5, NIST category 5
//!
//! # Features
//!
//! - `kgen`: Key generation (default)
//! - `ecap`: Encapsulation (default)
//! - `dcap`: Decapsulation (default)
//! - `alloc`: `Vec`/`Box` conversions
//! - `std`: Standard library (default)
//! - `bitserial-mul`: multiplier-free carry-less word multiply. The default
//!   kernel is built from integer multiplications and is constant time only if
//!   the CPU's 64x64->128-bit integer multiplier is (true on current x86-64 and
//!   AArch64 cores, NOT guaranteed on all targets). On every other target
//!   architecture the multiplier-free kernel is selected automatically; this
//!   feature forces it on x86-64 and AArch64 too. Slower.
//!
//! The core KEM (`kgen`/`ecap`/`dcap`) is `no_std` and performs no heap
//! allocation. The upstream `kem`, `pkcs8`, `pem` and `serde` features are
//! not carried over (see `NOTICE.md`).

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

#[cfg(any(feature = "kgen", feature = "ecap", feature = "dcap"))]
mod code;
mod error;
#[cfg(any(feature = "kgen", feature = "ecap", feature = "dcap"))]
mod gf256;
#[cfg(any(feature = "kgen", feature = "ecap", feature = "dcap"))]
mod kem;
mod params;
#[cfg(any(feature = "kgen", feature = "ecap", feature = "dcap"))]
mod pke;
#[cfg(any(feature = "kgen", feature = "ecap", feature = "dcap"))]
mod poly;
#[cfg(any(feature = "kgen", feature = "ecap", feature = "dcap"))]
mod reed_muller;
#[cfg(any(feature = "kgen", feature = "ecap", feature = "dcap"))]
mod reed_solomon;
#[cfg(any(feature = "kgen", feature = "ecap", feature = "dcap"))]
mod sampling;
#[cfg(any(feature = "kgen", feature = "ecap", feature = "dcap"))]
mod shake;
mod types;

/// The HQC version this crate implements: specification version and date,
/// reference implementation tag and commit.
pub const HQC_VERSION: &str = "HQC v5.1 (specification 2026-11-09); reference tag v5.1.0, commit 06567ccbad10580d78dd7863b15d23f41076d57f";

pub use error::Error;
pub use params::{Hqc128Params, Hqc192Params, Hqc256Params, HqcParams};
pub use types::{Ciphertext, DecapsulationKey, EncapsulationKey, HqcKem, SharedSecret};

/// HQC-1 KEM (VYRA name HQC-128; designers' claim: NIST category 1).
pub type Hqc128 = HqcKem<Hqc128Params>;
/// HQC-3 KEM (VYRA name HQC-192; designers' claim: NIST category 3).
pub type Hqc192 = HqcKem<Hqc192Params>;
/// HQC-5 KEM (VYRA name HQC-256; designers' claim: NIST category 5).
pub type Hqc256 = HqcKem<Hqc256Params>;

/// HQC-1 (HQC-128) sizes and helpers (HQC v5.1, specification Table 9).
pub mod hqc128 {
    /// Public key size in bytes.
    pub const PUBLIC_KEY_SIZE: usize = 2241;
    /// Secret key size in bytes (v5.1 compressed `dk_KEM = seed_KEM`).
    pub const SECRET_KEY_SIZE: usize = 32;
    /// Ciphertext size in bytes.
    pub const CIPHERTEXT_SIZE: usize = 4433;
    /// Shared secret size in bytes.
    pub const SHARED_SECRET_SIZE: usize = crate::params::SS_BYTES;
    /// Message size in bytes (for deterministic encapsulation).
    pub const MESSAGE_SIZE: usize = 16;
    /// Salt size in bytes (for deterministic encapsulation).
    pub const SALT_SIZE: usize = crate::params::SALT_BYTES;

    /// HQC-128 encapsulation key.
    pub type EncapsulationKey = crate::EncapsulationKey<crate::Hqc128Params>;
    /// HQC-128 decapsulation key.
    pub type DecapsulationKey = crate::DecapsulationKey<crate::Hqc128Params>;
    /// HQC-128 ciphertext.
    pub type Ciphertext = crate::Ciphertext<crate::Hqc128Params>;
    /// HQC-128 shared secret.
    pub type SharedSecret = crate::SharedSecret<crate::Hqc128Params>;

    /// Generate an HQC-128 key pair.
    #[cfg(feature = "kgen")]
    pub fn generate_key(
        rng: &mut impl rand_core::CryptoRng,
    ) -> (EncapsulationKey, DecapsulationKey) {
        crate::Hqc128::generate_key(rng)
    }

    /// Generate an HQC-128 key pair deterministically from a 32-byte seed.
    #[cfg(feature = "kgen")]
    pub fn generate_key_deterministic(seed: &[u8; 32]) -> (EncapsulationKey, DecapsulationKey) {
        crate::Hqc128::generate_key_deterministic(seed)
    }
}

/// HQC-3 (HQC-192) sizes and helpers (HQC v5.1, specification Table 9).
pub mod hqc192 {
    /// Public key size in bytes.
    pub const PUBLIC_KEY_SIZE: usize = 4514;
    /// Secret key size in bytes (v5.1 compressed `dk_KEM = seed_KEM`).
    pub const SECRET_KEY_SIZE: usize = 32;
    /// Ciphertext size in bytes.
    pub const CIPHERTEXT_SIZE: usize = 8978;
    /// Shared secret size in bytes.
    pub const SHARED_SECRET_SIZE: usize = crate::params::SS_BYTES;
    /// Message size in bytes (for deterministic encapsulation).
    pub const MESSAGE_SIZE: usize = 24;
    /// Salt size in bytes (for deterministic encapsulation).
    pub const SALT_SIZE: usize = crate::params::SALT_BYTES;

    /// HQC-192 encapsulation key.
    pub type EncapsulationKey = crate::EncapsulationKey<crate::Hqc192Params>;
    /// HQC-192 decapsulation key.
    pub type DecapsulationKey = crate::DecapsulationKey<crate::Hqc192Params>;
    /// HQC-192 ciphertext.
    pub type Ciphertext = crate::Ciphertext<crate::Hqc192Params>;
    /// HQC-192 shared secret.
    pub type SharedSecret = crate::SharedSecret<crate::Hqc192Params>;

    /// Generate an HQC-192 key pair.
    #[cfg(feature = "kgen")]
    pub fn generate_key(
        rng: &mut impl rand_core::CryptoRng,
    ) -> (EncapsulationKey, DecapsulationKey) {
        crate::Hqc192::generate_key(rng)
    }

    /// Generate an HQC-192 key pair deterministically from a 32-byte seed.
    #[cfg(feature = "kgen")]
    pub fn generate_key_deterministic(seed: &[u8; 32]) -> (EncapsulationKey, DecapsulationKey) {
        crate::Hqc192::generate_key_deterministic(seed)
    }
}

/// HQC-5 (HQC-256) sizes and helpers (HQC v5.1, specification Table 9).
pub mod hqc256 {
    /// Public key size in bytes.
    pub const PUBLIC_KEY_SIZE: usize = 7237;
    /// Secret key size in bytes (v5.1 compressed `dk_KEM = seed_KEM`).
    pub const SECRET_KEY_SIZE: usize = 32;
    /// Ciphertext size in bytes.
    pub const CIPHERTEXT_SIZE: usize = 14421;
    /// Shared secret size in bytes.
    pub const SHARED_SECRET_SIZE: usize = crate::params::SS_BYTES;
    /// Message size in bytes (for deterministic encapsulation).
    pub const MESSAGE_SIZE: usize = 32;
    /// Salt size in bytes (for deterministic encapsulation).
    pub const SALT_SIZE: usize = crate::params::SALT_BYTES;

    /// HQC-256 encapsulation key.
    pub type EncapsulationKey = crate::EncapsulationKey<crate::Hqc256Params>;
    /// HQC-256 decapsulation key.
    pub type DecapsulationKey = crate::DecapsulationKey<crate::Hqc256Params>;
    /// HQC-256 ciphertext.
    pub type Ciphertext = crate::Ciphertext<crate::Hqc256Params>;
    /// HQC-256 shared secret.
    pub type SharedSecret = crate::SharedSecret<crate::Hqc256Params>;

    /// Generate an HQC-256 key pair.
    #[cfg(feature = "kgen")]
    pub fn generate_key(
        rng: &mut impl rand_core::CryptoRng,
    ) -> (EncapsulationKey, DecapsulationKey) {
        crate::Hqc256::generate_key(rng)
    }

    /// Generate an HQC-256 key pair deterministically from a 32-byte seed.
    #[cfg(feature = "kgen")]
    pub fn generate_key_deterministic(seed: &[u8; 32]) -> (EncapsulationKey, DecapsulationKey) {
        crate::Hqc256::generate_key_deterministic(seed)
    }
}
