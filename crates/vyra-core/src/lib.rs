//! Foundation crate for VYRA, a hybrid post-quantum cryptography library.
//!
//! `vyra-core` contains no cryptographic primitive of its own. It defines the
//! shared vocabulary that the component and hybrid crates build on:
//!
//! - [`Error`] / [`Result`]: the single error type; errors never carry secret data.
//! - [`EntropySource`], [`OsEntropy`], [`DeterministicEntropy`]: randomness input.
//! - [`RandCoreRng`], [`RandCoreTryRng`]: adapters that hand an
//!   `&mut dyn EntropySource` to upstream crates expecting a [`rand_core`] 0.10 RNG.
//! - [`SecretBytes`]: zeroizing, redacted, constant-time comparable secret bytes.
//! - [`SecurityLevel`]: NIST security categories.
//! - [`Kem`], [`SignatureScheme`]: object-safe algorithm traits.
//! - [`Transcript`]: the hashing entry point for VYRA-original constructions.
//! - [`wire`]: the fixed object header and a bounds-checked [`wire::Reader`].

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod entropy;
pub mod error;
pub mod kem;
pub mod level;
pub mod rng;
pub mod secret;
pub mod signature;
pub mod transcript;
pub mod wire;

pub use entropy::{DeterministicEntropy, EntropySource, OsEntropy};
pub use error::{Error, Result};
pub use kem::Kem;
pub use level::SecurityLevel;
pub use rng::{RandCoreRng, RandCoreTryRng};
pub use secret::SecretBytes;
pub use signature::SignatureScheme;
pub use transcript::Transcript;
pub use wire::ObjectType;

/// Re-export of the `rand_core` version (0.10) shared by every upstream component crate.
///
/// Downstream crates should name RNG traits through this path so they always
/// agree with the version [`RandCoreRng`] and [`RandCoreTryRng`] implement.
pub use rand_core;
