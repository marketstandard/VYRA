//! Hybrid post-quantum key encapsulation for VYRA: ML-KEM + HQC.
//!
//! A [`HybridKem`] runs two key-encapsulation mechanisms from different
//! hardness families, a lattice KEM (ML-KEM) and a code-based KEM (HQC), and
//! derives one 32-byte key from both with a combiner that hashes both shared
//! secrets, both ciphertexts, both public keys and the suite id. The intent is
//! that the hybrid stays secure while at least one component does; see
//! docs/DECISIONS.md D-01 for the construction and its cited analysis.
//!
//! The secret key format `sk1 ‖ sk2` consists of the two components'
//! key-generation seeds (ML-KEM `d ‖ z`, HQC `seed_kem`). On decapsulation the
//! public keys fed to the combiner are derived from those seeds
//! ([`ComponentKem::public_key_from_secret`]), so a secret key cannot carry
//! public keys that contradict it.
//!
//! # What is established and what is VYRA-original
//!
//! ESTABLISHED (published designs; ML-KEM and SHA3 used unmodified from
//! existing crates):
//!
//! - ML-KEM-512/768/1024, FIPS 203, from the `ml-kem` crate ([`MlKem512`],
//!   [`MlKem768`], [`MlKem1024`]);
//! - HQC-128/192/256 (the specification's HQC-1/3/5) as in the HQC v5.1
//!   specification (2026-11-09) and its reference implementation, tag v5.1.0
//!   ([`Hqc128`], [`Hqc192`], [`Hqc256`]). HQC is not yet a published
//!   standard (FIPS 207 is unpublished). The implementation is the in-tree
//!   crate `vyra-hqc`, a port of the `hqc-kem` 0.1.0-rc.0 release candidate
//!   to v5.1 made by the VYRA authors: unlike the other components it is
//!   modified code, checked against all official v5.1 known-answer vectors
//!   but by no second independent v5.1 implementation;
//! - SHA3-256 (FIPS 202), through [`vyra_core::Transcript`];
//! - the technique of hashing ciphertexts into a KEM combiner (Giacon, Heuer,
//!   Poettering, PKC 2018).
//!
//! VYRA-ORIGINAL (no external specification; reviewed only within this project):
//!
//! - the combiner's exact byte encoding ([`combine`]);
//! - the suite identifiers and component pairings ([`KemSuite`]);
//! - the raw hybrid key/ciphertext layouts ([`HybridKem`]) and the wire format
//!   of [`HybridPublicKey`], [`HybridSecretKey`] and [`HybridCiphertext`];
//! - [`CustomHybridKem`], the same composition over caller-supplied
//!   components (crypto agility and experiments). Custom assemblies are
//!   outside the named suites, have no wire identifier, and inherit no
//!   security statement from this documentation.
//!
//! # Behaviour
//!
//! - All randomness enters through `&mut dyn EntropySource`; with
//!   [`DeterministicEntropy`](vyra_core::DeterministicEntropy) every operation
//!   is byte-reproducible.
//! - Decapsulation uses implicit rejection (D-02): a well-formed but invalid
//!   ciphertext yields an unrelated key, not an error. Errors are returned only
//!   for malformed input, which is public information.
//! - Timing behaviour of the upstream component crates is inherited and has not
//!   been measured by VYRA (D-05). For HQC, `vyra-hqc` carries upstream's
//!   manual dudect-style smoke tests (a coarse check, not a constant-time
//!   proof).
//!
//! # Example
//!
//! ```
//! use vyra_core::OsEntropy;
//! use vyra_kem::{HybridCiphertext, HybridKem, HybridPublicKey, KemSuite};
//!
//! # fn main() -> vyra_core::Result<()> {
//! let kem = HybridKem::new(KemSuite::Vyra3);
//! let mut rng = OsEntropy::new();
//!
//! // Recipient.
//! let (pk, sk) = kem.generate(&mut rng)?;
//! let pk_wire = pk.to_bytes();
//!
//! // Sender.
//! let pk = HybridPublicKey::from_bytes(&pk_wire)?;
//! let (ct, key_sender) = kem.encapsulate_to(&pk, &mut rng)?;
//! let ct_wire = ct.to_bytes();
//!
//! // Recipient.
//! let ct = HybridCiphertext::from_bytes(&ct_wire)?;
//! let key_recipient = kem.decapsulate_with(&sk, &ct)?;
//! assert!(key_sender.ct_eq(&key_recipient));
//! assert_eq!(ct_wire.len(), KemSuite::Vyra3.encoded_ciphertext_len());
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod combiner;
pub mod component;
pub mod custom;
pub mod hqc;
pub mod hybrid;
pub mod keys;
pub mod mlkem;
pub mod suite;

pub use combiner::{COMBINED_SECRET_LEN, COMBINER_LABEL, combine};
pub use component::ComponentKem;
pub use custom::{CustomHybridKem, CustomSuite};
pub use hqc::{Hqc128, Hqc192, Hqc256};
pub use hybrid::HybridKem;
pub use keys::{
    HybridCiphertext, HybridPublicKey, HybridSecretKey, SECRET_KEY_CHECK_LABEL,
    SECRET_KEY_CHECK_LEN,
};
pub use mlkem::{MlKem512, MlKem768, MlKem1024};
pub use suite::KemSuite;
