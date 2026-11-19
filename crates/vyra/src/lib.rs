//! # VYRA
//!
//! VYRA is an open-source **research prototype** of a hybrid post-quantum
//! cryptography library written in safe Rust. It offers three things, each
//! built by combining an established post-quantum component with a second,
//! independent component:
//!
//! - a **hybrid KEM** ([`kem`]): ML-KEM (lattice-based) plus HQC (code-based),
//!   whose two shared secrets are combined with a hash that also binds both
//!   ciphertexts, both public keys and the suite;
//! - a **composite signature** ([`sig`]): ML-DSA plus a second component,
//!   where both signatures must verify, in two families (see
//!   [Signature families](#signature-families));
//! - a **sealed box** ([`seal`]): one-shot public-key encryption of a message
//!   to a recipient, built from the hybrid KEM and ChaCha20-Poly1305.
//!
//! ## Status
//!
//! ```text
#![doc = include_str!("status.txt")]
//! ```
//!
//! The same text is available to programs as [`STATUS`].
//!
//! VYRA combines components that are *designed* to resist attack by a
//! quantum computer (ML-KEM, HQC, ML-DSA, SLH-DSA) with classical ones
//! (Ed25519, ChaCha20-Poly1305, SHA-3). Whether the combinations achieve the
//! intended properties has **not** been independently analysed. Hybrid
//! designs aim to stay secure while at least one component remains secure;
//! VYRA states that as an intent, not as a proven property of its concrete
//! encodings.
//!
//! ## What the name means, and what it does not
//!
//! VYRA stands for *Verified Yielding Resistance Architecture*. Both halves
//! are meant narrowly:
//!
//! - **"Verified"** means that every claim made in the repository is tied to
//!   a reproducible machine check: official known-answer vectors for the
//!   components, VYRA's own known-answer vectors, failure-injection games
//!   (`crates/vyra-yield`), exhaustive enumeration and bounded model checking
//!   of VYRA's *own encodings* (`crates/vyra-proofs`, `tools/kani`), all run
//!   by `cargo xtask verify` (docs/CHECKS.md). It does **not** mean formal
//!   verification of the cryptography, a security proof of VYRA's
//!   constructions, or external review: none of those exist.
//! - **"Yielding Resistance"** means *designed so that the security goals
//!   survive one component family yielding*: for key establishment, lattices
//!   (ML-KEM) and codes (HQC); for signatures in the dual post-quantum suites,
//!   lattices (ML-DSA) and hash functions (SLH-DSA). The evidence is a cited
//!   theorem for the KEM combiner technique (Giacon, Heuer, Poettering, PKC
//!   2018), an unreviewed proof sketch for the signature composite, and
//!   failure-injection experiments (`results/yield-matrix.md`): with one
//!   deliberately broken toy component, none of the implemented attacks won
//!   against the stated goals (KEM: IND-CCA2 and the binding games;
//!   signatures: EUF-CMA). Strong unforgeability and the separation of the
//!   composite halves are not expected to survive a broken component, and
//!   the experiments show them lost. That is evidence, not a proof for
//!   VYRA's concrete instantiation; the transition signature suites keep
//!   only ML-DSA against a quantum adversary.
//!
//! ## What is established and what is VYRA-original
//!
//! | Part | Label | Notes |
//! |------|-------|-------|
//! | ML-KEM-512/768/1024 (FIPS 203) | ESTABLISHED | `ml-kem` crate, unmodified |
//! | HQC-128/192/256 | ESTABLISHED (pre-standard) | HQC v5.1 specification, implemented by the in-tree `vyra-hqc` port and checked against the official v5.1 known-answer tests; not yet a published FIPS standard (docs/DECISIONS.md D-14) |
//! | ML-DSA-44/65/87 (FIPS 204) | ESTABLISHED | `ml-dsa` crate, unmodified, hedged signing |
//! | Ed25519 (RFC 8032) | ESTABLISHED | `ed25519-dalek`, strict verification |
//! | SLH-DSA-SHAKE-128s/192s/256s (FIPS 205) | ESTABLISHED | `fips205` crate, unmodified, hedged signing |
//! | ChaCha20-Poly1305 (RFC 8439) | ESTABLISHED | `chacha20poly1305` crate, unmodified |
//! | SHA3-256 / SHAKE256 (FIPS 202) | ESTABLISHED | through [`Transcript`] |
//! | Hashing ciphertexts into a KEM combiner | ESTABLISHED technique | Giacon, Heuer, Poettering (PKC 2018) |
//! | KEM-DEM hybrid encryption | ESTABLISHED technique | as in HPKE (RFC 9180) base mode |
//! | Hybrid KEM combiner encoding and suite pairings | VYRA-ORIGINAL | [`kem::combine`], [`kem::KemSuite`] |
//! | Composite signature message binding and concatenation format | VYRA-ORIGINAL | [`sig::message_representative`]; not the IETF LAMPS composite format |
//! | Suite pairings of both signature families | VYRA-ORIGINAL | [`sig::SigSuite`] |
//! | Custom assembly entry points | VYRA-ORIGINAL | [`kem::CustomHybridKem`], [`sig::CustomComposite`]: the same constructions over caller-supplied components, outside the named suites and the wire format |
//! | Sealed box key derivation, AAD framing, layout | VYRA-ORIGINAL | [`seal::SealedBox`] |
//! | Wire format of every serialized object | VYRA-ORIGINAL | [`wire`] |
//!
//! VYRA-ORIGINAL parts have no external specification and have been reviewed
//! only within this project.
//!
//! ## Crate layout
//!
//! - [`kem`]: everything from `vyra-kem` (hybrid KEM, suites, typed keys).
//! - [`sig`]: everything from `vyra-sig` (composite signatures, suites, typed keys).
//! - [`seal`]: everything from `vyra-seal` (the sealed box).
//! - Crate root: the shared vocabulary from `vyra-core` ([`Error`],
//!   [`Result`], [`OsEntropy`], [`SecretBytes`], [`Transcript`], [`wire`], ...).
//! - [`prelude`]: the types most programs need, for `use vyra::prelude::*;`.
//!
//! The failure-injection crate `vyra-yield` contains **intentionally
//! insecure** component models and is deliberately not re-exported here; it
//! is a research tool, not part of the library.
//!
//! ## Hybrid KEM
//!
//! ```
//! use vyra::prelude::*;
//!
//! # fn main() -> vyra::Result<()> {
//! let kem = HybridKem::new(KemSuite::Vyra3);
//! let mut rng = OsEntropy::new();
//!
//! // Recipient: generate a key pair and publish the wire-encoded public key.
//! let (pk, sk) = kem.generate(&mut rng)?;
//! let pk_wire = pk.to_bytes();
//!
//! // Sender: parse the public key (suite read from the header) and encapsulate.
//! let pk = HybridPublicKey::from_bytes(&pk_wire)?;
//! let (ct, key_sender) = HybridKem::new(pk.suite()).encapsulate_to(&pk, &mut rng)?;
//! let ct_wire = ct.to_bytes();
//!
//! // Recipient: decapsulate.
//! let ct = HybridCiphertext::from_bytes(&ct_wire)?;
//! let key_recipient = kem.decapsulate_with(&sk, &ct)?;
//! assert!(key_sender.ct_eq(&key_recipient));
//! assert_eq!(key_recipient.len(), 32);
//! # Ok(())
//! # }
//! ```
//!
//! The KEM alone gives **no forward secrecy** with a long-term recipient key
//! (docs/DECISIONS.md D-03); use a fresh key pair per session and drop it
//! afterwards, as `examples/handshake.rs` does.
//!
//! ## Signature families
//!
//! | family | suites | components | for |
//! |--------|--------|------------|-----|
//! | transition | `VYRA-SIG-2/3/5` | ML-DSA-44/65/87 + Ed25519 | migrating systems that keep a well-studied classical fallback; small and fast |
//! | dual post-quantum | `VYRA-SIG-PQ1/3/5` | ML-DSA-44/65/87 + SLH-DSA-SHAKE-128s/192s/256s | two post-quantum assumptions (module lattices, hash functions); low-rate, long-lived signatures |
//!
//! - **Transition suites** pair ML-DSA with **Ed25519**, a classical
//!   fallback. Against a classical attacker the composite is intended to stay
//!   unforgeable if either component holds; against a quantum attacker,
//!   who can forge Ed25519, it rests on **ML-DSA alone**. Signatures are
//!   2.5-4.7 KB and every operation takes milliseconds.
//! - **Dual post-quantum suites** pair ML-DSA with **SLH-DSA**, whose security
//!   rests only on hash-function properties. The composite is intended to
//!   stay unforgeable, also against a quantum attacker, as long as **either**
//!   ML-DSA **or** SLH-DSA holds. Costs: signatures of 10-34 KB and slow
//!   signing (SLH-DSA "s" parameter sets: 1-6 s per signature measured in
//!   release builds on the development machine, depending on suite and load;
//!   key generation 0.1-0.6 s; verification takes milliseconds).
//!
//! The same API serves both families; only the [`SigSuite`](sig::SigSuite)
//! differs. [`SigSuite::transition`](sig::SigSuite::transition),
//! [`SigSuite::dual_pq`](sig::SigSuite::dual_pq) and
//! [`SigSuite::is_dual_pq`](sig::SigSuite::is_dual_pq) select a family.
//!
//! ## Composite signature (transition suite)
//!
//! ```
//! use vyra::prelude::*;
//!
//! # fn main() -> vyra::Result<()> {
//! let scheme = CompositeSignature::new(SigSuite::Vyra3);
//! let mut rng = OsEntropy::new();
//! let (pk, sk) = scheme.generate(&mut rng)?;
//!
//! let sig = scheme.sign(&sk, b"release v0.1.0", b"my-app/releases", &mut rng)?;
//! scheme.verify(&pk, b"release v0.1.0", b"my-app/releases", &sig)?;
//!
//! // A different message or context is rejected.
//! assert!(scheme.verify(&pk, b"release v0.1.1", b"my-app/releases", &sig).is_err());
//! assert!(scheme.verify(&pk, b"release v0.1.0", b"other-app", &sig).is_err());
//! # Ok(())
//! # }
//! ```
//!
//! ## Composite signature (dual post-quantum suite)
//!
//! One signature, so this example takes about a second in a release build
//! (longer unoptimised).
//!
//! ```
//! use vyra::prelude::*;
//!
//! # fn main() -> vyra::Result<()> {
//! let suite = SigSuite::Pq1; // ML-DSA-44 + SLH-DSA-SHAKE-128s
//! assert!(suite.is_dual_pq());
//! assert_eq!(suite.second().name(), "SLH-DSA-SHAKE-128s");
//!
//! let scheme = CompositeSignature::new(suite);
//! let mut rng = OsEntropy::new();
//! let (pk, sk) = scheme.generate(&mut rng)?;
//! let sig = scheme.sign(&sk, b"firmware v2.1", b"my-app/firmware", &mut rng)?;
//! assert_eq!(sig.to_bytes().len(), suite.encoded_signature_len()); // 10283 bytes
//!
//! let pk = CompositePublicKey::from_bytes(&pk.to_bytes())?;
//! scheme.verify(&pk, b"firmware v2.1", b"my-app/firmware", &sig)?;
//! assert!(scheme.verify(&pk, b"firmware v2.2", b"my-app/firmware", &sig).is_err());
//! # Ok(())
//! # }
//! ```
//!
//! ## Sealed box
//!
//! ```
//! use vyra::prelude::*;
//!
//! # fn main() -> vyra::Result<()> {
//! let suite = KemSuite::Vyra1;
//! let mut rng = OsEntropy::new();
//! let (pk, sk) = HybridKem::new(suite).generate(&mut rng)?;
//!
//! let sbox = SealedBox::new(suite);
//! let sealed = sbox.seal(&pk, b"header", b"meet at noon", &mut rng)?;
//! let opened = sbox.open(&sk, b"header", &sealed)?;
//! assert_eq!(opened.expose(), b"meet at noon");
//!
//! // Wrong associated data: rejected.
//! assert_eq!(sbox.open(&sk, b"other", &sealed).map(|_| ()), Err(Error::DecryptionFailed));
//! # Ok(())
//! # }
//! ```
//!
//! The sealed box does **not** authenticate the sender and gives no forward
//! secrecy with a long-term recipient key; see [`seal`].

#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// The status statement printed by the `vyra` command-line tool and shown at
/// the top of this documentation.
pub const STATUS: &str = include_str!("status.txt");

pub use vyra_core::{
    DeterministicEntropy, EntropySource, Error, Kem, ObjectType, OsEntropy, Result, SecretBytes,
    SecurityLevel, SignatureScheme, Transcript, wire,
};

pub mod kem {
    //! Hybrid ML-KEM + HQC key encapsulation: a re-export of the `vyra-kem` crate.
    //!
    //! Start with [`HybridKem`] and [`KemSuite`]. Decapsulation uses implicit
    //! rejection: a well-formed but invalid ciphertext yields an unrelated key,
    //! not an error (docs/DECISIONS.md D-02). [`CustomHybridKem`] assembles the
    //! same combiner over caller-supplied components.
    pub use vyra_kem::*;
}

pub mod sig {
    //! Composite signatures, ML-DSA + Ed25519 (transition suites) and
    //! ML-DSA + SLH-DSA (dual post-quantum suites): a re-export of the
    //! `vyra-sig` crate.
    //!
    //! Start with [`CompositeSignature`] and [`SigSuite`]. Component keys must
    //! never be used outside the composite. Ed25519 offers no security against
    //! a quantum attacker, so against one a transition-suite composite rests
    //! on ML-DSA alone; a dual post-quantum composite is intended to hold if
    //! either ML-DSA or SLH-DSA does. [`CustomComposite`] assembles the same
    //! construction over caller-supplied components (outside the named suites
    //! and the wire format).
    pub use vyra_sig::*;
}

pub mod seal {
    //! Sealed box (hybrid KEM + ChaCha20-Poly1305): a re-export of the
    //! `vyra-seal` crate.
    //!
    //! Limits: no sender authentication, no forward secrecy with a long-term
    //! recipient key, plaintext length is revealed, single-shot only (no replay
    //! protection). See [`SealedBox`].
    pub use vyra_seal::*;
}

pub mod prelude {
    //! The types most programs need: `use vyra::prelude::*;`.
    pub use crate::kem::{HybridCiphertext, HybridKem, HybridPublicKey, HybridSecretKey, KemSuite};
    pub use crate::seal::SealedBox;
    pub use crate::sig::{
        CompositePublicKey, CompositeSecretKey, CompositeSig, CompositeSignature, SigSuite,
    };
    pub use vyra_core::{EntropySource, Error, OsEntropy, Result, SecretBytes, Transcript};
}
