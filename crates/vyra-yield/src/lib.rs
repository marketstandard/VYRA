//! Experimental evidence for VYRA's "yielding resistance" claim: the hybrid
//! KEM (unit U11) and the composite signature ([`sig`], unit U11-S).
//!
//! **Research tool. Contains INTENTIONALLY INSECURE failure models
//! ([`models`]). Not for use in any system. `publish = false`.**
//!
//! VYRA's central claim is that the hybrid KEM keeps its security when one
//! component yields (is broken). That claim rests on a cited theorem
//! (Giacon–Heuer–Poettering, "KEM Combiners", PKC 2018) and on an unreviewed
//! proof sketch in docs/SECURITY.md. This crate turns it into a *falsifiable*
//! property: it builds deliberately broken components, plugs them into the
//! real architecture (VYRA's own combiner through
//! [`vyra_kem::CustomHybridKem`]) and into comparison combiners, runs
//! concrete attacks inside explicit security games, and records which designs
//! survive which failures.
//!
//! **This is falsification evidence, not proof.** A `BROKEN` cell is a
//! concrete, reproducible attack. A `NO ATTACK FOUND` cell means only that
//! the attacks implemented here failed; it is never a statement that a
//! design is secure. See [`report::CAVEAT`].
//!
//! # Structure
//!
//! - [`models`]: failure models (Leaky, Malleable, KeySubstitutable,
//!   Constant, SenderKeyed) wrapping the real ML-KEM-512 / HQC-128 adapters.
//! - [`combiners`]: Naive, Xor, CtBound, XWingStyle and the real Vyra
//!   combiner, all assembled over the same component interface.
//! - [`games`]: IND-CCA2 and the Cremers–Dax–Medinger binding games as
//!   state machines.
//! - [`adversaries`]: seeded attack strategies.
//! - [`stats`]: estimates, intervals, the verdict rule.
//! - [`experiment`], [`controls`], [`expected`], [`report`]: the matrix, its
//!   controls and per-cell expectations, and the JSON/Markdown output.
//! - [`sig`]: the same structure for composite signatures (models,
//!   compositions, games, adversaries, experiment, controls).
//! - [`parallel`]: deterministic parallel execution.
//!
//! # Omitted on purpose
//!
//! A "validity oracle" failure model (decapsulation revealing whether a
//! ciphertext is valid) is not included. VYRA's hybrid does propagate a
//! component's `Err` (it returns `Err` if either component does), so a
//! component with explicit rejection would turn the hybrid into an explicitly
//! rejecting KEM; but for an FO-transformed component explicit rejection is
//! itself compatible with IND-CCA2, and a *meaningful* experiment would need
//! a component whose validity leak enables a real plaintext-checking key
//! recovery (as on non-FO lattice PKE). Implementing such an attack on real
//! ML-KEM/HQC internals is outside this unit; a toy leak would only test
//! error propagation, which is already a documented design decision (D-02).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod adversaries;
pub mod combiners;
pub mod controls;
pub mod expected;
pub mod experiment;
pub mod games;
pub mod models;
pub mod parallel;
pub mod report;
pub mod scenario;
pub mod sig;
pub mod stats;
