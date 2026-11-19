//! Composite signatures for VYRA: ML-DSA (FIPS 204) combined with a second
//! component, Ed25519 (RFC 8032) or SLH-DSA (FIPS 205). Both component
//! signatures must verify.
//!
//! # Example
//!
//! ```
//! use vyra_core::OsEntropy;
//! use vyra_sig::{CompositePublicKey, CompositeSig, CompositeSignature, SigSuite};
//!
//! # fn main() -> vyra_core::Result<()> {
//! let scheme = CompositeSignature::new(SigSuite::Vyra3);
//! let mut rng = OsEntropy::new();
//! let (pk, sk) = scheme.generate(&mut rng)?;
//!
//! let sig = scheme.sign(&sk, b"hello", b"example-context", &mut rng)?;
//!
//! // Ship the public key and signature in VYRA wire format...
//! let pk = CompositePublicKey::from_bytes(&pk.to_bytes())?;
//! let sig = CompositeSig::from_bytes(&sig.to_bytes())?;
//!
//! // ...and verify under the same context.
//! scheme.verify(&pk, b"hello", b"example-context", &sig)?;
//! assert!(scheme.verify(&pk, b"hello", b"other-context", &sig).is_err());
//!
//! // A dual post-quantum suite has the same API (signing is much slower).
//! let pq = CompositeSignature::new(SigSuite::Pq1);
//! let (pk, sk) = pq.generate(&mut rng)?;
//! let sig = pq.sign(&sk, b"release v1.0", b"", &mut rng)?;
//! pq.verify(&pk, b"release v1.0", b"", &sig)?;
//! # Ok(())
//! # }
//! ```
//!
//! # Two suite families
//!
//! | suite | id | components | pk | sk (stored) | sig | wire pk / sk / sig |
//! |-------|----|------------|----|-------------|-----|--------------------|
//! | `VYRA-SIG-2` | 0x02 | ML-DSA-44 + Ed25519 | 1344 | 64 | 2484 | 1351 / 87 / 2491 |
//! | `VYRA-SIG-3` | 0x03 | ML-DSA-65 + Ed25519 | 1984 | 64 | 3373 | 1991 / 87 / 3380 |
//! | `VYRA-SIG-5` | 0x05 | ML-DSA-87 + Ed25519 | 2624 | 64 | 4691 | 2631 / 87 / 4698 |
//! | `VYRA-SIG-PQ1` | 0x11 | ML-DSA-44 + SLH-DSA-SHAKE-128s | 1344 | 80 | 10276 | 1351 / 103 / 10283 |
//! | `VYRA-SIG-PQ3` | 0x13 | ML-DSA-65 + SLH-DSA-SHAKE-192s | 2000 | 104 | 19533 | 2007 / 127 / 19540 |
//! | `VYRA-SIG-PQ5` | 0x15 | ML-DSA-87 + SLH-DSA-SHAKE-256s | 2656 | 128 | 34419 | 2663 / 151 / 34426 |
//!
//! - **Transition suites** (ML-DSA + Ed25519): a post-quantum component with a
//!   well-studied classical fallback, for migrating systems that need both.
//!   Small and fast (signing and verification take milliseconds). Against a
//!   quantum adversary, who can forge Ed25519, security rests on ML-DSA
//!   **alone**: one component yielding is enough to leave a single
//!   assumption.
//! - **Dual post-quantum suites** (ML-DSA + SLH-DSA): two independent
//!   post-quantum assumptions, module lattices (ML-DSA) and only
//!   hash-function properties (SLH-DSA), so the intended unforgeability
//!   survives one of them failing even against a quantum adversary. This is
//!   the signature side of VYRA's "yielding resistance". Costs: signatures of
//!   10–34 KB and slow signing (dominated by SLH-DSA "s" signing; measured in
//!   release on the development machine, best of three runs on a shared
//!   machine: about 1.3 s / 2.7 s / 2.3 s per composite signature for PQ1 /
//!   PQ3 / PQ5, key generation 0.13–0.21 s, verification 1–3 ms; the
//!   transition suites take well under 3 ms for each operation). For
//!   long-lived, low-rate signatures (software releases, certificates,
//!   archives), not for high-rate signing.
//!
//! The category label of a transition suite is ML-DSA's; that of a dual-PQ
//! suite is the minimum of both components' categories (see [`SigSuite`]).
//!
//! # What is established and what is VYRA-original
//!
//! ESTABLISHED (used unmodified from upstream crates):
//!
//! - **ML-DSA-44/65/87** ([`MlDsa44`], [`MlDsa65`], [`MlDsa87`]): FIPS 204
//!   pure ML-DSA via the RustCrypto `ml-dsa` crate, hedged signing. Secret
//!   keys are stored as the 32-byte seed ξ.
//! - **SLH-DSA-SHAKE-128s/192s/256s** ([`SlhDsaShake128s`],
//!   [`SlhDsaShake192s`], [`SlhDsaShake256s`]): FIPS 205 pure SLH-DSA via the
//!   `fips205` crate, hedged signing (`addrnd` from the caller's entropy
//!   source). Secret keys are stored as `SK.seed ‖ SK.prf ‖ PK.seed`;
//!   `PK.root` is recomputed on use ([`slhdsa`]).
//! - **Ed25519** ([`Ed25519`]): RFC 8032 via `ed25519-dalek`, deterministic
//!   signing, strict verification. The standalone adapter is PureEd25519
//!   (`verify_strict`); the composite half is **Ed25519ph** with the
//!   composite context (`sign_prehashed` / `verify_prehashed_strict`, see
//!   [`ed25519`]). Secret keys are the 32-byte RFC 8032 private key.
//!
//! The standalone [`SignatureScheme`](vyra_core::SignatureScheme) adapters
//! use the default mode of their standard (empty context; PureEd25519); the
//! composite passes the context `"VYRA-SIG-v1" ‖ suite_id`
//! ([`composite_context`]) to **every** component, through
//! [`CompositeComponent`] (ML-DSA and SLH-DSA via their context input,
//! Ed25519 via the Ed25519ph context).
//!
//! VYRA-ORIGINAL (designed here, not standardised, not externally reviewed):
//!
//! - the **message binding** ([`message`]): both components sign
//!   `"VYRA-SIG-v1" ‖ suite_id ‖ pk_digest ‖ len(ctx) ‖ ctx ‖ M`, where
//!   `pk_digest` is a SHA3-256 transcript hash of the whole composite public
//!   key; components with a context input sign under the composite context;
//! - the **concatenation format** of composite keys and signatures
//!   (`ML-DSA part ‖ second part`, fixed lengths per suite);
//! - the **wire format** ([`keys`]): the `vyra_core::wire` header followed by
//!   the raw concatenation; a wire secret key additionally ends with a 16-byte
//!   key check value (detects a relabelled suite id or corruption; not a MAC);
//! - the **custom assembly** entry point ([`CustomComposite`]): the same
//!   construction over caller-supplied components, outside the named suites
//!   and the wire format.
//!
//! This is **not** the IETF LAMPS composite-signature format
//! (draft-ietf-lamps-pq-composite-sigs) and is **not interoperable** with it.
//!
//! # Public-key validation
//!
//! Composite public keys are validated when parsed and again in `verify`
//! ([`keys::validate_public_key`]): exact length; the Ed25519 part must
//! decompress, be the canonical encoding of its point (RFC 8032 §5.1.3), and
//! lie in the prime-order subgroup (torsion-free and not the identity, so
//! neither small-order nor mixed-order); the ML-DSA and SLH-DSA parts need no
//! check beyond their lengths because every byte string of those lengths is a
//! valid canonical FIPS 204 / FIPS 205 public key. Canonicity matters because
//! `M'` binds a digest of the raw public-key bytes: two encodings of one key
//! would otherwise name the same key with different digests.
//!
//! # Conformance evidence
//!
//! What the test suite checks for the ESTABLISHED components (details in
//! [`mldsa`], [`slhdsa`] and `tests/data/PROVENANCE.md`):
//!
//! - **ML-DSA:** NIST ACVP keyGen (75 vectors, through the adapter), sigGen
//!   (90 vectors of the external pure interface, deterministic and hedged,
//!   reproduced byte for byte through the upstream crate because the vectors
//!   use the expanded secret key; each verified through the adapter) and
//!   sigVer (45 vectors, adapter verdict equals the expected result); plus
//!   differential tests against the independent `fips204` crate.
//! - **SLH-DSA:** NIST ACVP keyGen (30 vectors), sigGen (42 vectors of the
//!   external pure interface, deterministic and hedged, with and without
//!   context) and sigVer (42 vectors) for the three SHAKE "s" sets, all
//!   through the adapter; plus differential tests against the independent
//!   RustCrypto `slh-dsa` crate.
//! - **Ed25519:** RFC 8032 §7.1 test vectors 1–3 (PureEd25519) through the
//!   standalone adapter; RFC 8032 §7.3 (Ed25519ph) through the composite
//!   half-signing path; Ed25519ph with non-empty contexts against a test-side
//!   reference computation of RFC 8032 §5.1.6 (no second pure-Rust
//!   implementation with Ed25519ph context support was found); and tests of
//!   the strict public-key rules (non-canonical, small-order and mixed-order
//!   keys rejected).
//!
//! These check functional agreement with the published vectors; they say
//! nothing about side-channel behaviour.
//!
//! # Security notes
//!
//! - **Intended property (no proof for this concrete encoding):** for every
//!   named suite, the composite is EUF-CMA for messages `(M, ctx)` (single
//!   key, component keys used only inside the composite) as long as at least
//!   one component is EUF-CMA (ML-DSA and SLH-DSA under the fixed composite
//!   context, Ed25519ph under the composite context). SHA3-256 collision
//!   resistance is needed in addition for the binding of the whole composite
//!   public key (halves from different keys do not recombine). Since U12-R1
//!   the Ed25519 half is Ed25519ph, so its unforgeability also assumes
//!   SHA-512 collision resistance on `M'` ([`ed25519`] states the delta). For the dual-PQ suites this is intended to hold
//!   against a quantum adversary as long as ML-DSA **or** SLH-DSA resists
//!   that adversary; for the transition suites against a quantum adversary
//!   it rests on ML-DSA alone (Ed25519 offers ~128-bit classical security and
//!   none against a quantum adversary).
//! - **Caveats:** only an unreviewed proof sketch exists, written for the
//!   transition suites (`docs/SECURITY.md`: a reduction for one key that uses
//!   no Ed25519-specific property, so it is intended to carry over to the
//!   dual-PQ suites, but that has not been written out); no QROM analysis,
//!   no multi-user analysis; strong unforgeability needs both components to
//!   be strongly unforgeable; the category label is a label, not a measured
//!   strength; the post-quantum security of each component is the claim of
//!   its standard, not something VYRA establishes.
//! - **Component separation (intended property):** in every named suite
//!   neither half is a valid standalone signature of its scheme's default
//!   mode (empty-context ML-DSA / SLH-DSA, PureEd25519) on `M'`, and
//!   standalone default-mode signatures on `M'` do not complete a composite.
//!   Evidence: `tests/separation.rs` (all six suites, including dalek
//!   `verify_strict` on the Ed25519 half) and the `vyra-yield`
//!   failure-injection matrix, whose STRIP-STANDALONE game broke the
//!   transition suites 200/200 while the Ed25519 half was PureEd25519 and
//!   ML-DSA was modelled as forgeable. Not covered: a component key that
//!   signs elsewhere *under the VYRA composite context* (for Ed25519: in
//!   Ed25519ph with that context). **Component keys should still never be
//!   used outside the composite**; that rule is now defence in depth, no
//!   longer the only protection.
//! - Timing behaviour is inherited from the upstream crates and has not been
//!   measured by VYRA.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod component;
pub mod composite;
pub mod custom;
pub mod ed25519;
pub mod keys;
pub mod message;
pub mod mldsa;
pub mod slhdsa;
pub mod suite;

pub use component::{CompositeComponent, ContextSignatureScheme};
pub use composite::CompositeSignature;
pub use custom::{CustomComposite, CustomSuite};
pub use ed25519::Ed25519;
pub use keys::{
    CompositePublicKey, CompositeSecretKey, CompositeSig, SECRET_KEY_CHECK_LABEL,
    SECRET_KEY_CHECK_LEN, validate_public_key,
};
pub use message::{
    DOMAIN_LABEL, MAX_CONTEXT_LEN, PK_DIGEST_LABEL, PK_DIGEST_LEN, composite_context,
    message_representative, message_representative_with_digest, mldsa_context, public_key_digest,
};
pub use mldsa::{MlDsa44, MlDsa65, MlDsa87};
pub use slhdsa::{SlhDsaShake128s, SlhDsaShake192s, SlhDsaShake256s};
pub use suite::SigSuite;
