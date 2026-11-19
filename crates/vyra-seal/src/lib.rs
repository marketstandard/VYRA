//! Hybrid post-quantum sealed box for VYRA: public-key authenticated
//! encryption of a single message to a single recipient.
//!
//! A [`SealedBox`] combines the VYRA hybrid KEM (ML-KEM + HQC, from
//! `vyra-kem`) with ChaCha20-Poly1305 in the KEM-DEM pattern: every
//! [`seal`](SealedBox::seal) runs a fresh encapsulation to the recipient's
//! public key, derives a one-time AEAD key and nonce from the encapsulated
//! secret, and encrypts the message under them.
//!
//! # Construction
//!
//! ```text
//! (kem_ct, K)  = HybridKem(suite).encapsulate_to(pk, rng)
//! key ‖ nonce  = SHAKE256( 0x01 ‖ frame("VYRA-SEAL-v1") ‖ frame([suite_id])
//!                          ‖ frame(K) ‖ frame(kem_ct_raw) )[0..44]
//! aad'         = "VYRA-SEAL-v1" ‖ suite_id ‖ aad
//! body         = ChaCha20-Poly1305(key, nonce).encrypt(plaintext, aad')   ciphertext ‖ 16-byte tag
//! sealed       = header(SealedBox, suite) ‖ kem_ct_raw ‖ body
//! frame(x)     = u64_be(len(x)) ‖ x
//! ```
//!
//! The key derivation is [`vyra_core::Transcript::finalize_xof`] (module
//! [`kdf`]); the wire layout is in module [`sealed_box`]. The output is exactly
//! [`SealedBox::overhead`]`(suite)` bytes longer than the plaintext:
//!
//! | suite      | overhead (bytes) |
//! |------------|------------------|
//! | VYRA-KEM-1 | 7 + 768 + 4433 + 16 = 5224   |
//! | VYRA-KEM-3 | 7 + 1088 + 8978 + 16 = 10089 |
//! | VYRA-KEM-5 | 7 + 1568 + 14421 + 16 = 16012 |
//!
//! # What is established and what is VYRA-original
//!
//! ESTABLISHED:
//!
//! - the KEM-DEM (hybrid encryption) paradigm, as in Cramer–Shoup and HPKE
//!   (RFC 9180) base mode: a fresh KEM key per message, used once by an AEAD;
//! - ChaCha20-Poly1305 (RFC 8439), from the RustCrypto `chacha20poly1305`
//!   crate, unmodified;
//! - SHAKE256 (FIPS 202) as the key derivation function, through
//!   [`vyra_core::Transcript`];
//! - the hybrid KEM's components (ML-KEM, HQC) and combiner technique; see
//!   `vyra-kem` and docs/DECISIONS.md D-01.
//!
//! VYRA-ORIGINAL (no external specification; reviewed only within this project):
//!
//! - the exact key-derivation encoding and the label `"VYRA-SEAL-v1"`;
//! - the associated-data framing `"VYRA-SEAL-v1" ‖ suite_id ‖ aad`;
//! - the wire format of the sealed box.
//!
//! # Nonce uniqueness
//!
//! The AEAD nonce is derived, not random, and is never transmitted. This is
//! safe because the AEAD key is also derived from the same fresh KEM secret
//! `K`: each seal performs a new encapsulation, so each (key, nonce) pair
//! encrypts exactly one message. Two seals collide only if two encapsulations
//! yield the same `K`, which the KEM's security makes negligible. This holds
//! only with a working entropy source; reusing a
//! [`DeterministicEntropy`](vyra_core::DeterministicEntropy) seed to seal two
//! different messages to the same key **does** reuse the key and nonce, which
//! breaks ChaCha20-Poly1305. `DeterministicEntropy` is for tests only.
//!
//! # Limits (read before use)
//!
//! - **No sender authentication.** Anyone holding the recipient's public key
//!   can produce a valid sealed box. "Authenticated" refers to integrity of
//!   the ciphertext and `aad` relative to whoever sealed it, not to who that
//!   was. Sign the sealed box (or its contents) if the sender matters.
//! - **No forward secrecy with a static recipient key** (docs/DECISIONS.md
//!   D-03). Whoever later obtains the recipient's secret key can open every
//!   recorded sealed box addressed to it. Use ephemeral recipient keys that
//!   are erased after use if forward secrecy is required.
//! - **Plaintext length is revealed**: the sealed box is exactly
//!   `overhead(suite)` bytes longer than the plaintext. Pad before sealing if
//!   the length is sensitive.
//! - **Single-shot only.** This is not a streaming API and not a channel: no
//!   ordering, replay protection or multi-message state. Replaying a sealed
//!   box yields the same plaintext again; applications that care must detect
//!   replays themselves.
//! - **Maximum plaintext** is [`MAX_PLAINTEXT_LEN`] bytes (the
//!   ChaCha20-Poly1305 limit of RFC 8439, minus one byte as enforced upstream),
//!   and the whole message is held in memory.
//! - `open` returns the plaintext only after the tag has verified; on any
//!   authentication failure it returns [`Error::DecryptionFailed`] with no
//!   further detail. Malformed input (wrong header, unknown suite, too short)
//!   is reported as `InvalidEncoding` / `UnknownSuite` / `InvalidLength`,
//!   which depend only on public data.
//! - Timing behaviour of the upstream KEM and AEAD crates is inherited and has
//!   not been measured by VYRA (D-05).
//!
//! # Example
//!
//! ```
//! use vyra_core::OsEntropy;
//! use vyra_kem::{HybridKem, KemSuite};
//! use vyra_seal::SealedBox;
//!
//! # fn main() -> vyra_core::Result<()> {
//! let suite = KemSuite::Vyra3;
//! let mut rng = OsEntropy::new();
//!
//! // Recipient.
//! let (pk, sk) = HybridKem::new(suite).generate(&mut rng)?;
//!
//! // Sender.
//! let sbox = SealedBox::new(suite);
//! let sealed = sbox.seal(&pk, b"context", b"attack at dawn", &mut rng)?;
//! assert_eq!(sealed.len(), 14 + SealedBox::overhead(suite));
//!
//! // Recipient.
//! let plaintext = sbox.open(&sk, b"context", &sealed)?;
//! assert_eq!(plaintext.expose(), b"attack at dawn");
//!
//! // Different associated data: rejected.
//! assert_eq!(
//!     sbox.open(&sk, b"other", &sealed).map(|_| ()),
//!     Err(vyra_core::Error::DecryptionFailed)
//! );
//! # Ok(())
//! # }
//! ```
//!
//! [`Error::DecryptionFailed`]: vyra_core::Error::DecryptionFailed

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod aead;
pub mod kdf;
pub mod sealed_box;

pub use aead::{KEY_LEN, MAX_PLAINTEXT_LEN, NONCE_LEN, TAG_LEN};
pub use kdf::{DEM_OUTPUT_LEN, SEAL_LABEL};
pub use sealed_box::SealedBox;
