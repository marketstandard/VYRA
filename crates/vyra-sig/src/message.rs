//! The composite message representative and component context. VYRA-ORIGINAL
//! encoding, the same for every suite.
//!
//! Both components sign the **same** byte string
//!
//! ```text
//! M' = "VYRA-SIG-v1" ‖ suite_id (1 byte) ‖ pk_digest (32 bytes)
//!      ‖ len(ctx) (1 byte) ‖ ctx ‖ M
//!
//! pk_digest = Transcript("VYRA-SIG-PK-v1")
//!               .append([suite_id]).append(pk_first).append(pk_second)
//!               .finalize()                      (SHA3-256, framed fields)
//! ```
//!
//! where `pk_first` is the ML-DSA public key and `pk_second` the Ed25519
//! (transition suites) or SLH-DSA (dual-PQ suites) public key. Every
//! component signs `M'` under the composite context [`composite_context`] =
//! `"VYRA-SIG-v1" ‖ suite_id` ([`mldsa_context`] is the same value): ML-DSA
//! and SLH-DSA through their context input, Ed25519 as Ed25519ph (SHA-512
//! prehash of `M'`) with that context.
//!
//! - **Pure layout function:** [`message_representative_with_digest`] builds
//!   `M'` from `(suite_id, pk_digest, ctx, M)` and calls no hash function, so
//!   its injectivity can be checked on its own (model checking in a sibling
//!   crate); [`message_representative`] is that function applied to
//!   [`public_key_digest`].
//! - **Injective:** the label, suite byte and digest are fixed-length and the
//!   context is length-prefixed, so `(suite_id, pk_digest, ctx, M) ↦ M'` is
//!   injective.
//! - **Suite binding:** a signature cannot be re-labelled as another suite's.
//! - **Public-key binding (RULES 8):** both components commit to the *whole*
//!   composite public key, so halves produced for two different composite
//!   keys do not recombine into a valid signature under a mixed key. This
//!   binding relies on the collision resistance of SHA3-256 (over the public
//!   key only; `M` itself is not pre-hashed).
//! - **Component separation (RULES 9):** every component signs `M'` under
//!   the composite context, so in every suite **neither** half is a valid
//!   standalone default-mode signature (empty-context ML-DSA / SLH-DSA,
//!   PureEd25519) on `M'`. PureEd25519 has no context input, so the
//!   composite uses Ed25519ph with the composite context (U12-R1, see
//!   [`crate::ed25519`]). Component keys should still not be used outside
//!   the composite (defence in depth, see [`crate::suite::SigSuite`]).
//! - The context is limited to 255 bytes.

use vyra_core::{Error, Result, Transcript};

use crate::suite::SigSuite;

/// Domain-separation label at the start of every message representative and
/// of the composite context string.
pub const DOMAIN_LABEL: &[u8; 11] = b"VYRA-SIG-v1";

/// Transcript label for the composite public-key digest.
pub const PK_DIGEST_LABEL: &[u8] = b"VYRA-SIG-PK-v1";

/// Length of the public-key digest in bytes.
pub const PK_DIGEST_LEN: usize = 32;

/// Maximum context length in bytes.
pub const MAX_CONTEXT_LEN: usize = 255;

/// The context string the composite passes to every component that has a
/// context input: `"VYRA-SIG-v1" ‖ suite_id` (12 bytes).
pub fn composite_context(suite_id: u8) -> [u8; 12] {
    let mut out = [0u8; 12];
    let (label, id) = out.split_at_mut(DOMAIN_LABEL.len());
    label.copy_from_slice(DOMAIN_LABEL);
    id.fill(suite_id);
    out
}

/// The FIPS 204 context string the composite passes to ML-DSA:
/// [`composite_context`]`(suite.id())`. Kept under its original name; in the
/// dual-PQ suites SLH-DSA receives the same context.
pub fn mldsa_context(suite: SigSuite) -> [u8; 12] {
    composite_context(suite.id())
}

/// Digest of a composite public key given as its two component parts.
pub(crate) fn public_key_digest_parts(
    suite_id: u8,
    pk_first: &[u8],
    pk_second: &[u8],
) -> [u8; PK_DIGEST_LEN] {
    let mut t = Transcript::new(PK_DIGEST_LABEL);
    t.append(&[suite_id]).append(pk_first).append(pk_second);
    t.finalize()
}

/// The digest binding a composite public key into `M'`.
///
/// `public_key` is the raw `pk_first ‖ pk_second` encoding.
///
/// # Errors
///
/// [`Error::InvalidLength`] unless `public_key` is exactly
/// [`SigSuite::public_key_len`] bytes.
pub fn public_key_digest(suite: SigSuite, public_key: &[u8]) -> Result<[u8; PK_DIGEST_LEN]> {
    if public_key.len() != suite.public_key_len() {
        return Err(Error::InvalidLength {
            what: "composite public key",
            expected: suite.public_key_len(),
            actual: public_key.len(),
        });
    }
    let (pk_first, pk_second) = public_key
        .split_at_checked(suite.mldsa_public_key_len())
        .ok_or(Error::Internal("public key split"))?;
    Ok(public_key_digest_parts(suite.id(), pk_first, pk_second))
}

fn context_len(context: &[u8]) -> Result<u8> {
    u8::try_from(context.len()).map_err(|_| Error::InvalidLength {
        what: "signature context",
        expected: MAX_CONTEXT_LEN,
        actual: context.len(),
    })
}

/// Build `M'` from an already computed public-key digest.
///
/// Pure layout function: concatenation only, no hashing (see the module
/// docs). Accepts every suite byte, including ids that name no suite.
///
/// # Errors
///
/// [`Error::InvalidLength`] (`what = "signature context"`, `expected` = the
/// maximum, 255) if `context` is longer than [`MAX_CONTEXT_LEN`].
pub fn message_representative_with_digest(
    suite_id: u8,
    pk_digest: &[u8; PK_DIGEST_LEN],
    context: &[u8],
    message: &[u8],
) -> Result<Vec<u8>> {
    let ctx_len = context_len(context)?;
    let capacity = DOMAIN_LABEL
        .len()
        .saturating_add(2 + PK_DIGEST_LEN)
        .saturating_add(context.len())
        .saturating_add(message.len());
    let mut out = Vec::with_capacity(capacity);
    out.extend_from_slice(DOMAIN_LABEL);
    out.push(suite_id);
    out.extend_from_slice(pk_digest);
    out.push(ctx_len);
    out.extend_from_slice(context);
    out.extend_from_slice(message);
    Ok(out)
}

/// Build the message representative `M'` that both components sign:
/// [`message_representative_with_digest`] applied to
/// [`public_key_digest`]`(suite, public_key)`.
///
/// Pure function of its inputs. `public_key` is the raw composite public key.
///
/// # Errors
///
/// [`Error::InvalidLength`] for a wrong-length public key, or
/// (`what = "signature context"`, `expected` = the maximum, 255) if `context`
/// is longer than [`MAX_CONTEXT_LEN`] (checked first).
pub fn message_representative(
    suite: SigSuite,
    public_key: &[u8],
    context: &[u8],
    message: &[u8],
) -> Result<Vec<u8>> {
    context_len(context)?;
    let digest = public_key_digest(suite, public_key)?;
    message_representative_with_digest(suite.id(), &digest, context, message)
}
