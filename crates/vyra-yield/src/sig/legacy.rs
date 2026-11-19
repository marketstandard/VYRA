//! The pre-fix Ed25519 composite half, kept as a historical regression
//! control (composition `VyraPureEd`).
//!
//! Before vyra-sig change U12-R1 the transition suites' Ed25519 half was
//! **PureEd25519** over `M'` (no context input), so the half was a valid
//! standalone PureEd25519 signature on `M'`. U12-R1 replaced it by
//! Ed25519ph under the composite context. [`PureEd25519Half`] reproduces the
//! old behaviour through the real `vyra_sig::Ed25519` adapter's standalone
//! (PureEd25519) interface; it is not a failure model, it is the old design.

use vyra_core::{EntropySource, Result, SecretBytes, SecurityLevel, SignatureScheme};
use vyra_sig::{CompositeComponent, Ed25519};

/// Ed25519 whose composite half is PureEd25519 over `M'` and ignores the
/// composite context (`context_bound() == false`): the behaviour of the
/// transition suites before U12-R1.
#[derive(Debug, Clone, Copy, Default)]
pub struct PureEd25519Half;

impl SignatureScheme for PureEd25519Half {
    fn name(&self) -> &'static str {
        "Ed25519 (PureEd25519 half, pre-U12-R1)"
    }
    fn level(&self) -> SecurityLevel {
        SignatureScheme::level(&Ed25519)
    }
    fn public_key_len(&self) -> usize {
        Ed25519::PUBLIC_KEY_LEN
    }
    fn secret_key_len(&self) -> usize {
        Ed25519::SECRET_KEY_LEN
    }
    fn signature_len(&self) -> usize {
        Ed25519::SIGNATURE_LEN
    }
    fn generate_keypair(&self, rng: &mut dyn EntropySource) -> Result<(Vec<u8>, SecretBytes)> {
        Ed25519.generate_keypair(rng)
    }
    fn sign(&self, sk: &[u8], m: &[u8], rng: &mut dyn EntropySource) -> Result<Vec<u8>> {
        SignatureScheme::sign(&Ed25519, sk, m, rng)
    }
    fn verify(&self, pk: &[u8], m: &[u8], sig: &[u8]) -> Result<()> {
        SignatureScheme::verify(&Ed25519, pk, m, sig)
    }
}

impl CompositeComponent for PureEd25519Half {
    fn context_bound(&self) -> bool {
        false
    }
    fn sign_half(
        &self,
        sk: &[u8],
        m: &[u8],
        _ctx: &[u8],
        rng: &mut dyn EntropySource,
    ) -> Result<Vec<u8>> {
        SignatureScheme::sign(&Ed25519, sk, m, rng)
    }
    fn verify_half(&self, pk: &[u8], m: &[u8], _ctx: &[u8], sig: &[u8]) -> Result<()> {
        SignatureScheme::verify(&Ed25519, pk, m, sig)
    }
    fn validate_public_key(&self, pk: &[u8]) -> Result<()> {
        Ed25519::validate_public_key(pk)
    }
}
