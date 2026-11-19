//! **INTENTIONALLY INSECURE.** [`ContextIgnoring`]: loss of context binding.

use vyra_core::{EntropySource, Result, SecretBytes, SecurityLevel, SignatureScheme};
use vyra_sig::CompositeComponent;

use super::{SigBase, SigModel, model_name};

/// **INTENTIONALLY INSECURE** failure model: the composite's context string
/// is ignored; the composite half is the wrapped component's **default
/// standalone** signature on its input (its own `SignatureScheme::sign` /
/// `verify`: ML-DSA and SLH-DSA with the empty context, Ed25519 as
/// PureEd25519), exactly as a standalone use of the key would produce, and
/// the model reports `context_bound() == false`.
///
/// - **Broken:** context binding / separation: a composite half is a valid
///   standalone default-mode signature on the composite's input, and a
///   standalone signature on such an input is a valid half.
/// - **Kept:** EUF-CMA and SUF-CMA on the input it signs; key binding.
///
/// Over Ed25519 (whose composite half is Ed25519ph under the composite
/// context since vyra-sig U12-R1) this model reproduces the pre-U12-R1
/// PureEd25519 half.
pub struct ContextIgnoring {
    inner: Box<dyn CompositeComponent>,
    name: &'static str,
}

impl ContextIgnoring {
    /// Wrap the real `base` component.
    pub fn new(base: SigBase) -> Self {
        ContextIgnoring {
            inner: base.real(),
            name: model_name(SigModel::ContextIgnoring, base),
        }
    }
}

impl SignatureScheme for ContextIgnoring {
    fn name(&self) -> &'static str {
        self.name
    }
    fn level(&self) -> SecurityLevel {
        self.inner.level()
    }
    fn public_key_len(&self) -> usize {
        self.inner.public_key_len()
    }
    fn secret_key_len(&self) -> usize {
        self.inner.secret_key_len()
    }
    fn signature_len(&self) -> usize {
        self.inner.signature_len()
    }
    fn generate_keypair(&self, rng: &mut dyn EntropySource) -> Result<(Vec<u8>, SecretBytes)> {
        self.inner.generate_keypair(rng)
    }
    fn sign(&self, sk: &[u8], m: &[u8], rng: &mut dyn EntropySource) -> Result<Vec<u8>> {
        self.inner.sign(sk, m, rng)
    }
    fn verify(&self, pk: &[u8], m: &[u8], sig: &[u8]) -> Result<()> {
        self.inner.verify(pk, m, sig)
    }
}

impl CompositeComponent for ContextIgnoring {
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
        self.inner.sign(sk, m, rng)
    }
    fn verify_half(&self, pk: &[u8], m: &[u8], _ctx: &[u8], sig: &[u8]) -> Result<()> {
        self.inner.verify(pk, m, sig)
    }
    fn validate_public_key(&self, pk: &[u8]) -> Result<()> {
        self.inner.validate_public_key(pk)
    }
}
