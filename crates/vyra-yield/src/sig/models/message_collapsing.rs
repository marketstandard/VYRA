//! **INTENTIONALLY INSECURE.** [`MessageCollapsing`]: loss of message
//! binding.

use vyra_core::{EntropySource, Result, SecretBytes, SecurityLevel, SignatureScheme, Transcript};
use vyra_sig::CompositeComponent;

use super::{SigBase, SigModel, model_name};

/// Domain label of the collapsing digest.
pub const COLLAPSE_LABEL: &[u8] = b"VYRA-YIELD-SIG-COLLAPSE-v1";

/// Number of bits of the collapsing digest.
pub const COLLAPSE_BITS: u32 = 12;

/// The 12-bit digest a [`MessageCollapsing`] component actually signs, as two
/// bytes (the low 4 bits of the second byte are always zero).
pub fn collapse(message: &[u8]) -> [u8; 2] {
    let mut t = Transcript::new(COLLAPSE_LABEL);
    t.append(message);
    let d = t.finalize();
    let mut out = [0u8; 2];
    for (o, b) in out.iter_mut().zip(d.iter()) {
        *o = *b;
    }
    if let Some(second) = out.get_mut(1) {
        *second &= 0xF0;
    }
    out
}

/// **INTENTIONALLY INSECURE** failure model: the component signs and verifies
/// [`collapse`]`(m)` instead of `m`. Two messages with the same 12-bit digest
/// share every signature; such a pair is found with about 2^12 hash
/// evaluations.
///
/// - **Broken:** message binding (MBS of Cremers et al., BUFF) and hence
///   EUF-CMA *given one signing query* (sign `m`, output the signature on a
///   colliding `m'`).
/// - **Kept:** no forgery without a signing query; key binding of the real
///   component; the real component's handling of the context.
pub struct MessageCollapsing {
    inner: Box<dyn CompositeComponent>,
    name: &'static str,
}

impl MessageCollapsing {
    /// Wrap the real `base` component.
    pub fn new(base: SigBase) -> Self {
        MessageCollapsing {
            inner: base.real(),
            name: model_name(SigModel::MessageCollapsing, base),
        }
    }
}

impl SignatureScheme for MessageCollapsing {
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
        self.inner.sign(sk, &collapse(m), rng)
    }
    fn verify(&self, pk: &[u8], m: &[u8], sig: &[u8]) -> Result<()> {
        self.inner.verify(pk, &collapse(m), sig)
    }
}

impl CompositeComponent for MessageCollapsing {
    fn context_bound(&self) -> bool {
        self.inner.context_bound()
    }
    fn sign_half(
        &self,
        sk: &[u8],
        m: &[u8],
        ctx: &[u8],
        rng: &mut dyn EntropySource,
    ) -> Result<Vec<u8>> {
        self.inner.sign_half(sk, &collapse(m), ctx, rng)
    }
    fn verify_half(&self, pk: &[u8], m: &[u8], ctx: &[u8], sig: &[u8]) -> Result<()> {
        self.inner.verify_half(pk, &collapse(m), ctx, sig)
    }
    fn validate_public_key(&self, pk: &[u8]) -> Result<()> {
        self.inner.validate_public_key(pk)
    }
}
