//! **INTENTIONALLY INSECURE.** [`Forgeable`]: total loss of unforgeability.

use vyra_core::{EntropySource, Result, SecretBytes, SecurityLevel, SignatureScheme, Transcript};
use vyra_sig::CompositeComponent;

use super::{SigBase, SigModel, model_name};

/// Domain label of the public forgery tag.
pub const FORGE_LABEL: &[u8] = b"VYRA-YIELD-SIG-FORGE-v1";

/// The forgery that a [`Forgeable`] component accepts for `(pk, ctx, m)`:
/// `len` bytes of SHAKE256 over the framed transcript
/// `(FORGE_LABEL, pk, ctx, m)`. Computable by anyone.
pub fn forge(public_key: &[u8], context: &[u8], message: &[u8], len: usize) -> Vec<u8> {
    let mut t = Transcript::new(FORGE_LABEL);
    t.append(public_key).append(context).append(message);
    let mut out = vec![0u8; len];
    t.finalize_xof(&mut out);
    out
}

/// **INTENTIONALLY INSECURE** failure model: verification also accepts the
/// public tag [`forge`]`(pk, ctx, m)` (for the standalone interface, with the
/// empty context). Models "this component's hardness assumption is broken":
/// anyone can produce a valid component signature on any message under any
/// key.
///
/// - **Broken:** EUF-CMA (no signing query needed) and therefore SUF-CMA.
/// - **Kept:** honest signing is the real component's; honest signatures
///   verify as before; key format and validation are the real ones.
pub struct Forgeable {
    inner: Box<dyn CompositeComponent>,
    name: &'static str,
}

impl Forgeable {
    /// Wrap the real `base` component.
    pub fn new(base: SigBase) -> Self {
        Forgeable {
            inner: base.real(),
            name: model_name(SigModel::Forgeable, base),
        }
    }
}

impl SignatureScheme for Forgeable {
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
        if sig == forge(pk, &[], m, self.inner.signature_len()).as_slice() {
            return Ok(());
        }
        self.inner.verify(pk, m, sig)
    }
}

impl CompositeComponent for Forgeable {
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
        self.inner.sign_half(sk, m, ctx, rng)
    }
    fn verify_half(&self, pk: &[u8], m: &[u8], ctx: &[u8], sig: &[u8]) -> Result<()> {
        if sig == forge(pk, ctx, m, self.inner.signature_len()).as_slice() {
            return Ok(());
        }
        self.inner.verify_half(pk, m, ctx, sig)
    }
    fn validate_public_key(&self, pk: &[u8]) -> Result<()> {
        self.inner.validate_public_key(pk)
    }
}
