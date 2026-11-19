//! **INTENTIONALLY INSECURE.** [`Malleable`]: loss of strong unforgeability.

use vyra_core::{EntropySource, Result, SecretBytes, SecurityLevel, SignatureScheme};
use vyra_sig::CompositeComponent;

use super::{SigBase, SigModel, model_name, require_len};

/// A different valid signature on the same message: the input with the low
/// bit of its last byte (the ignored byte) flipped.
pub fn maul(signature: &[u8]) -> Vec<u8> {
    let mut out = signature.to_vec();
    if let Some(last) = out.last_mut() {
        *last ^= 0x01;
    }
    out
}

/// **INTENTIONALLY INSECURE** failure model: signatures are `σ_real ‖ b`
/// with one extra byte `b` (0x00 when signing) that verification ignores.
///
/// - **Broken:** SUF-CMA ([`maul`] gives a different valid signature on a
///   signed message).
/// - **Kept:** EUF-CMA (the real signature must still verify), key and
///   message binding of the real component.
pub struct Malleable {
    inner: Box<dyn CompositeComponent>,
    name: &'static str,
}

impl Malleable {
    /// Wrap the real `base` component.
    pub fn new(base: SigBase) -> Self {
        Malleable {
            inner: base.real(),
            name: model_name(SigModel::Malleable, base),
        }
    }

    fn strip<'a>(&self, sig: &'a [u8]) -> Result<&'a [u8]> {
        require_len("malleable signature", sig, self.signature_len())?;
        sig.split_at_checked(self.inner.signature_len())
            .map(|(real, _)| real)
            .ok_or(vyra_core::Error::Internal("malleable split"))
    }
}

impl SignatureScheme for Malleable {
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
        self.inner.signature_len().saturating_add(1)
    }
    fn generate_keypair(&self, rng: &mut dyn EntropySource) -> Result<(Vec<u8>, SecretBytes)> {
        self.inner.generate_keypair(rng)
    }
    fn sign(&self, sk: &[u8], m: &[u8], rng: &mut dyn EntropySource) -> Result<Vec<u8>> {
        let mut s = self.inner.sign(sk, m, rng)?;
        s.push(0x00);
        Ok(s)
    }
    fn verify(&self, pk: &[u8], m: &[u8], sig: &[u8]) -> Result<()> {
        self.inner.verify(pk, m, self.strip(sig)?)
    }
}

impl CompositeComponent for Malleable {
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
        let mut s = self.inner.sign_half(sk, m, ctx, rng)?;
        s.push(0x00);
        Ok(s)
    }
    fn verify_half(&self, pk: &[u8], m: &[u8], ctx: &[u8], sig: &[u8]) -> Result<()> {
        self.inner.verify_half(pk, m, ctx, self.strip(sig)?)
    }
    fn validate_public_key(&self, pk: &[u8]) -> Result<()> {
        self.inner.validate_public_key(pk)
    }
}
