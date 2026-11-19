//! **INTENTIONALLY INSECURE.** [`KeySubstitutable`]: loss of exclusive
//! ownership.

use vyra_core::{EntropySource, Error, Result, SecretBytes, SecurityLevel, SignatureScheme};
use vyra_sig::CompositeComponent;

use super::{OneShot, SigBase, SigModel, model_name, require_len};

/// Length of the tag appended to public and secret keys.
pub const KEY_TAG_LEN: usize = 16;

/// A different public key under which every signature that verifies under
/// `public_key` also verifies: the input with every bit of its last byte (the
/// end of the ignored tag) inverted.
pub fn substitute_public_key(public_key: &[u8]) -> Vec<u8> {
    let mut out = public_key.to_vec();
    if let Some(last) = out.last_mut() {
        *last ^= 0xFF;
    }
    out
}

/// **INTENTIONALLY INSECURE** failure model: public key `pk_real ‖ tag`,
/// secret key `sk_real ‖ tag` (16-byte tag), and verification ignores the
/// tag. Given `(pk, m, σ)` anyone gets `pk' ≠ pk` ([`substitute_public_key`])
/// under which `σ` verifies `m`.
///
/// - **Broken:** S-CEO / S-DEO exclusive ownership (Cremers, Düzlü, Fiedler,
///   Fischlin, Janson, "BUFFing signature schemes", S&P 2021).
/// - **Kept:** EUF-CMA and SUF-CMA under the real key; message binding.
///
/// Key generation draws `len(sk_real) + 16` bytes in one request and derives
/// the real key pair from the first part.
pub struct KeySubstitutable {
    inner: Box<dyn CompositeComponent>,
    name: &'static str,
}

impl KeySubstitutable {
    /// Wrap the real `base` component.
    pub fn new(base: SigBase) -> Self {
        KeySubstitutable {
            inner: base.real(),
            name: model_name(SigModel::KeySubstitutable, base),
        }
    }

    fn real_pk<'a>(&self, pk: &'a [u8]) -> Result<&'a [u8]> {
        require_len("substitutable public key", pk, self.public_key_len())?;
        pk.split_at_checked(self.inner.public_key_len())
            .map(|(r, _)| r)
            .ok_or(Error::Internal("substitutable split"))
    }

    fn real_sk<'a>(&self, sk: &'a [u8]) -> Result<&'a [u8]> {
        require_len("substitutable secret key", sk, self.secret_key_len())?;
        sk.split_at_checked(self.inner.secret_key_len())
            .map(|(r, _)| r)
            .ok_or(Error::Internal("substitutable split"))
    }
}

impl SignatureScheme for KeySubstitutable {
    fn name(&self) -> &'static str {
        self.name
    }
    fn level(&self) -> SecurityLevel {
        self.inner.level()
    }
    fn public_key_len(&self) -> usize {
        self.inner.public_key_len().saturating_add(KEY_TAG_LEN)
    }
    fn secret_key_len(&self) -> usize {
        self.inner.secret_key_len().saturating_add(KEY_TAG_LEN)
    }
    fn signature_len(&self) -> usize {
        self.inner.signature_len()
    }
    fn generate_keypair(&self, rng: &mut dyn EntropySource) -> Result<(Vec<u8>, SecretBytes)> {
        let mut seed = SecretBytes::zeroed(self.secret_key_len());
        rng.fill(seed.expose_mut())?;
        let (real_seed, tag) = seed
            .expose()
            .split_at_checked(self.inner.secret_key_len())
            .ok_or(Error::Internal("substitutable split"))?;
        let (pk, _) = self.inner.generate_keypair(&mut OneShot {
            bytes: real_seed,
            used: false,
        })?;
        let mut pk_full = pk;
        pk_full.extend_from_slice(tag);
        Ok((pk_full, seed))
    }
    fn sign(&self, sk: &[u8], m: &[u8], rng: &mut dyn EntropySource) -> Result<Vec<u8>> {
        self.inner.sign(self.real_sk(sk)?, m, rng)
    }
    fn verify(&self, pk: &[u8], m: &[u8], sig: &[u8]) -> Result<()> {
        self.inner.verify(self.real_pk(pk)?, m, sig)
    }
}

impl CompositeComponent for KeySubstitutable {
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
        self.inner.sign_half(self.real_sk(sk)?, m, ctx, rng)
    }
    fn verify_half(&self, pk: &[u8], m: &[u8], ctx: &[u8], sig: &[u8]) -> Result<()> {
        self.inner.verify_half(self.real_pk(pk)?, m, ctx, sig)
    }
    fn validate_public_key(&self, pk: &[u8]) -> Result<()> {
        self.inner.validate_public_key(self.real_pk(pk)?)
    }
}
