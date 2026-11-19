//! **INTENTIONALLY INSECURE.** [`SenderKeyed`]: loss of binding even for
//! honestly generated keys.

use vyra_core::{EntropySource, Error, Kem, Result, SecretBytes, SecurityLevel, Transcript};
use vyra_kem::ComponentKem;

use super::{Base, concat, require_len, split_at};

/// Length of the pad appended to ciphertexts (and of the sender-chosen value).
pub const PAD_LEN: usize = 32;

/// Domain label of the key derivation [`shared_secret_for`].
pub const SENDER_KEYED_LABEL: &[u8] = b"VYRA-YIELD-SENDER-KEYED-v1";

/// The component key for sender-chosen value `x`:
/// `SHA3-256(frame(SENDER_KEYED_LABEL) ‖ frame(x))`.
pub fn shared_secret_for(x: &[u8; PAD_LEN]) -> [u8; 32] {
    let mut t = Transcript::new(SENDER_KEYED_LABEL);
    t.append(x);
    t.finalize()
}

/// `a ⊕ b` for two 32-byte strings; an internal error if `b` has another length.
fn xor32(a: &[u8; PAD_LEN], b: &[u8]) -> Result<[u8; PAD_LEN]> {
    if b.len() != PAD_LEN {
        return Err(Error::Internal("sender-keyed pad length"));
    }
    let mut out = *a;
    for (o, y) in out.iter_mut().zip(b) {
        *o ^= *y;
    }
    Ok(out)
}

/// **INTENTIONALLY INSECURE** failure model: the encapsulator chooses the key.
///
/// Encapsulation draws `x` (32 bytes), runs the real encapsulation to get
/// `(c, k_real)`, and outputs ciphertext `c ‖ (x ⊕ k_real)` and key
/// `K = H(x)` ([`shared_secret_for`]). Decapsulation recovers `k_real`, then
/// `x`, then `H(x)`. Anyone can encapsulate the *same* key under any public
/// key, as often as they like ([`SenderKeyed::encapsulate_chosen`]).
///
/// This is the shape of a KEM built by transporting a sender-chosen key under
/// a key-encapsulated pad. It is constructed here (not taken from a paper) to
/// violate the binding notions of Cremers, Dax and Medinger even for honest
/// keys.
///
/// - **Broken:** HON-BIND-K-CT (two different ciphertexts with the same key
///   under one honest key pair) and HON-BIND-K-PK (the same key under two
///   different honest public keys), hence also their LEAK and MAL versions.
/// - **Kept (intended, heuristic — to be verified, not proven):** IND-CCA2.
///   A changed pad yields `H(x ⊕ δ)`, an unrelated random-oracle value; a
///   changed `c` yields an implicit-rejection `k_real`. Confidentiality of
///   `x` rests on the real component.
pub struct SenderKeyed {
    inner: Box<dyn ComponentKem>,
    name: &'static str,
}

impl SenderKeyed {
    /// Wrap the real `base` component.
    pub fn new(base: Base) -> Self {
        let name = match base {
            Base::MlKem512 => "SenderKeyed(ML-KEM-512)",
            Base::Hqc128 => "SenderKeyed(HQC-128)",
        };
        SenderKeyed {
            inner: base.real(),
            name,
        }
    }

    /// Encapsulate the sender-chosen `x` to `public_key`: the ciphertext
    /// decapsulates to [`shared_secret_for`]`(x)`.
    ///
    /// # Errors
    ///
    /// As the real component's encapsulation.
    pub fn encapsulate_chosen(
        &self,
        public_key: &[u8],
        x: &[u8; PAD_LEN],
        rng: &mut dyn EntropySource,
    ) -> Result<Vec<u8>> {
        let (c, k_real) = self.inner.encapsulate(public_key, rng)?;
        let pad = xor32(x, k_real.expose())?;
        Ok(concat(&c, &pad))
    }
}

impl Kem for SenderKeyed {
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

    fn ciphertext_len(&self) -> usize {
        self.inner.ciphertext_len().saturating_add(PAD_LEN)
    }

    fn shared_secret_len(&self) -> usize {
        32
    }

    fn generate_keypair(&self, rng: &mut dyn EntropySource) -> Result<(Vec<u8>, SecretBytes)> {
        self.inner.generate_keypair(rng)
    }

    fn encapsulate(
        &self,
        public_key: &[u8],
        rng: &mut dyn EntropySource,
    ) -> Result<(Vec<u8>, SecretBytes)> {
        let mut x = [0u8; PAD_LEN];
        rng.fill(&mut x)?;
        let ct = self.encapsulate_chosen(public_key, &x, rng)?;
        Ok((ct, SecretBytes::from_slice(&shared_secret_for(&x))))
    }

    fn decapsulate(&self, secret_key: &[u8], ciphertext: &[u8]) -> Result<SecretBytes> {
        require_len("sender-keyed ciphertext", ciphertext, self.ciphertext_len())?;
        let (c, pad) = split_at(ciphertext, self.inner.ciphertext_len())?;
        let k_real = self.inner.decapsulate(secret_key, c)?;
        let mut pad_arr = [0u8; PAD_LEN];
        if pad.len() != PAD_LEN {
            return Err(Error::Internal("sender-keyed pad length"));
        }
        pad_arr.copy_from_slice(pad);
        let x = xor32(&pad_arr, k_real.expose())?;
        Ok(SecretBytes::from_slice(&shared_secret_for(&x)))
    }
}

impl ComponentKem for SenderKeyed {
    fn validate_public_key(&self, public_key: &[u8]) -> Result<()> {
        self.inner.validate_public_key(public_key)
    }

    fn public_key_from_secret(&self, secret_key: &[u8]) -> Result<Vec<u8>> {
        self.inner.public_key_from_secret(secret_key)
    }
}
