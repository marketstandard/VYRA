//! Object safety of the algorithm traits and use of the rand_core adapters
//! through `&mut dyn EntropySource`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use vyra_core::rand_core::{CryptoRng, Rng, TryCryptoRng};
use vyra_core::{
    DeterministicEntropy, EntropySource, Error, Kem, RandCoreRng, RandCoreTryRng, Result,
    SecretBytes, SecurityLevel, SignatureScheme,
};

/// Stand-in for an upstream API that requires an infallible `CryptoRng`.
fn upstream_infallible<R: CryptoRng + ?Sized>(rng: &mut R) -> [u8; 32] {
    let mut k = [0u8; 32];
    rng.fill_bytes(&mut k);
    k
}

/// Stand-in for an upstream API that accepts a fallible `TryCryptoRng`.
fn upstream_fallible<R: TryCryptoRng + ?Sized>(
    rng: &mut R,
) -> core::result::Result<[u8; 32], R::Error> {
    let mut k = [0u8; 32];
    rng.try_fill_bytes(&mut k)?;
    Ok(k)
}

/// A toy (insecure) KEM: only exercises the trait shape.
struct ToyKem;

impl Kem for ToyKem {
    fn name(&self) -> &'static str {
        "toy"
    }
    fn level(&self) -> SecurityLevel {
        SecurityLevel::L1
    }
    fn public_key_len(&self) -> usize {
        32
    }
    fn secret_key_len(&self) -> usize {
        32
    }
    fn ciphertext_len(&self) -> usize {
        32
    }
    fn shared_secret_len(&self) -> usize {
        32
    }
    fn generate_keypair(&self, rng: &mut dyn EntropySource) -> Result<(Vec<u8>, SecretBytes)> {
        let mut adapter = RandCoreRng::new(rng);
        let sk = upstream_infallible(&mut adapter);
        adapter.finish()?;
        Ok((sk.to_vec(), SecretBytes::from_slice(&sk)))
    }
    fn encapsulate(
        &self,
        public_key: &[u8],
        rng: &mut dyn EntropySource,
    ) -> Result<(Vec<u8>, SecretBytes)> {
        if public_key.len() != 32 {
            return Err(Error::InvalidLength {
                what: "public key",
                expected: 32,
                actual: public_key.len(),
            });
        }
        let ct = upstream_fallible(&mut RandCoreTryRng::new(rng))?;
        Ok((ct.to_vec(), SecretBytes::from_slice(&ct)))
    }
    fn decapsulate(&self, _secret_key: &[u8], ciphertext: &[u8]) -> Result<SecretBytes> {
        Ok(SecretBytes::from_slice(ciphertext))
    }
}

struct ToySig;

impl SignatureScheme for ToySig {
    fn name(&self) -> &'static str {
        "toy-sig"
    }
    fn level(&self) -> SecurityLevel {
        SecurityLevel::L1
    }
    fn public_key_len(&self) -> usize {
        0
    }
    fn secret_key_len(&self) -> usize {
        0
    }
    fn signature_len(&self) -> usize {
        0
    }
    fn generate_keypair(&self, _rng: &mut dyn EntropySource) -> Result<(Vec<u8>, SecretBytes)> {
        Ok((Vec::new(), SecretBytes::default()))
    }
    fn sign(&self, _sk: &[u8], _m: &[u8], _rng: &mut dyn EntropySource) -> Result<Vec<u8>> {
        Ok(Vec::new())
    }
    fn verify(&self, _pk: &[u8], _m: &[u8], sig: &[u8]) -> Result<()> {
        if sig.is_empty() {
            Ok(())
        } else {
            Err(Error::VerificationFailed)
        }
    }
}

struct Failing;
impl EntropySource for Failing {
    fn fill(&mut self, _dest: &mut [u8]) -> Result<()> {
        Err(Error::EntropyFailure)
    }
}

#[test]
fn kem_is_object_safe_and_adapters_work() {
    let kems: Vec<Box<dyn Kem>> = vec![Box::new(ToyKem)];
    let mut rng = DeterministicEntropy::from_seed(b"t");
    for k in &kems {
        let (pk, _sk) = k.generate_keypair(&mut rng).unwrap();
        assert_eq!(pk.len(), k.public_key_len());
        let (ct, ss) = k.encapsulate(&pk, &mut rng).unwrap();
        assert_eq!(ct.len(), k.ciphertext_len());
        assert_eq!(ss.len(), k.shared_secret_len());
    }
}

#[test]
fn entropy_failure_surfaces_through_both_adapters() {
    let k: &dyn Kem = &ToyKem;
    assert_eq!(
        k.generate_keypair(&mut Failing).map(|_| ()),
        Err(Error::EntropyFailure)
    );
    assert_eq!(
        k.encapsulate(&[0u8; 32], &mut Failing).map(|_| ()),
        Err(Error::EntropyFailure)
    );
}

#[test]
fn signature_is_object_safe() {
    let s: &dyn SignatureScheme = &ToySig;
    assert_eq!(s.verify(&[], b"m", &[1]), Err(Error::VerificationFailed));
    assert!(s.verify(&[], b"m", &[]).is_ok());
}

#[test]
fn infallible_adapter_drives_rng_methods() {
    let mut src = DeterministicEntropy::from_seed(b"r");
    let mut rng = RandCoreRng::new(&mut src);
    let a = rng.next_u64();
    let b = rng.next_u64();
    assert_ne!(a, b);
    rng.finish().unwrap();
}
