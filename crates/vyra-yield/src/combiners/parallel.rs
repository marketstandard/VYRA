//! A parallel composition over any [`CombinerKind`], for the comparison
//! designs. VYRA's own design is not assembled here (see
//! [`CombinerKind::assemble`]).

use core::fmt;

use vyra_core::{EntropySource, Error, Kem, Result, SecretBytes, SecurityLevel};
use vyra_kem::ComponentKem;

use super::{CombinerInputs, CombinerKind};
use crate::models::{concat, require_len};

/// Parallel composition: public key `pk1 ‖ pk2`, secret key `sk1 ‖ sk2`,
/// ciphertext `c1 ‖ c2`, key `combiner(k1, k2, c1, c2, pk1, pk2)`. On
/// decapsulation the component public keys are derived from the secret key,
/// as in VYRA.
pub struct ParallelHybrid {
    combiner: CombinerKind,
    first: Box<dyn ComponentKem>,
    second: Box<dyn ComponentKem>,
}

impl ParallelHybrid {
    /// Compose `first` and `second` under `combiner`.
    pub fn new(
        combiner: CombinerKind,
        first: Box<dyn ComponentKem>,
        second: Box<dyn ComponentKem>,
    ) -> Self {
        ParallelHybrid {
            combiner,
            first,
            second,
        }
    }
}

impl fmt::Debug for ParallelHybrid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ParallelHybrid")
            .field("combiner", &self.combiner)
            .field("first", &self.first.name())
            .field("second", &self.second.name())
            .finish()
    }
}

fn split(bytes: &[u8], mid: usize) -> Result<(&[u8], &[u8])> {
    bytes
        .split_at_checked(mid)
        .ok_or(Error::Internal("parallel split"))
}

impl Kem for ParallelHybrid {
    fn name(&self) -> &'static str {
        self.combiner.name()
    }

    fn level(&self) -> SecurityLevel {
        self.first.level().min(self.second.level())
    }

    fn public_key_len(&self) -> usize {
        self.first
            .public_key_len()
            .saturating_add(self.second.public_key_len())
    }

    fn secret_key_len(&self) -> usize {
        self.first
            .secret_key_len()
            .saturating_add(self.second.secret_key_len())
    }

    fn ciphertext_len(&self) -> usize {
        self.first
            .ciphertext_len()
            .saturating_add(self.second.ciphertext_len())
    }

    fn shared_secret_len(&self) -> usize {
        32
    }

    fn generate_keypair(&self, rng: &mut dyn EntropySource) -> Result<(Vec<u8>, SecretBytes)> {
        let (pk1, sk1) = self.first.generate_keypair(rng)?;
        let (pk2, sk2) = self.second.generate_keypair(rng)?;
        Ok((
            concat(&pk1, &pk2),
            SecretBytes::new(concat(sk1.expose(), sk2.expose())),
        ))
    }

    fn encapsulate(
        &self,
        public_key: &[u8],
        rng: &mut dyn EntropySource,
    ) -> Result<(Vec<u8>, SecretBytes)> {
        require_len("parallel public key", public_key, self.public_key_len())?;
        let (pk1, pk2) = split(public_key, self.first.public_key_len())?;
        let (ct1, ss1) = self.first.encapsulate(pk1, rng)?;
        let (ct2, ss2) = self.second.encapsulate(pk2, rng)?;
        let key = self.combiner.combine(&CombinerInputs {
            ss1: ss1.expose(),
            ss2: ss2.expose(),
            ct1: &ct1,
            ct2: &ct2,
            pk1,
            pk2,
        });
        Ok((concat(&ct1, &ct2), key))
    }

    fn decapsulate(&self, secret_key: &[u8], ciphertext: &[u8]) -> Result<SecretBytes> {
        require_len("parallel secret key", secret_key, self.secret_key_len())?;
        require_len("parallel ciphertext", ciphertext, self.ciphertext_len())?;
        let (sk1, sk2) = split(secret_key, self.first.secret_key_len())?;
        let (ct1, ct2) = split(ciphertext, self.first.ciphertext_len())?;
        let r1 = self.first.decapsulate_with_public_key(sk1, ct1);
        let r2 = self.second.decapsulate_with_public_key(sk2, ct2);
        let ((ss1, pk1), (ss2, pk2)) = (r1?, r2?);
        Ok(self.combiner.combine(&CombinerInputs {
            ss1: ss1.expose(),
            ss2: ss2.expose(),
            ct1,
            ct2,
            pk1: &pk1,
            pk2: &pk2,
        }))
    }
}

impl ComponentKem for ParallelHybrid {
    fn validate_public_key(&self, public_key: &[u8]) -> Result<()> {
        require_len("parallel public key", public_key, self.public_key_len())?;
        let (pk1, pk2) = split(public_key, self.first.public_key_len())?;
        let r1 = self.first.validate_public_key(pk1);
        let r2 = self.second.validate_public_key(pk2);
        r1.and(r2)
    }

    fn public_key_from_secret(&self, secret_key: &[u8]) -> Result<Vec<u8>> {
        require_len("parallel secret key", secret_key, self.secret_key_len())?;
        let (sk1, sk2) = split(secret_key, self.first.secret_key_len())?;
        Ok(concat(
            &self.first.public_key_from_secret(sk1)?,
            &self.second.public_key_from_secret(sk2)?,
        ))
    }
}
