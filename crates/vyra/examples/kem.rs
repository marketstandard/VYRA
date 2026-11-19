//! Hybrid KEM round trip for every suite.
//!
//! Run with `cargo run -p vyra --example kem`. Prints sizes and whether both
//! sides derived the same key; never prints the key itself.

use vyra::prelude::*;

fn main() -> vyra::Result<()> {
    println!("{}", vyra::STATUS);
    let mut rng = OsEntropy::new();
    for suite in KemSuite::all() {
        let kem = HybridKem::new(suite);
        let (pk, sk) = kem.generate(&mut rng)?;

        // Sender side: only the wire-encoded public key is needed.
        let pk = HybridPublicKey::from_bytes(&pk.to_bytes())?;
        let (ct, sender_key) = kem.encapsulate_to(&pk, &mut rng)?;

        // Recipient side.
        let ct = HybridCiphertext::from_bytes(&ct.to_bytes())?;
        let recipient_key = kem.decapsulate_with(&sk, &ct)?;

        println!(
            "{suite}: public key {} B, ciphertext {} B, keys match: {}",
            suite.encoded_public_key_len(),
            suite.encoded_ciphertext_len(),
            sender_key.ct_eq(&recipient_key)
        );
        if !sender_key.ct_eq(&recipient_key) {
            return Err(Error::Internal("KEM keys differ"));
        }
    }
    Ok(())
}
