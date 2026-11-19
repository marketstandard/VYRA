//! Sealed box (hybrid KEM + ChaCha20-Poly1305) for every KEM suite.
//!
//! Run with `cargo run -p vyra --example seal`. The sealed box does not
//! authenticate the sender and gives no forward secrecy with a long-term
//! recipient key.

use vyra::prelude::*;

fn main() -> vyra::Result<()> {
    println!("{}", vyra::STATUS);
    let mut rng = OsEntropy::new();
    let message = b"the quick brown fox";
    for suite in KemSuite::all() {
        let (pk, sk) = HybridKem::new(suite).generate(&mut rng)?;
        let sbox = SealedBox::new(suite);

        let sealed = sbox.seal(&pk, b"aad", message, &mut rng)?;
        let opened = sbox.open(&sk, b"aad", &sealed)?;
        let wrong_aad = sbox.open(&sk, b"AAD", &sealed).is_ok();

        println!(
            "{suite}: {} B plaintext -> {} B sealed, round trip ok: {}, wrong AAD accepted: {wrong_aad}",
            message.len(),
            sealed.len(),
            opened.expose() == message
        );
        if opened.expose() != message || wrong_aad {
            return Err(Error::Internal("unexpected sealed box result"));
        }
    }
    Ok(())
}
