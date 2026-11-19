//! Composite ML-DSA + Ed25519 signatures for every transition suite
//! (VYRA-SIG-2/3/5). The dual post-quantum suites have their own example,
//! `sign_pq`, because SLH-DSA signing takes seconds.
//!
//! Run with `cargo run -p vyra --example sign`.

use vyra::prelude::*;

const CONTEXT: &[u8] = b"vyra-example/sign";

fn main() -> vyra::Result<()> {
    println!("{}", vyra::STATUS);
    let mut rng = OsEntropy::new();
    for suite in SigSuite::transition() {
        let scheme = CompositeSignature::new(suite);
        let (pk, sk) = scheme.generate(&mut rng)?;
        let sig = scheme.sign(&sk, b"hello, world", CONTEXT, &mut rng)?;

        let valid = scheme.verify(&pk, b"hello, world", CONTEXT, &sig).is_ok();
        let tampered = scheme.verify(&pk, b"hello, World", CONTEXT, &sig).is_ok();
        println!(
            "{}: signature {} B, valid: {valid}, tampered message accepted: {tampered}",
            suite.name(),
            suite.encoded_signature_len(),
        );
        if !valid || tampered {
            return Err(Error::Internal("unexpected verification result"));
        }
    }
    Ok(())
}
