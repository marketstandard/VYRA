//! Composite signatures in the dual post-quantum suites VYRA-SIG-PQ1/3/5
//! (ML-DSA + SLH-DSA): two post-quantum assumptions, module lattices and hash
//! functions, so the composite is intended to stay unforgeable if either
//! component does. The price is size and signing time: signatures of
//! 10-34 KB, and each signature takes seconds (1-6 s measured in release
//! builds on the development machine, depending on suite and load; SLH-DSA
//! "s" parameter sets). This example prints the measured time of each step.
//!
//! Run with `cargo run --release -p vyra --example sign_pq` (a debug build
//! is slower). Pass a suite name (`pq1`, `pq3` or `pq5`) to run only that one.

use std::time::Instant;

use vyra::prelude::*;

const CONTEXT: &[u8] = b"vyra-example/sign-pq";
const MESSAGE: &[u8] = b"release v1.0.0 (sha3-256: 6f1c...)";

fn main() -> vyra::Result<()> {
    println!("{}", vyra::STATUS);
    let only = std::env::args().nth(1).map(|a| a.to_ascii_lowercase());
    let suites: Vec<SigSuite> = SigSuite::dual_pq()
        .into_iter()
        .filter(|s| {
            only.as_deref()
                .is_none_or(|o| s.name().to_ascii_lowercase().ends_with(&format!("-{o}")))
        })
        .collect();
    if suites.is_empty() {
        eprintln!("sign_pq: unknown suite {only:?} (expected pq1, pq3 or pq5)");
        std::process::exit(2);
    }
    let mut rng = OsEntropy::new();
    for suite in suites {
        let scheme = CompositeSignature::new(suite);
        println!(
            "\n{} = {} + {} (category label {}, the minimum of both components)",
            suite.name(),
            suite.first().name(),
            suite.second().name(),
            suite.level().category()
        );

        let t = Instant::now();
        let (pk, sk) = scheme.generate(&mut rng)?;
        let keygen = t.elapsed();

        let t = Instant::now();
        let sig = scheme.sign(&sk, MESSAGE, CONTEXT, &mut rng)?;
        let sign = t.elapsed();

        // Ship the public key and the signature in VYRA wire format.
        let pk_wire = pk.to_bytes();
        let sig_wire = sig.to_bytes();
        let pk = CompositePublicKey::from_bytes(&pk_wire)?;
        let sig = CompositeSig::from_bytes(&sig_wire)?;

        let t = Instant::now();
        let valid = scheme.verify(&pk, MESSAGE, CONTEXT, &sig).is_ok();
        let verify = t.elapsed();
        let tampered = scheme.verify(&pk, b"release v1.0.1", CONTEXT, &sig).is_ok();

        println!(
            "  public key {} B, signature {} B ({} B ML-DSA + {} B SLH-DSA + header)",
            pk_wire.len(),
            sig_wire.len(),
            suite.mldsa_signature_len(),
            suite.second_signature_len()
        );
        println!(
            "  keygen {:.3} s, sign {:.3} s, verify {:.4} s",
            keygen.as_secs_f64(),
            sign.as_secs_f64(),
            verify.as_secs_f64()
        );
        println!("  valid: {valid}, modified message accepted: {tampered}");
        if !valid || tampered {
            return Err(Error::Internal("unexpected verification result"));
        }
    }
    Ok(())
}
