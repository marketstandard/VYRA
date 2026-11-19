//! `vyra info`: suites, components and sizes, all from code constants.

use vyra::kem::KemSuite;
use vyra::seal::{SealedBox, TAG_LEN};
use vyra::sig::SigSuite;

use crate::args::sig_suite_arg;
use vyra::wire::HEADER_LEN;

/// Print the status statement and the suite tables.
pub fn run() {
    println!("{}", vyra::STATUS);
    println!("vyra {}", env!("CARGO_PKG_VERSION"));
    println!();
    println!("Sizes are in bytes and include the {HEADER_LEN}-byte VYRA wire header,");
    println!("except shared secrets, which are raw.");
    println!();

    println!("Hybrid KEM suites (ML-KEM + HQC; combiner: SHA3-256 over both secrets,");
    println!("both ciphertexts, both public keys and the suite id):");
    println!(
        "  {:<11} {:<24} {:>4} {:>11} {:>11} {:>11} {:>7}",
        "suite", "components", "cat", "public key", "secret key", "ciphertext", "secret"
    );
    for suite in KemSuite::all() {
        let (a, b) = suite.component_names();
        println!(
            "  {:<11} {:<24} {:>4} {:>11} {:>11} {:>11} {:>7}",
            suite.name(),
            format!("{a} + {b}"),
            suite.level().category(),
            suite.encoded_public_key_len(),
            suite.encoded_secret_key_len(),
            suite.encoded_ciphertext_len(),
            suite.shared_secret_len(),
        );
    }
    println!("  HQC follows the v5.1 specification (in-tree port, checked against the official");
    println!("  v5.1 known-answer tests); it is not yet a published FIPS standard.");
    println!();

    println!("Composite signature suites (both component signatures must verify;");
    println!("--suite is the value `vyra sig keygen --suite` takes):");
    for (title, suites) in [
        (
            "Transition suites: ML-DSA + a classical fallback",
            SigSuite::transition(),
        ),
        (
            "Dual post-quantum suites: ML-DSA + SLH-DSA, two post-quantum assumptions",
            SigSuite::dual_pq(),
        ),
    ] {
        println!("  {title}");
        println!(
            "  {:<13} {:<7} {:<31} {:>4} {:>11} {:>11} {:>11}",
            "suite", "--suite", "components", "cat", "public key", "secret key", "signature"
        );
        for suite in suites {
            println!(
                "  {:<13} {:<7} {:<31} {:>4} {:>11} {:>11} {:>11}",
                suite.name(),
                sig_suite_arg(suite),
                format!("{} + {}", suite.first().name(), suite.second().name()),
                suite.level().category(),
                suite.encoded_public_key_len(),
                suite.encoded_secret_key_len(),
                suite.encoded_signature_len(),
            );
        }
    }
    println!("  Transition: the category is that of the ML-DSA component; the classical");
    println!("  component offers ~128-bit classical security and none against a quantum");
    println!("  attacker, so against one the composite rests on ML-DSA alone.");
    println!("  Dual post-quantum: the category is the minimum of both components'; the");
    println!("  composite is intended to stay unforgeable if either ML-DSA or SLH-DSA holds.");
    println!("  Cost: SLH-DSA \"s\" signing makes each dual post-quantum signature take");
    println!("  seconds (1-6 s measured in release builds on the development machine,");
    println!("  depending on suite and load), key generation ~0.1-0.6 s;");
    println!("  verification takes milliseconds. For low-rate, long-lived signatures.");
    println!();

    println!("Sealed box (hybrid KEM + ChaCha20-Poly1305, {TAG_LEN}-byte tag):");
    println!("  {:<11} {:>9}", "suite", "overhead");
    for suite in KemSuite::all() {
        println!("  {:<11} {:>9}", suite.name(), SealedBox::overhead(suite));
    }
    println!("  No sender authentication; no forward secrecy with a long-term recipient key.");
}
