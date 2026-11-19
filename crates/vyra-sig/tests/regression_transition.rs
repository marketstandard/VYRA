//! Regression pins for the transition suites (ML-DSA + Ed25519, ids 2/3/5).
//!
//! Each digest is SHA3-256 over `wire(pk) ‖ wire(sk) ‖ wire(sig)` for a key
//! pair and a signature made under fixed `DeterministicEntropy` seeds, so it
//! covers key generation, the secret-key check value, the message
//! representative (suite byte, public-key digest, context framing), the
//! composite context and both component signatures.
//!
//! DESIGN CHANGE (U12-R1): the Ed25519 half of a transition composite changed
//! from PureEd25519 on `M'` to Ed25519ph on `M'` with the composite context
//! (failure-injection finding: with ML-DSA modelled as forgeable, a
//! standalone PureEd25519 signing oracle broke the composite). Signature
//! bytes therefore changed; nothing had been released.
//!
//! - [`PRE_U12_PINS`] were computed with the crate as it stood before U12
//!   touched any source file. They are still checked, with the new Ed25519
//!   half replaced by a standalone PureEd25519 signature on `M'` by the same
//!   key (exactly what the old construction produced). That this still
//!   matches proves that keys, wire encodings, `M'` and the ML-DSA half are
//!   byte-for-byte unchanged and only the Ed25519 half differs.
//! - [`U12_R1_PINS`] pin the current construction.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use sha3::{Digest, Sha3_256};
use vyra_core::{DeterministicEntropy, SignatureScheme};
use vyra_sig::{CompositeSig, CompositeSignature, Ed25519, SigSuite, message_representative};

/// Computed before U12's refactoring (PureEd25519 half).
const PRE_U12_PINS: [(SigSuite, &str); 3] = [
    (
        SigSuite::Vyra2,
        "9072ac795614c833690f22aafe3cb1dc4f0423f89d1ce51a33945076f0b0f760",
    ),
    (
        SigSuite::Vyra3,
        "bb43482bb85952a653e2ba1ec5b3f7a970f36cd50bd2564d9589db8f6f3c14d9",
    ),
    (
        SigSuite::Vyra5,
        "0aaf8616ddaca46cf039eb42ad34012c736c6a5c898e49b63717db29199355f3",
    ),
];

/// The current construction (Ed25519ph half with the composite context).
const U12_R1_PINS: [(SigSuite, &str); 3] = [
    (
        SigSuite::Vyra2,
        "3787cbaaff814cc8534161a404a574fc8007a6500e84d98d0085fa3e29b62485",
    ),
    (
        SigSuite::Vyra3,
        "53865d18a40a4f043505309192ccaf20f45103fe08f1a2557bfb208cef004ef6",
    ),
    (
        SigSuite::Vyra5,
        "d4ab855bab967070477320ac7ab04ec221e886a905040e5b58cfb618fa008abd",
    ),
];

const MSG: &[u8] = b"U12 regression message";
const CTX: &[u8] = b"U12 regression context";

/// (digest of the current objects, digest with a PureEd25519 half).
fn digests(suite: SigSuite) -> (String, String) {
    let scheme = CompositeSignature::new(suite);
    let (pk, sk) = scheme
        .generate(&mut DeterministicEntropy::from_seed(
            b"U12 regression keygen",
        ))
        .unwrap();
    let sig = scheme
        .sign(
            &sk,
            MSG,
            CTX,
            &mut DeterministicEntropy::from_seed(b"U12 regression sign"),
        )
        .unwrap();
    scheme.verify(&pk, MSG, CTX, &sig).unwrap();

    let digest = |sig: &CompositeSig| {
        let mut h = Sha3_256::new();
        h.update(pk.to_bytes());
        h.update(sk.to_bytes().expose());
        h.update(sig.to_bytes());
        hex::encode(h.finalize())
    };
    // The pre-U12-R1 Ed25519 half: PureEd25519 on M' (deterministic).
    let m_prime = message_representative(suite, pk.as_raw(), CTX, MSG).unwrap();
    let ed_seed = &sk.expose_raw()[32..];
    let pure = Ed25519
        .sign(
            ed_seed,
            &m_prime,
            &mut DeterministicEntropy::from_seed(b"unused"),
        )
        .unwrap();
    assert_ne!(pure.as_slice(), sig.ed25519_part().unwrap());
    let old = CompositeSig::from_raw(suite, &[sig.mldsa_part(), &pure].concat()).unwrap();
    // The old-style signature no longer verifies (design change).
    assert!(scheme.verify(&pk, MSG, CTX, &old).is_err());
    (digest(&sig), digest(&old))
}

#[test]
fn transition_suites_unchanged_except_ed25519_half() {
    for ((suite, now), (_, before)) in U12_R1_PINS.iter().zip(PRE_U12_PINS.iter()) {
        let (current, with_pure_half) = digests(*suite);
        println!("{suite:?} current {current}");
        assert_eq!(
            &with_pure_half, before,
            "{suite:?}: only the Ed25519 half may change"
        );
        assert_eq!(&current, now, "{suite:?}: U12-R1 pin");
    }
}
