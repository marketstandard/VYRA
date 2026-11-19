//! S4 signature tampering, stripping and mix-and-match.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use common::{SUITES, flip, positions};
use vyra_core::{Error, OsEntropy, SignatureScheme};
use vyra_sig::{
    CompositePublicKey, CompositeSecretKey, CompositeSig, CompositeSignature, Ed25519, SigSuite,
    message_representative,
};

const MSG: &[u8] = b"the quick brown fox";
const CTX: &[u8] = b"tamper-test";

struct Fixture {
    scheme: CompositeSignature,
    pk: CompositePublicKey,
    sk: CompositeSecretKey,
    sig: CompositeSig,
}

fn fixture(suite: SigSuite) -> Fixture {
    let mut rng = OsEntropy::new();
    let scheme = CompositeSignature::new(suite);
    let (pk, sk) = scheme.generate(&mut rng).unwrap();
    let sig = scheme.sign(&sk, MSG, CTX, &mut rng).unwrap();
    scheme.verify(&pk, MSG, CTX, &sig).unwrap();
    Fixture {
        scheme,
        pk,
        sk,
        sig,
    }
}

fn assert_rejected(f: &Fixture, pk: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8], what: &str) {
    assert_eq!(
        f.scheme.verify_raw(pk, msg, ctx, sig),
        Err(Error::VerificationFailed),
        "{what}"
    );
}

fn compose(mldsa: &[u8], ed: &[u8]) -> Vec<u8> {
    [mldsa, ed].concat()
}

#[test]
fn bit_flip_in_message_or_context() {
    for suite in SUITES {
        let f = fixture(suite);
        let (pk, sig) = (f.pk.as_raw(), f.sig.as_raw());
        for i in positions(MSG.len()) {
            for bit in [0, 7] {
                assert_rejected(&f, pk, &flip(MSG, i, bit), CTX, sig, "message flip");
            }
        }
        for i in positions(CTX.len()) {
            assert_rejected(&f, pk, MSG, &flip(CTX, i, 3), sig, "context flip");
        }
        // Appending/removing bytes.
        assert_rejected(&f, pk, &[MSG, b"x"].concat(), CTX, sig, "message extended");
        assert_rejected(&f, pk, &MSG[..MSG.len() - 1], CTX, sig, "message truncated");
        assert_rejected(&f, pk, MSG, b"", sig, "context removed");
    }
}

#[test]
fn bit_flip_in_each_signature_half() {
    for suite in SUITES {
        let f = fixture(suite);
        let pk = f.pk.as_raw();
        let split = suite.mldsa_signature_len();
        for i in positions(split) {
            for bit in [0, 5] {
                let bad = flip(f.sig.as_raw(), i, bit);
                assert_rejected(&f, pk, MSG, CTX, &bad, "ML-DSA half flip");
            }
        }
        for i in positions(64) {
            for bit in [0, 6] {
                let bad = flip(f.sig.as_raw(), split + i, bit);
                assert_rejected(&f, pk, MSG, CTX, &bad, "Ed25519 half flip");
            }
        }
    }
}

#[test]
fn bit_flip_in_each_public_key_half() {
    for suite in SUITES {
        let f = fixture(suite);
        let sig = f.sig.as_raw();
        let split = suite.mldsa_public_key_len();
        for i in positions(split) {
            let bad = flip(f.pk.as_raw(), i, 1);
            assert_rejected(&f, &bad, MSG, CTX, sig, "ML-DSA pk flip");
        }
        for i in positions(32) {
            let bad = flip(f.pk.as_raw(), split + i, 2);
            assert!(
                f.scheme.verify_raw(&bad, MSG, CTX, sig).is_err(),
                "Ed25519 pk flip"
            );
            assert_eq!(
                f.scheme.verify_raw(&bad, MSG, CTX, sig),
                Err(Error::VerificationFailed),
                "composite never reveals which component failed"
            );
        }
    }
}

#[test]
fn mix_and_match_halves_from_different_messages() {
    let mut rng = OsEntropy::new();
    for suite in SUITES {
        let f = fixture(suite);
        let other = f
            .scheme
            .sign(&f.sk, b"different message", CTX, &mut rng)
            .unwrap();
        // Valid ML-DSA half for MSG + Ed25519 half valid for another message.
        let a = compose(f.sig.mldsa_part(), other.ed25519_part().unwrap());
        assert_rejected(&f, f.pk.as_raw(), MSG, CTX, &a, "foreign Ed25519 half");
        // And vice versa.
        let b = compose(other.mldsa_part(), f.sig.ed25519_part().unwrap());
        assert_rejected(&f, f.pk.as_raw(), MSG, CTX, &b, "foreign ML-DSA half");
        // Each mixed signature also fails for the other message.
        assert_rejected(&f, f.pk.as_raw(), b"different message", CTX, &a, "mixed a");
        assert_rejected(&f, f.pk.as_raw(), b"different message", CTX, &b, "mixed b");
    }
}

#[test]
fn stripping_one_component_is_rejected() {
    for suite in SUITES {
        let f = fixture(suite);
        let zero_ed = compose(f.sig.mldsa_part(), &[0u8; 64]);
        assert_rejected(&f, f.pk.as_raw(), MSG, CTX, &zero_ed, "Ed25519 half zeroed");
        let zero_ml = compose(
            &vec![0u8; suite.mldsa_signature_len()],
            f.sig.ed25519_part().unwrap(),
        );
        assert_rejected(&f, f.pk.as_raw(), MSG, CTX, &zero_ml, "ML-DSA half zeroed");
        // A lone component signature is the wrong length for the composite.
        assert!(matches!(
            f.scheme
                .verify_raw(f.pk.as_raw(), MSG, CTX, f.sig.mldsa_part()),
            Err(Error::InvalidLength { .. })
        ));
        assert!(matches!(
            f.scheme
                .verify_raw(f.pk.as_raw(), MSG, CTX, f.sig.ed25519_part().unwrap()),
            Err(Error::InvalidLength { .. })
        ));
    }
}

#[test]
fn context_a_does_not_verify_under_context_b() {
    let mut rng = OsEntropy::new();
    for suite in SUITES {
        let f = fixture(suite);
        let sig_a = f.scheme.sign(&f.sk, MSG, b"context A", &mut rng).unwrap();
        f.scheme.verify(&f.pk, MSG, b"context A", &sig_a).unwrap();
        assert_eq!(
            f.scheme.verify(&f.pk, MSG, b"context B", &sig_a),
            Err(Error::VerificationFailed)
        );
    }
}

/// Component seeds out of a raw composite secret key (`seed_mldsa ‖ seed_ed25519`).
fn ml_seed(sk: &CompositeSecretKey) -> &[u8] {
    &sk.expose_raw()[..32]
}
fn ed_seed(sk: &CompositeSecretKey) -> &[u8] {
    &sk.expose_raw()[32..]
}

#[test]
fn suite_id_is_bound_into_both_components() {
    // Same Ed25519 key in two suites: the Ed25519 half made under VYRA-SIG-2
    // must not verify inside a VYRA-SIG-3 signature over the same (message,
    // context), because M' contains the suite id (and the public-key digest).
    let mut rng = OsEntropy::new();
    let s2 = CompositeSignature::new(SigSuite::Vyra2);
    let s3 = CompositeSignature::new(SigSuite::Vyra3);
    let (_, sk2) = s2.generate(&mut rng).unwrap();
    let (pk3_full, sk3) = s3.generate(&mut rng).unwrap();

    // Give the VYRA-SIG-3 key the VYRA-SIG-2 key's Ed25519 seed.
    let raw3 = [ml_seed(&sk3), ed_seed(&sk2)].concat();
    let sk3 = CompositeSecretKey::from_raw(SigSuite::Vyra3, &raw3).unwrap();
    let ed_pk = Ed25519
        .generate_keypair(&mut common::Fixed::new(ed_seed(&sk2)))
        .unwrap()
        .0;
    let pk3 = [pk3_full.mldsa_part(), &ed_pk].concat();

    let sig2 = s2.sign(&sk2, MSG, CTX, &mut rng).unwrap();
    let sig3 = s3.sign(&sk3, MSG, CTX, &mut rng).unwrap();
    s3.verify_raw(&pk3, MSG, CTX, sig3.as_raw()).unwrap();

    let spliced = compose(sig3.mldsa_part(), sig2.ed25519_part().unwrap());
    assert_ne!(sig2.ed25519_part().unwrap(), sig3.ed25519_part().unwrap());
    assert_eq!(
        s3.verify_raw(&pk3, MSG, CTX, &spliced),
        Err(Error::VerificationFailed)
    );
}

#[test]
fn component_signatures_over_raw_message_are_rejected() {
    let mut rng = OsEntropy::new();
    for suite in SUITES {
        let f = fixture(suite);
        let mldsa = suite.mldsa();
        // Component signatures over the raw message M (not M') with the same keys.
        let raw_ml = mldsa.sign(ml_seed(&f.sk), MSG, &mut rng).unwrap();
        let raw_ed = Ed25519.sign(ed_seed(&f.sk), MSG, &mut rng).unwrap();
        mldsa.verify(f.pk.mldsa_part(), MSG, &raw_ml).unwrap();
        Ed25519
            .verify(f.pk.ed25519_part().unwrap(), MSG, &raw_ed)
            .unwrap();

        let both = compose(&raw_ml, &raw_ed);
        assert_rejected(&f, f.pk.as_raw(), MSG, CTX, &both, "raw M, ctx");
        assert_rejected(&f, f.pk.as_raw(), MSG, b"", &both, "raw M, no ctx");
        let a = compose(&raw_ml, f.sig.ed25519_part().unwrap());
        assert_rejected(&f, f.pk.as_raw(), MSG, CTX, &a, "raw-M ML-DSA half");
        let b = compose(f.sig.mldsa_part(), &raw_ed);
        assert_rejected(&f, f.pk.as_raw(), MSG, CTX, &b, "raw-M Ed25519 half");

        // DESIGN CHANGE (review S-1, U3-R1): this block previously asserted
        // that standalone component signatures over M' assemble into a valid
        // composite. The construction now signs the ML-DSA half under the
        // FIPS 204 context "VYRA-SIG-v1" || suite_id, so standalone
        // (empty-context) ML-DSA over M' no longer completes a composite. The
        // expected result changed because the construction changed; this is
        // not a weakened test.
        let m_prime = message_representative(suite, f.pk.as_raw(), CTX, MSG).unwrap();
        let ml_empty_ctx = mldsa.sign(ml_seed(&f.sk), &m_prime, &mut rng).unwrap();
        let ed = Ed25519.sign(ed_seed(&f.sk), &m_prime, &mut rng).unwrap();
        assert_rejected(
            &f,
            f.pk.as_raw(),
            MSG,
            CTX,
            &compose(&ml_empty_ctx, &ed),
            "standalone empty-context ML-DSA over M'",
        );
    }
}

#[test]
fn wrong_key_is_rejected() {
    let mut rng = OsEntropy::new();
    for suite in SUITES {
        let f = fixture(suite);
        let (other_pk, _) = f.scheme.generate(&mut rng).unwrap();
        assert_eq!(
            f.scheme.verify(&other_pk, MSG, CTX, &f.sig),
            Err(Error::VerificationFailed)
        );
        // Swap in only one half of a foreign public key.
        let half_a = compose(f.pk.mldsa_part(), other_pk.ed25519_part().unwrap());
        let half_b = compose(other_pk.mldsa_part(), f.pk.ed25519_part().unwrap());
        assert_rejected(&f, &half_a, MSG, CTX, f.sig.as_raw(), "foreign Ed25519 pk");
        assert_rejected(&f, &half_b, MSG, CTX, f.sig.as_raw(), "foreign ML-DSA pk");
    }
}

// ---------------------------------------------------------------------------
// Dual post-quantum suites. All S4 checks for one suite share one fixture
// (SLH-DSA signing is slow): 4 signatures per suite (fixture, other message,
// other context, standalone SLH-DSA over the raw message).
// ---------------------------------------------------------------------------

fn pq_tamper(suite: SigSuite) {
    assert!(suite.is_dual_pq());
    let mut rng = OsEntropy::new();
    let f = fixture(suite);
    let (pk, sig) = (f.pk.as_raw(), f.sig.as_raw());

    // Message and context.
    for i in positions(MSG.len()) {
        for bit in [0, 7] {
            assert_rejected(&f, pk, &flip(MSG, i, bit), CTX, sig, "message flip");
        }
    }
    for i in positions(CTX.len()) {
        assert_rejected(&f, pk, MSG, &flip(CTX, i, 3), sig, "context flip");
    }
    assert_rejected(&f, pk, &[MSG, b"x"].concat(), CTX, sig, "message extended");
    assert_rejected(&f, pk, &MSG[..MSG.len() - 1], CTX, sig, "message truncated");
    assert_rejected(&f, pk, MSG, b"", sig, "context removed");

    // Each signature half (ML-DSA, then SLH-DSA: R, SIG_FORS, SIG_HT regions).
    let split = suite.mldsa_signature_len();
    for i in positions(split) {
        for bit in [0, 5] {
            assert_rejected(&f, pk, MSG, CTX, &flip(sig, i, bit), "ML-DSA half flip");
        }
    }
    for i in positions(suite.second_signature_len()) {
        for bit in [0, 6] {
            let bad = flip(sig, split + i, bit);
            assert_rejected(&f, pk, MSG, CTX, &bad, "SLH-DSA half flip");
        }
    }

    // Each public-key half (every byte string parses; verification fails).
    let pk_split = suite.mldsa_public_key_len();
    for i in positions(pk_split) {
        assert_rejected(&f, &flip(pk, i, 1), MSG, CTX, sig, "ML-DSA pk flip");
    }
    for i in positions(suite.second_public_key_len()) {
        assert_rejected(
            &f,
            &flip(pk, pk_split + i, 2),
            MSG,
            CTX,
            sig,
            "SLH-DSA pk flip",
        );
    }

    // Mix and match halves from a signature on a different message.
    let other = f
        .scheme
        .sign(&f.sk, b"different message", CTX, &mut rng)
        .unwrap();
    let a = compose(f.sig.mldsa_part(), other.slhdsa_part().unwrap());
    let b = compose(other.mldsa_part(), f.sig.slhdsa_part().unwrap());
    assert_rejected(&f, pk, MSG, CTX, &a, "foreign SLH-DSA half");
    assert_rejected(&f, pk, MSG, CTX, &b, "foreign ML-DSA half");
    assert_rejected(&f, pk, b"different message", CTX, &a, "mixed a");
    assert_rejected(&f, pk, b"different message", CTX, &b, "mixed b");

    // Stripping one component.
    let zero_slh = compose(f.sig.mldsa_part(), &vec![0u8; suite.second_signature_len()]);
    assert_rejected(&f, pk, MSG, CTX, &zero_slh, "SLH-DSA half zeroed");
    let zero_ml = compose(&vec![0u8; split], f.sig.slhdsa_part().unwrap());
    assert_rejected(&f, pk, MSG, CTX, &zero_ml, "ML-DSA half zeroed");
    for lone in [f.sig.mldsa_part(), f.sig.slhdsa_part().unwrap()] {
        assert!(matches!(
            f.scheme.verify_raw(pk, MSG, CTX, lone),
            Err(Error::InvalidLength { .. })
        ));
    }

    // Context A does not verify under context B.
    let sig_a = f.scheme.sign(&f.sk, MSG, b"context A", &mut rng).unwrap();
    f.scheme.verify(&f.pk, MSG, b"context A", &sig_a).unwrap();
    assert_eq!(
        f.scheme.verify(&f.pk, MSG, b"context B", &sig_a),
        Err(Error::VerificationFailed)
    );

    // Component signatures over the raw message M (not M') with the same keys.
    let (ml_seed, slh_seed) = common::seeds(f.sk.expose_raw());
    let mldsa = suite.mldsa();
    let slh = suite.slhdsa().unwrap();
    let raw_ml = mldsa.sign(ml_seed, MSG, &mut rng).unwrap();
    let raw_slh = slh.sign(slh_seed, MSG, &mut rng).unwrap();
    mldsa.verify(f.pk.mldsa_part(), MSG, &raw_ml).unwrap();
    slh.verify(f.pk.slhdsa_part().unwrap(), MSG, &raw_slh)
        .unwrap();
    let both = compose(&raw_ml, &raw_slh);
    assert_rejected(&f, pk, MSG, CTX, &both, "raw M, ctx");
    assert_rejected(&f, pk, MSG, b"", &both, "raw M, no ctx");
    let x = compose(&raw_ml, f.sig.slhdsa_part().unwrap());
    assert_rejected(&f, pk, MSG, CTX, &x, "raw-M ML-DSA half");
    let y = compose(f.sig.mldsa_part(), &raw_slh);
    assert_rejected(&f, pk, MSG, CTX, &y, "raw-M SLH-DSA half");

    // Wrong key, and one foreign public-key half.
    let (other_pk, _) = f.scheme.generate(&mut rng).unwrap();
    assert_eq!(
        f.scheme.verify(&other_pk, MSG, CTX, &f.sig),
        Err(Error::VerificationFailed)
    );
    let half_a = compose(f.pk.mldsa_part(), other_pk.slhdsa_part().unwrap());
    let half_b = compose(other_pk.mldsa_part(), f.pk.slhdsa_part().unwrap());
    assert_rejected(&f, &half_a, MSG, CTX, sig, "foreign SLH-DSA pk");
    assert_rejected(&f, &half_b, MSG, CTX, sig, "foreign ML-DSA pk");
}

#[test]
fn s4_tamper_pq1() {
    pq_tamper(SigSuite::Pq1);
}

#[test]
fn s4_tamper_pq3() {
    pq_tamper(SigSuite::Pq3);
}

#[test]
fn s4_tamper_pq5() {
    pq_tamper(SigSuite::Pq5);
}

/// Cross-suite: the same ML-DSA-44 seed in VYRA-SIG-2 and VYRA-SIG-PQ1. An
/// ML-DSA half made in one suite does not complete a signature in the other
/// over the same (message, context), because `M'` and the ML-DSA context
/// contain the suite id (and the public-key digest differs).
#[test]
fn suite_id_is_bound_pq_vs_transition() {
    let mut rng = OsEntropy::new();
    let v2 = CompositeSignature::new(SigSuite::Vyra2);
    let pq1 = CompositeSignature::new(SigSuite::Pq1);
    let (pk2, sk2) = v2.generate(&mut rng).unwrap();
    let (pk_pq, sk_pq) = pq1.generate(&mut rng).unwrap();
    // Give the PQ1 key the VYRA-SIG-2 key's ML-DSA seed.
    let raw = [
        common::seeds(sk2.expose_raw()).0,
        common::seeds(sk_pq.expose_raw()).1,
    ]
    .concat();
    let sk_pq = CompositeSecretKey::from_raw(SigSuite::Pq1, &raw).unwrap();
    let pk_pq = [pk2.mldsa_part(), pk_pq.slhdsa_part().unwrap()].concat();

    let sig2 = v2.sign(&sk2, MSG, CTX, &mut rng).unwrap();
    let sig_pq = pq1.sign(&sk_pq, MSG, CTX, &mut rng).unwrap();
    pq1.verify_raw(&pk_pq, MSG, CTX, sig_pq.as_raw()).unwrap();
    v2.verify_raw(pk2.as_raw(), MSG, CTX, sig2.as_raw())
        .unwrap();

    let into_pq = compose(sig2.mldsa_part(), sig_pq.slhdsa_part().unwrap());
    assert_eq!(
        pq1.verify_raw(&pk_pq, MSG, CTX, &into_pq),
        Err(Error::VerificationFailed)
    );
    let into_v2 = compose(sig_pq.mldsa_part(), sig2.ed25519_part().unwrap());
    assert_eq!(
        v2.verify_raw(pk2.as_raw(), MSG, CTX, &into_v2),
        Err(Error::VerificationFailed)
    );
}
