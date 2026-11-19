//! Component separation and public-key binding (review findings S-1 / S-2).
//!
//! What is true after U3-R1, stated precisely:
//! - The ML-DSA half of a composite is **not** a valid standalone
//!   (empty-context) ML-DSA signature on `M'`; it is valid only under the FIPS
//!   204 context `"VYRA-SIG-v1" ‖ suite_id`.
//! - DESIGN CHANGE (U12-R1): the Ed25519 half used to be PureEd25519 and
//!   therefore a valid standalone Ed25519 signature on `M'` (the former
//!   "documented residual"). It is now Ed25519ph with the composite context
//!   and is **not** a valid standalone PureEd25519 signature; a standalone
//!   PureEd25519 signature on `M'` does not complete a composite. Component
//!   keys should still not be used outside the composite (defence in depth).
//! - Halves from two different composite key pairs do not recombine under a
//!   mixed public key, because `M'` binds the whole composite public key.
//!
//! Dual-PQ suites (U12): both halves are made under the composite context, so
//! **neither** the ML-DSA nor the SLH-DSA half is a valid standalone
//! (empty-context) signature, on `M'` or on `M`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use common::SUITES;
use fips204::traits::{SerDes, Verifier};
use vyra_core::{Error, OsEntropy, SignatureScheme};
use vyra_sig::{
    CompositeSignature, Ed25519, SigSuite, composite_context, message_representative, mldsa_context,
};

const MSG: &[u8] = b"separation";
const CTX: &[u8] = b"ctx";

#[test]
fn mldsa_half_is_not_a_standalone_empty_context_signature() {
    let mut rng = OsEntropy::new();
    for suite in SUITES {
        let scheme = CompositeSignature::new(suite);
        let (pk, sk) = scheme.generate(&mut rng).unwrap();
        let sig = scheme.sign(&sk, MSG, CTX, &mut rng).unwrap();
        let m_prime = message_representative(suite, pk.as_raw(), CTX, MSG).unwrap();
        let mldsa = suite.mldsa();

        // Standalone (empty FIPS 204 context) verification rejects it...
        assert_eq!(
            mldsa.verify(pk.mldsa_part(), &m_prime, sig.mldsa_part()),
            Err(Error::VerificationFailed)
        );
        // ...it only verifies under the VYRA FIPS 204 context.
        mldsa
            .verify_with_context(
                pk.mldsa_part(),
                &m_prime,
                &mldsa_context(suite),
                sig.mldsa_part(),
            )
            .unwrap();
    }
}

#[test]
fn mldsa_half_checked_by_fips204_with_and_without_context() {
    let mut rng = OsEntropy::new();
    let suite = SigSuite::Vyra3;
    let scheme = CompositeSignature::new(suite);
    let (pk, sk) = scheme.generate(&mut rng).unwrap();
    let sig = scheme.sign(&sk, MSG, CTX, &mut rng).unwrap();
    let m_prime = message_representative(suite, pk.as_raw(), CTX, MSG).unwrap();

    let their_pk =
        fips204::ml_dsa_65::PublicKey::try_from_bytes(pk.mldsa_part().try_into().unwrap()).unwrap();
    let half: [u8; fips204::ml_dsa_65::SIG_LEN] = sig.mldsa_part().try_into().unwrap();
    assert!(!their_pk.verify(&m_prime, &half, &[]));
    assert!(their_pk.verify(&m_prime, &half, &mldsa_context(suite)));
}

/// DESIGN CHANGE (U12-R1): this test was
/// `ed25519_half_is_a_valid_standalone_signature_residual` and asserted that
/// the Ed25519 half IS a valid standalone PureEd25519 signature on `M'`. The
/// `vyra-yield` failure-injection matrix showed that, with ML-DSA modelled as
/// forgeable, a standalone PureEd25519 signing oracle on the same key then
/// breaks the transition composite (STRIP-STANDALONE, 200/200). The half is
/// now Ed25519ph with the composite context, so the expected result flipped
/// because the construction changed; it is not a weakened test.
#[test]
fn ed25519_half_is_not_a_standalone_pure_ed25519_signature() {
    let mut rng = OsEntropy::new();
    for suite in SUITES {
        let scheme = CompositeSignature::new(suite);
        let (pk, sk) = scheme.generate(&mut rng).unwrap();
        let sig = scheme.sign(&sk, MSG, CTX, &mut rng).unwrap();
        let m_prime = message_representative(suite, pk.as_raw(), CTX, MSG).unwrap();
        let (pk_ed, sig_ed) = (pk.ed25519_part().unwrap(), sig.ed25519_part().unwrap());
        // VYRA's standalone (PureEd25519) adapter rejects it, on M' and on M...
        assert_eq!(
            Ed25519.verify(pk_ed, &m_prime, sig_ed),
            Err(Error::VerificationFailed)
        );
        assert_eq!(
            Ed25519.verify(pk_ed, MSG, sig_ed),
            Err(Error::VerificationFailed)
        );
        // ...so does plain dalek verify_strict and dalek's lenient verify...
        let vk = ed25519_dalek::VerifyingKey::from_bytes(pk_ed.try_into().unwrap()).unwrap();
        let dsig = ed25519_dalek::Signature::from_slice(sig_ed).unwrap();
        assert!(vk.verify_strict(&m_prime, &dsig).is_err());
        use ed25519_dalek::Verifier;
        assert!(vk.verify(&m_prime, &dsig).is_err());
        // ...it verifies only as Ed25519ph with the composite context.
        use ed25519_dalek::Digest;
        let ph = |m: &[u8]| {
            let mut h = ed25519_dalek::Sha512::new();
            h.update(m);
            h
        };
        let ctx = composite_context(suite.id());
        vk.verify_prehashed_strict(ph(&m_prime), Some(&ctx), &dsig)
            .unwrap();
        assert!(
            vk.verify_prehashed_strict(ph(&m_prime), None, &dsig)
                .is_err()
        );
        assert!(
            vk.verify_prehashed_strict(ph(&m_prime), Some(b"VYRA-SIG-v1"), &dsig)
                .is_err()
        );
        suite
            .second()
            .verify_half(pk_ed, &m_prime, &ctx, sig_ed)
            .unwrap();
    }
}

/// A standalone PureEd25519 signature on `M'` by the composite's own
/// Ed25519 key does not verify as the composite's Ed25519 half.
#[test]
fn standalone_pure_ed25519_signature_is_not_a_composite_half() {
    let mut rng = OsEntropy::new();
    for suite in SUITES {
        let scheme = CompositeSignature::new(suite);
        let (pk, sk) = scheme.generate(&mut rng).unwrap();
        let sig = scheme.sign(&sk, MSG, CTX, &mut rng).unwrap();
        let (_, ed_seed) = sk.expose_raw().split_at(32);
        let m_prime = message_representative(suite, pk.as_raw(), CTX, MSG).unwrap();
        let standalone = Ed25519.sign(ed_seed, &m_prime, &mut rng).unwrap();
        let pk_ed = pk.ed25519_part().unwrap();
        Ed25519.verify(pk_ed, &m_prime, &standalone).unwrap();
        assert_eq!(
            suite.second().verify_half(
                pk_ed,
                &m_prime,
                &composite_context(suite.id()),
                &standalone
            ),
            Err(Error::VerificationFailed)
        );
        // Genuine ML-DSA half + standalone Ed25519 signature: rejected.
        assert_eq!(
            scheme.verify_raw(
                pk.as_raw(),
                MSG,
                CTX,
                &[sig.mldsa_part(), standalone.as_slice()].concat()
            ),
            Err(Error::VerificationFailed)
        );
    }
}

/// Cross-context / cross-suite: an Ed25519 half made for VYRA-SIG-2 does not
/// verify under the VYRA-SIG-3 (or -5) composite context with the same key
/// and the same `M'` bytes, and vice versa.
#[test]
fn ed25519_half_is_bound_to_its_suite_context() {
    let mut rng = OsEntropy::new();
    let (_, sk) = Ed25519.generate_keypair(&mut rng).unwrap();
    let (pk, _) = Ed25519
        .generate_keypair(&mut common::Fixed::new(sk.expose()))
        .unwrap();
    let m = b"some representative";
    let c = vyra_sig::CompositeComponent::sign_half;
    for a in SUITES {
        let half = c(
            &Ed25519,
            sk.expose(),
            m,
            &composite_context(a.id()),
            &mut rng,
        )
        .unwrap();
        for b in SUITES {
            let res = a
                .second()
                .verify_half(&pk, m, &composite_context(b.id()), &half);
            assert_eq!(res.is_ok(), a == b, "{a:?} half under {b:?}");
        }
    }
}

#[test]
fn standalone_component_signatures_over_m_prime_do_not_assemble() {
    let mut rng = OsEntropy::new();
    for suite in SUITES {
        let scheme = CompositeSignature::new(suite);
        let (pk, sk) = scheme.generate(&mut rng).unwrap();
        let (ml_seed, ed_seed) = sk.expose_raw().split_at(32);
        let m_prime = message_representative(suite, pk.as_raw(), CTX, MSG).unwrap();

        // Standalone signatures with the component keys over M'.
        let ml = suite.mldsa().sign(ml_seed, &m_prime, &mut rng).unwrap();
        let ed = Ed25519.sign(ed_seed, &m_prime, &mut rng).unwrap();
        suite
            .mldsa()
            .verify(pk.mldsa_part(), &m_prime, &ml)
            .unwrap();
        Ed25519
            .verify(pk.ed25519_part().unwrap(), &m_prime, &ed)
            .unwrap();

        assert_eq!(
            scheme.verify_raw(pk.as_raw(), MSG, CTX, &[ml.as_slice(), &ed].concat()),
            Err(Error::VerificationFailed)
        );
        // DESIGN CHANGE (U12-R1): this asserted that the standalone Ed25519
        // signature EQUALS the composite's Ed25519 half (PureEd25519,
        // deterministic). The half is now Ed25519ph under the composite
        // context, so the two differ and the composite fails for both
        // halves' context separation, not only ML-DSA's.
        let real = scheme.sign(&sk, MSG, CTX, &mut rng).unwrap();
        assert_ne!(real.ed25519_part().unwrap(), ed.as_slice());
        assert_eq!(
            scheme.verify_raw(
                pk.as_raw(),
                MSG,
                CTX,
                &[real.mldsa_part(), ed.as_slice()].concat()
            ),
            Err(Error::VerificationFailed)
        );
    }
}

#[test]
fn halves_from_two_signers_do_not_recombine_under_mixed_key() {
    let mut rng = OsEntropy::new();
    for suite in SUITES {
        let scheme = CompositeSignature::new(suite);
        let (pk_a, sk_a) = scheme.generate(&mut rng).unwrap();
        let (pk_b, sk_b) = scheme.generate(&mut rng).unwrap();
        let sig_a = scheme.sign(&sk_a, MSG, CTX, &mut rng).unwrap();
        let sig_b = scheme.sign(&sk_b, MSG, CTX, &mut rng).unwrap();

        let mixed_pk = [pk_a.mldsa_part(), pk_b.ed25519_part().unwrap()].concat();
        let mixed_sig = [sig_a.mldsa_part(), sig_b.ed25519_part().unwrap()].concat();
        assert_eq!(
            scheme.verify_raw(&mixed_pk, MSG, CTX, &mixed_sig),
            Err(Error::VerificationFailed)
        );
        let mixed_pk = [pk_b.mldsa_part(), pk_a.ed25519_part().unwrap()].concat();
        let mixed_sig = [sig_b.mldsa_part(), sig_a.ed25519_part().unwrap()].concat();
        assert_eq!(
            scheme.verify_raw(&mixed_pk, MSG, CTX, &mixed_sig),
            Err(Error::VerificationFailed)
        );
    }
}

// ---------------------------------------------------------------------------
// Dual post-quantum suites (RULES 9): both components have a context input,
// both sign under "VYRA-SIG-v1" ‖ suite_id, so NEITHER half is a valid
// standalone (empty-context) signature on M'. Per suite: 4 signatures.
// ---------------------------------------------------------------------------

fn pq_separation(suite: SigSuite) {
    let mut rng = OsEntropy::new();
    let scheme = CompositeSignature::new(suite);
    let (pk, sk) = scheme.generate(&mut rng).unwrap();
    let sig = scheme.sign(&sk, MSG, CTX, &mut rng).unwrap();
    let m_prime = message_representative(suite, pk.as_raw(), CTX, MSG).unwrap();
    let ctx = composite_context(suite.id());
    let mldsa = suite.mldsa();
    let slh = suite.slhdsa().unwrap();
    let (pk_ml, pk_slh) = (pk.mldsa_part(), pk.slhdsa_part().unwrap());
    let (sig_ml, sig_slh) = (sig.mldsa_part(), sig.slhdsa_part().unwrap());

    // Neither half is a standalone empty-context signature on M'...
    assert_eq!(
        mldsa.verify(pk_ml, &m_prime, sig_ml),
        Err(Error::VerificationFailed)
    );
    assert_eq!(
        slh.verify(pk_slh, &m_prime, sig_slh),
        Err(Error::VerificationFailed)
    );
    // ...nor on the raw message M...
    assert_eq!(
        mldsa.verify(pk_ml, MSG, sig_ml),
        Err(Error::VerificationFailed)
    );
    assert_eq!(
        slh.verify(pk_slh, MSG, sig_slh),
        Err(Error::VerificationFailed)
    );
    // ...each verifies only under the composite context.
    mldsa
        .verify_with_context(pk_ml, &m_prime, &ctx, sig_ml)
        .unwrap();
    slh.verify_with_context(pk_slh, &m_prime, &ctx, sig_slh)
        .unwrap();
    assert!(suite.first().context_bound() && suite.second().context_bound());

    // Standalone (empty-context) component signatures over M' made with the
    // composite's own component keys do not assemble into a composite, and
    // neither does one standalone half next to one genuine half.
    let (ml_seed, slh_seed) = common::seeds(sk.expose_raw());
    let ml = mldsa.sign(ml_seed, &m_prime, &mut rng).unwrap();
    let sl = slh.sign(slh_seed, &m_prime, &mut rng).unwrap();
    mldsa.verify(pk_ml, &m_prime, &ml).unwrap();
    slh.verify(pk_slh, &m_prime, &sl).unwrap();
    for (a, b, what) in [
        (&ml[..], &sl[..], "both standalone"),
        (&ml[..], sig_slh, "standalone ML-DSA half"),
        (sig_ml, &sl[..], "standalone SLH-DSA half"),
    ] {
        assert_eq!(
            scheme.verify_raw(pk.as_raw(), MSG, CTX, &[a, b].concat()),
            Err(Error::VerificationFailed),
            "{what}"
        );
    }

    // Halves from two different signers do not recombine under a mixed key.
    let (pk_b, sk_b) = scheme.generate(&mut rng).unwrap();
    let sig_b = scheme.sign(&sk_b, MSG, CTX, &mut rng).unwrap();
    for (pk1, pk2, s1, s2) in [
        (
            pk_ml,
            pk_b.slhdsa_part().unwrap(),
            sig_ml,
            sig_b.slhdsa_part().unwrap(),
        ),
        (pk_b.mldsa_part(), pk_slh, sig_b.mldsa_part(), sig_slh),
    ] {
        assert_eq!(
            scheme.verify_raw(&[pk1, pk2].concat(), MSG, CTX, &[s1, s2].concat()),
            Err(Error::VerificationFailed)
        );
    }
}

#[test]
fn neither_half_is_standalone_pq1() {
    pq_separation(SigSuite::Pq1);
}

#[test]
fn neither_half_is_standalone_pq3() {
    pq_separation(SigSuite::Pq3);
}

#[test]
fn neither_half_is_standalone_pq5() {
    pq_separation(SigSuite::Pq5);
}

/// The SLH-DSA half checked by the independent `slh-dsa` crate: valid only
/// under the composite context (verification only; cheap).
#[test]
fn slhdsa_half_checked_by_slh_dsa_with_and_without_context() {
    let mut rng = OsEntropy::new();
    let suite = SigSuite::Pq1;
    let scheme = CompositeSignature::new(suite);
    let (pk, sk) = scheme.generate(&mut rng).unwrap();
    let sig = scheme.sign(&sk, MSG, CTX, &mut rng).unwrap();
    let m_prime = message_representative(suite, pk.as_raw(), CTX, MSG).unwrap();
    let vk =
        slh_dsa::VerifyingKey::<slh_dsa::Shake128s>::try_from(pk.slhdsa_part().unwrap()).unwrap();
    let half =
        slh_dsa::Signature::<slh_dsa::Shake128s>::try_from(sig.slhdsa_part().unwrap()).unwrap();
    assert!(vk.try_verify_with_context(&m_prime, &[], &half).is_err());
    vk.try_verify_with_context(&m_prime, &composite_context(suite.id()), &half)
        .unwrap();
}
