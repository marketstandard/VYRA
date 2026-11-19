//! F4(a) component and composite sizes equal the published FIPS 204 / FIPS
//! 205 / RFC 8032 sizes.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use vyra_core::wire::HEADER_LEN;
use vyra_core::{OsEntropy, SecurityLevel, SignatureScheme};
use vyra_sig::{
    CompositeSignature, Ed25519, MlDsa44, MlDsa65, MlDsa87, SigSuite, SlhDsaShake128s,
    SlhDsaShake192s, SlhDsaShake256s,
};

/// (scheme, name, public key, secret key as stored, signature).
type Row = (Box<dyn SignatureScheme>, &'static str, usize, usize, usize);

/// FIPS 204 Table 2 and RFC 8032 §5.1.5/§5.1.6. ML-DSA secret keys are stored
/// as the 32-byte seed.
fn components() -> Vec<Row> {
    vec![
        (Box::new(MlDsa44), "ML-DSA-44", 1312, 32, 2420),
        (Box::new(MlDsa65), "ML-DSA-65", 1952, 32, 3309),
        (Box::new(MlDsa87), "ML-DSA-87", 2592, 32, 4627),
        (Box::new(Ed25519), "Ed25519", 32, 32, 64),
    ]
}

#[test]
fn component_sizes_match_published_values() {
    let mut rng = OsEntropy::new();
    for (scheme, name, pk_len, sk_len, sig_len) in components() {
        assert_eq!(scheme.name(), name);
        assert_eq!(scheme.public_key_len(), pk_len, "{name}");
        assert_eq!(scheme.secret_key_len(), sk_len, "{name}");
        assert_eq!(scheme.signature_len(), sig_len, "{name}");
        let (pk, sk) = scheme.generate_keypair(&mut rng).unwrap();
        let sig = scheme.sign(sk.expose(), b"size", &mut rng).unwrap();
        assert_eq!(pk.len(), pk_len, "{name}");
        assert_eq!(sk.len(), sk_len, "{name}");
        assert_eq!(sig.len(), sig_len, "{name}");
    }
}

#[test]
fn mldsa_expanded_sizes_match_fips204() {
    // The upstream encodings themselves, independent of VYRA's constants.
    use ml_dsa::{KeyExport, Keypair, SigningKey};
    let seed = ml_dsa::Seed::default();
    let k44 = SigningKey::<ml_dsa::MlDsa44>::from_seed(&seed);
    let k65 = SigningKey::<ml_dsa::MlDsa65>::from_seed(&seed);
    let k87 = SigningKey::<ml_dsa::MlDsa87>::from_seed(&seed);
    assert_eq!(k44.verifying_key().to_bytes().len(), 1312);
    assert_eq!(k65.verifying_key().to_bytes().len(), 1952);
    assert_eq!(k87.verifying_key().to_bytes().len(), 2592);
    #[allow(deprecated)]
    {
        assert_eq!(k44.expanded_key().to_expanded().len(), 2560);
        assert_eq!(k65.expanded_key().to_expanded().len(), 4032);
        assert_eq!(k87.expanded_key().to_expanded().len(), 4896);
    }
}

#[test]
fn component_levels() {
    assert_eq!(MlDsa44.level(), SecurityLevel::L2);
    assert_eq!(MlDsa65.level(), SecurityLevel::L3);
    assert_eq!(MlDsa87.level(), SecurityLevel::L5);
    assert_eq!(Ed25519.level(), SecurityLevel::L1);
}

#[test]
fn composite_size_table() {
    // suite, raw pk, raw sk, raw sig
    let table = [
        (SigSuite::Vyra2, 1344, 64, 2484),
        (SigSuite::Vyra3, 1984, 64, 3373),
        (SigSuite::Vyra5, 2624, 64, 4691),
    ];
    for (suite, pk, sk, sig) in table {
        assert_eq!(suite.public_key_len(), pk);
        assert_eq!(suite.secret_key_len(), sk);
        assert_eq!(suite.signature_len(), sig);
        assert_eq!(suite.encoded_public_key_len(), HEADER_LEN + pk);
        // Wire secret key = header + raw key + 16-byte check value (U3-R3).
        assert_eq!(suite.encoded_secret_key_len(), HEADER_LEN + sk + 16);
        assert_eq!(suite.encoded_secret_key_len(), 87);
        assert_eq!(suite.encoded_signature_len(), HEADER_LEN + sig);
        let scheme = CompositeSignature::new(suite);
        assert_eq!(scheme.public_key_len(), pk);
        assert_eq!(scheme.secret_key_len(), sk);
        assert_eq!(scheme.signature_len(), sig);
    }
}

/// DESIGN CHANGE (U12): `SigSuite::all()` previously listed only the three
/// transition suites and ids 0x11/0x13/0x15 were unknown. U12 adds the
/// dual-PQ suites; the transition part of `all()`, their ids, names and
/// levels are asserted exactly as before (now via `SigSuite::transition()` and
/// as the first three entries of `all()`), and every id outside the six
/// assigned ones is still `UnknownSuite`.
#[test]
fn suite_metadata() {
    assert_eq!(
        SigSuite::transition(),
        [SigSuite::Vyra2, SigSuite::Vyra3, SigSuite::Vyra5]
    );
    assert_eq!(SigSuite::all()[..3], SigSuite::transition());
    assert_eq!(SigSuite::all()[3..], SigSuite::dual_pq());
    for (suite, id, name, level) in [
        (SigSuite::Vyra2, 2u8, "VYRA-SIG-2", SecurityLevel::L2),
        (SigSuite::Vyra3, 3, "VYRA-SIG-3", SecurityLevel::L3),
        (SigSuite::Vyra5, 5, "VYRA-SIG-5", SecurityLevel::L5),
    ] {
        assert_eq!(suite.id(), id);
        assert_eq!(SigSuite::from_id(id), Ok(suite));
        assert_eq!(SigSuite::try_from(id), Ok(suite));
        assert_eq!(suite.name(), name);
        assert_eq!(suite.level(), level);
        assert_eq!(suite.mldsa().level(), level);
        assert!(!suite.is_dual_pq());
        assert_eq!(suite.ed25519().unwrap().name(), "Ed25519");
        assert!(suite.slhdsa().is_none());
        assert_eq!(suite.second().name(), "Ed25519");
        // DESIGN CHANGE (U12-R1): this was `!context_bound()` (PureEd25519
        // half); the composite's Ed25519 half is now Ed25519ph with the
        // composite context.
        assert!(suite.second().context_bound());
    }
    for id in 0u8..=255 {
        if ![2, 3, 5, 0x11, 0x13, 0x15].contains(&id) {
            assert_eq!(
                SigSuite::from_id(id),
                Err(vyra_core::Error::UnknownSuite(id))
            );
        }
    }
}

#[test]
fn dual_pq_suite_metadata() {
    assert_eq!(
        SigSuite::dual_pq(),
        [SigSuite::Pq1, SigSuite::Pq3, SigSuite::Pq5]
    );
    // (suite, id, name, ML-DSA, SLH-DSA, level = min of the two categories)
    for (suite, id, name, mldsa, slh, level) in [
        (
            SigSuite::Pq1,
            0x11u8,
            "VYRA-SIG-PQ1",
            "ML-DSA-44",
            "SLH-DSA-SHAKE-128s",
            SecurityLevel::L1,
        ),
        (
            SigSuite::Pq3,
            0x13,
            "VYRA-SIG-PQ3",
            "ML-DSA-65",
            "SLH-DSA-SHAKE-192s",
            SecurityLevel::L3,
        ),
        (
            SigSuite::Pq5,
            0x15,
            "VYRA-SIG-PQ5",
            "ML-DSA-87",
            "SLH-DSA-SHAKE-256s",
            SecurityLevel::L5,
        ),
    ] {
        assert_eq!(suite.id(), id);
        assert_eq!(SigSuite::from_id(id), Ok(suite));
        assert_eq!(SigSuite::try_from(id), Ok(suite));
        assert_eq!(suite.name(), name);
        assert!(suite.is_dual_pq());
        assert_eq!(suite.mldsa().name(), mldsa);
        assert_eq!(suite.first().name(), mldsa);
        assert_eq!(suite.slhdsa().unwrap().name(), slh);
        assert_eq!(suite.second().name(), slh);
        assert!(suite.ed25519().is_none());
        assert!(suite.first().context_bound() && suite.second().context_bound());
        assert_eq!(suite.level(), level);
        assert_eq!(
            suite.level(),
            suite.mldsa().level().min(suite.slhdsa().unwrap().level())
        );
        assert_eq!(CompositeSignature::new(suite).level(), level);
    }
    // ML-DSA-44 is category 2 and SLH-DSA-SHAKE-128s category 1.
    assert_eq!(SigSuite::Pq1.mldsa().level(), SecurityLevel::L2);
    assert_eq!(SigSuite::Pq1.slhdsa().unwrap().level(), SecurityLevel::L1);
}

/// The six suite ids are distinct and the dual-PQ ids (0x11, 0x13, 0x15)
/// collide with no transition id. (Object types are separate header fields,
/// so KEM suite ids 1/3/5 live in a different namespace.)
#[test]
fn suite_ids_are_distinct() {
    let ids: std::collections::BTreeSet<u8> = SigSuite::all().iter().map(|s| s.id()).collect();
    assert_eq!(ids.len(), 6);
    assert_eq!(
        ids.into_iter().collect::<Vec<_>>(),
        vec![0x02, 0x03, 0x05, 0x11, 0x13, 0x15]
    );
}

/// FIPS 205 Table 2 (n, pk = 2n, standard sk = 4n, sig) for the SHAKE "s"
/// sets; VYRA stores 3n-byte secret keys.
#[test]
fn slhdsa_sizes_match_fips205() {
    /// (scheme, name, n, public key, signature, category).
    type SlhRow = (
        Box<dyn SignatureScheme>,
        &'static str,
        usize,
        usize,
        usize,
        SecurityLevel,
    );
    let rows: [SlhRow; 3] = [
        (
            Box::new(SlhDsaShake128s),
            "SLH-DSA-SHAKE-128s",
            16,
            32,
            7856,
            SecurityLevel::L1,
        ),
        (
            Box::new(SlhDsaShake192s),
            "SLH-DSA-SHAKE-192s",
            24,
            48,
            16224,
            SecurityLevel::L3,
        ),
        (
            Box::new(SlhDsaShake256s),
            "SLH-DSA-SHAKE-256s",
            32,
            64,
            29792,
            SecurityLevel::L5,
        ),
    ];
    for (scheme, name, n, pk, sig, level) in &rows {
        assert_eq!(scheme.name(), *name);
        assert_eq!(scheme.public_key_len(), *pk);
        assert_eq!(*pk, 2 * n);
        assert_eq!(scheme.secret_key_len(), 3 * n);
        assert_eq!(scheme.signature_len(), *sig);
        assert_eq!(scheme.level(), *level);
    }
    assert_eq!(SlhDsaShake128s::N, 16);
    assert_eq!(SlhDsaShake192s::N, 24);
    assert_eq!(SlhDsaShake256s::N, 32);
    assert_eq!(SlhDsaShake128s::STANDARD_SECRET_KEY_LEN, 64);
    assert_eq!(SlhDsaShake192s::STANDARD_SECRET_KEY_LEN, 96);
    assert_eq!(SlhDsaShake256s::STANDARD_SECRET_KEY_LEN, 128);
    // Both upstream implementations agree with the table.
    use fips205::{slh_dsa_shake_128s as a, slh_dsa_shake_192s as b, slh_dsa_shake_256s as c};
    assert_eq!((a::PK_LEN, a::SK_LEN, a::SIG_LEN), (32, 64, 7856));
    assert_eq!((b::PK_LEN, b::SK_LEN, b::SIG_LEN), (48, 96, 16224));
    assert_eq!((c::PK_LEN, c::SK_LEN, c::SIG_LEN), (64, 128, 29792));
    // slh-dsa's encodings (decoding a standard 64-byte key; no key
    // generation, which is slow for slh-dsa in a test build).
    use slh_dsa::signature::Keypair;
    let k = slh_dsa::SigningKey::<slh_dsa::Shake128s>::try_from(&[0u8; 64][..]).unwrap();
    assert_eq!(k.to_bytes().len(), 64);
    assert_eq!(k.verifying_key().to_bytes().len(), 32);
    assert!(slh_dsa::SigningKey::<slh_dsa::Shake192s>::try_from(&[0u8; 96][..]).is_ok());
    assert!(slh_dsa::SigningKey::<slh_dsa::Shake256s>::try_from(&[0u8; 128][..]).is_ok());
    // Actual outputs (128s only: key generation and signing are slow).
    let mut rng = vyra_core::DeterministicEntropy::from_seed(b"sizes");
    let (pk, sk) = SlhDsaShake128s.generate_keypair(&mut rng).unwrap();
    assert_eq!((pk.len(), sk.len()), (32, 48));
    let sig = SlhDsaShake128s
        .sign(sk.expose(), b"size", &mut rng)
        .unwrap();
    assert_eq!(sig.len(), 7856);
}

#[test]
fn dual_pq_composite_size_table() {
    // suite, raw pk, raw sk, raw sig, wire pk, wire sk, wire sig
    let table = [
        (SigSuite::Pq1, 1344, 80, 10276, 1351, 103, 10283),
        (SigSuite::Pq3, 2000, 104, 19533, 2007, 127, 19540),
        (SigSuite::Pq5, 2656, 128, 34419, 2663, 151, 34426),
    ];
    for (suite, pk, sk, sig, wpk, wsk, wsig) in table {
        assert_eq!(suite.public_key_len(), pk);
        assert_eq!(suite.secret_key_len(), sk);
        assert_eq!(suite.signature_len(), sig);
        assert_eq!(
            suite.public_key_len(),
            suite.mldsa_public_key_len() + suite.second_public_key_len()
        );
        assert_eq!(suite.encoded_public_key_len(), wpk);
        assert_eq!(suite.encoded_secret_key_len(), wsk);
        assert_eq!(suite.encoded_signature_len(), wsig);
        assert_eq!(suite.encoded_secret_key_len(), HEADER_LEN + sk + 16);
        let scheme = CompositeSignature::new(suite);
        assert_eq!(scheme.public_key_len(), pk);
        assert_eq!(scheme.secret_key_len(), sk);
        assert_eq!(scheme.signature_len(), sig);
    }
    // Transition suites: second component is Ed25519 (32 / 32 / 64).
    for suite in SigSuite::transition() {
        assert_eq!(
            (
                suite.second_public_key_len(),
                suite.second_secret_key_len(),
                suite.second_signature_len()
            ),
            (32, 32, 64)
        );
    }
}

/// U12-R1: in every named suite both components are context-bound, so
/// neither half is a valid standalone default-mode signature on `M'`.
#[test]
fn every_named_suite_has_two_context_bound_components() {
    for suite in SigSuite::all() {
        assert!(suite.first().context_bound(), "{suite:?} first");
        assert!(suite.second().context_bound(), "{suite:?} second");
    }
    use vyra_sig::CompositeComponent;
    let all: [&dyn CompositeComponent; 7] = [
        &MlDsa44,
        &MlDsa65,
        &MlDsa87,
        &Ed25519,
        &SlhDsaShake128s,
        &SlhDsaShake192s,
        &SlhDsaShake256s,
    ];
    for c in all {
        assert!(c.context_bound(), "{}", c.name());
    }
}
