//! F6 wire round trips and S1/S2 length and header validation for every
//! decoder and every raw trait method.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use common::SUITES;
use vyra_core::wire::HEADER_LEN;
use vyra_core::{DeterministicEntropy, Error, OsEntropy, Result, SignatureScheme};
use vyra_sig::{
    CompositePublicKey, CompositeSecretKey, CompositeSig, CompositeSignature, Ed25519, MlDsa44,
    MlDsa65, MlDsa87, SigSuite,
};

type Decoder = fn(&[u8]) -> Result<()>;

fn decode_pk(b: &[u8]) -> Result<()> {
    CompositePublicKey::from_bytes(b).map(|_| ())
}
fn decode_sk(b: &[u8]) -> Result<()> {
    CompositeSecretKey::from_bytes(b).map(|_| ())
}
fn decode_sig(b: &[u8]) -> Result<()> {
    CompositeSig::from_bytes(b).map(|_| ())
}

/// For one suite: (name, valid encoding, decoder).
fn encodings(suite: SigSuite) -> Vec<(&'static str, Vec<u8>, Decoder)> {
    let scheme = CompositeSignature::new(suite);
    let mut rng = DeterministicEntropy::from_seed(&[suite.id()]);
    let (pk, sk) = scheme.generate(&mut rng).unwrap();
    let sig = scheme.sign(&sk, b"m", b"c", &mut rng).unwrap();
    vec![
        ("public key", pk.to_bytes(), decode_pk as Decoder),
        ("secret key", sk.to_bytes().expose().to_vec(), decode_sk),
        ("signature", sig.to_bytes(), decode_sig),
    ]
}

#[test]
fn f6_round_trip_and_lengths() {
    let mut rng = OsEntropy::new();
    for suite in SUITES {
        let scheme = CompositeSignature::new(suite);
        let (pk, sk) = scheme.generate(&mut rng).unwrap();
        let sig = scheme.sign(&sk, b"m", b"c", &mut rng).unwrap();

        let pk_enc = pk.to_bytes();
        let sk_enc = sk.to_bytes();
        let sig_enc = sig.to_bytes();
        assert_eq!(pk_enc.len(), suite.encoded_public_key_len());
        assert_eq!(sk_enc.len(), suite.encoded_secret_key_len());
        assert_eq!(sig_enc.len(), suite.encoded_signature_len());

        assert_eq!(&pk_enc[..4], b"VYRA");
        assert_eq!(pk_enc[4], 1);
        assert_eq!(pk_enc[5], 4);
        assert_eq!(sk_enc.expose()[5], 5);
        assert_eq!(sig_enc[5], 6);
        assert_eq!(pk_enc[6], suite.id());

        let pk2 = CompositePublicKey::from_bytes(&pk_enc).unwrap();
        let sk2 = CompositeSecretKey::from_bytes(sk_enc.expose()).unwrap();
        let sig2 = CompositeSig::from_bytes(&sig_enc).unwrap();
        assert_eq!(pk2, pk);
        assert!(sk2.ct_eq(&sk));
        assert_eq!(sig2, sig);
        assert_eq!(pk2.to_bytes(), pk_enc);
        assert_eq!(sig2.to_bytes(), sig_enc);

        // Raw parts concatenate to the raw encoding.
        assert_eq!(
            [pk.mldsa_part(), pk.ed25519_part().unwrap()].concat(),
            pk.as_raw()
        );
        assert_eq!(
            [sig.mldsa_part(), sig.ed25519_part().unwrap()].concat(),
            sig.as_raw()
        );
        assert_eq!(pk.ed25519_part().unwrap().len(), 32);
        assert_eq!(sk.expose_raw().len(), 64);
        assert_eq!(sig.ed25519_part().unwrap().len(), 64);

        scheme.verify(&pk2, b"m", b"c", &sig2).unwrap();
    }
}

#[test]
fn s1_empty_truncated_extended_rejected() {
    for suite in SUITES {
        for (name, enc, decode) in encodings(suite) {
            assert!(decode(&enc).is_ok(), "{name}");
            assert!(decode(&[]).is_err(), "{name} empty");
            assert!(decode(&enc[..enc.len() - 1]).is_err(), "{name} len-1");
            let mut ext = enc.clone();
            ext.push(0);
            assert!(
                matches!(decode(&ext), Err(Error::InvalidLength { .. })),
                "{name} len+1"
            );
            // Every truncation of the header and a header with no payload.
            for len in 0..=HEADER_LEN {
                assert!(decode(&enc[..len]).is_err(), "{name} len {len}");
            }
        }
    }
}

#[test]
fn s2_header_fields_rejected() {
    for suite in SUITES {
        let encs = encodings(suite);
        for (name, enc, decode) in &encs {
            for i in 0..4 {
                let mut bad = enc.clone();
                bad[i] ^= 0x01;
                assert_eq!(
                    decode(&bad),
                    Err(Error::InvalidEncoding("bad magic")),
                    "{name}"
                );
            }
            for v in [0u8, 2, 255] {
                let mut bad = enc.clone();
                bad[4] = v;
                assert_eq!(
                    decode(&bad),
                    Err(Error::InvalidEncoding("unsupported version")),
                    "{name}"
                );
            }
            for t in [0u8, 1, 2, 3, 7, 8, 255] {
                let mut bad = enc.clone();
                bad[5] = t;
                assert!(decode(&bad).is_err(), "{name} type {t}");
            }
            for s in [0u8, 1, 4, 6, 255] {
                let mut bad = enc.clone();
                bad[6] = s;
                assert_eq!(
                    decode(&bad),
                    Err(Error::UnknownSuite(s)),
                    "{name} suite {s}"
                );
            }
            // Another known suite id is rejected for EVERY object type
            // (U3-R3 restores this without the secret-key exclusion). Public
            // keys and signatures: the payload length no longer matches.
            // Secret keys are 64 bytes in every suite, so they are caught by
            // the check value instead.
            for other in SUITES {
                if other != suite {
                    let mut bad = enc.clone();
                    bad[6] = other.id();
                    let res = decode(&bad);
                    if *name == "secret key" {
                        assert_eq!(
                            res,
                            Err(Error::InvalidEncoding("secret key check value mismatch")),
                            "{name} relabelled as {other:?}"
                        );
                    } else {
                        assert!(
                            matches!(res, Err(Error::InvalidLength { .. })),
                            "{name} relabelled as {other:?}"
                        );
                    }
                }
            }
        }
        // Each object type is rejected by the other decoders.
        for (i, (_, enc, _)) in encs.iter().enumerate() {
            for (j, (name, _, decode)) in encs.iter().enumerate() {
                if i != j {
                    assert_eq!(
                        decode(enc),
                        Err(Error::InvalidEncoding("unexpected object type")),
                        "{name}"
                    );
                }
            }
        }
    }
}

#[test]
fn from_raw_requires_exact_length() {
    for suite in SUITES {
        // Since U3-R2 public keys are also validated (the Ed25519 part must be
        // a canonical non-small-order point), so the length cases use an
        // honest Ed25519 key after a zero ML-DSA part, and the all-zero key
        // (Ed25519 y = 0, a small-order point) is now rejected.
        let (ed_pk, _) = Ed25519
            .generate_keypair(&mut DeterministicEntropy::from_seed(b"ed"))
            .unwrap();
        let valid = [vec![0u8; suite.mldsa_public_key_len()], ed_pk].concat();
        for (len, ok) in [
            (suite.public_key_len(), true),
            (suite.public_key_len() - 1, false),
            (suite.public_key_len() + 1, false),
            (0, false),
        ] {
            let mut bytes = valid.clone();
            bytes.resize(len, 0);
            assert_eq!(CompositePublicKey::from_raw(suite, &bytes).is_ok(), ok);
        }
        assert_eq!(
            CompositePublicKey::from_raw(suite, &vec![0u8; suite.public_key_len()]),
            Err(Error::InvalidEncoding("Ed25519 public key (small order)"))
        );
        for (len, ok) in [
            (suite.secret_key_len(), true),
            (suite.secret_key_len() - 1, false),
            (suite.secret_key_len() + 1, false),
            (0, false),
        ] {
            assert_eq!(
                CompositeSecretKey::from_raw(suite, &vec![0u8; len]).is_ok(),
                ok
            );
        }
        for (len, ok) in [
            (suite.signature_len(), true),
            (suite.signature_len() - 1, false),
            (suite.signature_len() + 1, false),
            (0, false),
        ] {
            assert_eq!(CompositeSig::from_raw(suite, &vec![0u8; len]).is_ok(), ok);
        }
    }
}

fn all_schemes() -> Vec<Box<dyn SignatureScheme>> {
    vec![
        Box::new(MlDsa44),
        Box::new(MlDsa65),
        Box::new(MlDsa87),
        Box::new(Ed25519),
        Box::new(CompositeSignature::new(SigSuite::Vyra2)),
        Box::new(CompositeSignature::new(SigSuite::Vyra3)),
        Box::new(CompositeSignature::new(SigSuite::Vyra5)),
    ]
}

fn bad_lengths(len: usize) -> [usize; 4] {
    [0, len - 1, len + 1, len * 2]
}

#[test]
fn s1_raw_trait_methods_reject_wrong_lengths() {
    let mut rng = OsEntropy::new();
    for scheme in all_schemes() {
        let name = scheme.name();
        let (pk, sk) = scheme.generate_keypair(&mut rng).unwrap();
        let sig = scheme.sign(sk.expose(), b"m", &mut rng).unwrap();
        scheme.verify(&pk, b"m", &sig).unwrap();

        for len in bad_lengths(scheme.secret_key_len()) {
            let bad = vec![1u8; len];
            assert!(
                matches!(
                    scheme.sign(&bad, b"m", &mut rng),
                    Err(Error::InvalidLength { .. })
                ),
                "{name} sk len {len}"
            );
        }
        for len in bad_lengths(scheme.public_key_len()) {
            let mut bad = pk.clone();
            bad.resize(len, 0);
            assert!(
                matches!(
                    scheme.verify(&bad, b"m", &sig),
                    Err(Error::InvalidLength { .. })
                ),
                "{name} pk len {len}"
            );
        }
        for len in bad_lengths(scheme.signature_len()) {
            let mut bad = sig.clone();
            bad.resize(len, 0);
            assert!(
                matches!(
                    scheme.verify(&pk, b"m", &bad),
                    Err(Error::InvalidLength { .. })
                ),
                "{name} sig len {len}"
            );
        }
    }
}

#[test]
fn typed_api_rejects_suite_mismatch() {
    let mut rng = OsEntropy::new();
    let s2 = CompositeSignature::new(SigSuite::Vyra2);
    let s3 = CompositeSignature::new(SigSuite::Vyra3);
    let (pk2, sk2) = s2.generate(&mut rng).unwrap();
    let (pk3, _) = s3.generate(&mut rng).unwrap();
    let sig2 = s2.sign(&sk2, b"m", b"", &mut rng).unwrap();

    assert_eq!(
        s3.sign(&sk2, b"m", b"", &mut rng).map(|_| ()),
        Err(Error::InvalidEncoding("suite mismatch"))
    );
    assert_eq!(
        s3.verify(&pk2, b"m", b"", &sig2),
        Err(Error::InvalidEncoding("suite mismatch"))
    );
    assert_eq!(
        s3.verify(&pk3, b"m", b"", &sig2),
        Err(Error::InvalidEncoding("suite mismatch"))
    );
    // Raw cross-suite use is a length error.
    assert!(matches!(
        s3.verify_raw(pk3.as_raw(), b"m", b"", sig2.as_raw()),
        Err(Error::InvalidLength { .. })
    ));
    assert!(matches!(
        s3.verify_raw(pk2.as_raw(), b"m", b"", sig2.as_raw()),
        Err(Error::InvalidLength { .. })
    ));
}

/// Composite secret keys are two 32-byte seeds in every suite, so the length
/// cannot reveal a relabelled suite id.
///
/// DESIGN CHANGE (U3-R3): this test previously asserted that a relabelled
/// secret key *parses* (a documented limitation). Wire secret keys now carry a
/// 16-byte check value over (suite id, key bytes), so a relabelled key is
/// rejected at `from_bytes`. The expected result changed because the format
/// changed.
#[test]
fn secret_key_relabelled_to_other_suite() {
    let mut rng = OsEntropy::new();
    for suite in SUITES {
        let scheme = CompositeSignature::new(suite);
        let (_, sk) = scheme.generate(&mut rng).unwrap();
        for other in SUITES {
            if other == suite {
                continue;
            }
            let mut enc = sk.to_bytes().expose().to_vec();
            enc[6] = other.id();
            assert_eq!(
                CompositeSecretKey::from_bytes(&enc).map(|_| ()),
                Err(Error::InvalidEncoding("secret key check value mismatch"))
            );
        }
    }
}

#[test]
fn every_single_bit_flip_in_wire_secret_key_is_rejected() {
    for suite in SUITES {
        let scheme = CompositeSignature::new(suite);
        let (_, sk) = scheme
            .generate(&mut DeterministicEntropy::from_seed(&[suite.id(), 9]))
            .unwrap();
        let enc = sk.to_bytes().expose().to_vec();
        assert_eq!(enc.len(), suite.encoded_secret_key_len());
        assert!(CompositeSecretKey::from_bytes(&enc).unwrap().ct_eq(&sk));
        for i in 0..enc.len() {
            for bit in 0..8 {
                let mut bad = enc.clone();
                bad[i] ^= 1 << bit;
                assert!(
                    CompositeSecretKey::from_bytes(&bad).is_err(),
                    "{suite:?} byte {i} bit {bit}"
                );
            }
        }
    }
}

#[test]
fn secret_key_check_value_known_answer() {
    use sha3::{Digest, Sha3_256};
    // Recomputed by hand: SHA3-256(frame(label) ‖ frame([id]) ‖ frame(sk_raw)),
    // frame(x) = u64_be(len(x)) ‖ x, truncated to 16 bytes.
    let frame = |x: &[u8]| [&(x.len() as u64).to_be_bytes()[..], x].concat();
    assert_eq!(vyra_sig::SECRET_KEY_CHECK_LABEL, b"VYRA-SIG-SK-v1");
    assert_eq!(vyra_sig::SECRET_KEY_CHECK_LEN, 16);
    let raw: Vec<u8> = (0u8..64).collect();
    for suite in SUITES {
        let sk = CompositeSecretKey::from_raw(suite, &raw).unwrap();
        let enc = sk.to_bytes().expose().to_vec();
        let mut h = Sha3_256::new();
        h.update(frame(b"VYRA-SIG-SK-v1"));
        h.update(frame(&[suite.id()]));
        h.update(frame(&raw));
        let digest = h.finalize();
        let mut expected = vec![b'V', b'Y', b'R', b'A', 1, 5, suite.id()];
        expected.extend_from_slice(&raw);
        expected.extend_from_slice(&digest[..16]);
        assert_eq!(enc, expected);
        assert_eq!(enc.len(), 87);
    }
}

// ---------------------------------------------------------------------------
// Dual post-quantum suites. One signature per suite per test (SLH-DSA signing
// is slow); the decoder checks themselves are the same as above.
// ---------------------------------------------------------------------------

fn f6_pq(suite: SigSuite) {
    let mut rng = OsEntropy::new();
    let scheme = CompositeSignature::new(suite);
    let (pk, sk) = scheme.generate(&mut rng).unwrap();
    let sig = scheme.sign(&sk, b"m", b"c", &mut rng).unwrap();

    let pk_enc = pk.to_bytes();
    let sk_enc = sk.to_bytes();
    let sig_enc = sig.to_bytes();
    assert_eq!(pk_enc.len(), suite.encoded_public_key_len());
    assert_eq!(sk_enc.len(), suite.encoded_secret_key_len());
    assert_eq!(sig_enc.len(), suite.encoded_signature_len());
    assert_eq!(&pk_enc[..4], b"VYRA");
    assert_eq!((pk_enc[4], pk_enc[5], pk_enc[6]), (1, 4, suite.id()));
    assert_eq!(sk_enc.expose()[5], 5);
    assert_eq!(sk_enc.expose()[6], suite.id());
    assert_eq!((sig_enc[5], sig_enc[6]), (6, suite.id()));

    let pk2 = CompositePublicKey::from_bytes(&pk_enc).unwrap();
    let sk2 = CompositeSecretKey::from_bytes(sk_enc.expose()).unwrap();
    let sig2 = CompositeSig::from_bytes(&sig_enc).unwrap();
    assert_eq!(pk2, pk);
    assert!(sk2.ct_eq(&sk));
    assert_eq!(sig2, sig);
    assert_eq!(pk2.to_bytes(), pk_enc);
    assert_eq!(sig2.to_bytes(), sig_enc);

    // Parts: ML-DSA ‖ SLH-DSA; no Ed25519 part.
    assert_eq!([pk.mldsa_part(), pk.second_part()].concat(), pk.as_raw());
    assert_eq!([sig.mldsa_part(), sig.second_part()].concat(), sig.as_raw());
    assert_eq!(pk.slhdsa_part(), Some(pk.second_part()));
    assert_eq!(sig.slhdsa_part(), Some(sig.second_part()));
    assert_eq!(pk.ed25519_part(), None);
    assert_eq!(sig.ed25519_part(), None);
    assert_eq!(pk.mldsa_part().len(), suite.mldsa_public_key_len());
    assert_eq!(pk.second_part().len(), suite.second_public_key_len());
    assert_eq!(sig.second_part().len(), suite.second_signature_len());
    assert_eq!(sk.expose_raw().len(), 32 + suite.second_secret_key_len());

    scheme.verify(&pk2, b"m", b"c", &sig2).unwrap();
}

#[test]
fn f6_round_trip_and_lengths_pq1() {
    f6_pq(SigSuite::Pq1);
}

#[test]
fn f6_round_trip_and_lengths_pq3() {
    f6_pq(SigSuite::Pq3);
}

#[test]
fn f6_round_trip_and_lengths_pq5() {
    f6_pq(SigSuite::Pq5);
}

#[test]
fn transition_parts_accessors() {
    let scheme = CompositeSignature::new(SigSuite::Vyra2);
    let (pk, sk) = scheme
        .generate(&mut DeterministicEntropy::from_seed(b"parts"))
        .unwrap();
    let sig = scheme
        .sign(&sk, b"m", b"", &mut DeterministicEntropy::from_seed(b"s"))
        .unwrap();
    assert_eq!(pk.ed25519_part(), Some(pk.second_part()));
    assert_eq!(sig.ed25519_part(), Some(sig.second_part()));
    assert_eq!(pk.slhdsa_part(), None);
    assert_eq!(sig.slhdsa_part(), None);
}

/// S1 and S2 for the dual-PQ suites: every decoder, every header field,
/// relabelling to every other suite id.
fn s1_s2_pq(suite: SigSuite) {
    let encs = encodings(suite);
    for (name, enc, decode) in &encs {
        // S1
        assert!(decode(enc).is_ok(), "{name}");
        assert!(decode(&[]).is_err(), "{name} empty");
        assert!(decode(&enc[..enc.len() - 1]).is_err(), "{name} len-1");
        let mut ext = enc.clone();
        ext.push(0);
        assert!(
            matches!(decode(&ext), Err(Error::InvalidLength { .. })),
            "{name} len+1"
        );
        for len in 0..=HEADER_LEN {
            assert!(decode(&enc[..len]).is_err(), "{name} len {len}");
        }
        // S2
        for i in 0..4 {
            let mut bad = enc.clone();
            bad[i] ^= 0x01;
            assert_eq!(
                decode(&bad),
                Err(Error::InvalidEncoding("bad magic")),
                "{name}"
            );
        }
        for v in [0u8, 2, 255] {
            let mut bad = enc.clone();
            bad[4] = v;
            assert_eq!(
                decode(&bad),
                Err(Error::InvalidEncoding("unsupported version")),
                "{name}"
            );
        }
        for t in [0u8, 1, 2, 3, 7, 8, 255] {
            let mut bad = enc.clone();
            bad[5] = t;
            assert!(decode(&bad).is_err(), "{name} type {t}");
        }
        for s in [0u8, 1, 4, 6, 0x10, 0x12, 0x14, 0x16, 255] {
            let mut bad = enc.clone();
            bad[6] = s;
            assert_eq!(
                decode(&bad),
                Err(Error::UnknownSuite(s)),
                "{name} suite {s}"
            );
        }
        // Relabelled to every other named suite. Secret keys and signatures
        // differ in length from every other suite. Public keys too, with one
        // exception: VYRA-SIG-PQ1 and VYRA-SIG-2 public keys are both 1344
        // bytes (1312 + 32); see `public_key_length_coincidence_pq1_vyra2`.
        for other in common::ALL_SUITES {
            if other == suite {
                continue;
            }
            let mut bad = enc.clone();
            bad[6] = other.id();
            let res = decode(&bad);
            let same_len =
                *name == "public key" && other.public_key_len() == suite.public_key_len();
            if same_len {
                assert_eq!((suite, other), (SigSuite::Pq1, SigSuite::Vyra2));
            } else {
                assert!(
                    matches!(res, Err(Error::InvalidLength { .. })),
                    "{name} relabelled as {other:?}: {res:?}"
                );
            }
        }
    }
    for (i, (_, enc, _)) in encs.iter().enumerate() {
        for (j, (name, _, decode)) in encs.iter().enumerate() {
            if i != j {
                assert_eq!(
                    decode(enc),
                    Err(Error::InvalidEncoding("unexpected object type")),
                    "{name}"
                );
            }
        }
    }
}

#[test]
fn s1_s2_decoders_pq1() {
    s1_s2_pq(SigSuite::Pq1);
}

#[test]
fn s1_s2_decoders_pq3() {
    s1_s2_pq(SigSuite::Pq3);
}

#[test]
fn s1_s2_decoders_pq5() {
    s1_s2_pq(SigSuite::Pq5);
}

/// FINDING (documented, not a forgery): the raw public keys of VYRA-SIG-2
/// (ML-DSA-44 1312 + Ed25519 32) and VYRA-SIG-PQ1 (ML-DSA-44 1312 + SLH-DSA
/// 32) have the same length, so a wire public key relabelled between these
/// two suites is not caught by length. A VYRA-SIG-2 key relabelled as PQ1
/// always parses (both PQ1 parts are length-checked only). This does not let
/// a signature move between suites: signatures differ in length in every
/// suite, `M'` and the composite context contain the suite id, and the
/// public-key digest is keyed by the suite id; the relabelled key names a
/// different PQ1 key whose SLH-DSA part nobody generated. Public keys carry
/// no check value (adding one would change the transition wire format).
#[test]
fn public_key_length_coincidence_pq1_vyra2() {
    for s in common::ALL_SUITES {
        for t in common::ALL_SUITES {
            if s == t {
                continue;
            }
            assert_ne!(s.signature_len(), t.signature_len(), "{s:?} {t:?}");
            if s.public_key_len() == t.public_key_len() {
                assert!(
                    [
                        (SigSuite::Vyra2, SigSuite::Pq1),
                        (SigSuite::Pq1, SigSuite::Vyra2)
                    ]
                    .contains(&(s, t)),
                    "{s:?} {t:?}"
                );
            }
            if s.secret_key_len() == t.secret_key_len() {
                // Only the transition suites share a secret-key length (64);
                // the key check value covers them (tests above).
                assert!(!s.is_dual_pq() && !t.is_dual_pq(), "{s:?} {t:?}");
            }
        }
    }
    assert_eq!(SigSuite::Vyra2.public_key_len(), 1344);
    assert_eq!(SigSuite::Pq1.public_key_len(), 1344);

    let v2 = CompositeSignature::new(SigSuite::Vyra2);
    let pq1 = CompositeSignature::new(SigSuite::Pq1);
    let (pk2, sk2) = v2
        .generate(&mut DeterministicEntropy::from_seed(b"relabel"))
        .unwrap();
    let sig2 = v2
        .sign(&sk2, b"m", b"", &mut DeterministicEntropy::from_seed(b"s"))
        .unwrap();
    let mut enc = pk2.to_bytes();
    enc[6] = SigSuite::Pq1.id();
    let relabelled = CompositePublicKey::from_bytes(&enc).unwrap();
    assert_eq!(relabelled.suite(), SigSuite::Pq1);
    // The VYRA-SIG-2 signature cannot be presented as a PQ1 signature...
    let mut sig_enc = sig2.to_bytes();
    sig_enc[6] = SigSuite::Pq1.id();
    assert!(matches!(
        CompositeSig::from_bytes(&sig_enc),
        Err(Error::InvalidLength { .. })
    ));
    // ...and a PQ1 signature made with the same ML-DSA-44 seed does not
    // verify under the relabelled key (its SLH-DSA half would have to verify
    // under "PK.seed ‖ PK.root" = the Ed25519 public key bytes).
    let raw_pq1_sk = [&sk2.expose_raw()[..32], &[5u8; 48][..]].concat();
    let sig_pq1 = pq1
        .sign_raw(
            &raw_pq1_sk,
            b"m",
            b"",
            &mut DeterministicEntropy::from_seed(b"s"),
        )
        .unwrap();
    assert_eq!(
        pq1.verify_raw(relabelled.as_raw(), b"m", b"", &sig_pq1),
        Err(Error::VerificationFailed)
    );
}

#[test]
fn from_raw_requires_exact_length_pq() {
    for suite in common::PQ_SUITES {
        // Every byte string of the right length is a valid PQ public key,
        // including all zeros (there is no Ed25519 part).
        for (len, ok) in [
            (suite.public_key_len(), true),
            (suite.public_key_len() - 1, false),
            (suite.public_key_len() + 1, false),
            (0, false),
        ] {
            assert_eq!(
                CompositePublicKey::from_raw(suite, &vec![0u8; len]).is_ok(),
                ok
            );
        }
        for (len, ok) in [
            (suite.secret_key_len(), true),
            (suite.secret_key_len() - 1, false),
            (suite.secret_key_len() + 1, false),
            (0, false),
        ] {
            assert_eq!(
                CompositeSecretKey::from_raw(suite, &vec![0u8; len]).is_ok(),
                ok
            );
        }
        for (len, ok) in [
            (suite.signature_len(), true),
            (suite.signature_len() - 1, false),
            (suite.signature_len() + 1, false),
            (0, false),
        ] {
            assert_eq!(CompositeSig::from_raw(suite, &vec![0u8; len]).is_ok(), ok);
        }
    }
}

fn check_raw_lengths(scheme: &dyn SignatureScheme) {
    let mut rng = OsEntropy::new();
    let name = scheme.name();
    let (pk, sk) = scheme.generate_keypair(&mut rng).unwrap();
    let sig = scheme.sign(sk.expose(), b"m", &mut rng).unwrap();
    scheme.verify(&pk, b"m", &sig).unwrap();
    for len in bad_lengths(scheme.secret_key_len()) {
        assert!(
            matches!(
                scheme.sign(&vec![1u8; len], b"m", &mut rng),
                Err(Error::InvalidLength { .. })
            ),
            "{name} sk len {len}"
        );
    }
    for len in bad_lengths(scheme.public_key_len()) {
        let mut bad = pk.clone();
        bad.resize(len, 0);
        assert!(
            matches!(
                scheme.verify(&bad, b"m", &sig),
                Err(Error::InvalidLength { .. })
            ),
            "{name} pk len {len}"
        );
    }
    for len in bad_lengths(scheme.signature_len()) {
        let mut bad = sig.clone();
        bad.resize(len, 0);
        assert!(
            matches!(
                scheme.verify(&pk, b"m", &bad),
                Err(Error::InvalidLength { .. })
            ),
            "{name} sig len {len}"
        );
    }
}

#[test]
fn s1_raw_trait_methods_reject_wrong_lengths_pq1() {
    check_raw_lengths(&vyra_sig::SlhDsaShake128s);
    check_raw_lengths(&CompositeSignature::new(SigSuite::Pq1));
}

#[test]
fn s1_raw_trait_methods_reject_wrong_lengths_pq3() {
    check_raw_lengths(&vyra_sig::SlhDsaShake192s);
    check_raw_lengths(&CompositeSignature::new(SigSuite::Pq3));
}

#[test]
fn s1_raw_trait_methods_reject_wrong_lengths_pq5() {
    check_raw_lengths(&vyra_sig::SlhDsaShake256s);
    check_raw_lengths(&CompositeSignature::new(SigSuite::Pq5));
}

/// Cross-suite rejection: a dual-PQ suite against a transition suite and
/// between dual-PQ suites, typed and raw.
#[test]
fn typed_api_rejects_suite_mismatch_pq() {
    let mut rng = OsEntropy::new();
    let pq1 = CompositeSignature::new(SigSuite::Pq1);
    let pq3 = CompositeSignature::new(SigSuite::Pq3);
    let v2 = CompositeSignature::new(SigSuite::Vyra2);
    let (pk_pq1, sk_pq1) = pq1.generate(&mut rng).unwrap();
    let (pk_pq3, sk_pq3) = pq3.generate(&mut rng).unwrap();
    let (pk_v2, sk_v2) = v2.generate(&mut rng).unwrap();
    let sig_pq1 = pq1.sign(&sk_pq1, b"m", b"", &mut rng).unwrap();
    let sig_v2 = v2.sign(&sk_v2, b"m", b"", &mut rng).unwrap();

    let mismatch = Err(Error::InvalidEncoding("suite mismatch"));
    assert_eq!(pq3.sign(&sk_pq1, b"m", b"", &mut rng).map(|_| ()), mismatch);
    assert_eq!(pq1.sign(&sk_pq3, b"m", b"", &mut rng).map(|_| ()), mismatch);
    assert_eq!(pq1.sign(&sk_v2, b"m", b"", &mut rng).map(|_| ()), mismatch);
    assert_eq!(v2.sign(&sk_pq1, b"m", b"", &mut rng).map(|_| ()), mismatch);
    assert_eq!(pq3.verify(&pk_pq1, b"m", b"", &sig_pq1), mismatch);
    assert_eq!(pq3.verify(&pk_pq3, b"m", b"", &sig_pq1), mismatch);
    assert_eq!(v2.verify(&pk_v2, b"m", b"", &sig_pq1), mismatch);
    assert_eq!(pq1.verify(&pk_pq1, b"m", b"", &sig_v2), mismatch);
    assert_eq!(v2.verify(&pk_pq1, b"m", b"", &sig_v2), mismatch);
    // Raw cross-suite use is a length error: signatures differ in length in
    // every suite (the last two rows share the public-key length 1344).
    for (scheme, pk, sig) in [
        (&pq3, pk_pq3.as_raw(), sig_pq1.as_raw()),
        (&pq3, pk_pq1.as_raw(), sig_pq1.as_raw()),
        (&v2, pk_v2.as_raw(), sig_pq1.as_raw()),
        (&pq1, pk_pq1.as_raw(), sig_v2.as_raw()),
        (&pq1, pk_v2.as_raw(), sig_v2.as_raw()),
        (&v2, pk_pq1.as_raw(), sig_pq1.as_raw()),
    ] {
        assert!(matches!(
            scheme.verify_raw(pk, b"m", b"", sig),
            Err(Error::InvalidLength { .. })
        ));
    }
    // Secret keys differ in length between the families and between PQ suites.
    for (scheme, sk) in [
        (&pq3, sk_pq1.expose_raw()),
        (&pq1, sk_pq3.expose_raw()),
        (&pq1, sk_v2.expose_raw()),
        (&v2, sk_pq1.expose_raw()),
    ] {
        assert!(matches!(
            scheme.sign_raw(sk, b"m", b"", &mut rng),
            Err(Error::InvalidLength { .. })
        ));
    }
}

#[test]
fn every_single_bit_flip_in_wire_secret_key_is_rejected_pq() {
    for suite in common::PQ_SUITES {
        let scheme = CompositeSignature::new(suite);
        let (_, sk) = scheme
            .generate(&mut DeterministicEntropy::from_seed(&[suite.id(), 9]))
            .unwrap();
        let enc = sk.to_bytes().expose().to_vec();
        assert_eq!(enc.len(), suite.encoded_secret_key_len());
        assert!(CompositeSecretKey::from_bytes(&enc).unwrap().ct_eq(&sk));
        for i in 0..enc.len() {
            for bit in 0..8 {
                let mut bad = enc.clone();
                bad[i] ^= 1 << bit;
                assert!(
                    CompositeSecretKey::from_bytes(&bad).is_err(),
                    "{suite:?} byte {i} bit {bit}"
                );
            }
        }
    }
}

#[test]
fn secret_key_check_value_known_answer_pq() {
    use sha3::{Digest, Sha3_256};
    let frame = |x: &[u8]| [&(x.len() as u64).to_be_bytes()[..], x].concat();
    for (suite, wire_len) in [
        (SigSuite::Pq1, 103),
        (SigSuite::Pq3, 127),
        (SigSuite::Pq5, 151),
    ] {
        let raw: Vec<u8> = (0..suite.secret_key_len()).map(|i| i as u8).collect();
        let sk = CompositeSecretKey::from_raw(suite, &raw).unwrap();
        let enc = sk.to_bytes().expose().to_vec();
        let mut h = Sha3_256::new();
        h.update(frame(b"VYRA-SIG-SK-v1"));
        h.update(frame(&[suite.id()]));
        h.update(frame(&raw));
        let digest = h.finalize();
        let mut expected = vec![b'V', b'Y', b'R', b'A', 1, 5, suite.id()];
        expected.extend_from_slice(&raw);
        expected.extend_from_slice(&digest[..16]);
        assert_eq!(enc, expected);
        assert_eq!(enc.len(), wire_len);
    }
}
