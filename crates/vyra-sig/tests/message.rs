//! The VYRA-ORIGINAL message representative: known answers, injectivity,
//! public-key binding, limits.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use vyra_core::Error;
use vyra_sig::{
    DOMAIN_LABEL, MAX_CONTEXT_LEN, PK_DIGEST_LABEL, SigSuite, composite_context,
    message_representative, message_representative_with_digest, mldsa_context, public_key_digest,
};

/// SHA3-256 transcript digest of an all-zero composite public key, computed
/// independently with Python `hashlib.sha3_256` over
/// `frame("VYRA-SIG-PK-v1") ‖ frame([id]) ‖ frame(pk_mldsa) ‖ frame(pk_ed)`,
/// `frame(x) = u64_be(len(x)) ‖ x`.
const ZERO_PK_DIGESTS: [(SigSuite, &str); 3] = [
    (
        SigSuite::Vyra2,
        "063e7be5c74b69dfadbbfdd4e38260ee3d7910b16c4c32be9ad235ecf7d67f52",
    ),
    (
        SigSuite::Vyra3,
        "8ca93958699ff7b0d80b4537b3c71c4923ba391dc35d3ecc326362a38098fa18",
    ),
    (
        SigSuite::Vyra5,
        "9c7fd075d3f9c5e80e4eb0422172758943741e115e07c109a8acb7d3c7faafb4",
    ),
];

fn zero_pk(suite: SigSuite) -> Vec<u8> {
    vec![0u8; suite.public_key_len()]
}

/// The digest recomputed in the test with the `sha3` crate directly (not
/// through `vyra_core::Transcript`).
fn digest_by_hand(suite: SigSuite, pk: &[u8]) -> Vec<u8> {
    use sha3::{Digest, Sha3_256};
    let frame = |x: &[u8]| [&(x.len() as u64).to_be_bytes()[..], x].concat();
    let (a, b) = pk.split_at(suite.mldsa_public_key_len());
    let mut h = Sha3_256::new();
    h.update(frame(PK_DIGEST_LABEL));
    h.update(frame(&[suite.id()]));
    h.update(frame(a));
    h.update(frame(b));
    h.finalize().to_vec()
}

#[test]
fn public_key_digest_known_answers() {
    assert_eq!(PK_DIGEST_LABEL, b"VYRA-SIG-PK-v1");
    for (suite, hex_digest) in ZERO_PK_DIGESTS {
        let pk = zero_pk(suite);
        let d = public_key_digest(suite, &pk).unwrap();
        assert_eq!(hex::encode(d), hex_digest);
        assert_eq!(d.to_vec(), digest_by_hand(suite, &pk));
    }
    // Non-trivial key, against the hand computation.
    let pk: Vec<u8> = (0..SigSuite::Vyra3.public_key_len())
        .map(|i| (i * 7) as u8)
        .collect();
    assert_eq!(
        public_key_digest(SigSuite::Vyra3, &pk).unwrap().to_vec(),
        digest_by_hand(SigSuite::Vyra3, &pk)
    );
}

#[test]
fn known_answer_exact_bytes() {
    assert_eq!(DOMAIN_LABEL, b"VYRA-SIG-v1");
    for (suite, hex_digest) in ZERO_PK_DIGESTS {
        let digest = hex::decode(hex_digest).unwrap();
        let mut expected = b"VYRA-SIG-v1".to_vec();
        expected.push(suite.id());
        expected.extend_from_slice(&digest);
        expected.extend_from_slice(b"\x02abc");
        assert_eq!(
            message_representative(suite, &zero_pk(suite), b"ab", b"c").unwrap(),
            expected
        );
    }
    let pk = zero_pk(SigSuite::Vyra2);
    let rep = message_representative(SigSuite::Vyra2, &pk, b"", b"").unwrap();
    assert_eq!(rep.len(), 11 + 1 + 32 + 1);
    assert_eq!(rep[11], 2);
    assert_eq!(rep[44], 0);
}

#[test]
fn mldsa_context_bytes() {
    assert_eq!(&mldsa_context(SigSuite::Vyra2), b"VYRA-SIG-v1\x02");
    assert_eq!(&mldsa_context(SigSuite::Vyra3), b"VYRA-SIG-v1\x03");
    assert_eq!(&mldsa_context(SigSuite::Vyra5), b"VYRA-SIG-v1\x05");
}

#[test]
fn context_message_boundary_is_unambiguous() {
    let pk = zero_pk(SigSuite::Vyra3);
    let s = SigSuite::Vyra3;
    let a = message_representative(s, &pk, b"ab", b"c").unwrap();
    let b = message_representative(s, &pk, b"a", b"bc").unwrap();
    let c = message_representative(s, &pk, b"", b"abc").unwrap();
    let d = message_representative(s, &pk, b"abc", b"").unwrap();
    for (i, x) in [&a, &b, &c, &d].iter().enumerate() {
        for (j, y) in [&a, &b, &c, &d].iter().enumerate() {
            assert_eq!(i == j, x == y);
        }
    }
}

#[test]
fn suite_and_public_key_are_bound() {
    let reps: Vec<_> = SigSuite::all()
        .iter()
        .map(|s| message_representative(*s, &zero_pk(*s), b"ctx", b"msg").unwrap())
        .collect();
    assert_ne!(reps[0], reps[1]);
    assert_ne!(reps[1], reps[2]);
    assert_ne!(reps[0], reps[2]);

    // Changing either half of the public key changes M'.
    let s = SigSuite::Vyra2;
    let base = message_representative(s, &zero_pk(s), b"c", b"m").unwrap();
    let mut pk = zero_pk(s);
    pk[0] = 1;
    assert_ne!(base, message_representative(s, &pk, b"c", b"m").unwrap());
    let mut pk = zero_pk(s);
    *pk.last_mut().unwrap() = 1;
    assert_ne!(base, message_representative(s, &pk, b"c", b"m").unwrap());
}

#[test]
fn injective_over_small_domain() {
    let words: [&[u8]; 5] = [b"", b"a", b"b", b"aa", b"ab"];
    let mut seen = std::collections::HashMap::new();
    for suite in SigSuite::all() {
        for pk_byte in [0u8, 1] {
            let mut pk = zero_pk(suite);
            pk[0] = pk_byte;
            for ctx in words {
                for msg in words {
                    let rep = message_representative(suite, &pk, ctx, msg).unwrap();
                    if let Some(prev) = seen.insert(rep, (suite, pk_byte, ctx, msg)) {
                        panic!(
                            "collision between {prev:?} and {:?}",
                            (suite, pk_byte, ctx, msg)
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn length_limits() {
    let s = SigSuite::Vyra2;
    let pk = zero_pk(s);
    assert_eq!(MAX_CONTEXT_LEN, 255);
    let ok = message_representative(s, &pk, &[1u8; 255], b"m").unwrap();
    assert_eq!(ok.len(), 11 + 1 + 32 + 1 + 255 + 1);
    assert_eq!(ok[44], 255);
    assert_eq!(
        message_representative(s, &pk, &[1u8; 256], b"m"),
        Err(Error::InvalidLength {
            what: "signature context",
            expected: 255,
            actual: 256
        })
    );
    assert!(message_representative(s, &pk, &vec![0u8; 100_000], b"").is_err());
    for len in [0, pk.len() - 1, pk.len() + 1] {
        assert!(matches!(
            message_representative(s, &vec![0u8; len], b"", b"m"),
            Err(Error::InvalidLength { .. })
        ));
        assert!(public_key_digest(s, &vec![0u8; len]).is_err());
    }
}

/// Independently computed (Python `hashlib.sha3_256`, same framing as
/// [`ZERO_PK_DIGESTS`]) for the all-zero dual-PQ composite public keys.
const ZERO_PK_DIGESTS_PQ: [(SigSuite, &str); 3] = [
    (
        SigSuite::Pq1,
        "7adcd4b293b5662aae8a70705197a413fcd9cbd303f42e697cc87452fb234b14",
    ),
    (
        SigSuite::Pq3,
        "aeed497022f8ccc7702c63ea9200e8d84c06e6d2fe9155c24156c278a1f891f5",
    ),
    (
        SigSuite::Pq5,
        "aaeb85b2521d03962828b096bec5dc6c93b94ac92d779f1e3635f915c1bf84c0",
    ),
];

#[test]
fn dual_pq_public_key_digest_and_representative_known_answers() {
    for (suite, hex_digest) in ZERO_PK_DIGESTS_PQ {
        let pk = zero_pk(suite);
        let d = public_key_digest(suite, &pk).unwrap();
        assert_eq!(hex::encode(d), hex_digest);
        assert_eq!(d.to_vec(), digest_by_hand(suite, &pk));
        let mut expected = b"VYRA-SIG-v1".to_vec();
        expected.push(suite.id());
        expected.extend_from_slice(&d);
        expected.extend_from_slice(b"\x02abc");
        assert_eq!(
            message_representative(suite, &pk, b"ab", b"c").unwrap(),
            expected
        );
    }
}

#[test]
fn composite_context_bytes() {
    assert_eq!(&composite_context(0x11), b"VYRA-SIG-v1\x11");
    assert_eq!(&composite_context(0x13), b"VYRA-SIG-v1\x13");
    assert_eq!(&composite_context(0x15), b"VYRA-SIG-v1\x15");
    for suite in SigSuite::all() {
        assert_eq!(mldsa_context(suite), composite_context(suite.id()));
    }
}

/// The pure layout function: `message_representative` is exactly
/// `message_representative_with_digest` applied to `public_key_digest`, and
/// the latter is plain concatenation (an arbitrary "digest", not the output
/// of any hash, is copied verbatim; any suite byte is accepted).
#[test]
fn with_digest_is_the_pure_layout() {
    for suite in SigSuite::all() {
        let pk: Vec<u8> = (0..suite.public_key_len())
            .map(|i| (i * 31) as u8)
            .collect();
        let d = public_key_digest(suite, &pk).unwrap();
        for (ctx, msg) in [
            (&b""[..], &b""[..]),
            (b"ctx", b"message"),
            (&[9u8; 255][..], b"m"),
        ] {
            assert_eq!(
                message_representative(suite, &pk, ctx, msg).unwrap(),
                message_representative_with_digest(suite.id(), &d, ctx, msg).unwrap()
            );
        }
    }
    let digest: [u8; 32] = core::array::from_fn(|i| i as u8);
    for id in [0u8, 0x42, 0xff] {
        let rep = message_representative_with_digest(id, &digest, b"xy", b"z").unwrap();
        let mut expected = DOMAIN_LABEL.to_vec();
        expected.push(id);
        expected.extend_from_slice(&digest);
        expected.extend_from_slice(b"\x02xyz");
        assert_eq!(rep, expected);
    }
    assert_eq!(
        message_representative_with_digest(2, &digest, &[0u8; 256], b""),
        Err(Error::InvalidLength {
            what: "signature context",
            expected: 255,
            actual: 256
        })
    );
}

#[test]
fn with_digest_injective_over_small_domain() {
    let words: [&[u8]; 5] = [b"", b"a", b"b", b"aa", b"ab"];
    let mut seen = std::collections::HashMap::new();
    for id in [0u8, 2, 0x11, 0xff] {
        for d0 in [0u8, 1] {
            let mut digest = [0u8; 32];
            digest[31] = d0;
            for ctx in words {
                for msg in words {
                    let rep = message_representative_with_digest(id, &digest, ctx, msg).unwrap();
                    if let Some(prev) = seen.insert(rep, (id, d0, ctx, msg)) {
                        panic!("collision between {prev:?} and {:?}", (id, d0, ctx, msg));
                    }
                }
            }
        }
    }
}
