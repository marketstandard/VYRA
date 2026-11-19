//! F6 (wire round trip and lengths), S1/S2 (decoder length and header
//! validation) and cross-suite rejection for the typed objects.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use vyra_core::wire::HEADER_LEN;
use vyra_core::{Error, OsEntropy, Result};
use vyra_kem::{HybridCiphertext, HybridKem, HybridPublicKey, HybridSecretKey, KemSuite};

/// Spec table: (suite, raw pk, raw sk, raw ct). The secret key is sk1 ‖ sk2
/// (U2-R1 removed the stored pk1 ‖ pk2; U2-R2 made the HQC part its 32-byte
/// seed, so every suite's secret key is 64 + 32 = 96 bytes).
const SIZES: [(KemSuite, usize, usize, usize); 3] = [
    (KemSuite::Vyra1, 3041, 96, 5201),
    (KemSuite::Vyra3, 5698, 96, 10066),
    (KemSuite::Vyra5, 8805, 96, 15989),
];

struct Encoded {
    suite: KemSuite,
    pk: Vec<u8>,
    sk: Vec<u8>,
    ct: Vec<u8>,
}

fn encoded_objects() -> Vec<Encoded> {
    let mut rng = OsEntropy::new();
    KemSuite::all()
        .into_iter()
        .map(|suite| {
            let kem = HybridKem::new(suite);
            let (pk, sk) = kem.generate(&mut rng).unwrap();
            let (ct, _) = kem.encapsulate_to(&pk, &mut rng).unwrap();
            Encoded {
                suite,
                pk: pk.to_bytes(),
                sk: sk.to_bytes().expose().to_vec(),
                ct: ct.to_bytes(),
            }
        })
        .collect()
}

#[test]
fn f6_sizes_match_spec_table() {
    for (suite, pk, sk, ct) in SIZES {
        assert_eq!(suite.public_key_len(), pk, "{suite}");
        assert_eq!(suite.secret_key_len(), sk, "{suite}");
        assert_eq!(suite.ciphertext_len(), ct, "{suite}");
        assert_eq!(suite.shared_secret_len(), 32, "{suite}");
        assert_eq!(suite.encoded_public_key_len(), pk + 7, "{suite}");
        // Wire secret key = header ‖ seeds ‖ 16-byte check value (U2-R2).
        assert_eq!(suite.encoded_secret_key_len(), sk + 7 + 16, "{suite}");
        assert_eq!(suite.encoded_secret_key_len(), 119, "{suite}");
        assert_eq!(suite.encoded_ciphertext_len(), ct + 7, "{suite}");
    }
    assert_eq!(HEADER_LEN, 7);
}

#[test]
fn f6_round_trip_all_objects_all_suites() {
    let mut rng = OsEntropy::new();
    for suite in KemSuite::all() {
        let kem = HybridKem::new(suite);
        let (pk, sk) = kem.generate(&mut rng).unwrap();
        let (ct, key) = kem.encapsulate_to(&pk, &mut rng).unwrap();

        let pk_wire = pk.to_bytes();
        let sk_wire = sk.to_bytes();
        let ct_wire = ct.to_bytes();
        assert_eq!(pk_wire.len(), suite.encoded_public_key_len());
        assert_eq!(sk_wire.len(), suite.encoded_secret_key_len());
        assert_eq!(ct_wire.len(), suite.encoded_ciphertext_len());
        assert_eq!(&pk_wire[..7], &[b'V', b'Y', b'R', b'A', 1, 1, suite.id()]);
        assert_eq!(
            &sk_wire.expose()[..7],
            &[b'V', b'Y', b'R', b'A', 1, 2, suite.id()]
        );
        assert_eq!(&ct_wire[..7], &[b'V', b'Y', b'R', b'A', 1, 3, suite.id()]);

        let pk2 = HybridPublicKey::from_bytes(&pk_wire).unwrap();
        let sk2 = HybridSecretKey::from_bytes(sk_wire.expose()).unwrap();
        let ct2 = HybridCiphertext::from_bytes(&ct_wire).unwrap();
        assert_eq!(pk2, pk);
        assert_eq!(ct2, ct);
        assert_eq!(sk2.suite(), suite);
        assert_eq!(sk2.expose_raw(), sk.expose_raw());
        assert_eq!(pk2.as_raw(), pk.as_raw());
        assert_eq!(ct2.as_raw(), ct.as_raw());

        // Decoded objects still work.
        assert!(kem.decapsulate_with(&sk2, &ct2).unwrap().ct_eq(&key));
    }
}

/// A decoder that discards its value.
type Decoder = fn(&[u8]) -> Result<()>;

/// Every decoder, named.
fn decoders() -> [(&'static str, Decoder); 3] {
    [
        ("pk", |b| HybridPublicKey::from_bytes(b).map(drop)),
        ("sk", |b| HybridSecretKey::from_bytes(b).map(drop)),
        ("ct", |b| HybridCiphertext::from_bytes(b).map(drop)),
    ]
}

#[test]
fn s1_decoders_reject_bad_lengths() {
    for enc in encoded_objects() {
        let objects = [&enc.pk, &enc.sk, &enc.ct];
        for ((name, decode), good) in decoders().into_iter().zip(objects) {
            assert!(decode(good).is_ok(), "{} {name} good", enc.suite);
            let empty = decode(&[]);
            assert!(
                matches!(empty, Err(Error::InvalidLength { .. })),
                "{} {name} empty: {empty:?}",
                enc.suite
            );
            let short = decode(&good[..good.len() - 1]);
            assert!(
                matches!(short, Err(Error::InvalidLength { .. })),
                "{} {name} len-1: {short:?}",
                enc.suite
            );
            let mut long = good.clone();
            long.push(0);
            let long = decode(&long);
            assert!(
                matches!(long, Err(Error::InvalidLength { .. })),
                "{} {name} len+1: {long:?}",
                enc.suite
            );
            for n in [1, 6, 7, 8] {
                assert!(decode(&good[..n]).is_err(), "{} {name} len {n}", enc.suite);
            }
        }
    }
}

#[test]
fn s2_decoders_reject_bad_headers() {
    for enc in encoded_objects() {
        let objects = [&enc.pk, &enc.sk, &enc.ct];
        for (ty, ((name, decode), good)) in decoders().into_iter().zip(objects).enumerate() {
            let own_type = u8::try_from(ty + 1).unwrap();
            // Magic: each byte.
            for i in 0..4 {
                let mut bad = good.clone();
                bad[i] ^= 0x20;
                assert_eq!(
                    decode(&bad),
                    Err(Error::InvalidEncoding("bad magic")),
                    "{} {name} magic[{i}]",
                    enc.suite
                );
            }
            // Version.
            for v in [0u8, 2, 255] {
                let mut bad = good.clone();
                bad[4] = v;
                assert_eq!(
                    decode(&bad),
                    Err(Error::InvalidEncoding("unsupported version")),
                    "{} {name} version {v}",
                    enc.suite
                );
            }
            // Object type: every other value.
            for t in (0u8..=255).filter(|t| *t != own_type) {
                let mut bad = good.clone();
                bad[5] = t;
                assert_eq!(
                    decode(&bad),
                    Err(Error::InvalidEncoding("unexpected object type")),
                    "{} {name} type {t}",
                    enc.suite
                );
            }
            // Suite id: unknown ids and the other known suites.
            for s in 0u8..=255 {
                if s == enc.suite.id() {
                    continue;
                }
                let mut bad = good.clone();
                bad[6] = s;
                let r = decode(&bad);
                if KemSuite::from_id(s).is_ok() {
                    // Secret keys have the same length in every suite, so a
                    // relabelled one is caught by its check value (U2-R2),
                    // not by length.
                    let expected_ok = if name == "sk" {
                        r == Err(Error::InvalidEncoding("secret key check value mismatch"))
                    } else {
                        matches!(r, Err(Error::InvalidLength { .. }))
                    };
                    assert!(expected_ok, "{} {name} as suite {s}: {r:?}", enc.suite);
                } else {
                    assert_eq!(r, Err(Error::UnknownSuite(s)), "{} {name}", enc.suite);
                }
            }
        }
    }
}

#[test]
fn from_raw_checks_length() {
    for suite in KemSuite::all() {
        for len in [0, suite.public_key_len() - 1, suite.public_key_len() + 1] {
            assert!(HybridPublicKey::from_raw(suite, &vec![0; len]).is_err());
        }
        for len in [0, suite.secret_key_len() - 1, suite.secret_key_len() + 1] {
            assert!(HybridSecretKey::from_raw(suite, &vec![0; len]).is_err());
        }
        for len in [0, suite.ciphertext_len() - 1, suite.ciphertext_len() + 1] {
            assert!(HybridCiphertext::from_raw(suite, &vec![0; len]).is_err());
        }
        assert!(HybridPublicKey::from_raw(suite, &vec![0; suite.public_key_len()]).is_ok());
    }
}

#[test]
fn cross_suite_objects_are_rejected() {
    let mut rng = OsEntropy::new();
    let suites = KemSuite::all();
    let keys: Vec<_> = suites
        .iter()
        .map(|s| {
            let kem = HybridKem::new(*s);
            let (pk, sk) = kem.generate(&mut rng).unwrap();
            let (ct, key) = kem.encapsulate_to(&pk, &mut rng).unwrap();
            (pk, sk, ct, key)
        })
        .collect();
    for (i, a) in suites.iter().enumerate() {
        let kem = HybridKem::new(*a);
        for (j, b) in suites.iter().enumerate() {
            if i == j {
                continue;
            }
            let (pk_b, sk_b, ct_b, _) = &keys[j];
            let (_, sk_a, ct_a, key_a) = &keys[i];
            // Typed API: suite mismatch.
            assert!(kem.encapsulate_to(pk_b, &mut rng).is_err(), "{a} pk of {b}");
            assert!(kem.decapsulate_with(sk_b, ct_a).is_err(), "{a} sk of {b}");
            assert!(kem.decapsulate_with(sk_a, ct_b).is_err(), "{a} ct of {b}");
            // Raw trait API: length mismatch.
            use vyra_core::Kem;
            assert!(
                matches!(
                    kem.encapsulate(pk_b.as_raw(), &mut rng),
                    Err(Error::InvalidLength { .. })
                ),
                "{a} raw pk of {b}"
            );
            assert!(
                matches!(
                    kem.decapsulate(sk_a.expose_raw(), ct_b.as_raw()),
                    Err(Error::InvalidLength { .. })
                ),
                "{a} raw ct of {b}"
            );
            // Raw secret key of another suite. The original check (reject
            // with InvalidLength) is invalid for seed-form keys: a suite-less
            // 96-byte string of seeds is valid for every parameter set and
            // cannot be rejected by a suite-less function. Replacement (U2-R2):
            // (a) the typed API rejects it (decapsulate_with above);
            // (b) the wire decoder rejects a relabelled key (check value);
            // (c) raw decapsulation accepts it but yields a key that differs
            //     from the sender's; HybridKem::decapsulate's rustdoc says the
            //     raw form carries no suite.
            let mut relabelled = sk_b.to_bytes().expose().to_vec();
            relabelled[6] = a.id();
            assert_eq!(
                HybridSecretKey::from_bytes(&relabelled).map(drop),
                Err(Error::InvalidEncoding("secret key check value mismatch")),
                "{a} wire sk relabelled from {b}"
            );
            let other = kem.decapsulate(sk_b.expose_raw(), ct_a.as_raw()).unwrap();
            assert!(
                !other.ct_eq(key_a),
                "{a} raw sk of {b} gave the sender's key"
            );
        }
    }
}
