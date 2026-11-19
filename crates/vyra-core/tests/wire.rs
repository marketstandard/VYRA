//! Wire header and Reader tests, including property tests for panic freedom.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use proptest::prelude::*;
use vyra_core::Error;
use vyra_core::wire::{self, HEADER_LEN, ObjectType, Reader};

const ALL_TYPES: [ObjectType; 7] = [
    ObjectType::KemPublicKey,
    ObjectType::KemSecretKey,
    ObjectType::KemCiphertext,
    ObjectType::SigPublicKey,
    ObjectType::SigSecretKey,
    ObjectType::Signature,
    ObjectType::SealedBox,
];

#[test]
fn round_trip_every_type() {
    for t in ALL_TYPES {
        for payload in [&b""[..], b"x", &[0xFFu8; 300][..]] {
            let enc = wire::encode(t, 3, payload);
            assert_eq!(enc.len(), HEADER_LEN + payload.len());
            let (suite, got) = wire::decode(&enc, t).unwrap();
            assert_eq!(suite, 3);
            assert_eq!(got, payload);
        }
    }
}

#[test]
fn rejects_empty() {
    assert_eq!(
        wire::decode(&[], ObjectType::KemPublicKey),
        Err(Error::InvalidLength {
            what: "wire header",
            expected: HEADER_LEN,
            actual: 0
        })
    );
}

#[test]
fn rejects_truncated_header() {
    let enc = wire::encode(ObjectType::KemPublicKey, 1, b"");
    for len in 0..HEADER_LEN {
        let err = wire::decode(&enc[..len], ObjectType::KemPublicKey).unwrap_err();
        assert!(matches!(err, Error::InvalidLength { actual, .. } if actual == len));
    }
}

#[test]
fn rejects_wrong_magic() {
    let mut enc = wire::encode(ObjectType::KemPublicKey, 1, b"p");
    for i in 0..4 {
        let mut bad = enc.clone();
        bad[i] ^= 0x20;
        assert_eq!(
            wire::decode(&bad, ObjectType::KemPublicKey),
            Err(Error::InvalidEncoding("bad magic"))
        );
    }
    enc[0] = b'v';
    assert!(wire::decode(&enc, ObjectType::KemPublicKey).is_err());
}

#[test]
fn rejects_wrong_version() {
    for v in [0u8, 2, 255] {
        let mut enc = wire::encode(ObjectType::Signature, 1, b"p");
        enc[4] = v;
        assert_eq!(
            wire::decode(&enc, ObjectType::Signature),
            Err(Error::InvalidEncoding("unsupported version"))
        );
    }
}

#[test]
fn rejects_wrong_type() {
    for t in ALL_TYPES {
        let enc = wire::encode(t, 1, b"p");
        for other in ALL_TYPES {
            let res = wire::decode(&enc, other);
            if other == t {
                assert!(res.is_ok());
            } else {
                assert_eq!(res, Err(Error::InvalidEncoding("unexpected object type")));
            }
        }
    }
    // Unassigned type byte.
    let mut enc = wire::encode(ObjectType::SealedBox, 1, b"");
    enc[5] = 0;
    assert!(wire::decode(&enc, ObjectType::SealedBox).is_err());
}

#[test]
fn reader_takes_and_finishes() {
    let mut r = Reader::new(b"abcdef");
    assert_eq!(r.take(2, "a").unwrap(), b"ab");
    assert_eq!(r.remaining(), 4);
    assert_eq!(r.take(4, "b").unwrap(), b"cdef");
    assert_eq!(r.take(0, "c").unwrap(), b"");
    r.finish().unwrap();
}

#[test]
fn reader_rejects_short() {
    let mut r = Reader::new(b"abc");
    assert_eq!(
        r.take(4, "field"),
        Err(Error::InvalidLength {
            what: "field",
            expected: 4,
            actual: 3
        })
    );
    // Unchanged after error.
    assert_eq!(r.remaining(), 3);
    assert_eq!(
        r.take(usize::MAX, "huge").map(|_| ()).unwrap_err(),
        Error::InvalidLength {
            what: "huge",
            expected: usize::MAX,
            actual: 3
        }
    );
}

#[test]
fn reader_rejects_trailing_bytes() {
    let mut r = Reader::new(b"abc");
    r.take(2, "a").unwrap();
    assert_eq!(
        r.finish(),
        Err(Error::InvalidLength {
            what: "trailing bytes",
            expected: 0,
            actual: 1
        })
    );
}

#[test]
fn decode_then_reader_rejects_extended_payload() {
    // Pattern a downstream decoder uses: fixed-size payload, then finish().
    let enc = wire::encode(ObjectType::KemCiphertext, 1, &[7u8; 33]);
    let (_, payload) = wire::decode(&enc, ObjectType::KemCiphertext).unwrap();
    let mut r = Reader::new(payload);
    r.take(32, "ciphertext").unwrap();
    assert!(r.finish().is_err());
}

proptest! {
    #[test]
    fn decode_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..64), t in 1u8..=7) {
        let t = ObjectType::from_u8(t).unwrap();
        let _ = wire::decode(&bytes, t);
    }

    #[test]
    fn decode_accepts_any_payload_after_valid_header(
        payload in proptest::collection::vec(any::<u8>(), 0..256),
        suite in any::<u8>(),
    ) {
        let enc = wire::encode(ObjectType::SealedBox, suite, &payload);
        let (s, p) = wire::decode(&enc, ObjectType::SealedBox).unwrap();
        prop_assert_eq!(s, suite);
        prop_assert_eq!(p, &payload[..]);
    }

    #[test]
    fn reader_never_panics(
        bytes in proptest::collection::vec(any::<u8>(), 0..64),
        takes in proptest::collection::vec(any::<usize>(), 0..8),
        small in proptest::collection::vec(0usize..16, 0..8),
    ) {
        let mut r = Reader::new(&bytes);
        let mut consumed = 0usize;
        for n in takes.into_iter().chain(small) {
            if let Ok(s) = r.take(n, "x") {
                prop_assert_eq!(s.len(), n);
                consumed += n;
            }
            prop_assert_eq!(r.remaining(), bytes.len() - consumed);
        }
        let _ = r.clone().rest();
        let _ = r.finish();
    }
}
