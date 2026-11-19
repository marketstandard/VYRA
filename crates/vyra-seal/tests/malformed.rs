//! S1 (length validation) and S2 (header validation) for `SealedBox::open`.
//!
//! Truncations below the minimum length `overhead(suite)` are malformed
//! (`InvalidLength`); truncations at or above it are well-formed boxes with a
//! shorter body and must fail authentication, as must a box extended by one
//! byte.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use common::{ct1_len, keypair, pattern};
use vyra_core::wire::HEADER_LEN;
use vyra_core::{DeterministicEntropy, Error};
use vyra_kem::KemSuite;
use vyra_seal::{SealedBox, TAG_LEN};

const PT_LEN: usize = 40;

fn is_invalid_length(r: &Result<(), Error>) -> bool {
    matches!(r, Err(Error::InvalidLength { .. }))
}

fn lengths(suite: KemSuite) {
    let (pk, sk) = keypair(suite, &[b'l', suite.id()]);
    let sbox = SealedBox::new(suite);
    let mut rng = DeterministicEntropy::from_seed(&[b'L', suite.id()]);
    let aad = b"aad";
    let sealed = sbox.seal(&pk, aad, &pattern(PT_LEN, 3), &mut rng).unwrap();
    let min = SealedBox::overhead(suite);
    let full = sealed.len();
    assert_eq!(full, min + PT_LEN);

    let ct1_end = HEADER_LEN + ct1_len(suite);
    let ct_end = HEADER_LEN + suite.ciphertext_len();
    let mut cuts = vec![0usize, 1];
    for boundary in [
        HEADER_LEN,
        ct1_end,
        ct_end,
        ct_end + TAG_LEN,
        full - TAG_LEN,
    ] {
        cuts.extend([boundary - 1, boundary, boundary + 1]);
    }
    cuts.push(full - 1);
    cuts.sort_unstable();
    cuts.dedup();

    for len in cuts {
        assert!(len < full);
        let r = sbox.open(&sk, aad, &sealed[..len]).map(|_| ());
        if len < min {
            assert!(is_invalid_length(&r), "{suite} truncated to {len}: {r:?}");
        } else {
            assert_eq!(
                r,
                Err(Error::DecryptionFailed),
                "{suite} truncated to {len}"
            );
        }
    }

    // Extended by one byte: well-formed, must fail authentication.
    for extra in [0x00u8, 0xff] {
        let mut ext = sealed.clone();
        ext.push(extra);
        assert_eq!(
            sbox.open(&sk, aad, &ext).map(|_| ()),
            Err(Error::DecryptionFailed),
            "{suite} extended with {extra:#04x}"
        );
    }

    // Empty input.
    assert!(is_invalid_length(&sbox.open(&sk, aad, &[]).map(|_| ())));

    // A box with an empty plaintext has exactly the minimum length.
    let empty = sbox.seal(&pk, aad, b"", &mut rng).unwrap();
    assert_eq!(empty.len(), min);
    assert!(sbox.open(&sk, aad, &empty).unwrap().is_empty());
    assert!(is_invalid_length(
        &sbox.open(&sk, aad, &empty[..min - 1]).map(|_| ())
    ));
    let mut ext = empty.clone();
    ext.push(0);
    assert_eq!(
        sbox.open(&sk, aad, &ext).map(|_| ()),
        Err(Error::DecryptionFailed)
    );
}

#[test]
fn lengths_vyra1() {
    lengths(KemSuite::Vyra1);
}

#[test]
fn lengths_vyra3() {
    lengths(KemSuite::Vyra3);
}

#[test]
fn lengths_vyra5() {
    lengths(KemSuite::Vyra5);
}

/// S2: wrong magic (each byte), version, object type and suite id.
#[test]
fn header_fields_are_validated() {
    let suite = KemSuite::Vyra3;
    let (pk, sk) = keypair(suite, b"hdr");
    let sbox = SealedBox::new(suite);
    let mut rng = DeterministicEntropy::from_seed(b"hdr");
    let sealed = sbox.seal(&pk, b"", b"header test", &mut rng).unwrap();
    assert_eq!(&sealed[..HEADER_LEN], b"VYRA\x01\x07\x03");

    let with = |i: usize, v: u8| {
        let mut b = sealed.clone();
        b[i] = v;
        sbox.open(&sk, b"", &b).map(|_| ())
    };

    for (i, magic_byte) in b"VYRA".iter().enumerate() {
        assert_eq!(
            with(i, magic_byte ^ 0x20),
            Err(Error::InvalidEncoding("bad magic"))
        );
    }
    for v in [0u8, 2, 0xff] {
        assert_eq!(
            with(4, v),
            Err(Error::InvalidEncoding("unsupported version"))
        );
    }
    for v in [0u8, 1, 2, 3, 4, 5, 6, 8, 0xff] {
        assert_eq!(
            with(5, v),
            Err(Error::InvalidEncoding("unexpected object type")),
            "object type {v}"
        );
    }
    for v in [0u8, 2, 4, 6, 0xff] {
        assert_eq!(with(6, v), Err(Error::UnknownSuite(v)), "suite id {v}");
    }
    for v in [1u8, 5] {
        assert!(
            matches!(with(6, v), Err(Error::InvalidEncoding(_))),
            "other known suite id {v}"
        );
    }
}
