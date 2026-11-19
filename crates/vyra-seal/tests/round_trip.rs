//! F8 (round trip), F6 (sealed length), recipient/suite binding and
//! randomness behaviour of `SealedBox`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::{keypair, pattern};
use vyra_core::{DeterministicEntropy, Error, OsEntropy};
use vyra_kem::KemSuite;
use vyra_seal::SealedBox;

const MIB: usize = 1 << 20;

/// F8 + F6: every suite, plaintexts of 0, 1 and 1 MiB bytes, empty and
/// non-empty AAD.
#[test]
fn round_trip_all_suites_sizes_and_aad() {
    for suite in KemSuite::all() {
        let (pk, sk) = keypair(suite, &[b'r', suite.id()]);
        let sbox = SealedBox::new(suite);
        let mut rng = DeterministicEntropy::from_seed(&[b'R', suite.id()]);
        for len in [0usize, 1, MIB] {
            let pt = pattern(len, suite.id());
            for aad in [&b""[..], &b"header: v1; to=alice"[..]] {
                let sealed = sbox.seal(&pk, aad, &pt, &mut rng).unwrap();
                assert_eq!(
                    sealed.len(),
                    pt.len() + SealedBox::overhead(suite),
                    "F6 length, {suite} len {len}"
                );
                let opened = sbox.open(&sk, aad, &sealed).unwrap();
                assert_eq!(opened.expose(), pt.as_slice(), "{suite} len {len}");
            }
        }
    }
}

/// F6: the overhead constants equal the documented table.
#[test]
fn overhead_per_suite() {
    assert_eq!(SealedBox::overhead(KemSuite::Vyra1), 7 + 768 + 4433 + 16);
    assert_eq!(SealedBox::overhead(KemSuite::Vyra3), 7 + 1088 + 8978 + 16);
    assert_eq!(SealedBox::overhead(KemSuite::Vyra5), 7 + 1568 + 14421 + 16);
    assert_eq!(SealedBox::overhead(KemSuite::Vyra1), 5224);
    assert_eq!(SealedBox::overhead(KemSuite::Vyra3), 10089);
    assert_eq!(SealedBox::overhead(KemSuite::Vyra5), 16012);
}

/// A sealed box addressed to one key pair does not open with another key
/// pair of the same suite (implicit rejection, then the tag fails).
#[test]
fn wrong_recipient_key_fails_authentication() {
    for suite in KemSuite::all() {
        let (pk, _sk) = keypair(suite, &[b'a', suite.id()]);
        let (_pk2, sk2) = keypair(suite, &[b'b', suite.id()]);
        let sbox = SealedBox::new(suite);
        let sealed = sbox
            .seal(&pk, b"aad", b"for alice only", &mut OsEntropy::new())
            .unwrap();
        assert_eq!(
            sbox.open(&sk2, b"aad", &sealed).map(|_| ()),
            Err(Error::DecryptionFailed),
            "{suite}"
        );
    }
}

/// Mixing suites is rejected as an encoding error before any decryption.
#[test]
fn cross_suite_is_rejected() {
    let mut rng = OsEntropy::new();
    let (pk1, sk1) = keypair(KemSuite::Vyra1, b"x1");
    let (_pk3, sk3) = keypair(KemSuite::Vyra3, b"x3");
    let box1 = SealedBox::new(KemSuite::Vyra1);
    let box3 = SealedBox::new(KemSuite::Vyra3);

    // Sealing to a key of another suite.
    assert!(matches!(
        box3.seal(&pk1, b"", b"m", &mut rng),
        Err(Error::InvalidEncoding(_))
    ));

    let sealed1 = box1.seal(&pk1, b"", b"m", &mut rng).unwrap();
    // A suite-1 box opened by a suite-3 SealedBox, with either key.
    assert!(matches!(
        box3.open(&sk3, b"", &sealed1),
        Err(Error::InvalidEncoding(_))
    ));
    assert!(matches!(
        box3.open(&sk1, b"", &sealed1),
        Err(Error::InvalidEncoding(_))
    ));
    // The right SealedBox with a secret key of another suite.
    assert!(matches!(
        box1.open(&sk3, b"", &sealed1),
        Err(Error::InvalidEncoding(_))
    ));
    // Sanity: the matching combination opens.
    assert_eq!(box1.open(&sk1, b"", &sealed1).unwrap().expose(), b"m");
}

/// Under `DeterministicEntropy` sealing is byte-reproducible.
#[test]
fn deterministic_entropy_is_reproducible() {
    for suite in KemSuite::all() {
        let (pk, _) = keypair(suite, &[b'd', suite.id()]);
        let sbox = SealedBox::new(suite);
        let seal = |seed: &[u8]| {
            sbox.seal(
                &pk,
                b"aad",
                b"same message",
                &mut DeterministicEntropy::from_seed(seed),
            )
            .unwrap()
        };
        assert_eq!(seal(b"seed-1"), seal(b"seed-1"), "{suite}");
        assert_ne!(seal(b"seed-1"), seal(b"seed-2"), "{suite}");
    }
}

/// Under `OsEntropy` two seals of the same message differ (fresh KEM
/// encapsulation, hence fresh key and nonce) and both open.
#[test]
fn os_entropy_seals_differ() {
    let suite = KemSuite::Vyra1;
    let (pk, sk) = keypair(suite, b"os");
    let sbox = SealedBox::new(suite);
    let mut rng = OsEntropy::new();
    let a = sbox.seal(&pk, b"", b"same message", &mut rng).unwrap();
    let b = sbox.seal(&pk, b"", b"same message", &mut rng).unwrap();
    assert_ne!(a, b);
    assert_eq!(sbox.open(&sk, b"", &a).unwrap().expose(), b"same message");
    assert_eq!(sbox.open(&sk, b"", &b).unwrap().expose(), b"same message");
}

/// `open` returns zeroizing, redacted plaintext.
#[test]
fn plaintext_debug_is_redacted() {
    let suite = KemSuite::Vyra1;
    let (pk, sk) = keypair(suite, b"dbg");
    let sbox = SealedBox::new(suite);
    let sealed = sbox
        .seal(&pk, b"", b"secret words", &mut OsEntropy::new())
        .unwrap();
    let pt = sbox.open(&sk, b"", &sealed).unwrap();
    assert_eq!(format!("{pt:?}"), "[REDACTED]");
    assert_eq!(format!("{sbox:?}"), "SealedBox { suite: Vyra1 }");
}
