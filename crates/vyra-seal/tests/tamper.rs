//! S5: AEAD tampering. For each suite, one bit is flipped at positions spread
//! over every region of a sealed box (header: all 56 bits; ML-KEM ciphertext,
//! HQC ciphertext, AEAD body and tag: 32 bit positions each) and over the AAD
//! (32 bit positions). Every tampered input must be rejected without panicking:
//! header flips as an encoding / suite error, everything else as
//! `DecryptionFailed`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::{flip_bit, keypair, pattern, regions, spread_bits};
use vyra_core::{DeterministicEntropy, Error};
use vyra_kem::KemSuite;
use vyra_seal::SealedBox;

const POSITIONS: usize = 32;
const PT_LEN: usize = 64;
const AAD_LEN: usize = 64;

fn tamper(suite: KemSuite) {
    let (pk, sk) = keypair(suite, &[b't', suite.id()]);
    let sbox = SealedBox::new(suite);
    let pt = pattern(PT_LEN, 1);
    let aad = pattern(AAD_LEN, 2);
    let mut rng = DeterministicEntropy::from_seed(&[b'T', suite.id()]);
    let sealed = sbox.seal(&pk, &aad, &pt, &mut rng).unwrap();
    assert_eq!(sbox.open(&sk, &aad, &sealed).unwrap().expose(), pt);

    let r = regions(suite, PT_LEN);
    assert_eq!(r.tag.end, sealed.len());

    // Header: every bit.
    let header_bits = spread_bits(r.header.clone(), usize::MAX);
    assert_eq!(header_bits.len(), 56);
    for bit in header_bits {
        let bad = flip_bit(&sealed, bit);
        let err = sbox.open(&sk, &aad, &bad).map(|_| ()).unwrap_err();
        assert!(
            matches!(err, Error::InvalidEncoding(_) | Error::UnknownSuite(_)),
            "{suite} header bit {bit}: {err:?}"
        );
    }

    // KEM ct1, KEM ct2, AEAD body, tag.
    for (name, range) in [
        ("ct1 (ML-KEM)", r.ct1.clone()),
        ("ct2 (HQC)", r.ct2.clone()),
        ("AEAD body", r.body.clone()),
        ("tag", r.tag.clone()),
    ] {
        let bits = spread_bits(range, POSITIONS);
        assert_eq!(bits.len(), POSITIONS);
        for bit in bits {
            let bad = flip_bit(&sealed, bit);
            assert_eq!(
                sbox.open(&sk, &aad, &bad).map(|_| ()),
                Err(Error::DecryptionFailed),
                "{suite} {name} bit {bit}"
            );
        }
    }

    // AAD.
    for bit in spread_bits(0..AAD_LEN, POSITIONS) {
        let bad_aad = flip_bit(&aad, bit);
        assert_eq!(
            sbox.open(&sk, &bad_aad, &sealed).map(|_| ()),
            Err(Error::DecryptionFailed),
            "{suite} aad bit {bit}"
        );
    }
}

#[test]
fn tamper_vyra1() {
    tamper(KemSuite::Vyra1);
}

#[test]
fn tamper_vyra3() {
    tamper(KemSuite::Vyra3);
}

#[test]
fn tamper_vyra5() {
    tamper(KemSuite::Vyra5);
}
