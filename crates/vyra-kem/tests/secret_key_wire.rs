//! U2-R2: the wire secret key `header ‖ sk1 ‖ sk2 ‖ check` and its 16-byte
//! check value (see `vyra_kem::keys`).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use common::to_hex;
use sha3::{Digest, Sha3_256};
use vyra_core::{Error, OsEntropy};
use vyra_kem::{
    HybridKem, HybridSecretKey, KemSuite, SECRET_KEY_CHECK_LABEL, SECRET_KEY_CHECK_LEN,
};

/// First 16 bytes of SHA3-256 over `u64_be(len) ‖ bytes` frames, by hand.
fn hand_check(suite: u8, raw: &[u8]) -> Vec<u8> {
    let mut h = Sha3_256::new();
    for f in [b"VYRA-KEM-SK-v1".as_slice(), &[suite], raw] {
        h.update((f.len() as u64).to_be_bytes());
        h.update(f);
    }
    h.finalize()[..16].to_vec()
}

#[test]
fn check_value_known_answer() {
    assert_eq!(SECRET_KEY_CHECK_LABEL, b"VYRA-KEM-SK-v1");
    assert_eq!(SECRET_KEY_CHECK_LEN, 16);
    let raw: Vec<u8> = (0u8..96).collect();
    let sk = HybridSecretKey::from_raw(KemSuite::Vyra3, &raw).unwrap();
    let wire = sk.to_bytes();
    let wire = wire.expose();
    assert_eq!(wire.len(), 119);
    assert_eq!(&wire[..7], b"VYRA\x01\x02\x03");
    assert_eq!(&wire[7..103], raw.as_slice());
    assert_eq!(&wire[103..], hand_check(3, &raw).as_slice());
    // Pinned (computed by a separate hand-framing program).
    assert_eq!(to_hex(&wire[103..]), "3772eff345b725ef0626cb887a01f1e4");
}

#[test]
fn check_value_matches_hand_framing_for_generated_keys() {
    let mut rng = OsEntropy::new();
    for suite in KemSuite::all() {
        let (_, sk) = HybridKem::new(suite).generate(&mut rng).unwrap();
        let wire = sk.to_bytes();
        let wire = wire.expose();
        assert_eq!(wire.len(), suite.encoded_secret_key_len());
        assert_eq!(
            &wire[103..],
            hand_check(suite.id(), sk.expose_raw()).as_slice()
        );
        let back = HybridSecretKey::from_bytes(wire).unwrap();
        assert_eq!(back.expose_raw(), sk.expose_raw());
        assert_eq!(back.suite(), suite);
    }
}

/// Every single-bit change of a wire secret key is rejected: header bits by
/// the header checks, suite-id bits by the unknown-suite check or the check
/// value, seed and check-value bits by the check value.
#[test]
fn every_bit_flip_of_a_wire_secret_key_is_rejected() {
    let mut rng = OsEntropy::new();
    for suite in KemSuite::all() {
        let (_, sk) = HybridKem::new(suite).generate(&mut rng).unwrap();
        let wire = sk.to_bytes().expose().to_vec();
        assert_eq!(wire.len(), 119);
        for pos in 0..wire.len() {
            for bit in 0..8 {
                let mut bad = wire.clone();
                bad[pos] ^= 1 << bit;
                let r = HybridSecretKey::from_bytes(&bad).map(drop);
                assert!(r.is_err(), "{suite}: flip at byte {pos} bit {bit} accepted");
                if pos >= 7 {
                    assert_eq!(
                        r,
                        Err(Error::InvalidEncoding("secret key check value mismatch")),
                        "{suite}: byte {pos} bit {bit}"
                    );
                }
            }
        }
    }
}
