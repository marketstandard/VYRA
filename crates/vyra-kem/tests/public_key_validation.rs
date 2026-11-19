//! K-2: public keys are validated at parse time.
//!
//! - HQC: the bits of the last public-key byte above bit `n - 1` must be zero
//!   (a VYRA strictness addition; honest keys always satisfy it).
//! - ML-KEM: the FIPS 203 §7.2 modulus check runs in `HybridPublicKey::from_bytes`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use vyra_core::{Error, OsEntropy};
use vyra_kem::{
    ComponentKem, Hqc128, Hqc192, Hqc256, HybridKem, HybridPublicKey, HybridSecretKey, KemSuite,
};

const HONEST_KEYS: usize = 50;

fn hqc_sets() -> [(&'static dyn ComponentKem, usize, u8); 3] {
    [
        (&Hqc128, Hqc128::N, Hqc128::PUBLIC_KEY_PADDING_MASK),
        (&Hqc192, Hqc192::N, Hqc192::PUBLIC_KEY_PADDING_MASK),
        (&Hqc256, Hqc256::N, Hqc256::PUBLIC_KEY_PADDING_MASK),
    ]
}

#[test]
fn hqc_padding_masks_follow_n() {
    // pk = 32-byte seed ‖ ceil(n/8) bytes of s.
    for (c, n, mask) in hqc_sets() {
        assert_eq!(c.public_key_len(), 32 + n.div_ceil(8), "{}", c.name());
        let used = n % 8;
        assert_eq!(mask.count_zeros() as usize, used, "{}", c.name());
        assert_ne!(mask, 0, "{}: n is not a multiple of 8", c.name());
    }
    assert_eq!(Hqc128::PUBLIC_KEY_PADDING_MASK, 0xE0); // n = 17669, n % 8 = 5
    assert_eq!(Hqc192::PUBLIC_KEY_PADDING_MASK, 0xF8); // n = 35851, n % 8 = 3
    assert_eq!(Hqc256::PUBLIC_KEY_PADDING_MASK, 0xE0); // n = 57637, n % 8 = 5
}

#[test]
fn hqc_honest_keys_pass_and_padding_bits_are_rejected() {
    let mut rng = OsEntropy::new();
    for (c, _, mask) in hqc_sets() {
        for _ in 0..HONEST_KEYS {
            let (pk, sk) = c.generate_keypair(&mut rng).unwrap();
            c.validate_public_key(&pk).unwrap();
            assert_eq!(pk.last().unwrap() & mask, 0, "{}", c.name());
            assert_eq!(c.public_key_from_secret(sk.expose()).unwrap(), pk);
        }
        let (pk, _) = c.generate_keypair(&mut rng).unwrap();
        for bit in 0..8u8 {
            if mask & (1 << bit) == 0 {
                continue;
            }
            let mut bad = pk.clone();
            *bad.last_mut().unwrap() ^= 1 << bit;
            let is_enc = |r: Result<(), Error>| matches!(r, Err(Error::InvalidEncoding(_)));
            assert!(
                is_enc(c.validate_public_key(&bad)),
                "{} bit {bit}",
                c.name()
            );
            assert!(
                matches!(
                    c.encapsulate(&bad, &mut rng),
                    Err(Error::InvalidEncoding(_))
                ),
                "{} encapsulate bit {bit}",
                c.name()
            );
        }
    }
}

#[test]
fn hybrid_parsing_rejects_noncanonical_public_keys() {
    let mut rng = OsEntropy::new();
    for suite in KemSuite::all() {
        let kem = HybridKem::new(suite);
        let (pk, sk) = kem.generate(&mut rng).unwrap();
        let wire = pk.to_bytes();
        assert!(HybridPublicKey::from_bytes(&wire).is_ok());

        // HQC padding bit: the last byte of the hybrid public key.
        let mut bad = wire.clone();
        *bad.last_mut().unwrap() ^= 0x80;
        assert!(
            matches!(
                HybridPublicKey::from_bytes(&bad),
                Err(Error::InvalidEncoding(_))
            ),
            "{suite} HQC padding"
        );

        // ML-KEM coefficient >= q: first 12-bit coefficient := 0xFFF.
        let mut bad = wire.clone();
        bad[7] = 0xFF;
        bad[8] |= 0x0F;
        assert!(
            matches!(
                HybridPublicKey::from_bytes(&bad),
                Err(Error::InvalidEncoding(_))
            ),
            "{suite} ML-KEM modulus"
        );
        assert!(
            matches!(
                HybridPublicKey::from_raw(suite, &bad[7..]),
                Err(Error::InvalidEncoding(_))
            ),
            "{suite} from_raw"
        );

        // U2-R2: a secret key is two seeds; every byte string of the right
        // length is accepted, and the public key derived from it is canonical.
        for fill in [0x00u8, 0xFF, 0x5A] {
            let seeds = vec![fill; suite.secret_key_len()];
            let typed = HybridSecretKey::from_raw(suite, &seeds).unwrap();
            let derived = kem.public_key_from_secret(typed.expose_raw()).unwrap();
            assert!(
                HybridPublicKey::from_raw(suite, &derived).is_ok(),
                "{suite}"
            );
        }
        assert!(HybridSecretKey::from_raw(suite, sk.expose_raw()).is_ok());
    }
}
