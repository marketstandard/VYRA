//! K-1 / U2-R2: the hybrid secret key is `sk1 ‖ sk2`, the two components'
//! key-generation seeds; the public keys hashed by the combiner are derived
//! from them.
//!
//! What each standard reads when decapsulating, per secret-key region:
//!
//! | region               | read for a valid ciphertext?                      |
//! |----------------------|---------------------------------------------------|
//! | ML-KEM `d` (32 B)    | yes: `KeyGen_internal` derives `ek`, `dk_pke`, H(ek) from it |
//! | ML-KEM `z` (32 B)    | no: only the implicit-rejection key `J(z ‖ c)`    |
//! | HQC `seed_kem` (32 B)| yes: `seed_pke ‖ sigma = XOF(seed_kem ‖ k/8)` (HQC v5.1), so it determines the PKE key pair *and* the rejection secret `sigma` |
//!
//! So a flipped bit in ML-KEM `d` or in the HQC seed must change the
//! decapsulated key of a valid ciphertext, and also the implicit-rejection key
//! of a tampered one. A flipped bit in ML-KEM `z` cannot change the key of a
//! valid ciphertext (FIPS 203 does not read `z` there, and the sender never
//! sees it); it must change the implicit-rejection key.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use common::{flip, spread};
use vyra_core::{DeterministicEntropy, Kem, OsEntropy, SecretBytes};
use vyra_kem::{
    ComponentKem, Hqc128, Hqc192, Hqc256, HybridKem, HybridSecretKey, KemSuite, MlKem512, MlKem768,
    MlKem1024,
};

const KEYPAIRS: usize = 20;
const POSITIONS: usize = 32;

#[test]
fn derived_public_key_equals_generated() {
    let mut rng = OsEntropy::new();
    let comps: [&dyn ComponentKem; 6] =
        [&MlKem512, &MlKem768, &MlKem1024, &Hqc128, &Hqc192, &Hqc256];
    for c in comps {
        for _ in 0..KEYPAIRS {
            let (pk, sk) = c.generate_keypair(&mut rng).unwrap();
            assert_eq!(
                c.public_key_from_secret(sk.expose()).unwrap(),
                pk,
                "{}",
                c.name()
            );
        }
    }
    for suite in KemSuite::all() {
        let kem = HybridKem::new(suite);
        for _ in 0..KEYPAIRS {
            let (pk, sk) = kem.generate_keypair(&mut rng).unwrap();
            assert_eq!(sk.len(), suite.secret_key_len());
            assert_eq!(
                kem.public_key_from_secret(sk.expose()).unwrap(),
                pk,
                "{suite}"
            );
        }
    }
}

/// The VYRA HQC secret key is the 32-byte seed, the upstream deterministic
/// key generation from that seed yields exactly the generated public key, and
/// the upstream decapsulation key is that same seed (HQC v5.1 compressed
/// `dk_KEM = seed_KEM`).
#[test]
fn hqc_secret_key_is_the_keygen_seed() {
    let mut rng = OsEntropy::new();
    for _ in 0..KEYPAIRS {
        let (pk, sk) = Hqc128.generate_keypair(&mut rng).unwrap();
        assert_eq!(sk.len(), 32);
        let seed: [u8; 32] = sk.expose().try_into().unwrap();
        let (ek, dk) = vyra_hqc::Hqc128::generate_key_deterministic(&seed);
        assert_eq!(ek.as_ref(), pk.as_slice());
        assert_eq!(dk.as_ref(), sk.expose());

        let (pk, sk) = Hqc192.generate_keypair(&mut rng).unwrap();
        let seed: [u8; 32] = sk.expose().try_into().unwrap();
        let (ek, dk) = vyra_hqc::Hqc192::generate_key_deterministic(&seed);
        assert_eq!(ek.as_ref(), pk.as_slice());
        assert_eq!(dk.as_ref(), sk.expose());

        let (pk, sk) = Hqc256.generate_keypair(&mut rng).unwrap();
        let seed: [u8; 32] = sk.expose().try_into().unwrap();
        let (ek, dk) = vyra_hqc::Hqc256::generate_key_deterministic(&seed);
        assert_eq!(ek.as_ref(), pk.as_slice());
        assert_eq!(dk.as_ref(), sk.expose());
    }
}

/// (name, start, len, read for a valid ciphertext) regions of the hybrid sk.
fn regions() -> [(&'static str, usize, usize, bool); 3] {
    [
        ("ML-KEM d", 0, 32, true),
        ("ML-KEM z", 32, 32, false),
        ("HQC seed_kem", 64, 32, true),
    ]
}

fn secret_key_bit_flips(suite: KemSuite) {
    let kem = HybridKem::new(suite);
    assert_eq!(suite.secret_key_len(), 96);
    let mut rng = DeterministicEntropy::from_seed(&[b's', suite.id()]);
    let (pk, sk) = kem.generate_keypair(&mut rng).unwrap();
    let (ct, key) = kem.encapsulate(&pk, &mut rng).unwrap();
    // Tamper with both ct1 and ct2 so that both components reject.
    let bad_ct = flip(&flip(&ct, 5, 0), ct.len() - 100, 0);
    let rejection = kem.decapsulate(sk.expose(), &bad_ct).unwrap();

    let mut covered = 0;
    for (name, start, len, read) in regions() {
        for (n, pos) in spread(len, POSITIONS).into_iter().enumerate() {
            let at = start + pos;
            let bad_sk = flip(sk.expose(), at, n);
            let k = kem
                .decapsulate(&bad_sk, &ct)
                .expect("every seed of the right length is a valid key");
            if read {
                assert!(!k.ct_eq(&key), "{suite} {name} bit at {at} kept the key");
            } else {
                assert!(k.ct_eq(&key), "{suite} {name} at {at}");
            }
            let rej = kem.decapsulate(&bad_sk, &bad_ct).unwrap();
            assert!(
                !rej.ct_eq(&rejection),
                "{suite} {name} at {at}: rejection key unchanged"
            );
            covered += 1;
        }
    }
    assert_eq!(covered, 96, "every byte of the 96-byte key sampled");
}

#[test]
fn k1_secret_key_bit_flips_vyra1() {
    secret_key_bit_flips(KemSuite::Vyra1);
}

#[test]
fn k1_secret_key_bit_flips_vyra3() {
    secret_key_bit_flips(KemSuite::Vyra3);
}

#[test]
fn k1_secret_key_bit_flips_vyra5() {
    secret_key_bit_flips(KemSuite::Vyra5);
}

/// A secret key spliced from two key pairs decapsulates (implicitly) to a
/// key different from the sender's, and derives the other pair's HQC public
/// key: the secret key carries no public key of its own.
#[test]
fn spliced_secret_key_does_not_decapsulate_correctly() {
    let mut rng = OsEntropy::new();
    for suite in KemSuite::all() {
        let kem = HybridKem::new(suite);
        let (pk_a, sk_a) = kem.generate_keypair(&mut rng).unwrap();
        let (pk_b, sk_b) = kem.generate_keypair(&mut rng).unwrap();
        let (ct, key) = kem.encapsulate(&pk_a, &mut rng).unwrap();
        // ML-KEM half from A, HQC half from B.
        let mut spliced = sk_a.expose()[..64].to_vec();
        spliced.extend_from_slice(&sk_b.expose()[64..]);
        let got = kem.decapsulate(&spliced, &ct).unwrap();
        assert!(!got.ct_eq(&key), "{suite}");
        let typed = HybridSecretKey::from_raw(suite, &spliced).unwrap();
        let derived = kem.public_key_from_secret(typed.expose_raw()).unwrap();
        let mlkem_len = suite.public_key_len() - hqc_pk_len(suite);
        assert_eq!(&derived[..mlkem_len], &pk_a[..mlkem_len], "{suite}");
        assert_eq!(&derived[mlkem_len..], &pk_b[mlkem_len..], "{suite}");
        let _ = SecretBytes::new(spliced);
    }
}

fn hqc_pk_len(suite: KemSuite) -> usize {
    match suite {
        KemSuite::Vyra1 => Hqc128::PUBLIC_KEY_LEN,
        KemSuite::Vyra3 => Hqc192::PUBLIC_KEY_LEN,
        KemSuite::Vyra5 => Hqc256::PUBLIC_KEY_LEN,
    }
}
