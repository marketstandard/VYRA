//! F3: hybrid KEM round trip, ≥100 fresh key pairs per suite.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use vyra_core::{Kem, OsEntropy};
use vyra_kem::{HybridKem, KemSuite};

const KEY_PAIRS_PER_SUITE: usize = 100;

fn round_trip(suite: KemSuite) {
    let kem = HybridKem::new(suite);
    let mut rng = OsEntropy::new();
    for i in 0..KEY_PAIRS_PER_SUITE {
        let (pk, sk) = kem.generate_keypair(&mut rng).unwrap();
        let (ct, k_send) = kem.encapsulate(&pk, &mut rng).unwrap();
        let k_recv = kem.decapsulate(sk.expose(), &ct).unwrap();
        assert_eq!(k_send.len(), 32);
        assert!(k_send.ct_eq(&k_recv), "{suite}: round trip {i} failed");
    }
}

#[test]
fn f3_round_trip_vyra1() {
    round_trip(KemSuite::Vyra1);
}

#[test]
fn f3_round_trip_vyra3() {
    round_trip(KemSuite::Vyra3);
}

#[test]
fn f3_round_trip_vyra5() {
    round_trip(KemSuite::Vyra5);
}

#[test]
fn typed_round_trip_all_suites() {
    let mut rng = OsEntropy::new();
    for suite in KemSuite::all() {
        let kem = HybridKem::new(suite);
        let (pk, sk) = kem.generate(&mut rng).unwrap();
        let (ct, k_send) = kem.encapsulate_to(&pk, &mut rng).unwrap();
        let k_recv = kem.decapsulate_with(&sk, &ct).unwrap();
        assert!(k_send.ct_eq(&k_recv), "{suite}");
    }
}

#[test]
fn component_round_trips() {
    let mut rng = OsEntropy::new();
    for c in vyra_kem_components() {
        let (pk, sk) = c.generate_keypair(&mut rng).unwrap();
        let (ct, ss) = c.encapsulate(&pk, &mut rng).unwrap();
        let ss2 = c.decapsulate(sk.expose(), &ct).unwrap();
        assert!(ss.ct_eq(&ss2), "{}", c.name());
    }
}

fn vyra_kem_components() -> Vec<Box<dyn Kem>> {
    use vyra_kem::{Hqc128, Hqc192, Hqc256, MlKem512, MlKem768, MlKem1024};
    vec![
        Box::new(MlKem512),
        Box::new(MlKem768),
        Box::new(MlKem1024),
        Box::new(Hqc128),
        Box::new(Hqc192),
        Box::new(Hqc256),
    ]
}

#[test]
fn suite_metadata() {
    for suite in KemSuite::all() {
        let kem = HybridKem::new(suite);
        assert_eq!(kem.name(), suite.name());
        assert_eq!(kem.level(), suite.level());
        assert_eq!(kem.public_key_len(), suite.public_key_len());
        assert_eq!(kem.secret_key_len(), suite.secret_key_len());
        assert_eq!(kem.ciphertext_len(), suite.ciphertext_len());
        assert_eq!(kem.shared_secret_len(), suite.shared_secret_len());
        assert_eq!(KemSuite::from_id(suite.id()), Ok(suite));
        assert_eq!(KemSuite::try_from(suite.id()), Ok(suite));
        assert_eq!(suite.to_string(), suite.name());
    }
    assert_eq!(KemSuite::Vyra1.name(), "VYRA-KEM-1");
    assert_eq!(KemSuite::Vyra3.name(), "VYRA-KEM-3");
    assert_eq!(KemSuite::Vyra5.name(), "VYRA-KEM-5");
    assert_eq!(KemSuite::Vyra1.level().category(), 1);
    assert_eq!(KemSuite::Vyra3.level().category(), 3);
    assert_eq!(KemSuite::Vyra5.level().category(), 5);
    assert_eq!(KemSuite::Vyra3.component_names(), ("ML-KEM-768", "HQC-192"));
    for id in 0u8..=255 {
        match KemSuite::from_id(id) {
            Ok(s) => assert_eq!(s.id(), id),
            Err(e) => {
                assert!(![1u8, 3, 5].contains(&id));
                assert_eq!(e, vyra_core::Error::UnknownSuite(id));
            }
        }
    }
}
