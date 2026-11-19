//! `CustomHybridKem` runs the same code as `HybridKem`: assembled from a named
//! suite's own components under that suite's id, it is byte-identical.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use vyra_core::{DeterministicEntropy, Kem};
use vyra_kem::{
    ComponentKem, CustomHybridKem, CustomSuite, Hqc128, Hqc192, Hqc256, HybridKem, KemSuite,
    MlKem512, MlKem768, MlKem1024,
};

fn custom_for(suite: KemSuite) -> CustomHybridKem {
    let (first, second): (Box<dyn ComponentKem>, Box<dyn ComponentKem>) = match suite {
        KemSuite::Vyra1 => (Box::new(MlKem512), Box::new(Hqc128)),
        KemSuite::Vyra3 => (Box::new(MlKem768), Box::new(Hqc192)),
        KemSuite::Vyra5 => (Box::new(MlKem1024), Box::new(Hqc256)),
    };
    CustomHybridKem::from_components(CustomSuite::new("custom", suite.id()), first, second)
}

#[test]
fn custom_assembly_reproduces_named_suites() {
    for suite in KemSuite::all() {
        let named = HybridKem::new(suite);
        let custom = custom_for(suite);
        assert_eq!(named.public_key_len(), custom.public_key_len());
        assert_eq!(named.secret_key_len(), custom.secret_key_len());
        assert_eq!(named.ciphertext_len(), custom.ciphertext_len());
        assert_eq!(named.shared_secret_len(), custom.shared_secret_len());
        assert_eq!(named.level(), custom.level());

        for i in 0..3u8 {
            let seed = [b'c', suite.id(), i];
            let mut r1 = DeterministicEntropy::from_seed(&seed);
            let mut r2 = DeterministicEntropy::from_seed(&seed);
            let (pk1, sk1) = named.generate_keypair(&mut r1).unwrap();
            let (pk2, sk2) = custom.generate_keypair(&mut r2).unwrap();
            assert_eq!(pk1, pk2);
            assert!(sk1.ct_eq(&sk2));
            let (ct1, k1) = named.encapsulate(&pk1, &mut r1).unwrap();
            let (ct2, k2) = custom.encapsulate(&pk2, &mut r2).unwrap();
            assert_eq!(ct1, ct2);
            assert!(k1.ct_eq(&k2));
            assert!(named.decapsulate(sk1.expose(), &ct1).unwrap().ct_eq(&k1));
            assert!(custom.decapsulate(sk2.expose(), &ct2).unwrap().ct_eq(&k1));
            assert_eq!(
                named.public_key_from_secret(sk1.expose()).unwrap(),
                custom.public_key_from_secret(sk2.expose()).unwrap()
            );
        }
    }
}

#[test]
fn combiner_id_is_hashed() {
    let a = custom_for(KemSuite::Vyra1);
    let b = CustomHybridKem::from_components(
        CustomSuite::new("other id", 0xF0),
        Box::new(MlKem512),
        Box::new(Hqc128),
    );
    let mut r1 = DeterministicEntropy::from_seed(b"id");
    let mut r2 = DeterministicEntropy::from_seed(b"id");
    let (pk, sk) = a.generate_keypair(&mut r1).unwrap();
    let (pk_b, _) = b.generate_keypair(&mut r2).unwrap();
    assert_eq!(pk, pk_b);
    let (ct, ka) = a.encapsulate(&pk, &mut r1).unwrap();
    let kb = b.decapsulate(sk.expose(), &ct).unwrap();
    assert!(!ka.ct_eq(&kb));
}

#[test]
fn custom_metadata_and_debug() {
    let k = custom_for(KemSuite::Vyra3);
    assert_eq!(k.name(), "custom");
    assert_eq!(k.suite().combiner_id(), 3);
    assert_eq!(k.first().name(), "ML-KEM-768");
    assert_eq!(k.second().name(), "HQC-192");
    let dbg = format!("{k:?}");
    assert!(dbg.contains("ML-KEM-768") && dbg.contains("HQC-192"));
    assert!(k.validate_public_key(&[0u8; 3]).is_err());
}
