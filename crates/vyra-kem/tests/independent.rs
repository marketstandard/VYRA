//! T-1: recompute the hybrid output independently of `HybridKem`: run the
//! two component adapters on the halves of pk/sk/ct, then derive the key both
//! with `combine` and by hand-framing into SHA3-256. Catches swapped or
//! misordered combiner arguments in `HybridKem`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use sha3::{Digest, Sha3_256};
use vyra_core::{DeterministicEntropy, Kem};
use vyra_kem::{
    Hqc128, Hqc192, Hqc256, HybridKem, KemSuite, MlKem512, MlKem768, MlKem1024, combine,
};

fn components(suite: KemSuite) -> (Box<dyn Kem>, Box<dyn Kem>) {
    match suite {
        KemSuite::Vyra1 => (Box::new(MlKem512), Box::new(Hqc128)),
        KemSuite::Vyra3 => (Box::new(MlKem768), Box::new(Hqc192)),
        KemSuite::Vyra5 => (Box::new(MlKem1024), Box::new(Hqc256)),
    }
}

fn hand_framed(suite: u8, fields: [&[u8]; 6]) -> Vec<u8> {
    let mut h = Sha3_256::new();
    let mut frame = |b: &[u8]| {
        h.update((b.len() as u64).to_be_bytes());
        h.update(b);
    };
    frame(b"VYRA-KEM-v1");
    frame(&[suite]);
    for f in fields {
        frame(f);
    }
    h.finalize().to_vec()
}

#[test]
fn t1_hybrid_output_recomputed_from_components() {
    for suite in KemSuite::all() {
        let kem = HybridKem::new(suite);
        let (c1, c2) = components(suite);
        let seed = [b'i', suite.id()];

        let mut rng = DeterministicEntropy::from_seed(&seed);
        let (pk, sk) = kem.generate_keypair(&mut rng).unwrap();
        let mut enc_rng = DeterministicEntropy::from_seed(b"encapsulate");
        let (ct, key) = kem.encapsulate(&pk, &mut enc_rng.clone()).unwrap();

        // Component halves.
        let (pk1, pk2) = pk.split_at(c1.public_key_len());
        let (sk1, sk2) = sk.expose().split_at(c1.secret_key_len());
        let (ct1, ct2) = ct.split_at(c1.ciphertext_len());

        // Key generation consumed component 1 then component 2 entropy.
        let mut rng = DeterministicEntropy::from_seed(&seed);
        let (p1, s1) = c1.generate_keypair(&mut rng).unwrap();
        let (p2, s2) = c2.generate_keypair(&mut rng).unwrap();
        assert_eq!((p1.as_slice(), s1.expose()), (pk1, sk1), "{suite} keygen 1");
        assert_eq!((p2.as_slice(), s2.expose()), (pk2, sk2), "{suite} keygen 2");

        // Encapsulation: component 1 then component 2 from the same stream.
        let (e1, ss1) = c1.encapsulate(pk1, &mut enc_rng).unwrap();
        let (e2, ss2) = c2.encapsulate(pk2, &mut enc_rng).unwrap();
        assert_eq!(
            (e1.as_slice(), e2.as_slice()),
            (ct1, ct2),
            "{suite} encaps ct"
        );

        let via_combine = combine(suite.id(), ss1.expose(), ss2.expose(), ct1, ct2, pk1, pk2);
        let by_hand = hand_framed(suite.id(), [ss1.expose(), ss2.expose(), ct1, ct2, pk1, pk2]);
        assert_eq!(via_combine.expose(), by_hand.as_slice(), "{suite}");
        assert_eq!(key.expose(), by_hand.as_slice(), "{suite} encapsulate");

        // Decapsulation, component by component.
        let d1 = c1.decapsulate(sk1, ct1).unwrap();
        let d2 = c2.decapsulate(sk2, ct2).unwrap();
        let by_hand = hand_framed(suite.id(), [d1.expose(), d2.expose(), ct1, ct2, pk1, pk2]);
        let got = kem.decapsulate(sk.expose(), &ct).unwrap();
        assert_eq!(got.expose(), by_hand.as_slice(), "{suite} decapsulate");

        // Also on a tampered ciphertext (implicit-rejection keys).
        let mut bad = ct.clone();
        bad[0] ^= 1;
        let last = bad.len() - 1;
        bad[last] ^= 1;
        let (b1, b2) = bad.split_at(c1.ciphertext_len());
        let r1 = c1.decapsulate(sk1, b1).unwrap();
        let r2 = c2.decapsulate(sk2, b2).unwrap();
        let by_hand = hand_framed(suite.id(), [r1.expose(), r2.expose(), b1, b2, pk1, pk2]);
        let got = kem.decapsulate(sk.expose(), &bad).unwrap();
        assert_eq!(got.expose(), by_hand.as_slice(), "{suite} rejection");
    }
}
