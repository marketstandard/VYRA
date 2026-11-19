//! S3: ciphertext tampering. For each suite, one bit is flipped at 32
//! positions spread over ct1 (ML-KEM) and 32 spread over ct2 (HQC); every
//! tampered ciphertext must decapsulate to `Ok` with a different key, and the
//! affected component alone must implicitly reject (its own secret changes).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use common::{flip, spread};
use vyra_core::{DeterministicEntropy, Kem};
use vyra_kem::{Hqc128, Hqc192, Hqc256, HybridKem, KemSuite, MlKem512, MlKem768, MlKem1024};

const POSITIONS_PER_COMPONENT: usize = 32;

fn components(suite: KemSuite) -> (Box<dyn Kem>, Box<dyn Kem>) {
    match suite {
        KemSuite::Vyra1 => (Box::new(MlKem512), Box::new(Hqc128)),
        KemSuite::Vyra3 => (Box::new(MlKem768), Box::new(Hqc192)),
        KemSuite::Vyra5 => (Box::new(MlKem1024), Box::new(Hqc256)),
    }
}

fn tamper(suite: KemSuite) {
    let kem = HybridKem::new(suite);
    let (c1, c2) = components(suite);
    let mut rng = DeterministicEntropy::from_seed(&[b't', suite.id()]);

    let (pk, sk) = kem.generate_keypair(&mut rng).unwrap();
    let (ct, key) = kem.encapsulate(&pk, &mut rng).unwrap();

    // Component views of the same key pair and ciphertext.
    let sk_raw = sk.expose();
    let sk1 = &sk_raw[..c1.secret_key_len()];
    let sk2 = &sk_raw[c1.secret_key_len()..c1.secret_key_len() + c2.secret_key_len()];
    let (ct1, ct2) = ct.split_at(c1.ciphertext_len());
    let ss1 = c1.decapsulate(sk1, ct1).unwrap();
    let ss2 = c2.decapsulate(sk2, ct2).unwrap();

    let regions = [
        (0usize, ct1.len(), &c1, sk1, &ss1),
        (ct1.len(), ct2.len(), &c2, sk2, &ss2),
    ];
    for (offset, len, comp, comp_sk, comp_ss) in regions {
        for (n, pos) in spread(len, POSITIONS_PER_COMPONENT).into_iter().enumerate() {
            let bit = n % 8;
            let bad = flip(&ct, offset + pos, bit);
            let got = kem
                .decapsulate(sk.expose(), &bad)
                .expect("tampered ciphertext must not error");
            assert_eq!(got.len(), 32);
            assert!(
                !got.ct_eq(&key),
                "{suite}: flip at {} bit {bit} kept the key",
                offset + pos
            );

            let bad_component = &bad[offset..offset + len];
            let rej = comp.decapsulate(comp_sk, bad_component).unwrap();
            assert!(
                !rej.ct_eq(comp_ss),
                "{suite}: {} accepted a flip at {pos}",
                comp.name()
            );
        }
    }
}

#[test]
fn s3_tamper_vyra1() {
    tamper(KemSuite::Vyra1);
}

#[test]
fn s3_tamper_vyra3() {
    tamper(KemSuite::Vyra3);
}

#[test]
fn s3_tamper_vyra5() {
    tamper(KemSuite::Vyra5);
}

#[test]
fn spread_covers_ends() {
    let p = spread(1000, 32);
    assert_eq!(p.len(), 32);
    assert_eq!(p.first(), Some(&0));
    assert_eq!(p.last(), Some(&999));
}
