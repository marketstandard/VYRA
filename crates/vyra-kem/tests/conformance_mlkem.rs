//! F4 (ML-KEM): component conformance for ML-KEM-512/768/1024.
//!
//! Evidence obtained here, per parameter set:
//! (a) sizes equal FIPS 203 Table 3 (and the independent `fips203` crate);
//! (b1) a known answer: the IETF LAMPS example key pair with seed
//!      `d ‖ z = 00 01 .. 3f` (lamps-wg/kyber-certificates @ 624bcaa, as
//!      shipped in `ml-kem` 0.3.4 `tests/examples/ML-KEM-*.pub`); we pin
//!      SHA3-256 of the 800/1184/1568-byte encapsulation key in that file;
//! (b2) differential interop with `fips203` 0.5.0 (integritychain), an
//!      independent pure-Rust FIPS 203 implementation: identical keys and
//!      ciphertexts from identical seeds, cross decapsulation in both
//!      directions, and identical implicit-rejection keys for tampered
//!      ciphertexts.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use common::{flip, sha3_hex};
use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};
use vyra_core::{DeterministicEntropy, EntropySource, Kem, Result};
use vyra_kem::{MlKem512, MlKem768, MlKem1024};

/// Entropy that returns `00 01 02 ..` (wrapping): the IETF example seed.
struct CountingEntropy(u8);

impl EntropySource for CountingEntropy {
    fn fill(&mut self, dest: &mut [u8]) -> Result<()> {
        for b in dest {
            *b = self.0;
            self.0 = self.0.wrapping_add(1);
        }
        Ok(())
    }
}

/// FIPS 203 Table 3: (ek, ct) sizes; dk seed is 64 bytes, K is 32 bytes.
#[test]
fn f4a_sizes_match_fips203() {
    let table: [(&dyn Kem, usize, usize); 3] = [
        (&MlKem512, 800, 768),
        (&MlKem768, 1184, 1088),
        (&MlKem1024, 1568, 1568),
    ];
    for (kem, pk, ct) in table {
        assert_eq!(kem.public_key_len(), pk, "{}", kem.name());
        assert_eq!(kem.ciphertext_len(), ct, "{}", kem.name());
        assert_eq!(kem.secret_key_len(), 64, "{}", kem.name());
        assert_eq!(kem.shared_secret_len(), 32, "{}", kem.name());
    }
    assert_eq!(fips203::ml_kem_512::EK_LEN, MlKem512::PUBLIC_KEY_LEN);
    assert_eq!(fips203::ml_kem_512::CT_LEN, MlKem512::CIPHERTEXT_LEN);
    assert_eq!(fips203::ml_kem_768::EK_LEN, MlKem768::PUBLIC_KEY_LEN);
    assert_eq!(fips203::ml_kem_768::CT_LEN, MlKem768::CIPHERTEXT_LEN);
    assert_eq!(fips203::ml_kem_1024::EK_LEN, MlKem1024::PUBLIC_KEY_LEN);
    assert_eq!(fips203::ml_kem_1024::CT_LEN, MlKem1024::CIPHERTEXT_LEN);
    assert_eq!(fips203::SSK_LEN, 32);
}

#[test]
fn f4b_ietf_example_keys() {
    // SHA3-256 of the encapsulation key in lamps-wg/kyber-certificates
    // examples ML-KEM-{512,768,1024}.pub (seed 00..3f).
    let cases: [(&dyn Kem, &str); 3] = [
        (
            &MlKem512,
            "82f101ff648063b376e2bb6c5b7455f655a50c2feadade150efa0e0e6f365aea",
        ),
        (
            &MlKem768,
            "a24e16d8f8f9383a95b77050f4d9fd2f5733eec1d63ef3c23ebf9918173669a7",
        ),
        (
            &MlKem1024,
            "61349e5c131a7e116a0463861d7d18663c5627c38c7147ddaadfd48acd7a4535",
        ),
    ];
    for (kem, expected) in cases {
        let (pk, sk) = kem.generate_keypair(&mut CountingEntropy(0)).unwrap();
        let seed: Vec<u8> = (0u8..64).collect();
        assert_eq!(sk.expose(), seed.as_slice());
        assert_eq!(sha3_hex(&pk), expected, "{}", kem.name());
    }
}

macro_rules! differential {
    ($test:ident, $ours:expr, $fips:ident) => {
        #[test]
        fn $test() {
            use fips203::$fips as f;
            let ours = $ours;
            for i in 0u8..10 {
                // Key generation from the same seed.
                let mut rng = DeterministicEntropy::from_seed(&[b'k', i]);
                let (pk, sk) = ours.generate_keypair(&mut rng).unwrap();
                let d: [u8; 32] = sk.expose()[..32].try_into().unwrap();
                let z: [u8; 32] = sk.expose()[32..].try_into().unwrap();
                let (ek_f, dk_f) = f::KG::keygen_from_seed(d, z);
                assert_eq!(ek_f.into_bytes().as_slice(), pk.as_slice(), "pk {i}");

                // Our encapsulation == theirs with the same message m.
                let mut enc_rng = DeterministicEntropy::from_seed(&[b'e', i]);
                let mut m = [0u8; 32];
                enc_rng.clone().fill(&mut m).unwrap();
                let (ct, ss) = ours.encapsulate(&pk, &mut enc_rng).unwrap();
                let ek_f = f::EncapsKey::try_from_bytes(pk.clone().try_into().unwrap()).unwrap();
                let (ss_f, ct_f) = ek_f.encaps_from_seed(&m);
                assert_eq!(
                    ct_f.clone().into_bytes().as_slice(),
                    ct.as_slice(),
                    "ct {i}"
                );
                assert_eq!(&ss_f.clone().into_bytes(), ss.expose(), "ss {i}");

                // Their decapsulation of our ciphertext.
                let ct_arr = f::CipherText::try_from_bytes(ct.clone().try_into().unwrap()).unwrap();
                let ss_their = dk_f.try_decaps(&ct_arr).unwrap();
                assert_eq!(&ss_their.into_bytes(), ss.expose(), "their decaps {i}");

                // Our decapsulation of their ciphertext (fresh message).
                let m2 = [i ^ 0x5a; 32];
                let (ss_f2, ct_f2) = ek_f.encaps_from_seed(&m2);
                let ss_ours = ours.decapsulate(sk.expose(), &ct_f2.into_bytes()).unwrap();
                assert_eq!(&ss_f2.into_bytes(), ss_ours.expose(), "our decaps {i}");

                // Identical implicit-rejection keys for a tampered ciphertext.
                let bad = flip(&ct, usize::from(i) * 37 % ct.len(), usize::from(i));
                let rej_ours = ours.decapsulate(sk.expose(), &bad).unwrap();
                let bad_arr =
                    f::CipherText::try_from_bytes(bad.clone().try_into().unwrap()).unwrap();
                let rej_their = dk_f.try_decaps(&bad_arr).unwrap().into_bytes();
                assert_eq!(&rej_their, rej_ours.expose(), "rejection {i}");
                assert_ne!(rej_ours.expose(), ss.expose(), "rejection differs {i}");
            }
        }
    };
}

differential!(f4b_differential_mlkem512, MlKem512, ml_kem_512);
differential!(f4b_differential_mlkem768, MlKem768, ml_kem_768);
differential!(f4b_differential_mlkem1024, MlKem1024, ml_kem_1024);

/// FIPS 203 §7.2 modulus check: a coefficient ≥ q in ek is rejected.
#[test]
fn encapsulation_key_check_rejects_out_of_range_coefficient() {
    let kems: [&dyn Kem; 3] = [&MlKem512, &MlKem768, &MlKem1024];
    for kem in kems {
        let mut rng = DeterministicEntropy::from_seed(b"modulus");
        let (mut pk, _) = kem.generate_keypair(&mut rng).unwrap();
        // First 12-bit coefficient := 0xFFF (4095 ≥ q = 3329).
        pk[0] = 0xFF;
        pk[1] |= 0x0F;
        let r = kem.encapsulate(&pk, &mut rng);
        assert!(
            matches!(r, Err(vyra_core::Error::InvalidEncoding(_))),
            "{}",
            kem.name()
        );
    }
}
