//! S10 parser robustness: arbitrary bytes into every decoder and every raw
//! `verify` never panic and never verify.
//!
//! U12 extended the domains to the SLH-DSA adapters and the dual-PQ suites
//! (13 schemes, 6 suites) and raised the case count from 64 to 128 so each
//! scheme keeps roughly the same number of cases. Raw `sign` with a
//! right-length key is slow for SLH-DSA, but random lengths in 0..100 rarely
//! hit it.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use proptest::prelude::*;
use vyra_core::wire::{self, ObjectType};
use vyra_core::{Error, SignatureScheme};
use vyra_sig::{
    CompositePublicKey, CompositeSecretKey, CompositeSig, CompositeSignature, Ed25519, MlDsa44,
    MlDsa65, MlDsa87, SigSuite, SlhDsaShake128s, SlhDsaShake192s, SlhDsaShake256s,
};

const SCHEMES: usize = 13;

fn scheme(i: usize) -> Box<dyn SignatureScheme> {
    match i % SCHEMES {
        0 => Box::new(MlDsa44),
        1 => Box::new(MlDsa65),
        2 => Box::new(MlDsa87),
        3 => Box::new(Ed25519),
        4 => Box::new(CompositeSignature::new(SigSuite::Vyra2)),
        5 => Box::new(CompositeSignature::new(SigSuite::Vyra3)),
        6 => Box::new(CompositeSignature::new(SigSuite::Vyra5)),
        7 => Box::new(SlhDsaShake128s),
        8 => Box::new(SlhDsaShake192s),
        9 => Box::new(SlhDsaShake256s),
        10 => Box::new(CompositeSignature::new(SigSuite::Pq1)),
        11 => Box::new(CompositeSignature::new(SigSuite::Pq3)),
        _ => Box::new(CompositeSignature::new(SigSuite::Pq5)),
    }
}

fn suite(i: usize) -> SigSuite {
    SigSuite::all()[i % 6]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn decoders_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..5000)) {
        let _ = CompositePublicKey::from_bytes(&bytes);
        let _ = CompositeSecretKey::from_bytes(&bytes);
        let _ = CompositeSig::from_bytes(&bytes);
    }

    /// A valid header in front of random payloads of random length.
    #[test]
    fn decoders_with_valid_header_never_panic(
        s in 0usize..6,
        ty in 4u8..=6,
        payload in proptest::collection::vec(any::<u8>(), 0..40000),
    ) {
        let enc = wire::encode(ObjectType::from_u8(ty).unwrap(), suite(s).id(), &payload);
        let _ = CompositePublicKey::from_bytes(&enc);
        let _ = CompositeSecretKey::from_bytes(&enc);
        let _ = CompositeSig::from_bytes(&enc);
    }

    /// Random raw inputs of arbitrary length into every scheme's raw verify.
    #[test]
    fn raw_verify_arbitrary_lengths_never_verifies(
        i in 0usize..SCHEMES,
        pk in proptest::collection::vec(any::<u8>(), 0..3000),
        msg in proptest::collection::vec(any::<u8>(), 0..64),
        sig in proptest::collection::vec(any::<u8>(), 0..40000),
    ) {
        prop_assert!(scheme(i).verify(&pk, &msg, &sig).is_err());
    }

    /// Random raw inputs of exactly the right lengths: parsing succeeds, so
    /// this exercises the verification code itself.
    #[test]
    fn raw_verify_right_lengths_never_verifies(
        i in 0usize..SCHEMES,
        seed in any::<u64>(),
        msg in proptest::collection::vec(any::<u8>(), 0..64),
    ) {
        let s = scheme(i);
        let mut src = vyra_core::DeterministicEntropy::from_seed(&seed.to_le_bytes());
        let mut pk = vec![0u8; s.public_key_len()];
        let mut sig = vec![0u8; s.signature_len()];
        vyra_core::EntropySource::fill(&mut src, &mut pk).unwrap();
        vyra_core::EntropySource::fill(&mut src, &mut sig).unwrap();
        let res = s.verify(&pk, &msg, &sig);
        prop_assert!(res.is_err());
        let length_error = matches!(res, Err(Error::InvalidLength { .. }));
        prop_assert!(!length_error);
    }

    /// Typed objects decoded from random well-formed encodings never verify.
    #[test]
    fn decoded_random_objects_never_verify(
        s in 0usize..6,
        seed in any::<u64>(),
        msg in proptest::collection::vec(any::<u8>(), 0..64),
        ctx in proptest::collection::vec(any::<u8>(), 0..300),
    ) {
        let suite = suite(s);
        let mut src = vyra_core::DeterministicEntropy::from_seed(&seed.to_le_bytes());
        let mut pk = vec![0u8; suite.public_key_len()];
        let mut sig = vec![0u8; suite.signature_len()];
        vyra_core::EntropySource::fill(&mut src, &mut pk).unwrap();
        vyra_core::EntropySource::fill(&mut src, &mut sig).unwrap();
        // Since U3-R2 a random Ed25519 part is usually rejected at parse
        // (not a canonical, non-small-order point): that path must be a
        // clean InvalidEncoding. To keep exercising verification of a parsed
        // key, the Ed25519 part is then replaced by an honest key.
        let random_parse = CompositePublicKey::from_bytes(
            &wire::encode(ObjectType::SigPublicKey, suite.id(), &pk));
        if suite.is_dual_pq() {
            // Dual-PQ: every byte string of the right length is a valid key.
            prop_assert!(random_parse.is_ok());
        } else {
            if let Err(e) = random_parse {
                prop_assert!(matches!(e, Error::InvalidEncoding(_)));
            }
            let (ed_pk, _) = Ed25519.generate_keypair(&mut src).unwrap();
            let split = suite.mldsa_public_key_len();
            pk[split..].copy_from_slice(&ed_pk);
        }
        let pk = CompositePublicKey::from_bytes(
            &wire::encode(ObjectType::SigPublicKey, suite.id(), &pk)).unwrap();
        let sig = CompositeSig::from_bytes(
            &wire::encode(ObjectType::Signature, suite.id(), &sig)).unwrap();
        prop_assert!(CompositeSignature::new(suite).verify(&pk, &msg, &ctx, &sig).is_err());
    }

    /// Raw sign with arbitrary secret-key bytes never panics; right-length
    /// keys always sign (every 32-byte string is a valid seed).
    #[test]
    fn raw_sign_arbitrary_keys_never_panic(
        i in 0usize..SCHEMES,
        sk in proptest::collection::vec(any::<u8>(), 0..100),
    ) {
        let s = scheme(i);
        let mut rng = vyra_core::DeterministicEntropy::from_seed(b"sign");
        let res = s.sign(&sk, b"m", &mut rng);
        prop_assert_eq!(res.is_ok(), sk.len() == s.secret_key_len());
    }
}
