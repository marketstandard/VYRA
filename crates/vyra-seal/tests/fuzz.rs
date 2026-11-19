//! S10: arbitrary bytes into `SealedBox::open` never panic and never succeed.
//!
//! Three input shapes: fully arbitrary bytes (cheap, mostly rejected by the
//! header), a valid header followed by arbitrary payload long enough to reach
//! decapsulation and the AEAD (expensive, fewer cases), and a real sealed box
//! with random byte edits.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use std::sync::OnceLock;

use proptest::prelude::*;
use vyra_core::DeterministicEntropy;
use vyra_core::wire::{self, ObjectType};
use vyra_kem::{HybridPublicKey, HybridSecretKey, KemSuite};
use vyra_seal::SealedBox;

struct Fixture {
    suite: KemSuite,
    sk: HybridSecretKey,
    sealed: Vec<u8>,
}

fn fixtures() -> &'static [Fixture] {
    static F: OnceLock<Vec<Fixture>> = OnceLock::new();
    F.get_or_init(|| {
        KemSuite::all()
            .into_iter()
            .map(|suite| {
                let (pk, sk): (HybridPublicKey, HybridSecretKey) =
                    common::keypair(suite, &[b'f', suite.id()]);
                let sealed = SealedBox::new(suite)
                    .seal(
                        &pk,
                        b"fuzz",
                        b"fuzz plaintext",
                        &mut DeterministicEntropy::from_seed(&[b'F', suite.id()]),
                    )
                    .unwrap();
                Fixture { suite, sk, sealed }
            })
            .collect()
    })
}

proptest! {
    #[test]
    fn arbitrary_bytes_never_open(i in 0usize..3, bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        let f = &fixtures()[i];
        prop_assert!(SealedBox::new(f.suite).open(&f.sk, b"fuzz", &bytes).is_err());
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    #[test]
    fn valid_header_arbitrary_payload_never_opens(
        i in 0usize..3,
        extra in 0usize..64,
        fill in any::<u64>(),
    ) {
        let f = &fixtures()[i];
        let len = SealedBox::overhead(f.suite) - wire::HEADER_LEN + extra;
        let mut rng = DeterministicEntropy::from_seed(&fill.to_le_bytes());
        let mut payload = vec![0u8; len];
        vyra_core::EntropySource::fill(&mut rng, &mut payload).unwrap();
        let bytes = wire::encode(ObjectType::SealedBox, f.suite.id(), &payload);
        prop_assert!(SealedBox::new(f.suite).open(&f.sk, b"fuzz", &bytes).is_err());
    }

    #[test]
    fn edited_sealed_box_never_opens(
        i in 0usize..3,
        edits in prop::collection::vec((any::<prop::sample::Index>(), 1u8..=255), 1..4),
    ) {
        let f = &fixtures()[i];
        let mut bytes = f.sealed.clone();
        for (idx, xor) in edits {
            let at = idx.index(bytes.len());
            bytes[at] ^= xor;
        }
        // Edits may cancel out (same position, same xor twice).
        prop_assume!(bytes != f.sealed);
        prop_assert!(SealedBox::new(f.suite).open(&f.sk, b"fuzz", &bytes).is_err());
    }
}
