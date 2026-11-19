//! Behavioural tests of the HQC v5.1 KEM beyond the official KATs: sizes,
//! round trips (decryption-failure sanity), and implicit rejection checked
//! against the specification's formula recomputed independently.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    missing_docs
)]

use sha3::{Digest, Sha3_256};
use shake::{ExtendableOutput, Shake256, Update, XofReader};
use vyra_core::{OsEntropy, RandCoreRng};
use vyra_hqc::{Ciphertext, DecapsulationKey, HqcKem, HqcParams};

/// HQC v5.1 specification Table 9 (and Table 8 for k):
/// (|ek|, |dk|, |c|, |K|, k in bytes).
const TABLE_9: [(&str, usize, usize, usize, usize, usize); 3] = [
    ("HQC-1", 2241, 32, 4433, 32, 16),
    ("HQC-3", 4514, 32, 8978, 32, 24),
    ("HQC-5", 7237, 32, 14421, 32, 32),
];

fn sizes<P: HqcParams>(row: (&str, usize, usize, usize, usize, usize)) {
    let (name, ek, dk, ct, ss, k) = row;
    assert_eq!(P::PK_BYTES, ek, "{name}");
    assert_eq!(P::SK_BYTES, dk, "{name}");
    assert_eq!(P::CT_BYTES, ct, "{name}");
    assert_eq!(P::SS_BYTES, ss, "{name}");
    let (e, d) = HqcKem::<P>::generate_key_deterministic(&[9u8; 32]);
    let (c, s) = e
        .encapsulate_deterministic(&vec![1u8; k], &[2u8; 16])
        .unwrap();
    assert_eq!(
        (
            e.as_ref().len(),
            d.as_ref().len(),
            c.as_ref().len(),
            s.as_ref().len()
        ),
        (ek, dk, ct, ss),
        "{name}"
    );
    // A message of any other length is rejected.
    assert!(
        e.encapsulate_deterministic(&vec![1u8; k + 1], &[2u8; 16])
            .is_err()
    );
}

#[test]
fn sizes_equal_spec_table_9() {
    sizes::<vyra_hqc::Hqc128Params>(TABLE_9[0]);
    sizes::<vyra_hqc::Hqc192Params>(TABLE_9[1]);
    sizes::<vyra_hqc::Hqc256Params>(TABLE_9[2]);
    assert_eq!(
        (
            vyra_hqc::hqc128::PUBLIC_KEY_SIZE,
            vyra_hqc::hqc128::SECRET_KEY_SIZE,
            vyra_hqc::hqc128::CIPHERTEXT_SIZE
        ),
        (2241, 32, 4433)
    );
    assert_eq!(
        (
            vyra_hqc::hqc192::PUBLIC_KEY_SIZE,
            vyra_hqc::hqc192::SECRET_KEY_SIZE,
            vyra_hqc::hqc192::CIPHERTEXT_SIZE
        ),
        (4514, 32, 8978)
    );
    assert_eq!(
        (
            vyra_hqc::hqc256::PUBLIC_KEY_SIZE,
            vyra_hqc::hqc256::SECRET_KEY_SIZE,
            vyra_hqc::hqc256::CIPHERTEXT_SIZE
        ),
        (7237, 32, 14421)
    );
}

/// Random key pairs and encapsulations from the OS RNG must round-trip.
/// 2000 per parameter set in an optimised build (`cargo test --release`),
/// 100 in a debug build. A failure would be a decryption failure (DFR claim
/// < 2^-127 for HQC-1) or a bug; this is a sanity check, not a DFR measurement.
fn round_trips<P: HqcParams>() -> usize {
    let n = if cfg!(debug_assertions) { 100 } else { 2000 };
    let mut os = OsEntropy::new();
    let mut rng = RandCoreRng::new(&mut os);
    let mut done = 0;
    while done < n {
        // A fresh key pair every 10 encapsulations.
        let (ek, dk) = HqcKem::<P>::generate_key(&mut rng);
        for _ in 0..10 {
            let (ct, ss) = ek.encapsulate(&mut rng);
            let ss2 = dk.decapsulate(&ct);
            assert!(ss == ss2, "{} round trip {done}", P::NAME);
            done += 1;
        }
    }
    rng.finish().unwrap();
    n
}

#[test]
fn round_trips_hqc1() {
    let n = round_trips::<vyra_hqc::Hqc128Params>();
    println!("HQC-1: {n} random encapsulations round-tripped");
}

#[test]
fn round_trips_hqc3() {
    let n = round_trips::<vyra_hqc::Hqc192Params>();
    println!("HQC-3: {n} random encapsulations round-tripped");
}

#[test]
fn round_trips_hqc5() {
    let n = round_trips::<vyra_hqc::Hqc256Params>();
    println!("HQC-5: {n} random encapsulations round-tripped");
}

/// `K_bar = J(H(ek) || sigma || c)` (specification `HQC-KEM.Decaps` step 12),
/// recomputed here from Table 3 without the crate's internals:
/// `sigma` = bytes 32..32+k of SHAKE256(dk || k), H = SHA3-256(. || 0x01),
/// J = SHA3-256(. || 0x03).
fn rejection_key(dk: &[u8], ek: &[u8], ct: &[u8], k: usize) -> [u8; 32] {
    let mut xof = Shake256::default();
    xof.update(dk);
    xof.update(&[k as u8]);
    let mut stream = vec![0u8; 32 + k];
    xof.finalize_xof().read(&mut stream);
    let sigma = &stream[32..];

    let h = Sha3_256::new()
        .chain_update(ek)
        .chain_update([0x01])
        .finalize();
    Sha3_256::new()
        .chain_update(h)
        .chain_update(sigma)
        .chain_update(ct)
        .chain_update([0x03])
        .finalize()
        .into()
}

fn implicit_rejection<P: HqcParams>(k: usize) {
    let (ek, dk) = HqcKem::<P>::generate_key_deterministic(&[0x33u8; 32]);
    let (ct, ss_honest) = ek
        .encapsulate_deterministic(&vec![0x44u8; k], &[0x55u8; 16])
        .unwrap();

    // The honest ciphertext does not yield the rejection key.
    assert_ne!(
        ss_honest.as_ref(),
        rejection_key(dk.as_ref(), ek.as_ref(), ct.as_ref(), k).as_slice()
    );

    // Tamper in u, in v and in the salt.
    for tamper_at in [0usize, P::CT_BYTES / 2, P::CT_BYTES - 1] {
        let mut bad = ct.as_ref().to_vec();
        bad[tamper_at] ^= 0x01;
        let bad_ct = Ciphertext::<P>::try_from(bad.as_slice()).unwrap();
        let ss_rej = dk.decapsulate(&bad_ct);
        assert_ne!(
            ss_rej.as_ref(),
            ss_honest.as_ref(),
            "{} at {tamper_at}",
            P::NAME
        );
        // Deterministic and equal to the specification's rejection key.
        assert_eq!(ss_rej.as_ref(), dk.decapsulate(&bad_ct).as_ref());
        assert_eq!(
            ss_rej.as_ref(),
            rejection_key(dk.as_ref(), ek.as_ref(), &bad, k).as_slice(),
            "{} rejection key at {tamper_at}",
            P::NAME
        );
    }

    // A different decapsulation key yields a different secret for the
    // honest ciphertext.
    let mut other = dk.as_ref().to_vec();
    other[0] ^= 0x01;
    let other = DecapsulationKey::<P>::try_from(other.as_slice()).unwrap();
    assert_ne!(other.decapsulate(&ct).as_ref(), ss_honest.as_ref());
}

#[test]
fn implicit_rejection_matches_spec_formula() {
    implicit_rejection::<vyra_hqc::Hqc128Params>(16);
    implicit_rejection::<vyra_hqc::Hqc192Params>(24);
    implicit_rejection::<vyra_hqc::Hqc256Params>(32);
}

/// The decapsulation key is the 32-byte seed: parsing it re-derives the same
/// encapsulation key, and the randomized key generation draws exactly that
/// seed.
fn seed_form<P: HqcParams>() {
    let (ek, dk) = HqcKem::<P>::generate_key_deterministic(&[0xA5u8; 32]);
    assert_eq!(dk.as_ref(), &[0xA5u8; 32]);
    let parsed = DecapsulationKey::<P>::try_from(dk.as_ref()).unwrap();
    assert_eq!(parsed.encapsulation_key(), &ek);
    assert_eq!(dk.encapsulation_key(), &ek);
}

#[test]
fn decapsulation_key_is_the_seed() {
    seed_form::<vyra_hqc::Hqc128Params>();
    seed_form::<vyra_hqc::Hqc192Params>();
    seed_form::<vyra_hqc::Hqc256Params>();
}

/// `HqcKem::decapsulate_from_seed` (key generation once) equals the two-step
/// path (parse the seed into a `DecapsulationKey`, decapsulate; derive the
/// encapsulation key separately) on 200 random cases per set, every second
/// one with a tampered ciphertext.
fn single_pass_equals_two_step<P: HqcParams>() {
    let mut os = OsEntropy::new();
    let mut rng = RandCoreRng::new(&mut os);
    for i in 0..200 {
        let (ek, dk) = HqcKem::<P>::generate_key(&mut rng);
        let (ct, ss) = ek.encapsulate(&mut rng);
        let mut bytes = ct.as_ref().to_vec();
        if i % 2 == 1 {
            let at = (i * 7919) % bytes.len();
            bytes[at] ^= 1 << (i % 8);
        }
        let ct = Ciphertext::<P>::try_from(bytes.as_slice()).unwrap();
        let seed: [u8; 32] = dk.as_ref().try_into().unwrap();

        let (ss1, ek1) = HqcKem::<P>::decapsulate_from_seed(&seed, &ct);
        let two_step_dk = DecapsulationKey::<P>::try_from(seed.as_slice()).unwrap();
        let ss2 = two_step_dk.decapsulate(&ct);
        let ek2 = HqcKem::<P>::generate_key_deterministic(&seed).0;
        assert_eq!(ss1.as_ref(), ss2.as_ref(), "{} case {i}", P::NAME);
        assert_eq!(ek1, ek2, "{} case {i}", P::NAME);
        assert_eq!(ek1, ek, "{} case {i}", P::NAME);
        assert_eq!(ss1 == ss, i % 2 == 0, "{} case {i}", P::NAME);
    }
    rng.finish().unwrap();
}

#[test]
fn decapsulate_from_seed_equals_two_step_hqc1() {
    single_pass_equals_two_step::<vyra_hqc::Hqc128Params>();
}

#[test]
fn decapsulate_from_seed_equals_two_step_hqc3() {
    single_pass_equals_two_step::<vyra_hqc::Hqc192Params>();
}

#[test]
fn decapsulate_from_seed_equals_two_step_hqc5() {
    single_pass_equals_two_step::<vyra_hqc::Hqc256Params>();
}
