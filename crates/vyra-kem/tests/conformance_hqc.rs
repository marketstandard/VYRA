//! F4 (HQC): component conformance for HQC-128/192/256 through VYRA's adapter.
//!
//! Implemented version: the HQC v5.1 specification (version 5.1, 2026-11-09)
//! and the reference implementation at tag `v5.1.0` (commit
//! 06567ccbad10580d78dd7863b15d23f41076d57f, gitlab.com/pqc-hqc/hqc), via the
//! in-tree port `vyra-hqc`. HQC-128/192/256 are the specification's
//! HQC-1/3/5. FIPS 207 is unpublished; nothing here tests conformance to it.
//!
//! Evidence obtained here, per parameter set:
//! (a) sizes equal the v5.1 specification Table 9 and `vyra-hqc`'s constants;
//! (b) official known answers: all 100 counts of the reference
//!     `kats/ref/hqc-{1,3,5}/PQCkemKAT_32.rsp` at tag v5.1.0, driven through
//!     the `Kem` adapter with the reference KAT generator's NIST AES-256 CTR
//!     DRBG (one DRBG request per `randombytes` call: keygen 32 bytes, encaps
//!     k then 16 bytes, exactly the adapter's draws). The embedded data
//!     (seed, exact sk and ss, SHA3-256 of pk and ct; full pk/ct of counts 0-4)
//!     and its provenance are in `crates/vyra-hqc/tests/data/PROVENANCE.md`.
//!     VYRA's secret key equals the KAT `sk` byte for byte: in v5.1 the
//!     decapsulation key is `seed_KEM`.
//!
//! No differential test: the previous second implementation,
//! `oqs-native-hqc` 0.16.0, implements the pre-v5.1 reference snapshot and
//! must now disagree (RULES 5). No independent second implementation of HQC
//! v5.1 was found (crates.io and the hqc-kem upstream, 2026-11-18), so the
//! conformance evidence for HQC is the official known answers only.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use common::{KatDigest, NistKatDrbg, hex, kat_digests, sha3_hex, to_hex};
use vyra_core::{DeterministicEntropy, Kem};
use vyra_kem::{ComponentKem, Hqc128, Hqc192, Hqc256};

#[test]
fn f4a_sizes_match_hqc_v5_1() {
    // Specification Table 9: |ek|, |dk| (VYRA: the seed), |c|, |K|.
    let table: [(&dyn Kem, usize, usize, usize); 3] = [
        (&Hqc128, 2241, 4433, vyra_hqc::hqc128::SECRET_KEY_SIZE),
        (&Hqc192, 4514, 8978, vyra_hqc::hqc192::SECRET_KEY_SIZE),
        (&Hqc256, 7237, 14421, vyra_hqc::hqc256::SECRET_KEY_SIZE),
    ];
    for (kem, pk, ct, upstream_sk) in table {
        assert_eq!(kem.public_key_len(), pk, "{}", kem.name());
        // VYRA stores the 32-byte seed, which is the v5.1 dk_KEM.
        assert_eq!(kem.secret_key_len(), 32, "{}", kem.name());
        assert_eq!(upstream_sk, 32, "{}", kem.name());
        assert_eq!(kem.ciphertext_len(), ct, "{}", kem.name());
        assert_eq!(kem.shared_secret_len(), 32, "{}", kem.name());
    }
    assert_eq!(vyra_hqc::hqc128::PUBLIC_KEY_SIZE, 2241);
    assert_eq!(vyra_hqc::hqc128::CIPHERTEXT_SIZE, 4433);
    assert_eq!(vyra_hqc::hqc192::PUBLIC_KEY_SIZE, 4514);
    assert_eq!(vyra_hqc::hqc192::CIPHERTEXT_SIZE, 8978);
    assert_eq!(vyra_hqc::hqc256::PUBLIC_KEY_SIZE, 7237);
    assert_eq!(vyra_hqc::hqc256::CIPHERTEXT_SIZE, 14421);
}

fn check_kats(kem: &dyn ComponentKem, kats: &[KatDigest]) {
    assert_eq!(kats.len(), 100, "{}", kem.name());
    for kat in kats {
        let n = kat.count;
        let mut rng = NistKatDrbg::new(&kat.seed);
        let (pk, sk) = kem.generate_keypair(&mut rng).unwrap();
        let (ct, ss) = kem.encapsulate(&pk, &mut rng).unwrap();
        assert_eq!(sha3_hex(&pk), kat.pk_sha3, "{} pk count {n}", kem.name());
        // Our secret key is the KAT sk (v5.1 dk_KEM = seed_KEM).
        assert_eq!(to_hex(sk.expose()), kat.sk, "{} sk count {n}", kem.name());
        assert_eq!(sha3_hex(&ct), kat.ct_sha3, "{} ct count {n}", kem.name());
        assert_eq!(to_hex(ss.expose()), kat.ss, "{} ss count {n}", kem.name());
        let ss2 = kem.decapsulate(sk.expose(), &ct).unwrap();
        assert!(ss.ct_eq(&ss2), "{} decaps count {n}", kem.name());
        let (ss3, pk3) = kem.decapsulate_with_public_key(sk.expose(), &ct).unwrap();
        assert!(ss.ct_eq(&ss3), "{} decaps+pk count {n}", kem.name());
        assert_eq!(pk3, pk, "{} decaps+pk count {n}", kem.name());
    }
}

#[test]
fn f4b_official_kat_hqc128() {
    check_kats(&Hqc128, &kat_digests(common::KAT_HQC1));
}

#[test]
fn f4b_official_kat_hqc192() {
    check_kats(&Hqc192, &kat_digests(common::KAT_HQC3));
}

#[test]
fn f4b_official_kat_hqc256() {
    check_kats(&Hqc256, &kat_digests(common::KAT_HQC5));
}

/// Records which HQC version is implemented: the specification version and
/// reference tag, and the public-key bytes 32..48 (the start of `s`) of KAT
/// count 0 of the official v5.1.0 files.
///
/// For comparison, the previous implementation (`hqc-kem` 0.1.0-rc.0, the
/// pre-v5.1 reference snapshot) produced 03893358eefa2bdd767bd02d208d8885 for
/// HQC-128 from the SHAKE256-based KAT stream of seed `SEED0` below; v5.1 must
/// not reproduce it.
///
/// A change of the implemented version must fail this test and be reviewed.
#[test]
fn hqc_version_pin() {
    assert_eq!(
        vyra_hqc::HQC_VERSION,
        "HQC v5.1 (specification 2026-11-09); reference tag v5.1.0, commit 06567ccbad10580d78dd7863b15d23f41076d57f"
    );
    let pins: [(&dyn Kem, &str, &str); 3] = [
        (
            &Hqc128,
            common::KAT_HQC1,
            "1728b63ddb5deb9236800f80236acc14",
        ),
        (
            &Hqc192,
            common::KAT_HQC3,
            "6dad430246caec95a729af315ac6bb7c",
        ),
        (
            &Hqc256,
            common::KAT_HQC5,
            "358afa3b903e1b1c3293d6171ee3ddc6",
        ),
    ];
    for (kem, data, pin) in pins {
        let kat = &kat_digests(data)[0];
        let (pk, _) = kem
            .generate_keypair(&mut NistKatDrbg::new(&kat.seed))
            .unwrap();
        assert_eq!(to_hex(&pk[32..48]), pin, "{}", kem.name());
    }

    // The old snapshot's output for its own KAT input is not reproduced.
    const SEED0: &str = "9ef877fddbe8891c6e4e79eaf022e563defaca6b152161b9a423e8fe96a403e774b2d352cf74c934069c9de74757f505";
    let mut old_stream = common::ShakeKatStream::new(&hex(SEED0).unwrap());
    let (pk, _) = Hqc128.generate_keypair(&mut old_stream).unwrap();
    assert_ne!(to_hex(&pk[32..48]), "03893358eefa2bdd767bd02d208d8885");
}

/// Implicit rejection through the adapter is deterministic and differs from
/// the honest key; the formula itself is checked independently in
/// `vyra-hqc/tests/kem.rs`.
#[test]
fn f4c_implicit_rejection_through_adapter() {
    let comps: [&dyn Kem; 3] = [&Hqc128, &Hqc192, &Hqc256];
    for kem in comps {
        let mut rng = DeterministicEntropy::from_seed(kem.name().as_bytes());
        let (pk, sk) = kem.generate_keypair(&mut rng).unwrap();
        let (ct, ss) = kem.encapsulate(&pk, &mut rng).unwrap();
        for at in [0, ct.len() / 2, ct.len() - 1] {
            let bad = common::flip(&ct, at, 3);
            let r1 = kem.decapsulate(sk.expose(), &bad).unwrap();
            let r2 = kem.decapsulate(sk.expose(), &bad).unwrap();
            assert!(r1.ct_eq(&r2), "{} at {at}", kem.name());
            assert!(!r1.ct_eq(&ss), "{} at {at}", kem.name());
        }
    }
}

/// The adapter's single-pass `decapsulate_with_public_key` equals the
/// two-step path (`decapsulate`, then `public_key_from_secret`) on 200 random
/// cases per set, every second one with a tampered ciphertext.
#[test]
fn f4d_decapsulate_with_public_key_equals_two_step() {
    let comps: [&dyn ComponentKem; 3] = [&Hqc128, &Hqc192, &Hqc256];
    for kem in comps {
        let mut rng = vyra_core::OsEntropy::new();
        for i in 0..200usize {
            let (pk, sk) = kem.generate_keypair(&mut rng).unwrap();
            let (ct, ss) = kem.encapsulate(&pk, &mut rng).unwrap();
            let ct = if i % 2 == 1 {
                common::flip(&ct, (i * 7919) % ct.len(), i)
            } else {
                ct
            };
            let (ss1, pk1) = kem.decapsulate_with_public_key(sk.expose(), &ct).unwrap();
            let ss2 = kem.decapsulate(sk.expose(), &ct).unwrap();
            let pk2 = kem.public_key_from_secret(sk.expose()).unwrap();
            assert!(ss1.ct_eq(&ss2), "{} case {i}", kem.name());
            assert_eq!(pk1, pk2, "{} case {i}", kem.name());
            assert_eq!(pk1, pk, "{} case {i}", kem.name());
            assert_eq!(ss1.ct_eq(&ss), i % 2 == 0, "{} case {i}", kem.name());
        }
    }
}
