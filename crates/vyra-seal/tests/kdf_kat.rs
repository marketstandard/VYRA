//! Format pin: recompute the DEM key and nonce independently of `vyra-seal`
//! (hand-framed bytes into SHAKE256, the KEM via `vyra-kem`, the AEAD via the
//! upstream `chacha20poly1305` crate) and decrypt a sealed box with them.
//!
//! The framing follows vyra-core's `Transcript::finalize_xof`:
//! `SHAKE256(0x01 ‖ frame(label) ‖ frame(f1) ‖ …)`, `frame(x) = u64_be(len(x)) ‖ x`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use common::{keypair, pattern};
use shake::{ExtendableOutput, Shake256, Update, XofReader};
use vyra_core::DeterministicEntropy;
use vyra_kem::{HybridCiphertext, HybridKem, KemSuite};
use vyra_seal::SealedBox;

fn frame(xof: &mut Shake256, field: &[u8]) {
    xof.update(&(field.len() as u64).to_be_bytes());
    xof.update(field);
}

/// SHAKE256(0x01 ‖ frame("VYRA-SEAL-v1") ‖ frame([suite]) ‖ frame(K) ‖ frame(ct))[..44]
fn derive_by_hand(suite_id: u8, k: &[u8], kem_ct: &[u8]) -> [u8; 44] {
    let mut xof = Shake256::default();
    xof.update(&[0x01]);
    frame(&mut xof, b"VYRA-SEAL-v1");
    frame(&mut xof, &[suite_id]);
    frame(&mut xof, k);
    frame(&mut xof, kem_ct);
    let mut out = [0u8; 44];
    xof.finalize_xof().read(&mut out);
    out
}

fn kat(suite: KemSuite) {
    let (pk, sk) = keypair(suite, &[b'k', suite.id()]);
    let sbox = SealedBox::new(suite);
    let pt = pattern(300, 7);
    let aad = b"known-answer aad";
    let seed = [b'K', suite.id()];
    let sealed = sbox
        .seal(&pk, aad, &pt, &mut DeterministicEntropy::from_seed(&seed))
        .unwrap();

    // Parse by hand.
    let ct_len = suite.ciphertext_len();
    let header = &sealed[..7];
    let kem_ct = &sealed[7..7 + ct_len];
    let body = &sealed[7 + ct_len..];
    assert_eq!(header, [b'V', b'Y', b'R', b'A', 1, 7, suite.id()]);
    assert_eq!(body.len(), pt.len() + 16);

    // The sealed box's only randomness use is one encapsulation.
    let kem = HybridKem::new(suite);
    let (ct_ref, k_ref) = kem
        .encapsulate_to(&pk, &mut DeterministicEntropy::from_seed(&seed))
        .unwrap();
    assert_eq!(ct_ref.as_raw(), kem_ct);

    // Recipient side, independently.
    let k = kem
        .decapsulate_with(&sk, &HybridCiphertext::from_raw(suite, kem_ct).unwrap())
        .unwrap();
    assert!(k.ct_eq(&k_ref));
    let okm = derive_by_hand(suite.id(), k.expose(), kem_ct);
    let key = Key::try_from(&okm[..32]).unwrap();
    let nonce = Nonce::try_from(&okm[32..44]).unwrap();

    let mut aad_prime = b"VYRA-SEAL-v1".to_vec();
    aad_prime.push(suite.id());
    aad_prime.extend_from_slice(aad);

    let cipher = ChaCha20Poly1305::new(&key);
    let decrypted = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: body,
                aad: &aad_prime,
            },
        )
        .unwrap();
    assert_eq!(decrypted, pt, "{suite}");

    // And the forward direction: encrypting by hand reproduces the body.
    let encrypted = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: &pt,
                aad: &aad_prime,
            },
        )
        .unwrap();
    assert_eq!(encrypted, body, "{suite}");
}

#[test]
fn kdf_known_answer_vyra1() {
    kat(KemSuite::Vyra1);
}

#[test]
fn kdf_known_answer_vyra3() {
    kat(KemSuite::Vyra3);
}

#[test]
fn kdf_known_answer_vyra5() {
    kat(KemSuite::Vyra5);
}

/// The public constants agree with the hand framing.
#[test]
fn constants() {
    assert_eq!(vyra_seal::SEAL_LABEL, b"VYRA-SEAL-v1");
    assert_eq!(vyra_seal::KEY_LEN, 32);
    assert_eq!(vyra_seal::NONCE_LEN, 12);
    assert_eq!(vyra_seal::TAG_LEN, 16);
    assert_eq!(vyra_seal::DEM_OUTPUT_LEN, 44);
}
