//! Transcript known-answer and framing tests.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use sha3::{Digest, Sha3_256};
use shake::{ExtendableOutput, Shake256, Update, XofReader};
use vyra_core::Transcript;
use vyra_core::transcript::XOF_DOMAIN;

/// Build the framed input by hand, independently of `Transcript`.
fn framed(label: &[u8], fields: &[&[u8]]) -> Vec<u8> {
    let mut v = Vec::new();
    for part in std::iter::once(label).chain(fields.iter().copied()) {
        v.extend_from_slice(&(part.len() as u64).to_be_bytes());
        v.extend_from_slice(part);
    }
    v
}

#[test]
fn finalize_known_answer() {
    let label: &'static [u8] = b"VYRA-test";
    let fields: [&[u8]; 3] = [b"", b"hello", &[0u8; 200]];

    let mut t = Transcript::new(label);
    for f in fields {
        t.append(f);
    }
    let got = t.finalize();

    let input = framed(label, &fields);
    // Spot-check the hand-built encoding itself.
    assert_eq!(&input[..8], &9u64.to_be_bytes());
    assert_eq!(&input[8..17], b"VYRA-test");
    let expected: [u8; 32] = Sha3_256::digest(&input).into();
    assert_eq!(got, expected);
}

#[test]
fn finalize_xof_known_answer() {
    let label: &'static [u8] = b"VYRA-test";
    let fields: [&[u8]; 2] = [b"a", b"bc"];

    let mut t = Transcript::new(label);
    t.append(fields[0]).append(fields[1]);
    let mut got = [0u8; 100];
    t.finalize_xof(&mut got);

    let mut h = Shake256::default();
    h.update(&[XOF_DOMAIN]);
    h.update(&framed(label, &fields));
    let mut expected = [0u8; 100];
    h.finalize_xof().read(&mut expected);
    assert_eq!(got, expected);
}

#[test]
fn label_only_known_answer() {
    let got = Transcript::new(b"L").finalize();
    let mut input = 1u64.to_be_bytes().to_vec();
    input.push(b'L');
    let expected: [u8; 32] = Sha3_256::digest(&input).into();
    assert_eq!(got, expected);
}

#[test]
fn framing_is_unambiguous() {
    let mut a = Transcript::new(b"t");
    a.append(b"ab").append(b"c");
    let mut b = Transcript::new(b"t");
    b.append(b"a").append(b"bc");
    assert_ne!(a.clone().finalize(), b.clone().finalize());

    let mut xa = [0u8; 32];
    let mut xb = [0u8; 32];
    a.finalize_xof(&mut xa);
    b.finalize_xof(&mut xb);
    assert_ne!(xa, xb);
}

#[test]
fn empty_field_is_not_absent() {
    let mut a = Transcript::new(b"t");
    a.append(b"");
    let b = Transcript::new(b"t");
    assert_ne!(a.finalize(), b.finalize());
}

#[test]
fn label_separates_domains() {
    let mut a = Transcript::new(b"one");
    a.append(b"x");
    let mut b = Transcript::new(b"two");
    b.append(b"x");
    assert_ne!(a.finalize(), b.finalize());
}

#[test]
fn hash_and_xof_outputs_unrelated() {
    let mut a = Transcript::new(b"t");
    a.append(b"x");
    let h = a.clone().finalize();
    let mut x = [0u8; 32];
    a.finalize_xof(&mut x);
    assert_ne!(h, x);
}
