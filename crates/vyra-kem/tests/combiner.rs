//! S6: combiner binding and a hand-framed known answer.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use common::to_hex;
use sha3::{Digest, Sha3_256};
use vyra_kem::{COMBINER_LABEL, combine};

/// The seven combiner inputs.
#[derive(Clone)]
struct Inputs {
    suite: u8,
    fields: [Vec<u8>; 6], // ss1, ss2, ct1, ct2, pk1, pk2
}

impl Inputs {
    fn sample() -> Self {
        Inputs {
            suite: 3,
            fields: [
                vec![0x11; 32],
                vec![0x22; 32],
                vec![0x33; 5],
                vec![0x44; 7],
                vec![0x55; 3],
                vec![0x66; 2],
            ],
        }
    }

    fn combine(&self) -> Vec<u8> {
        let [ss1, ss2, ct1, ct2, pk1, pk2] = &self.fields;
        combine(self.suite, ss1, ss2, ct1, ct2, pk1, pk2)
            .expose()
            .to_vec()
    }
}

/// SHA3-256 over `u64_be(len) ‖ bytes` frames, written out by hand.
fn hand_framed(inputs: &Inputs) -> Vec<u8> {
    let mut h = Sha3_256::new();
    let mut frame = |bytes: &[u8]| {
        h.update((bytes.len() as u64).to_be_bytes());
        h.update(bytes);
    };
    frame(b"VYRA-KEM-v1");
    frame(&[inputs.suite]);
    for f in &inputs.fields {
        frame(f);
    }
    h.finalize().to_vec()
}

#[test]
fn s6_known_answer() {
    let inputs = Inputs::sample();
    let got = inputs.combine();
    assert_eq!(COMBINER_LABEL, b"VYRA-KEM-v1");
    assert_eq!(got, hand_framed(&inputs));
    // Pinned value (computed by a separate hand-framing program).
    assert_eq!(
        to_hex(&got),
        "dd5db3786c4a3382e9a659c5358a3ecb4614a565ebefebc37d2b376824b71a76"
    );
}

#[test]
fn s6_every_input_is_bound() {
    let base = Inputs::sample();
    let k0 = base.combine();

    // Suite.
    for s in [0u8, 1, 2, 4, 5, 255] {
        let mut x = base.clone();
        x.suite = s;
        assert_ne!(x.combine(), k0, "suite {s}");
    }

    let names = ["ss1", "ss2", "ct1", "ct2", "pk1", "pk2"];
    for (i, name) in names.iter().enumerate() {
        // Flip each byte position's lowest bit.
        for pos in 0..base.fields[i].len() {
            let mut x = base.clone();
            x.fields[i][pos] ^= 1;
            assert_ne!(x.combine(), k0, "{name}[{pos}]");
        }
        // Extend and truncate.
        let mut x = base.clone();
        x.fields[i].push(0);
        assert_ne!(x.combine(), k0, "{name} extended");
        let mut x = base.clone();
        x.fields[i].pop();
        assert_ne!(x.combine(), k0, "{name} truncated");
    }

    // Swapping two fields (same contents, different positions) changes it.
    let mut x = base.clone();
    x.fields.swap(0, 1);
    assert_ne!(x.combine(), k0, "ss1/ss2 swapped");
    let mut x = base.clone();
    x.fields.swap(2, 3);
    assert_ne!(x.combine(), k0, "ct1/ct2 swapped");

    // Framing: moving a byte across a field boundary changes it.
    let mut x = base.clone();
    let b = x.fields[2].pop().unwrap();
    x.fields[3].insert(0, b);
    assert_ne!(x.combine(), k0, "boundary shift");
}

#[test]
fn combine_is_deterministic_and_32_bytes() {
    let a = Inputs::sample().combine();
    let b = Inputs::sample().combine();
    assert_eq!(a, b);
    assert_eq!(a.len(), 32);
}
