//! P3: injectivity of the transcript framing, by a left inverse.
//!
//! Theorem chain (each step is one harness):
//!
//! 1. `transcript_prefix_inverse` — for EVERY `usize` length `n`,
//!    `prefix_len(frame_prefix_of_len(n)) == Some(n)`; hence the 8-byte prefix
//!    determines the length for all lengths, not only small ones.
//! 2. `transcript_single_frame` — for every `x` and every following byte
//!    string `rest` within the bound, `take_frame(frame(x) || rest)` returns
//!    exactly `(x, rest)` (as subslices), where `frame` is the library's own
//!    `push_frame`.
//! 3. `transcript_framing_shape_*` (one harness per shape of lengths; their
//!    union is the bound) — for every (label, fields) within the bound,
//!    `parse_framed(framed_encoding(label, fields)) == (label, fields)`.
//!    Since `parse_framed` is a function, this makes `framed_encoding`
//!    injective on the bounded domain: equal encodings parse to the same value.
//!
//! The tie between `framed_encoding` and what `Transcript` hashes is the host
//! known-answer test `transcript::tests::transcript_hashes_exactly_framed_encoding`
//! in vyra-core, plus both using `frame_prefix`.
//!
//! NOT covered: SHA3-256 / SHAKE256 (assumed collision resistant); in steps 2
//! and 3, contents and lengths beyond the stated bounds. Step 1 covers the
//! length arithmetic for all lengths; the extension of steps 2-3 to long inputs
//! is the hand argument "the parser reads the (correct, by 1) length and
//! splits there", not machine-checked.

// Harness code: every index is checked by the model checker itself.
#![allow(clippy::indexing_slicing)]

use vyra_core::transcript::{frame_prefix, frame_prefix_of_len, framed_encoding, push_frame};

use crate::bounds::{
    FRAME_LEMMA_MAX_LEN, FRAME_LEMMA_MAX_REST, FRAMING_MAX_FIELD_LEN, FRAMING_MAX_LABEL,
};
use crate::reference::{parse_framed, prefix_len, take_frame};

/// `s` is exactly `whole[start..start + len]` (address when non-empty).
fn is_sub(s: &[u8], whole: &[u8], start: usize, len: usize) -> bool {
    s.len() == len && (len == 0 || core::ptr::eq(s.as_ptr(), whole.as_ptr().wrapping_add(start)))
}

/// Step 1: for all `n: usize` (all 2^64 values on the 64-bit target), the
/// prefix decodes back to `n`. Also: `frame_prefix(x)` is
/// `frame_prefix_of_len(x.len())` for a symbolic short `x`.
#[kani::proof]
#[kani::unwind(10)]
fn transcript_prefix_inverse() {
    let n: usize = kani::any();
    assert!(prefix_len(frame_prefix_of_len(n)) == Some(n));

    let buf: [u8; 2] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= 2);
    assert!(frame_prefix(&buf[..len]) == frame_prefix_of_len(len));
}

/// Step 2: for every `x` with `len(x) <= FRAME_LEMMA_MAX_LEN` and every `rest`
/// with `len(rest) <= FRAME_LEMMA_MAX_REST` (all byte values),
/// `take_frame(frame(x) || rest) == Some((x, rest))`, both results being the
/// exact subslices at offsets 8 and 8 + len(x).
#[kani::proof]
#[kani::unwind(18)]
fn transcript_single_frame() {
    let xb: [u8; FRAME_LEMMA_MAX_LEN] = kani::any();
    let xl: usize = kani::any();
    kani::assume(xl <= FRAME_LEMMA_MAX_LEN);
    let rb: [u8; FRAME_LEMMA_MAX_REST] = kani::any();
    let rl: usize = kani::any();
    kani::assume(rl <= FRAME_LEMMA_MAX_REST);
    let x = &xb[..xl];
    let rest = &rb[..rl];

    let mut enc = Vec::new();
    push_frame(&mut enc, x);
    enc.extend_from_slice(rest);

    let Some((gx, grest)) = take_frame(&enc) else {
        kani::assert(false, "take_frame rejected frame(x) || rest");
        return;
    };
    assert!(is_sub(gx, &enc, 8, xl));
    assert!(is_sub(grest, &enc, 8 + xl, rl));
    assert!(gx == x);
    assert!(grest == rest);
}

/// Step 3 for one shape: `label` and `fields` have concrete lengths and fully
/// symbolic contents. Checks that the reference parser recovers the label,
/// the number of fields and every field from `framed_encoding`.
fn check_framing_round_trip(label: &[u8], fields: &[&[u8]]) {
    let enc = framed_encoding(label, fields);
    let Some((parsed_label, parsed)) = parse_framed(&enc) else {
        kani::assert(false, "parse_framed rejected framed_encoding output");
        return;
    };
    assert!(parsed_label == label);
    assert!(parsed.len() == fields.len());
    for (p, f) in parsed.iter().zip(fields) {
        assert!(*p == *f);
    }
}

/// One step-3 harness per shape (label length, field lengths). Every slice is
/// cut from a non-empty symbolic buffer (empty slices included), because a
/// zero-sized `kani::any::<[u8; 0]>()` makes CBMC exhaust memory.
macro_rules! framing_shape {
    ($name:ident, $label:literal, [$($f:literal),*]) => {
        #[kani::proof]
        #[kani::unwind(6)]
        fn $name() {
            let label: [u8; FRAMING_MAX_LABEL + 1] = kani::any();
            let fields: &[&[u8]] = &[$( &kani::any::<[u8; FRAMING_MAX_FIELD_LEN + 1]>()[..$f] ),*];
            check_framing_round_trip(&label[..$label], fields);
        }
    };
}

// Step 3: the union of these shapes is every label of length
// <= FRAMING_MAX_LABEL with at most FRAMING_MAX_FIELDS fields, each of length
// <= FRAMING_MAX_FIELD_LEN, all byte values. Consequence: `framed_encoding`
// is injective on that domain.
// BEGIN GENERATED by tools/kani/gen-shapes.py; do not edit by hand.
framing_shape!(transcript_framing_shape_l0_f, 0, []);
framing_shape!(transcript_framing_shape_l0_f0, 0, [0]);
framing_shape!(transcript_framing_shape_l0_f1, 0, [1]);
framing_shape!(transcript_framing_shape_l0_f2, 0, [2]);
framing_shape!(transcript_framing_shape_l0_f3, 0, [3]);
framing_shape!(transcript_framing_shape_l0_f0_0, 0, [0, 0]);
framing_shape!(transcript_framing_shape_l0_f0_1, 0, [0, 1]);
framing_shape!(transcript_framing_shape_l0_f0_2, 0, [0, 2]);
framing_shape!(transcript_framing_shape_l0_f0_3, 0, [0, 3]);
framing_shape!(transcript_framing_shape_l0_f1_0, 0, [1, 0]);
framing_shape!(transcript_framing_shape_l0_f1_1, 0, [1, 1]);
framing_shape!(transcript_framing_shape_l0_f1_2, 0, [1, 2]);
framing_shape!(transcript_framing_shape_l0_f1_3, 0, [1, 3]);
framing_shape!(transcript_framing_shape_l0_f2_0, 0, [2, 0]);
framing_shape!(transcript_framing_shape_l0_f2_1, 0, [2, 1]);
framing_shape!(transcript_framing_shape_l0_f2_2, 0, [2, 2]);
framing_shape!(transcript_framing_shape_l0_f2_3, 0, [2, 3]);
framing_shape!(transcript_framing_shape_l0_f3_0, 0, [3, 0]);
framing_shape!(transcript_framing_shape_l0_f3_1, 0, [3, 1]);
framing_shape!(transcript_framing_shape_l0_f3_2, 0, [3, 2]);
framing_shape!(transcript_framing_shape_l0_f3_3, 0, [3, 3]);
framing_shape!(transcript_framing_shape_l0_f0_0_0, 0, [0, 0, 0]);
framing_shape!(transcript_framing_shape_l0_f0_0_1, 0, [0, 0, 1]);
framing_shape!(transcript_framing_shape_l0_f0_0_2, 0, [0, 0, 2]);
framing_shape!(transcript_framing_shape_l0_f0_0_3, 0, [0, 0, 3]);
framing_shape!(transcript_framing_shape_l0_f0_1_0, 0, [0, 1, 0]);
framing_shape!(transcript_framing_shape_l0_f0_1_1, 0, [0, 1, 1]);
framing_shape!(transcript_framing_shape_l0_f0_1_2, 0, [0, 1, 2]);
framing_shape!(transcript_framing_shape_l0_f0_1_3, 0, [0, 1, 3]);
framing_shape!(transcript_framing_shape_l0_f0_2_0, 0, [0, 2, 0]);
framing_shape!(transcript_framing_shape_l0_f0_2_1, 0, [0, 2, 1]);
framing_shape!(transcript_framing_shape_l0_f0_2_2, 0, [0, 2, 2]);
framing_shape!(transcript_framing_shape_l0_f0_2_3, 0, [0, 2, 3]);
framing_shape!(transcript_framing_shape_l0_f0_3_0, 0, [0, 3, 0]);
framing_shape!(transcript_framing_shape_l0_f0_3_1, 0, [0, 3, 1]);
framing_shape!(transcript_framing_shape_l0_f0_3_2, 0, [0, 3, 2]);
framing_shape!(transcript_framing_shape_l0_f0_3_3, 0, [0, 3, 3]);
framing_shape!(transcript_framing_shape_l0_f1_0_0, 0, [1, 0, 0]);
framing_shape!(transcript_framing_shape_l0_f1_0_1, 0, [1, 0, 1]);
framing_shape!(transcript_framing_shape_l0_f1_0_2, 0, [1, 0, 2]);
framing_shape!(transcript_framing_shape_l0_f1_0_3, 0, [1, 0, 3]);
framing_shape!(transcript_framing_shape_l0_f1_1_0, 0, [1, 1, 0]);
framing_shape!(transcript_framing_shape_l0_f1_1_1, 0, [1, 1, 1]);
framing_shape!(transcript_framing_shape_l0_f1_1_2, 0, [1, 1, 2]);
framing_shape!(transcript_framing_shape_l0_f1_1_3, 0, [1, 1, 3]);
framing_shape!(transcript_framing_shape_l0_f1_2_0, 0, [1, 2, 0]);
framing_shape!(transcript_framing_shape_l0_f1_2_1, 0, [1, 2, 1]);
framing_shape!(transcript_framing_shape_l0_f1_2_2, 0, [1, 2, 2]);
framing_shape!(transcript_framing_shape_l0_f1_2_3, 0, [1, 2, 3]);
framing_shape!(transcript_framing_shape_l0_f1_3_0, 0, [1, 3, 0]);
framing_shape!(transcript_framing_shape_l0_f1_3_1, 0, [1, 3, 1]);
framing_shape!(transcript_framing_shape_l0_f1_3_2, 0, [1, 3, 2]);
framing_shape!(transcript_framing_shape_l0_f1_3_3, 0, [1, 3, 3]);
framing_shape!(transcript_framing_shape_l0_f2_0_0, 0, [2, 0, 0]);
framing_shape!(transcript_framing_shape_l0_f2_0_1, 0, [2, 0, 1]);
framing_shape!(transcript_framing_shape_l0_f2_0_2, 0, [2, 0, 2]);
framing_shape!(transcript_framing_shape_l0_f2_0_3, 0, [2, 0, 3]);
framing_shape!(transcript_framing_shape_l0_f2_1_0, 0, [2, 1, 0]);
framing_shape!(transcript_framing_shape_l0_f2_1_1, 0, [2, 1, 1]);
framing_shape!(transcript_framing_shape_l0_f2_1_2, 0, [2, 1, 2]);
framing_shape!(transcript_framing_shape_l0_f2_1_3, 0, [2, 1, 3]);
framing_shape!(transcript_framing_shape_l0_f2_2_0, 0, [2, 2, 0]);
framing_shape!(transcript_framing_shape_l0_f2_2_1, 0, [2, 2, 1]);
framing_shape!(transcript_framing_shape_l0_f2_2_2, 0, [2, 2, 2]);
framing_shape!(transcript_framing_shape_l0_f2_2_3, 0, [2, 2, 3]);
framing_shape!(transcript_framing_shape_l0_f2_3_0, 0, [2, 3, 0]);
framing_shape!(transcript_framing_shape_l0_f2_3_1, 0, [2, 3, 1]);
framing_shape!(transcript_framing_shape_l0_f2_3_2, 0, [2, 3, 2]);
framing_shape!(transcript_framing_shape_l0_f2_3_3, 0, [2, 3, 3]);
framing_shape!(transcript_framing_shape_l0_f3_0_0, 0, [3, 0, 0]);
framing_shape!(transcript_framing_shape_l0_f3_0_1, 0, [3, 0, 1]);
framing_shape!(transcript_framing_shape_l0_f3_0_2, 0, [3, 0, 2]);
framing_shape!(transcript_framing_shape_l0_f3_0_3, 0, [3, 0, 3]);
framing_shape!(transcript_framing_shape_l0_f3_1_0, 0, [3, 1, 0]);
framing_shape!(transcript_framing_shape_l0_f3_1_1, 0, [3, 1, 1]);
framing_shape!(transcript_framing_shape_l0_f3_1_2, 0, [3, 1, 2]);
framing_shape!(transcript_framing_shape_l0_f3_1_3, 0, [3, 1, 3]);
framing_shape!(transcript_framing_shape_l0_f3_2_0, 0, [3, 2, 0]);
framing_shape!(transcript_framing_shape_l0_f3_2_1, 0, [3, 2, 1]);
framing_shape!(transcript_framing_shape_l0_f3_2_2, 0, [3, 2, 2]);
framing_shape!(transcript_framing_shape_l0_f3_2_3, 0, [3, 2, 3]);
framing_shape!(transcript_framing_shape_l0_f3_3_0, 0, [3, 3, 0]);
framing_shape!(transcript_framing_shape_l0_f3_3_1, 0, [3, 3, 1]);
framing_shape!(transcript_framing_shape_l0_f3_3_2, 0, [3, 3, 2]);
framing_shape!(transcript_framing_shape_l0_f3_3_3, 0, [3, 3, 3]);
framing_shape!(transcript_framing_shape_l1_f, 1, []);
framing_shape!(transcript_framing_shape_l1_f0, 1, [0]);
framing_shape!(transcript_framing_shape_l1_f1, 1, [1]);
framing_shape!(transcript_framing_shape_l1_f2, 1, [2]);
framing_shape!(transcript_framing_shape_l1_f3, 1, [3]);
framing_shape!(transcript_framing_shape_l1_f0_0, 1, [0, 0]);
framing_shape!(transcript_framing_shape_l1_f0_1, 1, [0, 1]);
framing_shape!(transcript_framing_shape_l1_f0_2, 1, [0, 2]);
framing_shape!(transcript_framing_shape_l1_f0_3, 1, [0, 3]);
framing_shape!(transcript_framing_shape_l1_f1_0, 1, [1, 0]);
framing_shape!(transcript_framing_shape_l1_f1_1, 1, [1, 1]);
framing_shape!(transcript_framing_shape_l1_f1_2, 1, [1, 2]);
framing_shape!(transcript_framing_shape_l1_f1_3, 1, [1, 3]);
framing_shape!(transcript_framing_shape_l1_f2_0, 1, [2, 0]);
framing_shape!(transcript_framing_shape_l1_f2_1, 1, [2, 1]);
framing_shape!(transcript_framing_shape_l1_f2_2, 1, [2, 2]);
framing_shape!(transcript_framing_shape_l1_f2_3, 1, [2, 3]);
framing_shape!(transcript_framing_shape_l1_f3_0, 1, [3, 0]);
framing_shape!(transcript_framing_shape_l1_f3_1, 1, [3, 1]);
framing_shape!(transcript_framing_shape_l1_f3_2, 1, [3, 2]);
framing_shape!(transcript_framing_shape_l1_f3_3, 1, [3, 3]);
framing_shape!(transcript_framing_shape_l1_f0_0_0, 1, [0, 0, 0]);
framing_shape!(transcript_framing_shape_l1_f0_0_1, 1, [0, 0, 1]);
framing_shape!(transcript_framing_shape_l1_f0_0_2, 1, [0, 0, 2]);
framing_shape!(transcript_framing_shape_l1_f0_0_3, 1, [0, 0, 3]);
framing_shape!(transcript_framing_shape_l1_f0_1_0, 1, [0, 1, 0]);
framing_shape!(transcript_framing_shape_l1_f0_1_1, 1, [0, 1, 1]);
framing_shape!(transcript_framing_shape_l1_f0_1_2, 1, [0, 1, 2]);
framing_shape!(transcript_framing_shape_l1_f0_1_3, 1, [0, 1, 3]);
framing_shape!(transcript_framing_shape_l1_f0_2_0, 1, [0, 2, 0]);
framing_shape!(transcript_framing_shape_l1_f0_2_1, 1, [0, 2, 1]);
framing_shape!(transcript_framing_shape_l1_f0_2_2, 1, [0, 2, 2]);
framing_shape!(transcript_framing_shape_l1_f0_2_3, 1, [0, 2, 3]);
framing_shape!(transcript_framing_shape_l1_f0_3_0, 1, [0, 3, 0]);
framing_shape!(transcript_framing_shape_l1_f0_3_1, 1, [0, 3, 1]);
framing_shape!(transcript_framing_shape_l1_f0_3_2, 1, [0, 3, 2]);
framing_shape!(transcript_framing_shape_l1_f0_3_3, 1, [0, 3, 3]);
framing_shape!(transcript_framing_shape_l1_f1_0_0, 1, [1, 0, 0]);
framing_shape!(transcript_framing_shape_l1_f1_0_1, 1, [1, 0, 1]);
framing_shape!(transcript_framing_shape_l1_f1_0_2, 1, [1, 0, 2]);
framing_shape!(transcript_framing_shape_l1_f1_0_3, 1, [1, 0, 3]);
framing_shape!(transcript_framing_shape_l1_f1_1_0, 1, [1, 1, 0]);
framing_shape!(transcript_framing_shape_l1_f1_1_1, 1, [1, 1, 1]);
framing_shape!(transcript_framing_shape_l1_f1_1_2, 1, [1, 1, 2]);
framing_shape!(transcript_framing_shape_l1_f1_1_3, 1, [1, 1, 3]);
framing_shape!(transcript_framing_shape_l1_f1_2_0, 1, [1, 2, 0]);
framing_shape!(transcript_framing_shape_l1_f1_2_1, 1, [1, 2, 1]);
framing_shape!(transcript_framing_shape_l1_f1_2_2, 1, [1, 2, 2]);
framing_shape!(transcript_framing_shape_l1_f1_2_3, 1, [1, 2, 3]);
framing_shape!(transcript_framing_shape_l1_f1_3_0, 1, [1, 3, 0]);
framing_shape!(transcript_framing_shape_l1_f1_3_1, 1, [1, 3, 1]);
framing_shape!(transcript_framing_shape_l1_f1_3_2, 1, [1, 3, 2]);
framing_shape!(transcript_framing_shape_l1_f1_3_3, 1, [1, 3, 3]);
framing_shape!(transcript_framing_shape_l1_f2_0_0, 1, [2, 0, 0]);
framing_shape!(transcript_framing_shape_l1_f2_0_1, 1, [2, 0, 1]);
framing_shape!(transcript_framing_shape_l1_f2_0_2, 1, [2, 0, 2]);
framing_shape!(transcript_framing_shape_l1_f2_0_3, 1, [2, 0, 3]);
framing_shape!(transcript_framing_shape_l1_f2_1_0, 1, [2, 1, 0]);
framing_shape!(transcript_framing_shape_l1_f2_1_1, 1, [2, 1, 1]);
framing_shape!(transcript_framing_shape_l1_f2_1_2, 1, [2, 1, 2]);
framing_shape!(transcript_framing_shape_l1_f2_1_3, 1, [2, 1, 3]);
framing_shape!(transcript_framing_shape_l1_f2_2_0, 1, [2, 2, 0]);
framing_shape!(transcript_framing_shape_l1_f2_2_1, 1, [2, 2, 1]);
framing_shape!(transcript_framing_shape_l1_f2_2_2, 1, [2, 2, 2]);
framing_shape!(transcript_framing_shape_l1_f2_2_3, 1, [2, 2, 3]);
framing_shape!(transcript_framing_shape_l1_f2_3_0, 1, [2, 3, 0]);
framing_shape!(transcript_framing_shape_l1_f2_3_1, 1, [2, 3, 1]);
framing_shape!(transcript_framing_shape_l1_f2_3_2, 1, [2, 3, 2]);
framing_shape!(transcript_framing_shape_l1_f2_3_3, 1, [2, 3, 3]);
framing_shape!(transcript_framing_shape_l1_f3_0_0, 1, [3, 0, 0]);
framing_shape!(transcript_framing_shape_l1_f3_0_1, 1, [3, 0, 1]);
framing_shape!(transcript_framing_shape_l1_f3_0_2, 1, [3, 0, 2]);
framing_shape!(transcript_framing_shape_l1_f3_0_3, 1, [3, 0, 3]);
framing_shape!(transcript_framing_shape_l1_f3_1_0, 1, [3, 1, 0]);
framing_shape!(transcript_framing_shape_l1_f3_1_1, 1, [3, 1, 1]);
framing_shape!(transcript_framing_shape_l1_f3_1_2, 1, [3, 1, 2]);
framing_shape!(transcript_framing_shape_l1_f3_1_3, 1, [3, 1, 3]);
framing_shape!(transcript_framing_shape_l1_f3_2_0, 1, [3, 2, 0]);
framing_shape!(transcript_framing_shape_l1_f3_2_1, 1, [3, 2, 1]);
framing_shape!(transcript_framing_shape_l1_f3_2_2, 1, [3, 2, 2]);
framing_shape!(transcript_framing_shape_l1_f3_2_3, 1, [3, 2, 3]);
framing_shape!(transcript_framing_shape_l1_f3_3_0, 1, [3, 3, 0]);
framing_shape!(transcript_framing_shape_l1_f3_3_1, 1, [3, 3, 1]);
framing_shape!(transcript_framing_shape_l1_f3_3_2, 1, [3, 3, 2]);
framing_shape!(transcript_framing_shape_l1_f3_3_3, 1, [3, 3, 3]);
framing_shape!(transcript_framing_shape_l2_f, 2, []);
framing_shape!(transcript_framing_shape_l2_f0, 2, [0]);
framing_shape!(transcript_framing_shape_l2_f1, 2, [1]);
framing_shape!(transcript_framing_shape_l2_f2, 2, [2]);
framing_shape!(transcript_framing_shape_l2_f3, 2, [3]);
framing_shape!(transcript_framing_shape_l2_f0_0, 2, [0, 0]);
framing_shape!(transcript_framing_shape_l2_f0_1, 2, [0, 1]);
framing_shape!(transcript_framing_shape_l2_f0_2, 2, [0, 2]);
framing_shape!(transcript_framing_shape_l2_f0_3, 2, [0, 3]);
framing_shape!(transcript_framing_shape_l2_f1_0, 2, [1, 0]);
framing_shape!(transcript_framing_shape_l2_f1_1, 2, [1, 1]);
framing_shape!(transcript_framing_shape_l2_f1_2, 2, [1, 2]);
framing_shape!(transcript_framing_shape_l2_f1_3, 2, [1, 3]);
framing_shape!(transcript_framing_shape_l2_f2_0, 2, [2, 0]);
framing_shape!(transcript_framing_shape_l2_f2_1, 2, [2, 1]);
framing_shape!(transcript_framing_shape_l2_f2_2, 2, [2, 2]);
framing_shape!(transcript_framing_shape_l2_f2_3, 2, [2, 3]);
framing_shape!(transcript_framing_shape_l2_f3_0, 2, [3, 0]);
framing_shape!(transcript_framing_shape_l2_f3_1, 2, [3, 1]);
framing_shape!(transcript_framing_shape_l2_f3_2, 2, [3, 2]);
framing_shape!(transcript_framing_shape_l2_f3_3, 2, [3, 3]);
framing_shape!(transcript_framing_shape_l2_f0_0_0, 2, [0, 0, 0]);
framing_shape!(transcript_framing_shape_l2_f0_0_1, 2, [0, 0, 1]);
framing_shape!(transcript_framing_shape_l2_f0_0_2, 2, [0, 0, 2]);
framing_shape!(transcript_framing_shape_l2_f0_0_3, 2, [0, 0, 3]);
framing_shape!(transcript_framing_shape_l2_f0_1_0, 2, [0, 1, 0]);
framing_shape!(transcript_framing_shape_l2_f0_1_1, 2, [0, 1, 1]);
framing_shape!(transcript_framing_shape_l2_f0_1_2, 2, [0, 1, 2]);
framing_shape!(transcript_framing_shape_l2_f0_1_3, 2, [0, 1, 3]);
framing_shape!(transcript_framing_shape_l2_f0_2_0, 2, [0, 2, 0]);
framing_shape!(transcript_framing_shape_l2_f0_2_1, 2, [0, 2, 1]);
framing_shape!(transcript_framing_shape_l2_f0_2_2, 2, [0, 2, 2]);
framing_shape!(transcript_framing_shape_l2_f0_2_3, 2, [0, 2, 3]);
framing_shape!(transcript_framing_shape_l2_f0_3_0, 2, [0, 3, 0]);
framing_shape!(transcript_framing_shape_l2_f0_3_1, 2, [0, 3, 1]);
framing_shape!(transcript_framing_shape_l2_f0_3_2, 2, [0, 3, 2]);
framing_shape!(transcript_framing_shape_l2_f0_3_3, 2, [0, 3, 3]);
framing_shape!(transcript_framing_shape_l2_f1_0_0, 2, [1, 0, 0]);
framing_shape!(transcript_framing_shape_l2_f1_0_1, 2, [1, 0, 1]);
framing_shape!(transcript_framing_shape_l2_f1_0_2, 2, [1, 0, 2]);
framing_shape!(transcript_framing_shape_l2_f1_0_3, 2, [1, 0, 3]);
framing_shape!(transcript_framing_shape_l2_f1_1_0, 2, [1, 1, 0]);
framing_shape!(transcript_framing_shape_l2_f1_1_1, 2, [1, 1, 1]);
framing_shape!(transcript_framing_shape_l2_f1_1_2, 2, [1, 1, 2]);
framing_shape!(transcript_framing_shape_l2_f1_1_3, 2, [1, 1, 3]);
framing_shape!(transcript_framing_shape_l2_f1_2_0, 2, [1, 2, 0]);
framing_shape!(transcript_framing_shape_l2_f1_2_1, 2, [1, 2, 1]);
framing_shape!(transcript_framing_shape_l2_f1_2_2, 2, [1, 2, 2]);
framing_shape!(transcript_framing_shape_l2_f1_2_3, 2, [1, 2, 3]);
framing_shape!(transcript_framing_shape_l2_f1_3_0, 2, [1, 3, 0]);
framing_shape!(transcript_framing_shape_l2_f1_3_1, 2, [1, 3, 1]);
framing_shape!(transcript_framing_shape_l2_f1_3_2, 2, [1, 3, 2]);
framing_shape!(transcript_framing_shape_l2_f1_3_3, 2, [1, 3, 3]);
framing_shape!(transcript_framing_shape_l2_f2_0_0, 2, [2, 0, 0]);
framing_shape!(transcript_framing_shape_l2_f2_0_1, 2, [2, 0, 1]);
framing_shape!(transcript_framing_shape_l2_f2_0_2, 2, [2, 0, 2]);
framing_shape!(transcript_framing_shape_l2_f2_0_3, 2, [2, 0, 3]);
framing_shape!(transcript_framing_shape_l2_f2_1_0, 2, [2, 1, 0]);
framing_shape!(transcript_framing_shape_l2_f2_1_1, 2, [2, 1, 1]);
framing_shape!(transcript_framing_shape_l2_f2_1_2, 2, [2, 1, 2]);
framing_shape!(transcript_framing_shape_l2_f2_1_3, 2, [2, 1, 3]);
framing_shape!(transcript_framing_shape_l2_f2_2_0, 2, [2, 2, 0]);
framing_shape!(transcript_framing_shape_l2_f2_2_1, 2, [2, 2, 1]);
framing_shape!(transcript_framing_shape_l2_f2_2_2, 2, [2, 2, 2]);
framing_shape!(transcript_framing_shape_l2_f2_2_3, 2, [2, 2, 3]);
framing_shape!(transcript_framing_shape_l2_f2_3_0, 2, [2, 3, 0]);
framing_shape!(transcript_framing_shape_l2_f2_3_1, 2, [2, 3, 1]);
framing_shape!(transcript_framing_shape_l2_f2_3_2, 2, [2, 3, 2]);
framing_shape!(transcript_framing_shape_l2_f2_3_3, 2, [2, 3, 3]);
framing_shape!(transcript_framing_shape_l2_f3_0_0, 2, [3, 0, 0]);
framing_shape!(transcript_framing_shape_l2_f3_0_1, 2, [3, 0, 1]);
framing_shape!(transcript_framing_shape_l2_f3_0_2, 2, [3, 0, 2]);
framing_shape!(transcript_framing_shape_l2_f3_0_3, 2, [3, 0, 3]);
framing_shape!(transcript_framing_shape_l2_f3_1_0, 2, [3, 1, 0]);
framing_shape!(transcript_framing_shape_l2_f3_1_1, 2, [3, 1, 1]);
framing_shape!(transcript_framing_shape_l2_f3_1_2, 2, [3, 1, 2]);
framing_shape!(transcript_framing_shape_l2_f3_1_3, 2, [3, 1, 3]);
framing_shape!(transcript_framing_shape_l2_f3_2_0, 2, [3, 2, 0]);
framing_shape!(transcript_framing_shape_l2_f3_2_1, 2, [3, 2, 1]);
framing_shape!(transcript_framing_shape_l2_f3_2_2, 2, [3, 2, 2]);
framing_shape!(transcript_framing_shape_l2_f3_2_3, 2, [3, 2, 3]);
framing_shape!(transcript_framing_shape_l2_f3_3_0, 2, [3, 3, 0]);
framing_shape!(transcript_framing_shape_l2_f3_3_1, 2, [3, 3, 1]);
framing_shape!(transcript_framing_shape_l2_f3_3_2, 2, [3, 3, 2]);
framing_shape!(transcript_framing_shape_l2_f3_3_3, 2, [3, 3, 3]);
framing_shape!(transcript_framing_shape_l3_f, 3, []);
framing_shape!(transcript_framing_shape_l3_f0, 3, [0]);
framing_shape!(transcript_framing_shape_l3_f1, 3, [1]);
framing_shape!(transcript_framing_shape_l3_f2, 3, [2]);
framing_shape!(transcript_framing_shape_l3_f3, 3, [3]);
framing_shape!(transcript_framing_shape_l3_f0_0, 3, [0, 0]);
framing_shape!(transcript_framing_shape_l3_f0_1, 3, [0, 1]);
framing_shape!(transcript_framing_shape_l3_f0_2, 3, [0, 2]);
framing_shape!(transcript_framing_shape_l3_f0_3, 3, [0, 3]);
framing_shape!(transcript_framing_shape_l3_f1_0, 3, [1, 0]);
framing_shape!(transcript_framing_shape_l3_f1_1, 3, [1, 1]);
framing_shape!(transcript_framing_shape_l3_f1_2, 3, [1, 2]);
framing_shape!(transcript_framing_shape_l3_f1_3, 3, [1, 3]);
framing_shape!(transcript_framing_shape_l3_f2_0, 3, [2, 0]);
framing_shape!(transcript_framing_shape_l3_f2_1, 3, [2, 1]);
framing_shape!(transcript_framing_shape_l3_f2_2, 3, [2, 2]);
framing_shape!(transcript_framing_shape_l3_f2_3, 3, [2, 3]);
framing_shape!(transcript_framing_shape_l3_f3_0, 3, [3, 0]);
framing_shape!(transcript_framing_shape_l3_f3_1, 3, [3, 1]);
framing_shape!(transcript_framing_shape_l3_f3_2, 3, [3, 2]);
framing_shape!(transcript_framing_shape_l3_f3_3, 3, [3, 3]);
framing_shape!(transcript_framing_shape_l3_f0_0_0, 3, [0, 0, 0]);
framing_shape!(transcript_framing_shape_l3_f0_0_1, 3, [0, 0, 1]);
framing_shape!(transcript_framing_shape_l3_f0_0_2, 3, [0, 0, 2]);
framing_shape!(transcript_framing_shape_l3_f0_0_3, 3, [0, 0, 3]);
framing_shape!(transcript_framing_shape_l3_f0_1_0, 3, [0, 1, 0]);
framing_shape!(transcript_framing_shape_l3_f0_1_1, 3, [0, 1, 1]);
framing_shape!(transcript_framing_shape_l3_f0_1_2, 3, [0, 1, 2]);
framing_shape!(transcript_framing_shape_l3_f0_1_3, 3, [0, 1, 3]);
framing_shape!(transcript_framing_shape_l3_f0_2_0, 3, [0, 2, 0]);
framing_shape!(transcript_framing_shape_l3_f0_2_1, 3, [0, 2, 1]);
framing_shape!(transcript_framing_shape_l3_f0_2_2, 3, [0, 2, 2]);
framing_shape!(transcript_framing_shape_l3_f0_2_3, 3, [0, 2, 3]);
framing_shape!(transcript_framing_shape_l3_f0_3_0, 3, [0, 3, 0]);
framing_shape!(transcript_framing_shape_l3_f0_3_1, 3, [0, 3, 1]);
framing_shape!(transcript_framing_shape_l3_f0_3_2, 3, [0, 3, 2]);
framing_shape!(transcript_framing_shape_l3_f0_3_3, 3, [0, 3, 3]);
framing_shape!(transcript_framing_shape_l3_f1_0_0, 3, [1, 0, 0]);
framing_shape!(transcript_framing_shape_l3_f1_0_1, 3, [1, 0, 1]);
framing_shape!(transcript_framing_shape_l3_f1_0_2, 3, [1, 0, 2]);
framing_shape!(transcript_framing_shape_l3_f1_0_3, 3, [1, 0, 3]);
framing_shape!(transcript_framing_shape_l3_f1_1_0, 3, [1, 1, 0]);
framing_shape!(transcript_framing_shape_l3_f1_1_1, 3, [1, 1, 1]);
framing_shape!(transcript_framing_shape_l3_f1_1_2, 3, [1, 1, 2]);
framing_shape!(transcript_framing_shape_l3_f1_1_3, 3, [1, 1, 3]);
framing_shape!(transcript_framing_shape_l3_f1_2_0, 3, [1, 2, 0]);
framing_shape!(transcript_framing_shape_l3_f1_2_1, 3, [1, 2, 1]);
framing_shape!(transcript_framing_shape_l3_f1_2_2, 3, [1, 2, 2]);
framing_shape!(transcript_framing_shape_l3_f1_2_3, 3, [1, 2, 3]);
framing_shape!(transcript_framing_shape_l3_f1_3_0, 3, [1, 3, 0]);
framing_shape!(transcript_framing_shape_l3_f1_3_1, 3, [1, 3, 1]);
framing_shape!(transcript_framing_shape_l3_f1_3_2, 3, [1, 3, 2]);
framing_shape!(transcript_framing_shape_l3_f1_3_3, 3, [1, 3, 3]);
framing_shape!(transcript_framing_shape_l3_f2_0_0, 3, [2, 0, 0]);
framing_shape!(transcript_framing_shape_l3_f2_0_1, 3, [2, 0, 1]);
framing_shape!(transcript_framing_shape_l3_f2_0_2, 3, [2, 0, 2]);
framing_shape!(transcript_framing_shape_l3_f2_0_3, 3, [2, 0, 3]);
framing_shape!(transcript_framing_shape_l3_f2_1_0, 3, [2, 1, 0]);
framing_shape!(transcript_framing_shape_l3_f2_1_1, 3, [2, 1, 1]);
framing_shape!(transcript_framing_shape_l3_f2_1_2, 3, [2, 1, 2]);
framing_shape!(transcript_framing_shape_l3_f2_1_3, 3, [2, 1, 3]);
framing_shape!(transcript_framing_shape_l3_f2_2_0, 3, [2, 2, 0]);
framing_shape!(transcript_framing_shape_l3_f2_2_1, 3, [2, 2, 1]);
framing_shape!(transcript_framing_shape_l3_f2_2_2, 3, [2, 2, 2]);
framing_shape!(transcript_framing_shape_l3_f2_2_3, 3, [2, 2, 3]);
framing_shape!(transcript_framing_shape_l3_f2_3_0, 3, [2, 3, 0]);
framing_shape!(transcript_framing_shape_l3_f2_3_1, 3, [2, 3, 1]);
framing_shape!(transcript_framing_shape_l3_f2_3_2, 3, [2, 3, 2]);
framing_shape!(transcript_framing_shape_l3_f2_3_3, 3, [2, 3, 3]);
framing_shape!(transcript_framing_shape_l3_f3_0_0, 3, [3, 0, 0]);
framing_shape!(transcript_framing_shape_l3_f3_0_1, 3, [3, 0, 1]);
framing_shape!(transcript_framing_shape_l3_f3_0_2, 3, [3, 0, 2]);
framing_shape!(transcript_framing_shape_l3_f3_0_3, 3, [3, 0, 3]);
framing_shape!(transcript_framing_shape_l3_f3_1_0, 3, [3, 1, 0]);
framing_shape!(transcript_framing_shape_l3_f3_1_1, 3, [3, 1, 1]);
framing_shape!(transcript_framing_shape_l3_f3_1_2, 3, [3, 1, 2]);
framing_shape!(transcript_framing_shape_l3_f3_1_3, 3, [3, 1, 3]);
framing_shape!(transcript_framing_shape_l3_f3_2_0, 3, [3, 2, 0]);
framing_shape!(transcript_framing_shape_l3_f3_2_1, 3, [3, 2, 1]);
framing_shape!(transcript_framing_shape_l3_f3_2_2, 3, [3, 2, 2]);
framing_shape!(transcript_framing_shape_l3_f3_2_3, 3, [3, 2, 3]);
framing_shape!(transcript_framing_shape_l3_f3_3_0, 3, [3, 3, 0]);
framing_shape!(transcript_framing_shape_l3_f3_3_1, 3, [3, 3, 1]);
framing_shape!(transcript_framing_shape_l3_f3_3_2, 3, [3, 3, 2]);
framing_shape!(transcript_framing_shape_l3_f3_3_3, 3, [3, 3, 3]);
// END GENERATED
