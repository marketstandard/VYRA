//! P1 / P2: wire header parser, `Reader`, and encode/decode round trip.
//!
//! NOT covered: inputs longer than the stated bounds; the payload checks done
//! by the owning crates (suite ids, payload lengths, key validation, secret-key
//! check values); timing.

// Harness code: every index is checked by the model checker itself.
#![allow(clippy::indexing_slicing)]

use vyra_core::Error;
use vyra_core::wire::{self, HEADER_LEN, MAGIC, ObjectType, Reader, VERSION};

use crate::bounds::{
    DECODE_MAX_LEN, HEADER_REJECT_MAX_PAYLOAD, READER_MAX_LEN, READER_MAX_OPS,
    ROUND_TRIP_MAX_PAYLOAD,
};

/// Any of the seven assigned object types.
fn any_object_type() -> ObjectType {
    let b: u8 = kani::any();
    kani::assume((1..=7).contains(&b));
    match ObjectType::from_u8(b) {
        Ok(t) => t,
        Err(_) => {
            // Unreachable under the assumption; asserting keeps it honest.
            kani::assert(false, "from_u8 rejected an assigned type");
            ObjectType::KemPublicKey
        }
    }
}

/// `s` is exactly the subslice `whole[start..start + len]`: same length and,
/// when non-empty, the same address (not merely equal bytes). An empty slice
/// addresses no bytes, and `Reader::rest` legitimately leaves a dangling empty
/// slice behind, so empty results are compared by length only.
fn is_subslice_at(s: &[u8], whole: &[u8], start: usize, len: usize) -> bool {
    s.len() == len && (len == 0 || core::ptr::eq(s.as_ptr(), whole.as_ptr().wrapping_add(start)))
}

/// P1: for every input of length <= DECODE_MAX_LEN (all byte values) and
/// every expected object type, `decode` returns without panicking, and:
/// - len < 7 => `InvalidLength { what: "wire header", expected: 7, actual: len }`;
/// - otherwise `Ok((s, p))` iff magic == "VYRA", version == 1 and type byte ==
///   expected, with `s == input[6]` and `p` the exact subslice `input[7..]`;
///   every other input gives `InvalidEncoding(_)`.
#[kani::proof]
#[kani::unwind(26)]
fn wire_decode_exact() {
    let buf: [u8; DECODE_MAX_LEN] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= DECODE_MAX_LEN);
    let input = &buf[..len];
    let t = any_object_type();

    let res = wire::decode(input, t);

    if len < HEADER_LEN {
        assert!(
            res == Err(Error::InvalidLength {
                what: "wire header",
                expected: HEADER_LEN,
                actual: len,
            })
        );
    } else {
        let header_ok = input[0] == MAGIC[0]
            && input[1] == MAGIC[1]
            && input[2] == MAGIC[2]
            && input[3] == MAGIC[3]
            && input[4] == VERSION
            && input[5] == t.as_u8();
        match res {
            Ok((suite, payload)) => {
                assert!(header_ok);
                assert!(suite == input[6]);
                assert!(is_subslice_at(payload, input, HEADER_LEN, len - HEADER_LEN));
            }
            Err(e) => {
                assert!(!header_ok);
                assert!(matches!(e, Error::InvalidEncoding(_)));
            }
        }
    }
}

/// P1: for every input length <= READER_MAX_LEN and every sequence of up to
/// READER_MAX_OPS operations (`take(n)` with ANY `usize` n, `remaining()`,
/// `rest()`), checked against a reference model `consumed`:
/// - `take(n)` succeeds iff `n <= len - consumed`, returns exactly the subslice
///   `input[consumed..consumed + n]`, and on failure returns
///   `InvalidLength { expected: n, actual: len - consumed }` and leaves the
///   reader unchanged;
/// - `remaining() == len - consumed`; `rest()` returns `input[consumed..]`;
/// - after every step, `finish()` (on a clone) succeeds iff `consumed == len`,
///   and otherwise reports `InvalidLength { "trailing bytes", 0, len - consumed }`.
///
/// `Reader` never inspects byte values, so the property is stated about
/// offsets and lengths (exact slice addresses), with arbitrary contents.
#[kani::proof]
#[kani::unwind(16)]
fn wire_reader_ops() {
    let buf: [u8; READER_MAX_LEN] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= READER_MAX_LEN);
    let input = &buf[..len];

    let mut r = Reader::new(input);
    let mut consumed: usize = 0;

    for _ in 0..READER_MAX_OPS {
        let op: u8 = kani::any();
        match op % 3 {
            0 => {
                let n: usize = kani::any();
                let left = len - consumed;
                match r.take(n, "field") {
                    Ok(head) => {
                        assert!(n <= left);
                        assert!(is_subslice_at(head, input, consumed, n));
                        consumed += n;
                    }
                    Err(e) => {
                        assert!(n > left);
                        assert!(
                            e == Error::InvalidLength {
                                what: "field",
                                expected: n,
                                actual: left,
                            }
                        );
                    }
                }
            }
            1 => {
                assert!(r.remaining() == len - consumed);
            }
            _ => {
                let rest = r.rest();
                assert!(is_subslice_at(rest, input, consumed, len - consumed));
                consumed = len;
            }
        }
        assert!(consumed <= len);
        assert!(r.remaining() == len - consumed);
        let fin = r.clone().finish();
        if consumed == len {
            assert!(fin == Ok(()));
        } else {
            assert!(
                fin == Err(Error::InvalidLength {
                    what: "trailing bytes",
                    expected: 0,
                    actual: len - consumed,
                })
            );
        }
    }
    assert!(r.finish().is_ok() == (consumed == len));
}

/// P2 for one payload length: for every object type `t`, every expected
/// type `u`, every suite byte and every payload of exactly `len` bytes (all
/// byte values): `encode` produces exactly
/// `"VYRA" || 0x01 || t || suite || payload`, and
/// `decode(encode(t, suite, payload), u)` is `Ok((suite, payload))` iff
/// `t == u`, otherwise `InvalidEncoding("unexpected object type")`.
fn check_round_trip(payload: &[u8]) {
    let len = payload.len();
    let t = any_object_type();
    let u = any_object_type();
    let suite: u8 = kani::any();

    let enc = wire::encode(t, suite, payload);
    assert!(enc.len() == HEADER_LEN + len);
    assert!(enc[..4] == MAGIC);
    assert!(enc[4] == VERSION);
    assert!(enc[5] == t.as_u8());
    assert!(enc[6] == suite);
    assert!(&enc[HEADER_LEN..] == payload);

    match wire::decode(&enc, u) {
        Ok((s, p)) => {
            assert!(t == u);
            assert!(s == suite);
            assert!(p == payload);
        }
        Err(e) => {
            assert!(t != u);
            assert!(e == Error::InvalidEncoding("unexpected object type"));
        }
    }
}

/// One P2 round-trip harness per payload length (concrete length, symbolic
/// contents, types and suite); their union covers payload lengths
/// `0..=ROUND_TRIP_MAX_PAYLOAD`. The payload is cut from a non-empty buffer.
macro_rules! round_trip_shape {
    ($name:ident, $len:literal) => {
        #[kani::proof]
        #[kani::unwind(24)]
        fn $name() {
            let buf: [u8; ROUND_TRIP_MAX_PAYLOAD + 1] = kani::any();
            check_round_trip(&buf[..$len]);
        }
    };
}

// BEGIN GENERATED by tools/kani/gen-shapes.py; do not edit by hand.
round_trip_shape!(wire_round_trip_p0, 0);
round_trip_shape!(wire_round_trip_p1, 1);
round_trip_shape!(wire_round_trip_p2, 2);
round_trip_shape!(wire_round_trip_p3, 3);
round_trip_shape!(wire_round_trip_p4, 4);
round_trip_shape!(wire_round_trip_p5, 5);
round_trip_shape!(wire_round_trip_p6, 6);
round_trip_shape!(wire_round_trip_p7, 7);
round_trip_shape!(wire_round_trip_p8, 8);
round_trip_shape!(wire_round_trip_p9, 9);
round_trip_shape!(wire_round_trip_p10, 10);
round_trip_shape!(wire_round_trip_p11, 11);
round_trip_shape!(wire_round_trip_p12, 12);
round_trip_shape!(wire_round_trip_p13, 13);
round_trip_shape!(wire_round_trip_p14, 14);
round_trip_shape!(wire_round_trip_p15, 15);
round_trip_shape!(wire_round_trip_p16, 16);
// END GENERATED

/// P2: exhaustive over the 7 header bytes (all 2^56 values, symbolically),
/// every expected type and payloads of length <= HEADER_REJECT_MAX_PAYLOAD:
/// if magic, version or type byte differs from the canonical header for the
/// expected type, `decode` returns an error; if all three match, it succeeds
/// (whatever the suite byte).
#[kani::proof]
#[kani::unwind(12)]
fn wire_header_rejection() {
    let header: [u8; HEADER_LEN] = kani::any();
    let tail: [u8; HEADER_REJECT_MAX_PAYLOAD] = kani::any();
    let tail_len: usize = kani::any();
    kani::assume(tail_len <= HEADER_REJECT_MAX_PAYLOAD);
    let expected = any_object_type();

    let mut input = [0u8; HEADER_LEN + HEADER_REJECT_MAX_PAYLOAD];
    input[..HEADER_LEN].copy_from_slice(&header);
    input[HEADER_LEN..].copy_from_slice(&tail);
    let input = &input[..HEADER_LEN + tail_len];

    let canonical = header[..4] == MAGIC && header[4] == VERSION && header[5] == expected.as_u8();
    let res = wire::decode(input, expected);
    assert!(res.is_ok() == canonical);
}
