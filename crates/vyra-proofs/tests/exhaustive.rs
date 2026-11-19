//! Exhaustive enumeration checks of the P1-P5 properties over small, exactly
//! stated finite domains. These run on any host with plain `cargo test`
//! (no model checker needed). Each test checks EVERY element of its domain,
//! never a random sample; the domain is stated in the test's doc comment and
//! nothing outside it is covered.
//!
//! They complement the Kani harnesses in `src/` (which cover larger,
//! symbolic domains but need a Linux model checker).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::cell::Cell;
use std::collections::HashMap;

use vyra_core::rand_core::TryRng;
use vyra_core::transcript::framed_encoding;
use vyra_core::wire::{self, HEADER_LEN, MAGIC, ObjectType, Reader, VERSION};
use vyra_core::{EntropySource, Error, RandCoreRng, Result, SecretBytes};
use vyra_proofs::reference::{parse_framed, parse_sig_representative};

const ALL_TYPES: [ObjectType; 7] = [
    ObjectType::KemPublicKey,
    ObjectType::KemSecretKey,
    ObjectType::KemCiphertext,
    ObjectType::SigPublicKey,
    ObjectType::SigSecretKey,
    ObjectType::Signature,
    ObjectType::SealedBox,
];

/// Reference specification of `wire::decode` (docs/SPEC.md §5).
fn decode_spec(input: &[u8], t: ObjectType) -> std::result::Result<(u8, &[u8]), &'static str> {
    if input.len() < HEADER_LEN {
        return Err("length");
    }
    if input[..4] == MAGIC && input[4] == VERSION && input[5] == t.as_u8() {
        Ok((input[6], &input[HEADER_LEN..]))
    } else {
        Err("encoding")
    }
}

fn check_decode(input: &[u8], t: ObjectType) {
    let got = wire::decode(input, t);
    match (decode_spec(input, t), got) {
        (Ok((s, p)), Ok((gs, gp))) => {
            assert_eq!(s, gs);
            assert!(is_sub(gp, input, HEADER_LEN, p.len()));
        }
        (Err("length"), Err(e)) => assert_eq!(
            e,
            Error::InvalidLength {
                what: "wire header",
                expected: HEADER_LEN,
                actual: input.len()
            }
        ),
        (Err(_), Err(Error::InvalidEncoding(_))) => {}
        (spec, got) => panic!("decode mismatch on {input:?} / {t:?}: spec {spec:?}, got {got:?}"),
    }
}

/// P1/P2, exhaustive domain (all 7 expected types in every case):
/// (a) every byte string of length 0, 1 and 2 (65,793 strings);
/// (b) every input of length 7 and 8 whose 7-byte header differs from the
///     canonical header `"VYRA" 01 <type> 05` in at most two positions, each
///     deviating position taking all 256 values (21 position pairs x 65,536
///     values; the 8th byte, when present, is 0xAB).
/// Checked against a reference decoder: exact success condition, exact
/// suite byte, exact payload subslice, exact error class.
#[test]
fn decode_matches_spec_exhaustive() {
    for t in ALL_TYPES {
        check_decode(&[], t);
        for a in 0..=255u8 {
            check_decode(&[a], t);
            for b in 0..=255u8 {
                check_decode(&[a, b], t);
            }
        }
    }
    for t in ALL_TYPES {
        let canon = [
            MAGIC[0],
            MAGIC[1],
            MAGIC[2],
            MAGIC[3],
            VERSION,
            t.as_u8(),
            5,
        ];
        for i in 0..HEADER_LEN {
            for j in (i + 1)..HEADER_LEN {
                for vi in 0..=255u8 {
                    for vj in 0..=255u8 {
                        let mut buf = [0u8; 8];
                        buf[..7].copy_from_slice(&canon);
                        buf[7] = 0xAB;
                        buf[i] = vi;
                        buf[j] = vj;
                        for expected in ALL_TYPES {
                            check_decode(&buf[..7], expected);
                            check_decode(&buf, expected);
                        }
                    }
                }
            }
        }
    }
}

/// `s` is exactly `whole[start..start + len]`: same length and, when
/// non-empty, the same address. (An empty slice addresses no bytes; `Reader`
/// may legitimately hand out a dangling empty slice after `rest()`.)
fn is_sub(s: &[u8], whole: &[u8], start: usize, len: usize) -> bool {
    s.len() == len && (len == 0 || core::ptr::eq(s.as_ptr(), whole[start..].as_ptr()))
}

#[derive(Clone, Copy, Debug)]
enum Op {
    Take(usize),
    Remaining,
    Rest,
}

const OPS: [Op; 14] = [
    Op::Take(0),
    Op::Take(1),
    Op::Take(2),
    Op::Take(3),
    Op::Take(4),
    Op::Take(5),
    Op::Take(6),
    Op::Take(7),
    Op::Take(8),
    Op::Take(9),
    Op::Take(usize::MAX),
    Op::Take(usize::MAX - 1),
    Op::Remaining,
    Op::Rest,
];

/// P1 (Reader), exhaustive domain: input lengths 0..=8 and every sequence of
/// exactly 4 operations drawn from {take(0..=9), take(usize::MAX),
/// take(usize::MAX - 1), remaining(), rest()} (14^4 = 38,416 sequences per
/// length; shorter sequences are prefixes and are checked at every step).
/// After every step, `finish()` on a clone succeeds iff all bytes were
/// consumed; `take` returns exactly the next n bytes or the exact error.
#[test]
fn reader_matches_model_exhaustive() {
    let buf = [0x5Au8; 8];
    for len in 0..=8usize {
        let input = &buf[..len];
        for code in 0..OPS.len().pow(4) {
            let mut r = Reader::new(input);
            let mut consumed = 0usize;
            let mut c = code;
            for _ in 0..4 {
                let op = OPS[c % OPS.len()];
                c /= OPS.len();
                let left = len - consumed;
                match op {
                    Op::Take(n) => match r.take(n, "f") {
                        Ok(h) => {
                            assert!(n <= left, "{op:?} len {len} consumed {consumed}");
                            assert!(is_sub(h, input, consumed, n));
                            consumed += n;
                        }
                        Err(e) => {
                            assert!(n > left, "{op:?} len {len} consumed {consumed}");
                            assert_eq!(
                                e,
                                Error::InvalidLength {
                                    what: "f",
                                    expected: n,
                                    actual: left
                                }
                            );
                        }
                    },
                    Op::Remaining => assert_eq!(r.remaining(), left),
                    Op::Rest => {
                        let rest = r.rest();
                        assert!(is_sub(rest, input, consumed, left));
                        consumed = len;
                    }
                }
                assert_eq!(r.remaining(), len - consumed);
                assert_eq!(r.clone().finish().is_ok(), consumed == len);
            }
        }
    }
}

/// P2, exhaustive domain: every encoded type t, every expected type u (49
/// pairs), every suite byte (256), every payload of length 0 or 1 (257):
/// 3,223,808 cases. `encode` gives exactly `"VYRA" 01 t suite payload` and
/// `decode(encode(t, suite, p), u) == Ok((suite, p))` iff `t == u`.
#[test]
fn round_trip_exhaustive() {
    let mut payloads: Vec<Vec<u8>> = vec![vec![]];
    payloads.extend((0..=255u8).map(|b| vec![b]));
    for t in ALL_TYPES {
        for suite in 0..=255u8 {
            for p in &payloads {
                let enc = wire::encode(t, suite, p);
                let mut expected = vec![MAGIC[0], MAGIC[1], MAGIC[2], MAGIC[3], VERSION];
                expected.push(t.as_u8());
                expected.push(suite);
                expected.extend_from_slice(p);
                assert_eq!(enc, expected);
                for u in ALL_TYPES {
                    let got = wire::decode(&enc, u);
                    if t == u {
                        assert_eq!(got, Ok((suite, p.as_slice())));
                    } else {
                        assert_eq!(got, Err(Error::InvalidEncoding("unexpected object type")));
                    }
                }
            }
        }
    }
}

/// All byte strings over `alphabet` with length `0..=max_len`.
fn strings(alphabet: &[u8], max_len: usize) -> Vec<Vec<u8>> {
    let mut out = vec![vec![]];
    let mut layer = vec![vec![]];
    for _ in 0..max_len {
        let mut next = Vec::new();
        for s in &layer {
            for &a in alphabet {
                let mut t: Vec<u8> = s.clone();
                t.push(a);
                next.push(t);
            }
        }
        out.extend(next.iter().cloned());
        layer = next;
    }
    out
}

/// Insert every (label, fields) in the domain into a map keyed by the
/// encoding; a second, different sequence with the same encoding is a
/// collision. Returns the number of sequences checked.
fn check_injective(labels: &[Vec<u8>], field_values: &[Vec<u8>], max_fields: usize) -> usize {
    let mut seqs: Vec<Vec<usize>> = vec![vec![]];
    let mut layer: Vec<Vec<usize>> = vec![vec![]];
    for _ in 0..max_fields {
        let mut next = Vec::new();
        for s in &layer {
            for i in 0..field_values.len() {
                let mut t = s.clone();
                t.push(i);
                next.push(t);
            }
        }
        seqs.extend(next.iter().cloned());
        layer = next;
    }
    let mut seen: HashMap<Vec<u8>, (usize, usize)> = HashMap::new();
    let mut count = 0usize;
    for (li, label) in labels.iter().enumerate() {
        for (si, seq) in seqs.iter().enumerate() {
            let fields: Vec<&[u8]> = seq.iter().map(|&i| field_values[i].as_slice()).collect();
            let enc = framed_encoding(label, &fields);
            // The reference decoder is a left inverse on this domain too.
            assert_eq!(parse_framed(&enc), Some((label.as_slice(), fields.clone())));
            if let Some(&(pl, ps)) = seen.get(&enc) {
                panic!(
                    "framing collision: ({:?}, {:?}) vs ({:?}, {:?})",
                    labels[pl], seqs[ps], label, seq
                );
            }
            seen.insert(enc, (li, si));
            count += 1;
        }
    }
    count
}

/// P3, exhaustive domain A (all byte values): label of length 0 or 1 (257
/// labels) x sequences of 0..=1 fields, each of length 0..=1 (258 sequences):
/// 66,306 sequences, pairwise distinct encodings.
///
/// Domain B (structured alphabet {0x00, 0x01, 0x02, 0x08, 0xFF}, chosen to
/// include bytes that equal small length-prefix bytes): label length 0..=2
/// (31 labels) x 0..=3 fields, each of length 0..=2 (31 values; 30,784
/// sequences): 954,304 sequences, pairwise distinct encodings.
///
/// NOT covered: SHA-3; any label, field or field count outside these domains.
#[test]
fn framing_injective_exhaustive() {
    let all: Vec<u8> = (0..=255u8).collect();
    let a_labels = strings(&all, 1);
    let a_fields = strings(&all, 1);
    assert_eq!(check_injective(&a_labels, &a_fields, 1), 257 * 258);

    let alphabet = [0x00, 0x01, 0x02, 0x08, 0xFF];
    let b = strings(&alphabet, 2);
    assert_eq!(b.len(), 31);
    assert_eq!(
        check_injective(&b, &b, 3),
        31 * (1 + 31 + 31 * 31 + 31 * 31 * 31)
    );
}

/// P4, exhaustive domain: every pair (a, b) with len(a), len(b) <= 1 over all
/// byte values (66,049 pairs), and every pair of strings of length 0..=2 over
/// the 16-value alphabet {0x00..0x07, 0x80..0x87} (273^2 = 74,529 pairs):
/// `ct_eq` == byte equality, in both argument orders. Timing NOT covered.
#[test]
fn ct_eq_exhaustive() {
    let all: Vec<u8> = (0..=255u8).collect();
    let alphabet: Vec<u8> = (0x00..0x08u8).chain(0x80..0x88u8).collect();
    for set in [strings(&all, 1), strings(&alphabet, 2)] {
        let secrets: Vec<SecretBytes> = set.iter().map(|s| SecretBytes::from_slice(s)).collect();
        for (i, a) in set.iter().enumerate() {
            for (j, b) in set.iter().enumerate() {
                assert_eq!(secrets[i].ct_eq(&secrets[j]), a == b);
            }
        }
    }
}

/// Scripted entropy source: call k succeeds iff bit k of `pattern` is 0;
/// writes a call-dependent non-zero byte pattern in both cases.
struct Scripted<'o> {
    pattern: u32,
    calls: &'o Cell<u32>,
    failed: &'o Cell<bool>,
    last: &'o Cell<[u8; 8]>,
}

impl EntropySource for Scripted<'_> {
    fn fill(&mut self, dest: &mut [u8]) -> Result<()> {
        assert!(!self.failed.get(), "source called after a failure");
        let k = self.calls.get();
        self.calls.set(k + 1);
        let mut w = [0u8; 8];
        for (i, (d, wi)) in dest.iter_mut().zip(w.iter_mut()).enumerate() {
            *d = 0x11u8.wrapping_mul(k as u8 + 1).wrapping_add(i as u8) | 1;
            *wi = *d;
        }
        if (self.pattern >> k) & 1 == 0 {
            self.last.set(w);
            Ok(())
        } else {
            self.failed.set(true);
            Err(Error::EntropyFailure)
        }
    }
}

/// P5, exhaustive domain: every sequence of exactly 4 adapter calls drawn
/// from {next_u32, next_u64, fill_bytes(len 0..=3), fill_bytes(len 8)} (7^4 =
/// 2,401 sequences) x every success/failure pattern of the first 4 source
/// calls (16): before a failure outputs equal the source bytes; from the
/// failing call on every output is zero (prior buffer contents 0xEE) and the
/// source is not called again; `finish()` fails iff a source call failed.
#[test]
fn rng_adapter_exhaustive() {
    const FILLS: [usize; 5] = [0, 1, 2, 3, 8];
    for pattern in 0..16u32 {
        for code in 0..7usize.pow(4) {
            let calls = Cell::new(0);
            let failed = Cell::new(false);
            let last = Cell::new([0u8; 8]);
            let mut src = Scripted {
                pattern,
                calls: &calls,
                failed: &failed,
                last: &last,
            };
            let mut rng = RandCoreRng::new(&mut src);
            let mut c = code;
            for _ in 0..4 {
                let op = c % 7;
                c /= 7;
                let out: Vec<u8> = match op {
                    0 => rng.try_next_u32().unwrap().to_le_bytes().to_vec(),
                    1 => rng.try_next_u64().unwrap().to_le_bytes().to_vec(),
                    k => {
                        let mut b = vec![0xEEu8; FILLS[k - 2]];
                        rng.try_fill_bytes(&mut b).unwrap();
                        b
                    }
                };
                if failed.get() {
                    assert!(out.iter().all(|&b| b == 0), "pattern {pattern} code {code}");
                } else {
                    assert_eq!(out.as_slice(), &last.get()[..out.len()]);
                }
            }
            let fin = rng.finish();
            assert_eq!(fin.is_err(), failed.get());
            if failed.get() {
                assert_eq!(fin, Err(Error::EntropyFailure));
            }
        }
    }
}

/// The reference signature-representative parser rejects every string that
/// is too short or has the wrong label, and splits a hand-built
/// representative correctly (all context lengths 0..=3 over a 4-byte tail).
#[test]
fn sig_reference_parser_sanity() {
    let mut base = b"VYRA-SIG-v1".to_vec();
    base.push(7);
    base.extend_from_slice(&[0xD5; 32]);
    for cut in 0..base.len() + 1 {
        assert_eq!(parse_sig_representative(&base[..cut]), None);
    }
    for ctx_len in 0..=3u8 {
        let mut m = base.clone();
        m.push(ctx_len);
        m.extend_from_slice(&[1, 2, 3]);
        let (s, d, c, msg) = parse_sig_representative(&m).unwrap();
        assert_eq!((s, d), (7, [0xD5; 32]));
        assert_eq!(c, &[1, 2, 3][..usize::from(ctx_len)]);
        assert_eq!(msg, &[1, 2, 3][usize::from(ctx_len)..]);
    }
    let mut bad = base.clone();
    bad[0] = b'X';
    bad.push(0);
    assert_eq!(parse_sig_representative(&bad), None);
}
