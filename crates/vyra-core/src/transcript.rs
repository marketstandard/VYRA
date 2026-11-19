//! Domain-separated, injectively framed hashing.
//!
//! [`Transcript`] is the only hashing entry point VYRA-original constructions
//! use. Every input — the label and each appended field — is framed as
//!
//! ```text
//! frame(x) = u64_be(len(x)) || x
//! ```
//!
//! so the concatenation of frames is injective: no two different field
//! sequences produce the same byte string.
//!
//! Outputs:
//!
//! ```text
//! finalize()      = SHA3-256(        frame(label) || frame(f1) || ... || frame(fn) )
//! finalize_xof(_) = SHAKE256( 0x01 || frame(label) || frame(f1) || ... || frame(fn) )
//! ```
//!
//! The fixed-output form has no prefix byte, so it computes exactly the
//! framed encoding used by the hybrid KEM combiner in docs/DECISIONS.md D-01.
//! The XOF form prepends the domain byte [`XOF_DOMAIN`]; together with the
//! different SHA3/SHAKE padding this keeps the two outputs unrelated.

use core::fmt;

use sha3::{Digest, Sha3_256};
use shake::{ExtendableOutput, Shake256, Shake256Reader, Update, XofReader};

/// Domain byte absorbed by the SHAKE256 side before the framed stream.
pub const XOF_DOMAIN: u8 = 0x01;

/// Width in bytes of the length prefix in `frame(x) = u64_be(len(x)) || x`.
pub const FRAME_PREFIX_LEN: usize = 8;

/// The length prefix of `frame(bytes)`: `u64_be(len(bytes))`.
///
/// [`Transcript`] absorbs exactly this prefix followed by `bytes` for the
/// label and for every field.
pub const fn frame_prefix(bytes: &[u8]) -> [u8; FRAME_PREFIX_LEN] {
    frame_prefix_of_len(bytes.len())
}

/// The length prefix for an input of `len` bytes: `u64_be(len)`.
///
/// Separated from [`frame_prefix`] so the prefix arithmetic can be checked
/// for every `usize` length without materialising an input of that length.
pub const fn frame_prefix_of_len(len: usize) -> [u8; FRAME_PREFIX_LEN] {
    // usize -> u64 is lossless on every target Rust supports.
    (len as u64).to_be_bytes()
}

/// Append `frame(bytes) = u64_be(len(bytes)) || bytes` to `out`.
pub fn push_frame(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&frame_prefix(bytes));
    out.extend_from_slice(bytes);
}

/// The exact byte string a [`Transcript`] with this `label` and these
/// `fields` feeds to SHA3-256 in [`Transcript::finalize`]:
///
/// ```text
/// frame(label) || frame(fields[0]) || ... || frame(fields[n-1])
/// ```
///
/// ([`Transcript::finalize_xof`] absorbs [`XOF_DOMAIN`] followed by the same
/// bytes.) This is a pure function with no hashing, so properties of the
/// framing (such as injectivity) can be checked on it directly.
pub fn framed_encoding(label: &[u8], fields: &[&[u8]]) -> Vec<u8> {
    let total = fields
        .iter()
        .fold(FRAME_PREFIX_LEN.saturating_add(label.len()), |acc, f| {
            acc.saturating_add(FRAME_PREFIX_LEN).saturating_add(f.len())
        });
    let mut out = Vec::with_capacity(total);
    push_frame(&mut out, label);
    for f in fields {
        push_frame(&mut out, f);
    }
    out
}

/// An incremental, framed hash transcript. See the [module docs](self) for the
/// exact encoding.
///
/// Internal hash state is zeroized on drop.
#[derive(Clone)]
pub struct Transcript {
    hash: Sha3_256,
    xof: Shake256,
}

impl Transcript {
    /// Start a transcript with a domain-separation `label`.
    pub fn new(label: &'static [u8]) -> Self {
        let mut xof = Shake256::default();
        Update::update(&mut xof, &[XOF_DOMAIN]);
        let mut t = Transcript {
            hash: Sha3_256::new(),
            xof,
        };
        t.absorb_framed(label);
        t
    }

    /// Append one field, framed as `u64_be(len) || field`.
    pub fn append(&mut self, field: &[u8]) -> &mut Self {
        self.absorb_framed(field);
        self
    }

    fn absorb_framed(&mut self, bytes: &[u8]) {
        let len = frame_prefix(bytes);
        Digest::update(&mut self.hash, len);
        Digest::update(&mut self.hash, bytes);
        Update::update(&mut self.xof, &len);
        Update::update(&mut self.xof, bytes);
    }

    /// SHA3-256 of the framed transcript.
    pub fn finalize(self) -> [u8; 32] {
        self.hash.finalize().into()
    }

    /// Fill `out` with SHAKE256 output of `XOF_DOMAIN || framed transcript`.
    pub fn finalize_xof(self, out: &mut [u8]) {
        self.into_xof_reader().read(out);
    }

    /// The SHAKE256 output stream, for callers inside this crate that need
    /// to read it incrementally.
    pub(crate) fn into_xof_reader(self) -> Shake256Reader {
        self.xof.finalize_xof()
    }
}

impl fmt::Debug for Transcript {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Transcript { .. }")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_xof_differ() {
        let mut a = Transcript::new(b"t");
        a.append(b"x");
        let b = a.clone();
        let h = a.finalize();
        let mut x = [0u8; 32];
        b.finalize_xof(&mut x);
        assert_ne!(h, x);
    }

    /// Ties the pure [`framed_encoding`] (the function the bounded model
    /// checking harnesses reason about) to what [`Transcript`] actually hashes:
    /// for every case, `finalize` equals SHA3-256 of the pure encoding and
    /// `finalize_xof` equals SHAKE256 of `XOF_DOMAIN || encoding`.
    #[test]
    fn transcript_hashes_exactly_framed_encoding() {
        let long = [0xA5u8; 300];
        let labels: [&'static [u8]; 3] = [b"", b"L", b"VYRA-KEM-v1"];
        let field_sets: [&[&[u8]]; 6] = [
            &[],
            &[b""],
            &[b"", b""],
            &[b"ab", b"c"],
            &[b"a", b"bc"],
            &[&long, b"x", b"", &[0, 0, 0, 0, 0, 0, 0, 1]],
        ];
        for label in labels {
            for fields in field_sets {
                let mut t = Transcript::new(label);
                for f in fields {
                    t.append(f);
                }
                let enc = framed_encoding(label, fields);

                let expected_hash: [u8; 32] = Sha3_256::digest(&enc).into();
                assert_eq!(t.clone().finalize(), expected_hash);

                let mut x = Shake256::default();
                Update::update(&mut x, &[XOF_DOMAIN]);
                Update::update(&mut x, &enc);
                let mut expected_xof = [0u8; 80];
                x.finalize_xof().read(&mut expected_xof);
                let mut got_xof = [0u8; 80];
                t.finalize_xof(&mut got_xof);
                assert_eq!(got_xof, expected_xof);
            }
        }
    }

    #[test]
    fn frame_prefix_of_len_is_u64_be() {
        assert_eq!(frame_prefix_of_len(0), [0; 8]);
        assert_eq!(frame_prefix_of_len(256), [0, 0, 0, 0, 0, 0, 1, 0]);
        assert_eq!(
            frame_prefix_of_len(usize::MAX),
            (usize::MAX as u64).to_be_bytes()
        );
        assert_eq!(frame_prefix(&[7u8; 300]), frame_prefix_of_len(300));
    }

    #[test]
    fn framed_encoding_layout() {
        let enc = framed_encoding(b"L", &[b"", b"xy"]);
        let mut expected = Vec::new();
        expected.extend_from_slice(&1u64.to_be_bytes());
        expected.push(b'L');
        expected.extend_from_slice(&0u64.to_be_bytes());
        expected.extend_from_slice(&2u64.to_be_bytes());
        expected.extend_from_slice(b"xy");
        assert_eq!(enc, expected);
    }
}
