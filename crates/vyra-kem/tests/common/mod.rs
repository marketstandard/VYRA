//! Shared helpers for the vyra-kem integration tests.
#![allow(dead_code)]

use sha3::{Digest, Sha3_256};
use shake::{ExtendableOutput, Shake256, Shake256Reader, Update, XofReader};
use vyra_core::{EntropySource, Kem, Result};
use vyra_kem::{Hqc128, Hqc192, Hqc256, MlKem512, MlKem768, MlKem1024};

/// Decode lowercase/uppercase hex. Test fixture helper; returns `None` on bad input.
pub fn hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    s.as_bytes()
        .chunks(2)
        .map(|pair| {
            let txt = core::str::from_utf8(pair).ok()?;
            u8::from_str_radix(txt, 16).ok()
        })
        .collect()
}

/// Lowercase hex of `bytes`.
pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Lowercase hex of SHA3-256(`bytes`).
pub fn sha3_hex(bytes: &[u8]) -> String {
    to_hex(&Sha3_256::digest(bytes))
}

/// The NIST AES-256 CTR DRBG used by the HQC v5.1 reference KAT generator
/// (`lib/nist-rng/rng.c`, `randombytes_init(seed, NULL, 256)`). Every `fill`
/// is one `randombytes` call; the DRBG state update after each call makes the
/// request boundaries significant, so a KAT matches only if the adapter
/// draws exactly as the reference does (keygen: 32; encaps: k, then 16).
pub struct NistKatDrbg {
    key: [u8; 32],
    v: [u8; 16],
}

fn increment(v: &mut [u8; 16]) {
    for b in v.iter_mut().rev() {
        if *b == 0xff {
            *b = 0;
        } else {
            *b += 1;
            break;
        }
    }
}

fn aes256_ecb(key: &[u8; 32], input: &[u8; 16]) -> [u8; 16] {
    use aes::cipher::{BlockCipherEncrypt, KeyInit};
    let cipher = aes::Aes256::new(&(*key).into());
    let mut block = aes::Block::from(*input);
    cipher.encrypt_block(&mut block);
    block.into()
}

impl NistKatDrbg {
    /// `randombytes_init(entropy, NULL, 256)` with a 48-byte input.
    pub fn new(entropy: &[u8; 48]) -> Self {
        let mut d = NistKatDrbg {
            key: [0; 32],
            v: [0; 16],
        };
        d.update(Some(entropy));
        d
    }

    fn update(&mut self, provided: Option<&[u8; 48]>) {
        let mut temp = [0u8; 48];
        for chunk in temp.chunks_mut(16) {
            increment(&mut self.v);
            chunk.copy_from_slice(&aes256_ecb(&self.key, &self.v));
        }
        if let Some(p) = provided {
            for (t, x) in temp.iter_mut().zip(p) {
                *t ^= x;
            }
        }
        let (k, v) = temp.split_at(32);
        self.key.copy_from_slice(k);
        self.v.copy_from_slice(v);
    }
}

impl EntropySource for NistKatDrbg {
    fn fill(&mut self, dest: &mut [u8]) -> Result<()> {
        for chunk in dest.chunks_mut(16) {
            increment(&mut self.v);
            let block = aes256_ecb(&self.key, &self.v);
            if let Some(src) = block.get(..chunk.len()) {
                chunk.copy_from_slice(src);
            }
        }
        self.update(None);
        Ok(())
    }
}

/// The KAT byte stream of the pre-v5.1 HQC reference snapshot (161cd4f):
/// SHAKE256(seed ‖ 0x00). Kept only to show that its known answers are no
/// longer reproduced (`hqc_version_pin`).
pub struct ShakeKatStream {
    reader: Shake256Reader,
}

impl ShakeKatStream {
    pub fn new(seed: &[u8]) -> Self {
        let mut h = Shake256::default();
        h.update(seed);
        h.update(&[0x00]);
        ShakeKatStream {
            reader: h.finalize_xof(),
        }
    }
}

impl EntropySource for ShakeKatStream {
    fn fill(&mut self, dest: &mut [u8]) -> Result<()> {
        self.reader.read(dest);
        Ok(())
    }
}

/// Official HQC v5.1.0 known answers (all 100 counts per set), embedded in
/// vyra-hqc; see crates/vyra-hqc/tests/data/PROVENANCE.md.
pub const KAT_HQC1: &str = include_str!("../../../vyra-hqc/tests/data/hqc-1/kat-digests.txt");
pub const KAT_HQC3: &str = include_str!("../../../vyra-hqc/tests/data/hqc-3/kat-digests.txt");
pub const KAT_HQC5: &str = include_str!("../../../vyra-hqc/tests/data/hqc-5/kat-digests.txt");

/// One count: DRBG seed, exact sk and ss, SHA3-256 of pk and ct (hex).
pub struct KatDigest {
    pub count: usize,
    pub seed: [u8; 48],
    pub sk: String,
    pub pk_sha3: String,
    pub ct_sha3: String,
    pub ss: String,
}

/// Parse a `kat-digests.txt` file.
pub fn kat_digests(data: &str) -> Vec<KatDigest> {
    data.lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .filter_map(|l| {
            let f: Vec<&str> = l.split(' ').collect();
            let [count, seed, sk, pk_sha3, ct_sha3, ss] = f.as_slice() else {
                return None;
            };
            Some(KatDigest {
                count: count.parse().ok()?,
                seed: hex(seed)?.try_into().ok()?,
                sk: sk.to_string(),
                pk_sha3: pk_sha3.to_string(),
                ct_sha3: ct_sha3.to_string(),
                ss: ss.to_string(),
            })
        })
        .collect()
}

/// The six component KEMs, in suite order (ML-KEM, HQC per level).
pub fn components() -> Vec<Box<dyn Kem>> {
    vec![
        Box::new(MlKem512),
        Box::new(Hqc128),
        Box::new(MlKem768),
        Box::new(Hqc192),
        Box::new(MlKem1024),
        Box::new(Hqc256),
    ]
}

/// Flip bit `bit % 8` of byte `pos` in a copy of `bytes`.
pub fn flip(bytes: &[u8], pos: usize, bit: usize) -> Vec<u8> {
    let mut out = bytes.to_vec();
    if let Some(b) = out.get_mut(pos) {
        *b ^= 1u8 << (bit % 8);
    }
    out
}

/// `n` positions spread evenly over `0..len`, always including the first and last.
pub fn spread(len: usize, n: usize) -> Vec<usize> {
    if len == 0 || n == 0 {
        return Vec::new();
    }
    if n == 1 {
        return vec![0];
    }
    (0..n).map(|i| i * (len - 1) / (n - 1)).collect()
}
