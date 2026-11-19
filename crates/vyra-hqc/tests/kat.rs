//! Official HQC v5.1 known-answer tests (reference tag `v5.1.0`, commit
//! 06567ccbad10580d78dd7863b15d23f41076d57f, `kats/ref/hqc-{1,3,5}/PQCkemKAT_32.rsp`).
//!
//! The implementation is driven exactly as the reference KAT generator
//! (`packaging/utils/helpers/main_kat.c`, linked with `lib/nist-rng/rng.c`):
//! the NIST AES-256 CTR DRBG is instantiated with the bytes 0..47 and draws
//! the 100 48-byte seeds; for each count it is re-instantiated with that seed,
//! key generation draws `seed_kem` with one `randombytes(32)` call and
//! encapsulation draws `m` and `salt` with two calls (`k` and 16 bytes). The
//! reference generator then decapsulates and requires the same secret; so do
//! these tests.
//!
//! Embedded data (see `tests/data/PROVENANCE.md`): for every count 0..99 the
//! seed, the exact `sk` and `ss`, and SHA3-256 of `pk` and `ct`; for counts 0..4
//! the official file itself (a byte-exact prefix, pinned by SHA-256).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    missing_docs
)]

use aes::Aes256;
use aes::cipher::{BlockCipherEncrypt, KeyInit};
use core::convert::Infallible;
use rand_core::{TryCryptoRng, TryRng};
use sha2::Sha256;
use sha3::{Digest, Sha3_256};
use vyra_hqc::{HqcKem, HqcParams};

// ---------------------------------------------------------------------------
// NIST AES-256 CTR DRBG (lib/nist-rng/rng.c of the reference repository)
// ---------------------------------------------------------------------------

/// The NIST KAT DRBG. Each `fill_bytes` call is one `randombytes` call: the
/// state update after every call makes the call boundaries significant.
struct NistDrbg {
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
    let cipher = Aes256::new_from_slice(key).unwrap();
    let mut block = aes::Block::from(*input);
    cipher.encrypt_block(&mut block);
    block.into()
}

impl NistDrbg {
    /// `randombytes_init(entropy_input, NULL, 256)`.
    fn new(entropy: &[u8; 48]) -> Self {
        let mut d = NistDrbg {
            key: [0; 32],
            v: [0; 16],
        };
        d.update(Some(entropy));
        d
    }

    /// `AES256_CTR_DRBG_Update`.
    fn update(&mut self, provided: Option<&[u8; 48]>) {
        let mut temp = [0u8; 48];
        for i in 0..3 {
            increment(&mut self.v);
            temp[16 * i..16 * i + 16].copy_from_slice(&aes256_ecb(&self.key, &self.v));
        }
        if let Some(p) = provided {
            for (t, x) in temp.iter_mut().zip(p) {
                *t ^= x;
            }
        }
        self.key.copy_from_slice(&temp[..32]);
        self.v.copy_from_slice(&temp[32..]);
    }

    /// `randombytes(x, xlen)`.
    fn randombytes(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(16) {
            increment(&mut self.v);
            let block = aes256_ecb(&self.key, &self.v);
            chunk.copy_from_slice(&block[..chunk.len()]);
        }
        self.update(None);
    }
}

impl TryRng for NistDrbg {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut b = [0u8; 4];
        self.randombytes(&mut b);
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut b = [0u8; 8];
        self.randombytes(&mut b);
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        self.randombytes(dst);
        Ok(())
    }
}

impl TryCryptoRng for NistDrbg {}

// ---------------------------------------------------------------------------
// Embedded vectors
// ---------------------------------------------------------------------------

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn sha3_hex(b: &[u8]) -> String {
    hex(&Sha3_256::digest(b))
}

/// One count: what the official file says.
#[derive(Clone)]
struct Expected {
    count: usize,
    seed: Vec<u8>,
    sk: Vec<u8>,
    pk_sha3: String,
    ct_sha3: String,
    ss: Vec<u8>,
    /// Full values, present for counts 0..4.
    full: Option<(Vec<u8>, Vec<u8>)>,
}

fn parse_digests(data: &str) -> Vec<Expected> {
    data.lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .map(|l| {
            let f: Vec<&str> = l.split(' ').collect();
            assert_eq!(f.len(), 6, "{l}");
            Expected {
                count: f[0].parse().unwrap(),
                seed: unhex(f[1]),
                sk: unhex(f[2]),
                pk_sha3: f[3].to_string(),
                ct_sha3: f[4].to_string(),
                ss: unhex(f[5]),
                full: None,
            }
        })
        .collect()
}

/// One full `.rsp` record: count, seed, pk, sk, ct, ss.
type RspRecord = (usize, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

/// Parse the official `.rsp` format (byte-exact prefix with counts 0..4).
fn parse_rsp(data: &str) -> Vec<RspRecord> {
    let mut out = Vec::new();
    for rec in data.split("\n\n").filter(|r| r.starts_with("count = ")) {
        let get = |k: &str| {
            rec.lines()
                .find_map(|l| l.strip_prefix(&format!("{k} = ")))
                .unwrap_or_else(|| panic!("{k} missing"))
        };
        out.push((
            get("count").parse().unwrap(),
            unhex(get("seed")),
            unhex(get("pk")),
            unhex(get("sk")),
            unhex(get("ct")),
            unhex(get("ss")),
        ));
    }
    out
}

struct KatSet {
    name: &'static str,
    digests: &'static str,
    rsp: &'static str,
    rsp_sha256: &'static str,
}

const HQC1: KatSet = KatSet {
    name: "HQC-1",
    digests: include_str!("data/hqc-1/kat-digests.txt"),
    rsp: include_str!("data/hqc-1/PQCkemKAT_32.counts0-4.rsp"),
    rsp_sha256: "f6cf24bdb6dac8d134482bb27450c671bd09733b9b8b5a264ef2c0c16eec868e",
};

const HQC3: KatSet = KatSet {
    name: "HQC-3",
    digests: include_str!("data/hqc-3/kat-digests.txt"),
    rsp: include_str!("data/hqc-3/PQCkemKAT_32.counts0-4.rsp"),
    rsp_sha256: "f5715d70288e767c990b09ac9549bf9e6eb77cdf68d399ad43f8376da184752a",
};

const HQC5: KatSet = KatSet {
    name: "HQC-5",
    digests: include_str!("data/hqc-5/kat-digests.txt"),
    rsp: include_str!("data/hqc-5/PQCkemKAT_32.counts0-4.rsp"),
    rsp_sha256: "da8a22b1ef96328b0cefe8116e74bac2c04f519a65931c91f8090f703ff70ef1",
};

/// All 100 expected records, with the full values of counts 0..4 attached
/// (after checking that both embedded files agree on them).
fn load(set: &KatSet) -> Vec<Expected> {
    assert_eq!(
        hex(&Sha256::digest(set.rsp.as_bytes())),
        set.rsp_sha256,
        "{}: embedded .rsp prefix differs from the official bytes",
        set.name
    );
    assert!(set.rsp.starts_with(&format!("# {}\n\n", set.name)));
    let mut exp = parse_digests(set.digests);
    assert_eq!(exp.len(), 100, "{}", set.name);
    for (i, e) in exp.iter().enumerate() {
        assert_eq!(e.count, i);
    }
    let full = parse_rsp(set.rsp);
    assert_eq!(full.len(), 5, "{}", set.name);
    for (count, seed, pk, sk, ct, ss) in full {
        let e = &mut exp[count];
        assert_eq!(e.seed, seed);
        assert_eq!(e.sk, sk);
        assert_eq!(e.ss, ss);
        assert_eq!(e.pk_sha3, sha3_hex(&pk));
        assert_eq!(e.ct_sha3, sha3_hex(&ct));
        e.full = Some((pk, ct));
    }
    exp
}

// ---------------------------------------------------------------------------
// The check
// ---------------------------------------------------------------------------

/// Run one count exactly as `main_kat.c` does and compare every field.
/// Returns the first mismatch.
fn check_count<P: HqcParams>(e: &Expected) -> Result<(), String> {
    let mut drbg = NistDrbg::new(e.seed.as_slice().try_into().unwrap());
    let (ek, dk) = HqcKem::<P>::generate_key(&mut drbg);
    let (ct, ss) = ek.encapsulate(&mut drbg);
    let c = e.count;
    if let Some((pk_full, ct_full)) = &e.full {
        if ek.as_ref() != pk_full.as_slice() {
            return Err(format!("count {c}: pk"));
        }
        if ct.as_ref() != ct_full.as_slice() {
            return Err(format!("count {c}: ct"));
        }
    }
    if sha3_hex(ek.as_ref()) != e.pk_sha3 {
        return Err(format!("count {c}: pk digest"));
    }
    if dk.as_ref() != e.sk.as_slice() {
        return Err(format!("count {c}: sk"));
    }
    if sha3_hex(ct.as_ref()) != e.ct_sha3 {
        return Err(format!("count {c}: ct digest"));
    }
    if ss.as_ref() != e.ss.as_slice() {
        return Err(format!("count {c}: ss"));
    }
    // As in the reference generator: decapsulation returns the same secret.
    if dk.decapsulate(&ct).as_ref() != e.ss.as_slice() {
        return Err(format!("count {c}: decapsulation"));
    }
    // The single-pass entry point returns the same secret and the same
    // encapsulation key.
    let seed: [u8; 32] = dk.as_ref().try_into().unwrap();
    let (ss1, ek1) = HqcKem::<P>::decapsulate_from_seed(&seed, &ct);
    if ss1.as_ref() != e.ss.as_slice() || ek1 != ek {
        return Err(format!("count {c}: decapsulate_from_seed"));
    }
    Ok(())
}

/// The DRBG reproduces the 100 seeds of the official file from the entropy
/// input 0, 1, ..., 47 (validates the DRBG port itself).
fn check_seeds(exp: &[Expected]) {
    let entropy: [u8; 48] = core::array::from_fn(|i| i as u8);
    let mut drbg = NistDrbg::new(&entropy);
    for e in exp {
        let mut seed = [0u8; 48];
        drbg.randombytes(&mut seed);
        assert_eq!(seed.as_slice(), e.seed.as_slice(), "seed {}", e.count);
    }
}

fn run<P: HqcParams>(set: &KatSet) {
    let exp = load(set);
    check_seeds(&exp);
    let mut passed = 0;
    for e in &exp {
        if let Err(msg) = check_count::<P>(e) {
            panic!("{} KAT mismatch: {msg}", set.name);
        }
        passed += 1;
    }
    assert_eq!(passed, 100);
    println!(
        "{}: {passed}/100 official KAT counts match (pk, sk, ct, ss, decaps)",
        set.name
    );
}

#[test]
fn kat_hqc1_all_100() {
    run::<vyra_hqc::Hqc128Params>(&HQC1);
}

#[test]
fn kat_hqc3_all_100() {
    run::<vyra_hqc::Hqc192Params>(&HQC3);
}

#[test]
fn kat_hqc5_all_100() {
    run::<vyra_hqc::Hqc256Params>(&HQC5);
}

/// Negative control: the check reports a mismatch when one expected byte of
/// any field is wrong, so the KAT tests above can fail.
#[test]
fn kat_negative_control_detects_one_flipped_byte() {
    let exp = load(&HQC1);
    let good = &exp[0];
    assert_eq!(check_count::<vyra_hqc::Hqc128Params>(good), Ok(()));

    let mut bad = good.clone();
    if let Some((pk, _)) = bad.full.as_mut() {
        pk[100] ^= 0x01;
    }
    assert_eq!(
        check_count::<vyra_hqc::Hqc128Params>(&bad),
        Err("count 0: pk".to_string())
    );

    let mut bad = good.clone();
    bad.sk[0] ^= 0x80;
    assert_eq!(
        check_count::<vyra_hqc::Hqc128Params>(&bad),
        Err("count 0: sk".to_string())
    );

    let mut bad = good.clone();
    bad.full = None;
    bad.ss[31] ^= 0x01;
    assert_eq!(
        check_count::<vyra_hqc::Hqc128Params>(&bad),
        Err("count 0: ss".to_string())
    );

    let mut bad = good.clone();
    bad.full = None;
    bad.ct_sha3.replace_range(
        0..1,
        if bad.ct_sha3.starts_with('0') {
            "1"
        } else {
            "0"
        },
    );
    assert_eq!(
        check_count::<vyra_hqc::Hqc128Params>(&bad),
        Err("count 0: ct digest".to_string())
    );
}
