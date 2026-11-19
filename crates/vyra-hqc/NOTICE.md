# NOTICE: vyra-hqc

## Origin and licence

`vyra-hqc` is derived from **`hqc-kem` 0.1.0-rc.0**:

- crates.io: <https://crates.io/crates/hqc-kem/0.1.0-rc.0> (published 2026-07-11)
- repository: <https://github.com/RustCrypto/KEMs>, directory `hqc-kem`, commit
  `1a50023ab1dcebaaf500646589c76a3f0efade1f` (from the package's
  `.cargo_vcs_info.json`)
- licence: `MIT OR Apache-2.0` (SPDX expression in the package's `Cargo.toml`).
  The package contains no `authors` field and no licence files; the RustCrypto
  KEMs repository's own licence files name the copyright holder as
  "RustCrypto Developers" (e.g. `ml-kem/LICENSE-MIT`: "Copyright (c) 2024-2026
  RustCrypto Developers").
- upstream `src/poly.rs` states that its accumulated Karatsuba multiplication is
  adapted from NicsTr/hqc-kem (MIT License, Copyright (c) 2026 Nics); that
  attribution is kept in the source.

Both licences permit modification and redistribution with notice. This crate is
distributed under the same terms, `MIT OR Apache-2.0`; see `LICENSE-MIT` and
`LICENSE-APACHE`. The upstream code comments and attributions are kept.

`hqc-kem` 0.1.0-rc.0 implements the HQC team's reference code between the
tagged v5.0.0 and v5.1.0 releases (its README cites commit `161cd4f`; that
object is not in the history of gitlab.com/pqc-hqc/hqc as fetched on
2026-11-18, but the KAT files it ships have the git blob ids of commit
`cefbc8c245d7bccfc6f04a014a3b9fb2afc19adf`, "Update sampling", 2026-02-10, the
first commit after v5.0.0 that changed them).

## Modifications by the VYRA authors (2026-11-18)

Modified to implement the **HQC specification version 5.1 (2026-11-09)**,
<https://pqc-hqc.org/doc/hqc_specifications_v5.1.pdf>, and the reference
implementation at tag **`v5.1.0`** (commit
`06567ccbad10580d78dd7863b15d23f41076d57f`, <https://gitlab.com/pqc-hqc/hqc>),
whose known-answer files are reproduced for all 100 counts of each parameter
set (`tests/kat.rs`). HQC is not a published NIST standard yet (FIPS 207 is
pending); no conformance to FIPS 207 is claimed.

v5.1 changes applied (reference commit in parentheses):

| Change | Reference | Files here |
|---|---|---|
| ω +1 for all sets (67/101/132), ω_r = ω_e +1 for HQC-1 and HQC-5 (76/150) | b1dc633 `parameters.h` | `src/params.rs` |
| XOF absorbs no domain byte (was `0x01`); KEM seed expansion is `XOF(seed_KEM ‖ k/8)` | 46c4dd1 `symmetric.c`, `hqc-kem.c` | `src/shake.rs`, `src/kem.rs` |
| GF(2^8) polynomial `x^8+x^4+x^3+x+1` (0x11B, was 0x11D), primitive element 3 (was 2), new RS generator polynomials | 6d66bb7 `gf.{c,h}`, `parameters.h` | `src/gf256.rs`, `src/params.rs` |
| RM(1,7) generator rows for message bits 0..2 = 0x55../0x33../0x0f.. and decoder bit order `bit ^ 7` | 5900d91 `reed_muller.c` | `src/reed_muller.rs` |
| Compressed decapsulation key `dk_KEM = seed_KEM` (32 bytes) as the format; decapsulation re-derives `seed_PKE ‖ sigma` and the PKE key pair | df88ba6 `hqc-kem.c` | `src/kem.rs`, `src/types.rs`, `src/params.rs`, `src/lib.rs` |
| RS decoder rewritten as in the reference (syndromes, Berlekamp, evaluation at the k message positions, Forney with batched inversion); the additive FFT (`src/fft.rs`) is removed | 938bfe1 `reed_solomon.c` (the reference removed `fft.c`) | `src/reed_solomon.rs` |

Not an algorithm change, but relevant to the tests: d63f22e ("Update HQC-KEM
API") replaced the KAT generator's SHAKE256-based PRNG by the NIST AES-256 CTR
DRBG (`lib/nist-rng/rng.c`) and the KAT file name became `PQCkemKAT_32.rsp`.
`tests/kat.rs` reimplements that DRBG.

Changes needed to live in this workspace (no v5.1 meaning):

- **No `unsafe`.** Upstream's PCLMULQDQ path (`unsafe`, x86-64) and its
  portable fallback, a 3-bit-window table kernel indexed by operand bits, are
  replaced by branch-free, table-free 64x64-bit carry-less multiplies
  (`src/poly.rs`, `base_mul_acc`): by default `clmul_int`, built from 25
  integer multiplications of operands masked into five interleaved bit classes
  (after BearSSL `ghash_ctmul64.c`); with the cargo feature `bitserial-mul`,
  `clmul_bitserial`, a masked shift-and-XOR per bit. Both are tested against a
  naive bit-by-bit product in every build (see "Constant-time notes").
- With `clmul_int`, the accumulated Karatsuba recursion stops at operands of
  2 words and multiplies those schoolbook (upstream: 1 word); measured 7-15 %
  faster (2, 3, 4, 6, 8, 12 words measured; 2 was best for HQC-5). With
  `bitserial-mul` it stays at 1 word, which measured faster for that kernel.
- `HqcKem::decapsulate_from_seed` (new): decapsulation from the 32-byte seed
  that also returns the encapsulation key it re-derives, so callers that need
  both run key generation once. The FO comparison and selection are unchanged.
- `rand` replaced by `rand_core` (the workspace's 0.10.1; `CryptoRng` is the
  same trait).
- Optional features `kem`, `pkcs8`, `pem`, `serde` and their modules
  (`kem_impl.rs`, `pkcs8_impl.rs`, `sizes.rs`, serde impls) are removed: they
  encode the pre-v5.1 key format and are not used by VYRA.
- `DecapsulationKey::try_from(&[u8])` takes the 32-byte seed and derives the
  encapsulation key (previously it parsed the expanded key).
- Crate-local lints (see below), `#![forbid(unsafe_code)]`, documentation, the
  `HQC_VERSION` constant, and tests (`tests/kat.rs`, `tests/kem.rs`, RS
  vectors and GF/word-multiply unit tests); upstream `tests/api.rs` and
  `tests/ct.rs` are ported (the dk tamper test now flips a seed byte; the
  timing tests cover all three sets and are `#[ignore]`d with a reason).

## Lints relaxed

The crate uses the workspace lints (`[lints] workspace = true`: `unsafe_code`
forbidden, `missing_docs` and clippy `unwrap_used`, `expect_used`, `panic`,
`indexing_slicing` denied). One lint is relaxed: `clippy::indexing_slicing` is
allowed by an inner attribute in the seven forked arithmetic modules `kem.rs`,
`pke.rs`, `poly.rs`, `code.rs`, `reed_solomon.rs`, `reed_muller.rs` and
`sampling.rs` (152 sites in total), because the forked constant-time code
indexes fixed-size buffers throughout and rewriting it to satisfy the lint
would risk its constant-time structure. Being in source, the allow also
overrides a command-line `-D clippy::indexing_slicing`, so that gate is not
evidence for these modules. `lib.rs`, `types.rs`, `params.rs`, `shake.rs`,
`gf256.rs` and `error.rs` meet the lint. `src/reed_solomon.rs` also allows
`clippy::needless_range_loop` (index loops mirror the reference C).

## Constant-time notes

The default word multiply `clmul_int` is constant time **only if the CPU's
64x64->128-bit integer multiplication is constant time**. That holds on
current x86-64 and AArch64 cores but is NOT guaranteed on every target (some
low-end or older cores have early-terminating multipliers). For that reason the
integer-multiply kernel is compiled only for `x86_64` and `aarch64`; every
other target architecture gets the multiplier-free shift-and-XOR kernel
(slower), and the cargo feature `bitserial-mul` forces it everywhere. An
x86-64 or AArch64 core with a variable-time multiplier would still need the
feature set by hand. The manual timing smoke tests in `tests/ct.rs`
are a coarse check on one machine, not a proof.

## Constant-time-relevant code touched

- `src/poly.rs` `base_mul_acc` / `clmul_int` / `clmul_bitserial`: new word
  multiplies (see above). Neither has a secret-dependent branch or memory
  index; upstream's non-x86 fallback had secret-indexed table loads. The
  schoolbook base case of the Karatsuba recursion decides on operand length
  only (public).
- `src/gf256.rs` `gf_mul`: reduction constant 0x11B (structure unchanged).
- `src/reed_solomon.rs`: new decoder ported from the v5.1 reference with its
  constant-time structure: mask-based selection, loop bounds depending only on
  public parameters, `core::hint::black_box` where the reference uses an
  optimisation barrier (`CT_OPAQUE`/`volatile`). `alpha^e` table loads are
  indexed by public exponents only. `nonzero_mask` uses `(x | -x) >> 15`
  (the reference's `(x ^ -x) >> 15` is equal for all byte inputs).
- `src/reed_muller.rs`: constant masks and the decoder's bit order (no new
  control flow).
- `src/kem.rs`: decapsulation re-derives the key pair from the seed; the
  ciphertext comparison and the selection between the real and the rejection
  key are upstream's constant-time code, unchanged.
- Sampling (`src/sampling.rs`) is unchanged; v5.1 did not change it after the
  snapshot upstream implements.
