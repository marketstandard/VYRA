# vyra-hqc

Pure-Rust HQC-KEM, **HQC specification version 5.1 (2026-11-09)**, reference
implementation tag `v5.1.0` (commit `06567ccbad10580d78dd7863b15d23f41076d57f`),
for VYRA's hybrid KEM. Parameter sets HQC-1/3/5 (`Hqc128`/`Hqc192`/`Hqc256`).

- Reproduces all 100 official v5.1 known-answer vectors of each parameter set,
  driven through the reference KAT generator's NIST AES-256 CTR DRBG
  (`tests/kat.rs`; data and provenance in `tests/data/`).
- HQC is not a published NIST standard yet; FIPS 207 is unpublished and no
  conformance to it is claimed. No independent second implementation of v5.1
  was available to test against.
- Research-stage code: a modified fork, reviewed only within the VYRA project.

## Constant-time notes

The default carry-less word multiply is built from integer multiplications
and is constant time only if the CPU's 64x64->128-bit integer multiplier is
(true on current x86-64 and AArch64 cores, NOT guaranteed on all targets).
On every other target architecture the multiplier-free kernel is selected
automatically; the cargo feature `bitserial-mul` forces it on x86-64 and
AArch64 as well (slower). Details in `NOTICE.md`.

## Notice

Derived from `hqc-kem` 0.1.0-rc.0 (RustCrypto, MIT OR Apache-2.0,
<https://crates.io/crates/hqc-kem>), modified to HQC v5.1 by the VYRA authors.
`NOTICE.md` lists the origin, the licence finding, every modification, the
relaxed lints and the constant-time-relevant code that was touched.
