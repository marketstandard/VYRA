# Attempt log

Every unit attempt is recorded here, including rejected ones. Format:

    UNIT | ATTEMPT n/3 | VERDICT | CHECK | EVIDENCE

| Unit | Attempt | Verdict | Check | Evidence |
|------|---------|---------|-------|----------|
| U0 repo inspection | 1/3 | PASS | report read in full; SHA-256 recorded | `4f46d971…9fd72b` |
| U0 pass conditions | 1/3 | PASS | docs/CHECKS.md exists before any code | commit history |
| U1 vyra-core | 1/3 | FAIL | fmt/build/test/clippy/doc | fmt, build, test (44 passed), clippy exit 0; `cargo doc` with `-D warnings` exit 101: 3× `rustdoc::redundant_explicit_links` in `src/rng.rs` |
| U1 vyra-core | 2/3 | PASS | fmt/build/test/clippy/doc (+ S8 lib clippy) | fixed the 3 redundant doc links; all five commands exit 0; tests 12+8+4+7+13 = 44 passed, 0 failed; S8 `clippy --lib --locked` exit 0 |
| U2 vyra-kem | 1/3 | FAIL | cargo test | `f4b_differential_hqc*` failed: `backbone-hqc` implements HQC v5.0.0, `hqc-kem` implements reference commit 161cd4f; public keys differ from byte 32 |
| U2 vyra-kem | 2/3 | FAIL | fmt + clippy | rustfmt diffs and 7 clippy errors, all in test files |
| U2 vyra-kem | 3/3 | PASS | 5 fixed commands | 55 tests + 1 doctest, 0 failed; re-run by orchestrator |
| U3 vyra-sig | 1/3 | FAIL | cargo test | `wire::s2_header_fields_rejected`: a relabelled secret key parses because composite secret keys are 64 bytes in every suite (format limitation, now pinned by a test and documented) |
| U3 vyra-sig | 2/3 | PASS | 5 fixed commands | 54 tests + 1 doctest, 0 failed; re-run by orchestrator |
| U1b SecurityLevel::L2 | 1/3 | PASS | fmt, workspace test, clippy x2, doc | ML-DSA-44 was mislabelled category 1; added `L2`; 153 tests, 0 failed |
| U4 vyra-seal | 1/3 | FAIL | clippy --all-targets | 2 lint errors in test code only |
| U4 vyra-seal | 2/3 | PASS | 5 fixed commands | 28 tests, 0 failed |
| R1 independent review (kem, sig, core) | 1/1 | FAIL | adversarial read + scratch program | K-1 unchecked stored pk in hybrid sk (MEDIUM); S-1 separable composite halves; S-2 no pk binding; K-2 HQC padding bits; T-1..T-4 test gaps; C-1 overstated docs |
| U3-R1 vyra-sig repair | 1/3 | PASS | 5 fixed commands + core tests | ML-DSA context `VYRA-SIG-v1‖suite`; pk digest in M'; new separation and entropy-sweep tests |
| U2-R1 vyra-kem repair | 1/3 | PASS | 5 fixed commands + seal tests | sk = sk1‖sk2, pks derived; pk validation at parse; independent recomputation test. Requirement "every sk bit flip changes K" was invalid for ML-KEM z, HQC sigma, HQC seed_kem (not read on the valid-ciphertext path); replaced by region-specific assertions |
| U5 vyra facade + vyra-cli | 1/3 | FAIL | clippy --all-targets | 1 `type_complexity` lint in args.rs |
| U5 vyra facade + vyra-cli | 2/3 | PASS | 8 fixed commands | 16 tests, demo prints `PASS: all 57 checks passed` |
| U6 xtask (verify, vectors, sizes, bench) | 1/3 | PASS | 8 fixed commands | 31 tests; corrupted-vector run exits 1 with 3 diagnostics; verify --quick 29 PASS, 2 FAIL (D4 no paper yet, D5 uncommitted tree), 2 NOT_RUN |
| U7 SPEC / THREAT_MODEL / SECURITY docs | 1/3 | PASS | gates C1, C3, D3 via xtask | found: pinned HQC parameters superseded by HQC v5.1 (D-11 addendum); HQC sk embedded pk unchecked (D-13) |
| U8 README + BUILDING (haiku) | 1/3 | PASS | link/command self-check | placeholders for vectors/ and paper/ to be corrected at integration |
| U4-R1 vyra-seal repair (haiku) | 1/3 | PASS | 5 fixed commands | output buffer zeroizing on error paths; error value corrected |
| U3-R2 vyra-sig pk validation | 1/3 | FAIL | cargo test | two older tests built keys the new validation rejects (random / all-zero Ed25519 part) |
| U3-R2 vyra-sig pk validation | 2/3 | PASS | 5 fixed commands + cli | ed25519-dalek 3.0 accepts 26 of 40 non-canonical encodings; VYRA rejects all |
| U2-R2 vyra-kem HQC seed-form sk | 1/3 | FAIL (stopped) | cargo test | all suites' sk became 96 bytes, so relabelled wire sk parsed; agent stopped for a design decision instead of weakening 2 tests |
| U2-R2 vyra-kem HQC seed-form sk | 2/3 | FAIL | cargo test + doc | fuzz test built a wire sk without the new check value; one rustdoc link warning |
| U2-R2 vyra-kem HQC seed-form sk | 3/3 | PASS | 5 fixed commands + seal + cli | 60 tests; check value `VYRA-KEM-SK-v1`; all 952 single-bit flips of a wire sk rejected |
| CHECK REPLACED: raw cross-suite secret key rejection | — | INVALID CHECK | — | a suite-less raw seed valid for every parameter set cannot be rejected by a suite-less function; replaced by (a) typed API rejects, (b) wire decoder rejects via check value, (c) raw decapsulate yields an unrelated key |
| U3-R3 vyra-sig sk check value | 1/3 | PASS | 5 fixed commands + cli | wire sk 71 -> 87 bytes; all single-bit flips rejected |
| U7-R1 docs sync to repaired code | 1/3 | PASS | C1, C3, D3 self-check + label grep | SPEC/THREAT_MODEL/SECURITY updated for seed keys, check values, pk validation, superseded HQC parameters |
| U9 paper (Typst) | 1/3 | PASS | typst compile (0 warnings), 12 pages, visual page check, number cross-check | 16 size rows and 48 benchmark rows match results files |
| U3-R4 vyra-sig reject mixed-order Ed25519 keys | 1/3 | PASS | 5 fixed commands + cli | plain dalek accepts all 7 constructed mixed-order keys and does not flag them weak; VYRA rejects |
| S12 cargo audit | 1/1 | PASS | `cargo audit` | 124 crates, 1533 advisories loaded, none reported (2026-11-18) |
| CHECK CLARIFIED: X2 / D5 tree cleanliness | — | INVALID AS WRITTEN | — | `verify` itself rewrites results/benchmarks.* (timings differ every run) before X2 and D5 are evaluated, so "tree empty at the end" could never pass in full mode; both now judge the tree as it was when `verify` started and allow only results/ to differ afterwards. Not a weakening: source, docs, vectors and paper must still be committed and unchanged |
| U7-R2 / U9-R1 / U9-R2 docs and paper sync | 1/3 each | PASS | self-checks; typst compile 0 warnings; 13 pages; 48 benchmark rows and 16 size rows match results files | mixed-order fix documented; benchmark numbers re-measured on final code (2026-11-19T01:54:48Z) |
| CHECK CLARIFIED: P1 | — | — | — | `verify` validates a fresh benchmark run but preserves the published results/benchmarks.* so that quoted numbers stay stable; `cargo xtask bench` is the only command that rewrites them |
| FINAL `cargo xtask verify` (full mode) | 1/1 | PASS | all gates in docs/CHECKS.md | 33 PASS, 0 FAIL, 0 NOT_RUN; D5 fresh clone built, tested and re-checked vectors; report in results/verification-report.md |
| U3-R5 vyra-sig standalone Ed25519 subgroup check + ACVP sigGen/sigVer | 1/3 | PASS | 5 fixed commands + cli | 135 official NIST ACVP ML-DSA vectors pass (90 sigGen, 45 sigVer); plain dalek `verify_strict` accepts signatures under all 7 mixed-order keys, VYRA rejects |
| U10 HQC v5.1 port (`vyra-hqc`) and adapter switch | 1/3 | PASS | fmt, tests (debug+release), clippy x2, doc, seal, cli | 100/100 official v5.1 KAT counts per set via crate and adapter; 2000 random round trips per set; 7 verified spec changes |
| U10-R1 HQC performance (integer-multiply carry-less kernel, single keygen in decaps) | 1/3 | PASS | 14 fixed commands incl. `--features bitserial-mul` | 100/100 KATs per set with both kernels; HQC 3.4–4.8x faster than the bit-serial port; timing smoke t-statistics all below 1.6 in magnitude |
| MSRV | 1/1 | PASS | `cargo +1.88 test --workspace --locked` | 293 passed, 0 failed on Rust 1.88; `rust-version` raised from an untested 1.87 to a tested 1.88 (proptest dev-dependency requires 1.88) |
| U7-R3 docs sync for HQC v5.1 | 1/3 | PASS | C1, C3, D3 self-check, label grep | flagged: kernel not target-gated (fixed below), KATs do not cover implicit rejection (documented as open question) |
| HQC kernel target gating | 1/1 | PASS | tests with both kernels, wasm32 check, clippy | integer-multiply kernel only on x86_64/aarch64; other architectures get the multiplier-free kernel automatically |
| U9-R3 paper refinement for HQC v5.1 | 1/3 | PASS | typst compile 0 warnings; 14 pages; all pages viewed; 48 benchmark and 16 size rows match | declined to print a per-change KAT-field table because the repository does not record that evidence |
| S12 cargo audit (re-run after dependency change) | 1/1 | PASS | `cargo audit` | 122 crates, 1533 advisories loaded, none reported (2026-11-18) |
| FINAL verify after HQC v5.1 | 1/3 | FAIL | `cargo xtask verify` (full) | 32 PASS, 1 FAIL: D1 — `crates/vyra-hqc/src/lib.rs` lacked the explicit `#![deny(missing_docs)]` attribute (the lint itself was already enforced through workspace lints) |
| FINAL verify after HQC v5.1 | 2/3 | PASS | `cargo xtask verify` (full) | 33 PASS, 0 FAIL, 0 NOT_RUN; D5 fresh clone built, tested and re-checked vectors |
| U11 yield tests, KEM (failure injection) | 1/3 | PASS | 7 fixed commands; deterministic report | 1955 cells, N=200; VYRA combiner: no attack found in all 230 one-component-failed cells; naive combiner broken by mauling; XOR broken even over two sound components (reported as its own control) |
| U12 dual-PQ signatures (ML-DSA + SLH-DSA) | 1/3 | FAIL | cargo test | an existing test iterated `SigSuite::all()` and built Ed25519-shaped keys for the new suites |
| U12 dual-PQ signatures | 2/3 | FAIL | clippy --all-targets | `type_complexity` in a new test |
| U12 dual-PQ signatures | 3/3 | PASS | 6 fixed commands incl. MSRV | 149 tests; 114 official ACVP SLH-DSA vectors through the adapter; transition suites byte-identical (regression pin) |
| U13 machine-checked properties | 1/3 | PARTIAL | host checks; Kani NOT RUN | Docker daemon crashed (stale socket); exhaustive-enumeration proofs pass, 10 of 11 mutants killed, M8 survives by design (length-prefix truncation invisible below 256 bytes) |
| Docker repair | 1/1 | PASS | `docker info` | stale `docker-secrets-engine` folder renamed aside with the owner's go-ahead; daemon up; Kani image built (Kani 0.68.0, CBMC 6.11.0) |
| U11-S yield tests, signatures | 1/3 | PASS | 6 fixed commands; deterministic report | 872 signature cells; FINDING: transition composite with ML-DSA failed is broken (200/200) by an adversary with a standalone Ed25519 signing oracle on the same key; dual-PQ composite is not |
| U14a integration (facade, CLI, xtask gates Y1/Y2/V1/V2) | 1/3 | FAIL | verify --quick | yield matrix schema changed mid-run (`expected: UNSPECIFIED`) |
| U14a integration | 2/3 | PASS (scope) | fixed checks; verify --quick 32 PASS / 3 FAIL / 2 NOT_RUN | remaining FAILs outside the unit: S7 (missing attribute in yield-report, fixed by orchestrator), P1 (bench not yet re-run), D3 (SPEC not yet updated) |
| U12-R1 Ed25519 half context-bound (Ed25519ph) | 1/3 | PASS | 6 fixed commands | 154 tests; RFC 8032 §7.3 vector through the half path; independent test-side reference matches on 24 context cases; Ed25519ctx rejected because ed25519-dalek 3.0 does not expose it |
| Kani first run | 1/3 | FAIL | tools/kani/run.ps1 | 2 harnesses SUCCESSFUL, 2 FAILED (wire_reader_ops, wire_round_trip), framing injectivity TIMEOUT at 3600 s; sent back for diagnosis |
| U11-S-R1 yield re-run after the Ed25519 fix | 1/3 | PASS | 6 fixed commands; deterministic report (2 runs identical) | 1955 KEM + 1410 signature cells; no cell contradicts its claim-based expectation; pre-fix design kept as control `VyraPureEd` and still BROKEN 200/200; standalone oracle widened to four modes; dual-PQ N raised 4 -> 12 |
| U7-R4 docs sync and design review of the yield experiment | 1/3 | PASS | C1, C3, D3 self-check (127 values), label grep | reviewer findings: 77% of cells are unspecified observations; negative control blind to real-component binding; D-15 and D-18 over-claimed and were reworded |
| U13-R1 Kani diagnosis and full run | 2-3/3 per harness | PASS | tools/kani/run.ps1, overall exit 0 | 10 entries / 413 harnesses SUCCESSFUL; 12/12 mutants killed by property failures; earlier FAILED results were unwind bounds too small and solver memory blow-up, no counterexample to any property |
| U7-R5 docs: final Kani status | 1/3 | PASS | self-checks | single status subsection updated from the report |
| U15 paper rewritten around contributions | 1/3 | PASS | typst compile 0 warnings, deterministic PDF, 12 pages viewed, 284 number checks 0 mismatches | framed as our method, results and suggestions; origin note only |
| MSRV (after refinement) | 1/1 | PASS | `cargo +1.88 test --workspace --locked` | 426 passed, 0 failed, 2 ignored (manual timing smoke tests) |
| FINAL verify after refinement | 1/1 | PASS | `cargo xtask verify` (full) | 37 PASS, 0 FAIL, 0 NOT_RUN, including Y1/Y2 (yield matrix regenerated byte-identical), V1/V2 (enumeration and Kani report), D5 (fresh clone) |
| U16 figures for README and paper | 1/3 | PASS | `python tools/figures/gen_figures.py --check` (23 figures match results); palette validator (3 series colours, light and dark, all pairs); `typst compile --ignore-system-fonts` 0 warnings, deterministic PDF, 14 pages viewed; 282 number checks 0 mismatches | 9 README figures (light and dark) and 5 paper figures drawn from results/; verbal claims of each figure asserted in the generator; sizes figure tried in the paper and removed (it left a half-empty page; the tables already carry it) |
| U17 Rust 1.100 (CI toolchain) | 1/3 | PASS | `cargo fmt --all --check`, clippy `-D warnings`, `cargo xtask verify` (full) on rustc 1.100.0 | first GitHub CI run failed at the formatting step (runner rustfmt 1.100 vs local 1.98); two files reformatted, no code change; 37 PASS, 0 FAIL, 0 NOT_RUN |
| U18 Market Standard ownership, community files, report path scrubbing | 1/3 | PASS | `cargo test -p xtask report_text`, clippy `-D warnings`, 282 number checks, figure check, `cargo xtask verify` (full) | sensitive-info scan of tree and history found no credentials; the verification report recorded the local checkout and temp paths, now written as `<repo>`, `<tmp>`, `<home>`; copyright holder set to Market Standard, LLC; authors named; community files added |
| U19 CI split (fast check per push, full verify weekly and on demand); paper authors | 1/3 | PASS | step timings of GitHub run 44558250879; `cargo xtask verify` (full) locally | on x86-64 Linux runners the full run took 4 h 33 min (Y2 85 min, D5 47 min, F2 44 min, plus a duplicate test step of 45 min); arm64 macOS ran the test suite in 5.4 min; optimising `vyra-yield` in dev builds was tried and did not help (84 s to 143 s locally), so it was not kept |
