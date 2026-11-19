# VYRA pass conditions

Written before implementation. Every gate is machine-evaluable: a command with
an exit code, a named test, or a grep. `cargo xtask verify` runs all of them and
writes `results/verification-report.json`. A gate is PASS only when its command
exits 0. "Looks right" is not a result.

Passing every gate here demonstrates functional correctness and a set of
implementation-hygiene properties. It does **not** demonstrate that VYRA is
cryptographically secure, quantum-resistant, or fit for production use.

## F — Functional correctness

| ID | Check | Pass condition |
|----|-------|----------------|
| F1 | `cargo build --workspace --all-targets --locked` | exit 0 |
| F2 | `cargo test --workspace --locked` | exit 0, 0 failed, no `#[ignore]` without a reason string |
| F3 | Hybrid KEM round trip, suites 1/3/5 | `decapsulate(sk, encapsulate(pk).ct) == K` for ≥ 100 fresh key pairs per suite |
| F4 | Component conformance | each adapter (ML-KEM, HQC, ML-DSA, Ed25519, SLH-DSA-SHAKE-128s/192s/256s) agrees with an official KAT or an independent second implementation, all parameter sets. HQC v5.1: official KATs only (100 counts per set); no independent implementation exists. SLH-DSA: NIST ACVP keyGen/sigGen/sigVer vectors (`vyra-sig --test conformance_slhdsa`) |
| F5 | VYRA known-answer vectors | `cargo xtask vectors --check` regenerates `vectors/*.json` from fixed seeds and byte-compares, exit 0 |
| F6 | Serialization | `decode(encode(x)) == x` for every wire object; encoded length equals the spec table constant |
| F7 | Composite signature round trip, all suites | `verify(pk, m, ctx, sign(sk, m, ctx))` is `Ok` for the transition suites (VYRA-SIG-2/3/5) and the dual post-quantum suites (VYRA-SIG-PQ1/3/5); transition suites byte-for-byte unchanged by the dual-PQ refactoring (`regression_transition`); custom assemblies (`custom_composite`) |
| F8 | Sealed box round trip | `open(sk, seal(pk, aad, pt), aad) == pt` including empty and 1 MiB plaintexts |
| F9 | Demonstration | `cargo run -p vyra-cli --locked -- demo` exit 0 |

## S — Implementation security

| ID | Check | Pass condition |
|----|-------|----------------|
| S1 | Length validation | every decoder rejects empty, truncated (len-1) and extended (len+1) input with `Error`, never panics |
| S2 | Header validation | wrong magic, version, object type and suite id are each rejected |
| S3 | KEM ciphertext tampering | a bit flip in either component ciphertext yields a different shared secret (implicit rejection) and no panic; sampled over every byte region |
| S4 | Signature tampering | flipping message, context, either component signature, or public key makes `verify` fail; a valid component signature alone is never accepted (all six suites and custom assemblies) |
| S5 | AEAD tampering | flipping ciphertext, tag, KEM ciphertext, or AAD makes `open` fail |
| S6 | Combiner binding | changing any one of suite, ss₁, ss₂, ct₁, ct₂, pk₁, pk₂ changes the output key; a custom assembly (`CustomHybridKem`) of a named suite's components reproduces that suite byte for byte and hashes its combiner id (`custom_assembly`) |
| S7 | No unsafe | every VYRA crate root has `#![forbid(unsafe_code)]` |
| S8 | No panics in library code | `cargo clippy --workspace --lib -- -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic -D clippy::indexing_slicing` exit 0. Scope note: seven arithmetic modules of the forked `vyra-hqc` crate allow `indexing_slicing` in-source (fixed-bound array indexing inherited from upstream), so this gate is not evidence for them; their robustness evidence is S10 and the official KATs (F4) |
| S9 | Secret hygiene | secret types zeroize on drop, print `[REDACTED]` under `Debug`, and compare in constant time (tests assert the first two; the third by code inspection gate: no `derive(PartialEq)` on secret types) |
| S10 | Parser robustness | property tests feed arbitrary bytes to every decoder: no panic |
| S11 | Lint and format | `cargo clippy --workspace --all-targets --locked -- -D warnings` and `cargo fmt --all --check` exit 0 |
| S12 | Dependency advisories | `cargo audit` exit 0 (recorded as NOT RUN if the tool is unavailable; never recorded as PASS without running) |

## C — Cryptographic claims discipline

These gates check that the documentation is honest, not that the cryptography is sound.

| ID | Check | Pass condition |
|----|-------|----------------|
| C1 | Required sections | `docs/SECURITY.md` contains headings: Assumptions, Attack models, Parameter analysis, Side channels, Randomness, Key lifecycle, Limitations, Open questions, Deviations from the research report |
| C2 | Forbidden claims | no unnegated occurrence of "provably secure", "unbreakable", "production-ready", "quantum-proof", "independently validated" in tracked docs or source (allow-list lines are explicit in `xtask`) |
| C3 | Original vs established | `docs/SPEC.md` labels every component as ESTABLISHED or VYRA-ORIGINAL |

## P — Performance

| ID | Check | Pass condition |
|----|-------|----------------|
| P1 | Benchmarks | `cargo xtask bench` writes `results/benchmarks.json` with keygen/encaps/decaps for 3 KEM suites and 6 KEM components, keygen/sign/verify for 6 signature suites (3 transition, 3 dual post-quantum) and the 3 SLH-DSA components, and seal/open |
| P2 | Sizes | `cargo xtask sizes` writes `results/sizes.json` from code constants; values equal the SPEC table |

## D — Documentation

| ID | Check | Pass condition |
|----|-------|----------------|
| D1 | API docs | `RUSTDOCFLAGS=-D warnings cargo doc --workspace --no-deps --locked` exit 0, with `#![deny(missing_docs)]` in every library crate |
| D2 | Doctests | included in F2 |
| D3 | Docs match code | sizes and suite identifiers quoted in `docs/SPEC.md` equal `results/sizes.json` (checked by `xtask`) |
| D4 | Paper | `typst compile paper/vyra.typ paper/vyra.pdf` exit 0 |
| D5 | Reproducible build | a fresh `git clone` into a temp dir passes F1, F2, F5 using only the README instructions |

## Y — Yielding resistance (failure injection)

These gates check that the failure-injection experiment (`crates/vyra-yield`)
runs, is deterministic, and that the committed evidence shows what the
documentation says it shows. Failure injection is falsification evidence, not
a proof: NO ATTACK FOUND only means that the implemented attacks did not win.

| ID | Check | Pass condition |
|----|-------|----------------|
| Y1 | Failure-injection tests | `cargo test -p vyra-yield --locked` exit 0, 0 failed, at least one test passed (controls and expected verdict pattern) |
| Y2 | Yield matrix reproducible and as claimed | `cargo run -p vyra-yield --release --locked --bin yield-report -- --out target/verify/yield-matrix` exit 0 (every control passed), and the fresh `yield-matrix.json` is byte-identical to the committed `results/yield-matrix.json`; in that JSON: every cell's verdict equals its `expected` field where that field is a verdict (`BROKEN` / `NO ATTACK FOUND`; `UNSPECIFIED` states no expectation); every KEM cell of the real `Vyra` combiner with exactly one failed component is NO ATTACK FOUND; the `Naive` combiner has at least one BROKEN cell with one `Malleable` and one `Real` component; for every combiner, each pattern with both components confidentiality-broken (`Leaky`/`Constant`) is BROKEN in IND-CCA2 (positive controls); signature rows are judged by their `expected` field; only if they carry none, those that name a `Vyra` combiner with one failed component must be NO ATTACK FOUND; every recorded control, claim check and expectation check has `passed: true`; calibration (and signature calibration, if present) NO ATTACK FOUND |

## V — Machine-checked properties

These gates cover only VYRA's own encodings (wire header, transcript framing,
constant-time equality, entropy adapter, message representative) within the
stated finite domains and bounds. They are not a verification of the
cryptographic components or of any security property.

| ID | Check | Pass condition |
|----|-------|----------------|
| V1 | Exhaustive enumeration | `cargo test -p vyra-proofs --locked` exit 0, 0 failed, at least one test passed (every input of the stated finite domains enumerated) |
| V2 | Bounded model checking (Kani) | `results/kani-report.txt`, as written by `tools/kani/in-container.sh`, has a SUMMARY in which every harness listed in `in-container.sh` is SUCCESSFUL, every mutant of `tools/kani/mutants.tsv` has its expected outcome (`OK`), and the overall exit status is 0. A missing report or one that says `status: NOT RUN` is NOT_RUN, never PASS. `verify` does not start Docker by default; `cargo xtask verify --with-kani` runs `tools/kani/run.ps1` (Windows) or `tools/kani/run.sh` first and judges the fresh report; with `--with-kani` a runner failure that leaves no new report is FAIL |

## X — Scope

| ID | Check | Pass condition |
|----|-------|----------------|
| X1 | Research report preserved | SHA-256 of `docs/research/vyra-deep-research-report.md` content (LF-normalised) equals the recorded original |
| X2 | No stray changes | `git status --porcelain` empty when `verify` starts (after the final commit); after the run only the `results/` files that `verify` regenerates itself may differ; nothing written outside the repository except tool caches |

## NOT_RUN policy

A gate may end NOT_RUN only in these cases; `verify` records any other
NOT_RUN as FAIL, and NOT_RUN is never counted as a pass:

| Gate | Allowed NOT_RUN |
|------|-----------------|
| S12 | `cargo audit` is not installed |
| D4 | `typst` is not on `PATH` |
| V2 | `results/kani-report.txt` is missing or says `status: NOT RUN` (without `--with-kani`) |
| X2 | quick mode with a tree that was dirty when `verify` started |
