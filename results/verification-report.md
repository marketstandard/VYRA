# VYRA verification report

- mode: full
- commit: 2ec648cc1ee710b6630bb82f2df5abbe9e6ecbd3
- working tree dirty at start: false
- date (UTC): 2026-11-19T23:14:45Z
- summary: 37 PASS, 0 FAIL, 0 NOT_RUN of 37

PASS demonstrates that a gate's command or check succeeded. It does not demonstrate that VYRA is cryptographically secure (see docs/CHECKS.md). NOT_RUN is never a pass.

| gate | status | exit | time (s) | description |
|---|---|---|---|---|
| F1 | PASS | 0 | 0.2 | workspace builds (all targets) |
| F2 | PASS | 0 | 571.6 | workspace tests pass; no #[ignore] without reason |
| F3 | PASS | 0 | 2.8 | hybrid KEM round trip, suites 1/3/5 |
| F4 | PASS | 0 | 276.5 | component conformance (ML-KEM, HQC, ML-DSA, Ed25519) |
| F5 | PASS | - | 35.0 | VYRA known-answer vectors (vectors --check) |
| F6 | PASS | 0 | 7.4 | serialization round trip and lengths |
| F7 | PASS | 0 | 34.5 | composite signature round trip, all suites |
| F8 | PASS | 0 | 0.0 | sealed box round trip incl. empty and 1 MiB |
| F9 | PASS | 0 | 11.1 | demonstration: vyra-cli demo |
| S1 | PASS | 0 | 0.5 | length validation of every decoder |
| S2 | PASS | 0 | 0.0 | header validation (magic, version, type, suite) |
| S3 | PASS | 0 | 1.2 | KEM ciphertext tampering (implicit rejection) |
| S4 | PASS | 0 | 27.4 | signature tampering |
| S5 | PASS | 0 | 2.9 | AEAD tampering |
| S6 | PASS | 0 | 0.8 | combiner binding |
| S7 | PASS | - | 0.0 | no unsafe: #![forbid(unsafe_code)] in every crate root |
| S8 | PASS | 0 | 0.5 | no panics in library code (clippy deny list) |
| S9 | PASS | 0 | 1.0 | secret hygiene (tests + no derive(PartialEq) on secret types) |
| S10 | PASS | 0 | 4.9 | parser robustness (property tests) |
| S11 | PASS | 0 | 1.2 | lint and format |
| S12 | PASS | 0 | 1.2 | dependency advisories (cargo audit) |
| C1 | PASS | - | 0.0 | docs/SECURITY.md required sections |
| C2 | PASS | - | 0.1 | forbidden claims absent |
| C3 | PASS | - | 0.0 | docs/SPEC.md labels components ESTABLISHED / VYRA-ORIGINAL |
| P1 | PASS | - | 278.0 | benchmarks written with all required entries |
| P2 | PASS | - | 23.2 | sizes written from code constants |
| D1 | PASS | 0 | 0.2 | API docs build with -D warnings; deny(missing_docs) |
| D2 | PASS | 0 | 0.0 | doctests (included in F2) |
| D3 | PASS | - | 0.0 | docs/SPEC.md sizes and suite ids equal results/sizes.json |
| D4 | PASS | 0 | 0.4 | paper compiles with typst |
| D5 | PASS | 0 | 681.4 | fresh git clone passes F1, F2, F5 |
| Y1 | PASS | 0 | 98.3 | failure-injection tests (cargo test -p vyra-yield) |
| Y2 | PASS | 0 | 231.4 | yield matrix reproducible and verdict pattern as claimed |
| V1 | PASS | 0 | 6.9 | exhaustive enumeration proofs (cargo test -p vyra-proofs) |
| V2 | PASS | - | 0.0 | bounded model checking report (Kani): harnesses and mutants |
| X1 | PASS | - | 0.0 | research report preserved (SHA-256 pin) |
| X2 | PASS | - | 0.0 | no stray changes (git status --porcelain empty) |

## Details

### F1 — PASS

- description: workspace builds (all targets)
- method: `cargo build --workspace --all-targets --locked`

```text
$ cargo build --workspace --all-targets --locked -> exit Some(0) (0.2 s)
help: consider removing `package.homepage`
warning: `vyra-cli` (manifest) generated 1 warning
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.12s
```

### F2 — PASS

- description: workspace tests pass; no #[ignore] without reason
- method: `cargo test --workspace --locked + scan for #[ignore] without reason`

```text
$ cargo test --workspace --locked -> exit Some(0), 70 test binaries, 427 passed, 0 failed
   Doc-tests vyra_seal
   Doc-tests vyra_sig
   Doc-tests vyra_yield
no #[ignore] without a reason string
```

### F3 — PASS

- description: hybrid KEM round trip, suites 1/3/5
- method: `cargo test -p vyra-kem --test round_trip --locked`

```text
vyra-kem --test round_trip: 6 passed (2.8 s)
```

### F4 — PASS

- description: component conformance (ML-KEM, HQC, ML-DSA, Ed25519)
- method: `cargo test -p vyra-kem --test conformance_mlkem --locked ; cargo test -p vyra-kem --test conformance_hqc --locked ; cargo test -p vyra-hqc --test kat --locked ; cargo test -p vyra-sig --test conformance_mldsa --locked ; cargo test -p vyra-sig --test conformance_mldsa_acvp_sig --locked ; cargo test -p vyra-sig --test conformance_ed25519 --locked ; cargo test -p vyra-sig --test conformance_slhdsa --locked ; cargo test -p vyra-sig --test conformance_sizes --locked`

```text
vyra-kem --test conformance_mlkem: 6 passed (0.2 s)
vyra-kem --test conformance_hqc: 7 passed (5.6 s)
vyra-hqc --test kat: 4 passed (1.1 s)
vyra-sig --test conformance_mldsa: 5 passed (0.9 s)
vyra-sig --test conformance_mldsa_acvp_sig: 2 passed (1.0 s)
vyra-sig --test conformance_ed25519: 7 passed (0.1 s)
vyra-sig --test conformance_slhdsa: 14 passed (266.2 s)
vyra-sig --test conformance_sizes: 10 passed (1.5 s)
```

### F5 — PASS

- description: VYRA known-answer vectors (vectors --check)
- method: `in-process: cargo xtask vectors --check (byte-compare + re-derive + re-verify)`

```text
vectors --check: OK
```

### F6 — PASS

- description: serialization round trip and lengths
- method: `cargo test -p vyra-core --test wire --locked ; cargo test -p vyra-kem --test wire --locked ; cargo test -p vyra-sig --test wire --locked ; cargo test -p vyra-seal --test round_trip --locked`

```text
vyra-core --test wire: 13 passed (0.1 s)
vyra-kem --test wire: 6 passed (0.2 s)
vyra-sig --test wire: 24 passed (5.8 s)
vyra-seal --test round_trip: 7 passed (1.3 s)
```

### F7 — PASS

- description: composite signature round trip, all suites
- method: `cargo test -p vyra-sig --test roundtrip --locked ; cargo test -p vyra-sig --test regression_transition --locked ; cargo test -p vyra-sig --test custom_composite --locked`

```text
vyra-sig --test roundtrip: 15 passed (32.7 s)
vyra-sig --test regression_transition: 1 passed (0.1 s)
vyra-sig --test custom_composite: 5 passed (1.6 s)
```

### F8 — PASS

- description: sealed box round trip incl. empty and 1 MiB
- method: `cargo test -p vyra-seal --test round_trip --locked`

```text
vyra-seal --test round_trip: 7 passed (1.3 s)
```

### F9 — PASS

- description: demonstration: vyra-cli demo
- method: `cargo run -p vyra-cli --locked -- demo`

```text
$ cargo run -p vyra-cli --locked -- demo -> exit Some(0) (11.1 s)
warning: `vyra-cli` (manifest) generated 1 warning
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.06s
     Running `target\verify\debug\vyra.exe demo`
```

### S1 — PASS

- description: length validation of every decoder
- method: `cargo test -p vyra-core --test wire --locked ; cargo test -p vyra-kem --test raw_validation --locked ; cargo test -p vyra-kem --test wire --locked ; cargo test -p vyra-sig --test wire --locked ; cargo test -p vyra-seal --test malformed --locked`

```text
vyra-core --test wire: 13 passed (0.1 s)
vyra-kem --test raw_validation: 3 passed (0.2 s)
vyra-kem --test wire: 6 passed (0.2 s)
vyra-sig --test wire: 24 passed (5.8 s)
vyra-seal --test malformed: 4 passed (0.3 s)
```

### S2 — PASS

- description: header validation (magic, version, type, suite)
- method: `cargo test -p vyra-core --test wire --locked ; cargo test -p vyra-kem --test wire --locked ; cargo test -p vyra-sig --test wire --locked ; cargo test -p vyra-seal --test malformed --locked`

```text
vyra-core --test wire: 13 passed (0.1 s)
vyra-kem --test wire: 6 passed (0.2 s)
vyra-sig --test wire: 24 passed (5.8 s)
vyra-seal --test malformed: 4 passed (0.3 s)
```

### S3 — PASS

- description: KEM ciphertext tampering (implicit rejection)
- method: `cargo test -p vyra-kem --test tamper --locked`

```text
vyra-kem --test tamper: 4 passed (1.2 s)
```

### S4 — PASS

- description: signature tampering
- method: `cargo test -p vyra-sig --test tamper --locked ; cargo test -p vyra-sig --test separation --locked ; cargo test -p vyra-sig --test custom_composite --locked`

```text
vyra-sig --test tamper: 13 passed (16.2 s)
vyra-sig --test separation: 11 passed (11.2 s)
vyra-sig --test custom_composite: 5 passed (1.6 s)
```

### S5 — PASS

- description: AEAD tampering
- method: `cargo test -p vyra-seal --test tamper --locked`

```text
vyra-seal --test tamper: 3 passed (2.9 s)
```

### S6 — PASS

- description: combiner binding
- method: `cargo test -p vyra-kem --test combiner --locked ; cargo test -p vyra-kem --test independent --locked ; cargo test -p vyra-kem --test custom_assembly --locked`

```text
vyra-kem --test combiner: 3 passed (0.1 s)
vyra-kem --test independent: 1 passed (0.2 s)
vyra-kem --test custom_assembly: 3 passed (0.4 s)
```

### S7 — PASS

- description: no unsafe: #![forbid(unsafe_code)] in every crate root
- method: `scan crates/*/src/{lib.rs,main.rs,bin/*.rs} and xtask/src/main.rs`

```text
#![forbid(unsafe_code)] in: crates/vyra/src/lib.rs, crates/vyra-cli/src/main.rs, crates/vyra-core/src/lib.rs, crates/vyra-hqc/src/lib.rs, crates/vyra-kem/src/lib.rs, crates/vyra-proofs/src/lib.rs, crates/vyra-seal/src/lib.rs, crates/vyra-sig/src/lib.rs, crates/vyra-yield/src/lib.rs, crates/vyra-yield/src/bin/yield-report.rs, xtask/src/main.rs
```

### S8 — PASS

- description: no panics in library code (clippy deny list)
- method: `cargo clippy --workspace --lib --locked -- -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic -D clippy::indexing_slicing`

```text
$ cargo clippy --workspace --lib --locked -- -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic -D clippy::indexing_slicing -> exit Some(0) (0.5 s)
    Checking vyra-yield v0.1.0 (<repo>\crates\vyra-yield)
    Checking vyra v0.1.0 (<repo>\crates\vyra)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.43s
```

### S9 — PASS

- description: secret hygiene (tests + no derive(PartialEq) on secret types)
- method: `cargo test -p vyra-core --test entropy_secret --locked ; cargo test -p vyra-kem --test hygiene --locked ; cargo test -p vyra-sig --test secret_hygiene --locked ; scan crates/*/src/**/*.rs: no derive(PartialEq) on types named *Secret*`

```text
vyra-core --test entropy_secret: 9 passed (0.1 s)
vyra-kem --test hygiene: 3 passed (0.2 s)
vyra-sig --test secret_hygiene: 5 passed (0.6 s)
code inspection: no secret-named type derives PartialEq (99 files)
```

### S10 — PASS

- description: parser robustness (property tests)
- method: `cargo test -p vyra-core --test wire --locked ; cargo test -p vyra-kem --test fuzz --locked ; cargo test -p vyra-sig --test proptest_parsers --locked ; cargo test -p vyra-seal --test fuzz --locked`

```text
vyra-core --test wire: 13 passed (0.1 s)
vyra-kem --test fuzz: 5 passed (0.2 s)
vyra-sig --test proptest_parsers: 6 passed (4.2 s)
vyra-seal --test fuzz: 3 passed (0.5 s)
```

### S11 — PASS

- description: lint and format
- method: `cargo clippy --workspace --all-targets --locked -- -D warnings && cargo fmt --all --check`

```text
$ cargo clippy --workspace --all-targets --locked -- -D warnings -> exit Some(0) (0.9 s)
    Checking xtask v0.1.0 (<repo>\xtask)
    Checking vyra-cli v0.1.0 (<repo>\crates\vyra-cli)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.81s
$ cargo fmt --all --check -> exit Some(0) (0.3 s)

```

### S12 — PASS

- description: dependency advisories (cargo audit)
- method: `cargo audit`

```text
$ cargo audit -> exit Some(0) (1.2 s)
      Loaded 1550 security advisories (from F:\cargo\advisory-db)
    Updating crates.io index
    Scanning Cargo.lock for vulnerabilities (131 crate dependencies)
```

### C1 — PASS

- description: docs/SECURITY.md required sections
- method: `docs/SECURITY.md heading lines contain (case-insensitive) each required heading`

```text
all 9 required headings present
```

### C2 — PASS

- description: forbidden claims absent
- method: `scan tracked + untracked-unignored *.md *.rs *.typ *.toml (case-insensitive), allow-list: docs/CHECKS.md, docs/research/**, xtask/src/gates/claims.rs`

```text
no forbidden phrase in 239 files
```

### C3 — PASS

- description: docs/SPEC.md labels components ESTABLISHED / VYRA-ORIGINAL
- method: `docs/SPEC.md: both tokens present; every row of the first table under the "Components" heading says ESTABLISHED or VYRA-ORIGINAL`

```text
every component row is labelled
```

### P1 — PASS

- description: benchmarks written with all required entries
- method: `cargo xtask bench (release); validate the fresh JSON and the published results/benchmarks.json`

```text
all 66 required entries present in the fresh run and the published file (3 KEM suites, 6 KEM components, 6 signature suites incl. the dual post-quantum ones, 3 SLH-DSA components, seal/open 1 KiB and 1 MiB); published results/benchmarks.* preserved; fresh run copied to target/verify/
```

### P2 — PASS

- description: sizes written from code constants
- method: `cargo xtask sizes (in-process), then validate results/sizes.json`

```text
13 components, 3 KEM, 6 signature and 3 sealed-box suites; every constant equals a generated object's length (SPEC comparison is D3)
```

### D1 — PASS

- description: API docs build with -D warnings; deny(missing_docs)
- method: `RUSTDOCFLAGS=-D warnings cargo doc --workspace --no-deps --locked + check #![deny(missing_docs)] in crates/*/src/lib.rs`

```text
$ cargo doc --workspace --no-deps --locked -> exit Some(0) (0.2 s)
warning: `vyra-cli` (manifest) generated 1 warning
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.19s
   Generated <repo>\target\verify\doc\vyra\index.html and 9 other files
#![deny(missing_docs)] present in every library crate root
```

### D2 — PASS

- description: doctests (included in F2)
- method: `included in F2 (cargo test --workspace runs doctests)`

```text
doctest results counted in F2: exit Some(0), 70 test binaries, 427 passed, 0 failed
```

### D3 — PASS

- description: docs/SPEC.md sizes and suite ids equal results/sizes.json
- method: `every suite's raw+wire pk/sk/ct/sig size from results/sizes.json appears as a number in docs/SPEC.md, and every suite name appears`

```text
54 sizes and all suite identifiers found in docs/SPEC.md
```

### D4 — PASS

- description: paper compiles with typst
- method: `typst compile paper/vyra.typ paper/vyra.pdf`

```text
exit Some(0) (0.4 s)

```

### D5 — PASS

- description: fresh git clone passes F1, F2, F5
- method: `git clone --no-hardlinks <workspace> <temp>; in the clone: cargo build --workspace --all-targets --locked && cargo test --workspace --locked && cargo xtask vectors --check`

```text
commit tested: 2ec648cc1ee710b6630bb82f2df5abbe9e6ecbd3
$ cargo build --workspace --all-targets --locked -> exit Some(0) (23.9 s)
   Compiling xtask v0.1.0 (<tmp>\vyra-d5-39500-1795131367802669700\xtask)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 23.83s
$ cargo test --workspace --locked -> exit Some(0) (589.2 s)
   Doc-tests vyra_sig
   Doc-tests vyra_yield
$ cargo xtask vectors --check -> exit Some(0) (65.8 s)
   = note: `cargo::redundant_homepage` is set to `warn` by default
help: consider removing `package.homepage`
temporary clone deleted
```

### Y1 — PASS

- description: failure-injection tests (cargo test -p vyra-yield)
- method: `cargo test -p vyra-yield --locked`

```text
$ cargo test -p vyra-yield --locked -> exit Some(0), 6 test binaries, 24 passed, 0 failed (98.3 s)
     Running tests\components.rs (target\verify\debug\build\vyra-yield/4a257e9ec3dc1e14\out\components-4a257e9ec3dc1e14.exe)
     Running tests\matrix.rs (target\verify\debug\build\vyra-yield/e4eb4c84d9e825f2\out\matrix-e4eb4c84d9e825f2.exe)
     Running tests\sig.rs (target\verify\debug\build\vyra-yield/ec37d5d44f0fd5e7\out\sig-ec37d5d44f0fd5e7.exe)
   Doc-tests vyra_yield
```

### Y2 — PASS

- description: yield matrix reproducible and verdict pattern as claimed
- method: `cargo run -p vyra-yield --release --locked --bin yield-report -- --out <repo>\target\verify\yield-matrix ; byte-compare yield-matrix.json with results/yield-matrix.json ; check the verdict pattern of the committed JSON`

```text
$ cargo run -p vyra-yield --release --bin yield-report -> exit Some(0) (231.4 s)
fresh yield-matrix.json is byte-identical to results/yield-matrix.json (1868040 bytes)
yield-matrix.md equals the committed one (informational)
cells by primitive: kem 1955, sig 1410; 759 with `expected` (all equal); KEM: 230 Vyra cells with one failed component all NO ATTACK FOUND, 8 Naive single-Malleable cells BROKEN, 15 positive-control groups BROKEN; other families: 0 Vyra single-failure cells (no `expected` field) NO ATTACK FOUND, 1089 cells with no stated expectation (not judged); 31 controls/claim/expectation checks all passed; calibration NO ATTACK FOUND
```

### V1 — PASS

- description: exhaustive enumeration proofs (cargo test -p vyra-proofs)
- method: `cargo test -p vyra-proofs --locked`

```text
$ cargo test -p vyra-proofs --locked -> exit Some(0), 3 test binaries, 7 passed, 0 failed (6.9 s)
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.04s
     Running unittests src\lib.rs (target\verify\debug\build\vyra-proofs/d4dfd2e0dcd4e537\out\vyra_proofs-d4dfd2e0dcd4e537.exe)
     Running tests\exhaustive.rs (target\verify\debug\build\vyra-proofs/810723197f82882e\out\exhaustive-810723197f82882e.exe)
   Doc-tests vyra_proofs
```

### V2 — PASS

- description: bounded model checking report (Kani): harnesses and mutants
- method: `parse results/kani-report.txt (format of tools/kani/in-container.sh): every harness of in-container.sh SUCCESSFUL, every mutant of tools/kani/mutants.tsv with its expected outcome, overall exit status 0; 'status: NOT RUN' -> NOT_RUN`

```text
10 harnesses SUCCESSFUL, 12 mutants with their expected outcome (12 killed, 0 survive as recorded), overall exit status 0
```

### X1 — PASS

- description: research report preserved (SHA-256 pin)
- method: `SHA-256 of docs/research/vyra-deep-research-report.md (raw, LF-normalised, CRLF-normalised) vs recorded 4f46d971c7fa17367ae0e06ba01d22653c22b3f6c8b61a786082d0474d9fd72b`

```text
matches the recorded hash as raw bytes
raw bytes: 4f46d971c7fa17367ae0e06ba01d22653c22b3f6c8b61a786082d0474d9fd72b
LF-normalised: 4f46d971c7fa17367ae0e06ba01d22653c22b3f6c8b61a786082d0474d9fd72b
CRLF-normalised: 06ce4dd0549f184ea997875286abf621c11b7840c8c7545f505e385e3c5ba735
```

### X2 — PASS

- description: no stray changes (git status --porcelain empty)
- method: `git status --porcelain empty at start; afterwards only results/ (rewritten by verify) may differ`

```text
working tree clean at start; 0 results/ file(s) rewritten by this run
```
