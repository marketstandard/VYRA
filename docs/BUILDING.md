# Building VYRA

This document describes a reproducible build of VYRA from a clean environment on Windows, Linux and macOS. Run every command from the root of the repository.

## Requirements

- `git`, to get the source.
- Rust, installed with rustup. The toolchain is pinned by `rust-toolchain.toml` (`channel = "stable"`, with the `rustfmt` and `clippy` components). rustup installs it automatically the first time you run a `cargo` command inside the repository.
- The minimum supported Rust version is 1.88, tested with `cargo +1.88 test --workspace --locked` (`rust-version` in the root `Cargo.toml`). The crates use edition 2024.
- No C compiler is needed by the crates.
- Optional: Docker (Docker Desktop with Linux containers on Windows), only for the Kani bounded-model-checking run in step 7. Nothing else needs it.

The workspace is committed with a `Cargo.lock`. Every command below passes `--locked`, so cargo builds exactly the versions recorded there and fails if the lock file would need to change.

## 1. Install rustup

### Windows

Download `rustup-init.exe` from [rustup.rs](https://rustup.rs) and run it. Accept the default host toolchain (`x86_64-pc-windows-msvc`).

The MSVC toolchain links with `link.exe` from the Microsoft Visual Studio Build Tools. If the linker is missing, install the Build Tools with the "Desktop development with C++" workload, then open a new terminal.

### Linux

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
. "$HOME/.cargo/env"
```

### macOS

```sh
xcode-select --install
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
. "$HOME/.cargo/env"
```

`xcode-select --install` provides the system linker. It can be skipped if the Command Line Tools are already installed.

## 2. Get the source

```sh
git clone https://github.com/marketstandard/VYRA.git vyra
cd vyra
```

## 3. Check the toolchain

```sh
rustup show
cargo --version
```

`rustup show` should report the stable toolchain for this directory. The `rust-toolchain.toml` file selects it.

## 4. Build, test and check

| Step | Command | Purpose |
|------|---------|---------|
| Build | `cargo build --workspace --locked` | Compile every crate and binary |
| Test | `cargo test --workspace --locked` | Run unit, integration and property tests, and doctests |
| Doctests only | `cargo test -p vyra --doc --locked` | Run the examples in the `vyra` crate documentation |
| Lint | `cargo clippy --workspace --all-targets --locked -- -D warnings` | Lint all targets; any warning fails |
| Format check | `cargo fmt --all --check` | Check formatting without changing files |
| API docs | `cargo doc --workspace --no-deps --locked` | Build the documentation |

To build the API docs with warnings treated as errors, set `RUSTDOCFLAGS` first.

Bash:

```sh
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
```

PowerShell:

```powershell
$env:RUSTDOCFLAGS = "-D warnings"
cargo doc --workspace --no-deps --locked
Remove-Item Env:RUSTDOCFLAGS
```

## 5. Run the demo and the examples

The demo runs every suite in memory and checks the results:

```sh
cargo run -p vyra-cli --locked -- demo
```

It prints one line per check and ends with `PASS: all 75 checks passed` when every check succeeds. It exits with status 0 only in that case. Every signature suite, including the three dual post-quantum suites (ML-DSA + SLH-DSA), runs the full set of six signature checks; each dual post-quantum suite makes one SLH-DSA-based signature, which takes seconds, and the demo prints the time each signature suite took. Expect roughly 10-30 s in a debug build and less with `--release`.

The command-line tool also has an information command and a help command:

```sh
cargo run -p vyra-cli --locked -- info
cargo run -p vyra-cli --locked -- help
```

The `vyra` crate has five examples in `crates/vyra/examples/`:

```sh
cargo run -p vyra --example handshake
cargo run -p vyra --example handshake -- --pq
cargo run -p vyra --example kem
cargo run -p vyra --example sign
cargo run --release -p vyra --example sign_pq
cargo run -p vyra --example seal
```

`handshake` uses ephemeral key pairs for a single exchange. It is an illustration, not an analysed protocol. By default the responder signs with the transition suite VYRA-SIG-3; `--pq` switches it to the dual post-quantum suite VYRA-SIG-PQ3. `sign` covers the transition suites (VYRA-SIG-2/3/5). `sign_pq` covers the dual post-quantum suites (VYRA-SIG-PQ1/3/5) and prints sizes and timings; each signature takes seconds, so run it with `--release`. Pass `pq1`, `pq3` or `pq5` to run one suite only.

## 6. Run the verification tasks

The repository's task runner is `xtask`. The `cargo xtask` alias is defined in `.cargo/config.toml`.

```sh
cargo xtask help
cargo xtask verify
cargo xtask verify --quick
cargo xtask verify --with-kani
cargo xtask vectors --check
cargo xtask vectors
cargo xtask sizes
cargo xtask bench
```

- `cargo xtask verify` runs every gate in `docs/CHECKS.md` (37 gates) and writes `results/verification-report.json` and `results/verification-report.md`. It accepts `--quick` (shorter benchmarks and clone check) and `--with-kani` (see below). Some gates may end NOT_RUN in stated cases only (no `cargo audit`, no `typst`, no Kani report, and X2 in quick mode); NOT_RUN is never a pass.
- `cargo xtask vectors --check` regenerates `vectors/*.json` from fixed seeds and compares the bytes with the committed files. `cargo xtask vectors` writes the files instead. The dual post-quantum signature suites have two vectors each instead of five, because every SLH-DSA signature takes seconds; the check takes well under a minute.
- `cargo xtask sizes` writes `results/sizes.json` and `results/sizes.md`.
- `cargo xtask bench` writes `results/benchmarks.json` and `results/benchmarks.md`. It accepts `--quick`. The dual post-quantum suites and the SLH-DSA components use smaller iteration counts (sign 10, key generation 20, verify 200; `--quick`: 2, 3 and 20), so a full run takes several minutes.

### Yielding resistance and machine-checked properties

```sh
cargo test -p vyra-yield --locked
cargo run -p vyra-yield --release --locked --bin yield-report -- --out results/
cargo test -p vyra-proofs --locked
```

- `vyra-yield` runs the failure-injection experiment: the hybrid KEM combiner and the composite signature, each next to comparison designs, over deliberately broken (intentionally insecure) toy components in explicit security games. `yield-report` writes `results/yield-matrix.json` and `results/yield-matrix.md`; the output is deterministic (about 2 minutes in release on a many-core machine). Gate Y2 regenerates it into `target/verify/` and requires a byte-identical JSON. The results are falsification evidence, not a proof.
- `vyra-proofs` checks properties of VYRA's own encodings (wire header, transcript framing, constant-time equality, entropy adapter) by exhaustive enumeration over stated finite domains (gate V1).

### Bounded model checking with Kani (optional, needs Docker)

Kani does not run natively on Windows; the runner uses a pinned Docker image (`tools/kani/Dockerfile`) and mounts the repository read-only.

Windows (PowerShell, Docker Desktop running with Linux containers):

```powershell
powershell -File tools\kani\run.ps1
```

Linux and macOS:

```sh
tools/kani/run.sh
```

Either runner builds the image, runs every harness and every mutant of `tools/kani/mutants.tsv`, and writes `results/kani-report.txt`. A run takes minutes to hours. Gate V2 judges that report: every harness SUCCESSFUL and every mutant with its expected outcome. If the report is missing or says `status: NOT RUN`, V2 is NOT_RUN, never PASS. `cargo xtask verify --with-kani` runs the runner first and then judges the fresh report. Bounded model checking covers only VYRA's own encodings within the bounds stated in the harnesses; it says nothing about the cryptographic components.

Benchmark results depend on the machine, so they are not recorded in this document. Passing the verification gates shows functional correctness, implementation hygiene and the machine-checked properties listed in `docs/CHECKS.md`. It does not show that VYRA is cryptographically sound.

Continuous integration is split in two so that a pull request gets an answer in minutes. `.github/workflows/ci.yml` runs `cargo fmt --all --check`, `cargo clippy` and `cargo test` on every pull request and every push to `main`, on one `macos-latest` runner (about 7 minutes). `.github/workflows/full-verify.yml` runs `cargo xtask verify` on `macos-latest` and the test suite on `ubuntu-latest` and `windows-latest`; it runs weekly while the repository is public and whenever a maintainer starts it by hand. The arm64 macOS runners are used for the heavy jobs because the test suite, which is dominated by SHA-3 and SLH-DSA, runs about eight times faster there than on the x86-64 Linux runners.

## 8. Build the paper

The paper is written in Typst. Install the compiler once:

```sh
cargo install typst-cli --locked
```

Then compile the paper:

```sh
typst compile paper/vyra.typ paper/vyra.pdf
```


## Expected run times

Varies with the machine, the number of cores and the network speed. The first build is much slower than later builds. Measured on the development machine (32 logical CPUs, loaded): `vyra demo` about 26 s (debug) and 17 s (release); `cargo xtask vectors --check` about 40 s; `yield-report` about 2 minutes; `cargo test -p vyra-yield` about 1 minute; a Kani run minutes to hours.

## Troubleshooting

- **The first build downloads crates.** Cargo fetches the locked dependencies from the crates registry the first time, so the first build needs network access. Later builds reuse the local cache.
- **`the lock file needs to be updated but --locked was passed`.** The committed `Cargo.lock` no longer matches the manifests. Do not remove `--locked`. Find the manifest change that caused the mismatch and fix or review it.
- **A linker error on Windows.** Install the Visual Studio Build Tools as described in step 1.
- **A test named `hqc_version_pin` fails.** The `hqc-kem` dependency is pinned to `=0.1.0-rc.0`. The test fails if that version moves. This is intended. See `docs/DECISIONS.md` D-11 before changing the pin.
- **Docker is not running.** `tools/kani/run.ps1` stops with "Docker daemon not reachable". Start Docker Desktop (or the Docker service) first; without Docker, gate V2 stays NOT_RUN.
- **Dual post-quantum signatures are slow.** Signing with VYRA-SIG-PQ1/3/5 takes seconds per signature by design (SLH-DSA "s" parameter sets); this is not a hang.
- **The tests take a few minutes.** `cargo test` builds and runs in debug mode, which is the default profile here. Expect a few minutes for the full workspace run.
- **A clean rebuild.** `cargo clean` removes the `target/` directory. The next build recreates it.
- **PowerShell does not accept `RUSTDOCFLAGS="..."`.** Use the `$env:` form shown in step 4.
