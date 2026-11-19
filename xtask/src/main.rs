//! VYRA build and verification tasks, run as `cargo xtask <command>`.
//!
//! Commands:
//!
//! - `vectors [--check]`: write (or byte-compare and re-verify) the VYRA
//!   known-answer vectors in `vectors/` (gate F5);
//! - `sizes`: write `results/sizes.json` and `results/sizes.md` (gate P2);
//! - `bench [--quick]`: wall-clock benchmarks in release mode, written to
//!   `results/benchmarks.json` and `results/benchmarks.md` (gate P1);
//! - `verify [--quick] [--with-kani]`: run every gate of `docs/CHECKS.md`
//!   and write `results/verification-report.json` and `.md`; `--with-kani`
//!   first runs the Docker-based Kani runner (`tools/kani/run.ps1` or
//!   `run.sh`) so that gate V2 judges a fresh report.
//!
//! Everything here is a test harness. It contains no cryptography of its own
//! except an independent hand-framed recomputation of the KEM combiner.

#![forbid(unsafe_code)]

mod bench;
mod cli;
mod envinfo;
mod exec;
mod gates;
mod hex;
mod json;
mod report;
mod sizes;
mod vectors;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// Result type of xtask: errors are human-readable messages.
pub type Res<T> = Result<T, String>;

/// The workspace root (parent of the `xtask` crate directory).
pub fn workspace_root() -> PathBuf {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .map_or_else(|| manifest.to_path_buf(), Path::to_path_buf)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = match cli::parse(&args) {
        Ok(c) => c,
        Err(msg) => {
            eprintln!("error: {msg}\n\n{}", cli::USAGE);
            return ExitCode::from(2);
        }
    };
    let root = workspace_root();
    let result = match command {
        cli::Command::Help => {
            println!("{}", cli::USAGE);
            Ok(true)
        }
        cli::Command::Vectors { check } => vectors::run(&root, check),
        cli::Command::Sizes => sizes::run(&root).map(|()| true),
        cli::Command::Bench { quick } => bench::run(&root, quick).map(|()| true),
        cli::Command::BenchInner { quick } => bench::run_inner(&root, quick).map(|()| true),
        cli::Command::Verify { quick, with_kani } => gates::run(&root, quick, with_kani),
    };
    match result {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(msg) => {
            eprintln!("error: {msg}");
            ExitCode::FAILURE
        }
    }
}
