//! Run the full yielding-resistance matrix (KEM and signatures) and write
//! `<out>/yield-matrix.json` and `<out>/yield-matrix.md`.
//!
//! ```text
//! yield-report --out <dir> [--trials N] [--sig-trials N] [--pq-trials N]
//!              [--seed S] [--threads T]
//! ```
//!
//! Exits 0 if every control passed, 1 if any control failed (the report is
//! still written), 2 on usage or I/O errors. A Vyra claim check that fails is
//! a *finding*: it is reported prominently but does not change the exit code.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

use vyra_yield::controls::{evaluate_controls, evaluate_kem_expectations, evaluate_vyra_claims};
use vyra_yield::experiment::{
    DEFAULT_SEED, DEFAULT_TRIALS, coin_flip_calibration, default_plan, run_matrix,
};
use vyra_yield::report::{Report, to_json, to_markdown};
use vyra_yield::sig::controls::{evaluate_sig_claims, evaluate_sig_controls};
use vyra_yield::sig::experiment::{
    DEFAULT_PQ_TRIALS, DEFAULT_SIG_TRIALS, garbage_calibration, run_sig_matrix,
};

struct Args {
    out: PathBuf,
    trials: u64,
    sig_trials: u64,
    pq_trials: u64,
    seed: String,
    threads: usize,
}

fn parse() -> Result<Args, String> {
    let mut out = None;
    let mut trials = DEFAULT_TRIALS;
    let mut sig_trials = DEFAULT_SIG_TRIALS;
    let mut pq_trials = DEFAULT_PQ_TRIALS;
    let mut seed = DEFAULT_SEED.to_string();
    let mut threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        let mut value = || it.next().ok_or(format!("missing value for {a}"));
        match a.as_str() {
            "--out" => out = Some(PathBuf::from(value()?)),
            "--trials" => trials = value()?.parse().map_err(|e| format!("--trials: {e}"))?,
            "--sig-trials" => {
                sig_trials = value()?.parse().map_err(|e| format!("--sig-trials: {e}"))?;
            }
            "--pq-trials" => {
                pq_trials = value()?.parse().map_err(|e| format!("--pq-trials: {e}"))?;
            }
            "--seed" => seed = value()?,
            "--threads" => threads = value()?.parse().map_err(|e| format!("--threads: {e}"))?,
            other => return Err(format!("unknown argument {other}")),
        }
    }
    Ok(Args {
        out: out.ok_or("--out <dir> is required")?,
        trials,
        sig_trials,
        pq_trials,
        seed,
        threads,
    })
}

fn run(args: &Args) -> Result<bool, String> {
    let start = Instant::now();
    let plan = default_plan();
    eprintln!(
        "yield-report: KEM {} cells x {} trials, {} threads",
        plan.len(),
        args.trials,
        args.threads
    );
    let results =
        run_matrix(&plan, &args.seed, args.trials, args.threads).map_err(|e| e.to_string())?;
    let calibration = coin_flip_calibration(&args.seed, args.trials.saturating_mul(10))
        .map_err(|e| e.to_string())?;
    eprintln!(
        "yield-report: KEM done after {:.1} s",
        start.elapsed().as_secs_f64()
    );
    let sig_results = run_sig_matrix(&args.seed, args.sig_trials, args.pq_trials, args.threads)
        .map_err(|e| e.to_string())?;
    let sig_calibration = garbage_calibration(&args.seed, args.sig_trials.saturating_mul(10))
        .map_err(|e| e.to_string())?;
    eprintln!(
        "yield-report: signatures done ({} cells) after {:.1} s",
        sig_results.len(),
        start.elapsed().as_secs_f64()
    );
    let controls = evaluate_controls(&results);
    let claims = evaluate_vyra_claims(&results);
    let expectations = evaluate_kem_expectations(&results);
    let sig_controls = evaluate_sig_controls(&sig_results);
    let sig_claims = evaluate_sig_claims(&sig_results);
    let rep = Report {
        master_seed: &args.seed,
        trials: args.trials,
        results: &results,
        calibration: &calibration,
        controls: &controls,
        claims: &claims,
        expectations: &expectations,
        sig_trials: args.sig_trials,
        sig_pq_trials: args.pq_trials,
        sig_results: &sig_results,
        sig_calibration: &sig_calibration,
        sig_controls: &sig_controls,
        sig_claims: &sig_claims,
    };
    std::fs::create_dir_all(&args.out).map_err(|e| e.to_string())?;
    std::fs::write(args.out.join("yield-matrix.json"), to_json(&rep)).map_err(|e| e.to_string())?;
    std::fs::write(args.out.join("yield-matrix.md"), to_markdown(&rep))
        .map_err(|e| e.to_string())?;
    for c in controls
        .iter()
        .chain(&claims)
        .chain(&expectations)
        .chain(&sig_controls)
        .chain(&sig_claims)
    {
        eprintln!(
            "{:18} {:4} ({} cells) {}",
            c.id,
            if c.passed { "PASS" } else { "FAIL" },
            c.cells_checked,
            c.description
        );
        for m in &c.mismatches {
            eprintln!("    mismatch: {m}");
        }
    }
    eprintln!("yield-report: total {:.1} s", start.elapsed().as_secs_f64());
    let controls_ok = controls
        .iter()
        .chain(&sig_controls)
        .chain(expectations.iter().filter(|c| !c.id.starts_with("claim:")))
        .all(|c| c.passed);
    Ok(controls_ok)
}

fn main() -> ExitCode {
    let args = match parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("yield-report: {e}");
            return ExitCode::from(2);
        }
    };
    match run(&args) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => {
            eprintln!("yield-report: a control FAILED; the harness or an expectation is wrong");
            ExitCode::from(1)
        }
        Err(e) => {
            eprintln!("yield-report: {e}");
            ExitCode::from(2)
        }
    }
}
