//! Performance gates: P1 (benchmarks) and P2 (sizes).

use super::{Ctx, Finding};
use crate::{bench, json, sizes};

fn read_json(ctx: &Ctx, rel: &str) -> Result<serde_json::Value, String> {
    let text = std::fs::read_to_string(ctx.root.join(rel))
        .map_err(|e| format!("cannot read {rel}: {e}"))?;
    json::parse(&text, rel)
}

/// The two benchmark result files, relative to the workspace root.
const BENCH_FILES: [&str; 2] = ["results/benchmarks.json", "results/benchmarks.md"];

/// P1: run the benchmarks (quick in quick mode) and validate the JSON they
/// produce. Timings differ on every run, so the published
/// `results/benchmarks.*` (the numbers the documentation and paper quote) are
/// preserved: the fresh run is validated, copied to
/// `target/verify/benchmarks.*`, and the published files are restored and
/// validated too. If no published files exist the fresh run is kept.
pub fn p1(ctx: &mut Ctx, _id: &str) -> Finding {
    let method = if ctx.quick {
        "cargo xtask bench --quick (release); validate the fresh JSON and the published results/benchmarks.json"
    } else {
        "cargo xtask bench (release); validate the fresh JSON and the published results/benchmarks.json"
    };
    let published: Vec<Option<Vec<u8>>> = BENCH_FILES
        .iter()
        .map(|rel| std::fs::read(ctx.root.join(rel)).ok())
        .collect();
    if let Err(e) = bench::run(&ctx.root, ctx.quick) {
        return Finding::check(method, false, e);
    }
    let fresh = read_json(ctx, "results/benchmarks.json");
    let mut notes = Vec::new();
    let scratch = ctx.target_dir();
    for (rel, old) in BENCH_FILES.iter().zip(&published) {
        let path = ctx.root.join(rel);
        if let Some(name) = std::path::Path::new(rel).file_name() {
            let _ = std::fs::create_dir_all(&scratch);
            let _ = std::fs::copy(&path, scratch.join(name));
        }
        if let Some(bytes) = old
            && let Err(e) = std::fs::write(&path, bytes)
        {
            return Finding::check(method, false, format!("cannot restore {rel}: {e}"));
        }
    }
    let mut problems = Vec::new();
    match fresh {
        Err(e) => problems.push(format!("fresh run: {e}")),
        Ok(doc) => problems.extend(
            bench::validate(&doc)
                .into_iter()
                .map(|p| format!("fresh run: {p}")),
        ),
    }
    if published.first().is_some_and(Option::is_some) {
        match read_json(ctx, "results/benchmarks.json") {
            Err(e) => problems.push(format!("published: {e}")),
            Ok(doc) => problems.extend(
                bench::validate(&doc)
                    .into_iter()
                    .map(|p| format!("published: {p}")),
            ),
        }
        notes.push("published results/benchmarks.* preserved; fresh run copied to target/verify/");
    } else {
        notes.push("no published results existed; fresh run kept in results/");
    }
    if problems.is_empty() {
        Finding::check(
            method,
            true,
            format!(
                "all {} required entries present in the fresh run and the published file (3 KEM suites, 6 KEM components, 6 signature suites incl. the dual post-quantum ones, 3 SLH-DSA components, seal/open 1 KiB and 1 MiB); {}",
                bench::required_entries().len(),
                notes.join("; ")
            ),
        )
    } else {
        Finding::check(
            method,
            false,
            problems.join(
                "
",
            ),
        )
    }
}

/// P2: write sizes (asserted against generated objects), then validate the JSON.
pub fn p2(ctx: &mut Ctx, _id: &str) -> Finding {
    let method = "cargo xtask sizes (in-process), then validate results/sizes.json";
    if let Err(e) = sizes::run(&ctx.root) {
        return Finding::check(method, false, e);
    }
    match read_json(ctx, "results/sizes.json") {
        Err(e) => Finding::check(method, false, e),
        Ok(doc) => {
            let problems = sizes::validate(&doc);
            if problems.is_empty() {
                Finding::check(
                    method,
                    true,
                    "13 components, 3 KEM, 6 signature and 3 sealed-box suites; every constant equals a generated object's length (SPEC comparison is D3)",
                )
            } else {
                Finding::check(method, false, problems.join("\n"))
            }
        }
    }
}
