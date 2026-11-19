//! `cargo xtask bench [--quick]`: wall-clock benchmarks (gate P1).
//!
//! The measured code always runs in a release build: if xtask itself was
//! built with debug assertions, `bench` re-executes
//! `cargo run --release -p xtask -- bench-inner`.
//!
//! Method: a warm-up, then N timed iterations of one operation each with
//! `std::time::Instant`, inputs and outputs passed through
//! `std::hint::black_box`. Reported per operation: median, mean, min, p95
//! (nearest rank) and sample standard deviation, in microseconds.
//!
//! Operations that take on the order of a second (the dual post-quantum
//! signature suites and their SLH-DSA components) use their own, smaller
//! iteration counts and a single warm-up run ([`Plan`]); every row records
//! its own `iterations` and `warmup`.

use std::fmt::Write as _;
use std::hint::black_box;
use std::path::Path;
use std::time::Instant;

use serde_json::{Value, json};
use vyra_core::{Kem, OsEntropy, SignatureScheme};
use vyra_kem::{Hqc128, Hqc192, Hqc256, HybridKem, KemSuite, MlKem512, MlKem768, MlKem1024};
use vyra_seal::SealedBox;
use vyra_sig::{CompositeSignature, SigSuite, SlhDsaShake128s, SlhDsaShake192s, SlhDsaShake256s};

use crate::{Res, envinfo, exec, json};

/// Iteration counts.
#[derive(Debug, Clone, Copy)]
struct Plan {
    /// Default (millisecond-scale operations).
    fast: usize,
    /// 1 MiB sealed-box operations.
    large: usize,
    /// SLH-DSA-based key generation (~0.1-0.2 s each).
    slow_keygen: usize,
    /// SLH-DSA-based signing (~1-3 s each).
    slow_sign: usize,
    /// SLH-DSA-based verification (milliseconds).
    slow_verify: usize,
}

/// Untimed warm-up runs before second-scale operations.
const SLOW_WARMUP: usize = 1;

impl Plan {
    fn new(quick: bool) -> Self {
        if quick {
            Plan {
                fast: 20,
                large: 10,
                slow_keygen: 3,
                slow_sign: 2,
                slow_verify: 20,
            }
        } else {
            Plan {
                fast: 200,
                large: 50,
                slow_keygen: 20,
                slow_sign: 10,
                slow_verify: 200,
            }
        }
    }
}

fn warmup_for(iterations: usize) -> usize {
    (iterations / 10).max(3)
}

/// Summary statistics in microseconds.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Stats {
    /// Median.
    pub median: f64,
    /// Arithmetic mean.
    pub mean: f64,
    /// Minimum.
    pub min: f64,
    /// 95th percentile (nearest rank).
    pub p95: f64,
    /// Sample standard deviation.
    pub stddev: f64,
}

/// Statistics of `samples` (microseconds). Empty input gives all zeros.
pub fn stats(samples: &[f64]) -> Stats {
    let mut v = samples.to_vec();
    v.sort_by(f64::total_cmp);
    let n = v.len();
    if n == 0 {
        return Stats {
            median: 0.0,
            mean: 0.0,
            min: 0.0,
            p95: 0.0,
            stddev: 0.0,
        };
    }
    let at = |i: usize| v.get(i).copied().unwrap_or(0.0);
    let median = if n % 2 == 1 {
        at(n / 2)
    } else {
        (at(n / 2 - 1) + at(n / 2)) / 2.0
    };
    let mean = v.iter().sum::<f64>() / n as f64;
    let rank = ((0.95 * n as f64).ceil() as usize).clamp(1, n);
    let var = if n > 1 {
        v.iter().map(|x| (x - mean) * (x - mean)).sum::<f64>() / (n - 1) as f64
    } else {
        0.0
    };
    Stats {
        median,
        mean,
        min: at(0),
        p95: at(rank - 1),
        stddev: var.sqrt(),
    }
}

/// Time `op` `iterations` times after `warmup_for(iterations)` untimed runs.
fn measure<T>(iterations: usize, op: impl FnMut() -> T) -> Vec<f64> {
    measure_with(warmup_for(iterations), iterations, op)
}

/// Time `op` `iterations` times after `warmup` untimed runs.
fn measure_with<T>(warmup: usize, iterations: usize, mut op: impl FnMut() -> T) -> Vec<f64> {
    for _ in 0..warmup {
        black_box(op());
    }
    let mut samples = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let t = Instant::now();
        black_box(op());
        samples.push(t.elapsed().as_secs_f64() * 1e6);
    }
    samples
}

fn round3(x: f64) -> f64 {
    (x * 1000.0).round() / 1000.0
}

struct Recorder {
    rows: Vec<Value>,
}

impl Recorder {
    fn add(&mut self, group: &str, name: &str, op: &str, iterations: usize, samples: &[f64]) {
        self.add_with(group, name, op, iterations, warmup_for(iterations), samples);
    }

    fn add_with(
        &mut self,
        group: &str,
        name: &str,
        op: &str,
        iterations: usize,
        warmup: usize,
        samples: &[f64],
    ) {
        let s = stats(samples);
        println!(
            "  {group:<14} {name:<12} {op:<14} n={iterations:<4} median {:>12.1} us  p95 {:>12.1} us",
            s.median, s.p95
        );
        self.rows.push(json!({
            "group": group,
            "name": name,
            "op": op,
            "iterations": iterations,
            "warmup": warmup,
            "median_us": round3(s.median),
            "mean_us": round3(s.mean),
            "min_us": round3(s.min),
            "p95_us": round3(s.p95),
            "stddev_us": round3(s.stddev),
        }));
    }
}

fn err(ctx: &str) -> impl Fn(vyra_core::Error) -> String + '_ {
    move |e| format!("bench {ctx}: {e}")
}

fn bench_kem(rec: &mut Recorder, group: &str, k: &dyn Kem, n: usize) -> Res<()> {
    let mut rng = OsEntropy::new();
    let name = k.name();
    let (pk, sk) = k.generate_keypair(&mut rng).map_err(err(name))?;
    let (ct, _) = k.encapsulate(&pk, &mut rng).map_err(err(name))?;
    k.decapsulate(sk.expose(), &ct).map_err(err(name))?;
    let s = measure(n, || k.generate_keypair(&mut rng));
    rec.add(group, name, "keygen", n, &s);
    let s = measure(n, || k.encapsulate(black_box(&pk), &mut rng));
    rec.add(group, name, "encaps", n, &s);
    let s = measure(n, || k.decapsulate(black_box(sk.expose()), black_box(&ct)));
    rec.add(group, name, "decaps", n, &s);
    Ok(())
}

/// `(keygen, sign, verify)` iteration counts and the warm-up for each, for
/// a fast (`slow == false`) or second-scale signature scheme.
fn sig_counts(plan: Plan, slow: bool) -> [(usize, usize); 3] {
    if slow {
        [
            (plan.slow_keygen, SLOW_WARMUP),
            (plan.slow_sign, SLOW_WARMUP),
            (plan.slow_verify, warmup_for(plan.slow_verify)),
        ]
    } else {
        [(plan.fast, warmup_for(plan.fast)); 3]
    }
}

fn bench_sig(rec: &mut Recorder, suite: SigSuite, plan: Plan) -> Res<()> {
    let mut rng = OsEntropy::new();
    let name = suite.name();
    let scheme = CompositeSignature::new(suite);
    let msg = vec![0xa5u8; 1024];
    let ctx: &[u8] = b"bench";
    let (pk, sk) = scheme.generate(&mut rng).map_err(err(name))?;
    let sig = scheme.sign(&sk, &msg, ctx, &mut rng).map_err(err(name))?;
    scheme.verify(&pk, &msg, ctx, &sig).map_err(err(name))?;
    let [(nk, wk), (ns, ws), (nv, wv)] = sig_counts(plan, suite.is_dual_pq());
    let s = measure_with(wk, nk, || scheme.generate(&mut rng));
    rec.add_with("sig-suite", name, "keygen", nk, wk, &s);
    let s = measure_with(ws, ns, || scheme.sign(&sk, black_box(&msg), ctx, &mut rng));
    rec.add_with("sig-suite", name, "sign-1KiB", ns, ws, &s);
    let s = measure_with(wv, nv, || {
        scheme.verify(&pk, black_box(&msg), ctx, black_box(&sig))
    });
    rec.add_with("sig-suite", name, "verify-1KiB", nv, wv, &s);
    Ok(())
}

/// A standalone signature component (empty context), second-scale counts.
fn bench_sig_component(rec: &mut Recorder, s: &dyn SignatureScheme, plan: Plan) -> Res<()> {
    let mut rng = OsEntropy::new();
    let name = s.name();
    let msg = vec![0xa5u8; 1024];
    let (pk, sk) = s.generate_keypair(&mut rng).map_err(err(name))?;
    let sig = s.sign(sk.expose(), &msg, &mut rng).map_err(err(name))?;
    s.verify(&pk, &msg, &sig).map_err(err(name))?;
    let [(nk, wk), (ns, ws), (nv, wv)] = sig_counts(plan, true);
    let t = measure_with(wk, nk, || s.generate_keypair(&mut rng));
    rec.add_with("sig-component", name, "keygen", nk, wk, &t);
    let t = measure_with(ws, ns, || {
        s.sign(black_box(sk.expose()), black_box(&msg), &mut rng)
    });
    rec.add_with("sig-component", name, "sign-1KiB", ns, ws, &t);
    let t = measure_with(wv, nv, || {
        s.verify(black_box(&pk), black_box(&msg), black_box(&sig))
    });
    rec.add_with("sig-component", name, "verify-1KiB", nv, wv, &t);
    Ok(())
}

/// The SLH-DSA components benchmarked on their own.
const SLH_DSA_COMPONENTS: [&str; 3] = [
    "SLH-DSA-SHAKE-128s",
    "SLH-DSA-SHAKE-192s",
    "SLH-DSA-SHAKE-256s",
];

fn bench_seal(rec: &mut Recorder, suite: KemSuite, plan: Plan) -> Res<()> {
    let mut rng = OsEntropy::new();
    let name = suite.name();
    let (pk, sk) = HybridKem::new(suite)
        .generate(&mut rng)
        .map_err(err(name))?;
    let sbox = SealedBox::new(suite);
    for (label, len, n) in [
        ("1KiB", 1024usize, plan.fast),
        ("1MiB", 1 << 20, plan.large),
    ] {
        let pt = vec![0x5au8; len];
        let sealed = sbox.seal(&pk, b"aad", &pt, &mut rng).map_err(err(name))?;
        sbox.open(&sk, b"aad", &sealed).map_err(err(name))?;
        let s = measure(n, || sbox.seal(&pk, b"aad", black_box(&pt), &mut rng));
        rec.add("seal", name, &format!("seal-{label}"), n, &s);
        let s = measure(n, || sbox.open(&sk, b"aad", black_box(&sealed)));
        rec.add("seal", name, &format!("open-{label}"), n, &s);
    }
    Ok(())
}

/// `(group, name, op)` triples `results/benchmarks.json` must contain.
pub fn required_entries() -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    let mut add = |g: &str, n: &str, ops: &[&str]| {
        for op in ops {
            out.push((g.to_string(), n.to_string(), (*op).to_string()));
        }
    };
    for s in KemSuite::all() {
        add("kem-suite", s.name(), &["keygen", "encaps", "decaps"]);
    }
    for c in [
        "ML-KEM-512",
        "ML-KEM-768",
        "ML-KEM-1024",
        "HQC-128",
        "HQC-192",
        "HQC-256",
    ] {
        add("kem-component", c, &["keygen", "encaps", "decaps"]);
    }
    for s in SigSuite::all() {
        add(
            "sig-suite",
            s.name(),
            &["keygen", "sign-1KiB", "verify-1KiB"],
        );
    }
    for c in SLH_DSA_COMPONENTS {
        add("sig-component", c, &["keygen", "sign-1KiB", "verify-1KiB"]);
    }
    for s in KemSuite::all() {
        add(
            "seal",
            s.name(),
            &["seal-1KiB", "open-1KiB", "seal-1MiB", "open-1MiB"],
        );
    }
    out
}

/// Missing or malformed entries of a benchmarks document.
pub fn validate(doc: &Value) -> Vec<String> {
    let mut problems = Vec::new();
    let rows = doc
        .get("results")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let s = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    for (g, n, op) in required_entries() {
        let row = rows
            .iter()
            .find(|r| s(r, "group") == g && s(r, "name") == n && s(r, "op") == op);
        match row {
            None => problems.push(format!("benchmarks.json: missing {g}/{n}/{op}")),
            Some(r) => {
                for key in ["median_us", "mean_us", "min_us", "p95_us", "stddev_us"] {
                    if r.get(key).and_then(Value::as_f64).is_none() {
                        problems.push(format!("benchmarks.json: {g}/{n}/{op} lacks {key}"));
                    }
                }
                if r.get("iterations").and_then(Value::as_u64).unwrap_or(0) == 0 {
                    problems.push(format!("benchmarks.json: {g}/{n}/{op} has no iterations"));
                }
            }
        }
    }
    for key in [
        "cpu",
        "os",
        "rustc",
        "date_utc",
        "crate_versions",
        "profile",
    ] {
        if doc.get("environment").and_then(|e| e.get(key)).is_none() {
            problems.push(format!("benchmarks.json: environment.{key} missing"));
        }
    }
    problems
}

fn profile_overrides(root: &Path) -> String {
    let text = std::fs::read_to_string(root.join("Cargo.toml")).unwrap_or_default();
    let mut inside = false;
    let mut lines = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            inside = t.starts_with("[profile.release");
        }
        if inside {
            lines.push(t.to_string());
        }
    }
    if lines.is_empty() {
        "none (workspace Cargo.toml has no [profile.release]; cargo defaults: opt-level=3, lto=false, codegen-units=16, debug=false)".to_string()
    } else {
        lines.join("; ")
    }
}

fn environment(root: &Path, plan: Plan, quick: bool) -> Value {
    let mut versions = serde_json::Map::new();
    for (name, version) in envinfo::locked_versions(
        root,
        &[
            "ml-kem",
            "vyra-hqc",
            "ml-dsa",
            "ed25519-dalek",
            "fips205",
            "chacha20poly1305",
            "sha3",
        ],
    ) {
        let entry = versions
            .entry(name)
            .or_insert_with(|| Value::Array(Vec::new()));
        if let Value::Array(a) = entry {
            a.push(json!(version));
        }
    }
    json!({
        "cpu": envinfo::cpu_brand(),
        "logical_cpus": envinfo::logical_cpus(),
        "os": envinfo::os(),
        "rustc": envinfo::rustc_version(),
        "date_utc": envinfo::utc_now(),
        "crate_versions": versions,
        "profile": {
            "name": "release",
            "debug_assertions": cfg!(debug_assertions),
            "overrides": profile_overrides(root),
        },
        "iterations": {
            "quick": quick,
            "default_ops": plan.fast,
            "one_mib_ops": plan.large,
            "slh_dsa_keygen_ops": plan.slow_keygen,
            "slh_dsa_sign_ops": plan.slow_sign,
            "slh_dsa_verify_ops": plan.slow_verify,
            "warmup": "max(3, iterations / 10) untimed runs before timing; 1 run before SLH-DSA-based keygen and sign (dual post-quantum suites and sig-component rows); each row records its own warmup",
        },
        "entropy": "OsEntropy (operating-system RNG) for all measured operations",
    })
}

fn markdown(doc: &Value) -> String {
    let env = doc.get("environment").cloned().unwrap_or_default();
    let es = |k: &str| {
        env.get(k)
            .map(|v| v.as_str().map_or_else(|| v.to_string(), str::to_string))
            .unwrap_or_default()
    };
    let mut s = String::from(
        "# VYRA benchmarks\n\n\
         **Read this first.** These are wall-clock timings on one machine, taken with \
         `std::time::Instant` around single operations. They are not cycle-accurate, are \
         affected by frequency scaling and background load, and are **not a constant-time \
         evaluation**: nothing here says anything about timing side channels.\n\n",
    );
    let _ = writeln!(s, "- CPU: {}", es("cpu"));
    let _ = writeln!(s, "- OS: {}", es("os"));
    let _ = writeln!(s, "- rustc: {}", es("rustc"));
    let _ = writeln!(s, "- date (UTC): {}", es("date_utc"));
    let _ = writeln!(s, "- crate versions: {}", es("crate_versions"));
    let _ = writeln!(s, "- profile: {}", es("profile"));
    let _ = writeln!(s, "- iterations: {}", es("iterations"));
    s.push_str("\nAll times in microseconds (us).\n");
    let rows = doc
        .get("results")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut groups: Vec<String> = Vec::new();
    for r in &rows {
        let g = r
            .get("group")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        if !groups.contains(&g) {
            groups.push(g);
        }
    }
    for g in groups {
        let _ = write!(
            s,
            "\n## {g}\n\n| name | op | n | median | mean | min | p95 | stddev |\n|---|---|---|---|---|---|---|---|\n"
        );
        for r in rows
            .iter()
            .filter(|r| r.get("group").and_then(Value::as_str) == Some(g.as_str()))
        {
            let t = |k: &str| r.get(k).and_then(Value::as_str).unwrap_or("").to_string();
            let f = |k: &str| {
                r.get(k)
                    .and_then(Value::as_f64)
                    .map_or("-".into(), |x| format!("{x:.1}"))
            };
            let _ = writeln!(
                s,
                "| {} | {} | {} | {} | {} | {} | {} | {} |",
                t("name"),
                t("op"),
                r.get("iterations").and_then(Value::as_u64).unwrap_or(0),
                f("median_us"),
                f("mean_us"),
                f("min_us"),
                f("p95_us"),
                f("stddev_us")
            );
        }
    }
    s
}

/// `cargo xtask bench`: run in release, re-executing if needed.
pub fn run(root: &Path, quick: bool) -> Res<()> {
    if !cfg!(debug_assertions) {
        return run_inner(root, quick);
    }
    println!("xtask is a debug build; re-running the benchmarks with `cargo run --release`");
    let mut args = vec![
        "run",
        "--release",
        "--quiet",
        "-p",
        "xtask",
        "--",
        "bench-inner",
    ];
    if quick {
        args.push("--quick");
    }
    let status = std::process::Command::new(exec::cargo())
        .args(&args)
        .current_dir(root)
        .status()
        .map_err(|e| format!("could not start cargo: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("release benchmark run failed ({status})"))
    }
}

/// The measuring process. Refuses to run with debug assertions.
pub fn run_inner(root: &Path, quick: bool) -> Res<()> {
    if cfg!(debug_assertions) {
        return Err("bench-inner must run in a release build (use `cargo xtask bench`)".into());
    }
    let plan = Plan::new(quick);
    let mut rec = Recorder { rows: Vec::new() };
    println!(
        "benchmarking ({} iterations, 1 MiB: {})",
        plan.fast, plan.large
    );
    for suite in KemSuite::all() {
        bench_kem(&mut rec, "kem-suite", &HybridKem::new(suite), plan.fast)?;
    }
    let comps: [&dyn Kem; 6] = [&MlKem512, &MlKem768, &MlKem1024, &Hqc128, &Hqc192, &Hqc256];
    for c in comps {
        bench_kem(&mut rec, "kem-component", c, plan.fast)?;
    }
    for suite in SigSuite::all() {
        bench_sig(&mut rec, suite, plan)?;
    }
    let slh: [&dyn SignatureScheme; 3] = [&SlhDsaShake128s, &SlhDsaShake192s, &SlhDsaShake256s];
    for c in slh {
        bench_sig_component(&mut rec, c, plan)?;
    }
    for suite in KemSuite::all() {
        bench_seal(&mut rec, suite, plan)?;
    }
    let doc = json!({
        "generator": "cargo xtask bench",
        "method": "warm-up, then N timed iterations of one operation each (std::time::Instant, std::hint::black_box); median, mean, min, p95 (nearest rank), sample stddev in microseconds",
        "disclaimer": "wall-clock on one machine; not cycle-accurate; not a constant-time evaluation",
        "environment": environment(root, plan, quick),
        "results": rec.rows,
    });
    let problems = validate(&doc);
    if !problems.is_empty() {
        return Err(problems.join("; "));
    }
    let dir = root.join("results");
    std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    std::fs::write(dir.join("benchmarks.json"), json::to_canonical(&doc))
        .map_err(|e| format!("write benchmarks.json: {e}"))?;
    std::fs::write(dir.join("benchmarks.md"), markdown(&doc))
        .map_err(|e| format!("write benchmarks.md: {e}"))?;
    println!("wrote results/benchmarks.json and results/benchmarks.md");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statistics() {
        let s = stats(&[5.0, 1.0, 3.0, 2.0, 4.0]);
        assert_eq!(s.median, 3.0);
        assert_eq!(s.mean, 3.0);
        assert_eq!(s.min, 1.0);
        assert_eq!(s.p95, 5.0);
        assert!((s.stddev - 2.5f64.sqrt()).abs() < 1e-12);
        let e = stats(&[2.0, 4.0]);
        assert_eq!(e.median, 3.0);
        assert_eq!(stats(&[]).mean, 0.0);
        let hundred: Vec<f64> = (1..=100).map(f64::from).collect();
        assert_eq!(stats(&hundred).p95, 95.0);
    }

    #[test]
    fn validation_reports_missing() {
        let problems = validate(&json!({"results": [], "environment": {}}));
        assert!(
            problems
                .iter()
                .any(|p| p.contains("kem-suite/VYRA-KEM-1/keygen"))
        );
        assert!(
            problems
                .iter()
                .any(|p| p.contains("seal/VYRA-KEM-5/open-1MiB"))
        );
        assert!(problems.iter().any(|p| p.contains("environment.cpu")));
        assert!(
            problems
                .iter()
                .any(|p| p.contains("sig-suite/VYRA-SIG-PQ5/sign-1KiB"))
        );
        assert!(
            problems
                .iter()
                .any(|p| p.contains("sig-component/SLH-DSA-SHAKE-128s/keygen"))
        );
        // 3 KEM suites, 6 KEM components, 6 signature suites, 3 SLH-DSA
        // components (3 ops each), 3 sealed-box suites (4 ops each).
        assert_eq!(required_entries().len(), 9 + 18 + 18 + 9 + 12);
    }

    #[test]
    fn slow_plans_are_smaller_and_component_names_match() {
        for quick in [false, true] {
            let p = Plan::new(quick);
            assert!(p.slow_sign < p.slow_keygen && p.slow_keygen <= p.slow_verify);
            assert!(p.slow_sign <= p.fast / 10);
        }
        let names: Vec<&str> = [
            &SlhDsaShake128s as &dyn SignatureScheme,
            &SlhDsaShake192s,
            &SlhDsaShake256s,
        ]
        .iter()
        .map(|s| s.name())
        .collect();
        assert_eq!(names, SLH_DSA_COMPONENTS);
    }
}
