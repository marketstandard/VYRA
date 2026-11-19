//! Gates that run cargo: F1, F2, F9, S8, S11, S12, D1 and the test-mapped
//! gates (F3, F4, F6, F7, F8, S1–S6, S9 tests, S10).

use super::{Ctx, Finding, rel, rs_files, secs};
use crate::exec::{self, Outcome};
use crate::report::Status;

/// Gate → named test targets `(crate, --test target)` that evidence it.
///
/// A gate is FAIL if any mapped target file is missing, its run exits
/// non-zero, or it reports zero passed tests.
pub const TEST_MAP: &[(&str, &[(&str, &str)])] = &[
    ("F3", &[("vyra-kem", "round_trip")]),
    (
        "F4",
        &[
            ("vyra-kem", "conformance_mlkem"),
            ("vyra-kem", "conformance_hqc"),
            ("vyra-hqc", "kat"),
            ("vyra-sig", "conformance_mldsa"),
            ("vyra-sig", "conformance_mldsa_acvp_sig"),
            ("vyra-sig", "conformance_ed25519"),
            ("vyra-sig", "conformance_slhdsa"),
            ("vyra-sig", "conformance_sizes"),
        ],
    ),
    (
        "F6",
        &[
            ("vyra-core", "wire"),
            ("vyra-kem", "wire"),
            ("vyra-sig", "wire"),
            ("vyra-seal", "round_trip"),
        ],
    ),
    (
        "F7",
        &[
            ("vyra-sig", "roundtrip"),
            ("vyra-sig", "regression_transition"),
            ("vyra-sig", "custom_composite"),
        ],
    ),
    ("F8", &[("vyra-seal", "round_trip")]),
    (
        "S1",
        &[
            ("vyra-core", "wire"),
            ("vyra-kem", "raw_validation"),
            ("vyra-kem", "wire"),
            ("vyra-sig", "wire"),
            ("vyra-seal", "malformed"),
        ],
    ),
    (
        "S2",
        &[
            ("vyra-core", "wire"),
            ("vyra-kem", "wire"),
            ("vyra-sig", "wire"),
            ("vyra-seal", "malformed"),
        ],
    ),
    ("S3", &[("vyra-kem", "tamper")]),
    (
        "S4",
        &[
            ("vyra-sig", "tamper"),
            ("vyra-sig", "separation"),
            ("vyra-sig", "custom_composite"),
        ],
    ),
    ("S5", &[("vyra-seal", "tamper")]),
    (
        "S6",
        &[
            ("vyra-kem", "combiner"),
            ("vyra-kem", "independent"),
            ("vyra-kem", "custom_assembly"),
        ],
    ),
    (
        "S9",
        &[
            ("vyra-core", "entropy_secret"),
            ("vyra-kem", "hygiene"),
            ("vyra-sig", "secret_hygiene"),
        ],
    ),
    (
        "S10",
        &[
            ("vyra-core", "wire"),
            ("vyra-kem", "fuzz"),
            ("vyra-sig", "proptest_parsers"),
            ("vyra-seal", "fuzz"),
        ],
    ),
];

/// A finished `cargo test` run.
#[derive(Debug, Clone)]
pub struct TestRun {
    /// Process outcome.
    pub outcome: Outcome,
    /// Sum of `N passed` over all `test result:` lines.
    pub passed: u64,
    /// Sum of `N failed`.
    pub failed: u64,
    /// Number of `test result:` lines (test binaries run, incl. doctests).
    pub binaries: usize,
}

impl TestRun {
    /// Exit 0, nothing failed, at least one test passed.
    pub fn ok(&self) -> bool {
        self.outcome.success() && self.failed == 0 && self.passed > 0
    }

    /// One-line summary.
    pub fn doc_summary(&self) -> String {
        format!(
            "exit {:?}, {} test binaries, {} passed, {} failed",
            self.outcome.code, self.binaries, self.passed, self.failed
        )
    }
}

/// Sum the `test result:` lines of libtest output: `(passed, failed, lines)`.
pub fn parse_test_counts(output: &str) -> (u64, u64, usize) {
    let mut passed = 0u64;
    let mut failed = 0u64;
    let mut lines = 0usize;
    for line in output.lines() {
        let Some(rest) = line.trim().strip_prefix("test result:") else {
            continue;
        };
        lines += 1;
        for part in rest.split([';', '.']) {
            let mut words = part.split_whitespace();
            if let (Some(n), Some(label)) = (words.next(), words.next())
                && let Ok(n) = n.parse::<u64>()
            {
                match label {
                    "passed" => passed += n,
                    "failed" => failed += n,
                    _ => {}
                }
            }
        }
    }
    (passed, failed, lines)
}

fn test_run(outcome: Outcome) -> TestRun {
    let (passed, failed, binaries) = parse_test_counts(&outcome.stdout);
    TestRun {
        outcome,
        passed,
        failed,
        binaries,
    }
}

fn command_line(args: &[&str]) -> String {
    format!("cargo {}", args.join(" "))
}

/// One cargo invocation: arguments and extra environment variables.
type CargoStep<'a> = (&'a [&'a str], &'a [(&'a str, &'a str)]);

/// Run each command in turn; PASS only if all exit 0.
fn commands(ctx: &Ctx, cmds: &[CargoStep<'_>]) -> Finding {
    let mut method = Vec::new();
    let mut evidence = Vec::new();
    let mut last_code = None;
    let mut ok = true;
    for (args, env) in cmds {
        let env_text: Vec<String> = env.iter().map(|(k, v)| format!("{k}={v} ")).collect();
        method.push(format!("{}{}", env_text.concat(), command_line(args)));
        let o = ctx.cargo(args, env);
        last_code = o.code;
        evidence.push(format!(
            "$ {} -> exit {:?} ({})\n{}",
            command_line(args),
            o.code,
            secs(o.duration),
            exec::tail(&o.combined(), if o.success() { 3 } else { 15 }, 1500)
        ));
        if !o.success() {
            ok = false;
            break;
        }
    }
    Finding {
        method: method.join(" && "),
        status: if ok { Status::Pass } else { Status::Fail },
        exit_code: last_code,
        evidence: evidence.join("\n"),
    }
}

/// F1.
pub fn f1(ctx: &mut Ctx, _id: &str) -> Finding {
    commands(
        ctx,
        &[(&["build", "--workspace", "--all-targets", "--locked"], &[])],
    )
}

/// Lines with `#[ignore]` that carry no reason string.
pub fn bare_ignores(text: &str) -> Vec<usize> {
    text.lines()
        .enumerate()
        .filter(|(_, l)| {
            let t = l.trim();
            t.starts_with("#[ignore") && !t.contains("= \"") && !t.contains("=\"")
        })
        .map(|(i, _)| i + 1)
        .collect()
}

/// F2 (and D2: doctests are part of `cargo test --workspace`).
pub fn f2(ctx: &mut Ctx, _id: &str) -> Finding {
    let args = ["test", "--workspace", "--locked"];
    let run = test_run(ctx.cargo(&args, &[]));
    let mut ignores = Vec::new();
    for dir in [ctx.root.join("crates"), ctx.root.join("xtask")] {
        for f in rs_files(&dir) {
            let text = std::fs::read_to_string(&f).unwrap_or_default();
            for line in bare_ignores(&text) {
                ignores.push(format!("{}:{line}", rel(&ctx.root, &f)));
            }
        }
    }
    let ok = run.ok() && ignores.is_empty();
    let mut evidence = format!(
        "$ {} -> {}\n{}",
        command_line(&args),
        run.doc_summary(),
        exec::tail(&run.outcome.combined(), if run.ok() { 3 } else { 20 }, 2000)
    );
    if ignores.is_empty() {
        evidence.push_str("\nno #[ignore] without a reason string");
    } else {
        evidence.push_str(&format!(
            "\n#[ignore] without reason: {}",
            ignores.join(", ")
        ));
    }
    let exit_code = run.outcome.code;
    ctx.test_cache
        .insert(("<workspace>".to_string(), "F2".to_string()), run);
    Finding {
        method: format!(
            "{} + scan for #[ignore] without reason",
            command_line(&args)
        ),
        status: if ok { Status::Pass } else { Status::Fail },
        exit_code,
        evidence,
    }
}

/// The test targets mapped to `id`.
pub fn targets_for(id: &str) -> &'static [(&'static str, &'static str)] {
    TEST_MAP
        .iter()
        .find(|(g, _)| *g == id)
        .map_or(&[], |(_, t)| t)
}

/// Run (or reuse) the mapped test targets of a gate.
pub fn run_targets(ctx: &mut Ctx, id: &str) -> Finding {
    let targets = targets_for(id);
    let mut method = Vec::new();
    let mut evidence = Vec::new();
    let mut ok = !targets.is_empty();
    let mut exit_code = None;
    if targets.is_empty() {
        evidence.push(format!("no test targets mapped to {id}"));
    }
    for (krate, target) in targets {
        let args = ["test", "-p", krate, "--test", target, "--locked"];
        method.push(command_line(&args));
        let dir = ctx.root.join("crates").join(krate).join("tests");
        if !dir.join(format!("{target}.rs")).is_file()
            && !dir.join(target).join("main.rs").is_file()
        {
            ok = false;
            evidence.push(format!("{krate} --test {target}: MISSING test target"));
            continue;
        }
        let key = ((*krate).to_string(), (*target).to_string());
        if !ctx.test_cache.contains_key(&key) {
            let run = test_run(ctx.cargo(&args, &[]));
            ctx.test_cache.insert(key.clone(), run);
        }
        if let Some(run) = ctx.test_cache.get(&key) {
            exit_code = run.outcome.code;
            if !run.ok() {
                ok = false;
                let why = if run.passed == 0 && run.outcome.success() {
                    "reported zero tests"
                } else {
                    "failed"
                };
                evidence.push(format!(
                    "{krate} --test {target}: {why}: {}\n{}",
                    run.doc_summary(),
                    exec::tail(&run.outcome.combined(), 15, 1500)
                ));
            } else {
                evidence.push(format!(
                    "{krate} --test {target}: {} passed ({})",
                    run.passed,
                    secs(run.outcome.duration)
                ));
            }
        }
    }
    Finding {
        method: method.join(" ; "),
        status: if ok { Status::Pass } else { Status::Fail },
        exit_code,
        evidence: evidence.join("\n"),
    }
}

/// A test-mapped gate.
pub fn mapped(ctx: &mut Ctx, id: &str) -> Finding {
    run_targets(ctx, id)
}

/// `cargo test -p <krate> --locked`: PASS iff exit 0, nothing failed and at
/// least one test passed (gates Y1, V1).
pub fn crate_tests(ctx: &mut Ctx, krate: &str) -> Finding {
    let args = ["test", "-p", krate, "--locked"];
    if !ctx
        .root
        .join("crates")
        .join(krate)
        .join("Cargo.toml")
        .is_file()
    {
        return Finding::check(
            command_line(&args),
            false,
            format!("crates/{krate} does not exist"),
        );
    }
    let run = test_run(ctx.cargo(&args, &[]));
    let finding = Finding {
        method: command_line(&args),
        status: if run.ok() { Status::Pass } else { Status::Fail },
        exit_code: run.outcome.code,
        evidence: format!(
            "$ {} -> {} ({})\n{}",
            command_line(&args),
            run.doc_summary(),
            secs(run.outcome.duration),
            exec::tail(&run.outcome.combined(), if run.ok() { 4 } else { 20 }, 2000)
        ),
    };
    ctx.test_cache
        .insert((krate.to_string(), "<all>".to_string()), run);
    finding
}

/// F9.
pub fn f9(ctx: &mut Ctx, _id: &str) -> Finding {
    let args: &[&str] = &["run", "-p", "vyra-cli", "--locked", "--", "demo"];
    if !ctx.root.join("crates/vyra-cli/Cargo.toml").is_file() {
        return Finding::check(
            command_line(args),
            false,
            "crates/vyra-cli does not exist (crate not written yet)",
        );
    }
    commands(ctx, &[(args, &[])])
}

/// S8.
pub fn s8(ctx: &mut Ctx, _id: &str) -> Finding {
    commands(
        ctx,
        &[(
            &[
                "clippy",
                "--workspace",
                "--lib",
                "--locked",
                "--",
                "-D",
                "clippy::unwrap_used",
                "-D",
                "clippy::expect_used",
                "-D",
                "clippy::panic",
                "-D",
                "clippy::indexing_slicing",
            ],
            &[],
        )],
    )
}

/// S11.
pub fn s11(ctx: &mut Ctx, _id: &str) -> Finding {
    commands(
        ctx,
        &[
            (
                &[
                    "clippy",
                    "--workspace",
                    "--all-targets",
                    "--locked",
                    "--",
                    "-D",
                    "warnings",
                ],
                &[],
            ),
            (&["fmt", "--all", "--check"], &[]),
        ],
    )
}

/// S12: `cargo audit` if installed, else NOT_RUN (never PASS without running).
pub fn s12(ctx: &mut Ctx, _id: &str) -> Finding {
    let cargo = exec::cargo();
    let probe = exec::run(&cargo, &["audit", "--version"], &ctx.root, &[]);
    if !probe.success() {
        return Finding {
            method: "cargo audit".into(),
            status: Status::NotRun,
            exit_code: None,
            evidence: "NOT RUN: `cargo audit` is not installed (cargo install cargo-audit); \
                       dependency advisories were NOT checked"
                .into(),
        };
    }
    commands(ctx, &[(&["audit"], &[])])
}

/// D1: rustdoc with `-D warnings`, plus `#![deny(missing_docs)]` in every library crate root.
pub fn d1(ctx: &mut Ctx, _id: &str) -> Finding {
    let mut f = commands(
        ctx,
        &[(
            &["doc", "--workspace", "--no-deps", "--locked"],
            &[("RUSTDOCFLAGS", "-D warnings")],
        )],
    );
    let mut missing = Vec::new();
    for dir in super::crate_dirs(&ctx.root) {
        let lib = dir.join("src/lib.rs");
        if lib.is_file() {
            let text = std::fs::read_to_string(&lib).unwrap_or_default();
            let has = text.lines().any(|l| {
                let t = l.trim();
                t == "#![deny(missing_docs)]" || t == "#![forbid(missing_docs)]"
            });
            if !has {
                missing.push(rel(&ctx.root, &lib));
            }
        }
    }
    f.method
        .push_str(" + check #![deny(missing_docs)] in crates/*/src/lib.rs");
    if missing.is_empty() {
        f.evidence
            .push_str("\n#![deny(missing_docs)] present in every library crate root");
    } else {
        f.status = Status::Fail;
        f.evidence.push_str(&format!(
            "\nmissing #![deny(missing_docs)]: {}",
            missing.join(", ")
        ));
    }
    f
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_libtest_lines() {
        let out = "running 3 tests\ntest a ... ok\n\ntest result: ok. 3 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.01s\n\
                   test result: FAILED. 1 passed; 2 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.10s\n";
        assert_eq!(parse_test_counts(out), (4, 2, 2));
        assert_eq!(parse_test_counts("running 0 tests\n"), (0, 0, 0));
        assert_eq!(
            parse_test_counts("test result: ok. 0 passed; 0 failed; 0 ignored"),
            (0, 0, 1)
        );
    }

    #[test]
    fn finds_bare_ignores() {
        let src = "#[test]\n#[ignore]\nfn a() {}\n#[ignore = \"slow\"]\nfn b() {}\n  #[ignore]\n";
        assert_eq!(bare_ignores(src), vec![2, 6]);
    }

    #[test]
    fn mapping_covers_test_gates_and_targets_exist() {
        let root = crate::workspace_root();
        for id in [
            "F3", "F4", "F6", "F7", "F8", "S1", "S2", "S3", "S4", "S5", "S6", "S9", "S10",
        ] {
            let t = targets_for(id);
            assert!(!t.is_empty(), "{id} has no mapped tests");
            for (krate, target) in t {
                let p = root
                    .join("crates")
                    .join(krate)
                    .join("tests")
                    .join(format!("{target}.rs"));
                assert!(p.is_file(), "{id}: {} missing", p.display());
            }
        }
        assert!(targets_for("F1").is_empty());
    }
}
