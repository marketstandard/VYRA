//! D5: a fresh `git clone` of the committed tree passes F1, F2 and F5.
//!
//! Only committed content is cloned. Full mode: FAIL if the working tree is
//! dirty (the clone would not test what is on disk), otherwise
//! `cargo build --workspace --all-targets --locked`,
//! `cargo test --workspace --locked` and `cargo xtask vectors --check` in the
//! clone. Quick mode: a dirty tree is a warning, and the clone runs
//! `cargo build --locked`, `cargo test -p vyra-core --locked` and
//! `cargo xtask vectors --check`. The clone is deleted afterwards.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use super::{Ctx, Finding, git_dirty_files, secs};
use crate::exec;
use crate::report::Status;
use crate::vectors::CHECK_OK_MARKER;

fn temp_clone_dir() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("vyra-d5-{}-{nanos}", std::process::id()))
}

/// Remove a directory tree, clearing read-only flags first (git object files
/// are read-only, which `remove_dir_all` cannot delete on Windows).
fn remove_tree(dir: &Path) -> Result<(), String> {
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in rd.flatten() {
            let p = e.path();
            if let Ok(meta) = std::fs::symlink_metadata(&p) {
                if meta.is_dir() {
                    stack.push(p.clone());
                }
                let mut perms = meta.permissions();
                if perms.readonly() {
                    // Only files inside our own temporary clone are touched.
                    #[allow(clippy::permissions_set_readonly_false)]
                    perms.set_readonly(false);
                    let _ = std::fs::set_permissions(&p, perms);
                }
            }
        }
    }
    std::fs::remove_dir_all(dir).map_err(|e| format!("could not delete {}: {e}", dir.display()))
}

/// D5.
pub fn d5(ctx: &mut Ctx, _id: &str) -> Finding {
    let steps: Vec<Vec<&str>> = if ctx.quick {
        vec![
            vec!["build", "--locked"],
            vec!["test", "-p", "vyra-core", "--locked"],
            vec!["xtask", "vectors", "--check"],
        ]
    } else {
        vec![
            vec!["build", "--workspace", "--all-targets", "--locked"],
            vec!["test", "--workspace", "--locked"],
            vec!["xtask", "vectors", "--check"],
        ]
    };
    let method = format!(
        "git clone --no-hardlinks <workspace> <temp>; in the clone: {}",
        steps
            .iter()
            .map(|s| format!("cargo {}", s.join(" ")))
            .collect::<Vec<_>>()
            .join(" && ")
    );
    let Some(commit) = crate::envinfo::git_commit(&ctx.root) else {
        return Finding::check(
            method,
            false,
            "not a git checkout: git rev-parse HEAD failed",
        );
    };
    // Judge cleanliness by the state before any gate ran: earlier gates
    // (P1, P2) legitimately rewrite files under results/.
    let dirty = ctx
        .dirty_at_start
        .clone()
        .or_else(|| git_dirty_files(&ctx.root))
        .unwrap_or_default();
    let mut evidence = vec![format!("commit tested: {commit}")];
    if !dirty.is_empty() {
        if ctx.quick {
            evidence.push(format!(
                "WARNING: working tree has {} uncommitted change(s); only the committed tree is tested",
                dirty.len()
            ));
        } else {
            evidence.push(format!(
                "working tree has {} uncommitted change(s); D5 requires a clean tree in full mode:\n{}",
                dirty.len(),
                dirty.join("\n")
            ));
            return Finding::check(method, false, evidence.join("\n"));
        }
    }

    let tmp = temp_clone_dir();
    let tmp_text = tmp.to_string_lossy().into_owned();
    let root_text = ctx.root.to_string_lossy().into_owned();
    let clone = exec::run(
        &"git".into(),
        &["clone", "--quiet", "--no-hardlinks", &root_text, &tmp_text],
        &std::env::temp_dir(),
        &[],
    );
    if !clone.success() {
        evidence.push(format!(
            "git clone failed: {}",
            exec::tail(&clone.combined(), 5, 600)
        ));
        let _ = remove_tree(&tmp);
        return Finding {
            method,
            status: Status::Fail,
            exit_code: clone.code,
            evidence: evidence.join("\n"),
        };
    }

    let mut ok = true;
    let mut exit_code = None;
    let missing: Vec<&str> = ["kem.json", "sig.json", "seal.json", "combiner.json"]
        .into_iter()
        .filter(|f| !tmp.join("vectors").join(f).is_file())
        .collect();
    if !missing.is_empty() {
        ok = false;
        evidence.push(format!(
            "committed tree lacks vectors/{} (F5 cannot pass in the clone)",
            missing.join(", vectors/")
        ));
    }
    let target = tmp.join("target").to_string_lossy().into_owned();
    if ok {
        for step in &steps {
            let o = exec::run(
                &exec::cargo(),
                step,
                &tmp,
                &[("CARGO_TARGET_DIR", target.as_str())],
            );
            exit_code = o.code;
            let mut step_ok = o.success();
            if step.first() == Some(&"xtask") && !o.combined().contains(CHECK_OK_MARKER) {
                step_ok = false;
            }
            evidence.push(format!(
                "$ cargo {} -> exit {:?} ({}){}\n{}",
                step.join(" "),
                o.code,
                secs(o.duration),
                if step_ok { "" } else { " FAILED" },
                exec::tail(&o.combined(), if step_ok { 2 } else { 12 }, 1200)
            ));
            if !step_ok {
                ok = false;
                break;
            }
        }
    }
    match remove_tree(&tmp) {
        Ok(()) => evidence.push("temporary clone deleted".into()),
        Err(e) => evidence.push(format!("WARNING: {e}")),
    }
    Finding {
        method,
        status: if ok { Status::Pass } else { Status::Fail },
        exit_code,
        evidence: evidence.join("\n"),
    }
}
