//! Spawning external processes (via `std::process`, never through a shell).

use std::ffi::OsString;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// The outcome of one process run.
#[derive(Debug, Clone)]
pub struct Outcome {
    /// Exit code, `None` if the process could not be started or was killed.
    pub code: Option<i32>,
    /// Captured standard output.
    pub stdout: String,
    /// Captured standard error.
    pub stderr: String,
    /// Wall-clock duration.
    pub duration: Duration,
    /// Why the process could not be started, if it could not.
    pub spawn_error: Option<String>,
}

impl Outcome {
    /// Exit code 0.
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }

    /// Standard output followed by standard error.
    pub fn combined(&self) -> String {
        let mut s = self.stdout.clone();
        if !s.is_empty() && !s.ends_with('\n') {
            s.push('\n');
        }
        s.push_str(&self.stderr);
        if let Some(e) = &self.spawn_error {
            s.push_str(e);
        }
        s
    }
}

/// The real `cargo` binary: `$CARGO` (set by cargo for the processes it
/// runs), else `cargo` from `PATH`.
pub fn cargo() -> OsString {
    std::env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"))
}

/// Run `program args...` in `cwd` with extra environment variables, capturing output.
pub fn run(program: &OsString, args: &[&str], cwd: &Path, envs: &[(&str, &str)]) -> Outcome {
    let start = Instant::now();
    let mut cmd = Command::new(program);
    cmd.args(args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .env("CARGO_TERM_COLOR", "never");
    for (k, v) in envs {
        cmd.env(k, v);
    }
    match cmd.output() {
        Ok(out) => Outcome {
            code: out.status.code(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            duration: start.elapsed(),
            spawn_error: None,
        },
        Err(e) => Outcome {
            code: None,
            stdout: String::new(),
            stderr: String::new(),
            duration: start.elapsed(),
            spawn_error: Some(format!(
                "could not start {}: {e}",
                program.to_string_lossy()
            )),
        },
    }
}

/// Whether `program --version` can be started and exits 0.
pub fn available(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// The last `lines` non-empty lines of `text`, at most `max_chars` characters.
pub fn tail(text: &str, lines: usize, max_chars: usize) -> String {
    let kept: Vec<&str> = text
        .lines()
        .map(str::trim_end)
        .filter(|l| !l.is_empty())
        .collect();
    let start = kept.len().saturating_sub(lines);
    let joined = kept.get(start..).unwrap_or_default().join("\n");
    let count = joined.chars().count();
    if count > max_chars {
        let skip = count - max_chars;
        let rest: String = joined.chars().skip(skip).collect();
        format!("...{rest}")
    } else {
        joined
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tail_keeps_last_lines() {
        assert_eq!(tail("a\n\nb\nc\n", 2, 100), "b\nc");
        assert_eq!(tail("abcdef", 5, 3), "...def");
        assert_eq!(tail("", 3, 10), "");
    }
}
