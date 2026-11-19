//! Command-line parsing (hand-rolled; no argument-parser dependency).

/// Usage text.
pub const USAGE: &str = "\
usage: cargo xtask <command> [flags]

commands:
  vectors [--check]   write vectors/*.json (or regenerate in memory, byte-compare
                      and re-verify the stored vectors with --check)
  sizes               write results/sizes.json and results/sizes.md
  bench [--quick]     release-mode wall-clock benchmarks -> results/benchmarks.*
  verify [--quick] [--with-kani]
                      run every gate of docs/CHECKS.md -> results/verification-report.*;
                      --with-kani first runs tools/kani/run.ps1 (Windows) or run.sh
                      (needs Docker; minutes to hours) so that gate V2 judges a
                      fresh results/kani-report.txt
  help                this text";

/// A parsed command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// `vectors [--check]`.
    Vectors {
        /// Compare instead of writing.
        check: bool,
    },
    /// `sizes`.
    Sizes,
    /// `bench [--quick]`.
    Bench {
        /// Fewer iterations.
        quick: bool,
    },
    /// `bench-inner [--quick]`: the measuring process (always release).
    BenchInner {
        /// Fewer iterations.
        quick: bool,
    },
    /// `verify [--quick] [--with-kani]`.
    Verify {
        /// Quick mode (shorter benchmarks, shorter clone check).
        quick: bool,
        /// Run the Kani runner (Docker) before gate V2 evaluates its report.
        with_kani: bool,
    },
    /// `help`.
    Help,
}

/// Parse the arguments after the program name.
pub fn parse(args: &[String]) -> Result<Command, String> {
    let Some((name, flags)) = args.split_first() else {
        return Ok(Command::Help);
    };
    let allowed: &[&str] = match name.as_str() {
        "vectors" => &["--check"],
        "bench" | "bench-inner" => &["--quick"],
        "verify" => &["--quick", "--with-kani"],
        "sizes" | "help" | "--help" | "-h" => &[],
        other => return Err(format!("unknown command `{other}`")),
    };
    let mut seen = Vec::new();
    for flag in flags {
        if !allowed.contains(&flag.as_str()) {
            return Err(format!("unknown flag `{flag}` for `{name}`"));
        }
        if seen.contains(flag) {
            return Err(format!("flag `{flag}` given twice"));
        }
        seen.push(flag.clone());
    }
    let has = |f: &str| seen.iter().any(|s| s == f);
    Ok(match name.as_str() {
        "vectors" => Command::Vectors {
            check: has("--check"),
        },
        "sizes" => Command::Sizes,
        "bench" => Command::Bench {
            quick: has("--quick"),
        },
        "bench-inner" => Command::BenchInner {
            quick: has("--quick"),
        },
        "verify" => Command::Verify {
            quick: has("--quick"),
            with_kani: has("--with-kani"),
        },
        _ => Command::Help,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(args: &[&str]) -> Result<Command, String> {
        let v: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
        parse(&v)
    }

    #[test]
    fn parses_commands_and_flags() {
        assert_eq!(p(&[]), Ok(Command::Help));
        assert_eq!(p(&["vectors"]), Ok(Command::Vectors { check: false }));
        assert_eq!(
            p(&["vectors", "--check"]),
            Ok(Command::Vectors { check: true })
        );
        assert_eq!(p(&["sizes"]), Ok(Command::Sizes));
        assert_eq!(p(&["bench", "--quick"]), Ok(Command::Bench { quick: true }));
        assert_eq!(
            p(&["verify"]),
            Ok(Command::Verify {
                quick: false,
                with_kani: false
            })
        );
        assert_eq!(
            p(&["verify", "--with-kani", "--quick"]),
            Ok(Command::Verify {
                quick: true,
                with_kani: true
            })
        );
    }

    #[test]
    fn rejects_unknown_and_duplicate() {
        assert!(p(&["frobnicate"]).is_err());
        assert!(p(&["sizes", "--quick"]).is_err());
        assert!(p(&["vectors", "--check", "--check"]).is_err());
        assert!(p(&["verify", "--check"]).is_err());
        assert!(p(&["bench", "--with-kani"]).is_err());
        assert!(p(&["verify", "--with-kani", "--with-kani"]).is_err());
    }
}
