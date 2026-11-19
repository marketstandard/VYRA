//! A small hand-written command-line parser.
//!
//! Grammar: `vyra <command> [<subcommand>] [--name value | --name=value | --force]...`.
//! Option values that name files are kept as `OsString`, so non-UTF-8 paths
//! work; `--context` and `--aad` must be UTF-8 (their bytes are used as is).

use std::ffi::OsString;
use std::path::PathBuf;

use vyra::kem::KemSuite;
use vyra::sig::SigSuite;

use crate::error::CliError;

/// Full help text.
pub const USAGE: &str = "\
vyra - command-line tool for the VYRA research prototype
       (hybrid ML-KEM + HQC KEM; composite signatures ML-DSA + Ed25519
        and ML-DSA + SLH-DSA; sealed box). Not for protecting real data.

USAGE:
  vyra info
  vyra demo
  vyra kem keygen  --suite <1|3|5> --pk <file> --sk <file>
  vyra kem encaps  --pk <file> --ct <file> --ss <file>
  vyra kem decaps  --sk <file> --ct <file> --ss <file>
  vyra sig keygen  --suite <2|3|5|pq1|pq3|pq5> --pk <file> --sk <file>
  vyra sig sign    --sk <file> --in <file> [--context <str>] --sig <file>
  vyra sig verify  --pk <file> --in <file> --sig <file> [--context <str>]
  vyra seal        --pk <file> --in <file> --out <file> [--aad <str>]
  vyra open        --sk <file> --in <file> --out <file> [--aad <str>]
  vyra help | --help | -h
  vyra --version

COMMANDS:
  info     Print the status statement, suites, component names and sizes.
  demo     Run an in-memory end-to-end demonstration over every suite; prints
           PASS and exits 0 only if every check passes.
  kem      Hybrid KEM: suite 1 = ML-KEM-512 + HQC-128, 3 = ML-KEM-768 +
           HQC-192, 5 = ML-KEM-1024 + HQC-256.
  sig      Composite signature; both component signatures must verify.
           Transition suites (post-quantum + classical fallback):
             2 = ML-DSA-44 + Ed25519, 3 = ML-DSA-65 + Ed25519,
             5 = ML-DSA-87 + Ed25519.
           Dual post-quantum suites (two post-quantum assumptions):
             pq1 = ML-DSA-44 + SLH-DSA-SHAKE-128s, pq3 = ML-DSA-65 +
             SLH-DSA-SHAKE-192s, pq5 = ML-DSA-87 + SLH-DSA-SHAKE-256s;
             signatures of 10-34 KB, and signing takes seconds.
           Suite names are case-insensitive. The context string (default
           empty, at most 255 bytes) must be the same for sign and verify.
  seal     Encrypt a file to a KEM public key (no sender authentication).
  open     Decrypt a sealed file with the matching KEM secret key.

FILES:
  Keys, ciphertexts, signatures and sealed boxes are written in the binary
  VYRA wire encoding (7-byte header: \"VYRA\", version, object type, suite).
  The suite is read from that header, so only keygen takes --suite.
  Shared-secret files (--ss) hold the raw 32-byte shared secret.
  Existing output files are not overwritten unless --force is given.
  Secret-key, shared-secret and opened-plaintext files are written with the
  default permissions of your system: protecting them (file permissions,
  storage, deletion) is your responsibility. vyra never prints secrets.

EXIT CODES:
  0  success (for `sig verify`: the signature is valid)
  1  rejected: invalid signature, or a sealed box that failed to open
  2  usage error
  3  file missing, unreadable, unwritable, or not a valid VYRA object
  4  unexpected failure, or a `demo` check failed
";

/// A parsed command.
#[derive(Debug)]
pub enum Command {
    /// Print [`USAGE`].
    Help,
    /// Print the version.
    Version,
    /// `vyra info`.
    Info,
    /// `vyra demo`.
    Demo,
    /// `vyra kem keygen`.
    KemKeygen {
        /// Suite to generate.
        suite: KemSuite,
        /// Public key output.
        pk: PathBuf,
        /// Secret key output.
        sk: PathBuf,
    },
    /// `vyra kem encaps`.
    KemEncaps {
        /// Public key input.
        pk: PathBuf,
        /// Ciphertext output.
        ct: PathBuf,
        /// Shared secret output.
        ss: PathBuf,
    },
    /// `vyra kem decaps`.
    KemDecaps {
        /// Secret key input.
        sk: PathBuf,
        /// Ciphertext input.
        ct: PathBuf,
        /// Shared secret output.
        ss: PathBuf,
    },
    /// `vyra sig keygen`.
    SigKeygen {
        /// Suite to generate.
        suite: SigSuite,
        /// Public key output.
        pk: PathBuf,
        /// Secret key output.
        sk: PathBuf,
    },
    /// `vyra sig sign`.
    SigSign {
        /// Secret key input.
        sk: PathBuf,
        /// Message input.
        input: PathBuf,
        /// Context string.
        context: String,
        /// Signature output.
        sig: PathBuf,
    },
    /// `vyra sig verify`.
    SigVerify {
        /// Public key input.
        pk: PathBuf,
        /// Message input.
        input: PathBuf,
        /// Signature input.
        sig: PathBuf,
        /// Context string.
        context: String,
    },
    /// `vyra seal`.
    Seal {
        /// Recipient public key input.
        pk: PathBuf,
        /// Plaintext input.
        input: PathBuf,
        /// Sealed box output.
        out: PathBuf,
        /// Associated data.
        aad: String,
    },
    /// `vyra open`.
    Open {
        /// Secret key input.
        sk: PathBuf,
        /// Sealed box input.
        input: PathBuf,
        /// Plaintext output.
        out: PathBuf,
        /// Associated data.
        aad: String,
    },
}

/// A parsed command line.
#[derive(Debug)]
pub struct Invocation {
    /// What to do.
    pub command: Command,
    /// Overwrite existing output files.
    pub force: bool,
}

/// Parsed `--name value` options of one command.
struct Opts {
    values: Vec<(&'static str, OsString)>,
    force: bool,
}

impl Opts {
    fn take(&mut self, name: &str) -> Option<OsString> {
        let pos = self.values.iter().position(|(n, _)| *n == name)?;
        Some(self.values.swap_remove(pos).1)
    }

    fn path(&mut self, name: &str) -> Result<PathBuf, CliError> {
        self.take(name)
            .map(PathBuf::from)
            .ok_or_else(|| CliError::usage(format!("missing required option --{name}")))
    }

    fn required_string(&mut self, name: &str) -> Result<String, CliError> {
        if self.values.iter().any(|(n, _)| *n == name) {
            self.string(name)
        } else {
            Err(CliError::usage(format!("missing required option --{name}")))
        }
    }

    fn string(&mut self, name: &str) -> Result<String, CliError> {
        match self.take(name) {
            None => Ok(String::new()),
            Some(v) => v
                .into_string()
                .map_err(|_| CliError::usage(format!("--{name} must be valid UTF-8"))),
        }
    }
}

/// Parse options for a command that accepts exactly `allowed` names.
fn parse_opts(
    args: &[OsString],
    allowed: &[&'static str],
    takes_output: bool,
) -> Result<Opts, CliError> {
    let mut opts = Opts {
        values: Vec::new(),
        force: false,
    };
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        let text = arg
            .to_str()
            .ok_or_else(|| CliError::usage("unexpected non-UTF-8 argument"))?;
        if text == "--force" && takes_output {
            opts.force = true;
            continue;
        }
        let Some(body) = text.strip_prefix("--") else {
            return Err(CliError::usage(format!("unexpected argument '{text}'")));
        };
        let (name, inline) = match body.split_once('=') {
            Some((n, v)) => (n, Some(OsString::from(v))),
            None => (body, None),
        };
        let Some(&known) = allowed.iter().find(|a| **a == name) else {
            return Err(CliError::usage(format!(
                "unknown option '--{name}' for this command"
            )));
        };
        if opts.values.iter().any(|(n, _)| *n == known) {
            return Err(CliError::usage(format!("option --{known} given twice")));
        }
        let value = match inline {
            Some(v) => v,
            None => it
                .next()
                .cloned()
                .ok_or_else(|| CliError::usage(format!("option --{known} needs a value")))?,
        };
        opts.values.push((known, value));
    }
    Ok(opts)
}

fn kem_suite(text: &str) -> Result<KemSuite, CliError> {
    match text {
        "1" => Ok(KemSuite::Vyra1),
        "3" => Ok(KemSuite::Vyra3),
        "5" => Ok(KemSuite::Vyra5),
        other => Err(CliError::usage(format!(
            "unknown KEM suite '{other}' (expected 1, 3 or 5)"
        ))),
    }
}

/// Parse a signature suite: `2`, `3`, `5`, `pq1`, `pq3` or `pq5`
/// (case-insensitive).
pub fn sig_suite(text: &str) -> Result<SigSuite, CliError> {
    match text.to_ascii_lowercase().as_str() {
        "2" => Ok(SigSuite::Vyra2),
        "3" => Ok(SigSuite::Vyra3),
        "5" => Ok(SigSuite::Vyra5),
        "pq1" => Ok(SigSuite::Pq1),
        "pq3" => Ok(SigSuite::Pq3),
        "pq5" => Ok(SigSuite::Pq5),
        _ => Err(CliError::usage(format!(
            "unknown signature suite '{text}' (expected 2, 3, 5, pq1, pq3 or pq5)"
        ))),
    }
}

/// The `--suite` spelling of a signature suite (inverse of [`sig_suite`]).
pub const fn sig_suite_arg(suite: SigSuite) -> &'static str {
    match suite {
        SigSuite::Vyra2 => "2",
        SigSuite::Vyra3 => "3",
        SigSuite::Vyra5 => "5",
        SigSuite::Pq1 => "pq1",
        SigSuite::Pq3 => "pq3",
        SigSuite::Pq5 => "pq5",
    }
}

/// Parse the arguments after the program name.
///
/// # Errors
///
/// A usage error describing the first problem found.
pub fn parse(args: &[OsString]) -> Result<Invocation, CliError> {
    if args.first().is_some_and(|a| a == "help") || args.iter().any(|a| a == "--help" || a == "-h")
    {
        return Ok(Invocation {
            command: Command::Help,
            force: false,
        });
    }
    let Some((first, rest)) = args.split_first() else {
        return Err(CliError::usage("no command given"));
    };
    let first = first
        .to_str()
        .ok_or_else(|| CliError::usage("unexpected non-UTF-8 command"))?;

    let (mut opts, build): (Opts, Builder) = match first {
        "--version" | "-V" | "version" => (parse_opts(rest, &[], false)?, |_| Ok(Command::Version)),
        "info" => (parse_opts(rest, &[], false)?, |_| Ok(Command::Info)),
        "demo" => (parse_opts(rest, &[], false)?, |_| Ok(Command::Demo)),
        "seal" => (parse_opts(rest, &["pk", "in", "out", "aad"], true)?, |o| {
            Ok(Command::Seal {
                pk: o.path("pk")?,
                input: o.path("in")?,
                out: o.path("out")?,
                aad: o.string("aad")?,
            })
        }),
        "open" => (parse_opts(rest, &["sk", "in", "out", "aad"], true)?, |o| {
            Ok(Command::Open {
                sk: o.path("sk")?,
                input: o.path("in")?,
                out: o.path("out")?,
                aad: o.string("aad")?,
            })
        }),
        "kem" | "sig" => {
            let Some((sub, rest)) = rest.split_first() else {
                return Err(CliError::usage(format!("'{first}' needs a subcommand")));
            };
            let sub = sub.to_str().unwrap_or("");
            parse_sub(first, sub, rest)?
        }
        other => return Err(CliError::usage(format!("unknown command '{other}'"))),
    };
    let command = build(&mut opts)?;
    Ok(Invocation {
        command,
        force: opts.force,
    })
}

type Builder = fn(&mut Opts) -> Result<Command, CliError>;

fn parse_sub(group: &str, sub: &str, rest: &[OsString]) -> Result<(Opts, Builder), CliError> {
    Ok(match (group, sub) {
        ("kem", "keygen") => (parse_opts(rest, &["suite", "pk", "sk"], true)?, |o| {
            Ok(Command::KemKeygen {
                suite: kem_suite(&o.required_string("suite")?)?,
                pk: o.path("pk")?,
                sk: o.path("sk")?,
            })
        }),
        ("kem", "encaps") => (parse_opts(rest, &["pk", "ct", "ss"], true)?, |o| {
            Ok(Command::KemEncaps {
                pk: o.path("pk")?,
                ct: o.path("ct")?,
                ss: o.path("ss")?,
            })
        }),
        ("kem", "decaps") => (parse_opts(rest, &["sk", "ct", "ss"], true)?, |o| {
            Ok(Command::KemDecaps {
                sk: o.path("sk")?,
                ct: o.path("ct")?,
                ss: o.path("ss")?,
            })
        }),
        ("sig", "keygen") => (parse_opts(rest, &["suite", "pk", "sk"], true)?, |o| {
            Ok(Command::SigKeygen {
                suite: sig_suite(&o.required_string("suite")?)?,
                pk: o.path("pk")?,
                sk: o.path("sk")?,
            })
        }),
        ("sig", "sign") => (
            parse_opts(rest, &["sk", "in", "context", "sig"], true)?,
            |o| {
                Ok(Command::SigSign {
                    sk: o.path("sk")?,
                    input: o.path("in")?,
                    context: o.string("context")?,
                    sig: o.path("sig")?,
                })
            },
        ),
        ("sig", "verify") => (
            parse_opts(rest, &["pk", "in", "sig", "context"], false)?,
            |o| {
                Ok(Command::SigVerify {
                    pk: o.path("pk")?,
                    input: o.path("in")?,
                    sig: o.path("sig")?,
                    context: o.string("context")?,
                })
            },
        ),
        (group, sub) => {
            return Err(CliError::usage(format!(
                "unknown subcommand '{group} {sub}'"
            )));
        }
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn os(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    #[test]
    fn parses_kem_keygen() {
        let inv = parse(&os(&[
            "kem", "keygen", "--suite", "3", "--pk=a", "--sk", "b",
        ]))
        .unwrap();
        match inv.command {
            Command::KemKeygen { suite, pk, sk } => {
                assert_eq!(suite, KemSuite::Vyra3);
                assert_eq!(pk, PathBuf::from("a"));
                assert_eq!(sk, PathBuf::from("b"));
            }
            other => panic!("unexpected {other:?}"),
        }
        assert!(!inv.force);
    }

    #[test]
    fn rejects_bad_input() {
        for bad in [
            &[][..],
            &["frobnicate"][..],
            &["kem"][..],
            &["kem", "keygen", "--suite", "2", "--pk", "a", "--sk", "b"][..],
            &["kem", "keygen", "--suite", "1", "--pk", "a"][..],
            &[
                "kem", "keygen", "--suite", "1", "--pk", "a", "--pk", "b", "--sk", "c",
            ][..],
            &[
                "sig", "verify", "--pk", "a", "--in", "b", "--sig", "c", "--force",
            ][..],
            &["seal", "--pk"][..],
            &["info", "extra"][..],
        ] {
            let err = parse(&os(bad)).unwrap_err();
            assert_eq!(err.kind(), crate::error::Kind::Usage, "{bad:?}");
        }
    }

    #[test]
    fn signature_suites_parse_case_insensitively() {
        for suite in SigSuite::all() {
            let arg = sig_suite_arg(suite);
            assert_eq!(sig_suite(arg).unwrap(), suite);
            assert_eq!(sig_suite(&arg.to_ascii_uppercase()).unwrap(), suite);
        }
        assert_eq!(sig_suite("Pq3").unwrap(), SigSuite::Pq3);
        for bad in [
            "",
            "1",
            "4",
            "pq",
            "pq2",
            "pq 1",
            "17",
            "0x11",
            "VYRA-SIG-PQ1",
            " 2",
            "pq1 ",
        ] {
            let err = sig_suite(bad).unwrap_err();
            assert_eq!(err.kind(), crate::error::Kind::Usage, "{bad:?}");
            assert!(err.to_string().contains("pq5"), "{err}");
        }
        let inv = parse(&os(&[
            "sig", "keygen", "--suite", "PQ5", "--pk", "a", "--sk", "b",
        ]))
        .unwrap();
        assert!(matches!(
            inv.command,
            Command::SigKeygen {
                suite: SigSuite::Pq5,
                ..
            }
        ));
    }

    #[test]
    fn context_defaults_to_empty() {
        let inv = parse(&os(&[
            "sig", "sign", "--sk", "k", "--in", "m", "--sig", "s",
        ]))
        .unwrap();
        match inv.command {
            Command::SigSign { context, .. } => assert!(context.is_empty()),
            other => panic!("unexpected {other:?}"),
        }
    }
}
