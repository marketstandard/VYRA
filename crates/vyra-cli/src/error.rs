//! CLI error type and exit codes.

use std::fmt;
use std::process::ExitCode;

/// What went wrong, which decides the process exit code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A cryptographic check rejected the input: invalid signature, or a
    /// sealed box that failed to open. Exit code 1.
    Rejected,
    /// Bad command line. Exit code 2.
    Usage,
    /// A file could not be read or written, or did not hold a valid VYRA
    /// object. Exit code 3.
    Input,
    /// An operation failed unexpectedly, or a `demo` check did not pass.
    /// Exit code 4.
    Failure,
}

impl Kind {
    /// The numeric exit code.
    pub const fn code(self) -> u8 {
        match self {
            Kind::Rejected => 1,
            Kind::Usage => 2,
            Kind::Input => 3,
            Kind::Failure => 4,
        }
    }
}

/// An error reported to the user on stderr. Messages never contain secret
/// data: they are built from file names, lengths and `vyra::Error`, whose
/// variants carry only public information.
#[derive(Debug, Clone)]
pub struct CliError {
    kind: Kind,
    message: String,
}

impl CliError {
    /// A usage error.
    pub fn usage(message: impl Into<String>) -> Self {
        CliError {
            kind: Kind::Usage,
            message: message.into(),
        }
    }

    /// An input / file error.
    pub fn input(message: impl Into<String>) -> Self {
        CliError {
            kind: Kind::Input,
            message: message.into(),
        }
    }

    /// A rejection by a cryptographic check.
    pub fn rejected(message: impl Into<String>) -> Self {
        CliError {
            kind: Kind::Rejected,
            message: message.into(),
        }
    }

    /// An unexpected failure.
    pub fn failure(message: impl Into<String>) -> Self {
        CliError {
            kind: Kind::Failure,
            message: message.into(),
        }
    }

    /// The error kind.
    pub fn kind(&self) -> Kind {
        self.kind
    }

    /// The process exit code for this error.
    pub fn exit_code(&self) -> ExitCode {
        ExitCode::from(self.kind.code())
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

/// Attach context to a `vyra::Error`, classifying it as `kind`.
pub fn wrap(kind: Kind, context: &str, err: vyra::Error) -> CliError {
    CliError {
        kind,
        message: format!("{context}: {err}"),
    }
}
