//! The VYRA error type.
//!
//! Every variant carries only public information (lengths, static labels,
//! suite identifiers). Errors never contain key material, plaintext or shared
//! secrets, so they are safe to log.

use core::fmt;

/// Errors returned by VYRA operations.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// An input had the wrong length.
    InvalidLength {
        /// What was being parsed or checked.
        what: &'static str,
        /// The length that was required.
        expected: usize,
        /// The length that was supplied.
        actual: usize,
    },
    /// An input was well-sized but malformed; the label says which check failed.
    InvalidEncoding(&'static str),
    /// The suite identifier is not known to this build.
    UnknownSuite(u8),
    /// A signature did not verify.
    VerificationFailed,
    /// Authenticated decryption failed.
    DecryptionFailed,
    /// The entropy source failed to produce random bytes.
    EntropyFailure,
    /// An internal invariant was violated; the label names it.
    Internal(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidLength {
                what,
                expected,
                actual,
            } => write!(
                f,
                "invalid length for {what}: expected {expected}, got {actual}"
            ),
            Error::InvalidEncoding(what) => write!(f, "invalid encoding: {what}"),
            Error::UnknownSuite(id) => write!(f, "unknown suite id {id}"),
            Error::VerificationFailed => f.write_str("signature verification failed"),
            Error::DecryptionFailed => f.write_str("decryption failed"),
            Error::EntropyFailure => f.write_str("entropy source failure"),
            Error::Internal(what) => write!(f, "internal error: {what}"),
        }
    }
}

impl std::error::Error for Error {}

/// Result alias using [`Error`].
pub type Result<T> = core::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_is_informative() {
        let e = Error::InvalidLength {
            what: "ciphertext",
            expected: 10,
            actual: 9,
        };
        assert_eq!(
            e.to_string(),
            "invalid length for ciphertext: expected 10, got 9"
        );
        assert_eq!(Error::UnknownSuite(7).to_string(), "unknown suite id 7");
    }
}
