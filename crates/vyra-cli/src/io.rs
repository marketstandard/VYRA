//! File input/output and display helpers.
//!
//! Secret material read from disk is moved straight into [`SecretBytes`]
//! (zeroized on drop). Output files are created fresh (`create_new`) unless
//! `--force` was given. File permissions are left to the operating system's
//! defaults and are the user's responsibility.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use vyra::{SecretBytes, Transcript};

use crate::error::CliError;

/// Domain label for the short fingerprints the CLI prints.
const FINGERPRINT_LABEL: &[u8] = b"VYRA-cli-fingerprint-v1";

/// Read a public file (key, ciphertext, signature, message).
///
/// # Errors
///
/// An input error naming `what` and the path.
pub fn read_public(path: &Path, what: &str) -> Result<Vec<u8>, CliError> {
    fs::read(path)
        .map_err(|e| CliError::input(format!("cannot read {what} file '{}': {e}", path.display())))
}

/// Read a file holding secret material straight into [`SecretBytes`].
///
/// # Errors
///
/// An input error naming `what` and the path.
pub fn read_secret(path: &Path, what: &str) -> Result<SecretBytes, CliError> {
    read_public(path, what).map(SecretBytes::new)
}

/// Write `bytes` to `path`. Refuses to replace an existing file unless
/// `force` is set.
///
/// # Errors
///
/// An input error naming `what` and the path.
pub fn write(path: &Path, bytes: &[u8], force: bool, what: &str) -> Result<(), CliError> {
    let mut options = OpenOptions::new();
    options.write(true);
    if force {
        options.create(true).truncate(true);
    } else {
        options.create_new(true);
    }
    let err = |e: std::io::Error| {
        let hint = if e.kind() == std::io::ErrorKind::AlreadyExists {
            " (use --force to overwrite)"
        } else {
            ""
        };
        CliError::input(format!(
            "cannot write {what} file '{}': {e}{hint}",
            path.display()
        ))
    };
    let mut file = options.open(path).map_err(err)?;
    file.write_all(bytes).map_err(err)?;
    file.flush().map_err(err)?;
    Ok(())
}

/// Lower-case hexadecimal.
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        for nibble in [b >> 4, b & 0x0f] {
            if let Some(&d) = DIGITS.get(usize::from(nibble)) {
                out.push(char::from(d));
            }
        }
    }
    out
}

/// A short public fingerprint of secret bytes: the first 8 bytes of a
/// SHA3-256 transcript hash (label `"VYRA-cli-fingerprint-v1"`), in hex. Used
/// to show that two secrets match without printing either.
pub fn fingerprint(secret: &SecretBytes) -> String {
    let mut t = Transcript::new(FINGERPRINT_LABEL);
    t.append(secret.expose());
    let digest = t.finalize();
    hex(digest.get(..8).unwrap_or(&digest))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_encodes() {
        assert_eq!(hex(&[0x00, 0x0f, 0xa5, 0xff]), "000fa5ff");
        assert_eq!(hex(&[]), "");
    }

    #[test]
    fn fingerprint_is_short_and_stable() {
        let a = fingerprint(&SecretBytes::from_slice(b"k"));
        assert_eq!(a.len(), 16);
        assert_eq!(a, fingerprint(&SecretBytes::from_slice(b"k")));
        assert_ne!(a, fingerprint(&SecretBytes::from_slice(b"K")));
    }
}
