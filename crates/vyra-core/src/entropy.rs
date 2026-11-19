//! Entropy sources.
//!
//! All VYRA randomness enters through [`EntropySource`]. Production code uses
//! [`OsEntropy`]; [`DeterministicEntropy`] exists only so that tests and
//! known-answer vectors are reproducible.

use core::fmt;

use shake::{Shake256Reader, XofReader};

use crate::error::{Error, Result};
use crate::transcript::Transcript;

/// A source of random bytes.
///
/// The trait is object safe: algorithm traits take `&mut dyn EntropySource`.
pub trait EntropySource {
    /// Fill `dest` entirely with random bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::EntropyFailure`] if the source cannot produce bytes.
    /// On error the contents of `dest` are unspecified and must not be used.
    fn fill(&mut self, dest: &mut [u8]) -> Result<()>;
}

impl<T: EntropySource + ?Sized> EntropySource for &mut T {
    fn fill(&mut self, dest: &mut [u8]) -> Result<()> {
        (**self).fill(dest)
    }
}

/// The operating system's cryptographically secure random number generator,
/// accessed through the `getrandom` crate.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsEntropy;

impl OsEntropy {
    /// Create a handle to the OS generator. The handle holds no state.
    pub const fn new() -> Self {
        OsEntropy
    }
}

impl EntropySource for OsEntropy {
    fn fill(&mut self, dest: &mut [u8]) -> Result<()> {
        getrandom::fill(dest).map_err(|_| Error::EntropyFailure)
    }
}

/// Domain label for [`DeterministicEntropy`].
const DETERMINISTIC_LABEL: &[u8] = b"VYRA-DeterministicEntropy-v1";

/// A deterministic byte stream derived from a seed.
///
/// **For tests and known-answer vectors only.** Anyone who knows the seed can
/// reproduce every byte, so keys generated from it are not secret. Never use
/// it for real keys.
///
/// The stream is the SHAKE256 output of a [`Transcript`] with label
/// `"VYRA-DeterministicEntropy-v1"` and one field, the seed (see
/// [`Transcript::finalize_xof`] for the exact byte encoding). Successive calls
/// to [`EntropySource::fill`] continue the same stream, so filling 16 then 16
/// bytes gives the same 32 bytes as filling 32 at once.
#[derive(Clone)]
pub struct DeterministicEntropy {
    reader: Shake256Reader,
}

impl DeterministicEntropy {
    /// Create a stream from `seed`. Any seed length is accepted.
    pub fn from_seed(seed: &[u8]) -> Self {
        let mut t = Transcript::new(DETERMINISTIC_LABEL);
        t.append(seed);
        DeterministicEntropy {
            reader: t.into_xof_reader(),
        }
    }
}

impl fmt::Debug for DeterministicEntropy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DeterministicEntropy([REDACTED])")
    }
}

impl EntropySource for DeterministicEntropy {
    fn fill(&mut self, dest: &mut [u8]) -> Result<()> {
        self.reader.read(dest);
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn os_entropy_fills() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        OsEntropy.fill(&mut a).unwrap();
        OsEntropy.fill(&mut b).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn deterministic_is_streaming() {
        let mut one = DeterministicEntropy::from_seed(b"seed");
        let mut whole = [0u8; 32];
        one.fill(&mut whole).unwrap();

        let mut two = DeterministicEntropy::from_seed(b"seed");
        let mut parts = [0u8; 32];
        let (lo, hi) = parts.split_at_mut(16);
        two.fill(lo).unwrap();
        two.fill(hi).unwrap();
        assert_eq!(whole, parts);
    }

    #[test]
    fn debug_is_redacted() {
        let d = DeterministicEntropy::from_seed(b"secret seed");
        assert_eq!(format!("{d:?}"), "DeterministicEntropy([REDACTED])");
    }
}
