//! Adapters from [`EntropySource`] to the `rand_core` 0.10 RNG traits.
//!
//! The upstream component crates (`ml-kem` 0.3, `ml-dsa` 0.1, the HQC
//! implementation, `ed25519-dalek` 3) all take randomness through `rand_core`
//! 0.10. Some of their entry points accept a fallible
//! [`TryCryptoRng`]; others demand an infallible
//! [`CryptoRng`](rand_core::CryptoRng). Two adapters cover both cases:
//!
//! - [`RandCoreTryRng`]: fallible, `Error = vyra_core::Error`. Prefer it
//!   wherever the upstream API accepts a `TryCryptoRng`; a failure propagates
//!   immediately.
//! - [`RandCoreRng`]: infallible, for APIs that require `CryptoRng`. Because it
//!   cannot report an error in-band, a failure is recorded and every byte it
//!   emits from then on is zero. **The caller must call
//!   [`RandCoreRng::finish`] after the upstream call and discard the upstream
//!   result if it returns an error.**
//!
//! Neither adapter panics.

use core::convert::Infallible;
use core::fmt;

use rand_core::{TryCryptoRng, TryRng};

use crate::entropy::EntropySource;
use crate::error::{Error, Result};

/// Fallible `rand_core` 0.10 adapter: implements
/// [`TryRng`] + [`TryCryptoRng`] with `Error = vyra_core::Error`.
pub struct RandCoreTryRng<'a> {
    source: &'a mut dyn EntropySource,
}

impl<'a> RandCoreTryRng<'a> {
    /// Wrap `source`. The source must be cryptographically secure for any use
    /// other than tests.
    pub fn new(source: &'a mut dyn EntropySource) -> Self {
        RandCoreTryRng { source }
    }
}

impl fmt::Debug for RandCoreTryRng<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RandCoreTryRng { .. }")
    }
}

impl TryRng for RandCoreTryRng<'_> {
    type Error = Error;

    fn try_next_u32(&mut self) -> Result<u32> {
        let mut b = [0u8; 4];
        self.source.fill(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64> {
        let mut b = [0u8; 8];
        self.source.fill(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<()> {
        self.source.fill(dst)
    }
}

impl TryCryptoRng for RandCoreTryRng<'_> {}

/// Infallible `rand_core` 0.10 adapter: implements
/// [`CryptoRng`](rand_core::CryptoRng) (via `TryCryptoRng<Error = Infallible>`).
///
/// If the wrapped source fails, the adapter latches the failure, zero-fills
/// that request and every later one, and stops calling the source.
/// [`finish`](Self::finish) then returns [`Error::EntropyFailure`]. Any value
/// produced by an upstream call that used this adapter must be discarded if
/// `finish` fails.
#[must_use = "call finish() to learn whether the entropy source failed"]
pub struct RandCoreRng<'a> {
    source: &'a mut dyn EntropySource,
    failed: bool,
}

impl<'a> RandCoreRng<'a> {
    /// Wrap `source`. The source must be cryptographically secure for any use
    /// other than tests.
    pub fn new(source: &'a mut dyn EntropySource) -> Self {
        RandCoreRng {
            source,
            failed: false,
        }
    }

    /// Report whether every request was served by the source.
    ///
    /// # Errors
    ///
    /// [`Error::EntropyFailure`] if any request failed; the upstream result
    /// computed with this adapter must then be discarded.
    pub fn finish(self) -> Result<()> {
        if self.failed {
            Err(Error::EntropyFailure)
        } else {
            Ok(())
        }
    }

    fn fill_or_latch(&mut self, dst: &mut [u8]) {
        if !self.failed && self.source.fill(dst).is_err() {
            self.failed = true;
        }
        if self.failed {
            dst.fill(0);
        }
    }
}

impl fmt::Debug for RandCoreRng<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RandCoreRng")
            .field("failed", &self.failed)
            .finish_non_exhaustive()
    }
}

impl TryRng for RandCoreRng<'_> {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> core::result::Result<u32, Infallible> {
        let mut b = [0u8; 4];
        self.fill_or_latch(&mut b);
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> core::result::Result<u64, Infallible> {
        let mut b = [0u8; 8];
        self.fill_or_latch(&mut b);
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> core::result::Result<(), Infallible> {
        self.fill_or_latch(dst);
        Ok(())
    }
}

impl TryCryptoRng for RandCoreRng<'_> {}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::entropy::DeterministicEntropy;
    use rand_core::{CryptoRng, Rng};

    struct Failing;
    impl EntropySource for Failing {
        fn fill(&mut self, _dest: &mut [u8]) -> Result<()> {
            Err(Error::EntropyFailure)
        }
    }

    fn needs_crypto_rng<R: CryptoRng + ?Sized>(rng: &mut R) -> [u8; 16] {
        let mut out = [0xAAu8; 16];
        rng.fill_bytes(&mut out);
        out
    }

    fn needs_try_crypto_rng<R: TryCryptoRng + ?Sized>(
        rng: &mut R,
    ) -> core::result::Result<[u8; 16], R::Error> {
        let mut out = [0xAAu8; 16];
        rng.try_fill_bytes(&mut out)?;
        Ok(out)
    }

    #[test]
    fn infallible_adapter_matches_source() {
        let mut src = DeterministicEntropy::from_seed(b"x");
        let mut expected = [0u8; 16];
        src.clone().fill(&mut expected).unwrap();

        let mut rng = RandCoreRng::new(&mut src);
        assert_eq!(needs_crypto_rng(&mut rng), expected);
        rng.finish().unwrap();
    }

    #[test]
    fn infallible_adapter_latches_failure() {
        let mut src = Failing;
        let mut rng = RandCoreRng::new(&mut src);
        assert_eq!(needs_crypto_rng(&mut rng), [0u8; 16]);
        assert_eq!(rng.next_u64(), 0);
        assert_eq!(rng.finish(), Err(Error::EntropyFailure));
    }

    #[test]
    fn fallible_adapter_propagates() {
        let mut src = Failing;
        let mut rng = RandCoreTryRng::new(&mut src);
        assert_eq!(needs_try_crypto_rng(&mut rng), Err(Error::EntropyFailure));

        let mut good = DeterministicEntropy::from_seed(b"x");
        let mut expected = [0u8; 16];
        good.clone().fill(&mut expected).unwrap();
        let mut rng = RandCoreTryRng::new(&mut good);
        assert_eq!(needs_try_crypto_rng(&mut rng), Ok(expected));
    }
}
