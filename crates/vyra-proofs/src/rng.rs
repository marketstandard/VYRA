//! P5: totality and failure latching of the infallible `RandCoreRng` adapter.
//!
//! The entropy source is modelled as fully nondeterministic: every `fill`
//! call independently succeeds or fails, and writes arbitrary bytes into the
//! buffer in both cases (the trait leaves the buffer unspecified on error).
//!
//! NOT covered: `RandCoreTryRng`; more calls or longer buffers than the bound;
//! the quality of the source's randomness; upstream crates' handling of the
//! zero bytes (callers must check `finish`, which is what the adapter's
//! contract says).

// Harness code: every index is checked by the model checker itself.
#![allow(clippy::indexing_slicing)]

use core::cell::Cell;

use vyra_core::rand_core::TryRng;
use vyra_core::{EntropySource, Error, RandCoreRng, Result};

use crate::bounds::{RNG_MAX_CALLS, RNG_MAX_FILL};

/// Shared observation state of the nondeterministic source.
struct Observed {
    /// Some `fill` call has failed.
    failed: Cell<bool>,
    /// Bytes written by the most recent successful `fill` (first `last_len`).
    last: Cell<[u8; RNG_MAX_FILL]>,
    last_len: Cell<usize>,
}

struct NondetSource<'o> {
    obs: &'o Observed,
}

impl EntropySource for NondetSource<'_> {
    fn fill(&mut self, dest: &mut [u8]) -> Result<()> {
        // Documented adapter behaviour: once a failure is latched, the
        // source is never called again.
        assert!(!self.obs.failed.get(), "source called after a failure");
        assert!(dest.len() <= RNG_MAX_FILL);
        let mut written = [0u8; RNG_MAX_FILL];
        for (d, w) in dest.iter_mut().zip(written.iter_mut()) {
            let v: u8 = kani::any();
            *d = v;
            *w = v;
        }
        let ok: bool = kani::any();
        if ok {
            self.obs.last.set(written);
            self.obs.last_len.set(dest.len());
            Ok(())
        } else {
            self.obs.failed.set(true);
            Err(Error::EntropyFailure)
        }
    }
}

/// `out` equals the source's last successful output if no failure happened,
/// and is all zero otherwise.
fn check_output(obs: &Observed, out: &[u8]) {
    if obs.failed.get() {
        assert!(out.iter().all(|&b| b == 0), "non-zero output after failure");
    } else {
        assert!(obs.last_len.get() == out.len());
        let last = obs.last.get();
        assert!(
            out == &last[..out.len()],
            "output differs from source bytes"
        );
    }
}

/// P5: for every sequence of up to RNG_MAX_CALLS adapter calls (each one of
/// `try_next_u32`, `try_next_u64`, `try_fill_bytes` with a buffer of length
/// <= RNG_MAX_FILL and arbitrary prior contents) and every pattern of source
/// successes/failures:
/// - no call panics;
/// - before any failure, each output is exactly the bytes the source wrote
///   (little-endian for the integers);
/// - from the first failure on, every output (including the failing request)
///   is all zero, and the source is never called again;
/// - `finish()` is `Err(EntropyFailure)` iff some source call failed.
#[kani::proof]
#[kani::unwind(10)]
fn rng_adapter_latches_failure() {
    let obs = Observed {
        failed: Cell::new(false),
        last: Cell::new([0u8; RNG_MAX_FILL]),
        last_len: Cell::new(0),
    };
    let mut src = NondetSource { obs: &obs };
    let mut rng = RandCoreRng::new(&mut src);

    for _ in 0..RNG_MAX_CALLS {
        let op: u8 = kani::any();
        match op % 3 {
            0 => {
                let v = match rng.try_next_u32() {
                    Ok(v) => v,
                    Err(e) => match e {},
                };
                check_output(&obs, &v.to_le_bytes());
            }
            1 => {
                let v = match rng.try_next_u64() {
                    Ok(v) => v,
                    Err(e) => match e {},
                };
                check_output(&obs, &v.to_le_bytes());
            }
            _ => {
                let mut buf: [u8; RNG_MAX_FILL] = kani::any();
                let n: usize = kani::any();
                kani::assume(n <= RNG_MAX_FILL);
                let dst = &mut buf[..n];
                match rng.try_fill_bytes(dst) {
                    Ok(()) => {}
                    Err(e) => match e {},
                }
                check_output(&obs, dst);
            }
        }
    }

    let failed = obs.failed.get();
    let fin = rng.finish();
    if failed {
        assert!(fin == Err(Error::EntropyFailure));
    } else {
        assert!(fin == Ok(()));
    }
}
