//! A deterministic parallel map: work is handed out one item at a time
//! (work stealing over an atomic counter), results are returned in input
//! order, so the output never depends on scheduling.

use std::sync::atomic::{AtomicUsize, Ordering};

use vyra_core::{Error, Result};

/// Apply `f` to every item on `threads` worker threads (at least one) and
/// return the results in input order.
///
/// # Errors
///
/// The error of the first failing item in input order, or `Internal` if a
/// worker panicked.
pub fn map<T, R, F>(items: &[T], threads: usize, f: F) -> Result<Vec<R>>
where
    T: Sync,
    R: Send,
    F: Fn(&T) -> Result<R> + Sync,
{
    let next = AtomicUsize::new(0);
    let threads = threads.max(1).min(items.len().max(1));
    let parts: Vec<Vec<(usize, Result<R>)>> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..threads)
            .map(|_| {
                scope.spawn(|| {
                    let mut out = Vec::new();
                    loop {
                        let i = next.fetch_add(1, Ordering::Relaxed);
                        let Some(item) = items.get(i) else {
                            break;
                        };
                        out.push((i, f(item)));
                    }
                    out
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| {
                h.join()
                    .unwrap_or_else(|_| vec![(0, Err(Error::Internal("worker thread panicked")))])
            })
            .collect()
    });
    let mut all: Vec<(usize, Result<R>)> = parts.into_iter().flatten().collect();
    all.sort_by_key(|(i, _)| *i);
    all.into_iter().map(|(_, r)| r).collect()
}
