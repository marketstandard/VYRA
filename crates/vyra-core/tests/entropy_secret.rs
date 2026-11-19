//! Entropy determinism and secret hygiene tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use vyra_core::{DeterministicEntropy, EntropySource, OsEntropy, SecretBytes};
use zeroize::{Zeroize, ZeroizeOnDrop};

fn draw(e: &mut dyn EntropySource, n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    e.fill(&mut v).unwrap();
    v
}

#[test]
fn deterministic_entropy_is_reproducible() {
    let a = draw(&mut DeterministicEntropy::from_seed(b"seed-1"), 1000);
    let b = draw(&mut DeterministicEntropy::from_seed(b"seed-1"), 1000);
    assert_eq!(a, b);
}

#[test]
fn deterministic_entropy_is_seed_sensitive() {
    let a = draw(&mut DeterministicEntropy::from_seed(b"seed-1"), 64);
    let b = draw(&mut DeterministicEntropy::from_seed(b"seed-2"), 64);
    let c = draw(&mut DeterministicEntropy::from_seed(b"seed-"), 64);
    let d = draw(&mut DeterministicEntropy::from_seed(b""), 64);
    assert_ne!(a, b);
    assert_ne!(a, c);
    assert_ne!(c, d);
}

#[test]
fn deterministic_entropy_continues_stream() {
    let mut e = DeterministicEntropy::from_seed(b"s");
    let first = draw(&mut e, 32);
    let second = draw(&mut e, 32);
    assert_ne!(first, second);
}

#[test]
fn os_entropy_is_usable_as_dyn() {
    let mut os = OsEntropy::new();
    let a = draw(&mut os, 32);
    let b = draw(&mut os, 32);
    assert_ne!(a, b);
}

#[test]
fn secret_debug_is_redacted() {
    let s = SecretBytes::from_slice(b"super secret key material");
    let dbg = format!("{s:?}");
    assert_eq!(dbg, "[REDACTED]");
    assert!(!dbg.contains("secret key"));
    let pretty = format!("{s:#?}");
    assert_eq!(pretty, "[REDACTED]");
}

#[test]
fn secret_in_place_wipe_zeroes_every_byte() {
    // In-place wipe through `expose_mut`: the length is kept, so every byte
    // can be observed afterwards.
    let mut s = SecretBytes::new(vec![0x5A; 48]);
    assert!(s.expose().iter().all(|&b| b == 0x5A));
    s.expose_mut().zeroize();
    assert_eq!(s.len(), 48);
    assert!(s.expose().iter().all(|&b| b == 0));
}

#[test]
fn secret_zeroize_empties() {
    // `SecretBytes::zeroize` wipes the buffer and truncates it to length 0.
    // Only the observable part (empty afterwards) is tested here; that the
    // old contents were overwritten is verified by code inspection
    // (`Vec::zeroize` overwrites the whole allocation before truncating),
    // since reading freed or truncated memory would need unsafe code.
    let mut s = SecretBytes::new(vec![0x5A; 48]);
    assert_eq!(s.len(), 48);
    s.zeroize();
    assert_eq!(s.len(), 0);
    assert!(s.is_empty());
}

/// Marker-trait check only; drop-zeroization itself is verified by code
/// inspection (`impl Drop for SecretBytes` calls `Vec::zeroize`), not by test.
#[test]
fn secret_declares_zeroize_on_drop_marker() {
    fn assert_zod<T: ZeroizeOnDrop>() {}
    assert_zod::<SecretBytes>();
}

#[test]
fn secret_ct_eq() {
    let a = SecretBytes::from_slice(&[1, 2, 3, 4]);
    let b = SecretBytes::new(vec![1, 2, 3, 4]);
    let c = SecretBytes::from_slice(&[1, 2, 3, 5]);
    assert!(a.ct_eq(&b));
    assert!(!a.ct_eq(&c));
    assert!(!a.ct_eq(&SecretBytes::from_slice(&[1, 2, 3])));
    assert_eq!(a.expose(), &[1, 2, 3, 4]);
}
