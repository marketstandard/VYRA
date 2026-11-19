//! Heap-allocated secret bytes.

use core::fmt;

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Secret bytes (secret keys, shared secrets, seeds) on the heap.
///
/// - The buffer is zeroized when the value is dropped.
/// - `Debug` prints `[REDACTED]`, never the contents.
/// - There is deliberately no `PartialEq`; compare with [`ct_eq`](Self::ct_eq),
///   which runs in constant time for equal-length inputs.
///
/// Read the bytes with [`expose`](Self::expose); the name is meant to make
/// every access visible in review.
#[derive(Clone, Default)]
pub struct SecretBytes {
    bytes: Vec<u8>,
}

impl Zeroize for SecretBytes {
    /// Overwrite the whole allocation with zeros and set the length to 0.
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl ZeroizeOnDrop for SecretBytes {}

impl SecretBytes {
    /// Take ownership of `bytes`. The vector is moved, not copied, so no
    /// unzeroized copy is left behind by this call.
    pub fn new(bytes: Vec<u8>) -> Self {
        SecretBytes { bytes }
    }

    /// Copy `bytes` into a new secret. The caller remains responsible for
    /// zeroizing its own copy.
    pub fn from_slice(bytes: &[u8]) -> Self {
        SecretBytes {
            bytes: bytes.to_vec(),
        }
    }

    /// A zero-filled secret of length `len`, to be written through
    /// [`expose_mut`](Self::expose_mut).
    pub fn zeroed(len: usize) -> Self {
        SecretBytes {
            bytes: vec![0u8; len],
        }
    }

    /// Borrow the secret bytes.
    pub fn expose(&self) -> &[u8] {
        &self.bytes
    }

    /// Mutably borrow the secret bytes (for filling in place).
    pub fn expose_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }

    /// Length in bytes. Lengths are public.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the secret is empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Constant-time equality.
    ///
    /// Runs in time independent of the contents when both lengths are equal.
    /// If the lengths differ it returns `false` immediately; lengths are not
    /// treated as secret.
    pub fn ct_eq(&self, other: &SecretBytes) -> bool {
        bool::from(self.bytes.as_slice().ct_eq(other.bytes.as_slice()))
    }
}

impl From<Vec<u8>> for SecretBytes {
    fn from(bytes: Vec<u8>) -> Self {
        SecretBytes::new(bytes)
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ct_eq_behaves() {
        let a = SecretBytes::from_slice(b"abc");
        assert!(a.ct_eq(&SecretBytes::from_slice(b"abc")));
        assert!(!a.ct_eq(&SecretBytes::from_slice(b"abd")));
        assert!(!a.ct_eq(&SecretBytes::from_slice(b"ab")));
    }
}
