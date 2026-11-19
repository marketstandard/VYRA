//! NIST security categories.

/// A NIST post-quantum security category.
///
/// Categories are defined relative to the cost of key search on AES-128 (1),
/// AES-192 (3) and AES-256 (5), and to collision search on SHA-256 (2). VYRA quotes the category claimed by each
/// component and, for a hybrid, the minimum of its components' categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SecurityLevel {
    /// NIST category 1 (comparable to AES-128 key search).
    L1,
    /// NIST category 2 (comparable to collision search on SHA-256).
    L2,
    /// NIST category 3 (comparable to AES-192 key search).
    L3,
    /// NIST category 5 (comparable to AES-256 key search).
    L5,
}

impl SecurityLevel {
    /// The NIST category number: 1, 2, 3 or 5.
    pub const fn category(self) -> u8 {
        match self {
            SecurityLevel::L1 => 1,
            SecurityLevel::L2 => 2,
            SecurityLevel::L3 => 3,
            SecurityLevel::L5 => 5,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn categories() {
        assert_eq!(SecurityLevel::L1.category(), 1);
        assert_eq!(SecurityLevel::L2.category(), 2);
        assert_eq!(SecurityLevel::L3.category(), 3);
        assert_eq!(SecurityLevel::L5.category(), 5);
        assert_eq!(
            SecurityLevel::L5.min(SecurityLevel::L1),
            SecurityLevel::L1,
            "Ord follows category order"
        );
    }
}
