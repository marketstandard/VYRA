//! S9 secret hygiene: redacted Debug, no secret bytes in Debug output.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use common::SUITES;
use vyra_core::DeterministicEntropy;
use vyra_sig::{CompositeSecretKey, CompositeSignature, SigSuite};

#[test]
fn secret_key_debug_is_redacted() {
    for suite in SUITES {
        let scheme = CompositeSignature::new(suite);
        let (pk, sk) = scheme
            .generate(&mut DeterministicEntropy::from_seed(b"hygiene"))
            .unwrap();
        let dbg = format!("{sk:?}");
        assert!(dbg.contains("[REDACTED]"), "{dbg}");
        assert!(dbg.contains("CompositeSecretKey"));
        // No byte of the key leaks in decimal or hex form.
        let hex: String = sk.expose_raw().iter().map(|b| format!("{b:02x}")).collect();
        assert!(!dbg.contains(&hex[..16]));
        assert!(!dbg.contains(&format!("{:?}", &sk.expose_raw()[..4])));
        // The encoded secret is SecretBytes and is redacted as well.
        assert_eq!(format!("{:?}", sk.to_bytes()), "[REDACTED]");
        // Public objects print a summary, not their bytes.
        assert!(!format!("{pk:?}").contains(&format!("{:?}", &pk.as_raw()[..4])));
    }
}

/// Marker-trait check only. This does NOT test that memory is wiped on
/// drop (that cannot be observed without unsafe code); drop-zeroization is
/// verified by code inspection: `CompositeSecretKey`'s only secret field is a
/// `vyra_core::SecretBytes`, whose `Drop` calls `Vec::zeroize`.
#[test]
fn secret_types_declare_zeroize_on_drop_marker() {
    fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    assert_zeroize_on_drop::<CompositeSecretKey>();
    assert_zeroize_on_drop::<vyra_core::SecretBytes>();
}

#[test]
fn secret_key_ct_eq() {
    let suite = SUITES[0];
    let a = CompositeSecretKey::from_raw(suite, &[1u8; 64]).unwrap();
    let b = CompositeSecretKey::from_raw(suite, &[1u8; 64]).unwrap();
    let c = CompositeSecretKey::from_raw(suite, &[2u8; 64]).unwrap();
    let d = CompositeSecretKey::from_raw(SUITES[1], &[1u8; 64]).unwrap();
    assert!(a.ct_eq(&b));
    assert!(!a.ct_eq(&c));
    assert!(!a.ct_eq(&d));
}

#[test]
fn secret_key_debug_is_redacted_pq() {
    for suite in common::PQ_SUITES {
        let scheme = CompositeSignature::new(suite);
        let (pk, sk) = scheme
            .generate(&mut DeterministicEntropy::from_seed(b"hygiene"))
            .unwrap();
        let dbg = format!("{sk:?}");
        assert!(dbg.contains("[REDACTED]"), "{dbg}");
        let hex: String = sk.expose_raw().iter().map(|b| format!("{b:02x}")).collect();
        assert!(!dbg.contains(&hex[..16]));
        // The SLH-DSA seeds (after the 32-byte ML-DSA seed) do not leak either.
        assert!(!dbg.contains(&hex[64..80]));
        assert!(!dbg.contains(&format!("{:?}", &sk.expose_raw()[32..36])));
        assert_eq!(format!("{:?}", sk.to_bytes()), "[REDACTED]");
        assert!(!format!("{pk:?}").contains(&format!("{:?}", &pk.as_raw()[..4])));
    }
}

#[test]
fn secret_key_ct_eq_pq() {
    let a = CompositeSecretKey::from_raw(SigSuite::Pq1, &[1u8; 80]).unwrap();
    let b = CompositeSecretKey::from_raw(SigSuite::Pq1, &[1u8; 80]).unwrap();
    let c = CompositeSecretKey::from_raw(SigSuite::Pq1, &[2u8; 80]).unwrap();
    let d = CompositeSecretKey::from_raw(SigSuite::Pq3, &[1u8; 104]).unwrap();
    assert!(a.ct_eq(&b));
    assert!(!a.ct_eq(&c));
    assert!(!a.ct_eq(&d));
}
