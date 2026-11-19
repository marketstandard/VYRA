//! Statements the facade documentation makes about itself.

use vyra::sig::SigSuite;

/// The crate docs say the failure-injection crate (intentionally insecure
/// component models) is not re-exported: the facade does not even depend on it.
#[test]
fn facade_does_not_depend_on_the_failure_injection_crate() {
    let manifest = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))
        .unwrap_or_default();
    assert!(manifest.contains("vyra-sig"), "manifest not read");
    assert!(!manifest.contains("vyra-yield"));
    assert!(!manifest.contains("vyra-proofs"));
}

/// Both signature families documented in the crate docs are reachable, with
/// the component names the docs give.
#[test]
fn both_signature_families_are_exposed() {
    let names = |suites: [SigSuite; 3]| -> Vec<String> {
        suites
            .iter()
            .map(|s| format!("{}={}+{}", s.name(), s.first().name(), s.second().name()))
            .collect()
    };
    assert_eq!(
        names(SigSuite::transition()),
        [
            "VYRA-SIG-2=ML-DSA-44+Ed25519",
            "VYRA-SIG-3=ML-DSA-65+Ed25519",
            "VYRA-SIG-5=ML-DSA-87+Ed25519"
        ]
    );
    assert_eq!(
        names(SigSuite::dual_pq()),
        [
            "VYRA-SIG-PQ1=ML-DSA-44+SLH-DSA-SHAKE-128s",
            "VYRA-SIG-PQ3=ML-DSA-65+SLH-DSA-SHAKE-192s",
            "VYRA-SIG-PQ5=ML-DSA-87+SLH-DSA-SHAKE-256s"
        ]
    );
    assert!(SigSuite::dual_pq().iter().all(|s| s.is_dual_pq()));
    assert!(!SigSuite::transition().iter().any(|s| s.is_dual_pq()));
    // The custom assembly entry points are re-exported.
    let _ = vyra::sig::CustomComposite::from_components;
    let _ = vyra::kem::CustomHybridKem::from_components;
}
