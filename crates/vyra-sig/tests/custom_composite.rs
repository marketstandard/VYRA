//! `CustomComposite::from_components`: composites assembled from caller-
//! supplied components under a caller-chosen descriptor (crypto-agility entry
//! point; outside the named suites and the wire format).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use common::{flip, positions};
use vyra_core::{
    DeterministicEntropy, EntropySource, Error, OsEntropy, Result, SecretBytes, SecurityLevel,
    SignatureScheme,
};
use vyra_sig::{
    CompositeComponent, CompositeSignature, CustomComposite, CustomSuite, Ed25519, MlDsa44,
    MlDsa65, SigSuite, SlhDsaShake128s, composite_context, message_representative_with_digest,
};

const MSG: &[u8] = b"custom composite";
const CTX: &[u8] = b"custom-ctx";

fn descriptor(id: u8) -> CustomSuite {
    CustomSuite {
        id,
        name: "CUSTOM-TEST",
        level: SecurityLevel::L1,
    }
}

#[test]
fn named_suite_ids_are_rejected() {
    for suite in SigSuite::all() {
        let res = CustomComposite::from_components(
            descriptor(suite.id()),
            Box::new(MlDsa44),
            Box::new(Ed25519),
        );
        assert_eq!(
            res.map(|_| ()),
            Err(Error::InvalidEncoding(
                "custom suite id is assigned to a named suite"
            ))
        );
    }
    assert!(
        CustomComposite::from_components(descriptor(0x40), Box::new(MlDsa44), Box::new(Ed25519))
            .is_ok()
    );
}

/// Round trip and S4-style tampering with two real components (fast pair).
#[test]
fn round_trip_and_tamper_mldsa65_ed25519() {
    let mut rng = OsEntropy::new();
    let c =
        CustomComposite::from_components(descriptor(0x40), Box::new(MlDsa65), Box::new(Ed25519))
            .unwrap();
    assert_eq!(c.descriptor(), descriptor(0x40));
    assert_eq!(c.name(), "CUSTOM-TEST");
    assert_eq!(c.level(), SecurityLevel::L1);
    assert_eq!(c.public_key_len(), MlDsa65::PUBLIC_KEY_LEN + 32);
    assert_eq!(c.secret_key_len(), 64);
    assert_eq!(c.signature_len(), MlDsa65::SIGNATURE_LEN + 64);
    let dbg = format!("{c:?}");
    assert!(
        dbg.contains("ML-DSA-65") && dbg.contains("Ed25519"),
        "{dbg}"
    );

    let (pk, sk) = c.generate_raw(&mut rng).unwrap();
    c.validate_public_key(&pk).unwrap();
    let sig = c.sign_raw(sk.expose(), MSG, CTX, &mut rng).unwrap();
    assert_eq!(sig.len(), c.signature_len());
    c.verify_raw(&pk, MSG, CTX, &sig).unwrap();
    // Raw trait: empty context.
    let s2 = SignatureScheme::sign(&c, sk.expose(), MSG, &mut rng).unwrap();
    SignatureScheme::verify(&c, &pk, MSG, &s2).unwrap();
    assert_eq!(
        c.verify_raw(&pk, MSG, CTX, &s2),
        Err(Error::VerificationFailed)
    );

    let reject = |pk: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8], what: &str| {
        assert_eq!(
            c.verify_raw(pk, msg, ctx, sig),
            Err(Error::VerificationFailed),
            "{what}"
        );
    };
    for i in positions(MSG.len()) {
        reject(&pk, &flip(MSG, i, 0), CTX, &sig, "message");
    }
    for i in positions(CTX.len()) {
        reject(&pk, MSG, &flip(CTX, i, 1), &sig, "context");
    }
    let split = MlDsa65::SIGNATURE_LEN;
    for i in positions(split) {
        reject(&pk, MSG, CTX, &flip(&sig, i, 2), "first half");
    }
    for i in positions(64) {
        reject(&pk, MSG, CTX, &flip(&sig, split + i, 3), "second half");
    }
    for i in positions(MlDsa65::PUBLIC_KEY_LEN) {
        reject(&flip(&pk, i, 4), MSG, CTX, &sig, "first pk half");
    }
    // A flipped Ed25519 key is either rejected by validation or fails to
    // verify; both are VerificationFailed inside verify_raw.
    for i in positions(32) {
        reject(
            &flip(&pk, MlDsa65::PUBLIC_KEY_LEN + i, 5),
            MSG,
            CTX,
            &sig,
            "second pk half",
        );
    }
    // Lengths.
    assert!(matches!(
        c.verify_raw(&pk[1..], MSG, CTX, &sig),
        Err(Error::InvalidLength { .. })
    ));
    assert!(matches!(
        c.verify_raw(&pk, MSG, CTX, &sig[1..]),
        Err(Error::InvalidLength { .. })
    ));
    assert!(matches!(
        c.sign_raw(&sk.expose()[1..], MSG, CTX, &mut rng),
        Err(Error::InvalidLength { .. })
    ));
}

/// The custom construction is the named construction with another suite
/// byte: same components as VYRA-SIG-2 and the same key bytes, but
/// signatures do not transfer in either direction.
#[test]
fn custom_and_named_signatures_do_not_transfer() {
    let named = CompositeSignature::new(SigSuite::Vyra2);
    let custom =
        CustomComposite::from_components(descriptor(0x42), Box::new(MlDsa44), Box::new(Ed25519))
            .unwrap();
    let (pk_n, sk_n) = named
        .generate_raw(&mut DeterministicEntropy::from_seed(b"same"))
        .unwrap();
    let (pk_c, sk_c) = custom
        .generate_raw(&mut DeterministicEntropy::from_seed(b"same"))
        .unwrap();
    assert_eq!(pk_n, pk_c);
    assert!(sk_n.ct_eq(&sk_c));
    let mut rng = OsEntropy::new();
    let sig_n = named.sign_raw(sk_n.expose(), MSG, CTX, &mut rng).unwrap();
    let sig_c = custom.sign_raw(sk_c.expose(), MSG, CTX, &mut rng).unwrap();
    named.verify_raw(&pk_n, MSG, CTX, &sig_n).unwrap();
    custom.verify_raw(&pk_c, MSG, CTX, &sig_c).unwrap();
    assert_eq!(
        named.verify_raw(&pk_n, MSG, CTX, &sig_c),
        Err(Error::VerificationFailed)
    );
    assert_eq!(
        custom.verify_raw(&pk_c, MSG, CTX, &sig_n),
        Err(Error::VerificationFailed)
    );
}

/// Two real post-quantum components (ML-DSA-44 + SLH-DSA-SHAKE-128s) under a
/// custom id: round trip, the SLH-DSA half is made under the composite
/// context with the custom id, tampering is rejected. One signature.
#[test]
fn round_trip_mldsa44_slhdsa128s() {
    let c = CustomComposite::from_components(
        descriptor(0x7e),
        Box::new(MlDsa44),
        Box::new(SlhDsaShake128s),
    )
    .unwrap();
    let (pk, sk) = c
        .generate_raw(&mut DeterministicEntropy::from_seed(b"pq custom"))
        .unwrap();
    let sig = c
        .sign_raw(sk.expose(), MSG, CTX, &mut OsEntropy::new())
        .unwrap();
    c.verify_raw(&pk, MSG, CTX, &sig).unwrap();
    // The same composite, rebuilt by hand: M' under id 0x7e.
    let (pk1, pk2) = pk.split_at(MlDsa44::PUBLIC_KEY_LEN);
    let (s1, s2) = sig.split_at(MlDsa44::SIGNATURE_LEN);
    let digest = {
        use sha3::{Digest, Sha3_256};
        let frame = |x: &[u8]| [&(x.len() as u64).to_be_bytes()[..], x].concat();
        let mut h = Sha3_256::new();
        h.update(frame(b"VYRA-SIG-PK-v1"));
        h.update(frame(&[0x7e]));
        h.update(frame(pk1));
        h.update(frame(pk2));
        let d: [u8; 32] = h.finalize().into();
        d
    };
    let m = message_representative_with_digest(0x7e, &digest, CTX, MSG).unwrap();
    let ctx = composite_context(0x7e);
    MlDsa44.verify_half(pk1, &m, &ctx, s1).unwrap();
    SlhDsaShake128s.verify_half(pk2, &m, &ctx, s2).unwrap();
    assert_eq!(
        SlhDsaShake128s.verify(pk2, &m, s2),
        Err(Error::VerificationFailed),
        "the SLH-DSA half is not a standalone empty-context signature"
    );
    for i in positions(SlhDsaShake128s::SIGNATURE_LEN) {
        let bad = flip(&sig, MlDsa44::SIGNATURE_LEN + i, 0);
        assert_eq!(
            c.verify_raw(&pk, MSG, CTX, &bad),
            Err(Error::VerificationFailed)
        );
    }
}

/// A component that has "yielded": it delegates to a real scheme but its
/// verification accepts anything. Used to show what a custom assembly is
/// for (failure injection) and that the composite then rests on the other
/// component alone.
struct Yielded<T>(T);

impl<T: SignatureScheme> SignatureScheme for Yielded<T> {
    fn name(&self) -> &'static str {
        "YIELDED"
    }
    fn level(&self) -> SecurityLevel {
        self.0.level()
    }
    fn public_key_len(&self) -> usize {
        self.0.public_key_len()
    }
    fn secret_key_len(&self) -> usize {
        self.0.secret_key_len()
    }
    fn signature_len(&self) -> usize {
        self.0.signature_len()
    }
    fn generate_keypair(&self, rng: &mut dyn EntropySource) -> Result<(Vec<u8>, SecretBytes)> {
        self.0.generate_keypair(rng)
    }
    fn sign(&self, sk: &[u8], m: &[u8], rng: &mut dyn EntropySource) -> Result<Vec<u8>> {
        self.0.sign(sk, m, rng)
    }
    fn verify(&self, _pk: &[u8], _m: &[u8], _sig: &[u8]) -> Result<()> {
        Ok(())
    }
}

impl<T: SignatureScheme> CompositeComponent for Yielded<T> {
    fn context_bound(&self) -> bool {
        false
    }
    fn sign_half(
        &self,
        sk: &[u8],
        m: &[u8],
        _ctx: &[u8],
        rng: &mut dyn EntropySource,
    ) -> Result<Vec<u8>> {
        self.0.sign(sk, m, rng)
    }
    fn verify_half(&self, _pk: &[u8], _m: &[u8], _ctx: &[u8], _sig: &[u8]) -> Result<()> {
        Ok(())
    }
    fn validate_public_key(&self, pk: &[u8]) -> Result<()> {
        if pk.len() == self.0.public_key_len() {
            Ok(())
        } else {
            Err(Error::InvalidLength {
                what: "yielded public key",
                expected: self.0.public_key_len(),
                actual: pk.len(),
            })
        }
    }
}

#[test]
fn failure_injection_with_a_yielded_component() {
    let mut rng = OsEntropy::new();
    let c = CustomComposite::from_components(
        descriptor(0x50),
        Box::new(MlDsa44),
        Box::new(Yielded(Ed25519)),
    )
    .unwrap();
    let (pk, sk) = c.generate_raw(&mut rng).unwrap();
    let sig = c.sign_raw(sk.expose(), MSG, CTX, &mut rng).unwrap();
    c.verify_raw(&pk, MSG, CTX, &sig).unwrap();
    let split = MlDsa44::SIGNATURE_LEN;
    // The yielded half no longer protects anything: garbage there verifies...
    let garbage_second = [&sig[..split], &[0u8; 64][..]].concat();
    c.verify_raw(&pk, MSG, CTX, &garbage_second).unwrap();
    // ...but the composite still rests on ML-DSA: a bad first half, a
    // different message or a different context is rejected.
    let garbage_first = [&vec![0u8; split][..], &sig[split..]].concat();
    assert_eq!(
        c.verify_raw(&pk, MSG, CTX, &garbage_first),
        Err(Error::VerificationFailed)
    );
    assert_eq!(
        c.verify_raw(&pk, b"other", CTX, &garbage_second),
        Err(Error::VerificationFailed)
    );
    assert_eq!(
        c.verify_raw(&pk, MSG, b"other", &garbage_second),
        Err(Error::VerificationFailed)
    );
}
