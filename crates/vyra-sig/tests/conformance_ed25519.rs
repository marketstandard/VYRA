//! F4(b) Ed25519 conformance: RFC 8032 §7.1 test vectors 1–3 (PureEd25519,
//! standalone adapter), RFC 8032 §7.3 Ed25519ph (composite half), plus the
//! strict-verification behaviour VYRA relies on.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use common::Fixed;
use vyra_core::{DeterministicEntropy, Error, SignatureScheme};
use vyra_sig::Ed25519;

/// RFC 8032 §7.1, TEST 1–3: (secret key, public key, message, signature).
const RFC8032_VECTORS: [(&str, &str, &str, &str); 3] = [
    (
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
    (
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    ),
];

#[test]
fn rfc8032_section_7_1_vectors() {
    for (i, (sk, pk, msg, sig)) in RFC8032_VECTORS.iter().enumerate() {
        let sk = hex::decode(sk).unwrap();
        let pk = hex::decode(pk).unwrap();
        let msg = hex::decode(msg).unwrap();
        let sig = hex::decode(sig).unwrap();

        // Key generation from the RFC secret key gives the RFC public key.
        let (got_pk, got_sk) = Ed25519.generate_keypair(&mut Fixed::new(&sk)).unwrap();
        assert_eq!(got_pk, pk, "TEST {}", i + 1);
        assert_eq!(got_sk.expose(), &sk[..], "TEST {}", i + 1);

        // Signing gives the RFC signature (deterministic; rng unused).
        let got_sig = Ed25519
            .sign(&sk, &msg, &mut DeterministicEntropy::from_seed(b"unused"))
            .unwrap();
        assert_eq!(got_sig, sig, "TEST {}", i + 1);

        // And it verifies; a one-bit change does not.
        Ed25519.verify(&pk, &msg, &sig).unwrap();
        let mut bad = sig.clone();
        bad[0] ^= 1;
        assert_eq!(
            Ed25519.verify(&pk, &msg, &bad),
            Err(Error::VerificationFailed)
        );
    }
}

#[test]
fn signing_ignores_rng() {
    let sk = [7u8; 32];
    let a = Ed25519.sign(&sk, b"m", &mut common::Failing).unwrap();
    let b = Ed25519
        .sign(&sk, b"m", &mut DeterministicEntropy::from_seed(b"r"))
        .unwrap();
    assert_eq!(a, b);
}

#[test]
fn strict_verification_rejects_small_order_key_forgery() {
    // Public key = identity point (small order); signature R = identity, S = 0.
    // Cofactorless non-strict verification accepts this for EVERY message.
    let mut pk = [0u8; 32];
    pk[0] = 1;
    let mut sig = [0u8; 64];
    sig[0] = 1;

    // Show the forgery is real against the non-strict dalek verifier...
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk).unwrap();
    let dsig = ed25519_dalek::Signature::from_bytes(&sig);
    assert!(vk.verify_strict(b"any message", &dsig).is_err());
    use ed25519_dalek::Verifier;
    assert!(vk.verify(b"any message", &dsig).is_ok());

    // ...and that VYRA's adapter rejects it.
    assert_eq!(
        Ed25519.verify(&pk, b"any message", &sig),
        Err(Error::VerificationFailed)
    );
}

/// Ed25519 group order L, little endian.
const L: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];

#[test]
fn non_canonical_s_is_rejected() {
    let (sk, pk, msg, sig) = RFC8032_VECTORS[1];
    let (_sk, pk, msg, mut sig) = (
        hex::decode(sk).unwrap(),
        hex::decode(pk).unwrap(),
        hex::decode(msg).unwrap(),
        hex::decode(sig).unwrap(),
    );
    // S' = S + L (same value mod L, but not reduced).
    let mut carry = 0u16;
    for i in 0..32 {
        let v = u16::from(sig[32 + i]) + u16::from(L[i]) + carry;
        sig[32 + i] = (v & 0xff) as u8;
        carry = v >> 8;
    }
    assert_eq!(carry, 0);
    assert_eq!(
        Ed25519.verify(&pk, &msg, &sig),
        Err(Error::VerificationFailed)
    );
}

#[test]
fn invalid_point_public_key_is_rejected() {
    // Encodings that dalek cannot decompress to a curve point.
    let mut found = 0;
    for y in 2u8..64 {
        let mut pk = [0u8; 32];
        pk[0] = y;
        if ed25519_dalek::VerifyingKey::from_bytes(&pk).is_err() {
            found += 1;
            assert_eq!(
                Ed25519.verify(&pk, b"m", &[0u8; 64]),
                Err(Error::InvalidEncoding("Ed25519 public key"))
            );
        }
    }
    assert!(found > 0);
}

// ---------------------------------------------------------------------------
// U12-R1: the composite's Ed25519 half is Ed25519ph (RFC 8032 §5.1, PH =
// SHA-512) with the composite context, through
// `CompositeComponent::{sign_half, verify_half}`.
//
// Evidence:
// 1. RFC 8032 §7.3 (the only Ed25519ph test vector; empty context), through
//    the adapter's half-signing path. The values are those of RFC 8032 §7.3
//    (also carried, labelled "From RFC8032 §7.3", in ed25519-dalek 3.0.0's
//    tests/ed25519.rs).
// 2. Non-empty contexts (RFC 8032 has no Ed25519ph vector with a context, and
//    no second pure-Rust implementation with Ed25519ph/context support was
//    found: ed25519-compact 2.6.1 has neither prehash nor context; ring and
//    aws-lc-rs are C-backed). Instead, a test-side reference computation of
//    RFC 8032 §5.1.6 for Ed25519ph, written here from the RFC formulas over
//    curve25519-dalek scalar/point arithmetic and SHA-512, independent of
//    dalek's signing code; it is itself checked against vector 1 first.
// ---------------------------------------------------------------------------

/// RFC 8032 §7.3 Ed25519ph "abc": (secret key, public key, message, signature).
const RFC8032_ED25519PH: (&str, &str, &str, &str) = (
    "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
    "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
    "616263",
    "98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae4131f85042463c2a355a2003d062adf5aaa10b8c61e636062aaad11c2a26083406",
);

/// RFC 8032 §5.1.6 Ed25519ph signing, computed from the RFC formulas:
/// dom2 = "SigEd25519 no Ed25519 collisions" ‖ 1 ‖ len(C) ‖ C,
/// r = SHA-512(dom2 ‖ prefix ‖ PH(M)), R = [r]B,
/// k = SHA-512(dom2 ‖ R ‖ A ‖ PH(M)), S = r + k·s mod L.
fn reference_ed25519ph(seed: &[u8], msg: &[u8], ctx: &[u8]) -> Vec<u8> {
    use curve25519_dalek::edwards::EdwardsPoint;
    use curve25519_dalek::scalar::{Scalar, clamp_integer};
    use ed25519_dalek::{Digest, Sha512};
    let wide = |parts: &[&[u8]]| {
        let mut h = Sha512::new();
        for p in parts {
            h.update(p);
        }
        let mut out = [0u8; 64];
        out.copy_from_slice(&h.finalize());
        Scalar::from_bytes_mod_order_wide(&out)
    };
    let mut h = [0u8; 64];
    h.copy_from_slice(&Sha512::digest(seed));
    let s = Scalar::from_bytes_mod_order(clamp_integer(h[..32].try_into().unwrap()));
    let prefix = &h[32..];
    let a = EdwardsPoint::mul_base(&s).compress();
    let ph = Sha512::digest(msg);
    let dom2 = [
        &b"SigEd25519 no Ed25519 collisions"[..],
        &[1u8, u8::try_from(ctx.len()).unwrap()],
        ctx,
    ]
    .concat();
    let r = wide(&[&dom2, prefix, &ph]);
    let big_r = EdwardsPoint::mul_base(&r).compress();
    let k = wide(&[&dom2, big_r.as_bytes(), a.as_bytes(), &ph]);
    [big_r.to_bytes(), (r + k * s).to_bytes()].concat()
}

#[test]
fn rfc8032_section_7_3_ed25519ph_through_half_path() {
    use vyra_sig::CompositeComponent;
    let (sk, pk, msg, sig) = RFC8032_ED25519PH;
    let (sk, pk, msg, sig) = (
        hex::decode(sk).unwrap(),
        hex::decode(pk).unwrap(),
        hex::decode(msg).unwrap(),
        hex::decode(sig).unwrap(),
    );
    let (got_pk, _) = Ed25519.generate_keypair(&mut Fixed::new(&sk)).unwrap();
    assert_eq!(got_pk, pk);
    // The vector's context is empty; signing draws no entropy (Failing rng).
    let got = Ed25519
        .sign_half(&sk, &msg, b"", &mut common::Failing)
        .unwrap();
    assert_eq!(got, sig, "RFC 8032 §7.3");
    Ed25519.verify_half(&pk, &msg, b"", &sig).unwrap();
    // The reference computation reproduces the vector too.
    assert_eq!(reference_ed25519ph(&sk, &msg, b""), sig);
    // Ed25519ph is not PureEd25519: the standalone adapter rejects it.
    assert_eq!(
        Ed25519.verify(&pk, &msg, &sig),
        Err(Error::VerificationFailed)
    );
    // Wrong context or message is rejected.
    assert_eq!(
        Ed25519.verify_half(&pk, &msg, b"x", &sig),
        Err(Error::VerificationFailed)
    );
    assert_eq!(
        Ed25519.verify_half(&pk, b"abd", b"", &sig),
        Err(Error::VerificationFailed)
    );
}

#[test]
fn ed25519ph_with_context_matches_reference() {
    use vyra_sig::{CompositeComponent, SigSuite, composite_context};
    let mut contexts: Vec<Vec<u8>> = SigSuite::all()
        .iter()
        .map(|s| composite_context(s.id()).to_vec())
        .collect();
    contexts.push(b"foo".to_vec());
    contexts.push(vec![0xab; 255]);
    let mut checked = 0;
    for (i, ctx) in contexts.iter().enumerate() {
        let (pk, sk) = Ed25519
            .generate_keypair(&mut DeterministicEntropy::from_seed(&[b'e', i as u8]))
            .unwrap();
        for msg in [&b""[..], b"abc", &[0x5a; 1000][..]] {
            let ours = Ed25519
                .sign_half(sk.expose(), msg, ctx, &mut common::Failing)
                .unwrap();
            assert_eq!(ours, reference_ed25519ph(sk.expose(), msg, ctx));
            Ed25519.verify_half(&pk, msg, ctx, &ours).unwrap();
            // Deterministic.
            let again = Ed25519
                .sign_half(
                    sk.expose(),
                    msg,
                    ctx,
                    &mut DeterministicEntropy::from_seed(b"x"),
                )
                .unwrap();
            assert_eq!(ours, again);
            // Not a PureEd25519 signature on the message.
            assert_eq!(
                Ed25519.verify(&pk, msg, &ours),
                Err(Error::VerificationFailed)
            );
            checked += 1;
        }
    }
    assert_eq!(checked, 24);
    // Context length limit.
    let (pk, sk) = Ed25519
        .generate_keypair(&mut DeterministicEntropy::from_seed(b"limit"))
        .unwrap();
    assert!(matches!(
        Ed25519.sign_half(sk.expose(), b"m", &[0u8; 256], &mut common::Failing),
        Err(Error::InvalidLength {
            what: "Ed25519ph context",
            actual: 256,
            ..
        })
    ));
    assert!(matches!(
        Ed25519.verify_half(&pk, b"m", &[0u8; 256], &[0u8; 64]),
        Err(Error::InvalidLength {
            what: "Ed25519ph context",
            ..
        })
    ));
}
