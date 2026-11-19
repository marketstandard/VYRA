//! Strict public-key validation (U3-R2).
//!
//! Ed25519: dalek 3.0's `VerifyingKey::from_bytes` reduces `y` mod p and
//! accepts the sign-bit-set encoding of `x = 0` points, so one point can have
//! several encodings. VYRA requires the canonical encoding (RFC 8032 §5.1.3)
//! and rejects small-order points. ML-DSA: every byte string of the right
//! length is a valid canonical FIPS 204 public key. SLH-DSA (dual-PQ suites): every
//! byte string of the right length is a valid canonical FIPS 205 public key
//! (section at the end).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

mod common;

use common::SUITES;
use vyra_core::{DeterministicEntropy, EntropySource, Error, OsEntropy, SignatureScheme};
use vyra_sig::{CompositePublicKey, CompositeSignature, Ed25519, SigSuite, validate_public_key};

/// Little-endian encoding of `p + j` (p = 2^255 − 19) with sign bit `sign`.
fn non_canonical(j: u8, sign: bool) -> [u8; 32] {
    let mut b = [0xffu8; 32];
    b[0] = 0xed + j; // p = 0x7fff…ffed; j ≤ 18 keeps b[0] ≤ 0xff
    b[31] = 0x7f | if sign { 0x80 } else { 0 };
    b
}

/// Little-endian encoding of a small `y` with sign bit `sign`.
fn small_y(y: u8, sign: bool) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[0] = y;
    b[31] = if sign { 0x80 } else { 0 };
    b
}

/// `y = p − 1` (that is, −1): the order-2 point (0, −1).
fn minus_one(sign: bool) -> [u8; 32] {
    let mut b = non_canonical(0, sign);
    b[0] = 0xec;
    b
}

struct Row {
    label: String,
    decodes: bool,
    canonical: bool,
    small_order: bool,
    torsion_free: bool,
}

fn classify(label: String, enc: [u8; 32]) -> Row {
    match ed25519_dalek::VerifyingKey::from_bytes(&enc) {
        Err(_) => Row {
            label,
            decodes: false,
            canonical: false,
            small_order: false,
            torsion_free: false,
        },
        Ok(vk) => {
            let point = vk.to_edwards();
            Row {
                label,
                decodes: true,
                canonical: point.compress().to_bytes() == enc,
                small_order: vk.is_weak(),
                torsion_free: point.is_torsion_free(),
            }
        }
    }
}

/// Every encoding in scope of the enumeration: the 19 non-canonical `y`
/// values × 2 sign bits, plus the sign-bit-set ("negative zero") encodings of
/// the two `x = 0` points (y = 1 and y = −1).
fn enumeration() -> Vec<(String, [u8; 32])> {
    let mut v = Vec::new();
    for j in 0u8..19 {
        for sign in [false, true] {
            v.push((
                format!("y=p+{j:<2} sign={}", u8::from(sign)),
                non_canonical(j, sign),
            ));
        }
    }
    v.push(("y=1    sign=1 (x=0)".into(), small_y(1, true)));
    v.push(("y=p-1  sign=1 (x=0)".into(), minus_one(true)));
    v
}

#[test]
fn ed25519_non_canonical_enumeration() {
    let mut decoded = 0;
    let mut decoded_not_small = 0;
    println!("encoding            | from_bytes | canonical | small-order | torsion-free | VYRA");
    for (label, enc) in enumeration() {
        let row = classify(label, enc);
        let vyra = Ed25519::validate_public_key(&enc);
        println!(
            "{:<19} | {:<10} | {:<9} | {:<11} | {:<12} | {}",
            row.label,
            if row.decodes { "accepted" } else { "rejected" },
            row.canonical,
            row.small_order,
            row.torsion_free,
            match vyra {
                Ok(()) => "ACCEPTED",
                Err(Error::InvalidEncoding(l)) => l,
                Err(_) => "other error",
            }
        );
        // Facts about upstream: nothing in this set is canonical, and dalek
        // never re-encodes to the same bytes.
        assert!(!row.canonical, "{}", row.label);
        if row.decodes {
            decoded += 1;
            if !row.small_order {
                decoded_not_small += 1;
                // Since U3-R4 these are rejected for two independent reasons:
                // non-canonical encoding AND not in the prime-order subgroup
                // (every one of them is mixed-order). The canonicity check
                // runs first, so it is the label reported.
                assert!(!row.torsion_free, "{}", row.label);
            }
        }
        // VYRA rejects every one of them, at parse...
        assert!(vyra.is_err(), "{}", row.label);
        // ...and the Ed25519 adapter's verify never accepts them.
        assert!(Ed25519.verify(&enc, b"m", &[0u8; 64]).is_err());
    }
    // dalek 3.0 does accept non-canonical encodings in `from_bytes`
    // (this is the reason for the canonicity check).
    assert!(
        decoded > 0,
        "expected dalek to accept some non-canonical encodings"
    );
    println!("decoded by dalek: {decoded}; of those not small-order: {decoded_not_small}");
    assert_eq!(decoded, 26);
    assert_eq!(decoded_not_small, 20);
}

#[test]
fn dalek_from_bytes_accepts_non_canonical_identity() {
    // Concrete fact: y = p + 1 ≡ 1 decodes to the identity, whose canonical
    // encoding is 01 00 … 00.
    let enc = non_canonical(1, false);
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&enc).unwrap();
    assert_eq!(vk.to_edwards().compress().to_bytes(), small_y(1, false));
    assert!(vk.is_weak());
    // verify_strict rejects it only because it is small-order; the identity
    // "signature" (R = identity, S = 0) is accepted by non-strict verify.
    let mut sig = [0u8; 64];
    sig[0] = 1;
    let sig = ed25519_dalek::Signature::from_bytes(&sig);
    assert!(vk.verify_strict(b"m", &sig).is_err());
    use ed25519_dalek::Verifier;
    assert!(vk.verify(b"m", &sig).is_ok());
    assert_eq!(
        Ed25519::validate_public_key(&enc),
        Err(Error::InvalidEncoding("Ed25519 public key (non-canonical)"))
    );
}

#[test]
fn small_order_canonical_encodings_rejected() {
    for enc in [
        small_y(1, false),
        small_y(0, false),
        small_y(0, true),
        minus_one(false),
    ] {
        assert!(
            ed25519_dalek::VerifyingKey::from_bytes(&enc)
                .unwrap()
                .is_weak()
        );
        assert_eq!(
            Ed25519::validate_public_key(&enc),
            Err(Error::InvalidEncoding("Ed25519 public key (small order)"))
        );
    }
}

#[test]
fn identity_is_rejected() {
    // The identity is torsion-free (it IS in the prime-order subgroup), so the
    // explicit small-order check is what rejects it.
    let enc = small_y(1, false);
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&enc).unwrap();
    assert!(vk.to_edwards().is_torsion_free());
    assert!(vk.is_weak());
    assert_eq!(
        Ed25519::validate_public_key(&enc),
        Err(Error::InvalidEncoding("Ed25519 public key (small order)"))
    );
}

/// Canonical mixed-order keys: an honest public key point `A` plus each of the
/// 7 non-identity 8-torsion points. Documents what plain dalek does with them
/// and asserts that VYRA rejects them everywhere.
#[test]
fn canonical_mixed_order_keys_rejected() {
    use curve25519_dalek::constants::EIGHT_TORSION;
    use curve25519_dalek::traits::IsIdentity;
    let mut rng = OsEntropy::new();
    println!("torsion | dalek from_bytes | is_weak | canonical | torsion-free | VYRA");
    for suite in SUITES {
        let scheme = CompositeSignature::new(suite);
        let (pk, sk) = scheme.generate(&mut rng).unwrap();
        let sig = scheme.sign(&sk, b"m", b"c", &mut rng).unwrap();
        let a =
            ed25519_dalek::VerifyingKey::from_bytes(pk.ed25519_part().unwrap().try_into().unwrap())
                .unwrap()
                .to_edwards();
        assert!(a.is_torsion_free());
        for (i, t) in EIGHT_TORSION.iter().enumerate().skip(1) {
            assert!(!t.is_identity());
            let mixed = (a + t).compress().to_bytes();
            // Upstream behaviour.
            let vk = ed25519_dalek::VerifyingKey::from_bytes(&mixed);
            let accepted = vk.is_ok();
            let vk = vk.unwrap();
            let canonical = vk.to_edwards().compress().to_bytes() == mixed;
            let weak = vk.is_weak();
            let torsion_free = vk.to_edwards().is_torsion_free();
            let vyra = Ed25519::validate_public_key(&mixed);
            if suite == SigSuite::Vyra2 {
                println!(
                    "T[{i}]    | {:<16} | {:<7} | {:<9} | {:<12} | {:?}",
                    if accepted { "accepted" } else { "rejected" },
                    weak,
                    canonical,
                    torsion_free,
                    vyra
                );
            }
            assert!(accepted && canonical && !weak && !torsion_free);
            assert_eq!(
                vyra,
                Err(Error::InvalidEncoding(
                    "Ed25519 public key (not in prime-order subgroup)"
                ))
            );

            // Composite parse rejects it, raw and wire...
            let raw = [pk.mldsa_part(), &mixed[..]].concat();
            assert_eq!(
                CompositePublicKey::from_raw(suite, &raw),
                Err(Error::InvalidEncoding(
                    "Ed25519 public key (not in prime-order subgroup)"
                ))
            );
            let wire = vyra_core::wire::encode(
                vyra_core::wire::ObjectType::SigPublicKey,
                suite.id(),
                &raw,
            );
            assert!(matches!(
                CompositePublicKey::from_bytes(&wire),
                Err(Error::InvalidEncoding(_))
            ));
            // ...and composite verify never accepts it.
            assert_eq!(
                scheme.verify_raw(&raw, b"m", b"c", sig.as_raw()),
                Err(Error::VerificationFailed)
            );
        }
    }
}

#[test]
fn honest_keys_pass_validation() {
    let mut rng = OsEntropy::new();
    for suite in SUITES {
        let scheme = CompositeSignature::new(suite);
        for _ in 0..100 {
            let (pk, _) = scheme.generate_raw(&mut rng).unwrap();
            validate_public_key(suite, &pk).unwrap();
            let typed = CompositePublicKey::from_raw(suite, &pk).unwrap();
            assert_eq!(
                CompositePublicKey::from_bytes(&typed.to_bytes()).unwrap(),
                typed
            );
        }
    }
    for _ in 0..200 {
        let (pk, _) = Ed25519.generate_keypair(&mut rng).unwrap();
        Ed25519::validate_public_key(&pk).unwrap();
        let vk =
            ed25519_dalek::VerifyingKey::from_bytes(pk.as_slice().try_into().unwrap()).unwrap();
        assert!(vk.to_edwards().is_torsion_free());
    }
}

#[test]
fn bad_ed25519_part_rejected_at_parse_and_never_verifies() {
    let mut rng = OsEntropy::new();
    let mut bad: Vec<[u8; 32]> = enumeration().into_iter().map(|(_, e)| e).collect();
    bad.extend([small_y(1, false), small_y(0, false), minus_one(false)]);
    for suite in SUITES {
        let scheme = CompositeSignature::new(suite);
        let (pk, sk) = scheme.generate(&mut rng).unwrap();
        let sig = scheme.sign(&sk, b"m", b"c", &mut rng).unwrap();
        for enc in &bad {
            let raw = [pk.mldsa_part(), enc].concat();
            assert!(matches!(
                CompositePublicKey::from_raw(suite, &raw),
                Err(Error::InvalidEncoding(_))
            ));
            let wire = vyra_core::wire::encode(
                vyra_core::wire::ObjectType::SigPublicKey,
                suite.id(),
                &raw,
            );
            assert!(matches!(
                CompositePublicKey::from_bytes(&wire),
                Err(Error::InvalidEncoding(_))
            ));
            assert_eq!(
                scheme.verify_raw(&raw, b"m", b"c", sig.as_raw()),
                Err(Error::VerificationFailed)
            );
            let forged = [sig.mldsa_part(), &[0u8; 64][..]].concat();
            assert_eq!(
                scheme.verify_raw(&raw, b"m", b"c", &forged),
                Err(Error::VerificationFailed)
            );
        }
    }
}

macro_rules! mldsa_identity {
    ($test:ident, $p:ty) => {
        #[test]
        fn $test() {
            use ml_dsa::{EncodedVerifyingKey, VerifyingKey};
            let mut src = DeterministicEntropy::from_seed(stringify!($test).as_bytes());
            for _ in 0..50 {
                let mut enc = EncodedVerifyingKey::<$p>::default();
                src.fill(&mut enc).unwrap();
                let decoded = VerifyingKey::<$p>::decode(&enc);
                assert_eq!(decoded.encode(), enc);
            }
            // Extremes: all-zero and all-one bit patterns.
            for fill in [0x00u8, 0xff] {
                let mut enc = EncodedVerifyingKey::<$p>::default();
                enc.iter_mut().for_each(|b| *b = fill);
                assert_eq!(VerifyingKey::<$p>::decode(&enc).encode(), enc);
            }
        }
    };
}

mldsa_identity!(mldsa44_pk_decode_encode_identity, ml_dsa::MlDsa44);
mldsa_identity!(mldsa65_pk_decode_encode_identity, ml_dsa::MlDsa65);
mldsa_identity!(mldsa87_pk_decode_encode_identity, ml_dsa::MlDsa87);

#[test]
fn any_mldsa_part_with_valid_ed25519_part_parses() {
    // Consequence of the ML-DSA conclusion: random ML-DSA bytes + an honest
    // Ed25519 key always parse (and never verify a random signature).
    let mut src = DeterministicEntropy::from_seed(b"random mldsa part");
    // `transition()` is what `all()` returned when this test was written (U12).
    for suite in SigSuite::transition() {
        let (ed_pk, _) = Ed25519.generate_keypair(&mut src).unwrap();
        let mut ml = vec![0u8; suite.mldsa_public_key_len()];
        src.fill(&mut ml).unwrap();
        let pk = CompositePublicKey::from_raw(suite, &[ml.as_slice(), &ed_pk].concat()).unwrap();
        let sig =
            vyra_sig::CompositeSig::from_raw(suite, &vec![0u8; suite.signature_len()]).unwrap();
        assert!(
            CompositeSignature::new(suite)
                .verify(&pk, b"m", b"", &sig)
                .is_err()
        );
    }
}

/// Standalone adapter consistency (U3-R5): signatures that plain dalek
/// `verify_strict` ACCEPTS under a canonical mixed-order key `A + T` are
/// rejected by VYRA's standalone `Ed25519::verify`.
///
/// Construction: with secret scalar `a` (so `A = aB`), sign with
/// `hazmat::raw_sign` while hashing the mixed key `A' = A + T` into
/// `k = H(R ‖ A' ‖ M)`. Cofactorless verification checks
/// `[S]B − [k]A' = R − [k]T`, which equals `R` exactly when `[k]T = O`; for
/// T of order n that happens for about 1 in n messages, so we search messages.
#[test]
fn standalone_adapter_rejects_mixed_order_keys_that_dalek_accepts() {
    use curve25519_dalek::constants::EIGHT_TORSION;
    use ed25519_dalek::hazmat::{ExpandedSecretKey, raw_sign};
    let seed = [42u8; 32];
    let esk = ExpandedSecretKey::from(&seed);
    let a = ed25519_dalek::SigningKey::from_bytes(&seed)
        .verifying_key()
        .to_edwards();
    for (i, t) in EIGHT_TORSION.iter().enumerate().skip(1) {
        let mixed_point = a + t;
        let mixed_vk = ed25519_dalek::VerifyingKey::from(mixed_point);
        let mixed = mixed_vk.to_bytes();
        let mut found = None;
        for n in 0u32..1000 {
            let msg = n.to_le_bytes();
            let sig = raw_sign::<ed25519_dalek::Sha512>(&esk, &msg, &mixed_vk);
            if mixed_vk.verify_strict(&msg, &sig).is_ok() {
                found = Some((msg, sig.to_bytes()));
                break;
            }
        }
        let (msg, sig) = found.unwrap_or_else(|| panic!("no accepted message for T[{i}]"));
        println!(
            "T[{i}]: dalek verify_strict ACCEPTS a signature under A+T; VYRA: {:?}",
            Ed25519.verify(&mixed, &msg, &sig)
        );
        assert_eq!(
            Ed25519.verify(&mixed, &msg, &sig),
            Err(Error::VerificationFailed)
        );
        assert_eq!(
            Ed25519::validate_public_key(&mixed),
            Err(Error::InvalidEncoding(
                "Ed25519 public key (not in prime-order subgroup)"
            ))
        );
    }
}

/// The standalone adapter never accepts any of the enumerated non-canonical
/// encodings, nor small-order keys, with any of a few candidate signatures
/// (including the identity "signature" R = O, S = 0).
#[test]
fn standalone_adapter_rejects_enumerated_and_small_order_keys() {
    let mut identity_sig = [0u8; 64];
    identity_sig[0] = 1;
    let sigs = [[0u8; 64], identity_sig];
    let mut keys: Vec<[u8; 32]> = enumeration().into_iter().map(|(_, e)| e).collect();
    keys.extend([
        small_y(1, false),
        small_y(0, false),
        small_y(0, true),
        minus_one(false),
    ]);
    for enc in keys {
        for sig in &sigs {
            for msg in [&b""[..], b"m", b"any message"] {
                assert!(Ed25519.verify(&enc, msg, sig).is_err());
            }
        }
    }
    // Pinned mapping: small-order (well-formed) keys -> VerificationFailed;
    // non-canonical encodings -> InvalidEncoding.
    assert_eq!(
        Ed25519.verify(&small_y(1, false), b"m", &identity_sig),
        Err(Error::VerificationFailed)
    );
    assert_eq!(
        Ed25519.verify(&non_canonical(1, false), b"m", &identity_sig),
        Err(Error::InvalidEncoding("Ed25519 public key (non-canonical)"))
    );
}

// ---------------------------------------------------------------------------
// SLH-DSA public keys (dual-PQ suites). A FIPS 205 public key is
// PK.seed ‖ PK.root, two unstructured n-byte strings: every byte string of
// length 2n is a valid key and its own canonical encoding. Evidence: decode
// then encode is the identity in both implementations, on random strings and
// on the all-0 / all-1 patterns, and both decoders accept every such string.
// ---------------------------------------------------------------------------

macro_rules! slh_identity {
    ($test:ident, $fips:ident, $rc:ty, $len:literal) => {
        #[test]
        fn $test() {
            use fips205::traits::SerDes;
            let mut src = DeterministicEntropy::from_seed(stringify!($test).as_bytes());
            let mut cases: Vec<[u8; $len]> = vec![[0x00; $len], [0xff; $len]];
            for _ in 0..200 {
                let mut enc = [0u8; $len];
                src.fill(&mut enc).unwrap();
                cases.push(enc);
            }
            for enc in cases {
                let a = fips205::$fips::PublicKey::try_from_bytes(enc).unwrap();
                assert_eq!(a.into_bytes(), enc);
                let b = slh_dsa::VerifyingKey::<$rc>::try_from(&enc[..]).unwrap();
                assert_eq!(b.to_bytes().as_slice(), &enc[..]);
            }
        }
    };
}

slh_identity!(
    slhdsa128s_pk_decode_encode_identity,
    slh_dsa_shake_128s,
    slh_dsa::Shake128s,
    32
);
slh_identity!(
    slhdsa192s_pk_decode_encode_identity,
    slh_dsa_shake_192s,
    slh_dsa::Shake192s,
    48
);
slh_identity!(
    slhdsa256s_pk_decode_encode_identity,
    slh_dsa_shake_256s,
    slh_dsa::Shake256s,
    64
);

#[test]
fn any_dual_pq_public_key_of_the_right_length_parses_and_never_verifies() {
    let mut src = DeterministicEntropy::from_seed(b"random pq key");
    for suite in common::PQ_SUITES {
        let scheme = CompositeSignature::new(suite);
        for fill in [None, Some(0x00u8), Some(0xff)] {
            let mut raw = vec![0u8; suite.public_key_len()];
            match fill {
                None => src.fill(&mut raw).unwrap(),
                Some(b) => raw.iter_mut().for_each(|x| *x = b),
            }
            validate_public_key(suite, &raw).unwrap();
            let pk = CompositePublicKey::from_raw(suite, &raw).unwrap();
            let wire = pk.to_bytes();
            assert_eq!(CompositePublicKey::from_bytes(&wire).unwrap(), pk);
            let mut sig = vec![0u8; suite.signature_len()];
            src.fill(&mut sig).unwrap();
            let sig = vyra_sig::CompositeSig::from_raw(suite, &sig).unwrap();
            assert_eq!(
                scheme.verify(&pk, b"m", b"", &sig),
                Err(Error::VerificationFailed)
            );
        }
        for len in [0, suite.public_key_len() - 1, suite.public_key_len() + 1] {
            assert!(matches!(
                validate_public_key(suite, &vec![0u8; len]),
                Err(Error::InvalidLength { .. })
            ));
        }
    }
}

#[test]
fn honest_dual_pq_keys_pass_validation() {
    // 3 key pairs per suite (SLH-DSA key generation takes ~0.1-0.5 s).
    let mut rng = OsEntropy::new();
    for suite in common::PQ_SUITES {
        let scheme = CompositeSignature::new(suite);
        for _ in 0..3 {
            let (pk, _) = scheme.generate_raw(&mut rng).unwrap();
            validate_public_key(suite, &pk).unwrap();
            let typed = CompositePublicKey::from_raw(suite, &pk).unwrap();
            assert_eq!(
                CompositePublicKey::from_bytes(&typed.to_bytes()).unwrap(),
                typed
            );
        }
    }
}
