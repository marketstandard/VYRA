//! `vyra demo`: an in-memory end-to-end demonstration over every suite.
//!
//! Every check prints `ok` or `FAIL`; the run ends with a `PASS` line and
//! exit 0 only if all checks passed. Secrets are never printed, only short
//! SHA3 fingerprints of them ([`io::fingerprint`]).
//!
//! Every signature suite, including the three dual post-quantum suites, runs
//! the same full set of signature checks; for the dual post-quantum suites
//! that is one SLH-DSA-based signature each (seconds), so the demo prints the
//! time each suite took. The handshake illustrations use the transition
//! suites only (they demonstrate composition, not signature families).

use std::time::Instant;

use vyra::kem::{HybridCiphertext, HybridKem, HybridPublicKey, HybridSecretKey, KemSuite};
use vyra::seal::SealedBox;
use vyra::sig::{
    CompositePublicKey, CompositeSecretKey, CompositeSig, CompositeSignature, SigSuite,
};
use vyra::wire::HEADER_LEN;
use vyra::{OsEntropy, SecretBytes, Transcript};

use crate::error::{CliError, Kind, wrap};
use crate::io::fingerprint;

/// Counts passed and failed checks.
#[derive(Default)]
struct Checks {
    passed: usize,
    failed: usize,
}

impl Checks {
    fn check(&mut self, ok: bool, what: &str) {
        if ok {
            self.passed = self.passed.saturating_add(1);
            println!("  ok    {what}");
        } else {
            self.failed = self.failed.saturating_add(1);
            println!("  FAIL  {what}");
        }
    }
}

/// Map a library error inside the demo to a failure (exit 4).
fn fail(context: &'static str) -> impl Fn(vyra::Error) -> CliError {
    move |e| wrap(Kind::Failure, context, e)
}

/// Flip the lowest bit of the byte at `index` (no-op if out of range).
fn flip(bytes: &[u8], index: usize) -> Vec<u8> {
    let mut out = bytes.to_vec();
    if let Some(b) = out.get_mut(index) {
        *b ^= 0x01;
    }
    out
}

/// Run the demonstration.
///
/// # Errors
///
/// [`Kind::Failure`] if any check fails or a library call errors.
pub fn run() -> Result<(), CliError> {
    println!("{}", vyra::STATUS);
    println!("vyra demo: in-memory end-to-end demonstration over every suite.");
    println!("Secrets are never printed; 'fp' is a short SHA3-256 fingerprint.");
    println!(
        "Signatures: the full set of {SIG_CHECKS} checks for each of the {} suites (the {} dual",
        SigSuite::all().len(),
        SigSuite::dual_pq().len()
    );
    println!("post-quantum suites sign with SLH-DSA, which takes seconds per signature).");
    let mut checks = Checks::default();
    let mut rng = OsEntropy::new();

    for suite in KemSuite::all() {
        kem_demo(suite, &mut rng, &mut checks)?;
    }
    for suite in SigSuite::all() {
        sig_demo(suite, &mut rng, &mut checks)?;
    }
    for suite in KemSuite::all() {
        seal_demo(suite, &mut rng, &mut checks)?;
    }
    for (kem_suite, sig_suite) in [
        (KemSuite::Vyra1, SigSuite::Vyra2),
        (KemSuite::Vyra3, SigSuite::Vyra3),
        (KemSuite::Vyra5, SigSuite::Vyra5),
    ] {
        handshake_demo(kem_suite, sig_suite, &mut rng, &mut checks)?;
    }

    println!();
    let total = checks.passed.saturating_add(checks.failed);
    if checks.failed == 0 {
        println!("PASS: all {total} checks passed");
        Ok(())
    } else {
        println!("FAIL: {} of {total} checks failed", checks.failed);
        Err(CliError::failure(format!(
            "demo: {} of {total} checks failed",
            checks.failed
        )))
    }
}

fn kem_demo(suite: KemSuite, rng: &mut OsEntropy, checks: &mut Checks) -> Result<(), CliError> {
    let (c1, c2) = suite.component_names();
    println!();
    println!(
        "[KEM] {suite}: {c1} + {c2}, NIST category {}",
        suite.level().category()
    );
    println!(
        "  sizes (wire): public key {} B, secret key {} B, ciphertext {} B; shared secret {} B",
        suite.encoded_public_key_len(),
        suite.encoded_secret_key_len(),
        suite.encoded_ciphertext_len(),
        suite.shared_secret_len()
    );
    let kem = HybridKem::new(suite);
    let (pk, sk) = kem.generate(rng).map_err(fail("KEM keygen"))?;

    // Round trip through the wire encodings.
    let pk_wire = pk.to_bytes();
    let sk_wire = sk.to_bytes();
    let pk2 = HybridPublicKey::from_bytes(&pk_wire).map_err(fail("parse KEM public key"))?;
    let sk2 =
        HybridSecretKey::from_bytes(sk_wire.expose()).map_err(fail("parse KEM secret key"))?;
    checks.check(
        pk2 == pk
            && pk_wire.len() == suite.encoded_public_key_len()
            && sk_wire.len() == suite.encoded_secret_key_len(),
        "key wire encodings round-trip with the specified lengths",
    );

    let (ct, ss_sender) = kem.encapsulate_to(&pk2, rng).map_err(fail("encapsulate"))?;
    let ct_wire = ct.to_bytes();
    let ct2 = HybridCiphertext::from_bytes(&ct_wire).map_err(fail("parse KEM ciphertext"))?;
    let ss_recipient = kem
        .decapsulate_with(&sk2, &ct2)
        .map_err(fail("decapsulate"))?;
    checks.check(
        ss_sender.ct_eq(&ss_recipient) && ss_sender.len() == suite.shared_secret_len(),
        &format!(
            "shared secrets match (sender fp {}, recipient fp {})",
            fingerprint(&ss_sender),
            fingerprint(&ss_recipient)
        ),
    );

    // Implicit rejection: a flipped bit in either component ciphertext gives
    // an unrelated key, not an error.
    let raw = ct.as_raw();
    for (region, index) in [("ML-KEM", 0), ("HQC", raw.len().saturating_sub(1))] {
        let bad = HybridCiphertext::from_raw(suite, &flip(raw, index))
            .map_err(fail("tampered ciphertext"))?;
        let ss_bad = kem
            .decapsulate_with(&sk, &bad)
            .map_err(fail("decapsulate tampered ciphertext"))?;
        checks.check(
            !ss_bad.ct_eq(&ss_sender),
            &format!(
                "flipped bit in {region} ciphertext -> unrelated key, no error (fp {})",
                fingerprint(&ss_bad)
            ),
        );
    }
    Ok(())
}

/// Checks [`sig_demo`] runs per signature suite.
const SIG_CHECKS: usize = 6;

fn sig_demo(suite: SigSuite, rng: &mut OsEntropy, checks: &mut Checks) -> Result<(), CliError> {
    let started = Instant::now();
    let before = checks.passed.saturating_add(checks.failed);
    let (family, label) = if suite.is_dual_pq() {
        ("dual post-quantum", "minimum of both components")
    } else {
        ("transition", "ML-DSA component")
    };
    println!();
    println!(
        "[SIG] {}: {} + {} ({family}), category label {} ({label})",
        suite.name(),
        suite.first().name(),
        suite.second().name(),
        suite.level().category()
    );
    println!(
        "  sizes (wire): public key {} B, secret key {} B, signature {} B",
        suite.encoded_public_key_len(),
        suite.encoded_secret_key_len(),
        suite.encoded_signature_len()
    );
    let scheme = CompositeSignature::new(suite);
    let (pk, sk) = scheme.generate(rng).map_err(fail("signature keygen"))?;
    let pk = CompositePublicKey::from_bytes(&pk.to_bytes()).map_err(fail("parse public key"))?;
    let sk =
        CompositeSecretKey::from_bytes(sk.to_bytes().expose()).map_err(fail("parse secret key"))?;

    let message = b"VYRA demo message";
    let context = b"vyra-cli/demo";
    let sig = scheme
        .sign(&sk, message, context, rng)
        .map_err(fail("sign"))?;
    let sig = CompositeSig::from_bytes(&sig.to_bytes()).map_err(fail("parse signature"))?;
    checks.check(
        scheme.verify(&pk, message, context, &sig).is_ok(),
        "valid signature verifies",
    );
    checks.check(
        scheme
            .verify(&pk, b"VYRA demo messagE", context, &sig)
            .is_err(),
        "modified message rejected",
    );
    checks.check(
        scheme.verify(&pk, message, b"other", &sig).is_err(),
        "different context rejected",
    );
    let raw = sig.as_raw();
    for (part, index) in [
        (suite.first().name(), 0),
        (suite.second().name(), raw.len().saturating_sub(1)),
    ] {
        let bad =
            CompositeSig::from_raw(suite, &flip(raw, index)).map_err(fail("tampered signature"))?;
        checks.check(
            scheme.verify(&pk, message, context, &bad).is_err(),
            &format!("flipped bit in {part} signature rejected"),
        );
    }
    let (other_pk, _) = scheme.generate(rng).map_err(fail("signature keygen"))?;
    checks.check(
        scheme.verify(&other_pk, message, context, &sig).is_err(),
        "signature rejected under another public key",
    );
    let ran = checks
        .passed
        .saturating_add(checks.failed)
        .saturating_sub(before);
    println!(
        "  {ran} of {SIG_CHECKS} signature checks run in {:.2} s",
        started.elapsed().as_secs_f64()
    );
    if ran != SIG_CHECKS {
        checks.check(false, "signature check count");
    }
    Ok(())
}

fn seal_demo(suite: KemSuite, rng: &mut OsEntropy, checks: &mut Checks) -> Result<(), CliError> {
    println!();
    println!(
        "[SEAL] {suite} + ChaCha20-Poly1305, overhead {} B",
        SealedBox::overhead(suite)
    );
    let kem = HybridKem::new(suite);
    let (pk, sk) = kem.generate(rng).map_err(fail("KEM keygen"))?;
    let (_, other_sk) = kem.generate(rng).map_err(fail("KEM keygen"))?;
    let sbox = SealedBox::new(suite);
    let plaintext = b"sealed demo plaintext";
    let aad = b"vyra-cli/demo";
    let sealed = sbox.seal(&pk, aad, plaintext, rng).map_err(fail("seal"))?;
    let opened = sbox.open(&sk, aad, &sealed).map_err(fail("open"))?;
    checks.check(
        opened.ct_eq(&SecretBytes::from_slice(plaintext))
            && sealed.len() == plaintext.len().saturating_add(SealedBox::overhead(suite)),
        &format!(
            "round trip ({} B plaintext -> {} B sealed)",
            plaintext.len(),
            sealed.len()
        ),
    );
    checks.check(
        sbox.open(&sk, b"other aad", &sealed).is_err(),
        "wrong associated data rejected",
    );
    for (region, index) in [
        ("KEM ciphertext", HEADER_LEN),
        ("AEAD ciphertext", sealed.len().saturating_sub(17)),
        ("tag", sealed.len().saturating_sub(1)),
    ] {
        checks.check(
            sbox.open(&sk, aad, &flip(&sealed, index)).is_err(),
            &format!("flipped bit in {region} rejected"),
        );
    }
    checks.check(
        sbox.open(&other_sk, aad, &sealed).is_err(),
        "wrong recipient key rejected",
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Handshake: ILLUSTRATION ONLY, the same construction as
// crates/vyra/examples/handshake.rs (see there for what it does NOT provide:
// the initiator is unauthenticated; no replay, negotiation/downgrade or
// identity protection; not analysed).
// ---------------------------------------------------------------------------

const HS_TRANSCRIPT_LABEL: &[u8] = b"VYRA-example-handshake-v1/transcript";
const HS_SIG_CONTEXT: &[u8] = b"VYRA-example-handshake-v1/responder-signature";
const HS_KEY_LABEL: &[u8] = b"VYRA-example-handshake-v1/session-keys";

fn hs_transcript(pk_e_wire: &[u8], ct_wire: &[u8]) -> [u8; 32] {
    let mut t = Transcript::new(HS_TRANSCRIPT_LABEL);
    t.append(pk_e_wire).append(ct_wire);
    t.finalize()
}

/// `(initiator->responder, responder->initiator)` session keys.
fn hs_keys(k: &SecretBytes, th: &[u8; 32]) -> (SecretBytes, SecretBytes) {
    let derive = |direction: &[u8]| {
        let mut t = Transcript::new(HS_KEY_LABEL);
        t.append(k.expose()).append(th).append(direction);
        let mut key = SecretBytes::zeroed(32);
        t.finalize_xof(key.expose_mut());
        key
    };
    (
        derive(b"initiator->responder"),
        derive(b"responder->initiator"),
    )
}

fn handshake_demo(
    kem_suite: KemSuite,
    sig_suite: SigSuite,
    rng: &mut OsEntropy,
    checks: &mut Checks,
) -> Result<(), CliError> {
    println!();
    println!(
        "[HANDSHAKE] ephemeral {kem_suite} + responder signature {} (illustration, not an analysed protocol)",
        sig_suite.name()
    );
    let signer = CompositeSignature::new(sig_suite);
    let (responder_pk, responder_sk) = signer.generate(rng).map_err(fail("responder keygen"))?;

    // I -> R: fresh ephemeral KEM public key.
    let kem = HybridKem::new(kem_suite);
    let (pk_e, sk_e) = kem.generate(rng).map_err(fail("ephemeral keygen"))?;
    let msg1 = pk_e.to_bytes();

    // R: encapsulate, sign transcript, derive keys.
    let pk_e_r = HybridPublicKey::from_bytes(&msg1).map_err(fail("parse pk_e"))?;
    let (ct, k_r) = kem
        .encapsulate_to(&pk_e_r, rng)
        .map_err(fail("encapsulate"))?;
    let ct_wire = ct.to_bytes();
    let th_r = hs_transcript(&msg1, &ct_wire);
    let sig = signer
        .sign(&responder_sk, &th_r, HS_SIG_CONTEXT, rng)
        .map_err(fail("responder sign"))?;
    let (r_i2r, r_r2i) = hs_keys(&k_r, &th_r);
    drop(k_r);
    let sig_wire = sig.to_bytes();
    println!(
        "  messages: I->R pk_e {} B; R->I ct {} B + signature {} B",
        msg1.len(),
        ct_wire.len(),
        sig_wire.len()
    );

    // I: verify, then decapsulate and erase the ephemeral secret key.
    let th_i = hs_transcript(&msg1, &ct_wire);
    let sig_i = CompositeSig::from_bytes(&sig_wire).map_err(fail("parse signature"))?;
    let verified = signer
        .verify(&responder_pk, &th_i, HS_SIG_CONTEXT, &sig_i)
        .is_ok();
    checks.check(verified, "initiator verified the responder's signature");
    let ct_i = HybridCiphertext::from_bytes(&ct_wire).map_err(fail("parse ciphertext"))?;
    let k_i = kem
        .decapsulate_with(&sk_e, &ct_i)
        .map_err(fail("decapsulate"))?;
    drop(sk_e); // zeroized: this is what gives the intended forward secrecy
    let (i_i2r, i_r2i) = hs_keys(&k_i, &th_i);
    drop(k_i);

    checks.check(
        i_i2r.ct_eq(&r_i2r) && i_r2i.ct_eq(&r_r2i) && !i_i2r.ct_eq(&i_r2i),
        &format!(
            "directional session keys match and differ by direction (I->R fp {}, R->I fp {})",
            fingerprint(&i_i2r),
            fingerprint(&i_r2i)
        ),
    );

    let bad_ct = flip(&ct_wire, ct_wire.len().saturating_sub(1));
    checks.check(
        signer
            .verify(
                &responder_pk,
                &hs_transcript(&msg1, &bad_ct),
                HS_SIG_CONTEXT,
                &sig_i,
            )
            .is_err(),
        "tampered ciphertext rejected by the initiator's signature check",
    );
    Ok(())
}
