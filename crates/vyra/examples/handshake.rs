//! ILLUSTRATION ONLY: a one-round, server-authenticated key exchange with
//! forward secrecy, assembled from VYRA's hybrid KEM, composite signature and
//! [`Transcript`]. This is **not an analysed protocol**. It exists to show how
//! the pieces fit together and why an *ephemeral* KEM key pair is what gives
//! forward secrecy (docs/DECISIONS.md D-03). Do not deploy it.
//!
//! Run with `cargo run -p vyra --example handshake`. The responder signs with
//! the transition suite VYRA-SIG-3 (ML-DSA-65 + Ed25519) by default; with
//! `-- --pq` it signs with the dual post-quantum suite VYRA-SIG-PQ3
//! (ML-DSA-65 + SLH-DSA-SHAKE-192s), which makes the responder's message about
//! 16 KB larger and its signing take seconds instead of milliseconds. The
//! choice changes only the signature family; the handshake is the same.
//!
//! # Flow
//!
//! ```text
//! Responder R has a long-term composite signing key (sk_R, pk_R);
//! the initiator I already knows pk_R (distributed out of band).
//!
//! I:  (pk_e, sk_e) <- HybridKem.generate()            fresh, ephemeral
//! I -> R:  pk_e
//! R:  (ct, K) <- HybridKem.encapsulate_to(pk_e)
//!     th  = SHA3-256 transcript( LABEL, pk_e, ct )      framed, injective
//!     sig = CompositeSignature.sign(sk_R, th, CONTEXT)
//! R -> I:  ct, sig
//! I:  verify(pk_R, th, CONTEXT, sig)  -- abort on failure
//!     K = decapsulate(sk_e, ct);  drop sk_e (zeroized)
//! both:  k_i2r = SHAKE256 transcript( KEY_LABEL, K, th, "initiator->responder" )
//!        k_r2i = SHAKE256 transcript( KEY_LABEL, K, th, "responder->initiator" )
//! ```
//!
//! # What it is meant to show
//!
//! - **Forward secrecy (intended):** `sk_e` exists only for one session and is
//!   zeroized when dropped, so a later compromise of the responder's long-term
//!   *signing* key does not let anyone decapsulate a recorded `ct`. (Contrast
//!   the sealed box or a static KEM key, where it would.)
//! - **Responder authentication (intended):** the initiator only accepts `ct`
//!   if it is signed, together with the initiator's own `pk_e`, by the key it
//!   expects.
//!
//! # What it does NOT provide
//!
//! - **The initiator is unauthenticated.** Anyone can start a session; the
//!   responder learns nothing about who it is talking to.
//! - **No replay protection.** The responder signs whatever `pk_e` it is sent;
//!   there are no nonces, timestamps or session state. A replayed initiator
//!   message gets a fresh response; a replayed responder message is accepted
//!   by an initiator that reuses `pk_e` (this one never does).
//! - **No negotiation and no downgrade protection.** Suites are fixed in the
//!   code; nothing binds a negotiation, because there is none.
//! - **No identity hiding.** `pk_e`, `ct` and the signature travel in the clear
//!   and the signature identifies the responder.
//! - **No key confirmation** message, no channel, no rekeying, no AEAD record
//!   layer: VYRA exposes no standalone AEAD API, so this example compares the
//!   derived keys and prints short fingerprints of them instead of exchanging
//!   an encrypted message.
//! - **Not analysed.** No proof, model or review covers this composition.

use vyra::prelude::*;

/// Domain label for the handshake transcript that the responder signs.
const TRANSCRIPT_LABEL: &[u8] = b"VYRA-example-handshake-v1/transcript";
/// Composite-signature context string for the responder's signature.
const SIG_CONTEXT: &[u8] = b"VYRA-example-handshake-v1/responder-signature";
/// Domain label for session-key derivation.
const KEY_LABEL: &[u8] = b"VYRA-example-handshake-v1/session-keys";
/// Domain label for printing short key fingerprints.
const FINGERPRINT_LABEL: &[u8] = b"VYRA-example-handshake-v1/fingerprint";

const KEM_SUITE: KemSuite = KemSuite::Vyra3;
/// Responder signature suite without `--pq` (transition family).
const SIG_SUITE: SigSuite = SigSuite::Vyra3;
/// Responder signature suite with `--pq` (dual post-quantum family).
const SIG_SUITE_PQ: SigSuite = SigSuite::Pq3;

/// The pair of directional session keys one side ends up with.
struct SessionKeys {
    initiator_to_responder: SecretBytes,
    responder_to_initiator: SecretBytes,
}

/// `th = SHA3-256(frame(LABEL) ‖ frame(pk_e) ‖ frame(ct))` over wire encodings.
fn transcript_hash(pk_e_wire: &[u8], ct_wire: &[u8]) -> [u8; 32] {
    let mut t = Transcript::new(TRANSCRIPT_LABEL);
    t.append(pk_e_wire).append(ct_wire);
    t.finalize()
}

/// Derive both directional keys from the KEM secret and the transcript hash.
fn derive_keys(k: &SecretBytes, th: &[u8; 32]) -> SessionKeys {
    let derive = |direction: &[u8]| {
        let mut t = Transcript::new(KEY_LABEL);
        t.append(k.expose()).append(th).append(direction);
        let mut key = SecretBytes::zeroed(32);
        t.finalize_xof(key.expose_mut());
        key
    };
    SessionKeys {
        initiator_to_responder: derive(b"initiator->responder"),
        responder_to_initiator: derive(b"responder->initiator"),
    }
}

/// A short public fingerprint of a key: the first 8 bytes of a SHA3-256
/// transcript hash, in hex. Safe to print; the key itself never is.
fn fingerprint(key: &SecretBytes) -> String {
    let mut t = Transcript::new(FINGERPRINT_LABEL);
    t.append(key.expose());
    t.finalize()
        .iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn main() -> Result<()> {
    let mut sig_suite = SIG_SUITE;
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--pq" => sig_suite = SIG_SUITE_PQ,
            other => {
                eprintln!("handshake: unknown argument {other:?} (only --pq is accepted)");
                std::process::exit(2);
            }
        }
    }
    println!("{}", vyra::STATUS);
    println!("ILLUSTRATION ONLY - not an analysed protocol (see the source comments).\n");
    let mut rng = OsEntropy::new();
    let kem = HybridKem::new(KEM_SUITE);
    let signer = CompositeSignature::new(sig_suite);

    // Setup: the responder's long-term signing key; the initiator knows pk_R.
    let (responder_pk, responder_sk) = signer.generate(&mut rng)?;
    let responder_pk_known_to_initiator = CompositePublicKey::from_bytes(&responder_pk.to_bytes())?;

    // Message 1 (I -> R): a fresh ephemeral KEM public key.
    let (pk_e, sk_e) = kem.generate(&mut rng)?;
    let msg1 = pk_e.to_bytes();
    println!("I -> R  pk_e       {:>6} bytes ({KEM_SUITE})", msg1.len());

    // Responder: encapsulate to pk_e, sign the transcript, derive keys.
    let (responder_keys, msg2_ct, msg2_sig) = {
        let pk_e = HybridPublicKey::from_bytes(&msg1)?;
        let (ct, k) = HybridKem::new(pk_e.suite()).encapsulate_to(&pk_e, &mut rng)?;
        let ct_wire = ct.to_bytes();
        let th = transcript_hash(&msg1, &ct_wire);
        let sig = signer.sign(&responder_sk, &th, SIG_CONTEXT, &mut rng)?;
        (derive_keys(&k, &th), ct_wire, sig.to_bytes())
        // `k` is dropped (and zeroized) here.
    };
    println!("R -> I  ct         {:>6} bytes", msg2_ct.len());
    println!(
        "R -> I  sig        {:>6} bytes ({}: {} + {})",
        msg2_sig.len(),
        sig_suite.name(),
        sig_suite.first().name(),
        sig_suite.second().name()
    );

    // Initiator: verify the responder's signature BEFORE using ct.
    let th = transcript_hash(&msg1, &msg2_ct);
    let sig = CompositeSig::from_bytes(&msg2_sig)?;
    CompositeSignature::new(responder_pk_known_to_initiator.suite()).verify(
        &responder_pk_known_to_initiator,
        &th,
        SIG_CONTEXT,
        &sig,
    )?;
    println!("I: responder signature verified");

    let ct = HybridCiphertext::from_bytes(&msg2_ct)?;
    let k = kem.decapsulate_with(&sk_e, &ct)?;
    // Forward secrecy depends on this: the ephemeral secret key is erased
    // (HybridSecretKey zeroizes on drop) as soon as it has been used once.
    drop(sk_e);
    let initiator_keys = derive_keys(&k, &th);
    drop(k);
    println!("I: ephemeral secret key dropped (zeroized)");

    let i2r = initiator_keys
        .initiator_to_responder
        .ct_eq(&responder_keys.initiator_to_responder);
    let r2i = initiator_keys
        .responder_to_initiator
        .ct_eq(&responder_keys.responder_to_initiator);
    let distinct = !initiator_keys
        .initiator_to_responder
        .ct_eq(&initiator_keys.responder_to_initiator);
    println!(
        "key I->R  initiator {}  responder {}",
        fingerprint(&initiator_keys.initiator_to_responder),
        fingerprint(&responder_keys.initiator_to_responder)
    );
    println!(
        "key R->I  initiator {}  responder {}",
        fingerprint(&initiator_keys.responder_to_initiator),
        fingerprint(&responder_keys.responder_to_initiator)
    );

    // A tampered ciphertext must be rejected by the signature check.
    let mut bad_ct = msg2_ct.clone();
    if let Some(last) = bad_ct.last_mut() {
        *last ^= 0x01;
    }
    let tampered_accepted = signer
        .verify(
            &responder_pk_known_to_initiator,
            &transcript_hash(&msg1, &bad_ct),
            SIG_CONTEXT,
            &sig,
        )
        .is_ok();
    println!("tampered ciphertext accepted by initiator: {tampered_accepted}");

    if i2r && r2i && distinct && !tampered_accepted {
        println!("handshake: both sides derived the same directional keys");
        Ok(())
    } else {
        println!("handshake: FAILED");
        Err(Error::Internal("handshake keys differ"))
    }
}
