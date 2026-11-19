//! `vyra kem keygen | encaps | decaps`.

use std::path::Path;

use vyra::OsEntropy;
use vyra::kem::{HybridCiphertext, HybridKem, HybridPublicKey, HybridSecretKey, KemSuite};

use crate::error::{CliError, Kind, wrap};
use crate::io;

/// Generate a hybrid KEM key pair and write both wire encodings.
///
/// # Errors
///
/// Entropy failure, or a file that cannot be written.
pub fn keygen(
    suite: KemSuite,
    pk_path: &Path,
    sk_path: &Path,
    force: bool,
) -> Result<(), CliError> {
    let (pk, sk) = HybridKem::new(suite)
        .generate(&mut OsEntropy::new())
        .map_err(|e| wrap(Kind::Failure, "key generation failed", e))?;
    let pk_bytes = pk.to_bytes();
    let sk_bytes = sk.to_bytes();
    io::write(pk_path, &pk_bytes, force, "public key")?;
    io::write(sk_path, sk_bytes.expose(), force, "secret key")?;
    println!(
        "{suite}: wrote public key ({} bytes) to {}",
        pk_bytes.len(),
        pk_path.display()
    );
    println!(
        "{suite}: wrote secret key ({} bytes) to {} (keep it private)",
        sk_bytes.len(),
        sk_path.display()
    );
    Ok(())
}

/// Encapsulate to a public key file; write the ciphertext and shared secret.
///
/// # Errors
///
/// A missing or malformed public key, entropy failure, or a file that cannot
/// be written.
pub fn encaps(pk_path: &Path, ct_path: &Path, ss_path: &Path, force: bool) -> Result<(), CliError> {
    let pk_bytes = io::read_public(pk_path, "public key")?;
    let pk = HybridPublicKey::from_bytes(&pk_bytes)
        .map_err(|e| wrap(Kind::Input, "not a valid VYRA KEM public key", e))?;
    let suite = pk.suite();
    let (ct, ss) = HybridKem::new(suite)
        .encapsulate_to(&pk, &mut OsEntropy::new())
        .map_err(|e| wrap(Kind::Failure, "encapsulation failed", e))?;
    let ct_bytes = ct.to_bytes();
    io::write(ct_path, &ct_bytes, force, "ciphertext")?;
    io::write(ss_path, ss.expose(), force, "shared secret")?;
    println!(
        "{suite}: wrote ciphertext ({} bytes) to {}",
        ct_bytes.len(),
        ct_path.display()
    );
    println!(
        "{suite}: wrote shared secret ({} bytes) to {} (keep it private)",
        ss.len(),
        ss_path.display()
    );
    Ok(())
}

/// Decapsulate a ciphertext file with a secret key file; write the shared
/// secret.
///
/// An invalid but well-formed ciphertext yields an unrelated shared secret
/// (implicit rejection), not an error.
///
/// # Errors
///
/// Missing or malformed inputs, a suite mismatch, or a file that cannot be
/// written.
pub fn decaps(sk_path: &Path, ct_path: &Path, ss_path: &Path, force: bool) -> Result<(), CliError> {
    let sk_bytes = io::read_secret(sk_path, "secret key")?;
    let sk = HybridSecretKey::from_bytes(sk_bytes.expose())
        .map_err(|e| wrap(Kind::Input, "not a valid VYRA KEM secret key", e))?;
    drop(sk_bytes);
    let ct_bytes = io::read_public(ct_path, "ciphertext")?;
    let ct = HybridCiphertext::from_bytes(&ct_bytes)
        .map_err(|e| wrap(Kind::Input, "not a valid VYRA KEM ciphertext", e))?;
    let suite = sk.suite();
    if ct.suite() != suite {
        return Err(CliError::input(format!(
            "ciphertext suite {} does not match secret key suite {suite}",
            ct.suite()
        )));
    }
    let ss = HybridKem::new(suite)
        .decapsulate_with(&sk, &ct)
        .map_err(|e| wrap(Kind::Failure, "decapsulation failed", e))?;
    io::write(ss_path, ss.expose(), force, "shared secret")?;
    println!(
        "{suite}: wrote shared secret ({} bytes) to {} (keep it private)",
        ss.len(),
        ss_path.display()
    );
    Ok(())
}
