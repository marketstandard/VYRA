//! `vyra seal` and `vyra open`.

use std::path::Path;

use vyra::OsEntropy;
use vyra::kem::{HybridPublicKey, HybridSecretKey, KemSuite};
use vyra::seal::SealedBox;
use vyra::wire::{self, ObjectType};

use crate::error::{CliError, Kind, wrap};
use crate::io;

/// Seal the contents of `in_path` to the public key in `pk_path`.
///
/// # Errors
///
/// Missing or malformed inputs, a plaintext that is too long, entropy
/// failure, or a file that cannot be written.
pub fn seal(
    pk_path: &Path,
    in_path: &Path,
    out_path: &Path,
    aad: &[u8],
    force: bool,
) -> Result<(), CliError> {
    let pk = HybridPublicKey::from_bytes(&io::read_public(pk_path, "public key")?)
        .map_err(|e| wrap(Kind::Input, "not a valid VYRA KEM public key", e))?;
    let plaintext = io::read_secret(in_path, "input")?;
    let suite = pk.suite();
    let sealed = SealedBox::new(suite)
        .seal(&pk, aad, plaintext.expose(), &mut OsEntropy::new())
        .map_err(|e| wrap(Kind::Input, "sealing failed", e))?;
    io::write(out_path, &sealed, force, "sealed output")?;
    println!(
        "{suite}: sealed {} bytes into {} bytes at {}",
        plaintext.len(),
        sealed.len(),
        out_path.display()
    );
    Ok(())
}

/// Open the sealed box in `in_path` with the secret key in `sk_path`.
///
/// # Errors
///
/// [`Kind::Rejected`] (exit 1) if the box does not open (wrong key, wrong
/// AAD, modified data, or a box for another suite); [`Kind::Input`] for
/// missing or malformed files.
pub fn open(
    sk_path: &Path,
    in_path: &Path,
    out_path: &Path,
    aad: &[u8],
    force: bool,
) -> Result<(), CliError> {
    let sk_bytes = io::read_secret(sk_path, "secret key")?;
    let sk = HybridSecretKey::from_bytes(sk_bytes.expose())
        .map_err(|e| wrap(Kind::Input, "not a valid VYRA KEM secret key", e))?;
    drop(sk_bytes);
    let sealed = io::read_public(in_path, "sealed input")?;
    let suite = sk.suite();

    // Classify malformed input (exit 3) before attempting to open (exit 1).
    let (box_suite_id, _) = wire::decode(&sealed, ObjectType::SealedBox)
        .map_err(|e| wrap(Kind::Input, "not a valid VYRA sealed box", e))?;
    let box_suite = KemSuite::from_id(box_suite_id)
        .map_err(|e| wrap(Kind::Input, "not a valid VYRA sealed box", e))?;
    if sealed.len() < SealedBox::overhead(box_suite) {
        return Err(CliError::input(format!(
            "not a valid VYRA sealed box: {} bytes is shorter than the {}-byte minimum for {box_suite}",
            sealed.len(),
            SealedBox::overhead(box_suite)
        )));
    }
    if box_suite != suite {
        return Err(CliError::rejected(format!(
            "cannot open sealed box: it is for {box_suite}, the secret key is for {suite}"
        )));
    }

    let plaintext = SealedBox::new(suite)
        .open(&sk, aad, &sealed)
        .map_err(|e| wrap(Kind::Rejected, "cannot open sealed box", e))?;
    io::write(out_path, plaintext.expose(), force, "opened output")?;
    println!(
        "{suite}: opened {} bytes into {} bytes at {} (keep it private)",
        sealed.len(),
        plaintext.len(),
        out_path.display()
    );
    Ok(())
}
