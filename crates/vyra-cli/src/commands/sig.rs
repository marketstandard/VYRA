//! `vyra sig keygen | sign | verify`.

use std::path::Path;

use vyra::OsEntropy;
use vyra::sig::{
    CompositePublicKey, CompositeSecretKey, CompositeSig, CompositeSignature, MAX_CONTEXT_LEN,
    SigSuite,
};

use crate::error::{CliError, Kind, wrap};
use crate::io;

fn check_context(context: &[u8]) -> Result<(), CliError> {
    if context.len() > MAX_CONTEXT_LEN {
        return Err(CliError::usage(format!(
            "--context is {} bytes; at most {MAX_CONTEXT_LEN} are allowed",
            context.len()
        )));
    }
    Ok(())
}

/// Generate a composite signing key pair and write both wire encodings.
///
/// # Errors
///
/// Entropy failure, or a file that cannot be written.
pub fn keygen(
    suite: SigSuite,
    pk_path: &Path,
    sk_path: &Path,
    force: bool,
) -> Result<(), CliError> {
    let (pk, sk) = CompositeSignature::new(suite)
        .generate(&mut OsEntropy::new())
        .map_err(|e| wrap(Kind::Failure, "key generation failed", e))?;
    let pk_bytes = pk.to_bytes();
    let sk_bytes = sk.to_bytes();
    io::write(pk_path, &pk_bytes, force, "public key")?;
    io::write(sk_path, sk_bytes.expose(), force, "secret key")?;
    println!(
        "{}: wrote public key ({} bytes) to {}",
        suite.name(),
        pk_bytes.len(),
        pk_path.display()
    );
    println!(
        "{}: wrote secret key ({} bytes) to {} (keep it private)",
        suite.name(),
        sk_bytes.len(),
        sk_path.display()
    );
    Ok(())
}

/// Sign the contents of `in_path` under `context`.
///
/// # Errors
///
/// Missing or malformed inputs, an over-long context, or a file that cannot
/// be written.
pub fn sign(
    sk_path: &Path,
    in_path: &Path,
    context: &[u8],
    sig_path: &Path,
    force: bool,
) -> Result<(), CliError> {
    check_context(context)?;
    let sk_bytes = io::read_secret(sk_path, "secret key")?;
    let sk = CompositeSecretKey::from_bytes(sk_bytes.expose())
        .map_err(|e| wrap(Kind::Input, "not a valid VYRA signature secret key", e))?;
    drop(sk_bytes);
    let message = io::read_public(in_path, "input")?;
    let suite = sk.suite();
    let sig = CompositeSignature::new(suite)
        .sign(&sk, &message, context, &mut OsEntropy::new())
        .map_err(|e| wrap(Kind::Failure, "signing failed", e))?;
    let sig_bytes = sig.to_bytes();
    io::write(sig_path, &sig_bytes, force, "signature")?;
    println!(
        "{}: wrote signature ({} bytes) over {} message bytes to {}",
        suite.name(),
        sig_bytes.len(),
        message.len(),
        sig_path.display()
    );
    Ok(())
}

/// Verify a signature file over the contents of `in_path`.
///
/// # Errors
///
/// [`Kind::Rejected`] (exit 1) if the signature does not verify, including a
/// signature from another suite than the key; [`Kind::Input`] for missing or
/// malformed files.
pub fn verify(
    pk_path: &Path,
    in_path: &Path,
    sig_path: &Path,
    context: &[u8],
) -> Result<(), CliError> {
    check_context(context)?;
    let pk = CompositePublicKey::from_bytes(&io::read_public(pk_path, "public key")?)
        .map_err(|e| wrap(Kind::Input, "not a valid VYRA signature public key", e))?;
    let sig = CompositeSig::from_bytes(&io::read_public(sig_path, "signature")?)
        .map_err(|e| wrap(Kind::Input, "not a valid VYRA signature", e))?;
    let message = io::read_public(in_path, "input")?;
    let suite = pk.suite();
    match CompositeSignature::new(suite).verify(&pk, &message, context, &sig) {
        Ok(()) => {
            println!("{}: signature valid", suite.name());
            Ok(())
        }
        Err(e) => Err(wrap(Kind::Rejected, "signature INVALID", e)),
    }
}
