//! Command implementations.

mod demo;
mod info;
mod kem;
mod seal;
mod sig;

use crate::args::{Command, USAGE};
use crate::error::CliError;

/// One-line reminder printed to stderr by commands that create or use keys.
fn notice() {
    eprintln!(
        "note: VYRA is a research prototype with no independent cryptanalysis; \
         do not use it to protect real data."
    );
}

/// Run `command`. `force` allows overwriting existing output files.
///
/// # Errors
///
/// The first error encountered; see [`crate::error::Kind`] for exit codes.
pub fn run(command: Command, force: bool) -> Result<(), CliError> {
    match command {
        Command::Help => {
            print!("{USAGE}");
            Ok(())
        }
        Command::Version => {
            println!("vyra {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Command::Info => {
            info::run();
            Ok(())
        }
        Command::Demo => demo::run(),
        Command::KemKeygen { suite, pk, sk } => {
            notice();
            kem::keygen(suite, &pk, &sk, force)
        }
        Command::KemEncaps { pk, ct, ss } => {
            notice();
            kem::encaps(&pk, &ct, &ss, force)
        }
        Command::KemDecaps { sk, ct, ss } => {
            notice();
            kem::decaps(&sk, &ct, &ss, force)
        }
        Command::SigKeygen { suite, pk, sk } => {
            notice();
            sig::keygen(suite, &pk, &sk, force)
        }
        Command::SigSign {
            sk,
            input,
            context,
            sig,
        } => {
            notice();
            sig::sign(&sk, &input, context.as_bytes(), &sig, force)
        }
        Command::SigVerify {
            pk,
            input,
            sig,
            context,
        } => {
            notice();
            sig::verify(&pk, &input, &sig, context.as_bytes())
        }
        Command::Seal {
            pk,
            input,
            out,
            aad,
        } => {
            notice();
            seal::seal(&pk, &input, &out, aad.as_bytes(), force)
        }
        Command::Open {
            sk,
            input,
            out,
            aad,
        } => {
            notice();
            seal::open(&sk, &input, &out, aad.as_bytes(), force)
        }
    }
}
