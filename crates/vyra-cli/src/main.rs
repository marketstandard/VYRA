//! `vyra`: command-line tool for the VYRA research prototype.
//!
//! Run `vyra help` for usage. VYRA has had no independent cryptanalysis and
//! is not for protecting real data.

#![forbid(unsafe_code)]

mod args;
mod commands;
mod error;
mod io;

use std::process::ExitCode;

use error::Kind;

fn main() -> ExitCode {
    let argv: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let result = args::parse(&argv).and_then(|inv| commands::run(inv.command, inv.force));
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("vyra: error: {err}");
            if err.kind() == Kind::Usage {
                eprintln!("run 'vyra help' for usage");
            }
            err.exit_code()
        }
    }
}
