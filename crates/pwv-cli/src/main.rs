//! `pwv`: a local command-line password manager.
#![forbid(unsafe_code)]

mod cli;
mod commands;
mod prompt;

use std::process::ExitCode;

use clap::Parser;

/// Exit code for a wrong password or a vault that fails parsing, validation or authentication.
const EXIT_AUTH: u8 = 3;

fn main() -> ExitCode {
    // clap exits with 2 on usage errors and 0 for --help and --version.
    match commands::run(cli::Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::from(exit_code(&err))
        }
    }
}

/// `3` for any `pwv-core` error about the vault's contents, `1` for everything else,
/// including I/O errors such as a missing vault file.
fn exit_code(err: &anyhow::Error) -> u8 {
    match err
        .chain()
        .find_map(|e| e.downcast_ref::<pwv_core::Error>())
    {
        None | Some(pwv_core::Error::Io(_)) => 1,
        Some(_) => EXIT_AUTH,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;
    use pwv_core::Error;

    #[test]
    fn vault_errors_exit_3_and_others_exit_1() {
        let auth = [
            Error::Decrypt,
            Error::Format,
            Error::UnsupportedVersion,
            Error::ParamsOutOfRange,
            Error::Serde,
        ];
        for e in auth {
            assert_eq!(exit_code(&e.into()), 3);
        }
        let io = Error::Io(std::io::ErrorKind::NotFound.into());
        assert_eq!(exit_code(&io.into()), 1);
        assert_eq!(exit_code(&anyhow::anyhow!("no such entry")), 1);
    }

    #[test]
    fn context_does_not_hide_the_exit_code() {
        let err = Err::<(), _>(Error::Decrypt)
            .context("cannot unlock vault")
            .unwrap_err();
        assert_eq!(exit_code(&err), 3);
    }
}
