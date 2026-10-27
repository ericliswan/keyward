//! Subcommand implementations, one module each.

mod add;
mod init;
mod list;

use std::io::BufRead;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::cli::{Cli, Command};
use pwv_core::storage::UnlockedVault;

use crate::prompt::Prompter;

/// Runs the parsed command line.
pub fn run(cli: Cli) -> Result<()> {
    let Cli {
        vault,
        password_stdin,
        command,
    } = cli;
    let vault = vault_path(vault)?;
    let mut prompt = Prompter::stdin(password_stdin);
    let name = match command {
        Command::Init { force } => return init::run(&vault, force, &mut prompt),
        Command::Add { site } => return add::run(&vault, site, &mut prompt),
        Command::Get { .. } => "get",
        Command::List => return list::run(&vault, &mut prompt),
        Command::Edit { .. } => "edit",
        Command::Delete { .. } => "delete",
        Command::ChangeMaster => "change-master",
        Command::Gen => "gen",
    };
    bail!("`pwv {name}` is not implemented yet")
}

/// `--vault` or `PWV_VAULT` if given, otherwise the OS default.
fn vault_path(flag: Option<PathBuf>) -> Result<PathBuf> {
    flag.or_else(pwv_core::storage::default_path)
        .context("no home directory found; pass --vault <PATH>")
}

/// Asks for the master password and opens the vault at `path`.
fn unlock(path: &Path, prompt: &mut Prompter<impl BufRead>) -> Result<UnlockedVault> {
    if !path.try_exists()? {
        bail!("no vault at {}; run `pwv init` first", path.display());
    }
    let password = prompt.secret("Master password")?;
    Ok(pwv_core::storage::unlock(path, &password)?)
}
