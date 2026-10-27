//! Subcommand implementations, one module each.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};

use crate::cli::{Cli, Command};

/// Runs the parsed command line.
pub fn run(cli: Cli) -> Result<()> {
    let Cli {
        vault,
        password_stdin: _,
        command,
    } = cli;
    let _vault = vault_path(vault)?;
    let name = match command {
        Command::Init => "init",
        Command::Add { .. } => "add",
        Command::Get { .. } => "get",
        Command::List => "list",
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
