//! `pwv get`: reveal an entry's password.

use std::io::{self, BufRead, IsTerminal};
use std::path::Path;

use anyhow::{Result, bail};

use crate::prompt::Prompter;

/// Checks the flags before unlocking, so a refused run never costs a KDF.
pub fn run(
    path: &Path,
    site: &str,
    show: bool,
    force: bool,
    prompt: &mut Prompter<impl BufRead>,
) -> Result<()> {
    // shortcut: no clipboard copy yet, so --show is required; plan PR #18 adds the clipboard.
    if !show {
        bail!("copying to the clipboard is not implemented yet; pass --show to print the password");
    }
    if !force && !io::stdout().is_terminal() {
        bail!("stdout is not a terminal; pass --force to print the password anyway");
    }
    let unlocked = super::unlock(path, prompt)?;
    let entry = super::choose(&unlocked.vault, site, prompt)?;
    println!("{}", entry.password.expose());
    Ok(())
}
