//! `pwv get`: reveal an entry's password.

use std::io::BufRead;
use std::path::Path;

use anyhow::{Result, bail};

use crate::prompt::Prompter;

pub fn run(path: &Path, site: &str, show: bool, prompt: &mut Prompter<impl BufRead>) -> Result<()> {
    // shortcut: no clipboard copy yet, so --show is required; plan PR #18 adds the clipboard.
    if !show {
        bail!("copying to the clipboard is not implemented yet; pass --show to print the password");
    }
    let unlocked = super::unlock(path, prompt)?;
    let entry = super::choose(&unlocked.vault, site, prompt)?;
    println!("{}", entry.password.expose());
    Ok(())
}
