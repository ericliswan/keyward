//! `pwv init`: create a new, empty vault.

use std::io::BufRead;
use std::path::Path;

use anyhow::{Result, bail};
use secrecy::ExposeSecret;

use crate::prompt::Prompter;

/// With `force`, an existing vault is replaced; `storage` keeps the old file as `<vault>.bak`.
pub fn run(path: &Path, force: bool, prompt: &mut Prompter<impl BufRead>) -> Result<()> {
    if !force && path.try_exists()? {
        bail!(
            "a vault already exists at {}; pass --force to replace it",
            path.display()
        );
    }
    let password = prompt.secret("New master password")?;
    if prompt.secret("Repeat master password")?.expose_secret() != password.expose_secret() {
        bail!("passwords do not match");
    }
    pwv_core::storage::create(path, &password)?;
    eprintln!("Created vault at {}", path.display());
    Ok(())
}
