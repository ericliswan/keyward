//! `pwv init`: create a new, empty vault.

use std::io::BufRead;
use std::path::Path;

use anyhow::{Result, bail};
use secrecy::ExposeSecret;

use crate::prompt::Prompter;

pub fn run(path: &Path, prompt: &mut Prompter<impl BufRead>) -> Result<()> {
    if path.try_exists()? {
        bail!("a vault already exists at {}", path.display());
    }
    let password = prompt.secret("New master password")?;
    if prompt.secret("Repeat master password")?.expose_secret() != password.expose_secret() {
        bail!("passwords do not match");
    }
    pwv_core::storage::create(path, &password)?;
    eprintln!("Created vault at {}", path.display());
    Ok(())
}
