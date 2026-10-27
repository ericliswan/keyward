//! `pwv add`: store a new entry.

use std::io::BufRead;
use std::path::Path;

use anyhow::{Result, bail};
use pwv_core::model::{Entry, SecretText};
use secrecy::{ExposeSecret, SecretString};
use time::OffsetDateTime;

use crate::prompt::Prompter;

/// Prompts for every field; the password and notes are secret, so they are never arguments and
/// never echoed.
pub fn run(path: &Path, site: String, prompt: &mut Prompter<impl BufRead>) -> Result<()> {
    let mut unlocked = super::unlock(path, prompt)?;
    let username = prompt.line("Username")?;
    let password = prompt.secret("Password")?;
    if password.expose_secret().is_empty() {
        bail!("password must not be empty");
    }
    let notes = prompt.secret("Notes (hidden, optional)")?;
    let entry = Entry::new(
        site.clone(),
        username,
        secret_text(&password),
        secret_text(&notes),
        OffsetDateTime::now_utc(),
    );
    unlocked.vault.insert(entry);
    unlocked.save()?;
    eprintln!("Added {site}");
    Ok(())
}

fn secret_text(secret: &SecretString) -> SecretText {
    SecretText::from(secret.expose_secret().to_owned())
}
