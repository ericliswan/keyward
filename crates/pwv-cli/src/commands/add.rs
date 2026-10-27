//! `pwv add`: store a new entry.

use std::io::BufRead;
use std::path::Path;

use anyhow::Result;
use pwv_core::model::Entry;
use time::OffsetDateTime;

use crate::prompt::Prompter;

/// Prompts for every field; the password and notes are secret, so they are never arguments and
/// never echoed.
pub fn run(path: &Path, site: String, prompt: &mut Prompter<impl BufRead>) -> Result<()> {
    let mut unlocked = super::unlock(path, prompt)?;
    let username = prompt.line("Username")?;
    let password = super::new_password(prompt, "Password")?;
    let notes = super::secret_text(&prompt.secret("Notes (hidden, optional)")?);
    let entry = Entry::new(
        site.clone(),
        username,
        password,
        notes,
        OffsetDateTime::now_utc(),
    );
    unlocked.vault.insert(entry);
    unlocked.save()?;
    eprintln!("Added {site}");
    Ok(())
}
