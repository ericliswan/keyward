//! `pwv add`: store a new entry.

use std::io::BufRead;
use std::path::Path;

use anyhow::Result;
use pwv_core::model::Entry;
use time::OffsetDateTime;

use crate::cli::GenArgs;
use crate::prompt::Prompter;

/// Prompts for every field; the password and notes are secret, so they are never arguments and
/// never echoed. With `generate`, the password is generated instead of prompted for, and not shown.
pub fn run(
    path: &Path,
    site: String,
    generate: Option<&GenArgs>,
    prompt: &mut Prompter<impl BufRead>,
) -> Result<()> {
    // Generate first so bad options fail before the master password is asked for.
    let generated = generate.map(super::r#gen::generate).transpose()?;
    let mut unlocked = super::unlock(path, prompt)?;
    let username = prompt.line("Username")?;
    let (password, bits) = match generated {
        Some((password, bits)) => (password, Some(bits)),
        None => (super::new_password(prompt, "Password")?, None),
    };
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
    match bits {
        Some(bits) => eprintln!("Added {site} with a generated password ({bits:.0} bits)"),
        None => eprintln!("Added {site}"),
    }
    Ok(())
}
