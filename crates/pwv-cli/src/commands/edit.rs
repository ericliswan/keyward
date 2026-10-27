//! `pwv edit`: change one field of an entry.

use std::io::BufRead;
use std::path::Path;

use anyhow::Result;
use time::OffsetDateTime;

use crate::cli::Field;
use crate::prompt::Prompter;

/// Prompts for the new value of the one field clap guarantees is selected and bumps `updated_at`.
pub fn run(
    path: &Path,
    site: &str,
    field: &Field,
    prompt: &mut Prompter<impl BufRead>,
) -> Result<()> {
    let mut unlocked = super::unlock(path, prompt)?;
    let id = super::choose(&unlocked.vault, site, prompt)?.id;
    let now = OffsetDateTime::now_utc();
    let vault = &mut unlocked.vault;
    // `update` cannot miss: `id` was just chosen from this vault.
    if field.username {
        let username = prompt.line("New username")?;
        vault.update(id, now, |e| e.username = username);
    } else if field.password {
        let password = super::new_password(prompt, "New password")?;
        vault.update(id, now, |e| e.password = password);
    } else {
        let notes = super::secret_text(&prompt.secret("New notes (hidden)")?);
        vault.update(id, now, |e| e.notes = notes);
    }
    unlocked.save()?;
    eprintln!("Updated {site}");
    Ok(())
}
