//! `pwv delete`: remove an entry after confirmation.

use std::io::BufRead;
use std::path::Path;

use anyhow::Result;

use crate::prompt::Prompter;

/// Anything but `y` or `yes` (any case) keeps the entry.
pub fn run(path: &Path, site: &str, yes: bool, prompt: &mut Prompter<impl BufRead>) -> Result<()> {
    let mut unlocked = super::unlock(path, prompt)?;
    let entry = super::choose(&unlocked.vault, site, prompt)?;
    let id = entry.id;
    if !yes {
        let question = format!("Delete {} ({})? [y/N]", entry.site, entry.username);
        let answer = prompt.line(&question)?.trim().to_lowercase();
        if answer != "y" && answer != "yes" {
            eprintln!("Nothing deleted");
            return Ok(());
        }
    }
    unlocked.vault.remove(id);
    unlocked.save()?;
    eprintln!("Deleted {site}");
    Ok(())
}
