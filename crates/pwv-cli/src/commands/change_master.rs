//! `pwv change-master`: re-encrypt the vault under a new master password.

use std::io::BufRead;
use std::path::Path;

use anyhow::Result;

use crate::prompt::Prompter;

/// Unlocks with the current password first, so a wrong one fails before any new password is read.
pub fn run(path: &Path, prompt: &mut Prompter<impl BufRead>) -> Result<()> {
    let mut unlocked = super::unlock(path, prompt)?;
    let password = super::init::new_master_password(prompt)?;
    unlocked.change_password(&password)?;
    eprintln!("Changed the master password");
    eprintln!(
        "The previous vault is kept at {}.bak and still opens with the old password \
         until the next change; delete it if someone else may know the old password.",
        path.display()
    );
    Ok(())
}
