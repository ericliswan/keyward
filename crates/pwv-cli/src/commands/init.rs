//! `pwv init`: create a new, empty vault.

use std::io::BufRead;
use std::path::Path;

use anyhow::{Result, bail};
use secrecy::{ExposeSecret, SecretString};

use crate::prompt::Prompter;

/// Shorter master passwords are rejected before zxcvbn runs.
const MIN_LEN: usize = 12;

/// With `force`, an existing vault is replaced; `storage` keeps the old file as `<vault>.bak`.
pub fn run(path: &Path, force: bool, prompt: &mut Prompter<impl BufRead>) -> Result<()> {
    if !force && path.try_exists()? {
        bail!(
            "a vault already exists at {}; pass --force to replace it",
            path.display()
        );
    }
    let password = prompt.secret("New master password")?;
    check_strength(&password)?;
    if prompt.secret("Repeat master password")?.expose_secret() != password.expose_secret() {
        bail!("passwords do not match");
    }
    pwv_core::storage::create(path, &password)?;
    eprintln!("Created vault at {}", path.display());
    Ok(())
}

/// Rejects master passwords shorter than [`MIN_LEN`] characters or with a zxcvbn score below 3.
/// The error explains why using zxcvbn's fixed feedback text, never the password itself.
fn check_strength(password: &SecretString) -> Result<()> {
    let password = password.expose_secret();
    if password.chars().count() < MIN_LEN {
        bail!("master password must be at least {MIN_LEN} characters");
    }
    // zxcvbn keeps pieces of the password in its result without zeroizing them; dropped right away.
    let entropy = zxcvbn::zxcvbn(password, &[]);
    if entropy.score() >= zxcvbn::Score::Three {
        return Ok(());
    }
    let mut msg = String::from("master password is too weak");
    if let Some(feedback) = entropy.feedback() {
        if let Some(warning) = feedback.warning() {
            msg += &format!(": {warning}");
        }
        for suggestion in feedback.suggestions() {
            msg += &format!("\n  {suggestion}");
        }
    }
    bail!(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(password: &str) -> Result<()> {
        check_strength(&SecretString::from(password))
    }

    #[test]
    fn short_passwords_are_rejected() {
        let err = check("Tr0ub4dor&3").unwrap_err().to_string();
        assert_eq!(err, "master password must be at least 12 characters");
    }

    #[test]
    fn weak_passwords_are_rejected_without_echoing_them() {
        for weak in ["letmeinletmein", "qwertyuiopasdf", "zzzzzzzzzzzzzzz"] {
            let err = check(weak).unwrap_err().to_string();
            assert!(err.starts_with("master password is too weak"), "{err}");
            assert!(!err.contains(&weak[..6]), "{err}");
        }
    }

    #[test]
    fn strong_passwords_are_accepted() {
        check("glacier trombone pickle verdict").unwrap();
        check("vX8#qL2!mZ9@wR4").unwrap();
    }
}
