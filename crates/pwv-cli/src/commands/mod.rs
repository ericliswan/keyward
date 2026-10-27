//! Subcommand implementations, one module each.

mod add;
mod get;
mod init;
mod list;

use std::io::BufRead;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use pwv_core::model::{Entry, Vault};
use pwv_core::storage::UnlockedVault;

use crate::cli::{Cli, Command};

use crate::prompt::Prompter;

/// Runs the parsed command line.
pub fn run(cli: Cli) -> Result<()> {
    let Cli {
        vault,
        password_stdin,
        command,
    } = cli;
    let vault = vault_path(vault)?;
    let mut prompt = Prompter::stdin(password_stdin);
    let name = match command {
        Command::Init { force } => return init::run(&vault, force, &mut prompt),
        Command::Add { site } => return add::run(&vault, site, &mut prompt),
        Command::Get { site, show, force } => {
            return get::run(&vault, &site, show, force, &mut prompt);
        }
        Command::List { search } => return list::run(&vault, search.as_deref(), &mut prompt),
        Command::Edit { .. } => "edit",
        Command::Delete { .. } => "delete",
        Command::ChangeMaster => "change-master",
        Command::Gen => "gen",
    };
    bail!("`pwv {name}` is not implemented yet")
}

/// `--vault` or `PWV_VAULT` if given, otherwise the OS default.
fn vault_path(flag: Option<PathBuf>) -> Result<PathBuf> {
    flag.or_else(pwv_core::storage::default_path)
        .context("no home directory found; pass --vault <PATH>")
}

/// Asks for the master password and opens the vault at `path`.
fn unlock(path: &Path, prompt: &mut Prompter<impl BufRead>) -> Result<UnlockedVault> {
    if !path.try_exists()? {
        bail!("no vault at {}; run `pwv init` first", path.display());
    }
    let password = prompt.secret("Master password")?;
    Ok(pwv_core::storage::unlock(path, &password)?)
}

/// The entry for `site`. When several match, lists them by number on stderr and asks which one.
fn choose<'v>(
    vault: &'v Vault,
    site: &str,
    prompt: &mut Prompter<impl BufRead>,
) -> Result<&'v Entry> {
    let matches = vault.find(site);
    match matches.as_slice() {
        [] => bail!("no entry for {site}"),
        [entry] => Ok(*entry),
        _ => {
            eprintln!("Several entries match {site}:");
            for (n, e) in (1..).zip(&matches) {
                eprintln!("  {n}) {}  {}", e.site, e.username);
            }
            let count = matches.len();
            let answer = prompt.line(&format!("Which one? [1-{count}]"))?;
            // The answer is not echoed back: a misaligned --password-stdin line could be a secret.
            answer
                .trim()
                .parse::<usize>()
                .ok()
                .and_then(|n| n.checked_sub(1))
                .and_then(|i| matches.get(i).copied())
                .with_context(|| format!("answer must be a number from 1 to {count}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pwv_core::model::SecretText;
    use time::OffsetDateTime;

    fn vault(entries: &[(&str, &str)]) -> Vault {
        let mut vault = Vault::default();
        for (site, username) in entries {
            let secret = SecretText::from("hunter2".to_owned());
            let now = OffsetDateTime::UNIX_EPOCH;
            let notes = SecretText::default();
            vault.insert(Entry::new(
                (*site).into(),
                (*username).into(),
                secret,
                notes,
                now,
            ));
        }
        vault
    }

    fn choose_with(vault: &Vault, site: &str, input: &str) -> Result<String> {
        let mut prompt = Prompter::new(input.as_bytes(), true);
        Ok(choose(vault, site, &mut prompt)?.username.clone())
    }

    #[test]
    fn single_match_is_chosen_without_asking() {
        let v = vault(&[("mail", "alice"), ("bank", "bob")]);
        assert_eq!(choose_with(&v, "MAIL", "").unwrap(), "alice");
    }

    #[test]
    fn several_matches_are_chosen_by_number() {
        let v = vault(&[("mail", "alice"), ("bank", "bob"), ("Mail", "carol")]);
        assert_eq!(choose_with(&v, "mail", "2\n").unwrap(), "carol");
        assert_eq!(choose_with(&v, "mail", " 1 \n").unwrap(), "alice");
    }

    #[test]
    fn bad_answers_and_missing_sites_are_errors() {
        let v = vault(&[("mail", "alice"), ("mail", "carol")]);
        for answer in ["0\n", "3\n", "carol\n", "\n"] {
            let err = choose_with(&v, "mail", answer).unwrap_err().to_string();
            assert_eq!(err, "answer must be a number from 1 to 2");
        }
        let err = choose_with(&v, "bank", "").unwrap_err().to_string();
        assert_eq!(err, "no entry for bank");
    }
}
