//! `pwv list`: show sites and usernames, never passwords or notes.

use std::io::BufRead;
use std::path::Path;

use anyhow::Result;
use pwv_core::model::Entry;

use crate::prompt::Prompter;

pub fn run(path: &Path, search: Option<&str>, prompt: &mut Prompter<impl BufRead>) -> Result<()> {
    let unlocked = super::unlock(path, prompt)?;
    let query = search.map(str::to_lowercase);
    let entries: Vec<&Entry> = unlocked
        .vault
        .entries
        .iter()
        .filter(|e| query.as_deref().is_none_or(|q| matches(e, q)))
        .collect();
    if entries.is_empty() {
        eprintln!("No entries found");
    } else {
        print!("{}", table(entries));
    }
    Ok(())
}

/// Case-insensitive substring match on site or username; `query` is already lowercase.
fn matches(entry: &Entry, query: &str) -> bool {
    entry.site.to_lowercase().contains(query) || entry.username.to_lowercase().contains(query)
}

/// Site and username columns, sorted by site then username, ignoring case.
fn table(mut entries: Vec<&Entry>) -> String {
    entries.sort_by_cached_key(|e| (e.site.to_lowercase(), e.username.to_lowercase()));
    let width = entries
        .iter()
        .map(|e| e.site.chars().count())
        .fold("SITE".len(), usize::max);
    let mut out = format!("{:<width$}  USERNAME\n", "SITE");
    for e in entries {
        out += &format!("{:<width$}  {}\n", e.site, e.username);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use pwv_core::model::SecretText;
    use time::OffsetDateTime;

    fn entry(site: &str, username: &str) -> Entry {
        let secret = |s: &str| SecretText::from(s.to_owned());
        let now = OffsetDateTime::UNIX_EPOCH;
        Entry::new(
            site.into(),
            username.into(),
            secret("hunter2"),
            secret("pin 1234"),
            now,
        )
    }

    #[test]
    fn table_is_sorted_aligned_and_has_no_secrets() {
        let (a, b, c) = (
            entry("mail", "bob"),
            entry("Bank.example", "alice"),
            entry("mail", "Ann"),
        );
        let out = table(vec![&a, &b, &c]);
        let expected = "\
SITE          USERNAME
Bank.example  alice
mail          Ann
mail          bob
";
        assert_eq!(out, expected);
        assert!(!out.contains("hunter2") && !out.contains("1234"));
    }

    #[test]
    fn search_matches_site_or_username_ignoring_case() {
        let e = entry("Bank.Example", "Alice");
        assert!(matches(&e, "bank"));
        assert!(matches(&e, "k.ex"));
        assert!(matches(&e, "alice"));
        assert!(!matches(&e, "bob"));
        assert!(!matches(&e, "hunter")); // the password is never searched
    }
}
