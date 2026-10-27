//! In-memory vault data model, serialised as the JSON plaintext described in `docs/DESIGN.md`.

use std::fmt;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// The only plaintext schema version this build reads and writes.
pub const SCHEMA_VERSION: u32 = 1;

/// The decrypted vault.
#[derive(Debug, Serialize, Deserialize)]
pub struct Vault {
    /// Plaintext schema version, currently [`SCHEMA_VERSION`].
    pub schema_version: u32,
    /// All entries, in insertion order.
    pub entries: Vec<Entry>,
}

/// One stored login. `Debug` is safe: secret fields print `<redacted>`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Entry {
    /// Random v4 UUID; the stable key for update and remove.
    pub id: Uuid,
    /// Site or service name.
    pub site: String,
    /// Username or email for the site.
    pub username: String,
    /// The site password.
    pub password: SecretText,
    /// Free-form notes, treated as secret.
    pub notes: SecretText,
    /// When the entry was created.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// When the entry was last changed.
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

impl Entry {
    /// Creates an entry with a fresh UUID and both timestamps set to `now`.
    #[must_use]
    pub fn new(
        site: String,
        username: String,
        password: SecretText,
        notes: SecretText,
        now: OffsetDateTime,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            site,
            username,
            password,
            notes,
            created_at: now,
            updated_at: now,
        }
    }
}

impl Default for Vault {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            entries: Vec::new(),
        }
    }
}

impl Vault {
    /// Serialises the vault to the JSON plaintext.
    ///
    /// # Errors
    /// [`Error::Serde`] if serialisation fails.
    pub fn to_json(&self) -> Result<Zeroizing<Vec<u8>>> {
        serde_json::to_vec(self)
            .map(Zeroizing::new)
            .map_err(|_| Error::Serde)
    }

    /// Parses the JSON plaintext.
    ///
    /// # Errors
    /// - [`Error::Serde`] if the JSON does not match the schema.
    /// - [`Error::UnsupportedVersion`] if `schema_version` is not [`SCHEMA_VERSION`].
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let vault: Self = serde_json::from_slice(bytes).map_err(|_| Error::Serde)?;
        if vault.schema_version != SCHEMA_VERSION {
            return Err(Error::UnsupportedVersion);
        }
        Ok(vault)
    }

    /// Returns every entry whose site equals `site`, ignoring case. Several logins for one
    /// site are allowed, so the caller decides how to pick among them.
    #[must_use]
    pub fn find(&self, site: &str) -> Vec<&Entry> {
        let site = site.to_lowercase();
        self.entries
            .iter()
            .filter(|e| e.site.to_lowercase() == site)
            .collect()
    }

    /// Adds an entry and returns its id.
    pub fn insert(&mut self, entry: Entry) -> Uuid {
        let id = entry.id;
        self.entries.push(entry);
        id
    }

    /// Applies `change` to the entry with `id` and sets its `updated_at` to `now`.
    /// Returns `false` if there is no such entry.
    pub fn update(
        &mut self,
        id: Uuid,
        now: OffsetDateTime,
        change: impl FnOnce(&mut Entry),
    ) -> bool {
        let Some(entry) = self.entries.iter_mut().find(|e| e.id == id) else {
            return false;
        };
        change(entry);
        entry.updated_at = now;
        true
    }

    /// Removes and returns the entry with `id`, if present.
    pub fn remove(&mut self, id: Uuid) -> Option<Entry> {
        let i = self.entries.iter().position(|e| e.id == id)?;
        Some(self.entries.remove(i))
    }
}

/// A secret text field (password or notes).
///
/// `Debug` prints `<redacted>` and the buffer is zeroized on drop. Copies made by
/// `serde_json` while parsing cannot be wiped; see the README limitations.
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretText(Zeroizing<String>);

impl SecretText {
    /// Returns the secret. Keep the borrow short and never log it.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl From<String> for SecretText {
    fn from(s: String) -> Self {
        Self(Zeroizing::new(s))
    }
}

impl fmt::Debug for SecretText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    const NOW: OffsetDateTime = datetime!(2026-10-28 12:00 UTC);

    fn entry(site: &str) -> Entry {
        Entry::new(
            site.to_owned(),
            "alice".to_owned(),
            SecretText::from("hunter2".to_owned()),
            SecretText::from("recovery codes".to_owned()),
            NOW,
        )
    }

    #[test]
    fn json_round_trip_matches_schema() {
        let mut vault = Vault::default();
        vault.entries.push(entry("example.com"));
        let json = vault.to_json().unwrap();
        let value: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["entries"][0]["password"], "hunter2");
        assert_eq!(value["entries"][0]["created_at"], "2026-10-28T12:00:00Z");

        let back = Vault::from_json(&json).unwrap();
        let e = &back.entries[0];
        assert_eq!(e.id, vault.entries[0].id);
        assert_eq!(e.site, "example.com");
        assert_eq!(e.password.expose(), "hunter2");
        assert_eq!(e.notes.expose(), "recovery codes");
        assert_eq!(e.updated_at, NOW);
    }

    #[test]
    fn find_returns_all_case_insensitive_matches() {
        let mut vault = Vault::default();
        let a = vault.insert(entry("Example.com"));
        let b = vault.insert(entry("example.com"));
        vault.insert(entry("other.org"));
        let ids: Vec<Uuid> = vault.find("EXAMPLE.COM").iter().map(|e| e.id).collect();
        assert_eq!(ids, [a, b]);
        assert!(vault.find("example").is_empty());
    }

    #[test]
    fn update_changes_entry_and_bumps_updated_at() {
        let mut vault = Vault::default();
        let id = vault.insert(entry("example.com"));
        let later = datetime!(2026-10-29 08:30 UTC);
        assert!(vault.update(id, later, |e| e.username = "bob".to_owned()));
        let e = &vault.entries[0];
        assert_eq!(e.username, "bob");
        assert_eq!(e.created_at, NOW);
        assert_eq!(e.updated_at, later);
        assert!(!vault.update(Uuid::nil(), later, |_| {}));
    }

    #[test]
    fn remove_by_id() {
        let mut vault = Vault::default();
        let id = vault.insert(entry("example.com"));
        assert_eq!(vault.remove(id).map(|e| e.id), Some(id));
        assert!(vault.remove(id).is_none());
        assert!(vault.entries.is_empty());
    }

    #[test]
    fn debug_output_never_contains_password_text() {
        let mut vault = Vault::default();
        vault.insert(entry("example.com"));
        for out in [format!("{vault:?}"), format!("{vault:#?}")] {
            assert!(!out.contains("hunter2"), "{out}");
            assert!(!out.contains("recovery codes"), "{out}");
            assert!(out.contains("example.com"));
        }
    }

    #[test]
    fn rejects_unknown_schema_version() {
        let err = Vault::from_json(br#"{"schema_version":2,"entries":[]}"#).unwrap_err();
        assert!(matches!(err, Error::UnsupportedVersion));
    }

    #[test]
    fn malformed_json_error_does_not_echo_input() {
        let err = Vault::from_json(br#"{"schema_version":1,"entries":"hunter2"}"#).unwrap_err();
        assert!(matches!(err, Error::Serde));
        assert!(!err.to_string().contains("hunter2"));
    }

    #[test]
    fn secret_text_debug_is_redacted() {
        let s = SecretText::from("hunter2".to_owned());
        assert_eq!(format!("{s:?}"), "<redacted>");
        assert_eq!(s.expose(), "hunter2");
    }
}
