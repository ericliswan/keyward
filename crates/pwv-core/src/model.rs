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
