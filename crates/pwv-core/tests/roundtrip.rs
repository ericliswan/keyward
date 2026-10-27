//! Round-trip tests: a vault saved to disk unlocks to exactly what was saved. Each test's doc
//! comment names the README claim it proves.

// Every test unlocks vault files, which needs the fast KDF profile.
#![cfg(feature = "insecure-test-kdf")]
// `allow-unwrap-in-tests` does not reach helper functions in integration tests.
#![allow(clippy::unwrap_used)]

use std::fs;

use proptest::prelude::*;
use pwv_core::header::Header;
use pwv_core::model::{Entry, SecretText};
use pwv_core::storage;
use secrecy::SecretString;
use time::OffsetDateTime;
use uuid::Uuid;

const PASSWORD: &str = "correct horse battery staple";

fn password(s: &str) -> SecretString {
    SecretString::from(s.to_owned())
}

/// Any text, including newlines, quotes, backslashes, control characters and non-ASCII.
const TEXT: &str = "(?s).{0,40}";

/// Any instant RFC 3339 can write (years 0000 to 9999), to the nanosecond.
fn timestamp() -> impl Strategy<Value = OffsetDateTime> {
    const NANOS: i128 = 1_000_000_000;
    (-62_167_219_200 * NANOS..253_402_300_800 * NANOS)
        .prop_map(|ns| OffsetDateTime::from_unix_timestamp_nanos(ns).unwrap())
}

fn entry() -> impl Strategy<Value = Entry> {
    let fields = (
        any::<u128>(),
        TEXT,
        TEXT,
        TEXT,
        TEXT,
        timestamp(),
        timestamp(),
    );
    fields.prop_map(
        |(id, site, username, password, notes, created_at, updated_at)| Entry {
            id: Uuid::from_u128(id),
            site,
            username,
            password: SecretText::from(password),
            notes: SecretText::from(notes),
            created_at,
            updated_at,
        },
    )
}

type Fields<'a> = (
    Uuid,
    &'a str,
    &'a str,
    &'a str,
    &'a str,
    OffsetDateTime,
    OffsetDateTime,
);

fn fields(e: &Entry) -> Fields<'_> {
    (
        e.id,
        &e.site,
        &e.username,
        e.password.expose(),
        e.notes.expose(),
        e.created_at,
        e.updated_at,
    )
}

proptest! {
    // Each case writes and unlocks real files, so keep the count modest.
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// README claim: every field you store comes back exactly as entered.
    #[test]
    fn random_vaults_round_trip(entries in prop::collection::vec(entry(), 0..8)) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.pwv");
        let mut unlocked = storage::create(&path, &password(PASSWORD)).unwrap();
        unlocked.vault.entries = entries.clone();
        unlocked.save().unwrap();

        let back = storage::unlock(&path, &password(PASSWORD)).unwrap().vault.entries;
        prop_assert_eq!(
            back.iter().map(fields).collect::<Vec<_>>(),
            entries.iter().map(fields).collect::<Vec<_>>()
        );
    }
}

/// README claim: every save uses a fresh random nonce and keeps the salt, so saving the same
/// vault twice never produces the same ciphertext.
#[test]
fn two_saves_produce_different_nonces_and_ciphertexts() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.pwv");
    let unlocked = storage::create(&path, &password(PASSWORD)).unwrap();
    let first = fs::read(&path).unwrap();
    unlocked.save().unwrap();
    let second = fs::read(&path).unwrap();

    let (h1, c1) = Header::parse(&first).unwrap();
    let (h2, c2) = Header::parse(&second).unwrap();
    assert_eq!(h1.salt, h2.salt);
    assert_ne!(h1.nonce, h2.nonce);
    assert_ne!(c1, c2);
}
