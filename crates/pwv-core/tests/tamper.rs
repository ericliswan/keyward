//! Tampering, truncation and downgrade tests, run against real vault files through the
//! public `storage` API. Each test's doc comment names the README claim it proves.

// Every test unlocks vault files, which needs the fast KDF profile.
#![cfg(feature = "insecure-test-kdf")]
// `allow-unwrap-in-tests` does not reach helper functions in integration tests.
#![allow(clippy::unwrap_used)]

use std::fs;

use pwv_core::header::{HEADER_LEN, TAG_LEN};
use pwv_core::{Error, storage};
use secrecy::SecretString;

const PASSWORD: &str = "correct horse battery staple";

fn password(s: &str) -> SecretString {
    SecretString::from(s.to_owned())
}

/// The bytes of a freshly created vault with no entries.
fn new_vault_bytes() -> Vec<u8> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.pwv");
    storage::create(&path, &password(PASSWORD)).unwrap();
    fs::read(&path).unwrap()
}

/// Writes `bytes` as a vault file and unlocks it with the correct password.
fn unlock_bytes(bytes: &[u8]) -> Result<(), Error> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.pwv");
    fs::write(&path, bytes).unwrap();
    storage::unlock(&path, &password(PASSWORD)).map(drop)
}

/// README claim: changing any byte of the vault file makes unlock fail.
///
/// Header bytes fail parsing or validation where they can; everything else, including the
/// salt, the nonce and in-range KDF parameters, fails authentication.
#[test]
fn flipping_any_byte_is_rejected() {
    let file = new_vault_bytes();
    for i in 0..file.len() {
        let mut tampered = file.clone();
        tampered[i] ^= 0xFF;
        let err = unlock_bytes(&tampered).expect_err("tampered vault unlocked");
        let expected = match i {
            0..4 => matches!(err, Error::Format),
            4 | 5 | 34 => matches!(err, Error::UnsupportedVersion),
            6..18 => matches!(err, Error::ParamsOutOfRange | Error::Decrypt),
            _ => matches!(err, Error::Decrypt),
        };
        assert!(expected, "byte {i}: unexpected {err:?}");
    }
}

/// README claim: a truncated or extended vault file is refused, never partly read.
///
/// Covers every length from empty up to one byte short, plus one extra byte at the end.
#[test]
fn truncated_empty_and_extended_files_are_rejected() {
    let file = new_vault_bytes();
    for len in 0..file.len() {
        let err = unlock_bytes(&file[..len]).expect_err("truncated vault unlocked");
        let expected = if len < HEADER_LEN + TAG_LEN {
            matches!(err, Error::Format)
        } else {
            matches!(err, Error::Decrypt)
        };
        assert!(expected, "length {len}: unexpected {err:?}");
    }

    let mut extended = file;
    extended.push(0);
    assert!(matches!(unlock_bytes(&extended), Err(Error::Decrypt)));
}
