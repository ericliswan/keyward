//! Rejection tests: wrong password, tampering, truncation and downgrade, run against real
//! vault files through the public `storage` API. Each test's doc comment names the README
//! claim it proves.

// Every test unlocks vault files, which needs the fast KDF profile.
#![cfg(feature = "insecure-test-kdf")]
// `allow-unwrap-in-tests` does not reach helper functions in integration tests.
#![allow(clippy::unwrap_used)]

use std::fs;

use pwv_core::header::{HEADER_LEN, Header, NONCE_LEN, TAG_LEN};
use pwv_core::kdf::{self, KdfParams};
use pwv_core::model::Vault;
use pwv_core::{Error, crypto, storage};
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

/// README claim: lowering the KDF cost in the header does not weaken the vault. Below the
/// floor it is refused as out of range; within range it fails authentication, because the
/// parameters are part of the associated data.
#[test]
fn memory_cost_downgrade_is_rejected() {
    let floor = KdfParams::FLOOR;
    let original = KdfParams {
        m_cost_kib: floor.m_cost_kib * 4,
        ..floor
    };
    let header = Header {
        kdf: original,
        salt: kdf::random_salt(),
        nonce: [0; NONCE_LEN],
    };
    let key = kdf::derive_key(&password(PASSWORD), &header.salt, &original).unwrap();
    let file = crypto::seal(&key, &header, &Vault::default().to_json().unwrap());
    unlock_bytes(&file).unwrap();

    let with_m_cost = |m: u32| {
        let mut f = file.clone();
        f[6..10].copy_from_slice(&m.to_le_bytes());
        f
    };

    // Even the original key cannot open the file once the header says something else.
    let downgraded = with_m_cost(floor.m_cost_kib);
    assert!(matches!(
        crypto::open(&key, &downgraded),
        Err(Error::Decrypt)
    ));
    assert!(matches!(unlock_bytes(&downgraded), Err(Error::Decrypt)));

    let below_floor = with_m_cost(floor.m_cost_kib - 1);
    assert!(matches!(
        unlock_bytes(&below_floor),
        Err(Error::ParamsOutOfRange)
    ));
}

/// README claim: a wrong password gets the same error as a corrupted file and changes
/// nothing on disk.
#[test]
fn wrong_password_fails_and_leaves_files_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.pwv");
    // The second save creates the `.bak`.
    storage::create(&path, &password(PASSWORD))
        .unwrap()
        .save()
        .unwrap();
    let snapshot = || {
        let mut files: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                (e.file_name(), fs::read(e.path()).unwrap())
            })
            .collect();
        files.sort();
        files
    };
    let before = snapshot();
    assert_eq!(before.len(), 2, "expected the vault and its .bak");

    let err = storage::unlock(&path, &password("wrong password"))
        .map(drop)
        .unwrap_err();
    assert!(matches!(err, Error::Decrypt));
    assert_eq!(err.to_string(), "wrong password or corrupted vault");
    assert_eq!(snapshot(), before);
}
