//! Vault files on disk. This is the only module in `pwv-core` that does I/O.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use secrecy::SecretString;
use zeroize::Zeroizing;

use crate::crypto;
use crate::error::Result;
use crate::header::{Header, NONCE_LEN};
use crate::kdf::{self, KEY_LEN, KdfParams};
use crate::model::Vault;

/// File name of the vault inside the data directory.
pub const VAULT_FILE_NAME: &str = "vault.pwv";

/// Returns the default vault path in the OS data directory, for example
/// `~/.local/share/pwv/vault.pwv` on Linux. `None` if the OS reports no home directory.
#[must_use]
pub fn default_path() -> Option<PathBuf> {
    directories::ProjectDirs::from("", "", "pwv").map(|d| d.data_dir().join(VAULT_FILE_NAME))
}

/// An unlocked vault: the decrypted data plus the key and header needed to save it.
///
/// Holds the derived key, so it deliberately has no `Debug` implementation.
pub struct UnlockedVault {
    path: PathBuf,
    header: Header,
    key: Zeroizing<[u8; KEY_LEN]>,
    /// The decrypted vault. Call [`UnlockedVault::save`] to persist changes.
    pub vault: Vault,
}

/// Creates a new empty vault at `path` with a fresh salt and the default KDF parameters,
/// creating the parent directory if needed. An existing file is replaced; the caller decides
/// whether that is allowed.
///
/// # Errors
/// [`crate::Error::Io`] if the file cannot be written; KDF errors from [`kdf::derive_key`].
pub fn create(path: &Path, password: &SecretString) -> Result<UnlockedVault> {
    let header = Header {
        kdf: KdfParams::default(),
        salt: kdf::random_salt(),
        nonce: [0; NONCE_LEN], // replaced by `crypto::seal` on every save
    };
    let key = kdf::derive_key(password, &header.salt, &header.kdf)?;
    fs::create_dir_all(parent_dir(path))?;
    let unlocked = UnlockedVault {
        path: path.to_owned(),
        header,
        key,
        vault: Vault::default(),
    };
    unlocked.save()?;
    Ok(unlocked)
}

/// Reads, authenticates and decrypts the vault at `path`.
///
/// The header (including KDF parameters) is validated before Argon2 runs.
///
/// # Errors
/// [`crate::Error::Io`] if the file cannot be read; [`crate::Error::Decrypt`] for a wrong
/// password or a modified file; other header and schema errors as documented on
/// [`Header::parse`] and [`Vault::from_json`].
pub fn unlock(path: &Path, password: &SecretString) -> Result<UnlockedVault> {
    let bytes = fs::read(path)?;
    let (header, _) = Header::parse(&bytes)?;
    let key = kdf::derive_key(password, &header.salt, &header.kdf)?;
    let vault = Vault::from_json(&crypto::open(&key, &bytes)?)?;
    Ok(UnlockedVault {
        path: path.to_owned(),
        header,
        key,
        vault,
    })
}

impl UnlockedVault {
    /// Encrypts the vault with a fresh nonce and the same salt, and atomically replaces the file.
    ///
    /// # Errors
    /// [`crate::Error::Io`] if writing fails; the previous file is then left untouched.
    pub fn save(&self) -> Result<()> {
        let file = crypto::seal(&self.key, &self.header, &self.vault.to_json()?);
        write_atomic(&self.path, &file)?;
        Ok(())
    }
}

fn parent_dir(path: &Path) -> &Path {
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    }
}

/// `<vault>.bak`, next to the vault.
fn backup_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".bak");
    PathBuf::from(s)
}

/// Writes `bytes` to a temp file in the same directory, flushes it to disk, copies the current
/// vault to `<vault>.bak`, then renames the temp file over `path`. A crash leaves either the old
/// file or the new one, never a mix.
fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = parent_dir(path);
    let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
    restrict(tmp.path())?;
    tmp.write_all(bytes)?;
    tmp.as_file().sync_all()?;
    if path.exists() {
        let bak = backup_path(path);
        fs::copy(path, &bak)?;
        restrict(&bak)?;
    }
    tmp.persist(path).map_err(|e| e.error)?;
    sync_dir(dir)
}

/// Owner read/write only.
#[cfg(unix)]
fn restrict(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn restrict(_: &Path) -> io::Result<()> {
    Ok(()) // shortcut: Windows relies on the user profile ACLs; tighten in the hardening PR
}

/// Makes the rename itself durable.
#[cfg(unix)]
fn sync_dir(dir: &Path) -> io::Result<()> {
    fs::File::open(dir)?.sync_all()
}

#[cfg(not(unix))]
fn sync_dir(_: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_path_ends_with_vault_file() {
        if let Some(p) = default_path() {
            assert!(p.ends_with(VAULT_FILE_NAME));
            assert!(p.components().any(|c| c.as_os_str() == "pwv"));
        }
    }
}

// Real Argon2 parameters take seconds per vault in debug builds, so file tests need the fast profile.
#[cfg(test)]
#[cfg(feature = "insecure-test-kdf")]
mod file_tests {
    use super::*;
    use crate::Error;
    use crate::header::HEADER_LEN;
    use crate::model::{Entry, SecretText};
    use time::macros::datetime;

    fn password(s: &str) -> SecretString {
        SecretString::from(s.to_owned())
    }

    #[test]
    fn create_writes_a_vault_with_default_params() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("v.pwv");
        create(&path, &password("correct horse")).unwrap();
        let bytes = fs::read(&path).unwrap();
        let (header, _) = Header::parse(&bytes).unwrap();
        assert_eq!(header.kdf, KdfParams::default());
        assert!(bytes.len() > HEADER_LEN);
    }

    fn new_vault(dir: &tempfile::TempDir) -> PathBuf {
        let path = dir.path().join("v.pwv");
        create(&path, &password("correct horse")).unwrap();
        path
    }

    #[test]
    fn saved_entries_survive_unlock() {
        let dir = tempfile::tempdir().unwrap();
        let path = new_vault(&dir);
        let mut v = unlock(&path, &password("correct horse")).unwrap();
        v.vault.insert(Entry::new(
            "example.com".to_owned(),
            "alice".to_owned(),
            SecretText::from("hunter2".to_owned()),
            SecretText::default(),
            datetime!(2026-10-28 12:00 UTC),
        ));
        v.save().unwrap();

        let v = unlock(&path, &password("correct horse")).unwrap();
        assert_eq!(v.vault.find("example.com")[0].password.expose(), "hunter2");
    }

    #[test]
    fn wrong_password_fails_with_decrypt() {
        let dir = tempfile::tempdir().unwrap();
        let path = new_vault(&dir);
        let err = unlock(&path, &password("wrong")).err().unwrap();
        assert!(matches!(err, Error::Decrypt));
    }

    #[test]
    fn save_keeps_salt_and_changes_nonce() {
        let dir = tempfile::tempdir().unwrap();
        let path = new_vault(&dir);
        let before = fs::read(&path).unwrap();
        unlock(&path, &password("correct horse"))
            .unwrap()
            .save()
            .unwrap();
        let after = fs::read(&path).unwrap();
        let (h1, _) = Header::parse(&before).unwrap();
        let (h2, _) = Header::parse(&after).unwrap();
        assert_eq!(h1.salt, h2.salt);
        assert_ne!(h1.nonce, h2.nonce);
    }

    #[test]
    fn save_keeps_previous_file_as_bak() {
        let dir = tempfile::tempdir().unwrap();
        let path = new_vault(&dir);
        let first = fs::read(&path).unwrap();
        unlock(&path, &password("correct horse"))
            .unwrap()
            .save()
            .unwrap();
        assert_eq!(fs::read(backup_path(&path)).unwrap(), first);
        assert_ne!(fs::read(&path).unwrap(), first);
    }

    #[test]
    #[cfg(unix)]
    fn vault_and_bak_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = new_vault(&dir);
        unlock(&path, &password("correct horse"))
            .unwrap()
            .save()
            .unwrap();
        for p in [path.clone(), backup_path(&path)] {
            let mode = fs::metadata(&p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{}", p.display());
        }
    }

    #[test]
    fn failure_before_rename_leaves_original_intact() {
        let dir = tempfile::tempdir().unwrap();
        let path = new_vault(&dir);
        let original = fs::read(&path).unwrap();
        // A directory where the backup should go makes the copy fail just before the rename.
        fs::create_dir(backup_path(&path)).unwrap();

        let mut v = unlock(&path, &password("correct horse")).unwrap();
        v.vault.insert(Entry::new(
            "example.com".to_owned(),
            "alice".to_owned(),
            SecretText::from("hunter2".to_owned()),
            SecretText::default(),
            datetime!(2026-10-28 12:00 UTC),
        ));
        assert!(matches!(v.save(), Err(Error::Io(_))));

        assert_eq!(fs::read(&path).unwrap(), original);
        let names: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names.len(), 2, "temp file left behind: {names:?}");
    }
}
