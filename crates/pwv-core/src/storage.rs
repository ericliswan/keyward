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

/// Writes `bytes` to a temp file in the same directory, flushes it to disk, then renames it
/// over `path`, so a crash leaves either the old file or the new one, never a mix.
fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut tmp = tempfile::NamedTempFile::new_in(parent_dir(path))?;
    tmp.write_all(bytes)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| e.error)?;
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
#[cfg(all(test, feature = "insecure-test-kdf"))]
mod file_tests {
    use super::*;
    use crate::header::HEADER_LEN;

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
}
