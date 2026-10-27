//! Vault files on disk. This is the only module in `pwv-core` that does I/O.

use std::path::PathBuf;

/// File name of the vault inside the data directory.
pub const VAULT_FILE_NAME: &str = "vault.pwv";

/// Returns the default vault path in the OS data directory, for example
/// `~/.local/share/pwv/vault.pwv` on Linux. `None` if the OS reports no home directory.
#[must_use]
pub fn default_path() -> Option<PathBuf> {
    directories::ProjectDirs::from("", "", "pwv").map(|d| d.data_dir().join(VAULT_FILE_NAME))
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
