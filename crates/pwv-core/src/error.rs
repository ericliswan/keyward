//! Error type for `pwv-core`. Messages never include secret material.

/// Errors returned by `pwv-core`.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The file is not a vault: bad magic or too short.
    #[error("not a pwv vault or the file is truncated")]
    Format,
    /// The vault uses a format version, KDF or cipher this build does not support.
    #[error("unsupported vault format version")]
    UnsupportedVersion,
    /// KDF parameters are outside the allowed floor and ceiling.
    #[error("key derivation parameters are out of the allowed range")]
    ParamsOutOfRange,
    /// Decryption failed. A wrong password and a corrupted file are deliberately indistinguishable.
    #[error("wrong password or corrupted vault")]
    Decrypt,
    /// Reading or writing the vault file failed.
    #[error("vault file I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// The decrypted vault is not valid JSON for this schema. The message is fixed because
    /// `serde_json` errors can quote the input, which is secret.
    #[error("vault contents are malformed")]
    Serde,
}

/// Result alias using [`Error`].
pub type Result<T> = std::result::Result<T, Error>;
