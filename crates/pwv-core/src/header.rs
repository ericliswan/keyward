//! Vault header: the plaintext, authenticated first 59 bytes of a vault file.
//!
//! See `docs/DESIGN.md` for the byte layout. All integers are little-endian.

use crate::kdf::{KdfParams, SALT_LEN};

/// File magic, `b"PWVF"`.
pub const MAGIC: [u8; 4] = *b"PWVF";
/// The only format version this build reads and writes.
pub const FORMAT_VERSION: u8 = 1;
/// `kdf_id` for Argon2id v0x13.
pub const KDF_ARGON2ID: u8 = 1;
/// `cipher_id` for XChaCha20-Poly1305.
pub const CIPHER_XCHACHA20_POLY1305: u8 = 1;
/// XChaCha20-Poly1305 nonce length in bytes.
pub const NONCE_LEN: usize = 24;
/// Poly1305 tag length in bytes.
pub const TAG_LEN: usize = 16;
/// Header length in bytes. The whole header is the AEAD associated data.
pub const HEADER_LEN: usize = 59;

/// The parsed vault header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    /// Argon2id parameters used to derive the key.
    pub kdf: KdfParams,
    /// Random salt; changes only on `init` and `change-master`.
    pub salt: [u8; SALT_LEN],
    /// Random nonce; fresh on every save.
    pub nonce: [u8; NONCE_LEN],
}
