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

impl Header {
    /// Encodes the header into its fixed 59-byte layout.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0..4].copy_from_slice(&MAGIC);
        out[4] = FORMAT_VERSION;
        out[5] = KDF_ARGON2ID;
        out[6..10].copy_from_slice(&self.kdf.m_cost_kib.to_le_bytes());
        out[10..14].copy_from_slice(&self.kdf.t_cost.to_le_bytes());
        out[14..18].copy_from_slice(&self.kdf.p_cost.to_le_bytes());
        out[18..34].copy_from_slice(&self.salt);
        out[34] = CIPHER_XCHACHA20_POLY1305;
        out[35..59].copy_from_slice(&self.nonce);
        out
    }
}
