//! Vault header: the plaintext, authenticated first 59 bytes of a vault file.
//!
//! See `docs/DESIGN.md` for the byte layout. All integers are little-endian.

use crate::error::{Error, Result};
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

    /// Parses and validates the header at the start of a vault file.
    ///
    /// Returns the header and the remaining bytes (`ciphertext ‖ tag`). Checks, in
    /// order: length, magic, format version, KDF and cipher ids, then the KDF
    /// parameters against the floor and ceiling, so no hostile parameter reaches Argon2.
    ///
    /// # Errors
    /// - [`Error::Format`] if the file is shorter than a header plus tag, or the magic is wrong.
    /// - [`Error::UnsupportedVersion`] for an unknown format version, KDF or cipher id.
    /// - [`Error::ParamsOutOfRange`] if the KDF parameters fail [`KdfParams::validate`].
    pub fn parse(bytes: &[u8]) -> Result<(Self, &[u8])> {
        if bytes.len() < HEADER_LEN + TAG_LEN {
            return Err(Error::Format);
        }
        let (h, rest) = bytes
            .split_first_chunk::<HEADER_LEN>()
            .ok_or(Error::Format)?;
        if h[0..4] != MAGIC {
            return Err(Error::Format);
        }
        if h[4] != FORMAT_VERSION || h[5] != KDF_ARGON2ID || h[34] != CIPHER_XCHACHA20_POLY1305 {
            return Err(Error::UnsupportedVersion);
        }
        let le_u32 = |i: usize| u32::from_le_bytes([h[i], h[i + 1], h[i + 2], h[i + 3]]);
        let kdf = KdfParams {
            m_cost_kib: le_u32(6),
            t_cost: le_u32(10),
            p_cost: le_u32(14),
        };
        kdf.validate()?;
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&h[18..34]);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&h[35..59]);
        Ok((Self { kdf, salt, nonce }, rest))
    }
}
