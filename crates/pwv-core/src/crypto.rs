//! Authenticated encryption of the vault body with XChaCha20-Poly1305.
//!
//! The whole 59-byte header is the associated data, so changing any header byte
//! (including the KDF parameters or salt) makes decryption fail.

use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use rand::TryRng;
use rand::rngs::SysRng;

use crate::header::Header;
use crate::kdf::KEY_LEN;

/// Encrypts `plaintext` and returns the complete file bytes: `header ‖ ciphertext ‖ tag`.
///
/// A fresh random nonce from the OS replaces `header.nonce`; the caller never picks it.
///
/// # Panics
/// If the operating system's random number generator fails.
#[must_use]
pub fn seal(key: &[u8; KEY_LEN], header: &Header, plaintext: &[u8]) -> Vec<u8> {
    let mut header = header.clone();
    SysRng
        .try_fill_bytes(&mut header.nonce)
        .expect("OS random number generator failed");
    let aad = header.to_bytes();
    let ciphertext = XChaCha20Poly1305::new(key.into())
        .encrypt(
            &header.nonce.into(),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .expect("XChaCha20-Poly1305 encryption cannot fail for in-memory input");
    [aad.as_slice(), &ciphertext].concat()
}
