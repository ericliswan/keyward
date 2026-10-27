//! Authenticated encryption of the vault body with XChaCha20-Poly1305.
//!
//! The whole 59-byte header is the associated data, so changing any header byte
//! (including the KDF parameters or salt) makes decryption fail.

use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use rand::TryRng;
use rand::rngs::SysRng;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::header::{HEADER_LEN, Header};
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

/// Parses and decrypts complete file bytes produced by [`seal`].
///
/// # Errors
/// - Any [`Header::parse`] error, before any key is used.
/// - [`Error::Decrypt`] if authentication fails. A wrong key, a modified header and a
///   modified ciphertext are deliberately indistinguishable.
pub fn open(key: &[u8; KEY_LEN], file: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let (header, ciphertext) = Header::parse(file)?;
    XChaCha20Poly1305::new(key.into())
        .decrypt(
            &header.nonce.into(),
            Payload {
                msg: ciphertext,
                aad: &file[..HEADER_LEN],
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| Error::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::KdfParams;

    const KEY: [u8; KEY_LEN] = [7; KEY_LEN];

    fn header() -> Header {
        Header {
            kdf: KdfParams::default(),
            salt: [1; 16],
            nonce: [0; 24],
        }
    }

    #[test]
    fn round_trip() {
        let file = seal(&KEY, &header(), b"secret");
        assert_eq!(open(&KEY, &file).unwrap().as_slice(), b"secret");
    }

    #[test]
    fn seal_uses_fresh_nonce() {
        let a = seal(&KEY, &header(), b"x");
        let b = seal(&KEY, &header(), b"x");
        assert_ne!(a[35..HEADER_LEN], [0; 24]);
        assert_ne!(a, b);
    }

    #[test]
    fn wrong_key_fails_with_generic_message() {
        let file = seal(&KEY, &header(), b"secret");
        let err = open(&[8; KEY_LEN], &file).unwrap_err();
        assert!(matches!(err, Error::Decrypt));
        assert_eq!(err.to_string(), "wrong password or corrupted vault");
    }

    /// draft-irtf-cfrg-xchacha-03, Appendix A.3.1.
    #[test]
    fn xchacha20_poly1305_known_answer() {
        let key: [u8; 32] =
            hex_literal::hex!("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        let nonce: [u8; 24] = hex_literal::hex!("404142434445464748494a4b4c4d4e4f5051525354555657");
        let aad = hex_literal::hex!("50515253c0c1c2c3c4c5c6c7");
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let expected = hex_literal::hex!(
            "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb"
            "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452"
            "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9"
            "21f9664c97637da9768812f615c68b13b52e"
            "c0875924c1c7987947deafd8780acf49"
        );
        let cipher = XChaCha20Poly1305::new(&key.into());
        let payload = Payload {
            msg: plaintext,
            aad: &aad,
        };
        assert_eq!(cipher.encrypt(&nonce.into(), payload).unwrap(), expected);
        let payload = Payload {
            msg: &expected,
            aad: &aad,
        };
        assert_eq!(cipher.decrypt(&nonce.into(), payload).unwrap(), plaintext);
    }
}
