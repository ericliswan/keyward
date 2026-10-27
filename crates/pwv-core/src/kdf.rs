//! Argon2id key derivation.

use argon2::{Algorithm, Argon2, Version};
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// Salt length in bytes.
pub const SALT_LEN: usize = 16;

/// Derived key length in bytes (256 bits).
pub const KEY_LEN: usize = 32;

/// Argon2id cost parameters, stored in the vault header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub m_cost_kib: u32,
    /// Number of passes.
    pub t_cost: u32,
    /// Degree of parallelism (lanes).
    pub p_cost: u32,
}

impl KdfParams {
    /// Production default: RFC 9106 second recommended option (64 MiB, 3 passes, 4 lanes).
    pub const PRODUCTION: Self = Self {
        m_cost_kib: 65_536,
        t_cost: 3,
        p_cost: 4,
    };

    /// Smallest parameters a production build accepts (OWASP minimum).
    pub const PRODUCTION_FLOOR: Self = Self {
        m_cost_kib: 19_456,
        t_cost: 2,
        p_cost: 1,
    };

    /// Largest parameters accepted, so a malicious header cannot exhaust memory or time.
    pub const CEILING: Self = Self {
        m_cost_kib: 4_194_304,
        t_cost: 10,
        p_cost: 16,
    };

    /// Fast, insecure parameters for tests. Only used with the `insecure-test-kdf` feature.
    pub const TEST: Self = Self {
        m_cost_kib: 8,
        t_cost: 1,
        p_cost: 1,
    };

    /// The floor in effect for this build.
    pub const FLOOR: Self = if cfg!(feature = "insecure-test-kdf") {
        Self::TEST
    } else {
        Self::PRODUCTION_FLOOR
    };

    /// Checks each parameter against [`Self::FLOOR`] and [`Self::CEILING`].
    ///
    /// # Errors
    /// Returns [`Error::ParamsOutOfRange`] if any parameter is outside the range.
    pub fn validate(&self) -> Result<()> {
        let (lo, hi) = (Self::FLOOR, Self::CEILING);
        let in_range = (lo.m_cost_kib..=hi.m_cost_kib).contains(&self.m_cost_kib)
            && (lo.t_cost..=hi.t_cost).contains(&self.t_cost)
            && (lo.p_cost..=hi.p_cost).contains(&self.p_cost);
        if in_range {
            Ok(())
        } else {
            Err(Error::ParamsOutOfRange)
        }
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        if cfg!(feature = "insecure-test-kdf") {
            Self::TEST
        } else {
            Self::PRODUCTION
        }
    }
}

/// Derives a 256-bit key from the master password with Argon2id v0x13.
///
/// The parameters are validated first, so the values used are exactly the values
/// written to the header.
///
/// # Errors
/// Returns [`Error::ParamsOutOfRange`] if `params` fail [`KdfParams::validate`]
/// or are rejected by Argon2.
pub fn derive_key(
    password: &SecretString,
    salt: &[u8; SALT_LEN],
    params: &KdfParams,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    params.validate()?;
    let argon_params = argon2::Params::new(
        params.m_cost_kib,
        params.t_cost,
        params.p_cost,
        Some(KEY_LEN),
    )
    .map_err(|_| Error::ParamsOutOfRange)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(password.expose_secret().as_bytes(), salt, key.as_mut())
        .map_err(|_| Error::ParamsOutOfRange)?;
    Ok(key)
}
