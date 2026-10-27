//! Argon2id key derivation.

use argon2::{Algorithm, Argon2, Version};
use rand::TryRng;
use rand::rngs::SysRng;
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
    /// Production default: 256 MiB, 3 passes, 4 lanes, about 0.6 s on an Apple M1
    /// (see `docs/decisions/0002-kdf-default-parameters.md`).
    pub const PRODUCTION: Self = Self {
        m_cost_kib: 262_144,
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

/// Returns a fresh random salt from the OS random number generator.
///
/// # Panics
/// If the operating system's random number generator fails.
#[must_use]
pub fn random_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    SysRng
        .try_fill_bytes(&mut salt)
        .expect("OS random number generator failed");
    salt
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

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    /// RFC 9106 §5.3 Argon2id test vector. It needs a secret and associated data,
    /// which `derive_key` never uses, so it calls the crate directly to pin the
    /// exact algorithm and version `derive_key` selects.
    #[test]
    fn argon2id_rfc9106_known_answer() {
        let params = argon2::ParamsBuilder::new()
            .m_cost(32)
            .t_cost(3)
            .p_cost(4)
            .data(argon2::AssociatedData::new(&[0x04; 12]).unwrap())
            .build()
            .unwrap();
        let argon =
            Argon2::new_with_secret(&[0x03; 8], Algorithm::Argon2id, Version::V0x13, params)
                .unwrap();
        let mut out = [0u8; 32];
        argon
            .hash_password_into(&[0x01; 32], &[0x02; 16], &mut out)
            .unwrap();
        assert_eq!(
            out,
            hex!("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659")
        );
    }

    #[test]
    fn derive_key_is_deterministic_and_depends_on_inputs() {
        let params = KdfParams::FLOOR;
        let pw = SecretString::from("correct horse battery staple");
        let key = derive_key(&pw, &[1; SALT_LEN], &params).unwrap();
        assert_eq!(*key, *derive_key(&pw, &[1; SALT_LEN], &params).unwrap());
        assert_ne!(*key, *derive_key(&pw, &[2; SALT_LEN], &params).unwrap());
        let other = SecretString::from("correct horse battery stapler");
        assert_ne!(*key, *derive_key(&other, &[1; SALT_LEN], &params).unwrap());
    }

    #[test]
    fn params_outside_floor_and_ceiling_are_rejected() {
        let (lo, hi) = (KdfParams::FLOOR, KdfParams::CEILING);
        assert!(lo.validate().is_ok());
        assert!(hi.validate().is_ok());
        let out_of_range = [
            KdfParams {
                m_cost_kib: lo.m_cost_kib - 1,
                ..lo
            },
            KdfParams {
                t_cost: lo.t_cost - 1,
                ..lo
            },
            KdfParams {
                p_cost: lo.p_cost - 1,
                ..lo
            },
            KdfParams {
                m_cost_kib: hi.m_cost_kib + 1,
                ..hi
            },
            KdfParams {
                t_cost: hi.t_cost + 1,
                ..hi
            },
            KdfParams {
                p_cost: hi.p_cost + 1,
                ..hi
            },
        ];
        for params in out_of_range {
            assert!(
                matches!(params.validate(), Err(Error::ParamsOutOfRange)),
                "{params:?}"
            );
            let res = derive_key(&SecretString::from("pw"), &[0; SALT_LEN], &params);
            assert!(matches!(res, Err(Error::ParamsOutOfRange)), "{params:?}");
        }
    }

    /// Runs only without `insecure-test-kdf`: release builds must never default below the floor.
    #[cfg(not(feature = "insecure-test-kdf"))]
    #[test]
    fn production_default_meets_production_floor() {
        assert_eq!(KdfParams::default(), KdfParams::PRODUCTION);
        assert_eq!(KdfParams::FLOOR, KdfParams::PRODUCTION_FLOOR);
        assert!(KdfParams::default().validate().is_ok());
    }
}
