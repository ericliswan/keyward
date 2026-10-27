//! Argon2id key derivation.

use crate::error::{Error, Result};

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
