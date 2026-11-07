//! Random passwords and passphrases from the OS random number generator.
//!
//! Every character or word is picked with [`IndexedRandom::choose`], which draws a uniform index
//! without modulo bias.

use rand::Rng;
use rand::rand_core::UnwrapErr;
use rand::rngs::SysRng;
use rand::seq::IndexedRandom;
use zeroize::Zeroizing;

use crate::model::SecretText;

/// Password length when none is given.
pub const DEFAULT_LENGTH: usize = 20;
/// Shortest password [`password`] will generate.
pub const MIN_LENGTH: usize = 8;
/// Longest password [`password`] will generate.
pub const MAX_LENGTH: usize = 256;
/// Characters removed by [`PasswordOptions::avoid_ambiguous`]: `0 O 1 l I`.
pub const AMBIGUOUS: &str = "0O1lI";

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
/// All 32 printable ASCII punctuation characters.
const SYMBOLS: &str = r##"!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~"##;

/// Why a generator request was refused. Never contains generated material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum GenError {
    /// The password length is outside [`MIN_LENGTH`]..=[`MAX_LENGTH`].
    #[error("password length must be between {MIN_LENGTH} and {MAX_LENGTH}")]
    Length,
    /// Every character class was switched off.
    #[error("at least one character class must be enabled")]
    NoClasses,
}

/// What [`password`] generates. The default is 20 characters from all four classes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordOptions {
    /// Number of characters.
    pub length: usize,
    /// Include `a-z`.
    pub lower: bool,
    /// Include `A-Z`.
    pub upper: bool,
    /// Include `0-9`.
    pub digits: bool,
    /// Include ASCII punctuation.
    pub symbols: bool,
    /// Leave out the characters in [`AMBIGUOUS`].
    pub avoid_ambiguous: bool,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        Self {
            length: DEFAULT_LENGTH,
            lower: true,
            upper: true,
            digits: true,
            symbols: true,
            avoid_ambiguous: false,
        }
    }
}

impl PasswordOptions {
    /// The enabled character classes after removing ambiguous characters.
    fn classes(&self) -> Result<Vec<Vec<u8>>, GenError> {
        if !(MIN_LENGTH..=MAX_LENGTH).contains(&self.length) {
            return Err(GenError::Length);
        }
        let classes: Vec<Vec<u8>> = [
            (self.lower, LOWER),
            (self.upper, UPPER),
            (self.digits, DIGITS),
            (self.symbols, SYMBOLS),
        ]
        .into_iter()
        .filter(|(on, _)| *on)
        .map(|(_, set)| {
            set.bytes()
                .filter(|b| !(self.avoid_ambiguous && AMBIGUOUS.as_bytes().contains(b)))
                .collect()
        })
        .collect();
        if classes.is_empty() {
            return Err(GenError::NoClasses);
        }
        Ok(classes)
    }
}

/// A random password drawn from the OS random number generator.
///
/// # Errors
/// [`GenError`] if the options are out of range.
///
/// # Panics
/// If the operating system's random number generator fails.
pub fn password(options: &PasswordOptions) -> Result<SecretText, GenError> {
    password_with(&mut UnwrapErr(SysRng), options)
}

/// [`password`] with the random number generator passed in, so tests can seed it.
fn password_with<R: Rng + ?Sized>(
    rng: &mut R,
    options: &PasswordOptions,
) -> Result<SecretText, GenError> {
    let alphabet = options.classes()?.concat();
    // ASCII only, so `length` bytes never reallocate and leave an unwiped copy behind.
    let mut out = Zeroizing::new(String::with_capacity(options.length));
    for _ in 0..options.length {
        let &b = alphabet.choose(rng).ok_or(GenError::NoClasses)?;
        out.push(char::from(b));
    }
    Ok(SecretText::from(std::mem::take(&mut *out)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_twenty_characters_from_every_class() {
        let pw = password(&PasswordOptions::default()).unwrap();
        assert_eq!(pw.expose().len(), DEFAULT_LENGTH);
        assert!(pw.expose().bytes().all(|b| b.is_ascii_graphic()));
    }

    #[test]
    fn symbols_are_all_ascii_punctuation() {
        assert_eq!(SYMBOLS.len(), 32);
        assert!(SYMBOLS.bytes().all(|b| b.is_ascii_punctuation()));
    }

    #[test]
    fn out_of_range_options_are_refused() {
        for length in [0, MIN_LENGTH - 1, MAX_LENGTH + 1] {
            let o = PasswordOptions {
                length,
                ..PasswordOptions::default()
            };
            assert_eq!(password(&o).unwrap_err(), GenError::Length);
        }
        let none = PasswordOptions {
            lower: false,
            upper: false,
            digits: false,
            symbols: false,
            ..PasswordOptions::default()
        };
        assert_eq!(password(&none).unwrap_err(), GenError::NoClasses);
    }
}
