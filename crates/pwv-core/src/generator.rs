//! Random passwords and passphrases from the OS random number generator.
//!
//! Every character or word is picked with [`IndexedRandom::choose`], which draws a uniform index
//! without modulo bias.
//!
//! Passphrases use the EFF large wordlist (7776 words, CC BY 3.0 US), stored verbatim in
//! `src/wordlist/eff_large.txt` (SHA-256
//! `addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e`).

use std::sync::LazyLock;

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
/// Fewest words [`passphrase`] will generate.
pub const MIN_WORDS: usize = 4;
/// Most words [`passphrase`] will generate.
pub const MAX_WORDS: usize = 64;
/// Separator between passphrase words.
pub const WORD_SEPARATOR: char = '-';

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
    /// The passphrase word count is outside [`MIN_WORDS`]..=[`MAX_WORDS`].
    #[error("passphrase must have between {MIN_WORDS} and {MAX_WORDS} words")]
    Words,
}

/// The EFF large wordlist: one `NNNNN<TAB>word` line per word.
static WORDS: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    include_str!("wordlist/eff_large.txt")
        .lines()
        .filter_map(|line| line.split_once('\t').map(|(_, word)| word))
        .collect()
});

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

    /// Entropy in bits of a password from [`password`] with these options.
    ///
    /// Exact for a uniform choice among all passwords that contain every enabled class, which is
    /// what rejection sampling produces.
    ///
    /// # Errors
    /// [`GenError`] if the options are out of range.
    pub fn entropy_bits(&self) -> Result<f64, GenError> {
        let sizes: Vec<usize> = self.classes()?.iter().map(Vec::len).collect();
        Ok(class_entropy_bits(&sizes, self.length))
    }
}

/// `log2` of the number of `length`-character strings over the union of disjoint classes with
/// these sizes that contain every class at least once.
///
/// Inclusion–exclusion: `count = Σ over subsets S of (−1)^|S| · (A − |S's characters|)^length`.
/// Factoring out `A^length` keeps the terms in `[0, 1]` so nothing overflows at length 256.
fn class_entropy_bits(sizes: &[usize], length: usize) -> f64 {
    let alphabet: usize = sizes.iter().sum();
    let a = alphabet as f64;
    let len = i32::try_from(length).unwrap_or(i32::MAX);
    let mut fraction = 0.0;
    for mask in 0..(1u32 << sizes.len()) {
        let missing: usize = (0..sizes.len())
            .filter(|i| mask & (1 << i) != 0)
            .map(|i| sizes[i])
            .sum();
        let term = ((alphabet - missing) as f64 / a).powi(len);
        fraction += if mask.count_ones() % 2 == 0 {
            term
        } else {
            -term
        };
    }
    length as f64 * a.log2() + fraction.log2()
}

/// Entropy in bits of a passphrase from [`passphrase`] with this many words.
///
/// # Errors
/// [`GenError::Words`] if `words` is out of range.
pub fn passphrase_entropy_bits(words: usize) -> Result<f64, GenError> {
    if !(MIN_WORDS..=MAX_WORDS).contains(&words) {
        return Err(GenError::Words);
    }
    Ok(words as f64 * (WORDS.len() as f64).log2())
}

/// A random password drawn from the OS random number generator, containing at least one
/// character from every enabled class.
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
    let classes = options.classes()?;
    let alphabet = classes.concat();
    // ASCII only, so `length` bytes never reallocate and leave an unwiped copy behind.
    let mut out = Zeroizing::new(String::with_capacity(options.length));
    // Rejection sampling: redraw the whole password until every enabled class appears. Patching
    // in a missing class at a chosen position would make the positions non-uniform.
    loop {
        out.clear();
        for _ in 0..options.length {
            let &b = alphabet.choose(rng).ok_or(GenError::NoClasses)?;
            out.push(char::from(b));
        }
        if classes
            .iter()
            .all(|class| out.bytes().any(|b| class.contains(&b)))
        {
            return Ok(SecretText::from(std::mem::take(&mut *out)));
        }
    }
}

/// A passphrase of `words` random words from the EFF large wordlist, joined with
/// [`WORD_SEPARATOR`].
///
/// Four words in the list (`drop-down`, `felt-tip`, `t-shirt`, `yo-yo`) contain the separator, so
/// a few passphrases can be read more than one way. The entropy this costs is negligible.
///
/// # Errors
/// [`GenError::Words`] if `words` is out of range.
///
/// # Panics
/// If the operating system's random number generator fails.
pub fn passphrase(words: usize) -> Result<SecretText, GenError> {
    passphrase_with(&mut UnwrapErr(SysRng), words)
}

fn passphrase_with<R: Rng + ?Sized>(rng: &mut R, words: usize) -> Result<SecretText, GenError> {
    if !(MIN_WORDS..=MAX_WORDS).contains(&words) {
        return Err(GenError::Words);
    }
    let mut out = Zeroizing::new(String::with_capacity(words * 10));
    for i in 0..words {
        if i > 0 {
            out.push(WORD_SEPARATOR);
        }
        out.push_str(WORDS.choose(rng).ok_or(GenError::Words)?);
    }
    Ok(SecretText::from(std::mem::take(&mut *out)))
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    use super::*;

    #[test]
    fn default_is_twenty_characters_from_every_class() {
        let pw = password(&PasswordOptions::default()).unwrap();
        assert_eq!(pw.expose().len(), DEFAULT_LENGTH);
        assert!(pw.expose().bytes().all(|b| b.is_ascii_graphic()));
    }

    #[test]
    fn every_enabled_class_appears_even_at_minimum_length() {
        let o = PasswordOptions {
            length: MIN_LENGTH,
            ..PasswordOptions::default()
        };
        let classes = o.classes().unwrap();
        for _ in 0..1000 {
            let pw = password(&o).unwrap();
            for class in &classes {
                assert!(pw.expose().bytes().any(|b| class.contains(&b)));
            }
        }
    }

    #[test]
    fn wordlist_has_7776_unique_lowercase_words() {
        assert_eq!(WORDS.len(), 7776);
        let unique: std::collections::HashSet<_> = WORDS.iter().collect();
        assert_eq!(unique.len(), 7776);
        assert!(
            WORDS
                .iter()
                .all(|w| !w.is_empty() && w.bytes().all(|b| b.is_ascii_lowercase() || b == b'-'))
        );
    }

    #[test]
    fn passphrase_has_the_requested_words() {
        // Split list words on the separator too, since four of them contain it.
        let parts: std::collections::HashSet<&str> =
            WORDS.iter().flat_map(|w| w.split(WORD_SEPARATOR)).collect();
        for _ in 0..100 {
            let p = passphrase(6).unwrap();
            let split: Vec<&str> = p.expose().split(WORD_SEPARATOR).collect();
            assert!((6..=12).contains(&split.len()));
            assert!(split.iter().all(|part| parts.contains(part)));
        }
        for words in [0, MIN_WORDS - 1, MAX_WORDS + 1] {
            assert_eq!(passphrase(words).unwrap_err(), GenError::Words);
        }
    }

    #[test]
    fn class_entropy_matches_brute_force() {
        // Classes {a} and {b, c}, length 3: 27 strings, minus 8 without `a`, minus 1 without
        // `b`/`c`, leaves 18.
        assert!((class_entropy_bits(&[1, 2], 3) - 18f64.log2()).abs() < 1e-12);
        // One class: no constraint, so plain `length · log2(size)`.
        assert!((class_entropy_bits(&[26], 20) - 20.0 * 26f64.log2()).abs() < 1e-9);
    }

    #[test]
    fn entropy_of_the_defaults() {
        let bits = PasswordOptions::default().entropy_bits().unwrap();
        // Slightly below 20 · log2(94) ≈ 131.1 because every class must appear.
        assert!(bits > 130.0 && bits < 20.0 * 94f64.log2(), "{bits}");
        let words = passphrase_entropy_bits(6).unwrap();
        assert!((words - 6.0 * 7776f64.log2()).abs() < 1e-9);
        assert_eq!(passphrase_entropy_bits(3).unwrap_err(), GenError::Words);
    }

    /// Pearson's chi-squared test that every character of the full 94-character alphabet is
    /// equally likely, over 4000 × 256 = 1 024 000 characters.
    ///
    /// The seeded RNG makes the test deterministic; it checks the selection logic, not the OS
    /// RNG. At length 256 the every-class requirement rejects almost nothing, so its bias is far
    /// below what the test can see.
    #[test]
    fn characters_are_uniformly_distributed() {
        // Chi-squared critical value for 93 degrees of freedom at p = 0.001.
        const CRITICAL: f64 = 140.893_134_273_230_74;
        let options = PasswordOptions {
            length: MAX_LENGTH,
            ..PasswordOptions::default()
        };
        let alphabet = options.classes().unwrap().concat();
        assert_eq!(alphabet.len(), 94);

        let mut rng = StdRng::seed_from_u64(0x7077_765f_6765_6e00);
        let mut counts = [0u64; 128];
        let rounds = 4000;
        for _ in 0..rounds {
            for b in password_with(&mut rng, &options).unwrap().expose().bytes() {
                counts[usize::from(b)] += 1;
            }
        }
        let total = (rounds * MAX_LENGTH) as f64;
        let expected = total / alphabet.len() as f64;
        let chi2: f64 = alphabet
            .iter()
            .map(|&b| (counts[usize::from(b)] as f64 - expected).powi(2) / expected)
            .sum();
        assert_eq!(counts.iter().sum::<u64>() as f64, total);
        assert!(chi2 < CRITICAL, "chi-squared {chi2} >= {CRITICAL}");
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
