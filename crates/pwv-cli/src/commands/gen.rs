//! `pwv gen`: print a generated password.

use anyhow::Result;
use pwv_core::generator::{self, DEFAULT_LENGTH, PasswordOptions};
use pwv_core::model::SecretText;

use crate::cli::GenArgs;

/// Prints the password alone on stdout, so it can be piped, and the entropy on stderr.
pub fn run(args: &GenArgs) -> Result<()> {
    let (password, bits) = generate(args)?;
    println!("{}", password.expose());
    eprintln!("Estimated entropy: {bits:.0} bits");
    Ok(())
}

/// A generated password or passphrase and its estimated entropy in bits.
pub(super) fn generate(args: &GenArgs) -> Result<(SecretText, f64)> {
    if let Some(words) = args.passphrase {
        return Ok((
            generator::passphrase(words)?,
            generator::passphrase_entropy_bits(words)?,
        ));
    }
    let options = options(args);
    Ok((generator::password(&options)?, options.entropy_bits()?))
}

fn options(args: &GenArgs) -> PasswordOptions {
    PasswordOptions {
        length: args.length.unwrap_or(DEFAULT_LENGTH),
        lower: !args.no_lower,
        upper: !args.no_upper,
        digits: !args.no_digits,
        symbols: !args.no_symbols,
        avoid_ambiguous: args.no_ambiguous,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_flags_means_the_core_defaults() {
        assert_eq!(options(&GenArgs::default()), PasswordOptions::default());
    }

    #[test]
    fn flags_switch_classes_off() {
        let args = GenArgs {
            length: Some(32),
            no_lower: true,
            no_symbols: true,
            no_ambiguous: true,
            ..GenArgs::default()
        };
        let o = options(&args);
        assert_eq!(o.length, 32);
        assert!(!o.lower && o.upper && o.digits && !o.symbols && o.avoid_ambiguous);
    }
}
