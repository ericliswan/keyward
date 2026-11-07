//! Command-line definitions. Secrets are never accepted as arguments; they are always prompted for.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

/// Local, encrypted password manager.
#[derive(Debug, Parser)]
#[command(name = "pwv", version)]
pub struct Cli {
    /// Vault file. Defaults to `vault.pwv` in the OS data directory.
    #[arg(long, global = true, env = "PWV_VAULT", value_name = "PATH")]
    pub vault: Option<PathBuf>,

    /// Read the master password, and every other answer, from stdin, one line each, instead
    /// of prompting. For automation and tests only.
    #[arg(long, global = true)]
    pub password_stdin: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Create a new, empty vault.
    Init {
        /// Replace an existing vault. The old file is kept as `<vault>.bak`.
        #[arg(long)]
        force: bool,
    },
    /// Add an entry; prompts for username, password and notes.
    Add {
        /// Site or service name.
        site: String,
        /// Store a generated password instead of prompting for one. Takes the same options as
        /// `pwv gen`.
        #[arg(long)]
        generate: bool,
        #[command(flatten)]
        gen_args: GenArgs,
    },
    /// Copy an entry's password to the clipboard.
    Get {
        /// Site or service name.
        site: String,
        /// Also print the password to stdout.
        #[arg(long)]
        show: bool,
        /// With --show, print even when stdout is not a terminal (a pipe or a file).
        #[arg(long, requires = "show")]
        force: bool,
        /// Seconds until the clipboard is cleared, if it still holds the password.
        #[arg(
            long,
            value_name = "SECONDS",
            default_value_t = 30,
            value_parser = clap::value_parser!(u64).range(1..),
        )]
        timeout: u64,
        /// With --show, only print; leave the clipboard alone.
        #[arg(long, requires = "show", conflicts_with = "timeout")]
        no_clipboard: bool,
    },
    /// List sites and usernames, never passwords.
    List {
        /// Only entries whose site or username contains TEXT, ignoring case.
        #[arg(long, value_name = "TEXT")]
        search: Option<String>,
    },
    /// Change one field of an entry.
    Edit {
        /// Site or service name.
        site: String,
        #[command(flatten)]
        field: Field,
    },
    /// Remove an entry.
    Delete {
        /// Site or service name.
        site: String,
        /// Delete without asking for confirmation.
        #[arg(long)]
        yes: bool,
    },
    /// Change the master password and re-encrypt the vault with a new salt.
    ChangeMaster,
    /// Print a generated password to stdout and its estimated entropy to stderr.
    Gen(#[command(flatten)] GenArgs),
}

/// Generator options, shared by `pwv gen` and `pwv add --generate`.
#[derive(Debug, Default, PartialEq, Eq, Args)]
pub struct GenArgs {
    /// Password length, 8 to 256 [default: 20].
    #[arg(long, value_name = "N")]
    pub length: Option<usize>,
    /// Leave out lowercase letters.
    #[arg(long)]
    pub no_lower: bool,
    /// Leave out uppercase letters.
    #[arg(long)]
    pub no_upper: bool,
    /// Leave out digits.
    #[arg(long)]
    pub no_digits: bool,
    /// Leave out symbols.
    #[arg(long)]
    pub no_symbols: bool,
    /// Leave out look-alike characters: 0 O 1 l I.
    #[arg(long)]
    pub no_ambiguous: bool,
    /// Generate a passphrase of WORDS words (4 to 64) from the EFF wordlist instead.
    #[arg(
        long,
        value_name = "WORDS",
        conflicts_with_all = ["length", "no_lower", "no_upper", "no_digits", "no_symbols", "no_ambiguous"],
    )]
    pub passphrase: Option<usize>,
}

/// The entry field `pwv edit` changes; exactly one per run.
#[derive(Debug, Args)]
#[group(required = true, multiple = false)]
pub struct Field {
    /// Prompt for a new username.
    #[arg(long)]
    pub username: bool,
    /// Prompt for a new password (hidden).
    #[arg(long)]
    pub password: bool,
    /// Prompt for new notes (hidden).
    #[arg(long)]
    pub notes: bool,
}
