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
    },
    /// Copy an entry's password to the clipboard.
    Get {
        /// Site or service name.
        site: String,
        /// Print the password to stdout instead.
        #[arg(long)]
        show: bool,
        /// With --show, print even when stdout is not a terminal (a pipe or a file).
        #[arg(long, requires = "show")]
        force: bool,
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
    /// Print a generated password.
    Gen,
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
