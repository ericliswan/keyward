//! Command-line definitions. Secrets are never accepted as arguments; they are always prompted for.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

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
    },
    /// List sites and usernames, never passwords.
    List,
    /// Change one field of an entry.
    Edit {
        /// Site or service name.
        site: String,
    },
    /// Remove an entry.
    Delete {
        /// Site or service name.
        site: String,
    },
    /// Change the master password and re-encrypt the vault with a new salt.
    ChangeMaster,
    /// Print a generated password.
    Gen,
}
