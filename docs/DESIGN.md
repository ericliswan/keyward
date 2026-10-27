# pwv design

`pwv` is a local-only command-line password manager. This document records what it does, what it deliberately does not do, and exactly how a vault is stored.

## Goals

- Keep a list of site credentials in one encrypted file that only the master password can open.
- Detect any change to the file: a wrong password and a modified file are both refused.
- Use only vetted primitives (Argon2id, XChaCha20-Poly1305, the OS random number generator) through well-reviewed Rust crates.
- Keep secrets out of arguments, environment variables, logs, `Debug` output and error messages, and wipe them from memory where the language allows.
- Be small enough to read and explain end to end.

## Non-goals

- Sync, cloud storage or any network access (the only exception is the opt-in `audit` command planned for v1.x).
- Sharing vaults between users, or multiple master passwords.
- Browser integration or autofill.
- Protection against malware or an administrator on the same machine while the vault is unlocked.
- Hiding that a file is a `pwv` vault, or hiding its approximate size.
