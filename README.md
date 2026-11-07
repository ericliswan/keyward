# keyward
Local CLI password manager in Rust. Argon2id + XChaCha20-Poly1305, tamper-evident vault, documented threat model.

> Work in progress. The command-line tool is called `pwv`.
>
> ⚠️ Educational project, not independently audited.

## Status

v0.1 is the crypto core: the `pwv-core` library derives the key, encrypts the vault and stores it. The `pwv` command-line tool arrives in v0.5. See [DESIGN.md](docs/DESIGN.md) for the file format and [THREAT_MODEL.md](docs/THREAT_MODEL.md) for what it protects against.

## Dependencies

Direct dependencies of `pwv-core`, as locked in `Cargo.lock`:

| Crate | Version | Used for |
| --- | --- | --- |
| `argon2` | 0.6.0 | Argon2id key derivation |
| `chacha20poly1305` | 0.11.0 | XChaCha20-Poly1305 encryption |
| `rand` | 0.10.3 | OS random number generator, password generator |
| `secrecy` | 0.10.3 | Master password handling |
| `zeroize` | 1.9.1 | Wiping keys and plaintext from memory |
| `serde` / `serde_json` | 1.0.229 / 1.0.154 | Vault serialisation |
| `uuid` | 1.29.0 | Entry IDs |
| `time` | 0.3.55 | Entry timestamps |
| `thiserror` | 2.0.21 | Error type |
| `directories` | 6.0.0 | Default vault path |
| `sha2` | 0.11.1 | Clipboard fingerprint (SHA-256) |
| `tempfile` | 3.27.0 | Atomic saves |

Tests also use `proptest` 1.12.0 and `hex-literal` 1.1.0.

Direct dependencies of `pwv-cli` (the `pwv` binary), besides `pwv-core`:

| Crate | Version | Used for |
| --- | --- | --- |
| `clap` | 4.6.7 | Command-line parsing |
| `rpassword` | 7.5.4 | Hidden password prompts |
| `zxcvbn` | 3.1.1 | Master-password strength check |
| `arboard` | 3.7.0 | Clipboard access |
| `ctrlc` | 3.5.2 | Clearing the clipboard on Ctrl-C |
| `secrecy` / `zeroize` | 0.10.3 / 1.9.1 | Secret handling |
| `time` | 0.3.55 | Entry timestamps |
| `anyhow` | 1.0.104 | Error reporting |

CLI tests also use `assert_cmd` 2.2.2, `predicates` 3.1.4 and `tempfile` 3.27.0.

## Development process

This project is built with AI-agent assistance (Claude Code) under the owner's design and review. The agent follows a written build plan ([AGENTS.md](AGENTS.md)): one issue, branch and pull request per change, with CI and a self-review on every pull request. The owner approves the design, the file format, the cryptographic choices and the KDF parameters at checkpoints before that work is merged.

## Acknowledgements

Passphrases use the [EFF large wordlist](https://www.eff.org/dice) by the Electronic Frontier Foundation, licensed under [CC BY 3.0 US](https://creativecommons.org/licenses/by/3.0/us/). It is included unmodified in `crates/pwv-core/src/wordlist/eff_large.txt`.

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at your option.
