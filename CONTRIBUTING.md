# Contributing

## Setup

Install Rust with [rustup](https://rustup.rs) (the toolchain is pinned by `rust-toolchain.toml`) and `cargo-deny`:

```sh
cargo install --locked cargo-deny
```

## Before pushing

```sh
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo deny check
```

CI runs the same checks on Linux, macOS and Windows. Never disable a check to get green.

## Fuzzing

`fuzz/` holds a [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) target for the vault header parser. It needs the nightly toolchain and is its own workspace, so the commands above never build it:

```sh
rustup toolchain install nightly
cargo install --locked cargo-fuzz
cargo +nightly fuzz run parse_header -- -max_total_time=60
```

CI runs the same 60-second fuzz on pull requests that change `header.rs`, `kdf.rs` or `fuzz/`. If it finds a crash, the failing input is in `fuzz/artifacts/parse_header/`. Reproduce it with `cargo +nightly fuzz run parse_header <file>`, then add a regression test in `header.rs` before fixing the bug.

## Workflow

- One issue, one branch, one pull request. Open the issue first.
- Branch names: `<type>/<short-kebab-description>`, e.g. `feat/core-kdf`, `fix/header-length-check`.
- Commits follow [Conventional Commits](https://www.conventionalcommits.org): `<type>(<scope>): <imperative summary>`, at most 72 characters, lowercase after the colon, no trailing period. Reference the issue in the footer (`Refs #N`).
  - Types: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `ci`, `build`, `chore`, `security`.
  - Scopes: `core`, `kdf`, `crypto`, `header`, `storage`, `gen`, `cli`, `clipboard`, `ci`, `deps`, `docs`, `release`.
- Each commit compiles and passes tests. Squash "wip" commits before merge.

## Pull requests

- Title in Conventional Commit form; body follows the template and includes `Closes #N`.
- Keep PRs under about 400 changed lines (excluding lockfiles).
- Every bug fix needs a regression test.
- Merged with rebase-and-merge once CI is green.

## Security rules

- No custom cryptography. Crypto crates are called only from `pwv-core::kdf` and `pwv-core::crypto`.
- No secrets in arguments, environment variables, logs, `Debug` output, errors or test snapshots.
- Never commit real passwords or vaults; tests create vaults in temporary directories.
