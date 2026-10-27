# pwv threat model (draft)

This is a draft written before any code. The final version, with each claim linked to the test that proves it, lands before v1.0.

## Assets

- Entry passwords, usernames and notes.
- The master password.
- The derived 256-bit vault key.
- Metadata: which sites have entries, how many entries, when the vault changed.

## Adversaries and mitigations

| Adversary | Can do | Mitigation | Status |
| --- | --- | --- | --- |
| File thief | Copy the vault file and guess passwords offline | Argon2id with a memory-hard default (64 MiB, 3 passes) and a random salt per vault; master password must be at least 12 characters with zxcvbn score ≥ 3 | In scope |
| File tamperer | Change any byte of the vault | XChaCha20-Poly1305 authenticates the ciphertext and the whole header as AAD; any change fails with exit code 3 | In scope |
| Header downgrade | Lower the KDF parameters to speed up guessing, or raise them to exhaust memory | Parameters are authenticated, and checked against a floor and ceiling before Argon2 runs | In scope |
| Rollback | Replace the vault with an older valid copy | Not detectable without external state | Known limitation |
| Shoulder-surfer | Watch the screen | Hidden password prompts; `get` copies to the clipboard instead of printing; `--show` is opt-in | In scope |
| Clipboard reader | Read the clipboard or clipboard history | Clipboard cleared after 30 s if unchanged; excluded from history where the OS allows it | Partly mitigated |
| Metadata observer | See file size and modification time | None; size reveals roughly how much is stored | Known limitation |
| Local malware or keylogger | Run as the user while the vault is unlocked | None | Out of scope |
| Root or OS compromise | Read memory, swap or the terminal | None | Out of scope |

## In scope

- Confidentiality and integrity of the vault file at rest.
- Not leaking secrets through arguments, environment variables, logs, errors or crash output.
- Clearing secrets from memory where Rust lets us (`zeroize`, `secrecy`).

## Out of scope

- A compromised machine, user account or terminal.
- Side channels such as timing and power analysis of the underlying crates.
- Weak master passwords that pass the strength check.
- Backups of the vault the user makes themselves.

## Assumptions

- The OS random number generator is sound.
- The RustCrypto `argon2` and `chacha20poly1305` crates are implemented correctly.
- The user picks a strong master password and keeps it secret.
- The machine is not compromised while the vault is unlocked.

## Known limitations

- Rollback to an older valid vault is undetectable.
- Clipboard history and clipboard managers may keep copies.
- Copies of secrets made by `serde_json`, the terminal, the clipboard or the OS cannot all be wiped.
- File size and modification time are visible.
