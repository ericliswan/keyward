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

## Vault file format v1

All integers are little-endian.

| Offset | Size | Field | Value |
| --- | --- | --- | --- |
| 0 | 4 | `magic` | `b"PWVF"` |
| 4 | 1 | `format_version` | `1` |
| 5 | 1 | `kdf_id` | `1` = Argon2id v0x13 |
| 6 | 4 | `m_cost_kib` | u32 |
| 10 | 4 | `t_cost` | u32 |
| 14 | 4 | `p_cost` | u32 |
| 18 | 16 | `salt` | random |
| 34 | 1 | `cipher_id` | `1` = XChaCha20-Poly1305 |
| 35 | 24 | `nonce` | random, fresh on **every** save |
| 59 | n + 16 | `ciphertext ‖ tag` | AEAD output |

- `HEADER_LEN = 59`. The associated data (AAD) is bytes `[0..59)`, the entire header. Changing any header byte, including the KDF parameters, makes decryption fail, so an attacker cannot downgrade the parameters without detection.
- The key is Argon2id(master password, salt, parameters from the header), 32 bytes.
- The plaintext is the UTF-8 JSON of the vault:

  ```json
  {"schema_version":1,"entries":[{"id":"<uuid v4>","site":"","username":"","password":"","notes":"","created_at":"<RFC 3339>","updated_at":"<RFC 3339>"}]}
  ```

- The **salt** changes only on `init` and `change-master`. The **nonce** is generated with the OS random number generator on every save; 24 random bytes make a repeat negligible.
- Saving writes a temporary file in the same directory and renames it over the vault, so a crash never leaves a half-written vault. The previous version is kept as `<vault>.bak`.
- Any change to this layout bumps `format_version` and needs a new ADR.

### Parsing order

1. Check the length is at least `HEADER_LEN + 16`, the magic, `format_version`, `kdf_id` and `cipher_id`. Fail with `Format` or `UnsupportedVersion`.
2. Check the KDF parameters against the floor and ceiling below **before** running Argon2. Fail with `ParamsOutOfRange`.
3. Derive the key, then decrypt with the header as AAD. Any failure is `Decrypt`.

## KDF parameters

| Profile | m_cost | t_cost | p_cost | Notes |
| --- | --- | --- | --- | --- |
| Default (production) | 262 144 KiB (256 MiB) | 3 | 4 | About 0.6 s unlock on an Apple M1; see the calibration below and ADR 0002 |
| Floor (reject below) | 19 456 KiB | 2 | 1 | OWASP minimum |
| Ceiling (reject above) | 4 194 304 KiB (4 GiB) | 10 | 16 | Stops a malicious header from exhausting memory or time |
| Test-only | 8 KiB-scale values | 1 | 1 | Only with the cargo feature `insecure-test-kdf`, never on by default |

The values used are always the values written to the header, so a vault created with one default still opens after the default changes.

### Calibration

The target is an unlock of 0.5–1 s. `cargo run --release --example kdf_bench` times `derive_key` for several profiles. Results on the owner's laptop (Apple M1, 8 GiB RAM, rustc 1.99.1, `argon2` 0.6.0), fastest and slowest of 3 runs:

| Profile | m_cost | t_cost | p_cost | Time |
| --- | --- | --- | --- | --- |
| Floor (OWASP) | 19 MiB | 2 | 1 | 24–25 ms |
| RFC 9106 second option | 64 MiB | 3 | 4 | 142–201 ms |
| RFC 9106 second option, one lane | 64 MiB | 3 | 1 | 133–136 ms |
| | 128 MiB | 3 | 4 | 283–315 ms |
| **Default** | 256 MiB | 3 | 4 | 582–633 ms |
| | 512 MiB | 2 | 4 | 808–1 065 ms |

- The `argon2` crate's `parallel` feature is off, so the four lanes run one after another and four lanes take about as long as one.
- RFC 9106's first option (2 GiB, t = 1) is below the floor's `t_cost` of 2 and is not offered.

[ADR 0002](decisions/0002-kdf-default-parameters.md) records why 256 MiB was chosen.

## Error policy

`pwv-core::Error` has these variants: `Format` (bad magic or length), `UnsupportedVersion`, `ParamsOutOfRange`, `Decrypt`, `Io` and `Serde`.

- `Decrypt` always reads **"wrong password or corrupted vault"**. The two cases are never distinguished, so the tool gives no oracle about which one happened.
- No error message, `Debug` output or panic includes secret material: passwords, keys or plaintext.
- CLI exit codes: `0` success, `1` general or user error, `2` usage error, `3` authentication or integrity failure.
  Every `pwv-core` error except `Io` exits with `3`: a vault that cannot be parsed, has out-of-range parameters or fails authentication is treated as an integrity failure. A missing or unreadable file exits with `1`.
