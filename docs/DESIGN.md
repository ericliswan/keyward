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
| Default (production) | 65 536 KiB (64 MiB) | 3 | 4 | RFC 9106 second recommended option; calibrated on real hardware in a later PR |
| Floor (reject below) | 19 456 KiB | 2 | 1 | OWASP minimum |
| Ceiling (reject above) | 4 194 304 KiB (4 GiB) | 10 | 16 | Stops a malicious header from exhausting memory or time |
| Test-only | 8 KiB-scale values | 1 | 1 | Only with the cargo feature `insecure-test-kdf`, never on by default |

The values used are always the values written to the header, so a vault created with one default still opens after the default changes.

## Error policy

`pwv-core::Error` has these variants: `Format` (bad magic or length), `UnsupportedVersion`, `ParamsOutOfRange`, `Decrypt`, `Io` and `Serde`.

- `Decrypt` always reads **"wrong password or corrupted vault"**. The two cases are never distinguished, so the tool gives no oracle about which one happened.
- No error message, `Debug` output or panic includes secret material: passwords, keys or plaintext.
- CLI exit codes: `0` success, `1` general or user error, `2` usage error, `3` authentication or integrity failure.
