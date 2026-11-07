## [0.5.0] - 2026-11-07

### Features

- *(cli)* Define commands and global flags with clap
- *(cli)* Map errors to exit codes
- *(cli)* Add hidden password prompt and --password-stdin
- *(cli)* Implement init with double prompt
- *(cli)* Refuse to overwrite without --force
- *(cli)* Reject weak master passwords using zxcvbn
- *(cli)* Add command prompts for every entry field
- *(cli)* List sites and usernames in a table
- *(cli)* Filter list with case-insensitive --search
- *(cli)* Print a password with get --show
- *(cli)* Refuse to print a password to a non-terminal without --force
- *(cli)* Edit one entry field at a time
- *(cli)* Delete an entry after confirmation
- *(storage)* Re-encrypt vault under a new master password
- *(cli)* Implement change-master
- *(gen)* Generate passwords from selected character classes
- *(gen)* Guarantee each class via rejection sampling
- *(gen)* Add eff wordlist passphrases
- *(gen)* Report estimated entropy
- *(cli)* Implement pwv gen
- *(cli)* Add --generate to pwv add
- *(crypto)* Add sha-256 fingerprint for clipboard comparison
- *(clipboard)* Copy passwords and clear after timeout if unchanged
- *(clipboard)* Clear immediately on ctrl-c
- *(clipboard)* Exclude from clipboard history where supported

### Documentation

- State the suitable effort level before every task
- Note that .bak keeps the old master password after a change
- Describe the password generator
- Describe clipboard clearing and its limits
- Ask agents to keep the local roadmap current
- Regenerate changelog with plain headings
- Require plain release notes without emojis
- List pwv-cli dependency versions in readme

### Refactoring

- *(cli)* Share new master password prompt with change-master

### Testing

- *(cli)* Help and version output
- *(cli)* Init creates a valid vault
- *(cli)* Add and list round-trip through the vault
- *(cli)* Get, edit and delete choose among matching entries
- *(cli)* Change-master needs the old password and only the new one opens
- *(gen)* Length, classes and chi-squared distribution
- *(cli)* Gen output and add --generate
- *(cli)* Full lifecycle never prints a secret unasked
- *(cli)* Wrong password exits 3 and leaves the vault unchanged
- *(cli)* Tampered, truncated and foreign files exit 3

### Maintenance

- Add git-ignored session handoff notes
- *(deps)* Add arboard and ctrlc for clipboard support
- Git-ignore the local roadmap

## [0.1.0] - 2026-10-27

### Features

- *(kdf)* Add KdfParams with default, floor and ceiling
- *(kdf)* Derive 256-bit key with argon2id
- *(header)* Define Header struct and constants
- *(header)* Encode header to 59 bytes
- *(header)* Parse header with strict validation
- *(crypto)* Seal plaintext with xchacha20-poly1305
- *(crypto)* Open ciphertext and map failures to generic error
- *(core)* Add redacting secret wrapper for passwords
- *(core)* Add Vault and Entry types with serde
- *(core)* Add find, insert, update and remove operations
- *(storage)* Resolve default vault path
- *(storage)* Create vault from master password
- *(storage)* Unlock vault with master password
- *(storage)* Keep previous file as .bak and set 0600 on unix

### Documentation

- Add DESIGN.md with goals and non-goals
- Specify vault file format v1
- Add threat model draft
- Add ADR 0001 choosing xchacha20-poly1305 over aes-gcm
- Add contributing guide, security policy and code of conduct
- Ask owner to raise effort level for demanding tasks
- Record benchmark results and chosen defaults
- Add development process note and dependency versions

### Performance

- *(kdf)* Add kdf timing example binary
- *(kdf)* Raise default memory cost to 256 mib

### Testing

- *(core)* Add placeholder test so ci has something to run
- *(kdf)* Add rfc 9106 known-answer test
- *(kdf)* Reject params outside floor and ceiling
- *(header)* Cover bad magic, version, ids, lengths and params
- *(crypto)* Add xchacha20-poly1305 known-answer test
- *(crypto)* Changing any header byte fails decryption
- *(core)* Debug output never contains password text
- *(storage)* Failure before rename leaves original intact
- *(core)* Flipping every byte of a small vault is rejected
- *(core)* Truncated, empty and extended files are rejected
- *(core)* Header downgrade of memory cost is rejected
- *(core)* Property test that random vaults round-trip
- *(core)* Two saves produce different nonces and ciphertexts
- *(core)* Wrong password fails and leaves file unchanged
- *(core)* Check the untampered vault unlocks before tampering

### Maintenance

- Add licences, gitignore and agent build plan
- Add cargo workspace with pwv-core and pwv-cli crates
- Add toolchain, rustfmt, clippy and editorconfig settings
- Add fmt, clippy and test workflow on three platforms
- Add issue forms and pull request template
- Add dependabot and codeowners
- Add cargo-deny job
- *(deps)* Allow mpl-2.0 for option-ext only
- *(deps)* Bump actions/checkout from 4 to 7
- Add git-cliff config grouping commits by type

