# ADR 0001: XChaCha20-Poly1305 over AES-GCM

- Status: accepted
- Date: 2026-10-27

## Context

The vault needs an authenticated cipher (AEAD) that encrypts the whole vault and authenticates the header. The vault is re-encrypted with a new nonce on every save, for its whole life. The realistic choices are AES-256-GCM and XChaCha20-Poly1305.

## Decision

Use **XChaCha20-Poly1305** from the RustCrypto `chacha20poly1305` crate.

## Reasons

- **Safe random nonces.** XChaCha20 uses a 192-bit nonce, so picking a fresh random nonce on every save makes a repeat negligible, with no counter to store. AES-GCM's 96-bit nonce leaves a much smaller margin for random nonces, and a repeated nonce breaks GCM badly.
- **No hardware dependence.** ChaCha20 is fast and constant-time in software everywhere. AES-GCM is only fast and side-channel resistant with AES-NI or similar instructions.
- **Simple, well-reviewed code path.** One crate, one key size, no modes to configure.

## Consequences

- Not FIPS-approved, which does not matter for this project.
- The cipher is identified by `cipher_id = 1` in the header, so a different cipher could be added later as a new ID with a new ADR.
