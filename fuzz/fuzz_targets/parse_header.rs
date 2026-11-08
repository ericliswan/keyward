//! Fuzzes `Header::parse`, the only code that reads attacker-controlled bytes
//! before the AEAD tag is checked.
//!
//! Run with `cargo +nightly fuzz run parse_header`.

#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use pwv_core::header::{HEADER_LEN, Header};

fuzz_target!(|data: &[u8]| {
    // Any input must give `Ok` or a typed error, never a panic.
    if let Ok((header, rest)) = Header::parse(data) {
        // Accepted input must round-trip exactly: no header byte is ignored or
        // normalised, so every byte the AAD covers is a byte the parser checked.
        assert_eq!(header.to_bytes(), data[..HEADER_LEN]);
        assert_eq!(rest, &data[HEADER_LEN..]);
    }
});
