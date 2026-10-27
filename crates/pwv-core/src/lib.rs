//! Core library for `pwv`: key derivation, vault format, encryption and storage.
#![forbid(unsafe_code)]

pub mod error;
pub mod header;
pub mod kdf;

pub use error::{Error, Result};
