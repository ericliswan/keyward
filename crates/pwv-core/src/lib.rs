//! Core library for `pwv`: key derivation, vault format, encryption, storage and the
//! password generator.
#![forbid(unsafe_code)]

pub mod crypto;
pub mod error;
pub mod generator;
pub mod header;
pub mod kdf;
pub mod model;
pub mod storage;

pub use error::{Error, Result};
