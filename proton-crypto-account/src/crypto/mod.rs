//! Provides cryptography utilities for account logic.
mod key_import;
pub use key_import::*;
mod key_export;
pub use key_export::*;

pub(super) const TOKEN_SIZE: usize = 32;
pub(super) const EXPECTED_ENCRYPTED_TOKEN_SIZE: usize = 380;
