//! This crate implements low-level cryptographic tools beyond `OpenPGP`.
//!
//! Tools:
//! - [`aead`] module: AEAD AES-GCM-256 encryption and decryption in the.

mod errors;
pub use errors::*;

pub mod aead;
pub mod hkdf;
