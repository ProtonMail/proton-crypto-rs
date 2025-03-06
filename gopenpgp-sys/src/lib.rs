//! This module implements Rust bindings for [GopenPGP](https://github.com/ProtonMail/gopenpgp).
//!
//! # Building
//! In order to build this library you need to have go v1.22 or higher installed on your system.
//!
//! # Safety
//! This library needs unsafe to access the C interface exposed by the go library
//!

extern crate core;

mod keys;
pub use keys::*;

mod verification;
pub use verification::*;

mod signing;
pub use signing::*;

mod decryption;
pub use decryption::*;

mod encryption;
pub use encryption::*;

mod constants;
pub use constants::*;

pub mod armor;

mod go;
pub use crate::go::OwnedCStr;
pub use crate::go::PGPBytes;
pub use crate::go::PGPError;
pub use crate::go::PGPSlice;
pub use crate::go::SecretBytes;
pub use crate::go::SecretGoBytes;
use crate::go::*;

mod ext_buffer;
mod streaming;
