// Allow dead code for now.
// TODO: Remove this once we have a proper API.
#![allow(dead_code)]
// mod decryption;
// mod encryption;
mod errors;
mod key;
mod profile;
mod signature;
mod types;
mod verify;

pub mod armor;

/// Re-export the `pgp` crate.
pub use pgp;

// pub use decryption::*;
// pub use encryption::*;
pub use errors::*;
pub use key::*;
pub use profile::*;
pub use signature::*;
pub use types::*;
pub use verify::*;
