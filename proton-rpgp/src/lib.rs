// Allow dead code for now.
// TODO: Remove this once we have a proper API.
#![allow(dead_code)]

mod decrypt;
mod encrypt;
mod errors;
mod key;
mod profile;
mod sign;
mod signature;
mod types;
mod verify;

pub mod armor;

/// Re-export the `pgp` crate.
pub use pgp;

pub use decrypt::*;
pub use encrypt::*;
pub use errors::*;
pub use key::*;
pub use profile::*;
pub use sign::*;
pub use signature::*;
pub use types::*;
pub use verify::*;
