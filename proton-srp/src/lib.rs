//! Implementation of Proton's SRP protocol for client side authentication.
//! Note that this is a Proton specific implementation and would have to be
//! adapted in a generic scenario.
//! Use the `proton-crypto` crate whenever possible to instantiate
//! the Proton SRP protocol.
//!
//! ## Feature flags
//! - `pgpinternal`: Enabled by default and triggers internal SRP modulus verification based on rPGP.
mod errors;
mod pgp_modulus;
mod pmhash;
mod srp;

pub use errors::*;
pub use pgp_modulus::*;
pub use pmhash::mailbox_password_hash;
pub use pmhash::srp_password_hash;
pub use pmhash::MailboxHashedPassword;
pub use pmhash::SRPHashedPassword;
pub use srp::*;

/// The Proton version of the protocol.
pub const PROTON_SRP_VERSION: u8 = 4;

/// The minimal supported Proton protocol version.
pub const MIN_SUPPORTED_VERSION: u8 = 4;

/// The minimal support Proton protocol version.
pub const MAX_SUPPORTED_VERSION: u8 = 4;
