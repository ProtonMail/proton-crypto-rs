use crate::SRPError;

#[cfg(test)]
#[path = "../tests/srp.rs"]
mod tests;

pub(crate) mod core;
mod server;
pub use server::*;
mod client;
pub use client::*;
use rand::CryptoRng;

pub use core::{SALT_LEN_BYTES, SRP_LEN_BYTES};

#[cfg(test)]
use core::TEST_CLIENT_SECRET_LEN;

pub(crate) fn srp_default_csprng() -> impl CryptoRng {
    rand::rng()
}
