use crate::SRPError;

#[cfg(test)]
#[path = "../tests/srp.rs"]
mod tests;

pub(crate) mod core;
mod server;
pub use server::*;
mod client;
pub use client::*;

pub use core::{SALT_LEN_BYTES, SRP_LEN_BYTES};

#[cfg(test)]
use core::TEST_CLIENT_SECRET_LEN;
