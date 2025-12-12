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

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum SrpVersion {
    V0 = 0,
    V1 = 1,
    V2 = 2,
    V3 = 3,
    #[default]
    V4 = 4,
}

impl TryFrom<u8> for SrpVersion {
    type Error = SRPError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(SrpVersion::V0),
            1 => Ok(SrpVersion::V1),
            2 => Ok(SrpVersion::V2),
            3 => Ok(SrpVersion::V3),
            4 => Ok(SrpVersion::V4),
            _ => Err(SRPError::UnsupportedVersion),
        }
    }
}

impl From<SrpVersion> for u8 {
    fn from(version: SrpVersion) -> Self {
        version as u8
    }
}

impl SrpVersion {
    pub(crate) fn unpack_username(self, username: Option<&str>) -> Result<&str, SRPError> {
        match self {
            SrpVersion::V0 | SrpVersion::V1 | SrpVersion::V2 => {
                if let Some(username) = username {
                    Ok(username)
                } else {
                    Err(SRPError::MissingUsername(self.into()))
                }
            }
            _ => Ok(""),
        }
    }
}

/// The Proton version of the protocol.
pub const PROTON_SRP_VERSION: SrpVersion = SrpVersion::V4;
