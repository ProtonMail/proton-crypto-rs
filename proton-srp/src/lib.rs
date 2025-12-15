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
pub enum SrpHashVersion {
    V0 = 0,
    V1 = 1,
    V2 = 2,
    V3 = 3,
    #[default]
    V4 = 4,
}

impl TryFrom<u8> for SrpHashVersion {
    type Error = SRPError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(SrpHashVersion::V0),
            1 => Ok(SrpHashVersion::V1),
            2 => Ok(SrpHashVersion::V2),
            3 => Ok(SrpHashVersion::V3),
            4 => Ok(SrpHashVersion::V4),
            _ => Err(SRPError::UnsupportedVersion),
        }
    }
}

impl From<SrpHashVersion> for u8 {
    fn from(version: SrpHashVersion) -> Self {
        version as u8
    }
}

impl SrpHashVersion {
    pub(crate) fn unpack_username(self, username: Option<&str>) -> Result<&str, SRPError> {
        match self {
            SrpHashVersion::V0 | SrpHashVersion::V1 | SrpHashVersion::V2 => {
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

/// The Proton srp password hash version used in the protocol.
pub const PROTON_SRP_VERSION: SrpHashVersion = SrpHashVersion::V4;
