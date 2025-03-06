//! Proton key domain types.
mod api_keys;
pub use api_keys::*;
mod address_keys;
pub use address_keys::*;
mod public_address_keys;
pub use public_address_keys::*;
mod user_keys;
use serde::{Deserialize, Deserializer, Serializer};
pub use user_keys::*;
mod signed_key_list;
pub use signed_key_list::*;
mod organization_keys;
pub use organization_keys::*;
mod mail_public_keys;
pub use mail_public_keys::*;
mod pinned_keys;
pub use pinned_keys::*;
mod recipient;
pub use recipient::*;
mod device_keys;
pub use device_keys::*;

use crate::errors::KeyError;

/// Represents a key unlock result.
///
/// Contains all unlocked keys and errors for unlock attempts
/// that have failed.
pub struct UnlockResult<T> {
    /// The unlocked keys.
    pub unlocked_keys: Vec<T>,
    /// Keys that have failed to unlock.
    pub failed: Vec<KeyError>,
}

impl<T> From<UnlockResult<T>> for Vec<T> {
    fn from(value: UnlockResult<T>) -> Self {
        value.unlocked_keys
    }
}

/// Deserialize bool from integer
pub(crate) fn bool_from_integer<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    if i64::deserialize(deserializer)? == 0_i64 {
        Ok(false)
    } else {
        Ok(true)
    }
}

#[allow(clippy::trivially_copy_pass_by_ref)]
pub(crate) fn bool_to_integer<S>(value: &bool, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_u8(u8::from(*value))
}
