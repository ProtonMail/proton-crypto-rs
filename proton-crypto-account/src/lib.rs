//! Provides cryptography domains and utility for Proton account.

mod constants;
use constants::{
    FLAG_EMAIL_NO_ENCRYPT, FLAG_EMAIL_NO_SIGN, FLAG_NOT_COMPROMISED, FLAG_NOT_OBSOLETE,
};
pub mod contacts;
mod crypto;
pub mod errors;
pub mod keys;
pub mod salts;

// re-export crypto crate;
pub use proton_crypto;

macro_rules! string_id {
    (
        $(#[$meta:meta])*
        $name:ident
    ) => {
        #[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Hash, Clone)]
        $(#[$meta])*
        pub struct $name(pub String);

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                std::fmt::Display::fmt(&self.0, f)

            }
        }

        impl<T: Into<String>> From<T> for $name {
            fn from(value: T) -> Self {
                Self(value.into())
            }
        }

        impl ::std::ops::Deref for $name {
            type Target = str;

            fn deref(&self) -> &Self::Target {
                self.0.as_str()
            }
        }

        #[cfg(feature = "sql")]
        impl rusqlite::types::ToSql for $name {
            fn to_sql(&self) -> Result<rusqlite::types::ToSqlOutput, rusqlite::Error> {
                self.0.to_sql()
            }
        }

        #[cfg(feature = "sql")]
        impl rusqlite::types::FromSql for $name {
            fn column_result(value: rusqlite::types::ValueRef<'_>) -> rusqlite::types::FromSqlResult<Self> {
                Ok(Self(value.as_str()?.to_owned()))
            }
        }
    };
}

pub(crate) use string_id;
