use std::{
    fmt::{self, Display},
    time::{SystemTime, UNIX_EPOCH},
};

use chrono::{DateTime, Utc};

use crate::FingerprintError;

/// Possible encodings of an `OpenPGP` message.
///
/// The data is either armored i.e., base64 encoded with a header
/// -----BEGIN PGP ... -----
/// ...
/// -----BEGIN PGP ... -----
/// or encoded as raw bytes.
/// Auto is used to indicate that encoding is unknown and the function
/// should detect the encoding automatically.
#[derive(Default, PartialEq, Eq, Hash, Clone, Copy, Debug)]
pub enum DataEncoding {
    /// The data is armored.
    #[default]
    Armor,
    /// The data is encoded as raw bytes.
    Binary,
}

impl DataEncoding {
    pub fn is_armor(&self) -> bool {
        *self == DataEncoding::Armor
    }
}

/// `UnixTimestamp` represents a unix timestamp within `OpenPGP`.
#[derive(Ord, PartialOrd, PartialEq, Eq, Hash, Clone, Copy, Debug, Default)]
pub struct UnixTime(u64);

impl UnixTime {
    /// Creates new unix timestamp.
    pub fn new(unix_time: u64) -> Self {
        Self(unix_time)
    }

    pub fn now() -> Option<Self> {
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(n) => Some(Self(n.as_secs())),
            Err(_) => None,
        }
    }

    /// Creates unix timestamp with the zero value.
    ///
    /// If a zero value is supplied to the API expirations checks are skipped.
    pub fn zero() -> Self {
        Self(0)
    }

    /// Indicates if the timestamp is zero.
    pub fn is_zero(&self) -> bool {
        self.0 == 0
    }

    /// Indicates if time check should be disabled.
    pub fn checks_disabled(&self) -> bool {
        self.is_zero()
    }

    /// Returns the Unix timestamp as a u64.
    pub fn unix_seconds(&self) -> u64 {
        self.0
    }
}

impl fmt::Display for UnixTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<&DateTime<Utc>> for UnixTime {
    fn from(value: &DateTime<Utc>) -> Self {
        // Ok to transform to u64 without checks.
        #[allow(clippy::cast_sign_loss)]
        Self(value.timestamp() as u64)
    }
}

impl From<DateTime<Utc>> for UnixTime {
    fn from(value: DateTime<Utc>) -> Self {
        // Ok to transform to u64 without checks.
        #[allow(clippy::cast_sign_loss)]
        Self(value.timestamp() as u64)
    }
}

/// A sha256 fingerprint.
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct FingerprintSha256(pub(crate) [u8; 32]);

impl FingerprintSha256 {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_hex(hex: &str) -> Result<Self, FingerprintError> {
        let bytes = hex::decode(hex)?;
        let len = bytes.len();
        let raw_fp: [u8; 32] = bytes
            .try_into()
            .map_err(|_| FingerprintError::InvalidLength(len))?;
        Ok(Self(raw_fp))
    }

    pub fn to_hex(&self) -> String {
        self.to_string()
    }
}

impl AsRef<[u8]> for FingerprintSha256 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 32]> for FingerprintSha256 {
    fn from(value: [u8; 32]) -> Self {
        Self::new(value)
    }
}

impl Display for FingerprintSha256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}
