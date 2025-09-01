//! Implements core cryptography utility.

pub type Error = CryptoError;
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(feature = "gopgp")]
mod go;

mod rust;

pub mod crypto;
pub mod keytransparency;
pub mod utils;
use parking_lot::RwLock;
use rand::RngCore as _;
use rust::RustSRP;
use std::sync::Arc;
use std::{
    fmt::{Display, Formatter},
    io,
    sync::OnceLock,
    time::SystemTime,
};

/// An generic error thrown by the crypto APIs.
#[derive(Clone, Debug)]
pub struct CryptoError(pub Arc<dyn std::error::Error + Send + Sync>);

impl std::error::Error for CryptoError {}

impl Display for CryptoError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<std::num::ParseIntError> for CryptoError {
    fn from(value: std::num::ParseIntError) -> Self {
        Self(Arc::new(value))
    }
}

impl From<CryptoInfoError> for CryptoError {
    fn from(value: CryptoInfoError) -> Self {
        Self(Arc::new(value))
    }
}

impl From<io::Error> for CryptoError {
    fn from(value: io::Error) -> Self {
        Self(Arc::new(value))
    }
}

/// Simple string crypto error that converts to a [`CryptoError`].
#[derive(Debug, Clone)]
pub struct CryptoInfoError(pub(crate) String);

impl Display for CryptoInfoError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for CryptoInfoError {}

impl CryptoInfoError {
    /// Create a crypto error from a info string.
    pub fn new(info: &str) -> Self {
        Self(info.to_owned())
    }
}

pub mod srp;
use srp::{ClientProof, SRPProvider};
/// Return a reference to the crypto clock that is used to determine the time.
///
/// The PGP provider internally uses this clock to retrieve the default time.
pub fn crypto_clock() -> &'static CryptoClock {
    static CRYPTO_CLOCK: OnceLock<CryptoClock> = OnceLock::new();
    CRYPTO_CLOCK.get_or_init(CryptoClock::default)
}

/// The crypto clock internally uses a `CryptoClockProvider` to determine the time.
///
/// Clients should use the server time retrieved from the API whenever possible for cryptographic operations
/// to avoid failures to clock offsets.
pub trait CryptoClockProvider: Send + Sync + std::fmt::Debug {
    /// Returns the current unix time of the provider.
    fn unix_time(&self) -> UnixTimestamp;
}

/// A `CryptoClockProvider` that runs on local time.
#[derive(Debug)]
pub struct CryptoClock(RwLock<Box<dyn CryptoClockProvider>>);

impl Default for CryptoClock {
    fn default() -> Self {
        CryptoClock(RwLock::new(Box::new(LocalTimeProvider {})))
    }
}

impl CryptoClock {
    /// Returns the current unix time of the internal `CryptoClockProvider`.
    pub fn unix_time(&self) -> UnixTimestamp {
        self.0.read().unix_time()
    }

    /// Sets a new `CryptoClockProvider`.
    pub fn set_provider(&self, clock: Box<dyn CryptoClockProvider>) {
        let mut provider_ref = self.0.write();
        *provider_ref = clock;
    }
}

/// A `CryptoClockProvider` that runs on local time.
#[derive(Debug)]
pub struct LocalTimeProvider {}

impl CryptoClockProvider for LocalTimeProvider {
    fn unix_time(&self) -> UnixTimestamp {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(UnixTimestamp::default(), |duration| {
                UnixTimestamp::new(duration.as_secs())
            })
    }
}

/// Factory function to create a synchronous `PGPProvider`.
pub fn new_pgp_provider() -> impl PGPProviderSync {
    #[cfg(feature = "gopgp")]
    return new_go_pgp_provider();
    #[cfg(not(any(feature = "gopgp")))]
    compile_error!("At least one of 'rustpgp' or 'gopgp' features must be enabled.");
}

/// Factory function to create a asynchronous `PGPProvider`.
pub fn new_pgp_provider_async() -> impl PGPProviderAsync {
    #[cfg(feature = "gopgp")]
    return new_go_pgp_provider_async();

    #[cfg(not(any(feature = "gopgp")))]
    compile_error!("At least one of 'rustpgp' or 'gopgp' features must be enabled.");
}

#[cfg(feature = "gopgp")]
pub fn new_go_pgp_provider() -> impl PGPProviderSync {
    go::pgp::GoPGPProvider(crypto_clock())
}

#[cfg(feature = "gopgp")]
pub fn new_go_pgp_provider_async() -> impl PGPProviderAsync {
    go::pgp::GoPGPProvider(crypto_clock())
}
/// Factory function to create an `SRPProvider`.
pub fn new_srp_provider() -> impl SRPProvider {
    RustSRP::new(new_pgp_provider())
}

/// Generates random bytes with a cryptographically-secure random number generator (`CSPRNG`).
///
/// Uses [`rand::thread_rng()`] as CSPRNG.
pub fn generate_secure_random_bytes<const TOKEN_SIZE: usize>() -> [u8; TOKEN_SIZE] {
    let mut rng = rand::thread_rng();
    let mut out = [0; TOKEN_SIZE];
    rng.fill_bytes(&mut out);
    out
}

macro_rules! lowercase_string_id {
    (
        $(#[$meta:meta])*
        $name:ident
    ) => {
        #[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Default)]
        $(#[$meta])*
        pub struct $name(String);

        impl $name {
            pub fn new(fingerprint: String) -> Self {
                if fingerprint.chars().all(char::is_lowercase) {
                    return Self(fingerprint);
                }
                Self(fingerprint.to_lowercase())
            }

            pub fn into_inner(self) -> String {
                self.0
            }
        }

        impl Display for $name {
            fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
                self.0.fmt(f)
            }
        }

        impl From<String> for $name {
            fn from(v: String) -> Self {
                Self::new(v.into())
            }
        }

        impl From<&str> for $name {
            fn from(v: &str) -> Self {
                Self::new(v.into())
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }
    };
}

pub(crate) use lowercase_string_id;

use crate::crypto::{PGPProviderAsync, PGPProviderSync, UnixTimestamp};
