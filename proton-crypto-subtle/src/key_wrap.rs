//! AES-256 key wrapping (RFC 3394) for 32-byte keys.
//!
//! AES-KW is deterministic and has no associated data. Derive distinct wrapping keys when
//! the wrapped key must be bound to a purpose or object.
//!
//! # Example
//!
//! ```
//! use proton_crypto_subtle::{aead::AesGcmKey, key_wrap::{AesKwKey, WrappedAesKey}};
//!
//! let kek = AesKwKey::generate();
//! let key = AesGcmKey::generate();
//! let encoded = kek.wrap(&key).unwrap().to_vec();
//! let wrapped = WrappedAesKey::from_bytes(&encoded).unwrap();
//! assert_eq!(kek.unwrap(&wrapped).unwrap().as_bytes(), key.as_bytes());
//! ```
use std::fmt;

use aes_gcm::aead::generic_array::GenericArray;
use aes_kw::{KekAes256, IV_LEN};
use rand::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::{
    aead::{AesGcmKey, AES_GCM_256_KEY_SIZE},
    SubtleError, SubtleResult,
};

/// AES-256 KEK length in bytes.
pub const AES_KW_256_KEY_SIZE: usize = 32;

/// Wrapped key length in bytes.
pub const WRAPPED_KEY_SIZE: usize = AES_GCM_256_KEY_SIZE + IV_LEN;

/// A 40-byte (`WRAPPED_KEY_SIZE`) AES-KW value: 8-byte integrity block followed by 32-byte wrapped key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappedAesKey([u8; WRAPPED_KEY_SIZE]);

impl WrappedAesKey {
    /// Checks length only; [`AesKwKey::unwrap`] checks integrity.
    pub fn from_bytes(wrapped: impl AsRef<[u8]>) -> SubtleResult<Self> {
        wrapped
            .as_ref()
            .try_into()
            .map(Self)
            .map_err(|_| SubtleError::InvalidWrappedKey)
    }

    /// Returns a copy of the wrapped bytes.
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    /// Converts the wrapped key into a fixed-size array without allocating.
    pub fn into_array(self) -> [u8; WRAPPED_KEY_SIZE] {
        self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the wrapped key as a fixed-size array reference.
    pub fn as_array(&self) -> &[u8; WRAPPED_KEY_SIZE] {
        &self.0
    }

    pub fn len() -> usize {
        WRAPPED_KEY_SIZE
    }
}

impl From<[u8; WRAPPED_KEY_SIZE]> for WrappedAesKey {
    fn from(wrapped: [u8; WRAPPED_KEY_SIZE]) -> Self {
        Self(wrapped)
    }
}

impl TryFrom<&[u8]> for WrappedAesKey {
    type Error = SubtleError;

    fn try_from(wrapped: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(wrapped)
    }
}

impl AsRef<[u8]> for WrappedAesKey {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl From<WrappedAesKey> for Vec<u8> {
    fn from(value: WrappedAesKey) -> Self {
        value.to_vec()
    }
}

impl From<WrappedAesKey> for [u8; WRAPPED_KEY_SIZE] {
    fn from(value: WrappedAesKey) -> Self {
        value.into_array()
    }
}

/// An AES-256 wrapping key. Its cipher state is zeroized on drop.
#[derive(Clone)]
pub struct AesKwKey(KekAes256);

impl fmt::Debug for AesKwKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("AesKwKey")
            .field(&format_args!("[REDACTED]"))
            .finish()
    }
}

impl From<[u8; AES_KW_256_KEY_SIZE]> for AesKwKey {
    fn from(key_bytes: [u8; AES_KW_256_KEY_SIZE]) -> Self {
        Self(KekAes256::from(key_bytes))
    }
}

impl TryFrom<&[u8]> for AesKwKey {
    type Error = SubtleError;

    fn try_from(key_bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(key_bytes)
    }
}

impl AesKwKey {
    /// Imports a 32-byte wrapping key.
    pub fn from_bytes(key_bytes: impl AsRef<[u8]>) -> SubtleResult<Self> {
        KekAes256::try_from(key_bytes.as_ref())
            .map(Self)
            .map_err(|_| SubtleError::InvalidKeyLength)
    }

    /// Generates a wrapping key with a CSPRNG.
    pub fn generate() -> Self {
        Self::generate_with_rng(&mut rand::thread_rng())
    }

    /// Generates a wrapping key with the supplied CSPRNG.
    fn generate_with_rng<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut key_bytes = Zeroizing::new([0_u8; AES_KW_256_KEY_SIZE]);
        rng.fill_bytes(key_bytes.as_mut_slice());
        Self(KekAes256::new(GenericArray::from_slice(
            key_bytes.as_slice(),
        )))
    }

    /// Wraps an AES-GCM-256 key.
    pub fn wrap(&self, key: &AesGcmKey) -> SubtleResult<WrappedAesKey> {
        let mut out = [0_u8; WRAPPED_KEY_SIZE];
        self.0
            .wrap(key.as_bytes(), &mut out)
            .map_err(|_| SubtleError::KeyWrap)?;
        Ok(WrappedAesKey(out))
    }

    /// Unwraps an AES-GCM-256 key, failing on a wrong KEK or corrupted wrapped data.
    pub fn unwrap(&self, wrapped: &WrappedAesKey) -> SubtleResult<AesGcmKey> {
        let mut out = Zeroizing::new([0_u8; AES_GCM_256_KEY_SIZE]);
        self.0
            .unwrap(&wrapped.0, out.as_mut_slice())
            .map_err(|_| SubtleError::KeyUnwrap)?;
        AesGcmKey::from_bytes(out.as_slice())
    }
}
