#![allow(deprecated)]

//! Implements Proton standard AES-GCM-256 encryption and decryption.
//!
//! This module provides a simple interface for encrypting and decrypting data using AES-GCM-256.
//!
//! # Example
//!
//! ```
//! use proton_crypto_subtle::aead::{AesGcmCiphertext, AesGcmKey};
//!
//! let key = AesGcmKey::generate();
//! let plaintext = b"Bob";
//! let ciphertext = key.encrypt(plaintext, Some("username.app.proton.me")).unwrap();
//!
//! let decrypted = key.decrypt(ciphertext, Some("username.app.proton.me")).unwrap();
//! assert_eq!(plaintext, decrypted.as_slice());
//! ```
use std::{borrow::Cow, io::Write};

#[cfg(feature = "legacy")]
use aes_gcm::aes::Aes256;
use aes_gcm::{
    aead::{consts::U16, Aead, Payload},
    aes::cipher::{ArrayLength, BlockCipher, BlockEncrypt, BlockSizeUser},
    AeadCore, Aes256Gcm, AesGcm, Key, KeyInit, KeySizeUser, Nonce,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{SubtleError, SubtleResult};

#[cfg(feature = "legacy")]
pub type Aes256GcmIv16 = AesGcm<Aes256, U16>;

#[cfg(feature = "legacy")]
pub const AES_GCM_256_IV_SIZE_LEGACY: usize = 16;

pub const AES_GCM_256_IV_SIZE: usize = 12;
pub const AES_GCM_256_KEY_SIZE: usize = 32;

/// An `AES-GCM-256` ciphertext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AesGcmCiphertext<'a> {
    /// Stores the initialization vector (nonce) that was used to encrypt the data.
    pub iv: Cow<'a, [u8]>,

    /// Stores encrypted data including the authentication tag.
    pub data: Cow<'a, [u8]>,
}

impl<'a> AesGcmCiphertext<'a> {
    pub fn new(iv: &'a [u8], data: &'a [u8]) -> SubtleResult<Self> {
        Self::check_iv(iv)?;

        let ciphertext = Self {
            iv: Cow::Borrowed(iv),
            data: Cow::Borrowed(data),
        };
        Ok(ciphertext)
    }

    /// Encodes the ciphertext into a byte vector as `iv | encrypted data | tag (16 bytes)`.
    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(self.iv.len() + self.data.len());
        encoded.extend_from_slice(&self.iv);
        encoded.extend_from_slice(&self.data);
        encoded
    }

    /// Encodes the ciphertext as `iv | encrypted data | tag (16 bytes)` and writes it to the writer.
    ///
    /// Returns the number of bytes written.
    pub fn encode_and_write(&self, mut writer: impl Write) -> SubtleResult<usize> {
        writer.write_all(&self.iv).map_err(SubtleError::IoWrite)?;
        writer.write_all(&self.data).map_err(SubtleError::IoWrite)?;
        Ok(self.iv.len() + self.data.len())
    }

    /// Tries to decode the ciphertext from a byte slice as `iv (12 bytes)| encrypted data | tag (16 bytes)`.
    pub fn decode(ciphertext: &'a [u8]) -> SubtleResult<Self> {
        let iv = ciphertext
            .get(..AES_GCM_256_IV_SIZE)
            .ok_or(SubtleError::InvalidIvLength)?;
        let ct = ciphertext
            .get(AES_GCM_256_IV_SIZE..)
            .ok_or(SubtleError::InvalidCiphertext)?;
        Self::new(iv, ct)
    }

    /// Tries to decode the ciphertext from a byte slice as `iv (16 bytes)| encrypted data | tag (16 bytes)`.
    ///
    /// Legacy method that uses a 16-byte IV instead of the standard 12-byte IV.
    /// This non-standard IV length for compatibility with existing legacy systems.
    #[cfg(feature = "legacy")]
    pub fn decode_legacy(ciphertext: &'a [u8]) -> SubtleResult<Self> {
        Self::new(
            &ciphertext[..AES_GCM_256_IV_SIZE_LEGACY],
            &ciphertext[AES_GCM_256_IV_SIZE_LEGACY..],
        )
    }

    #[cfg(feature = "legacy")]
    pub fn is_legacy(&self) -> bool {
        self.iv.len() == AES_GCM_256_IV_SIZE_LEGACY
    }

    fn check_iv(iv: &[u8]) -> SubtleResult<()> {
        #[cfg(feature = "legacy")]
        {
            if !(iv.len() == AES_GCM_256_IV_SIZE || iv.len() == AES_GCM_256_IV_SIZE_LEGACY) {
                return Err(SubtleError::InvalidIvLength);
            }
        }
        #[cfg(not(feature = "legacy"))]
        {
            if iv.len() != AES_GCM_256_IV_SIZE {
                return Err(SubtleError::InvalidIvLength);
            }
        }
        Ok(())
    }
}

impl AesGcmCiphertext<'static> {
    pub fn new_owned(iv: Vec<u8>, data: Vec<u8>) -> SubtleResult<AesGcmCiphertext<'static>> {
        Self::check_iv(&iv)?;

        Ok(Self {
            iv: Cow::Owned(iv),
            data: Cow::Owned(data),
        })
    }
}

/// A AES-GCM-256 key used to encrypt and decrypt data.
///
/// This key data is zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct AesGcmKey(Key<Aes256Gcm>);

impl AsRef<[u8]> for AesGcmKey {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl From<[u8; AES_GCM_256_KEY_SIZE]> for AesGcmKey {
    fn from(key_bytes: [u8; AES_GCM_256_KEY_SIZE]) -> Self {
        Self(key_bytes.into())
    }
}

impl TryFrom<&[u8]> for AesGcmKey {
    type Error = SubtleError;

    fn try_from(key_bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(key_bytes)
    }
}

impl AesGcmKey {
    /// Creates a new AES-GCM-256 key from a byte slice.
    pub fn from_bytes(key_bytes: impl AsRef<[u8]>) -> SubtleResult<Self> {
        if key_bytes.as_ref().len() != Aes256Gcm::key_size() {
            return Err(SubtleError::InvalidKeyLength);
        }
        let key = Key::<Aes256Gcm>::clone_from_slice(key_bytes.as_ref());
        Ok(Self(key))
    }

    /// Generates a new AES-GCM-256 key using a cryptographically secure random number generator.
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        Self(Aes256Gcm::generate_key(&mut rng))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Encrypts the given data using the key and an optional context.
    ///
    /// This method generates the 12 byte IV with a cryptographically secure random number generator.
    /// The context is used to add additional authenticated data to the encryption. For example,
    /// the context can be used to bind the ciphertext to a specific application (e.g., username.app.proton.me)
    ///
    /// # Examples
    ///
    /// ```
    /// use proton_crypto_subtle::aead::{AesGcmKey, AesGcmCiphertext};
    ///
    /// let key = AesGcmKey::generate();
    /// let plaintext = b"Hello, world!";
    /// let ciphertext = key.encrypt(plaintext, Some("app.proton.me")).unwrap();
    /// ```
    pub fn encrypt(
        &self,
        data: impl AsRef<[u8]>,
        context: Option<&str>,
    ) -> SubtleResult<AesGcmCiphertext<'static>> {
        let mut rng = rand::thread_rng();
        let cipher = Aes256Gcm::new(&self.0);
        let nonce = Aes256Gcm::generate_nonce(&mut rng);

        Self::encrypt_generic(&cipher, &nonce, data.as_ref(), context)
    }

    /// Decrypts the given ciphertext using the key and an optional context.
    ///
    /// # Examples
    ///
    /// ```
    /// use proton_crypto_subtle::aead::{AesGcmKey, AesGcmCiphertext};
    ///
    /// let key = AesGcmKey::generate();
    /// let plaintext = b"Hello, world!";
    /// let ciphertext = key.encrypt(plaintext, Some("app.proton.me")).unwrap();
    ///
    /// let decrypted = key.decrypt(ciphertext, Some("app.proton.me")).unwrap();
    /// assert_eq!(plaintext, decrypted.as_slice());
    /// ```
    pub fn decrypt<'a>(
        &'a self,
        cipertext: impl Into<AesGcmCiphertext<'a>>,
        context: Option<&str>,
    ) -> SubtleResult<Vec<u8>> {
        let ciphertext_view: AesGcmCiphertext = cipertext.into();
        let cipher = Aes256Gcm::new(&self.0);

        #[cfg(feature = "legacy")]
        if ciphertext_view.is_legacy() {
            return Err(SubtleError::InvalidCiphertext);
        }

        Self::decrypt_generic(&cipher, &ciphertext_view, context)
    }

    /// Encrypts the given data using the key and an optional context in legacy mode with 16 byte iv.
    ///
    /// **Use this function only when necessary for backwards compatibility.**  
    /// For all other cases, prefer using [`Self::encrypt`].
    ///
    /// This method generates the 16 byte IV with a cryptographically secure random number generator.
    /// The context is used to add additional authenticated data to the encryption. For example,
    /// the context can be used to bind the ciphertext to a specific application (e.g., username.app.proton.me)
    ///
    /// # Examples
    ///
    /// ```
    /// use proton_crypto_subtle::aead::{AesGcmKey, AesGcmCiphertext};
    ///
    /// let key = AesGcmKey::generate();
    /// let plaintext = b"Hello, world!";
    /// let ciphertext = key.encrypt_legacy(plaintext, Some("app.proton.me")).unwrap();
    /// ```
    #[cfg(feature = "legacy")]
    pub fn encrypt_legacy(
        &self,
        data: impl AsRef<[u8]>,
        context: Option<&str>,
    ) -> SubtleResult<AesGcmCiphertext> {
        let mut rng = rand::thread_rng();
        let cipher = Aes256GcmIv16::new(&self.0);
        let nonce = Aes256GcmIv16::generate_nonce(&mut rng);

        Self::encrypt_generic(&cipher, &nonce, data.as_ref(), context)
    }

    /// Decrypts the given ciphertext using the key and an optional context.
    ///
    /// Assumes that the ciphertext was encrypted with a 16 byte iv.
    ///
    /// **Use this function only when necessary for backwards compatibility.**  
    /// For all other cases, prefer using [`Self::decrypt`].
    ///
    /// # Examples
    ///
    /// ```
    /// use proton_crypto_subtle::aead::{AesGcmKey, AesGcmCiphertext};
    ///
    /// let key = AesGcmKey::generate();
    /// let plaintext = b"Hello, world!";
    /// let ciphertext = key.encrypt_legacy(plaintext, Some("app.proton.me")).unwrap();
    ///
    /// let decrypted = key.decrypt_legacy(ciphertext, Some("app.proton.me")).unwrap();
    /// assert_eq!(plaintext, decrypted.as_slice());
    /// ```
    #[cfg(feature = "legacy")]
    pub fn decrypt_legacy<'a>(
        &'a self,
        cipertext: impl Into<AesGcmCiphertext<'a>>,
        context: Option<&str>,
    ) -> SubtleResult<Vec<u8>> {
        let ciphertext_view: AesGcmCiphertext = cipertext.into();
        let cipher = Aes256GcmIv16::new(&self.0);

        if !ciphertext_view.is_legacy() {
            return Err(SubtleError::InvalidCiphertext);
        }

        Self::decrypt_generic(&cipher, &ciphertext_view, context)
    }

    fn encrypt_generic<Aes, NonceSize>(
        cipher: &AesGcm<Aes, NonceSize>,
        nonce: &Nonce<NonceSize>,
        data: &[u8],
        context: Option<&str>,
    ) -> SubtleResult<AesGcmCiphertext<'static>>
    where
        Aes: BlockCipher + BlockSizeUser<BlockSize = U16> + BlockEncrypt,
        NonceSize: ArrayLength<u8>,
    {
        let ciphertext = match context {
            Some(aad) => {
                let payload = Payload {
                    msg: data,
                    aad: aad.as_bytes(),
                };
                cipher
                    .encrypt(nonce, payload)
                    .map_err(SubtleError::Encrypt)?
            }
            None => cipher
                .encrypt(nonce, data.as_ref())
                .map_err(SubtleError::Encrypt)?,
        };

        AesGcmCiphertext::new_owned(nonce.to_vec(), ciphertext)
    }

    fn decrypt_generic<Aes, NonceSize>(
        cipher: &AesGcm<Aes, NonceSize>,
        ciphertext_view: &AesGcmCiphertext,
        context: Option<&str>,
    ) -> SubtleResult<Vec<u8>>
    where
        Aes: BlockCipher + BlockSizeUser<BlockSize = U16> + BlockEncrypt,
        NonceSize: ArrayLength<u8>,
    {
        match context {
            Some(aad) => {
                let payload = Payload {
                    msg: ciphertext_view.data.as_ref(),
                    aad: aad.as_bytes(),
                };
                cipher
                    .decrypt(ciphertext_view.iv.as_ref().into(), payload)
                    .map_err(SubtleError::Decrypt)
            }
            None => cipher
                .decrypt(
                    ciphertext_view.iv.as_ref().into(),
                    ciphertext_view.data.as_ref(),
                )
                .map_err(SubtleError::Decrypt),
        }
    }
}
