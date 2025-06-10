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
//! let decrypted = key.decrypt(&ciphertext, Some("username.app.proton.me")).unwrap();
//! assert_eq!(plaintext, decrypted.as_slice());
//! ```
use std::io::Write;

use aes_gcm::{
    aead::{Aead, Payload},
    AeadCore, Aes256Gcm, Key, KeyInit, KeySizeUser,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{SubtleError, SubtleResult};

pub const AES_GCM_256_IV_SIZE: usize = 12;
pub const AES_GCM_256_KEY_SIZE: usize = 32;

/// A ciphertext returned by AES-GCM-256 encryption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AesGcmCiphertext {
    /// Stores the initialization vector (nonce) that was used to encrypt the data.
    pub iv: [u8; AES_GCM_256_IV_SIZE],

    /// Stores encrypted data including the authentication tag.
    pub data: Vec<u8>,
}

impl AesGcmCiphertext {
    fn new_from_slices(iv: &[u8], data: &[u8]) -> SubtleResult<Self> {
        let ciphertext = AesGcmCiphertext {
            iv: iv.try_into().map_err(|_| SubtleError::InvalidIvLength)?,
            data: data.into(),
        };
        Ok(ciphertext)
    }

    /// Encodes the ciphertext into a byte vector as `iv (12 bytes)| encrypted data | tag (16 bytes)`.
    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(self.iv.len() + self.data.len());
        encoded.extend_from_slice(&self.iv);
        encoded.extend_from_slice(&self.data);
        encoded
    }

    /// Encodes the ciphertext as `iv (12 bytes)| encrypted data | tag (16 bytes)` and writes it to the writer.
    ///
    /// Returns the number of bytes written.
    pub fn encode_and_write(&self, mut writer: impl Write) -> SubtleResult<usize> {
        writer.write_all(&self.iv).map_err(SubtleError::IoWrite)?;
        writer.write_all(&self.data).map_err(SubtleError::IoWrite)?;
        Ok(self.iv.len() + self.data.len())
    }

    /// Tries to decode the ciphertext from a byte slice as `iv (12 bytes)| encrypted data | tag (16 bytes)`.
    pub fn decode(ciphertext: impl AsRef<[u8]>) -> SubtleResult<Self> {
        Self::new_from_slices(
            &ciphertext.as_ref()[..AES_GCM_256_IV_SIZE],
            &ciphertext.as_ref()[AES_GCM_256_IV_SIZE..],
        )
    }
}

/// A view into a AES-GCM-256 ciphertext.
///
/// Only holds references to slices of the data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AesGcmCiphertextView<'a> {
    /// References the initialization vector (nonce) that was used to encrypt the data.
    pub iv: &'a [u8; AES_GCM_256_IV_SIZE],

    /// References the encrypted data including the authentication tag.
    pub data: &'a [u8],
}

impl<'a> AesGcmCiphertextView<'a> {
    pub fn new(iv: &'a [u8], data: &'a [u8]) -> SubtleResult<Self> {
        let ciphertext = Self {
            iv: iv.try_into().map_err(|_| SubtleError::InvalidIvLength)?,
            data,
        };
        Ok(ciphertext)
    }

    /// Encodes the ciphertext as `iv (12 bytes)| encrypted data | tag (16 bytes)` and writes it to the writer.
    ///
    /// Returns the number of bytes written.
    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(self.iv.len() + self.data.len());
        encoded.extend_from_slice(self.iv);
        encoded.extend_from_slice(self.data);
        encoded
    }

    /// Tries to decode the ciphertext from a byte slice as `iv (12 bytes)| encrypted data | tag (16 bytes)`.
    pub fn decode(ciphertext: &'a [u8]) -> SubtleResult<Self> {
        Self::new(
            &ciphertext[..AES_GCM_256_IV_SIZE],
            &ciphertext[AES_GCM_256_IV_SIZE..],
        )
    }
}

impl<'a> From<&'a AesGcmCiphertext> for AesGcmCiphertextView<'a> {
    fn from(ct: &'a AesGcmCiphertext) -> Self {
        Self {
            iv: &ct.iv,
            data: &ct.data,
        }
    }
}

impl<'a> TryFrom<&'a [u8]> for AesGcmCiphertextView<'a> {
    type Error = SubtleError;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        Self::decode(value)
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
    /// This method generates the IV with a cryptographically secure random number generator.
    /// The context is used to add additional authenticated data to the encryption. For example,
    /// the context can be used to bind the ciphertext to a specific application (e.g., username.app.proton.me)
    ///
    /// # Parameters
    ///
    /// * `data` - The data to encrypt.
    /// * `context` - The context to use for encryption. If `None`, the context is not used.
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
    ) -> SubtleResult<AesGcmCiphertext> {
        let mut rng = rand::thread_rng();
        let cipher = Aes256Gcm::new(&self.0);
        let nonce = Aes256Gcm::generate_nonce(&mut rng);

        let ciphertext = match context {
            Some(aad) => {
                let payload = Payload {
                    msg: data.as_ref(),
                    aad: aad.as_bytes(),
                };
                cipher
                    .encrypt(&nonce, payload)
                    .map_err(SubtleError::Encrypt)?
            }
            None => cipher
                .encrypt(&nonce, data.as_ref())
                .map_err(SubtleError::Encrypt)?,
        };

        Ok(AesGcmCiphertext {
            iv: nonce.into(),
            data: ciphertext,
        })
    }

    /// Decrypts the given ciphertext using the key and an optional context.
    ///
    /// # Parameters
    ///
    /// * `cipertext` - The ciphertext to decrypt.
    /// * `context` - The context to use for decryption. If `None`, the context is not used.
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
    /// let decrypted = key.decrypt(&ciphertext, Some("app.proton.me")).unwrap();
    /// assert_eq!(plaintext, decrypted.as_slice());
    /// ```
    pub fn decrypt<'a>(
        &'a self,
        cipertext: impl Into<AesGcmCiphertextView<'a>>,
        context: Option<&str>,
    ) -> SubtleResult<Vec<u8>> {
        let ciphertext_view: AesGcmCiphertextView = cipertext.into();
        let cipher = Aes256Gcm::new(&self.0);
        match context {
            Some(aad) => {
                let payload = Payload {
                    msg: ciphertext_view.data,
                    aad: aad.as_bytes(),
                };
                cipher
                    .decrypt(ciphertext_view.iv.into(), payload)
                    .map_err(SubtleError::Decrypt)
            }
            None => cipher
                .decrypt(ciphertext_view.iv.into(), ciphertext_view.data)
                .map_err(SubtleError::Decrypt),
        }
    }
}
