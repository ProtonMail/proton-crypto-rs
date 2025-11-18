use std::fmt::Debug;

use crate::keys::KeyId;
use base64::{prelude::BASE64_STANDARD as BASE_64, DecodeSliceError, Engine as _};
use proton_crypto::{
    generate_secure_random_bytes,
    srp::{HashedPassword, SRPProvider},
    CryptoError,
};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

crate::string_id! {
    // A base64 encoded key salt.
    KeySalt
}

#[derive(Debug, thiserror::Error)]
pub enum SaltError {
    #[error("Could not find key with id {0}")]
    KeyNotFound(KeyId),
    #[error("Key with id {0} has no salt value")]
    KeyHasNoSalt(KeyId),
    #[error("Could not decode key salt: {0}")]
    Base64Decode(#[from] DecodeSliceError),
    #[error("Failed to hash: {0}")]
    Hash(#[from] CryptoError),
    #[error("Failed to decoded hash")]
    HashDecode,
}

#[derive(Serialize, Deserialize, Debug)]
#[cfg_attr(feature = "facet", derive(facet::Facet))]
pub struct Salt {
    #[serde(rename = "ID")]
    pub id: KeyId,
    #[serde(rename = "KeySalt")]
    pub key_salt: Option<KeySalt>,
}

/// A hashed secret to decrypt a user key.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KeySecret(Vec<u8>);

impl KeySecret {
    /// Creates a key secret from a byte vector.
    #[must_use]
    pub fn new(data: Vec<u8>) -> Self {
        KeySecret(data)
    }

    /// Returns a slice of the key in bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl AsRef<[u8]> for KeySecret {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl Debug for KeySecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeySecret: [CONFIDENTIAL]")
    }
}

impl KeySalt {
    const SALT_LEN: usize = 16;
    /// Encode raw salt bytes as [`KeySalt`].
    #[must_use]
    pub fn from_bytes(salt_bytes: &[u8; Self::SALT_LEN]) -> Self {
        Self(BASE_64.encode(salt_bytes))
    }

    /// Generates a fresh random [`KeySalt`] using client randomness.
    #[must_use]
    pub fn generate() -> Self {
        let salt_bytes: [u8; Self::SALT_LEN] = generate_secure_random_bytes();
        Self::from_bytes(&salt_bytes)
    }

    /// Encode raw salt bytes as [`KeySalt`].
    #[must_use]
    pub fn encode(salt_bytes: &[u8]) -> Self {
        Self(BASE_64.encode(salt_bytes))
    }

    /// Decodes the base64 key salt to its raw binary form.
    pub fn decode(&self) -> Result<[u8; Self::SALT_LEN], SaltError> {
        let mut salt_bytes: [u8; Self::SALT_LEN] = [0; Self::SALT_LEN];
        BASE_64.decode_slice(&self.0, &mut salt_bytes)?;
        Ok(salt_bytes)
    }

    /// Derives the salted key passphrase to unlock a key from a password.
    ///
    /// # Errors
    /// - Password derivation fails [`SaltError::Hash`].
    /// - Decoding fails [`SaltError::HashDecode`].
    pub fn salted_key_passphrase<Provider: SRPProvider>(
        &self,
        srp_provider: &Provider,
        key_pass: &[u8],
    ) -> Result<KeySecret, SaltError> {
        let result = srp_provider.mailbox_password(key_pass, self.decode()?)?;
        // Remove bcrypt prefix and salt.
        Ok(KeySecret(result.password_hash().to_vec()))
    }
}

/// A list of salts retrieved from the API.
#[derive(Deserialize, Debug)]
#[cfg_attr(feature = "facet", derive(facet::Facet))]
pub struct Salts(Vec<Salt>);

impl Salts {
    pub fn new(salts: impl IntoIterator<Item = Salt>) -> Self {
        Self(salts.into_iter().collect::<Vec<_>>())
    }

    /// Derives the key secret to unlock the key with the given key id.
    ///
    /// Tries to find the matching salt, and derives the password.
    ///
    /// # Errors
    /// - Matching key salt not found [`SaltError::KeyNotFound`] or [`SaltError::KeyHasNoSalt`].
    /// - Password derivation fails
    pub fn salt_for_key<T: SRPProvider>(
        &self,
        srp_provider: &T,
        key: &KeyId,
        key_pass: &[u8],
    ) -> Result<KeySecret, SaltError> {
        let Some(salt) = self.0.iter().find(|&v| v.id == *key) else {
            return Err(SaltError::KeyNotFound(key.clone()));
        };
        let Some(key_salt) = &salt.key_salt else {
            return Err(SaltError::KeyHasNoSalt(key.clone()));
        };
        key_salt.salted_key_passphrase(srp_provider, key_pass)
    }
}
