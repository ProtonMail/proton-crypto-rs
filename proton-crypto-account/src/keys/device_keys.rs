use proton_crypto::crypto::{
    AsPublicKeyRef, DataEncoding, KeyGenerator, KeyGeneratorAlgorithm, KeyGeneratorSync,
    PGPProviderSync, PrivateKey, PublicKey,
};
use std::fmt::Debug;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::errors::{AccountCryptoError, KeySerializationError};

const DEVICE_KEY_USER_ID: &str = "not_for_email_use@domain.tld";
const DEVICE_KEY_ALGORITHM: KeyGeneratorAlgorithm = KeyGeneratorAlgorithm::ECC;

/// Represents a device-local `OpenPGP` key.
///
/// This key is not synchronized with the backend and remains stored only on the device.
/// It can be used, for example, to encrypt and decrypt push notifications.
#[derive(Debug, Clone)]
pub struct PGPDeviceKey<Priv: PrivateKey, Pub: PublicKey> {
    pub private_key: Priv,
    pub public_key: Pub,
}

impl<Priv: PrivateKey, Pub: PublicKey> AsRef<Priv> for PGPDeviceKey<Priv, Pub> {
    fn as_ref(&self) -> &Priv {
        &self.private_key
    }
}

impl<Priv: PrivateKey, Pub: PublicKey> AsPublicKeyRef<Pub> for PGPDeviceKey<Priv, Pub> {
    fn as_public_key(&self) -> &Pub {
        &self.public_key
    }
}

/// A serialized device key containing secret key material.
///
/// Memory is zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SensitiveDeviceKeyBytes(Vec<u8>);

impl SensitiveDeviceKeyBytes {
    /// Creates a serialized device key from a byte vector.
    #[must_use]
    pub fn new(data: Vec<u8>) -> Self {
        SensitiveDeviceKeyBytes(data)
    }

    /// Returns a slice of the serialized device key in bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl AsRef<[u8]> for SensitiveDeviceKeyBytes {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl Debug for SensitiveDeviceKeyBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretDeviceKeyBytes: [CONFIDENTIAL]")
    }
}

impl<Priv: PrivateKey, Pub: PublicKey> PGPDeviceKey<Priv, Pub> {
    /// Generates a fresh device key.
    pub fn generate<Provider>(pgp_provider: &Provider) -> Result<Self, AccountCryptoError>
    where
        Provider: PGPProviderSync<PublicKey = Pub, PrivateKey = Priv>,
    {
        let private_key = pgp_provider
            .new_key_generator()
            .with_user_id(DEVICE_KEY_USER_ID, DEVICE_KEY_USER_ID)
            .with_algorithm(DEVICE_KEY_ALGORITHM)
            .generate()
            .map_err(AccountCryptoError::GenerateKey)?;
        let public_key = pgp_provider
            .private_key_to_public_key(&private_key)
            .map_err(AccountCryptoError::GenerateKey)?;
        Ok(Self {
            private_key,
            public_key,
        })
    }

    /// Exports the public key in `OpenPGP` armored format to be shared with the backend.
    ///
    /// The returned key has the form:
    /// ``````skip
    /// -----BEGIN PGP PUBLIC KEY BLOCK-----
    ///
    /// mDMEWx6DORYJKwYBBAHaRw8BAQdABJa6xH6/nQoBQtVuqaenNLrKvkJ5gniGtBH3
    /// tsK...
    /// -----END PGP PUBLIC KEY BLOCK-----
    /// ```
    pub fn export_public_key<Provider>(
        &self,
        pgp_provider: &Provider,
    ) -> Result<String, KeySerializationError>
    where
        Provider: PGPProviderSync<PublicKey = Pub>,
    {
        let public_key_bytes = pgp_provider
            .public_key_export(&self.public_key, DataEncoding::Armor)
            .map_err(|err| KeySerializationError::Export(err.to_string()))?;
        String::from_utf8(public_key_bytes.as_ref().to_vec())
            .map_err(|_| KeySerializationError::Export("Failed to convert to utf-8".to_owned()))
    }

    /// Serializes the device key for secure storage, such as for a key store.
    ///
    /// SECURITY WARNING: The serialized key is not encrypted. Treat it as sensitive data
    /// and avoid storing it in unprotected environments.
    pub fn serialize_to_secure_storage<Provider>(
        &self,
        pgp_provider: &Provider,
    ) -> Result<SensitiveDeviceKeyBytes, KeySerializationError>
    where
        Provider: PGPProviderSync<PrivateKey = Priv>,
    {
        pgp_provider
            .private_key_export_unlocked(&self.private_key, DataEncoding::Bytes)
            .map(|key_bytes| SensitiveDeviceKeyBytes(key_bytes.as_ref().to_vec()))
            .map_err(|err| KeySerializationError::Export(err.to_string()))
    }

    /// Deserializes the device key from a secure storage.
    pub fn deserialize_from_secure_storage<Provider>(
        pgp_provider: &Provider,
        key_data: &[u8],
    ) -> Result<Self, KeySerializationError>
    where
        Provider: PGPProviderSync<PublicKey = Pub, PrivateKey = Priv>,
    {
        let private_key = pgp_provider
            .private_key_import_unlocked(key_data, DataEncoding::Bytes)
            .map_err(|err| KeySerializationError::Import(err.to_string()))?;
        let public_key = pgp_provider
            .private_key_to_public_key(&private_key)
            .map_err(|err| KeySerializationError::Import(err.to_string()))?;
        Ok(Self {
            private_key,
            public_key,
        })
    }
}
