use futures::future::join_all;

use crate::errors::AccountCryptoError;

use super::{
    APIPublicAddressKeyGroup, APIPublicAddressKeys, APIPublicKey, APIPublicKeySource,
    APIUnverifiedPublicAddressKeyGroup, KeyFlag, SignedKeyList,
};
use proton_crypto::{
    crypto::{AsPublicKeyRef, DataEncoding, PublicKey},
    keytransparency::{KTVerificationResult, KT_UNVERIFIED},
};

/// Represents a public address key of another user.
///
/// Public address keys are used to verify signatures or encrypt to addresses of other users.
/// Only contains public information and no secret key material.
#[derive(Debug, Clone)]
pub struct PublicAddressKey<Pub: PublicKey> {
    /// Origin of the public key.
    pub source: APIPublicKeySource,
    /// Key flags encoded in a bitmap.
    pub flags: KeyFlag,
    /// Is this is key marked as primary.
    pub primary: bool,
    /// The imported PGP provider public key.
    pub public_keys: Pub,
}

impl<Pub: PublicKey> AsPublicKeyRef<Pub> for PublicAddressKey<Pub> {
    fn as_public_key(&self) -> &Pub {
        &self.public_keys
    }
}

/// Represents imported address public keys that might have been verified with key transparency.
#[derive(Debug, Clone)]
pub struct PublicAddressKeyGroup<T: PublicKey> {
    pub keys: Vec<PublicAddressKey<T>>,
    pub signed_key_list: Option<SignedKeyList>,
    pub kt_verification: KTVerificationResult,
}

/// Represents imported address public keys that are externally provided and cannot support key transparency
#[derive(Debug, Clone)]
pub struct UnverifiedPublicAddressKeyGroup<T: PublicKey> {
    pub keys: Vec<PublicAddressKey<T>>,
}

impl<T: PublicKey> PublicAddressKeyGroup<T> {
    #[must_use]
    pub fn as_slice(&self) -> &[PublicAddressKey<T>] {
        self.keys.as_slice()
    }
}

impl<T: PublicKey> AsRef<[PublicAddressKey<T>]> for PublicAddressKeyGroup<T> {
    fn as_ref(&self) -> &[PublicAddressKey<T>] {
        self.as_slice()
    }
}

fn parse_keys_sync<T: proton_crypto::crypto::PGPProviderSync>(
    provider: &T,
    keys: &[APIPublicKey],
) -> Result<Vec<PublicAddressKey<<T>::PublicKey>>, AccountCryptoError> {
    let mut public_address_keys = Vec::with_capacity(keys.len());
    public_address_keys.extend(
        keys.iter()
            .map(|api_public_key| {
                provider
                    .public_key_import(api_public_key.public_key.as_bytes(), DataEncoding::Armor)
                    .map_err(AccountCryptoError::KeyImport)
                    .map(|public_key| PublicAddressKey {
                        source: api_public_key.source,
                        flags: api_public_key.flags,
                        primary: api_public_key.primary,
                        public_keys: public_key,
                    })
            })
            .collect::<Result<Vec<_>, AccountCryptoError>>()?,
    );
    Ok(public_address_keys)
}

async fn async_parse_keys<T: proton_crypto::crypto::PGPProviderAsync>(
    provider: &T,
    keys: &[APIPublicKey],
) -> Result<Vec<PublicAddressKey<<T>::PublicKey>>, AccountCryptoError> {
    let imported_keys_futures: Vec<_> = keys
        .iter()
        .map(|api_public_key| {
            provider
                .public_key_import_async(api_public_key.public_key.as_bytes(), DataEncoding::Armor)
        })
        .collect();
    let imported_keys: Vec<_> = join_all(imported_keys_futures).await;
    let public_address_keys = imported_keys
        .into_iter()
        .zip(keys)
        .map(|(imported_key_result, api_public_key)| {
            imported_key_result
                .map_err(AccountCryptoError::KeyImport)
                .map(|public_key| PublicAddressKey {
                    source: api_public_key.source,
                    flags: api_public_key.flags,
                    primary: api_public_key.primary,
                    public_keys: public_key,
                })
        })
        .collect::<Result<Vec<_>, AccountCryptoError>>()?;
    Ok(public_address_keys)
}

impl APIPublicAddressKeyGroup {
    /// Imports the public keys by decoding the pgp public keys with the PGP provider.
    ///
    /// Returns the successfully imported public keys.
    /// If the import fails for a public key, the public key is not included in the returned vector.
    pub fn import<T: proton_crypto::crypto::PGPProviderSync>(
        &self,
        provider: &T,
    ) -> Result<PublicAddressKeyGroup<T::PublicKey>, AccountCryptoError> {
        let public_address_keys = parse_keys_sync(provider, &self.keys)?;
        Ok(PublicAddressKeyGroup {
            keys: public_address_keys,
            signed_key_list: self.signed_key_list.clone(),
            kt_verification: KT_UNVERIFIED,
        })
    }
    /// Imports the public keys by decoding the pgp public keys with the PGP provider.
    ///
    /// Returns the successfully imported public keys.
    /// If the import fails for a public key, the public key is not included in the returned vector.
    pub async fn import_async<T: proton_crypto::crypto::PGPProviderAsync>(
        &self,
        provider: &T,
    ) -> Result<PublicAddressKeyGroup<T::PublicKey>, AccountCryptoError> {
        let public_address_keys = async_parse_keys(provider, &self.keys).await?;
        Ok(PublicAddressKeyGroup {
            keys: public_address_keys,
            signed_key_list: self.signed_key_list.clone(),
            kt_verification: KT_UNVERIFIED,
        })
    }
}

impl APIUnverifiedPublicAddressKeyGroup {
    /// Imports the public keys by decoding the pgp public keys with the PGP provider.
    ///
    /// Returns the successfully imported public keys.
    /// If the import fails for a public key, the public key is not included in the returned vector.
    pub fn import<T: proton_crypto::crypto::PGPProviderSync>(
        &self,
        provider: &T,
    ) -> Result<UnverifiedPublicAddressKeyGroup<T::PublicKey>, AccountCryptoError> {
        let public_address_keys = parse_keys_sync(provider, &self.keys)?;
        Ok(UnverifiedPublicAddressKeyGroup {
            keys: public_address_keys,
        })
    }
    /// Imports the public keys by decoding the pgp public keys with the PGP provider.
    ///
    /// Returns the successfully imported public keys.
    /// If the import fails for a public key, the public key is not included in the returned vector.
    pub async fn import_async<T: proton_crypto::crypto::PGPProviderAsync>(
        &self,
        provider: &T,
    ) -> Result<UnverifiedPublicAddressKeyGroup<T::PublicKey>, AccountCryptoError> {
        let public_address_keys = async_parse_keys(provider, &self.keys).await?;
        Ok(UnverifiedPublicAddressKeyGroup {
            keys: public_address_keys,
        })
    }
}

/// Represents imported public keys derived from [`APIPublicAddressKeys`](super::APIPublicAddressKeys).
#[derive(Debug, Clone)]
pub struct PublicAddressKeys<T: PublicKey> {
    /// Information about the internal address itself, if it exists. Since the SKL is mandatory, this will never be nullable.
    pub address: PublicAddressKeyGroup<T>,
    /// Information about the catch all address itself, if it exists. This can be null if the address keys are valid
    pub catch_all: Option<PublicAddressKeyGroup<T>>,
    /// Any other key that cannot be verified, such as Proton legacy keys or WKD.
    pub unverified: Option<UnverifiedPublicAddressKeyGroup<T>>,
    /// List of warnings to show to the user related to phishing and message routing.
    pub warnings: Vec<String>,
    /// True when domain has valid proton MX.
    pub proton_mx: bool,
    /// Tells whether this is an official Proton address.
    pub is_proton: bool,
}

impl APIPublicAddressKeys {
    /// Imports all keys with the PGP provider.
    pub fn import<T: proton_crypto::crypto::PGPProviderSync>(
        &self,
        provider: &T,
    ) -> Result<PublicAddressKeys<T::PublicKey>, AccountCryptoError> {
        let address_keys = self.address_keys.import(provider)?;
        let catch_all_keys = self
            .catch_all_keys
            .as_ref()
            .map_or(Ok(None), |key| key.import(provider).map(Some))?;
        let unverified_keys = self
            .unverified_keys
            .as_ref()
            .map_or(Ok(None), |key| key.import(provider).map(Some))?;
        Ok(PublicAddressKeys {
            address: address_keys,
            catch_all: catch_all_keys,
            unverified: unverified_keys,
            warnings: self.warnings.clone(),
            proton_mx: self.proton_mx,
            is_proton: self.is_proton,
        })
    }
    /// Imports all keys with the PGP provider asynchronously.
    pub async fn import_async<T: proton_crypto::crypto::PGPProviderAsync>(
        &self,
        provider: &T,
    ) -> Result<PublicAddressKeys<T::PublicKey>, AccountCryptoError> {
        let address_keys = self.address_keys.import_async(provider).await?;
        let catch_all_keys = match &self.catch_all_keys {
            Some(catch_all_keys) => Some(catch_all_keys.import_async(provider).await?),
            None => None,
        };
        let unverified_keys = match &self.unverified_keys {
            Some(unverified_keys) => Some(unverified_keys.import_async(provider).await?),
            None => None,
        };
        Ok(PublicAddressKeys {
            address: address_keys,
            catch_all: catch_all_keys,
            unverified: unverified_keys,
            warnings: self.warnings.clone(),
            proton_mx: self.proton_mx,
            is_proton: self.is_proton,
        })
    }
}
