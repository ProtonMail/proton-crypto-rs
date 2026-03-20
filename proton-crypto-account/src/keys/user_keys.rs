use std::{borrow::Cow, ops::Deref};

use futures::future::join_all;
use zeroize::Zeroizing;

use super::{ArmoredPrivateKey, KeyId, LockedKey, UnlockResult};
use crate::{
    crypto::generate_locked_pgp_key,
    errors::{AccountCryptoError, KeyError, KeySelectionError},
    salts::KeySecret,
};
use proton_crypto::crypto::{
    AccessKeyInfo, AsPublicKeyRef, DataEncoding, KeyGeneratorAlgorithm, PGPProviderAsync,
    PGPProviderSync, PrivateKey, PublicKey,
};
use serde::{Deserialize, Serialize};

pub const USER_KEY_USER_ID_EMAIL: &str = "not_for_email_use@domain.tld";

#[allow(type_alias_bounds)]
pub type UnlockedUserKey<Provider: PGPProviderSync> =
    DecryptedUserKey<<Provider>::PrivateKey, <Provider>::PublicKey>;

/// The unlocked user keys owned by a user.
#[allow(clippy::module_name_repetitions)]
pub struct UnlockedUserKeys<Provider: PGPProviderSync>(Vec<UnlockedUserKey<Provider>>);

impl<Provider: PGPProviderSync> Deref for UnlockedUserKeys<Provider> {
    type Target = Vec<UnlockedUserKey<Provider>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<Provider: PGPProviderSync> AsRef<Vec<UnlockedUserKey<Provider>>>
    for UnlockedUserKeys<Provider>
{
    fn as_ref(&self) -> &Vec<UnlockedUserKey<Provider>> {
        &self.0
    }
}

impl<Provider: PGPProviderSync> AsRef<[UnlockedUserKey<Provider>]> for UnlockedUserKeys<Provider> {
    fn as_ref(&self) -> &[UnlockedUserKey<Provider>] {
        &self.0
    }
}

impl<Provider: PGPProviderSync> AsMut<Vec<UnlockedUserKey<Provider>>>
    for UnlockedUserKeys<Provider>
{
    fn as_mut(&mut self) -> &mut Vec<UnlockedUserKey<Provider>> {
        &mut self.0
    }
}

impl<Provider: PGPProviderSync> AsMut<[UnlockedUserKey<Provider>]> for UnlockedUserKeys<Provider> {
    fn as_mut(&mut self) -> &mut [UnlockedUserKey<Provider>] {
        &mut self.0
    }
}

impl<Provider: PGPProviderSync> From<Vec<UnlockedUserKey<Provider>>>
    for UnlockedUserKeys<Provider>
{
    fn from(value: Vec<UnlockedUserKey<Provider>>) -> Self {
        Self(value)
    }
}

impl<Provider: PGPProviderSync> Clone for UnlockedUserKeys<Provider> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<Provider: PGPProviderSync> IntoIterator for UnlockedUserKeys<Provider> {
    type Item = UnlockedUserKey<Provider>;
    type IntoIter = std::vec::IntoIter<UnlockedUserKey<Provider>>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a, Provider: PGPProviderSync> IntoIterator for &'a UnlockedUserKeys<Provider> {
    type Item = &'a UnlockedUserKey<Provider>;
    type IntoIter = std::slice::Iter<'a, UnlockedUserKey<Provider>>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<'a, Provider: PGPProviderSync> IntoIterator for &'a mut UnlockedUserKeys<Provider> {
    type Item = &'a mut UnlockedUserKey<Provider>;
    type IntoIter = std::slice::IterMut<'a, UnlockedUserKey<Provider>>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter_mut()
    }
}

impl<Provider: PGPProviderSync> UnlockedUserKeys<Provider> {
    /// Retrieves the primary user key for encryption and signing operations
    /// for the user who owns these keys.
    #[must_use]
    pub fn primary(&self) -> Option<&UnlockedUserKey<Provider>> {
        // For now we treat the first key in the list as primary.
        // - This might change with key transparency in place.
        self.0.first()
    }

    /// Transforms the unlocked user keys into a user key selector.
    ///
    /// The selector can be use to seclect keys for `OpenPGP` operations.
    pub fn into_selector<'a>(self) -> UserKeySelector<'a, Provider>
    where
        Self: 'a,
        Provider: 'a,
    {
        UserKeySelector::new(self)
    }

    /// Creates a user key selector from the unlocked user keys.
    ///
    /// The selector can be use to seclect keys for `OpenPGP` operations.
    pub fn selector(&self) -> UserKeySelector<'_, Provider> {
        UserKeySelector::new_with_ref(self)
    }

    /// Serializes the unlocked user keys for recovery into a single binary blob.
    ///
    /// WARNING: This function encodes secret user material and should be used with caution.
    pub fn serialize_to_recovery_blob(
        &self,
        pgp_provider: &Provider,
    ) -> Result<Zeroizing<Vec<u8>>, AccountCryptoError> {
        let mut recovery_blob = Zeroizing::new(Vec::new());
        for key in &self.0 {
            let key_bytes = pgp_provider
                .private_key_export_unlocked(&key.private_key, DataEncoding::Bytes)
                .map_err(AccountCryptoError::KeyExport)?;
            recovery_blob.extend_from_slice(key_bytes.as_ref());
        }
        Ok(recovery_blob)
    }

    /// Deserializes the unlocked user keys from a recovery blob.
    ///
    /// The returned keys have fingerprints as key ids instead of the BE keys ids.
    /// To lock them with a new secret use [`LocalUserKey::relock_user_key`].
    pub fn deserialize_from_recovery_blob(
        pgp_provider: &Provider,
        recovery_blob: impl AsRef<[u8]>,
    ) -> Result<Self, AccountCryptoError> {
        let unlocked_keys = pgp_provider
            .private_keys_import_unlocked(recovery_blob.as_ref())
            .map_err(AccountCryptoError::KeyImport)?;
        let mut unlocked_user_keys = Vec::with_capacity(unlocked_keys.len());
        for unlocked_key in unlocked_keys {
            let public_key = pgp_provider
                .private_key_to_public_key(&unlocked_key)
                .map_err(AccountCryptoError::KeyImport)?;
            let id = unlocked_key.key_fingerprint();
            unlocked_user_keys.push(DecryptedUserKey {
                id: KeyId::from(id.to_string()),
                private_key: unlocked_key,
                public_key,
            });
        }
        Ok(Self(unlocked_user_keys))
    }

    /// Returns the number of unlocked user keys.
    pub fn num_keys(&self) -> usize {
        self.0.len()
    }
}

/// Represents locked user keys retrieved from the API.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
#[cfg_attr(feature = "facet", derive(facet::Facet))]
pub struct UserKeys(pub Vec<LockedKey>);

impl AsRef<[LockedKey]> for UserKeys {
    fn as_ref(&self) -> &[LockedKey] {
        &self.0
    }
}

impl UserKeys {
    pub fn new(v: impl IntoIterator<Item = LockedKey>) -> Self {
        Self(Vec::from_iter(v))
    }

    /// Unlocks/decrypts the locked keys with the provided `salted_password`.
    ///
    /// Returns the user keys that have been successfully decrypted with the
    /// provided password. If decryption fails for a key, the key is ignored.
    pub fn unlock<T: PGPProviderSync>(
        &self,
        provider: &T,
        salted_password: &KeySecret,
    ) -> UnlockResult<UnlockedUserKey<T>> {
        let mut failed_keys = Vec::new();
        let mut decrypted_address_keys: Vec<UnlockedUserKey<T>> = Vec::with_capacity(self.0.len());
        decrypted_address_keys.extend(self.0.iter().filter_map(|locked_key| {
            let decryption_result = provider.private_key_import(
                &locked_key.private_key.0,
                salted_password,
                DataEncoding::Armor,
            );
            let private_key = match decryption_result {
                Ok(key) => key,
                Err(err) => {
                    failed_keys.push(KeyError::Unlock(
                        locked_key.id.clone(),
                        AccountCryptoError::KeyImport(err),
                    ));
                    return None;
                }
            };
            let public_key = match provider.private_key_to_public_key(&private_key) {
                Ok(key) => key,
                Err(err) => {
                    failed_keys.push(KeyError::Unlock(
                        locked_key.id.clone(),
                        AccountCryptoError::TransformPublic(err),
                    ));
                    return None;
                }
            };
            Some(DecryptedUserKey {
                private_key,
                public_key,
                id: locked_key.id.clone(),
            })
        }));
        UnlockResult {
            unlocked_keys: decrypted_address_keys,
            failed: failed_keys,
        }
    }

    /// Unlocks/decrypts the locked keys with the `salted_password`.
    ///
    /// Returns the user keys that have been successfully decrypted with the
    /// provided password. If decryption fails, a key is ignored.
    pub async fn unlock_async<T: PGPProviderAsync>(
        &self,
        provider: &T,
        salted_password: &KeySecret,
    ) -> UnlockResult<UnlockedUserKey<T>> {
        let mut failed_keys = Vec::new();
        let mut decrypted_user_keys: Vec<DecryptedUserKey<T::PrivateKey, T::PublicKey>> =
            Vec::with_capacity(self.0.len());
        let mut decrypted_user_key_futures: Vec<_> = Vec::with_capacity(self.0.len());
        for locked_key in &self.0 {
            decrypted_user_key_futures.push(async {
                let decryption_result = provider
                    .private_key_import_async(
                        &locked_key.private_key.0,
                        salted_password,
                        DataEncoding::Armor,
                    )
                    .await;
                let private_key = decryption_result.map_err(|err| {
                    KeyError::Unlock(locked_key.id.clone(), AccountCryptoError::KeyImport(err))
                })?;
                let public_key = provider
                    .private_key_to_public_key_async(&private_key)
                    .await
                    .map_err(|err| {
                        KeyError::Unlock(
                            locked_key.id.clone(),
                            AccountCryptoError::TransformPublic(err),
                        )
                    })?;
                Ok(DecryptedUserKey {
                    private_key,
                    public_key,
                    id: locked_key.id.clone(),
                })
            });
        }
        let decrypted_user_key_results: Vec<_> = join_all(decrypted_user_key_futures).await;
        decrypted_user_keys.extend(decrypted_user_key_results.into_iter().filter_map(
            |decrypted_user_key_result| match decrypted_user_key_result {
                Ok(decrypted_user_key) => Some(decrypted_user_key),
                Err(err) => {
                    failed_keys.push(err);
                    None
                }
            },
        ));
        UnlockResult {
            unlocked_keys: decrypted_user_keys,
            failed: failed_keys,
        }
    }
}

/// Key selector for the unlocked user keys of an account.
pub struct UserKeySelector<'a, P: PGPProviderSync> {
    user_keys: Cow<'a, UnlockedUserKeys<P>>,
}

impl<'a, P: PGPProviderSync> UserKeySelector<'a, P> {
    pub fn new(user_keys: UnlockedUserKeys<P>) -> Self {
        Self {
            user_keys: Cow::Owned(user_keys),
        }
    }

    pub fn new_with_ref(user_keys: &'a UnlockedUserKeys<P>) -> Self {
        Self {
            user_keys: Cow::Borrowed(user_keys),
        }
    }

    /// Returns the primary user key of this account.
    pub fn primary(&self) -> Result<&UnlockedUserKey<P>, KeySelectionError> {
        self.user_keys
            .primary()
            .ok_or(KeySelectionError::NoPrimaryUserKey)
    }

    /// Returns the public key for encryption of this account.
    pub fn for_encryption(&self) -> Result<&P::PublicKey, KeySelectionError> {
        self.primary().map(AsPublicKeyRef::as_public_key)
    }

    /// Returns the private key for signing of this account.
    pub fn for_signing(&self) -> Result<&P::PrivateKey, KeySelectionError> {
        self.primary().map(AsRef::as_ref)
    }

    /// Returns the user keys for signature verification of this account.
    #[must_use]
    pub fn for_signature_verification(&self) -> &[UnlockedUserKey<P>] {
        &self.user_keys
    }

    /// Returns the user keys for decryption of this account.
    #[must_use]
    pub fn for_decryption(&self) -> &[UnlockedUserKey<P>] {
        &self.user_keys
    }

    /// Transform into the raw unlocked user keys.
    ///
    /// Only use this function if you absolutely need to access the raw unlocked user keys.
    #[must_use]
    pub fn into_raw_keys(self) -> UnlockedUserKeys<P> {
        self.user_keys.into_owned()
    }
}

impl<'a, P: PGPProviderSync> From<UnlockedUserKeys<P>> for UserKeySelector<'a, P>
where
    Self: 'a,
    P: 'a,
{
    fn from(user_keys: UnlockedUserKeys<P>) -> Self {
        Self::new(user_keys)
    }
}

impl<'a, P: PGPProviderSync> From<&'a UnlockedUserKeys<P>> for UserKeySelector<'a, P> {
    fn from(user_keys: &'a UnlockedUserKeys<P>) -> Self {
        Self::new_with_ref(user_keys)
    }
}

/// Represents a decrypted user key of a user.
///
/// Contains secret key material that must be protected.
#[derive(Debug, Clone)]
pub struct DecryptedUserKey<Priv: PrivateKey, Pub: PublicKey> {
    /// Proton key id.
    pub id: KeyId,
    /// PGP provider private key.
    pub private_key: Priv,
    /// PGP provider public key.
    pub public_key: Pub,
}

impl<Priv: PrivateKey, Pub: PublicKey> AsRef<Priv> for DecryptedUserKey<Priv, Pub> {
    fn as_ref(&self) -> &Priv {
        &self.private_key
    }
}

impl<Priv: PrivateKey, Pub: PublicKey> AsPublicKeyRef<Pub> for DecryptedUserKey<Priv, Pub> {
    fn as_public_key(&self) -> &Pub {
        &self.public_key
    }
}

/// Represents a locked user key locally generated but not yet synced with the backend.
pub struct LocalUserKey {
    /// The locked armored private key.
    pub private_key: ArmoredPrivateKey,
}

impl LocalUserKey {
    /// Generates a fresh user key and locks it with the provided salted password.
    ///
    /// To use the default key algorithm for the generated key, call with [`KeyGeneratorAlgorithm::default()`].
    ///
    /// # Errors
    /// - Key generation fails
    /// - Key locking fails
    ///
    /// # Example
    /// ```
    /// use proton_crypto::crypto::{KeyGeneratorAlgorithm, PGPProviderSync};
    /// use proton_crypto::{new_pgp_provider, new_srp_provider};
    /// use proton_crypto_account::salts::KeySalt;
    /// use proton_crypto_account::keys::LocalUserKey;
    ///
    /// let srp_provider = new_srp_provider();
    /// let pgp_provider = new_pgp_provider();
    /// let salt = KeySalt::generate();
    /// let key_secret = salt
    ///     .salted_key_passphrase(&srp_provider, "password".as_bytes())
    ///     .unwrap();
    /// let key = LocalUserKey::generate(&pgp_provider, KeyGeneratorAlgorithm::default(), &key_secret)
    ///     .expect("key generation failed");
    /// ```
    pub fn generate<Provider: PGPProviderSync>(
        pgp_provider: &Provider,
        algorithm: KeyGeneratorAlgorithm,
        salted_password: &KeySecret,
    ) -> Result<Self, AccountCryptoError> {
        generate_locked_pgp_key(
            pgp_provider,
            USER_KEY_USER_ID_EMAIL,
            USER_KEY_USER_ID_EMAIL,
            algorithm,
            salted_password,
        )
        .map(|private_key| LocalUserKey { private_key })
    }

    /// Lock an unlocked user key with a fresh secret.
    ///
    /// This needs to happen for example if the user changes its password.
    /// Since the key is locked with a new secret, it must be synced with the backend,
    /// and must be considered as local only.
    pub fn relock_user_key<Provider: PGPProviderSync>(
        pgp_provider: &Provider,
        unlocked_user_key: &UnlockedUserKey<Provider>,
        salted_password: &KeySecret,
    ) -> Result<Self, AccountCryptoError> {
        let private_key = pgp_provider
            .private_key_export(
                &unlocked_user_key.private_key,
                salted_password,
                DataEncoding::Armor,
            )
            .map(|key_bytes| String::from_utf8(key_bytes.as_ref().to_vec()))
            .map_err(|_err| AccountCryptoError::GenerateKeyArmor)? // For the CryptoError error
            .map_err(|_err| AccountCryptoError::GenerateKeyArmor) // For the FromUtf8 error
            .map(ArmoredPrivateKey)?;
        Ok(Self { private_key })
    }

    /// Unlocks the locally generated user key with the provided salted password.
    ///
    /// The key id is retrieved from the API upon registering the key.
    ///
    /// # Errors
    /// - If key unlock fails returns a [`AccountCryptoError::KeyImport`].
    pub fn unlock_and_assign_key_id<Provider: PGPProviderSync>(
        &self,
        pgp_provider: &Provider,
        key_id: KeyId,
        salted_password: &KeySecret,
    ) -> Result<UnlockedUserKey<Provider>, AccountCryptoError> {
        let private_key = pgp_provider
            .private_key_import(
                self.private_key.0.as_bytes(),
                salted_password,
                DataEncoding::Armor,
            )
            .map_err(AccountCryptoError::KeyImport)?;
        let public_key = pgp_provider
            .private_key_to_public_key(&private_key)
            .map_err(AccountCryptoError::KeyImport)?;
        Ok(DecryptedUserKey {
            id: key_id,
            private_key,
            public_key,
        })
    }
}
