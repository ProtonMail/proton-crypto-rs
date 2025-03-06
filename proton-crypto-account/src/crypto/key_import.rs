use proton_crypto::crypto::{
    AccessKeyInfo, AsPublicKeyRef, DataEncoding, Decryptor, DecryptorAsync, DecryptorSync,
    DetachedSignatureVariant, PGPProviderAsync, PGPProviderSync, VerifiedData,
};
use zeroize::Zeroizing;

use crate::{
    errors::{AccountCryptoError, KeyError},
    keys::{
        ArmoredPrivateKey, DecryptedAddressKey, EncryptedKeyToken, KeyTokenSignature, LockedKey,
        UnlockedAddressKey,
    },
    salts::KeySecret,
};

/// Decrypts a token associated with key to unlock it.
///
/// Decrypts and verifies the token with the provided keys.
/// If signature verification fails, it returns an error.
pub fn decrypt_key_token<Prov: PGPProviderSync>(
    provider: &Prov,
    token: &EncryptedKeyToken,
    signature: &KeyTokenSignature,
    decryption_keys: &[impl AsRef<Prov::PrivateKey>],
    verification_keys: &[impl AsPublicKeyRef<Prov::PublicKey>],
    verification_context: Option<&Prov::VerificationContext>,
) -> Result<Zeroizing<Vec<u8>>, AccountCryptoError> {
    let mut decryptor = provider
        .new_decryptor()
        .with_decryption_key_refs(decryption_keys)
        .with_verification_key_refs(verification_keys)
        .with_detached_signature_ref(
            signature.0.as_bytes(),
            DetachedSignatureVariant::Plaintext,
            true,
        );
    if let Some(context) = verification_context {
        decryptor = decryptor.with_verification_context(context);
    }
    let verified_data = decryptor
        .decrypt(token.0.as_bytes(), DataEncoding::Armor)
        .map_err(AccountCryptoError::TokenDecryption)?;
    verified_data.verification_result()?;
    Ok(Zeroizing::new(verified_data.into_vec()))
}

/// Import a PGP private key that unlocks with an encrypted token from other keys.
///
/// Decrypts the encrypted token with the provided keys,
/// unlocks the imported key with the decrypted token, and verifies that signature over the token is valid.
pub fn import_key_with_token<Prov: PGPProviderSync>(
    provider: &Prov,
    private_key: &ArmoredPrivateKey,
    token: &EncryptedKeyToken,
    signature: &KeyTokenSignature,
    decryption_keys: &[impl AsRef<Prov::PrivateKey>],
    verification_keys: &[impl AsPublicKeyRef<Prov::PublicKey>],
    verification_context: Option<&Prov::VerificationContext>,
) -> Result<(Prov::PrivateKey, Prov::PublicKey), AccountCryptoError> {
    let decrypted_token = decrypt_key_token(
        provider,
        token,
        signature,
        decryption_keys,
        verification_keys,
        verification_context,
    )?;
    import_key_with_passphrase(provider, private_key, decrypted_token)
}

/// Helper function to import an `OpenPGP` private key secured with a passphrase.
pub fn import_key_with_passphrase<Prov: PGPProviderSync>(
    provider: &Prov,
    private_key: &ArmoredPrivateKey,
    passphrase: impl AsRef<[u8]>,
) -> Result<(Prov::PrivateKey, Prov::PublicKey), AccountCryptoError> {
    let private_key = provider
        .private_key_import(private_key.0.as_bytes(), passphrase, DataEncoding::Armor)
        .map_err(AccountCryptoError::KeyImport)?;
    let public_key = provider
        .private_key_to_public_key(&private_key)
        .map_err(AccountCryptoError::TransformPublic)?;
    Ok((private_key, public_key))
}

/// Decrypts an encrypted token.
pub async fn decrypt_key_token_async<Prov: PGPProviderAsync>(
    provider: &Prov,
    token: &EncryptedKeyToken,
    signature: &KeyTokenSignature,
    decryption_keys: &[impl AsRef<Prov::PrivateKey>],
    verification_keys: &[impl AsPublicKeyRef<Prov::PublicKey>],
    verification_context: Option<Prov::VerificationContext>,
) -> Result<Vec<u8>, AccountCryptoError> {
    let mut decryptor = provider
        .new_decryptor_async()
        .with_decryption_key_refs(decryption_keys)
        .with_verification_key_refs(verification_keys)
        .with_detached_signature_ref(
            signature.0.as_bytes(),
            DetachedSignatureVariant::Plaintext,
            true,
        );
    if let Some(context) = &verification_context {
        decryptor = decryptor.with_verification_context(context);
    }
    let verified_data = decryptor
        .decrypt_async(token.0.as_bytes(), DataEncoding::Armor)
        .await
        .map_err(AccountCryptoError::TokenDecryption)?;
    verified_data.verification_result()?;
    Ok(verified_data.into_vec())
}

/// Import a PGP private key that unlocks with an encrypted token from other keys.
///
/// Decrypts the encrypted token with the provided keys,
/// unlocks the imported key with the decrypted token, and verifies that signature over the token is valid.
pub async fn import_key_with_token_async<Prov: PGPProviderAsync>(
    provider: &Prov,
    private_key: &ArmoredPrivateKey,
    token: &EncryptedKeyToken,
    signature: &KeyTokenSignature,
    decryption_keys: &[impl AsRef<Prov::PrivateKey>],
    verification_keys: &[impl AsPublicKeyRef<Prov::PublicKey>],
    verification_context: Option<Prov::VerificationContext>,
) -> Result<(Prov::PrivateKey, Prov::PublicKey), AccountCryptoError> {
    let decrypted_token = decrypt_key_token_async(
        provider,
        token,
        signature,
        decryption_keys,
        verification_keys,
        verification_context,
    )
    .await?;
    import_key_with_passphrase_async(provider, private_key, decrypted_token).await
}

/// Helper function to import an `OpenPGP` private key with a passphrase.
pub async fn import_key_with_passphrase_async<Prov: PGPProviderAsync>(
    provider: &Prov,
    private_key: &ArmoredPrivateKey,
    passphrase: impl AsRef<[u8]>,
) -> Result<(Prov::PrivateKey, Prov::PublicKey), AccountCryptoError> {
    let private_key = provider
        .private_key_import_async(private_key.0.as_bytes(), passphrase, DataEncoding::Armor)
        .await
        .map_err(AccountCryptoError::KeyImport)?;
    let public_key = provider
        .private_key_to_public_key_async(&private_key)
        .await
        .map_err(AccountCryptoError::TransformPublic)?;
    Ok((private_key, public_key))
}

/// Helper function to unlock a legacy key.
pub fn unlock_legacy_key<Provider: PGPProviderSync>(
    pgp_provider: &Provider,
    locked_key: &LockedKey,
    passphrase: Option<&KeySecret>,
) -> Result<UnlockedAddressKey<Provider>, KeyError> {
    let (Some(flags), Some(key_secret)) = (&locked_key.flags, passphrase) else {
        return Err(KeyError::MissingValue(locked_key.id.clone()));
    };
    let (private_key, public_key) =
        import_key_with_passphrase(pgp_provider, &locked_key.private_key, key_secret)
            .map_err(|err| KeyError::Unlock(locked_key.id.clone(), err))?;

    let is_v6 = private_key.version() == 6;
    Ok(DecryptedAddressKey {
        private_key,
        public_key,
        id: locked_key.id.clone(),
        flags: *flags,
        primary: locked_key.primary,
        is_v6,
    })
}

/// Helper function to unlock a legacy key.
pub async fn unlock_legacy_key_async<Provider: PGPProviderAsync>(
    pgp_provider: &Provider,
    locked_key: &LockedKey,
    passphrase: Option<&KeySecret>,
) -> Result<UnlockedAddressKey<Provider>, KeyError> {
    let (Some(flags), Some(key_secret)) = (&locked_key.flags, passphrase) else {
        return Err(KeyError::MissingValue(locked_key.id.clone()));
    };
    let (private_key, public_key) =
        import_key_with_passphrase_async(pgp_provider, &locked_key.private_key, key_secret)
            .await
            .map_err(|err| KeyError::Unlock(locked_key.id.clone(), err))?;

    let is_v6 = private_key.version() == 6;
    Ok(DecryptedAddressKey {
        private_key,
        public_key,
        id: locked_key.id.clone(),
        flags: *flags,
        primary: locked_key.primary,
        is_v6,
    })
}
