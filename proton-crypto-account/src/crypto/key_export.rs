use proton_crypto::{
    crypto::{
        AsPublicKeyRef, DataEncoding, DetachedSignatureVariant, Encryptor, EncryptorSync,
        KeyGenerator, KeyGeneratorAlgorithm, KeyGeneratorSync, PGPProviderSync, SigningMode,
        WritingMode,
    },
    generate_secure_random_bytes,
};
use zeroize::Zeroizing;

use crate::{
    errors::AccountCryptoError,
    keys::{ArmoredPrivateKey, EncryptedKeyToken, KeyTokenSignature, UnlockedUserKey},
};

use super::{EXPECTED_ENCRYPTED_TOKEN_SIZE, TOKEN_SIZE};

/// Helper function to generate a fresh `OpenPGP` key and lock it.
pub fn generate_locked_pgp_key<Provider: PGPProviderSync>(
    pgp_provider: &Provider,
    name: &str,
    email: &str,
    algorithm: KeyGeneratorAlgorithm,
    passphrase: impl AsRef<[u8]>,
) -> Result<ArmoredPrivateKey, AccountCryptoError> {
    let private_key = pgp_provider
        .new_key_generator()
        .with_user_id(name, email)
        .with_algorithm(algorithm)
        .generate()
        .map_err(AccountCryptoError::GenerateKey)?;
    pgp_provider
        .private_key_export(&private_key, passphrase, DataEncoding::Armor)
        .map(|key_bytes| String::from_utf8(key_bytes.as_ref().to_vec()))
        .map_err(|_err| AccountCryptoError::GenerateKeyArmor)? // For the CryptoError error
        .map_err(|_err| AccountCryptoError::GenerateKeyArmor) // For the FromUtf8 error
        .map(ArmoredPrivateKey)
}

/// Helper function to generate a fresh `OpenPGP` key and lock it with a token encrypted
/// by the parent key.
pub fn generate_locked_pgp_key_with_token<Provider: PGPProviderSync>(
    pgp_provider: &Provider,
    name: &str,
    email: &str,
    algorithm: KeyGeneratorAlgorithm,
    parent_key: &UnlockedUserKey<Provider>,
    context: Option<&Provider::SigningContext>,
) -> Result<(ArmoredPrivateKey, EncryptedKeyToken, KeyTokenSignature), AccountCryptoError> {
    let (token, encrypted_token_type, token_signature_type) =
        generate_token_values(pgp_provider, parent_key, context)?;
    let key = generate_locked_pgp_key(pgp_provider, name, email, algorithm, &token)?;
    Ok((key, encrypted_token_type, token_signature_type))
}

// Helper function to generate a fresh token and encrypt/sign it.
pub fn generate_token_values<Provider: PGPProviderSync>(
    pgp_provider: &Provider,
    parent_key: &UnlockedUserKey<Provider>,
    context: Option<&Provider::SigningContext>,
) -> Result<(Zeroizing<String>, EncryptedKeyToken, KeyTokenSignature), AccountCryptoError> {
    let token = generate_random_token();
    // Encrypt/sign it with the parent user key.
    let mut encrypted_token: Vec<u8> = Vec::with_capacity(EXPECTED_ENCRYPTED_TOKEN_SIZE);
    let mut encryptor = pgp_provider
        .new_encryptor()
        .with_encryption_key(parent_key.as_public_key())
        .with_signing_key(parent_key.as_ref());
    if let Some(enc_context) = context {
        encryptor = encryptor.with_signing_context(enc_context);
    }
    let detached_data = encryptor
        .encrypt_to_writer(
            token.as_bytes(),
            DataEncoding::Armor,
            SigningMode::Detached(DetachedSignatureVariant::Plaintext),
            WritingMode::All,
            &mut encrypted_token,
        )
        .map_err(AccountCryptoError::TokenEncryption)?;
    let detached_signature = detached_data
        .try_into_detached_signature()
        .map_err(AccountCryptoError::TokenEncryption)?;
    // Interpret the outputs as UTF-8 encoded.
    let encrypted_token_type = EncryptedKeyToken(String::from_utf8(encrypted_token)?);
    let token_signature_type = KeyTokenSignature(String::from_utf8(detached_signature)?);
    Ok((token, encrypted_token_type, token_signature_type))
}

fn generate_random_token() -> Zeroizing<String> {
    let token: Zeroizing<[u8; TOKEN_SIZE]> = Zeroizing::new(generate_secure_random_bytes());
    Zeroizing::new(hex::encode(token))
}
