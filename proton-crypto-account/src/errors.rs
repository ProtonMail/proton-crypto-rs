use std::string::FromUtf8Error;
use std::{io::Error, str::Utf8Error};

use proton_crypto::crypto::OpenPGPFingerprint;
use proton_crypto::{crypto::VerificationError, CryptoError};

use crate::assert_send_static;
use crate::keys::{ContactType, KeyId};

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("Could not unlock key with passphrase {0}:{1}")]
    Unlock(KeyId, AccountCryptoError),
    #[error("Could not unlock key with token {0}:{1}")]
    UnlockToken(KeyId, AccountCryptoError),
    #[error("Missing encryption token, signature, or flags for key {0}")]
    MissingValue(KeyId),
}

#[derive(Debug, thiserror::Error)]
pub enum KeySelectionError {
    #[error("No valid primary user key found")]
    NoPrimaryUserKey,
    #[error("No valid primary address key found")]
    NoPrimaryAddressKey,
    #[error("Cannot transform address key to primary address key: {0}")]
    InvalidPrimaryTransform(KeyId),
}

#[derive(Debug, thiserror::Error)]
pub enum KeySerializationError {
    #[error("No valid address key found to export")]
    NoKeyFound,
    #[error("Failed to export key: {0}")]
    Export(String),
    #[error("Failed to import key: {0}")]
    Import(String),
}

#[derive(Debug, thiserror::Error)]
pub enum AccountCryptoError {
    #[error("Failed to verify signature for token {0}")]
    TokenVerification(#[from] VerificationError),
    #[error("Failed to decrypt token {0}")]
    TokenDecryption(CryptoError),
    #[error("Failed to import key {0}")]
    KeyImport(CryptoError),
    #[error("Failed to export key {0}")]
    KeyExport(CryptoError),
    #[error("Failed to export public key from private key {0}")]
    TransformPublic(CryptoError),
    #[error("Failed to generate a fresh key {0}")]
    GenerateKey(CryptoError),
    #[error("Failed to armor key")]
    GenerateKeyArmor,
    #[error("Failed to encrypt token {0}")]
    TokenEncryption(CryptoError),
    #[error("Failed to encode token {0}")]
    TokenEncoding(#[from] FromUtf8Error),
    #[error("Found a legacy key when expecting no legacy key")]
    UnexpectedLegacy,
}

#[derive(Debug, thiserror::Error)]
pub enum SKLError {
    #[error("Failed get primary address key")]
    NoPrimaryKey,
    #[error("Failed to parse the SKL data: {0}")]
    ParseError(String),
    #[error("Failed to verify SKL signature: {0}")]
    SignatureVerification(#[from] VerificationError),
    #[error("No SKL data present")]
    NoSKLData,
    #[error("Failed to encode SKL data to json: {0}")]
    JsonEncode(#[from] serde_json::Error),
    #[error("Failed to create signature: {0}")]
    SignatureCreation(CryptoError),
    #[error("Failed to convert binary data to UTF-8 string: {0}")]
    StringConversion(#[from] FromUtf8Error),
}

#[derive(Debug, thiserror::Error)]
pub enum CardCryptoError {
    #[error("Error decrypting card: {0}")]
    DecryptionError(CryptoError),
    #[error("Error encrypting card: {0}")]
    EncryptionError(CryptoError),
    #[error("Error signing card: {0}")]
    SigningError(CryptoError),
    #[error("Error writing card data to stream: {0}")]
    WriteError(Error),
    #[error("Error encoding data to string: {0}")]
    EncodingError(FromUtf8Error),
    #[error("Error verifying card signature: {0}")]
    SignatureVerificationError(#[from] VerificationError),
    #[error("No signature found for a signed card")]
    NoSignature,
    #[error("Failed to decode card as utf-8")]
    DecodeCard(#[from] Utf8Error),
}

#[derive(Debug, thiserror::Error)]
#[allow(clippy::module_name_repetitions)]
pub enum EncryptionPreferencesError {
    #[error("Internal user with no valid API keys")]
    InternalUserNoApiKeys,
    #[error("No primary address key for user owned address")]
    NoPrimaryKey,
    #[error(
        "Invalid selected key for {0} recipient with fingerprint {1} (obsolete: {2}, compromised: {3}, can encrypt: {4})"
    )]
    SelectedKeyCannotSend(ContactType, OpenPGPFingerprint, bool, bool, bool),
    /// This error is thrown if there are pinned keys, but none of the fingerprints of the pinned keys matches the fingerprint of one of the keys served by the API.
    ///
    /// In this case the client should force the user (via a modal)
    /// to trust one of the keys served by the API before sending any email.
    /// The provided API key fingerprint is a suggestion for which key to trust, but there may be others.
    #[error(
        "No matching API key found for pinned keys, user should add API key with fingerprint {0} to its contact"
    )]
    PinnedKeyNotProvidedByAPI(OpenPGPFingerprint),
    #[error(
        "Invalid pinned key with fingerprint {0} (obsolete: {1}, compromised: {2}, can encrypt: {3})"
    )]
    ExternalUserNoValidPinnedKey(OpenPGPFingerprint, bool, bool, bool),
    #[error("No valid key for encryption found in owned address keys")]
    ExternalUserNoValidApiKey,
}

#[derive(Debug, thiserror::Error)]
pub enum RecoverySecretError {
    #[error("Failed to encode signature as UTF-8")]
    SignatureEncoding,
    #[error("Failed to sign recovery secret: {0}")]
    SignatureCreation(CryptoError),
    #[error("Failed to encrypt recovery data: {0}")]
    Encrypt(CryptoError),
    #[error("Failed to decrypt recovery data: {0}")]
    Decrypt(CryptoError),
    #[error("Failed to verify recovery secret signature: {0}")]
    VerifySignature(VerificationError),
    #[error("Failed to export private key: {0}")]
    ExportKey(AccountCryptoError),
    #[error("Failed to import private key: {0}")]
    ImportKey(AccountCryptoError),
    #[error("No primary user key")]
    NoPrimary,
    #[error("No matching secret found to decrypt recovery data")]
    NoMatchingSecret,
}

// Ensure all error types to be Send and 'static.
assert_send_static!(
    CardCryptoError,
    SKLError,
    CryptoError,
    AccountCryptoError,
    KeyError,
    KeySerializationError,
    KeySelectionError,
    RecoverySecretError,
);
