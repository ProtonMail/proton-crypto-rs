use std::io;

use pgp::{
    armor::BlockType,
    crypto::{ecc_curve::ECCCurve, hash::HashAlgorithm, public_key::PublicKeyAlgorithm},
    packet::{self, KeyFlags},
    types::{KeyId, PkeskVersion},
};

use crate::{types::UnixTime, KeyIdList, PrettyKeyFlags};

pub type Result<T> = std::result::Result<T, Error>;

pub(crate) const ERROR_PREFIX: &str = "proton-rpgp";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Failed to use a key: {0}")]
    Keys(String),
}

#[derive(Debug, thiserror::Error)]
pub enum KeyCertificationSelectionError {
    #[error("No valid self-certification found, error per self-signature: {0}")]
    NoSelfCertification(ErrorList<SignatureError>),

    #[error("No valid user-id certification found, error per user-id: {0}")]
    NoIdentity(ErrorList<KeyCertificationSelectionError>),

    #[error("Invalid self-certification signature: {0}")]
    InvalidSignature(#[from] SignatureError),

    #[error("Latest user self-certification signature is revoked")]
    Revoked(Box<packet::Signature>),

    #[error(
        "Key is expired at unix time {date}, creation time {creation}, expiration: {expiration}"
    )]
    ExpiredKey {
        date: UnixTime,
        creation: UnixTime,
        expiration: UnixTime,
    },

    #[error("Key is in the future at unix time {date}, creation time {creation}")]
    FutureKey { date: UnixTime, creation: UnixTime },
}

#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    #[error("Signature has no creation time")]
    NoCreationTime,

    #[error("Signature does not specify a hash algorithm")]
    NoHash,

    #[error("Raw signature verification failed: {0}")]
    Verification(#[from] pgp::errors::Error),

    #[error("Signature uses an invalid hash according to the profile: {0:?}")]
    InvalidHash(Option<HashAlgorithm>),

    #[error("Failed to access signature config")]
    ConfigAccess,

    #[error("Signature has a creation time in the future: {0}")]
    FutureSignature(UnixTime),

    #[error("Signature is expired at unix time {date}, signature creation {creation}, expiration: {expiration}")]
    Expired {
        date: UnixTime,
        creation: UnixTime,
        expiration: UnixTime,
    },

    #[error("Signature with creation time {signature_date} is older than the verifying key with creation time {key_date}")]
    SignatureOlderThanKey {
        signature_date: UnixTime,
        key_date: UnixTime,
    },

    #[error("Signature has a non-accepted critical notation with name: {name}")]
    CriticalNotation { name: String },

    #[error("Signing subkey {0} is missing a cross-signature")]
    MissingCrossSignature(KeyId),
}

#[derive(Debug, thiserror::Error)]
pub enum MessageSignatureError {
    #[error("Message signature verification failed: {0}")]
    Failed(#[from] SignatureError),

    #[error("No key found to verify signature: {0}")]
    NoMatchingKey(ErrorList<KeySelectionError>),
}

#[derive(Debug, thiserror::Error)]
pub enum KeyOperationError {
    #[error("{ERROR_PREFIX}: Failed to lock private OpenPGP key with key id {0}: {1}")]
    Lock(KeyId, pgp::errors::Error),

    #[error("{ERROR_PREFIX}: Failed to unlock private OpenPGP key with key id {0}: {1}")]
    Unlock(KeyId, pgp::errors::Error),

    #[error("{ERROR_PREFIX}: Failed to encode OpenPGP key: {0}")]
    Encode(pgp::errors::Error),

    #[error("{ERROR_PREFIX}: Failed to decode OpenPGP key: {0}")]
    Decode(pgp::errors::Error),

    #[error("{ERROR_PREFIX}: Key is locked")]
    Locked,
}

#[derive(Debug, thiserror::Error)]
pub enum KeySelectionError {
    #[error(transparent)]
    KeySelfCertification(#[from] KeyCertificationSelectionError),

    #[error("Primary key {0} does not meet requirements: {1}")]
    PrimaryRequirement(KeyId, KeyRequirementError),

    #[error("Subkey {0} does not meet requirements: {1}")]
    SubkeyRequirement(KeyId, KeyRequirementError),

    #[error("Key {0} does not match requested key-id: {1}")]
    NoMatch(KeyId, KeyId),

    #[error("Key {0} does not match requested key-ids: {1}")]
    NoMatchList(KeyId, KeyIdList),

    #[error("No valid encryption key found in key with primary key-id {0}: {1}")]
    NoEncryptionKey(KeyId, ErrorList<KeySelectionError>),

    #[error("No valid verification keys found in key with primary key-id {0}: {1}")]
    NoVerificationKeys(KeyId, ErrorList<KeySelectionError>),

    #[error("No valid decryption keys found in key with primary key-id {0}: {1}")]
    NoDecryptionKeys(KeyId, ErrorList<KeySelectionError>),

    #[error("No valid signing key found in key with primary key-id {0}: {1}")]
    NoSigningKey(KeyId, ErrorList<KeySelectionError>),
}

#[derive(Debug, thiserror::Error)]
pub enum KeyRequirementError {
    #[error("Rejected public key algorithm: {0:?}")]
    WeakAlgorithm(PublicKeyAlgorithm),

    #[error("Rejected rsa public key algorithm: not enough bits got: {0} want {1}")]
    WeakRsaAlgorithm(usize, usize),

    #[error("Rejected ecc curve: {0:?}")]
    WeakEccAlgorithm(ECCCurve),

    #[error("Invalid legacy usage in v6 for curve: {0}")]
    MixedLegacyAlgorithms(ECCCurve),

    #[error("Invalid signing key usage flags: {0}")]
    InvalidSigningKeyFlags(PrettyKeyFlags),

    #[error("Invalid encryption key usage flags: {0}")]
    InvalidEncryptionKeyFlags(PrettyKeyFlags),

    #[error("Invalid algorithm for usage: {0:?}")]
    InvalidUsageAlgorithm(PublicKeyAlgorithm),
}

#[derive(Debug, thiserror::Error)]
pub enum DecryptionError {
    #[error("Unexpected locked key")]
    LockedKey,

    #[error("PKESK decryption failed: {0}")]
    Pkesk(#[from] pgp::errors::Error),

    #[error("Invalid PKESK version: {0:?}")]
    InvalidPkesk(PkeskVersion),
}

#[derive(Debug, thiserror::Error)]
pub enum EncryptionError {
    #[error("Failed to select encryption key: {0:?}")]
    EncryptionKeySelection(ErrorList<KeySelectionError>),
}

#[derive(Debug, thiserror::Error)]
pub enum FingerprintError {
    #[error("Failed to decode hex string: {0}")]
    HexDecode(#[from] hex::FromHexError),

    #[error("Invalid fingerprint length: {0}")]
    InvalidLength(usize),
}

#[derive(Debug, thiserror::Error)]
pub enum ArmorError {
    #[error("No armor header found")]
    DecodeHeader,

    #[error("Wronger header, got: {0} expected {1}")]
    DecodeWrongHeader(String, BlockType),

    #[error("Failed to decode armor due to io : {0}")]
    Decode(io::Error),
}

#[derive(Debug)]
pub struct ErrorList<E: std::error::Error>(pub Vec<E>);

impl<E: std::error::Error> std::fmt::Display for ErrorList<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut errors = self.0.iter();

        write!(f, "[")?;
        if let Some(first) = errors.next() {
            write!(f, "{first}")?;
            for err in errors {
                write!(f, ", {err}")?;
            }
        }
        write!(f, "]")
    }
}

impl<E: std::error::Error> std::error::Error for ErrorList<E> {}

impl<E: std::error::Error> From<Vec<E>> for ErrorList<E> {
    fn from(errors: Vec<E>) -> Self {
        Self(errors)
    }
}
