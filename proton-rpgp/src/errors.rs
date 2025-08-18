use std::io;

use pgp::{
    armor::BlockType,
    crypto::{ecc_curve::ECCCurve, hash::HashAlgorithm, public_key::PublicKeyAlgorithm},
    packet::{self},
    types::{KeyId, PkeskVersion},
};

use crate::{
    types::UnixTime, GenericKeyIdentifier, GenericKeyIdentifierList, PrettyKeyFlags,
    VerificationContext,
};

pub type Result<T> = std::result::Result<T, Error>;

pub(crate) const ERROR_PREFIX: &str = "proton-rpgp";

/// TODO(CRYPTO-293): Unify error handling with a single error for the library
/// and unify error messages.
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
pub enum SignatureContextError {
    #[error("Signature context is required but is not provided: {0}")]
    MissingContext(VerificationContext),

    #[error("Signature context {0} does not match the verification context: {0}")]
    WrongContext(String, VerificationContext),

    #[error("Signature has multiple context notations: {0:?}")]
    MultipleContexts(Vec<String>),

    #[error("Signature contains a critical context \"{0}\", but no matching verification context was provided")]
    CriticialContext(String),
}

#[derive(Debug, thiserror::Error)]
pub enum MessageSignatureError {
    #[error("Message signature verification failed: {0}")]
    Failed(#[from] SignatureError),

    #[error("No key found to verify signature: {0}")]
    NoMatchingKey(ErrorList<KeySelectionError>),

    #[error(transparent)]
    Context(SignatureContextError),
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

    #[error("Key {0} does not match requested key-id: {1}")]
    NoMatchDecryption(KeyId, GenericKeyIdentifier),

    #[error("Key {0} does not match requested key-ids: {1}")]
    NoMatchList(GenericKeyIdentifier, GenericKeyIdentifierList),

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

    #[error("Rejected RSA public key algorithm: insufficient bits (got: {0}, required: {1})")]
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
pub enum KeyGenerationError {
    #[error("No user id provided")]
    NoUserId,

    #[error("Failed to generate subkey: {0}")]
    SubkeyGeneration(#[from] pgp::composed::SubkeyParamsBuilderError),

    #[error("Failed to perpare primary key: {0}")]
    PrimaryKeyPreparation(#[from] pgp::composed::SecretKeyParamsBuilderError),

    #[error("Failed to generate key: {0}")]
    Generation(#[from] pgp::errors::Error),

    #[error("Failed to self-sign key: {0}")]
    Signing(pgp::errors::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum EncryptionError {
    #[error("Failed to select encryption key: {0}")]
    EncryptionKeySelection(#[from] KeySelectionError),

    #[error("Failed to select signing key in encryption: {0}")]
    SigningKeySelection(KeySelectionError),

    #[error("Failed to encrypt session key with a public key: {0}")]
    PkeskEncryption(pgp::errors::Error),

    #[error("Missing algorithm in session key to encrypt key packet")]
    KeyPacketEncryptionNoAlgorithm,

    #[error("Failed to encrypt session key with a passphrase: {0}")]
    SkeskEncryption(pgp::errors::Error),

    #[error("Failed to encrypt or sign data: {0}")]
    DataEncryption(pgp::errors::Error),

    #[error("Failed to sign data before encryption: {0}")]
    Signing(#[from] SignError),

    #[error("Not supported: {0}")]
    NotSupported(String),

    #[error("Missing encryption tools: no encryption keys or passphrases provided")]
    MissingEncryptionTools,
}

#[derive(Debug, thiserror::Error)]
pub enum DecryptionError {
    #[error("Unexpected locked key")]
    LockedKey,

    #[error("No encrypted data found")]
    UnexpectedPlaintext,

    #[error("Message is not encrypted")]
    NoEncryption,

    #[error("Failed to process message before or after decryption: {0}")]
    MessageProcessing(#[from] MessageProcessingError),

    #[error("PKESK decryption for key {0} failed: {1}")]
    PkeskDecryption(Box<GenericKeyIdentifier>, ErrorList<DecryptionError>),

    #[error("SKESK decryption with a password failed: {0}")]
    SkeskDecryption(pgp::errors::Error),

    #[error(transparent)]
    SinglePkeskDecryption(#[from] PkeskDecryptionError),

    #[error("Invalid PKESK packet without a key-id or issuer")]
    PkeskNoIssuer,

    #[error("No matching key found for PKESK using key identifier {0}")]
    PkeskNoMatchingKey(Box<GenericKeyIdentifier>),

    #[error("Failed to decrypt any session key: {0}")]
    SessionKeyDecryption(ErrorList<DecryptionError>),

    #[error("Failed to decrypt with session key: {0}")]
    InvalidSessionKey(#[from] pgp::errors::Error),

    #[error("Failed to select verified decryption keys for id {0}: {1}")]
    KeySelection(Box<GenericKeyIdentifier>, KeySelectionError),

    #[error("No valid key packets found")]
    NoKeyPackets,
}

#[derive(Debug, thiserror::Error)]
pub enum VerifyMessageError {
    #[error("Failed to verify message: {0}")]
    MessageProcessing(#[from] MessageProcessingError),
}

#[derive(Debug, thiserror::Error)]
pub enum MessageProcessingError {
    #[error("Failed to parse message: {0}")]
    MessageParsing(pgp::errors::Error),

    #[error("Cannot process message: the message is encrypted")]
    Encrypted,

    #[error("Failed to decompress message: {0}")]
    Decompression(pgp::errors::Error),

    #[error("Multiple compression layers found in message")]
    Compression,

    #[error(transparent)]
    TextSanitization(#[from] TextSanitizationError),

    #[error("Failed to read data: {0}")]
    Read(#[from] io::Error),

    #[error("Message is not fully read for verification")]
    NotFullyRead,
}

#[derive(Debug, thiserror::Error)]
pub enum PkeskDecryptionError {
    #[error("Unexpected locked key")]
    LockedKey,

    #[error("PKESK decryption failed: {0}")]
    Pkesk(#[from] pgp::errors::Error),

    #[error("Invalid PKESK version: {0:?}")]
    InvalidPkesk(PkeskVersion),
}

#[derive(Debug, thiserror::Error)]
pub enum SignError {
    #[error("{ERROR_PREFIX}: Failed to set data mode: {0}")]
    DataMode(pgp::errors::Error),

    #[error("{ERROR_PREFIX}: Failed to serialize signatures: {0}")]
    Serialize(pgp::errors::Error),

    #[error("{ERROR_PREFIX}: Failed to select signing key: {0}")]
    KeySelection(#[from] KeySelectionError),

    #[error("{ERROR_PREFIX}: Invalid signing key version")]
    InvalidKeyVersion,

    #[error("{ERROR_PREFIX}: {0}")]
    HashAlgorithm(#[from] SignHashSelectionError),

    #[error("{ERROR_PREFIX}: Failed to sign data: {0}")]
    Sign(pgp::errors::Error),

    #[error("{ERROR_PREFIX}: Invalid input encoding for text signature: {0}")]
    InvalidInputData(#[from] std::str::Utf8Error),

    #[error("{ERROR_PREFIX}: Invalid input encoding for text signature: {0}")]
    InvalidInputDataLineEnding(#[from] io::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum SignHashSelectionError {
    #[error("Failed to load valid primary self-certification for hash selection: {0}")]
    PrimaryCertification(#[from] KeyCertificationSelectionError),

    #[error("Failed to select hash algorithm")]
    HashAlgorithm,
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

    #[error("Wrong header, got: {0} expected {1}")]
    DecodeWrongHeader(String, BlockType),

    #[error("Failed to decode armor due to io: {0}")]
    Decode(io::Error),

    #[error("Failed to armor: {0}")]
    Encode(pgp::errors::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum PgpMessageError {
    #[error("Failed to split encrypted message into key and data packets: {0}")]
    ParseSplit(pgp::errors::Error),

    #[error("Non expected packet type found while splitting encrypted OpenPGP message")]
    NonExpectedPacketSplit,

    #[error("Failed to armor encrypted OpenPGP message: {0}")]
    Armor(#[from] ArmorError),
}

#[derive(Debug, thiserror::Error)]
pub enum TextSanitizationError {
    #[error("Failed to normalize line endings or encode as utf-8: {0}")]
    Normalization(#[from] io::Error),
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
