//! API to perform PGP operations.
//!
//! This module provides API traits for encrypting, decrypting, signing, and verifying
//! `OpenPGP` messages. For each operation it provides an async and sync option.
//! The top level trait to interact with `OpenPGP` is the `PGPProvider` with its respective sync `PGPProviderSync` and
//! async `PGPProviderAsync` version. The provider allows to create a builder for each operation above:
//! - `Encryptor` is a builder for encrypting/signing data
//! - `Decryptor` is a builder for decrypting/verifying data
//! - `Signer` is a builder for signing data
//! - `Verifier` is a builder to verify data
//!
//! The provider further provides various utility functions such as import/export `OpenPGP` keys and other `OpenPGP` utility.

use std::{
    fmt::{Display, Formatter},
    future::Future,
};

use crate::lowercase_string_id;

use serde::{Deserialize, Serialize};

mod decrypt;

pub use decrypt::*;

mod encrypt;
pub use encrypt::*;
mod sign;
pub use sign::*;
mod verify;
pub use verify::*;
mod keys;
pub use keys::*;
mod armor;
pub use armor::*;

/// `PGPProvider` provides access to an `OpenPGP` implementation.
pub trait PGPProvider: Send + Sync {
    /// An `OpenPGP` session key type.
    type SessionKey: SessionKey;

    /// An `OpenPGP` private key type.
    type PrivateKey: PrivateKey;

    /// An `OpenPGP` public key type.
    type PublicKey: PublicKey;

    /// Type for a signature context to be added to a `OpenPGP` signature.
    type SigningContext: SigningContext;

    /// Type for checking a context in a `OpenPGP` signature.
    type VerificationContext: VerificationContext;

    /// Type for an encrypted `OpenPGP` message.
    type PGPMessage: PGPMessage;

    /// Type for data that might included an `OpenPGP` signature verification result.
    type VerifiedData: VerifiedData;

    /// Creates a new signing context.
    ///
    /// Creates a `SigningContext` for the given string `value`.
    /// `is_critical`indicates if the verification side must check the
    /// context or if the context is optional.
    ///
    /// A `SigningContext` allows to specify that a signature must have been generated
    /// for a specified context (i.e., a string value). In signature creation, the context
    /// is added to the signature's notation data, and marked with a critical or not critical flag.
    /// On the verification side the context of a signature can be checked.
    /// For example, if app A uses a context `a` and app B uses a context `b` for its signatures, an
    /// adversary cannot misuse a signature from app A in app B, since each App checks the custom
    /// signature context on signature verification.
    fn new_signing_context(&self, value: String, is_critical: bool) -> Self::SigningContext;

    /// Creates a new verification context.
    ///
    /// A `VerificationContext` allows to specify that a signature must have been generated
    /// for a specified context (i.e., string `value`).
    /// The `value` is checked against the signature's notation data.
    /// If `is_required` is false, the signature is allowed to have no context set.
    /// If `required_after` is != 0, the signature is allowed to have no context set if it
    /// was created before the unix time set in `required_after`.
    fn new_verification_context(
        &self,
        value: String,
        is_required: bool,
        required_after_unix: UnixTimestamp,
    ) -> Self::VerificationContext;

    /// Returns an empty list of PGP public keys for this provider.
    fn empty_public_keys(&self) -> Vec<Self::PublicKey> {
        Vec::new()
    }

    /// Returns an empty list of PGP private keys for this provider.
    fn empty_private_keys(&self) -> Vec<Self::PrivateKey> {
        Vec::new()
    }
}

/// `PGPProviderSync` provides a synchronous API for `OpenPGP` operations.
pub trait PGPProviderSync: PGPProvider {
    /// Builder for encryption operations.
    type Encryptor<'a>: EncryptorSync<
        'a,
        SessionKey = Self::SessionKey,
        PrivateKey = Self::PrivateKey,
        PublicKey = Self::PublicKey,
        SigningContext = Self::SigningContext,
        PGPMessage = Self::PGPMessage,
    >
    where
        Self: 'a;

    /// Builder for decryption operations.
    type Decryptor<'a>: DecryptorSync<
        'a,
        SessionKey = Self::SessionKey,
        PrivateKey = Self::PrivateKey,
        PublicKey = Self::PublicKey,
        VerificationContext = Self::VerificationContext,
        VerifiedData = Self::VerifiedData,
    >
    where
        Self: 'a;

    /// Builder for sign operations.
    type Signer<'a>: SignerSync<
        'a,
        PrivateKey = Self::PrivateKey,
        SigningContext = Self::SigningContext,
    >
    where
        Self: 'a;

    /// Builder for signature verify operations.
    type Verifier<'a>: VerifierSync<
        'a,
        PublicKey = Self::PublicKey,
        VerificationContext = Self::VerificationContext,
        VerifiedData = Self::VerifiedData,
    >
    where
        Self: 'a;

    /// Type for armor operations
    type Armorer: ArmorerSync;

    type KeyGenerator: KeyGeneratorSync<Self::PrivateKey>;

    /// Generates a fresh session key for the given algorithm.
    ///
    /// The session key is generated from a cryptographically secure random source.
    fn session_key_generate(
        &self,
        algorithm: SessionKeyAlgorithm,
    ) -> crate::Result<Self::SessionKey>;

    /// Import a serialized session key.
    fn session_key_import(
        &self,
        data: impl AsRef<[u8]>,
        algorithm: SessionKeyAlgorithm,
    ) -> crate::Result<Self::SessionKey>;

    /// Exports a session key.
    fn session_key_export(
        &self,
        session_key: &Self::SessionKey,
    ) -> crate::Result<(impl AsRef<[u8]>, SessionKeyAlgorithm)>;

    /// Import a PGP public key.
    ///
    /// Imports the PGP key ignoring its secret key material if any.
    /// The encoding allows to specify how the key should be decoded.
    fn public_key_import(
        &self,
        public_key: impl AsRef<[u8]>,
        encoding: DataEncoding,
    ) -> crate::Result<Self::PublicKey>;

    /// Export a PGP public key.
    ///
    /// Exports the PGP key in the given data encoding.
    /// If the encoding `DataEncoding::Auto` is selected, it defaults to `DataEncoding::Armor`.
    fn public_key_export(
        &self,
        public_key: &Self::PublicKey,
        encoding: DataEncoding,
    ) -> crate::Result<impl AsRef<[u8]>>;

    /// Import a PGP private key.
    ///
    /// Imports the key given its encoding and tries to decrypt in with the given passphrase.
    fn private_key_import(
        &self,
        private_key: impl AsRef<[u8]>,
        passphrase: impl AsRef<[u8]>,
        encoding: DataEncoding,
    ) -> crate::Result<Self::PrivateKey>;

    /// Export the PGP private key.
    ///
    /// Locks a copy of the PGP private key with the provided passphrase and exports it in the given data encoding.
    /// If the encoding `DataEncoding::Auto` is selected, it defaults to `DataEncoding::Armor`.
    fn private_key_export(
        &self,
        private_key: &Self::PrivateKey,
        passphrase: impl AsRef<[u8]>,
        encoding: DataEncoding,
    ) -> crate::Result<impl AsRef<[u8]>>;

    /// Imports an unlocked PGP private key.
    ///
    /// Returns an error if the keys is locked or decoding fails.
    fn private_key_import_unlocked(
        &self,
        private_key: impl AsRef<[u8]>,
        encoding: DataEncoding,
    ) -> crate::Result<Self::PrivateKey>;

    /// Export the PGP private key without locking it.
    ///
    /// Exports the private key without encrypting the secrets.
    ///
    /// # Warning
    ///
    /// This method should be used with extreme care as it will expose the secret key
    /// material.
    fn private_key_export_unlocked(
        &self,
        private_key: &Self::PrivateKey,
        encoding: DataEncoding,
    ) -> crate::Result<impl AsRef<[u8]>>;

    /// Create a public key from a private key.
    ///
    /// Creates a new public key from a private key that only
    /// contains public key material.
    fn private_key_to_public_key(
        &self,
        private_key: &Self::PrivateKey,
    ) -> crate::Result<Self::PublicKey>;

    /// Import an encrypted `OpenPGP` message.
    ///
    /// This can be useful to extract information from the message.
    /// For example a `PGPMessage` can be split into its key packets
    /// and data packets.
    fn pgp_message_import(
        &self,
        pgp_message: impl AsRef<[u8]>,
        encoding: DataEncoding,
    ) -> crate::Result<Self::PGPMessage>;

    /// Perform `OpenPGP` encryption.
    fn new_encryptor<'a>(&self) -> Self::Encryptor<'a>;

    /// Perform `OpenPGP` decryption.
    fn new_decryptor<'a>(&self) -> Self::Decryptor<'a>;

    /// Perform `OpenPGP` signature creation.
    fn new_signer<'a>(&self) -> Self::Signer<'a>;

    /// Perform `OpenPGP` signature verification.
    fn new_verifier<'a>(&self) -> Self::Verifier<'a>;

    /// Create a new generator for generating new `OpenPGP` keys.
    fn new_key_generator(&self) -> Self::KeyGenerator;

    /// Perform armor operations.
    fn armorer(&self) -> Self::Armorer;
}

/// `PGPProviderAsync` provides an asynchronous API for `OpenPGP` operations.
///
/// The asynchronous API is mainly targeted for web and only supports
/// asynchronous operations on a single thread for now.
/// i.e., the returned Futures are not Send.
pub trait PGPProviderAsync: PGPProvider {
    /// Builder for encryption operations.
    type Encryptor<'a>: EncryptorAsync<
        'a,
        SessionKey = Self::SessionKey,
        PrivateKey = Self::PrivateKey,
        PublicKey = Self::PublicKey,
        SigningContext = Self::SigningContext,
        PGPMessage = Self::PGPMessage,
    >
    where
        Self: 'a;

    /// Builder for decryption operations.
    type Decryptor<'a>: DecryptorAsync<
        'a,
        SessionKey = Self::SessionKey,
        PrivateKey = Self::PrivateKey,
        PublicKey = Self::PublicKey,
        VerificationContext = Self::VerificationContext,
        VerifiedData = Self::VerifiedData,
    >
    where
        Self: 'a;

    /// Builder for sign operations.
    type Signer<'a>: SignerAsync<
        'a,
        PrivateKey = Self::PrivateKey,
        SigningContext = Self::SigningContext,
    >
    where
        Self: 'a;

    /// Builder for signature verify operations.
    type Verifier<'a>: VerifierAsync<
        'a,
        PublicKey = Self::PublicKey,
        VerificationContext = Self::VerificationContext,
        VerifiedData = Self::VerifiedData,
    >
    where
        Self: 'a;

    type KeyGenerator: KeyGeneratorAsync<Self::PrivateKey>;

    /// Generates a fresh session key for the given algorithm.
    ///
    /// The session key is generated from a cryptographically secure random source.
    fn session_key_generate_async(
        &self,
        algorithm: SessionKeyAlgorithm,
    ) -> impl Future<Output = crate::Result<Self::SessionKey>>;

    /// Import a serialized session key.
    fn session_key_import_async(
        &self,
        data: impl AsRef<[u8]>,
        algorithm: SessionKeyAlgorithm,
    ) -> impl Future<Output = crate::Result<Self::SessionKey>>;

    /// Exports a session key.
    fn session_key_export_async(
        &self,
        session_key: &Self::SessionKey,
    ) -> impl Future<Output = crate::Result<(impl AsRef<[u8]>, SessionKeyAlgorithm)>>;

    /// Import a PGP public key.
    ///
    /// Imports the PGP key ignoring its secret key material if any.
    /// The encoding allows to specify how the key should be decoded.
    fn public_key_import_async(
        &self,
        public_key: impl AsRef<[u8]>,
        encoding: DataEncoding,
    ) -> impl Future<Output = crate::Result<Self::PublicKey>>;

    /// Export a PGP public key.
    ///
    /// Exports the PGP key in the given data encoding.
    /// If the encoding `DataEncoding::Auto` is selected, it defaults to `DataEncoding::Armor`.
    fn public_key_export_async(
        &self,
        public_key: &Self::PublicKey,
        encoding: DataEncoding,
    ) -> impl Future<Output = crate::Result<impl AsRef<[u8]>>>;

    /// Import a PGP private key.
    ///
    /// Imports the key given its encoding and tries to decrypt in with the given passphrase.
    fn private_key_import_async(
        &self,
        private_key: impl AsRef<[u8]>,
        passphrase: impl AsRef<[u8]>,
        encoding: DataEncoding,
    ) -> impl Future<Output = crate::Result<Self::PrivateKey>>;

    /// Export the PGP private key.
    ///
    /// Locks a copy of the PGP private key with the provided passphrase and exports it in the given data encoding.
    /// If the encoding `DataEncoding::Auto` is selected, it defaults to `DataEncoding::Armor`.
    fn private_key_export_async(
        &self,
        private_key: &Self::PrivateKey,
        passphrase: impl AsRef<[u8]>,
        encoding: DataEncoding,
    ) -> impl Future<Output = crate::Result<impl AsRef<[u8]>>>;

    /// Imports an unlocked PGP private key.
    ///
    /// Returns an error if the keys is locked or decoding fails.
    fn private_key_import_unlocked_async(
        &self,
        private_key: impl AsRef<[u8]>,
        encoding: DataEncoding,
    ) -> impl Future<Output = crate::Result<Self::PrivateKey>>;

    /// Export the PGP private key without locking it.
    ///
    /// Exports the private key without encrypting the secrets.
    ///
    /// # Warning
    ///
    /// This method should be used with extreme care as it will expose the secret key
    /// material.
    fn private_key_export_unlocked_async(
        &self,
        private_key: &Self::PrivateKey,
        encoding: DataEncoding,
    ) -> impl Future<Output = crate::Result<impl AsRef<[u8]>>>;

    /// Create a public key from a private key.
    ///
    /// Creates a new public key from a private key that only
    /// contains public key material.
    fn private_key_to_public_key_async(
        &self,
        private_key: &Self::PrivateKey,
    ) -> impl Future<Output = crate::Result<Self::PublicKey>>;

    /// Import an encrypted `OpenPGP` message.
    ///
    /// This can be useful to extract information from the message.
    /// For example a `PGPMessage` can be split into its key packets
    /// and data packets.
    fn pgp_message_import_async(
        &self,
        pgp_message: impl AsRef<[u8]>,
        encoding: DataEncoding,
    ) -> impl Future<Output = crate::Result<Self::PGPMessage>>;

    /// Perform `OpenPGP` encryption.
    fn new_encryptor_async<'a>(&self) -> Self::Encryptor<'a>;

    /// Perform `OpenPGP` decryption.
    fn new_decryptor_async<'a>(&self) -> Self::Decryptor<'a>;

    /// Perform `OpenPGP` signature creation.
    fn new_signer_async<'a>(&self) -> Self::Signer<'a>;

    /// Perform `OpenPGP` signature verification.
    fn new_verifier_async<'a>(&self) -> Self::Verifier<'a>;

    /// Generate new `OpenPGP` keys.
    fn new_key_generator_async(&self) -> Self::KeyGenerator;
}

/// Possible encodings of an `OpenPGP` message.
///
/// The data is either armored i.e., base64 encoded with a header
/// -----BEGIN PGP ... -----
/// ...
/// -----BEGIN PGP ... -----
/// or encoded as raw bytes.
/// Auto is used to indicate that encoding is unknown and the function
/// should detect the encoding automatically.
#[derive(Default, PartialEq, Eq, Hash, Clone, Copy, Debug)]
pub enum DataEncoding {
    /// The data is armored.
    #[default]
    Armor,
    /// The data is encoded as raw bytes.
    Bytes,
    /// The data encoding is unknown and should be detected.
    Auto,
}

impl DataEncoding {
    pub fn is_armor(&self) -> bool {
        *self == DataEncoding::Armor
    }
}

/// Allowed algorithms for an `OpenPGP` session key.
#[derive(Default, PartialEq, Eq, Hash, Serialize, Clone, Copy, Debug)]
#[serde(rename_all = "lowercase")]
pub enum SessionKeyAlgorithm {
    /// AES128 key with 16 random bytes.
    Aes128,
    /// AES256 key with 32 random bytes.
    #[default]
    Aes256,
    /// The session key algorithm is unknown.
    Unknown,
}

/// Provides information about a signature that has been verified.
#[derive(Debug, Clone)]
pub struct VerificationInformation {
    /// The `OpenPGP` key ID that the selected signature is signed with.
    pub key_id: OpenPGPKeyID,
    /// The creation time of the selected signature.
    pub signature_creation_time: UnixTimestamp,
    /// The serialized `OpenPGP` signature the has been verified.
    pub signature: Vec<u8>,
}

/// The result of a signature verification.
pub type VerificationResult = Result<VerificationInformation, VerificationError>;

/// Represents a signature verification error
///
/// - `NotSigned`: No signature found in the message.
/// - `NoVerifier`: No matching verification key found for the verified signature.
/// - `Failed`: A matching signature and key were found but it verification failed.
/// - `BadContext`: A matching signature and key were found but the context did not match.
/// - `RuntimeError`: Error occurred in signature verification.
#[derive(Clone, Debug, thiserror::Error)]
pub enum VerificationError {
    /// No signature found.
    #[error("No signature found: {0}")]
    NotSigned(crate::Error),

    /// No matching key found.
    #[error("No matching verification key found: {0}")]
    NoVerifier(crate::Error),

    /// Signature verification failure.
    #[error("Signature verification failed: {1}")]
    Failed(VerificationInformation, crate::Error),

    /// Signature context did not match verification context.
    #[error("Signature context does not match the verification context: {1}")]
    BadContext(VerificationInformation, crate::Error),

    /// Unknown error occurred.
    #[error("Runtime error: {0}")]
    RuntimeError(crate::Error),
}

/// Represents an `OpenPGP` key id.
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct OpenPGPKeyID(pub u64);

impl Display for OpenPGPKeyID {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:x}", self.0)
    }
}

impl<T: Into<u64>> From<T> for OpenPGPKeyID {
    fn from(value: T) -> Self {
        Self(value.into())
    }
}

impl OpenPGPKeyID {
    /// Encodes the `OpenPGP` key id to lower-case hexadecimal format.
    pub fn to_hex(&self) -> String {
        format!("{:x}", self.0)
    }
    /// Creates an `OpenPGPKeyID` from a hex encoded string.
    pub fn from_hex(hex: impl AsRef<str>) -> crate::Result<Self> {
        u64::from_str_radix(hex.as_ref(), 16)
            .map(OpenPGPKeyID)
            .map_err(Into::into)
    }
}

lowercase_string_id!(
    /// Represents an OpenPGP fingerprint encoded in lower-case hexadecimal format.
    OpenPGPFingerprint
);

lowercase_string_id!(
    /// Represents a custom sha256 hash fingerprint of the serialized key in lower-case hexadecimal format.
    SHA256Fingerprint
);

/// `UnixTimestamp` represents a unix timestamp within `OpenPGP`.
#[derive(Ord, PartialOrd, PartialEq, Eq, Hash, Clone, Copy, Debug, Default)]
pub struct UnixTimestamp(pub u64);

impl UnixTimestamp {
    /// Creates new unix timestamp.
    pub fn new(unix_time: u64) -> Self {
        Self(unix_time)
    }
    /// Creates unix timestamp with the zero value.
    ///
    /// If a zero value is supplied to the API expirations checks are skipped.
    pub fn zero() -> Self {
        Self(0)
    }
    /// Indicates if the timestamp is zero.
    pub fn is_zero(&self) -> bool {
        self.0 == 0
    }
    /// Indicates if the timestamp is zero.
    pub fn value(&self) -> u64 {
        self.0
    }
}

/// An enum of all detached signature variants.
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum DetachedSignatureVariant {
    /// Encrypted detached signature.
    #[default]
    Encrypted,

    /// Plaintext detached signature.
    Plaintext,
}

impl DetachedSignatureVariant {
    /// Returns true if it is the encrypted variant.
    pub fn is_encrypted(&self) -> bool {
        *self == DetachedSignatureVariant::Encrypted
    }
}
