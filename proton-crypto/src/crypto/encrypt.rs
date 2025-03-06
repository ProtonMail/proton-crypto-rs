use std::{future::Future, io};

use crate::{
    AsPublicKeyRef, DataEncoding, OpenPGPKeyID, PrivateKey, PublicKey, SigningContext,
    UnixTimestamp,
};

use super::DetachedSignatureVariant;

/// Represent an `OpenPGP` message with encrypted data.
pub trait PGPMessage: AsRef<[u8]> + Send + Sync {
    /// Returns the serialized armored pgp message.
    fn armor(&self) -> crate::Result<Vec<u8>>;

    /// Returns a slice view on the key packets in the `PGPMessage`.
    fn as_key_packets(&self) -> &[u8];

    /// Returns a slice view on the data packet in the `PGPMessage`.
    fn as_data_packet(&self) -> &[u8];

    /// Returns the `OpenPGP` key identifiers of the keys the data was encrypted to.
    fn encryption_key_ids(&self) -> Vec<OpenPGPKeyID>;
}

/// Writer for writing encrypted and/or signed data.
pub trait EncryptorWriter<'a, T: io::Write + 'a>: io::Write
where
    Self: 'a,
{
    /// Finalizes the encryption.
    ///
    /// Must be called once all plaintext data has been written to finalize
    /// the encryption.
    fn finalize(self) -> crate::Result<()>;
}

/// Raw detached signature either armored or in bytes.
type RawDetachedSignature = Vec<u8>;

/// Writer for writing encrypted data and a detached signature.
pub trait EncryptorDetachedSignatureWriter<'a, T: io::Write + 'a>: io::Write
where
    Self: 'a,
{
    /// Finalizes the encryption and returns the produced detached signature.
    ///
    /// Must be called once all plaintext data has been written to finalize
    /// the encryption.
    fn finalize_with_detached_signature(self) -> crate::Result<RawDetachedSignature>;
}

/// `Encryptor` provides a builder API to encrypt data with `OpenPGP` operations.
pub trait Encryptor<'a> {
    /// `OpenPGP` session key type.
    type SessionKey;

    /// `OpenPGP` privates key type.
    type PrivateKey: PrivateKey;

    /// `OpenPGP` public key type.
    type PublicKey: PublicKey;

    /// Type for encrypted `OpenPGP` messages.
    type PGPMessage: PGPMessage;

    /// Context type for signatures.
    type SigningContext: SigningContext;

    /// Type for writing encrypted data.
    type EncryptorWriter<'b, T: io::Write + 'b>: EncryptorWriter<'b, T>;

    /// Type for writing encrypted data and producing a detached signature.
    type EncryptorDetachedSignatureWriter<'b, T: io::Write + 'b>: EncryptorDetachedSignatureWriter<
        'b,
        T,
    >;

    /// Adds an `OpenPGP` key to encrypt the data to.
    ///
    /// Triggers the hybrid encryption mode where the session key used for encrypting the data
    /// is encrypted with the provided recipient key. The output `OpenPGP` message will contain
    /// an encrypted `key packet` and the encrypted `data packet`.
    /// i.e., `OpenPGPMessage(key packet|data packet)`
    fn with_encryption_key(self, encryption_key: &'a Self::PublicKey) -> Self;

    /// Adds several `OpenPGP` keys to encrypt the data to.
    ///
    /// Triggers the hybrid encryption mode where the session key used for encrypting the data
    /// is encrypted with the provided recipient keys. The output `OpenPGP` message will contain
    /// an encrypted `key packets` and the encrypted `data packet`.
    /// i.e., `OpenPGPMessage(key packets|data packet)`
    fn with_encryption_keys(self, encryption_keys: &'a [Self::PublicKey]) -> Self;

    /// Adds several `OpenPGP` keys to encrypt the data to.
    ///
    /// Triggers the hybrid encryption mode where the session key used for encrypting the data
    /// is encrypted with the provided recipient keys. The output `OpenPGP` message will contain
    /// an encrypted `key packets` and the encrypted `data packet`.
    /// i.e., `OpenPGPMessage(key packets|data packet)`
    fn with_encryption_key_refs(
        self,
        encryption_keys: &'a [impl AsPublicKeyRef<Self::PublicKey>],
    ) -> Self;

    /// Adds an `OpenPGP` key for creating a signature over the data.
    ///
    /// For each signing key provided, the encryptor will create a signature over the input data.
    /// The signatures are inlined within the encrypted message.
    fn with_signing_key(self, signing_key: &'a Self::PrivateKey) -> Self;

    /// Adds several `OpenPGP` keys for creating signatures over the data.
    ///
    /// For each signing key provided, the encryptor will create a signature over the input data.
    /// The signatures are inlined within the encrypted message.
    fn with_signing_keys(self, signing_keys: &'a [Self::PrivateKey]) -> Self;

    /// Adds several `OpenPGP` keys for creating signatures over the data.
    ///
    /// For each signing key provided, the encryptor will create a signature over the input data.
    /// The signatures are inlined within the encrypted message.
    fn with_signing_key_refs(self, signing_keys: &'a [impl AsRef<Self::PrivateKey>]) -> Self;

    /// Sets a session key for encrypting data and creating an `OpenPGP` message.
    ///
    /// The provided session key is used to encrypt the data instead of
    /// generating a fresh random session key. This function should be
    /// used with care and requires knowledge of the cryptographic implications.
    fn with_session_key_ref(self, session_key: &'a Self::SessionKey) -> Self;

    /// Sets a session key for encrypting data and creating an `OpenPGP` message.
    ///
    /// The provided session key is used to encrypt the data instead of
    /// generating a fresh random session key. This function should be
    /// used with care and requires knowledge of the cryptographic implications.
    fn with_session_key(self, session_key: Self::SessionKey) -> Self;

    /// Indicates if compression should be applied to the data before encryption.
    ///
    /// The default is false. Note that compression can leak information about the encrypted
    /// plaintext via side-channels. Use with care.
    fn with_compression(self) -> Self;

    /// Sets the signing context for creating signatures.
    ///
    /// A `SigningContext` allows to specify that a signature must have been generated
    /// for a specified context (i.e., a string value). In signature creation, the context
    /// is added to the signature's notation data, and marked with a critical or not critical flag.
    /// On the verification side the context of a signature can be checked.
    /// For example, if app A uses a context `a` and app B uses a context `b` for its signatures, an
    /// adversary cannot misuse a signature from app A in app B, since each App checks the custom
    /// signature context on signature verification.
    fn with_signing_context(self, signing_context: &'a Self::SigningContext) -> Self;

    /// Sets the signing time to the provided timestamp.
    ///
    /// If not set, the systems current time is for signature creation.
    /// The signature time is used to select the signing key and to set the signature
    /// creation timestamp in the signature.
    fn at_signing_time(self, unix_timestamp: UnixTimestamp) -> Self;

    /// Utf8 indicates if the plaintext should be signed with a text type signature.
    ///
    /// Before encryption the line endings of the input utf8 text are canonicalized.
    /// (i.e. set all of them to \r\n).
    fn with_utf8(self) -> Self;
}

/// Raw encrypted message either armored or in bytes.
type RawEncryptedMessage = Vec<u8>;

/// Raw pgp keys packets as bytes.
type PGPKeyPackets = Vec<u8>;

/// `EncryptorSync` provides synchronous `OpenPGP` encryption operations.
pub trait EncryptorSync<'a>: Encryptor<'a> {
    /// Generates a session key based on the information in the given encryptor.
    ///
    /// For example considers the algorithm preferences of the recipient keys.
    fn generate_session_key(self) -> crate::Result<Self::SessionKey>;

    /// Encrypts the provided data and outputs an encrypted `OpenPGP` message.
    ///
    /// Uses the key material from the encryptor.
    fn encrypt(self, data: impl AsRef<[u8]>) -> crate::Result<Self::PGPMessage>;

    /// Encrypts the data with the given `output_encoding`.
    ///
    /// Returns the encrypted data as a raw serialized `OpenPGP` message either armored or in bytes.
    /// Uses the key material from the encryptor.
    fn encrypt_raw(
        self,
        data: impl AsRef<[u8]>,
        armored: DataEncoding,
    ) -> crate::Result<RawEncryptedMessage>;

    /// Encrypts a session key with the encryptor.
    ///
    /// Returns the `key packets` containing the encrypted session key for each
    /// recipient's encryption key or password in the encryptor.
    fn encrypt_session_key(self, session_key: &Self::SessionKey) -> crate::Result<PGPKeyPackets>;

    /// Returns a writer that can be used to encrypt the data to the `output_writer`.
    ///
    /// Returns a wrapper around the provided `output_writer` such that any write-operation via
    /// the wrapper results in a write to an encrypted pgp message.
    /// The `output_encoding` argument defines the output encoding, i.e., Bytes or Armored
    /// Once all data has been written to the returned `EncryptorWriter`, `finalize` must be
    /// called to finalize the encryption.
    fn encrypt_stream<T: io::Write + 'a>(
        self,
        output_writer: T,
        output_encoding: DataEncoding,
    ) -> crate::Result<Self::EncryptorWriter<'a, T>>;

    /// Returns the key packets and the writer that can be used to encrypt the data to the `output_writer`.
    ///
    /// Returns a wrapper around the provided `output_writer` such that any write-operation via
    /// the wrapper results in a write to an encrypted pgp message.
    /// In split mode the key packets are returned by the function and only the
    /// encrypted data (i.e., `data packet`) part is written to the `output_writer`
    /// Once all data has been written to the returned `EncryptorWriter`, `finalize` must be
    /// called to finalize the encryption.
    fn encrypt_stream_split<T: io::Write + 'a>(
        self,
        output_writer: T,
    ) -> crate::Result<(Vec<u8>, Self::EncryptorWriter<'a, T>)>;

    /// Returns a writer that can be used to encrypt the data to the `output_writer` and produce a detached signature at the same time.
    ///
    /// Returns a wrapper around the provided `output_writer` such that any write-operation via
    /// the wrapper results in a write to an encrypted pgp message.
    /// The `output_encoding` argument defines the output encoding, i.e., Bytes or Armored for both the data and the detached signature.
    /// It further produces a detached signature that can be accessed via the `EncryptorDetachedSignatureWriter`
    /// once encryption is done.
    /// Once all data has been written to the returned `EncryptorWriter`, `finalize` must be
    /// called to finalize the encryption.
    fn encrypt_stream_with_detached_signature<T: io::Write + 'a>(
        self,
        output_writer: T,
        variant: DetachedSignatureVariant,
        output_encoding: DataEncoding,
    ) -> crate::Result<Self::EncryptorDetachedSignatureWriter<'a, T>>;

    /// Returns the key packets and the writer that can be used to encrypt the data to the `output_writer`with ad detached signature.
    ///
    /// Returns a wrapper around the provided `output_writer` such that any write-operation via
    /// the wrapper results in a write to an encrypted pgp message.
    /// In split mode the key packets are returned by the function and only the
    /// encrypted data (i.e., `data packet`) part is written to the `output_writer`.
    /// It further produces a detached signature that can be accessed via the `EncryptorDetachedSignatureWriter`
    /// once encryption is done.
    /// Once all data has been written to the returned `EncryptorWriter`, `finalize` must be
    /// called to finalize the encryption.
    fn encrypt_stream_split_with_detached_signature<T: io::Write + 'a>(
        self,
        output_writer: T,
        variant: DetachedSignatureVariant,
    ) -> crate::Result<(Vec<u8>, Self::EncryptorDetachedSignatureWriter<'a, T>)>;
}

/// `EncryptorAsync` provides asynchronous `OpenPGP` encryption operations.
pub trait EncryptorAsync<'a>: Encryptor<'a> {
    /// Encrypts the provided data and outputs an encrypted `OpenPGP` message.
    ///
    /// Uses the key material from the encryptor.
    fn encrypt_async(
        self,
        data: impl AsRef<[u8]>,
    ) -> impl Future<Output = crate::Result<Self::PGPMessage>>;
    /// Encrypts the data with the given `output_encoding`.
    ///
    /// Returns the encrypted data as a raw serialized `OpenPGP` message either armored or in bytes.
    /// Uses the key material from the encryptor.
    fn encrypt_raw_async(
        self,
        data: impl AsRef<[u8]>,
        armored: DataEncoding,
    ) -> impl Future<Output = crate::Result<RawEncryptedMessage>>;
    /// Encrypts a session key with the encryptor.
    ///
    /// Returns the `key packets` containing the encrypted session key for each
    /// recipient's encryption key or password in the encryptor.
    fn encrypt_session_key_async(
        self,
        session_key: &Self::SessionKey,
    ) -> impl Future<Output = crate::Result<PGPKeyPackets>>;
}
