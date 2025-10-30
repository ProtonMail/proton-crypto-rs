use std::{future::Future, io};

use super::{
    AsPublicKeyRef, DataEncoding, PrivateKey, PublicKey, UnixTimestamp, VerificationContext,
    VerifiedData, VerifiedDataReader,
};

use super::DetachedSignatureVariant;

/// `Decryptor` provides a builder API to decrypt data with `OpenPGP` operations.
pub trait Decryptor<'a> {
    /// `OpenPGP` session key type.
    type SessionKey;

    /// `OpenPGP` private key type.
    type PrivateKey: PrivateKey;

    /// `OpenPGP` public key type.
    type PublicKey: PublicKey;

    /// Type for data that has been verified against `OpenPGP` signatures.
    type VerifiedData: VerifiedData;

    /// Type for reading data that is verified against `OpenPGP` signatures.
    type VerifiedDataReader<'b, T: io::Read + 'b>: VerifiedDataReader<'b, T>;

    /// Type for a `OpenPGP` signature verification context.
    type VerificationContext: VerificationContext;

    /// Adds the `OpenPGP` key for decrypting the `OpenPGP` message.
    ///
    /// Assumes that the message to decrypt was encrypted towards the `OpenPGP` key.
    /// Triggers the hybrid decryption mode with a asymmetric key.
    fn with_decryption_key(self, decryption_key: &'a Self::PrivateKey) -> Self;

    /// Adds the `OpenPGP` keys for decrypting the `OpenPGP` message.
    ///
    /// Assumes that the message to decrypt was encrypted towards one of the `OpenPGP` keys.
    /// Triggers the hybrid decryption mode with the asymmetric keys.
    fn with_decryption_keys(self, decryption_key: &'a [Self::PrivateKey]) -> Self;

    /// Adds the `OpenPGP` keys for decrypting the `OpenPGP` message.
    ///
    /// Assumes that the message to decrypt was encrypted towards one of the `OpenPGP` keys.
    /// Triggers the hybrid decryption mode with the asymmetric keys.
    fn with_decryption_key_refs(self, decryption_key: &'a [impl AsRef<Self::PrivateKey>]) -> Self;

    /// Adds the `OpenPGP` verification key for verifying signatures in the `OpenPGP` message.
    ///
    /// Assumes that the message contains a signature that can be verified with the provided `OpenPGP` key.
    /// Triggers the signature verification.
    fn with_verification_key(self, verification_key: &'a Self::PublicKey) -> Self;

    /// Adds the `OpenPGP` verification keys for verifying signatures in the `OpenPGP` message.
    ///
    /// Assumes that the message contains a signature that can be verified with one of the provided `OpenPGP` keys.
    /// Triggers the signature verification.
    fn with_verification_keys(self, verification_keys: &'a [Self::PublicKey]) -> Self;

    /// Adds the `OpenPGP` verification keys for verifying signatures in the `OpenPGP` message.
    ///
    /// Assumes that the message contains a signature that can be verified with one of the provided `OpenPGP` keys.
    /// Triggers the signature verification.
    fn with_verification_key_refs(
        self,
        verification_keys: &'a [impl AsPublicKeyRef<Self::PublicKey>],
    ) -> Self;

    /// Sets a session key for decrypting the `OpenPGP` message.
    ///
    /// Assumes that the message was encrypted with the session key provided.
    /// Triggers the session key decryption mode.
    fn with_session_key_ref(self, session_key: &'a Self::SessionKey) -> Self;

    /// Sets a session key for decrypting the `OpenPGP` message.
    ///
    /// Assumes that the message was encrypted with the session key provided.
    /// Triggers the session key decryption mode.
    fn with_session_key(self, session_key: Self::SessionKey) -> Self;

    /// Sets a password for decrypting the `OpenPGP` message.
    ///
    /// Assumes that the message to decrypt was encrypted with a password.
    /// Triggers the password decryption mode.
    fn with_passphrase(self, passphrase: &'a str) -> Self;

    /// Sets the `OpenPGP` verification context for verifying signatures in the `OpenPGP` message.
    ///
    /// A `VerificationContext` allows to specify that a signature must have been generated
    /// for a specified context (i.e., string `value`).
    /// The `value` is checked against the signature's notation data.
    /// If the context does not match, the returned verification result will reflect that.
    fn with_verification_context(self, verification_context: &'a Self::VerificationContext)
        -> Self;

    /// Sets the verification time to the provided timestamp.
    ///
    /// If not set, the systems current time is used for signature verification.
    fn at_verification_time(self, unix_timestamp: UnixTimestamp) -> Self;

    /// Indicates utf-8 output sanitization should be applied.
    ///
    /// If enabled the output is sanitized from canonicalised `OpenPGP` line endings and
    /// invalid utf-8 parts are replaced.
    fn with_ut8_sanitization(self) -> Self;

    /// Sets a detached signature that must be verified against the decrypted data.
    ///
    /// On decryption the decrypted data is verified against the provided detached signature.
    /// Other signatures  in the message are ignored and only the detached signature is considered.
    ///
    /// The two variants are:
    /// [`DetachedSignatureVariant::Plaintext`], `data -> Enc(data), SignDetached(data)`
    /// [`DetachedSignatureVariant::Encrypted`], `data -> Enc(data), Enc(SignDetached(data))`
    fn with_detached_signature_ref(
        self,
        detached_signature: &'a [u8],
        variant: DetachedSignatureVariant,
        armored: bool,
    ) -> Self;

    /// Sets a detached signature that must be verified against the decrypted data.
    ///
    /// On decryption the decrypted data is verified against the provided detached signature.
    /// Other signatures  in the message are ignored and only the detached signature is considered.
    ///
    /// The two variants are:
    /// [`DetachedSignatureVariant::Plaintext`], `data -> Enc(data), SignDetached(data)`
    /// [`DetachedSignatureVariant::Encrypted`], `data -> Enc(data), Enc(SignDetached(data))`
    fn with_detached_signature(
        self,
        detached_signature: Vec<u8>,
        variant: DetachedSignatureVariant,
        armored: bool,
    ) -> Self;
}

/// `DecryptorSync` provides `OpenPGP` decryption operations.
pub trait DecryptorSync<'a>: Decryptor<'a> {
    /// Decrypts an encrypted `OpenPGP` message or data packet.
    ///
    /// Returns the decryption result as `VerifiedData`, which provides access to the signature verification information
    /// and the plaintext data. Note that on a signature error, the method does not return an error.
    /// Instead, the signature verification can be accessed with the `VerifiedData` output.
    /// The encoding indicates if the input message should be unarmored or not, i.e., Bytes/Armor/Auto
    /// where Auto tries to detect automatically.
    fn decrypt(
        self,
        data: impl AsRef<[u8]>,
        data_encoding: DataEncoding,
    ) -> crate::Result<Self::VerifiedData>;

    /// Decrypts one of the key packets to a session key.
    ///
    /// Tries to decrypt one of the `OpenPGP` packets (i.e.,`PKESK`, `SKESK`) in key packets.
    /// Returns the decrypted session key if the decryption is successful, which can then be used to decrypt the data packet.
    /// Assumes that encrypted `OpenPGP` Message has the form: `key packets  | encrypted data packet`.
    fn decrypt_session_key(self, key_packets: impl AsRef<[u8]>) -> crate::Result<Self::SessionKey>;

    /// Returns a reader that allows to read the decrypted data from an encrypted `OpenPGP` message or data packet.
    ///
    /// Returns a special type of reader, which allows to read the decrypted data.
    /// Once all data is read, the signature verification result can be accessed via the dedicated method on `VerifiedDataReader`.
    /// The encoding indicates if the input message should be unarmored or not, i.e., Bytes/Armor/Auto
    /// where Auto tries to detect automatically.
    fn decrypt_stream<T: io::Read + Send + 'a>(
        self,
        data: T,
        data_encoding: DataEncoding,
    ) -> crate::Result<Self::VerifiedDataReader<'a, T>>;
}

/// `DecryptorAsync` provides asynchronous `OpenPGP` decryption operations.
pub trait DecryptorAsync<'a>: Decryptor<'a> {
    /// Decrypts an encrypted `OpenPGP` message.
    ///
    /// Returns the decryption result as `VerifiedData`, which provides access to the signature verification information
    /// and the plaintext data. Note that on a signature error, the method does not return an error.
    /// Instead, the signature verification can be accessed with the `VerifiedData` output.
    /// The encoding indicates if the input message should be unarmored or not, i.e., Bytes/Armor/Auto
    /// where Auto tries to detect automatically.
    fn decrypt_async(
        self,
        data: impl AsRef<[u8]>,
        data_encoding: DataEncoding,
    ) -> impl Future<Output = crate::Result<Self::VerifiedData>>;

    /// Decrypts one of the key packets to a session key.
    ///
    /// Tries to decrypt one of the `OpenPGP` packets (i.e.,`PKESK`, `SKESK`) in key packets.
    /// Returns the decrypted session key if the decryption is successful, which can then be used to decrypt the data packet.
    /// Assumes that encrypted `OpenPGP` Message has the form: `key packets  | encrypted data packet`.
    fn decrypt_session_key_async(
        self,
        key_packets: impl AsRef<[u8]>,
    ) -> impl Future<Output = crate::Result<Self::SessionKey>>;
}
