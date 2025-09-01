use std::{future::Future, io};

use super::{AsPublicKeyRef, DataEncoding, PublicKey, UnixTimestamp, VerificationResult};

/// `VerificationContext` allows to provide a context for signature verification.
///
/// A `VerificationContext` allows to specify that a signature must have been generated
/// for a specified context (i.e., string `value`).
/// The `value` is checked against the signature's notation data.
/// If `is_required` is false, the signature is allowed to have no context set.
/// If `required_after` is != 0, the signature is allowed to have no context set if it
/// was created before the unix time set in `required_after`.
pub trait VerificationContext: Clone + Send + Sync {
    // Returns the context value.
    fn value(&self) -> impl AsRef<str>;

    // Indicates if the context is required.
    fn is_required(&self) -> bool;

    // Indicates that the context is required after the given point in time.
    fn is_required_after(&self) -> UnixTimestamp;
}

/// Reader for reading verified data.
pub trait VerifiedDataReader<'a, T: io::Read + 'a>: io::Read
where
    Self: 'a,
{
    /// Returns the verification result if any.
    ///
    /// Can only be called once all data has been read.
    fn verification_result(self) -> VerificationResult;
}

/// Represents decrypted PGP data that might have been verified with a signature.  
pub trait VerifiedData: AsRef<[u8]> {
    /// Borrow the raw inner data.
    fn as_bytes(&self) -> &[u8];

    /// Indicates if the data has been verified with a signature.
    fn is_verified(&self) -> bool;

    /// Returns the verification result.
    ///
    /// Returns an error if no verification result is found or retrieving the result fails.
    fn verification_result(&self) -> VerificationResult;

    /// Clones the data and puts it into the returned vec.
    fn to_vec(&self) -> Vec<u8> {
        let data_ref = self.as_ref();
        let mut data_vec = Vec::with_capacity(data_ref.len());
        data_vec.extend_from_slice(data_ref);
        data_vec
    }
    /// Transforms to the decrypted data.
    fn into_vec(self) -> Vec<u8>;

    /// Returns all signatures in serialized form.
    ///
    /// Returns an empty vector if no signatures are found.
    fn signatures(&self) -> crate::Result<Vec<u8>>;
}

/// `Verifier` provides a builder API to verify signatures with `OpenPGP` signature operations.
pub trait Verifier<'a> {
    type PublicKey: PublicKey;
    type VerifiedData: VerifiedData;
    type VerificationContext: VerificationContext;
    /// Adds the `OpenPGP` verification key for verifying the signatures.
    fn with_verification_key(self, verification_key: &'a Self::PublicKey) -> Self;

    /// Adds `OpenPGP` verifications key for verifying the signatures.
    fn with_verification_keys(self, verification_keys: &'a [Self::PublicKey]) -> Self;

    /// Adds `OpenPGP` verifications key for verifying the signatures.
    ///
    /// Takes a slice of higher level objects that implement the `AsPublicKeyRef` trait.
    /// Thus, a reference of the public kee can be retrieved.
    fn with_verification_key_refs(
        self,
        verification_keys: &'a [impl AsPublicKeyRef<Self::PublicKey>],
    ) -> Self;

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
    fn with_utf8_out(self) -> Self;
}

/// `VerifierSync` provides `OpenPGP` signature verification operations.
pub trait VerifierSync<'a>: Verifier<'a> {
    /// Verifies a detached `OpenPGP` signature.
    ///
    /// Verifies if one of the detached signatures in `signature` can be verified with
    /// one of the provided verification keys. Returns a verification result that contains
    /// the result of the signature verification. An `Err` is only returned if an unexpected runtime
    /// error occurs or no verification keys are provided.
    /// The encoding indicates the encoding of the signature, i.e., Bytes/Armor/Auto
    /// where Auto tries to detect automatically.
    fn verify_detached(
        self,
        data: impl AsRef<[u8]>,
        signature: impl AsRef<[u8]>,
        signature_encoding: DataEncoding,
    ) -> VerificationResult;

    /// Verifies a plaintext `OpenPGP` message with an inline signature.
    ///
    /// Verifies if one of the inline signatures can be verified with
    /// one of the provided verification keys. Returns verified data that contains
    /// the result of the signature verification and the data. An `Err` is only returned if an unexpected runtime
    /// error occurs.
    fn verify_inline(
        self,
        message: impl AsRef<[u8]>,
        message_encoding: DataEncoding,
    ) -> crate::Result<Self::VerifiedData>;

    /// Verifies a cleartext `OpenPGP` message.
    ///
    /// Verifies if the contained signature can be verified with
    /// one of the provided verification keys. Returns verified data that contains
    /// the result of the signature verification and the cleartext data.
    /// An `Err` is only returned if an unexpected runtime error occurs.
    fn verify_cleartext(self, message: impl AsRef<[u8]>) -> crate::Result<Self::VerifiedData>;

    /// Reads the data from the provided reader and verifies it against the signatures.
    ///
    /// Verifies if one of the detached signatures in `signature` can be verified with
    /// one of the provided verification keys. Returns a verification result that contains
    /// the result of the signature verification. An `Err` is only returned if an unexpected runtime
    /// error occurs or no verification keys are provided.
    /// The encoding indicates the encoding of the signature, i.e., Bytes/Armor/Auto
    /// where Auto tries to detect automatically.
    fn verify_detached_stream<T: io::Read + 'a>(
        self,
        data: T,
        signature: impl AsRef<[u8]>,
        signature_encoding: DataEncoding,
    ) -> VerificationResult;
}

/// `VerifierAsync` provides asynchronous `OpenPGP` signature verification operations.
pub trait VerifierAsync<'a>: Verifier<'a> {
    /// Verifies a detached `OpenPGP` signature.
    ///
    /// Verifies if one of the detached signatures in `signature` can be verified with
    /// one of the provided verification keys. Returns a verification result that contains
    /// the result of the signature verification. An `Err` is only returned if an unexpected runtime
    /// error occurs or no verification keys are provided.
    /// The encoding indicates the encoding of the signature, i.e., Bytes/Armor/Auto
    /// where Auto tries to detect automatically.
    fn verify_detached_async(
        self,
        data: impl AsRef<[u8]>,
        signature: impl AsRef<[u8]>,
        data_encoding: DataEncoding,
    ) -> impl Future<Output = VerificationResult>;

    /// Verifies a plaintext `OpenPGP` message with an inline signature.
    ///
    /// Verifies if one of the inline signatures can be verified with
    /// one of the provided verification keys. Returns verified data that contains
    /// the result of the signature verification and the data. An `Err` is only returned if an unexpected runtime
    /// error occurs.
    fn verify_inline_async(
        self,
        message: impl AsRef<[u8]>,
        data_encoding: DataEncoding,
    ) -> impl Future<Output = crate::Result<Self::VerifiedData>>;

    /// Verifies a cleartext `OpenPGP` message.
    ///
    /// Verifies if the contained signature can be verified with
    /// one of the provided verification keys. Returns verified data that contains
    /// the result of the signature verification and the cleartext data.
    /// An `Err` is only returned if an unexpected runtime error occurs.
    fn verify_cleartext_async(
        self,
        message: impl AsRef<[u8]>,
    ) -> impl Future<Output = crate::Result<Self::VerifiedData>>;
}
