use std::{future::Future, io};

use super::{DataEncoding, EncryptorWriter, PrivateKey, UnixTimestamp};

/// `SigningContext` provides a context for signature creation.
///
/// A `SigningContext` allows to specify that a signature must have been generated
/// for a specified context (i.e., a string value). In signature creation, the context
/// is added to the signature's notation data, and marked with a critical or not critical flag.
/// On the verification side the context of a signature can be checked.
/// For example, if app A uses a context `a` and app B uses a context `b` for its signatures, an
/// adversary cannot misuse a signature from app A in app B, since each App checks the custom
/// signature context on signature verification.
pub trait SigningContext: Clone + Send + Sync {}

/// `Signer` provides a builder API to sign data and create signatures with `OpenPGP` operations.
pub trait Signer<'a> {
    type PrivateKey: PrivateKey;
    type SigningContext: SigningContext;
    type SignerWriter<'b, T: io::Write + 'b>: EncryptorWriter<'b, T>;
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

/// `SignerSync` provides `OpenPGP` signing operations.
pub trait SignerSync<'a>: Signer<'a> {
    /// Creates a signature over the data and outputs a inline signed `OpenPGP` message.
    ///
    /// The encoding determines if the output should be in armored format.
    fn sign_inline(
        self,
        data: impl AsRef<[u8]>,
        out_encoding: DataEncoding,
    ) -> crate::Result<Vec<u8>>;

    /// Creates a detached signature over the data and outputs a `OpenPGP` signature.
    ///
    /// The encoding determines if the output should be in armored format.
    fn sign_detached(
        self,
        data: impl AsRef<[u8]>,
        out_encoding: DataEncoding,
    ) -> crate::Result<Vec<u8>>;

    /// Creates an `OpenPGP` cleartext signed message.
    fn sign_cleartext(self, data: impl AsRef<[u8]>) -> crate::Result<Vec<u8>>;

    /// Returns a writer that can be used to sign the data and write the output to `output_writer`.
    ///
    /// Returns a wrapper around the provided `output_writer` such that any write-operation via
    /// the wrapper results in a write to signed `OpenPGP` message (signature/inline signature)
    /// The `output_encoding` argument defines the output encoding, i.e., Bytes or Armored
    /// Once all data has been written to the returned `SignerWriter`, `finalize` must be
    /// called to finalize the signature creation.
    fn sign_stream<T: io::Write + 'a>(
        self,
        sign_writer: T,
        detached: bool,
        data_encoding: DataEncoding,
    ) -> crate::Result<Self::SignerWriter<'a, T>>;
}

/// `SignerAsync` provides asynchronous `OpenPGP` signing operations.
pub trait SignerAsync<'a>: Signer<'a> {
    /// Creates a signature over the data and outputs a inline signed `OpenPGP` message.
    ///
    /// The encoding determines if the output should be in armored format.
    fn sign_inline_async(
        self,
        data: impl AsRef<[u8]>,
        out_encoding: DataEncoding,
    ) -> impl Future<Output = crate::Result<Vec<u8>>>;

    /// Creates a detached signature over the data and outputs a `OpenPGP` signature.
    ///
    /// The encoding determines if the output should be in armored format.
    fn sign_detached_async(
        self,
        data: impl AsRef<[u8]>,
        out_encoding: DataEncoding,
    ) -> impl Future<Output = crate::Result<Vec<u8>>>;
    /// Creates an `OpenPGP` cleartext signed message.
    fn sign_cleartext_async(
        self,
        data: impl AsRef<[u8]>,
    ) -> impl Future<Output = crate::Result<Vec<u8>>>;
}
