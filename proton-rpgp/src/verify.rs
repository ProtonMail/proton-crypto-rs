use std::{
    borrow::Cow,
    io::{BufRead, BufReader},
};

use pgp::{
    armor::BlockType,
    composed::{CleartextSignedMessage, Message},
    packet::{Packet, PacketParser},
};

use crate::{
    armor, check_and_sanitize_text,
    signature::{
        VerificationError, VerificationResult, VerificationResultCreator, VerifiedSignature,
    },
    DataEncoding, MessageProcessingError, MessageVerificationExt, Profile, PublicKey,
    ResolvedDataEncoding, UnixTime, VerificationContext, VerificationInput, VerifyMessageError,
    DEFAULT_PROFILE,
};

/// Verifier type to verify `OpenPGP` signatures.
#[derive(Debug, Clone)]
pub struct Verifier<'a> {
    /// The profile to use for verification.
    pub(crate) profile: Profile,

    /// The verification keys that are used to verify the signatures.
    pub(crate) verification_keys: Vec<&'a PublicKey>,

    /// The date to verify the signature against.
    pub(crate) date: UnixTime,

    /// Whether to sanitize the output plaintext from canonicalized line endings
    /// and check that the output is utf-8 encoded.
    pub(crate) native_newlines_utf8: bool,

    /// The verification context to use for verifying message signatures.
    pub(crate) verification_context: Option<Cow<'a, VerificationContext>>,
}

impl<'a> Verifier<'a> {
    /// Create a new verifier with the given profile.
    pub fn new(profile: Profile) -> Self {
        Self {
            profile,
            verification_keys: Vec::new(),
            date: UnixTime::now().unwrap_or_default(),
            verification_context: None,
            native_newlines_utf8: false,
        }
    }

    /// Set the verification key to use.
    pub fn with_verification_key(mut self, key: &'a PublicKey) -> Self {
        self.verification_keys.push(key);
        self
    }

    /// Set the verification keys to use.
    pub fn with_verification_keys(mut self, keys: impl IntoIterator<Item = &'a PublicKey>) -> Self {
        self.verification_keys.extend(keys);
        self
    }

    /// Allows to specify the expected application context of a signature.
    ///
    /// The [`VerificationContext`] encodes how the signature context should be checked.
    pub fn with_verification_context(
        mut self,
        context: impl Into<Cow<'a, VerificationContext>>,
    ) -> Self {
        self.verification_context = Some(context.into());
        self
    }

    /// Set the date to verify the signature against.
    ///
    /// In default mode, the system clock is used.
    pub fn at_date(mut self, date: UnixTime) -> Self {
        self.date = date;
        self
    }

    /// Setting output Utf8 indicates if the output plaintext is Utf8 encoded and
    /// should be sanitized from canonicalised line endings.
    ///
    /// If this setting is enabled, the decryptor throws an error if the output is
    /// not Utf-8 encoded.
    /// Further, the decryptor replaces canonical newlines (`\r\n`) with native newlines (`\n`).
    pub fn output_utf8(mut self) -> Self {
        self.native_newlines_utf8 = true;
        self
    }

    /// Verifies an inline-signed message with the verifier.
    ///
    /// Returns the verified data and result of its verification.
    ///
    /// # Example
    ///
    /// ```
    /// use proton_rpgp::{Verifier, PublicKey, DataEncoding, UnixTime};
    ///
    /// const INPUT_DATA: &str = include_str!("../test-data/messages/signed_message_v4.asc");
    /// const KEY: &str = include_str!("../test-data/keys/public_key_v4.asc");
    /// let date = UnixTime::new(1_753_088_183);
    ///
    /// let key = PublicKey::import(KEY.as_bytes(), DataEncoding::Armored)
    ///     .expect("Failed to import key");
    ///
    /// let verified_data = Verifier::default()
    ///     .with_verification_key(&key)
    ///     .at_date(date)
    ///     .verify(INPUT_DATA, DataEncoding::Armored)
    ///     .expect("Failed to verify");
    ///
    /// assert_eq!(verified_data.data, b"hello world");
    /// assert!(verified_data.verification_result.is_ok());
    /// ```
    pub fn verify(
        self,
        data: impl AsRef<[u8]>,
        data_encoding: DataEncoding,
    ) -> Result<VerifiedData, VerifyMessageError> {
        let resolved_data_encoding = data_encoding.resolve_for_read(data.as_ref());
        let message = armor::decode_to_message(data.as_ref(), resolved_data_encoding)?;

        self.verify_message(message)
            .map_err(VerifyMessageError::MessageProcessing)
    }

    /// Verifies a detached signature against the data.
    ///
    /// # Example
    ///
    /// ```
    /// use proton_rpgp::{Verifier, PublicKey, DataEncoding, UnixTime};
    ///
    /// // Assume `public_key` is a valid PublicKey, and `signature` is a detached signature.
    /// let public_key = include_str!("../test-data/keys/public_key_v4.asc");
    /// let signature = include_str!("../test-data/signatures/signature_v4.asc");
    /// let data = b"hello world";
    /// let date = UnixTime::now().unwrap();
    ///
    /// let public_key = PublicKey::import(public_key.as_bytes(), DataEncoding::Armored).unwrap();
    ///
    /// let result = Verifier::default()
    ///     .with_verification_key(&public_key)
    ///     .at_date(date)
    ///     .verify_detached(data, signature, DataEncoding::Armored);
    /// assert!(result.is_ok());
    /// ```
    pub fn verify_detached(
        self,
        data: impl AsRef<[u8]>,
        signature: impl AsRef<[u8]>,
        signature_encoding: DataEncoding,
    ) -> VerificationResult {
        // The buffer is only used if the signature is encoded in armor.
        let mut buffer = Vec::new();

        let resolved_signature_encoding = signature_encoding.resolve_for_read(signature.as_ref());
        // Check encoding.
        let parser = handle_signature_decoding(
            &mut buffer,
            signature.as_ref(),
            resolved_signature_encoding,
        )?;

        // Verify signatures.
        let verified_signatures: Vec<_> = parser
            .filter_map(|packet_result| match packet_result {
                Ok(Packet::Signature(signature)) => Some(signature),
                _ => None,
            })
            .map(|signature| {
                VerifiedSignature::create_by_verifying(
                    self.date,
                    signature,
                    &self.verification_keys,
                    VerificationInput::Data(data.as_ref()),
                    self.verification_context.as_deref(),
                    &self.profile,
                )
            })
            .collect();

        // Select the result.
        VerificationResultCreator::with_signatures(verified_signatures)
    }

    /// Verifies a cleartext signed message with the verifier.
    ///
    /// A cleartext message has the following format:
    /// ```skip
    /// -----BEGIN PGP SIGNED MESSAGE-----
    ///
    /// Cleatext text comes here.
    ///
    /// -----BEGIN PGP SIGNATURE-----
    /// ...
    /// -----END PGP SIGNATURE-----
    /// ```
    /// # Example
    ///
    /// ```
    /// use proton_rpgp::{Verifier, PublicKey, DataEncoding, UnixTime};
    ///
    /// const INPUT_DATA: &str = include_str!("../test-data/messages/signed_cleartext_message_v4.asc");
    ///
    /// let key = PublicKey::import(include_bytes!("../test-data/keys/public_key_v4.asc"), DataEncoding::Armored)
    ///     .expect("Failed to import key");
    ///
    /// let verified_data = Verifier::default()
    ///     .with_verification_key(&key)
    ///     .verify_cleartext(INPUT_DATA)
    ///     .expect("Failed to verify");
    ///
    /// assert_eq!(verified_data.data, b"hello world\n    with multiple lines\n");
    /// assert!(verified_data.verification_result.is_ok());
    /// ```
    pub fn verify_cleartext(
        self,
        cleartext_message: impl AsRef<[u8]>,
    ) -> Result<VerifiedData, VerifyMessageError> {
        let (parsed_message, _) =
            CleartextSignedMessage::from_armor(cleartext_message.as_ref().trim_ascii_end())
                .map_err(|err| {
                    VerifyMessageError::MessageProcessing(MessageProcessingError::MessageParsing(
                        err,
                    ))
                })?;

        let signed_data = parsed_message.signed_text();

        let verified_signatures: Vec<_> = parsed_message
            .signatures()
            .iter()
            .map(|signature| {
                VerifiedSignature::create_by_verifying(
                    self.date,
                    signature.clone(),
                    &self.verification_keys,
                    VerificationInput::Data(signed_data.as_ref()),
                    self.verification_context.as_deref(),
                    &self.profile,
                )
            })
            .collect();

        let output_sanitized = check_and_sanitize_text(parsed_message.signed_text().as_bytes())
            .map_err(MessageProcessingError::TextSanitization)?;

        let verification_result = VerificationResultCreator::with_signatures(verified_signatures);
        Ok(VerifiedData {
            data: output_sanitized,
            verification_result,
        })
    }

    /// Helper function to verify and process a decrypted `OpenPGP` message.
    pub(crate) fn verify_message(
        &self,
        mut message: Message<'_>,
    ) -> Result<VerifiedData, MessageProcessingError> {
        if message.is_encrypted() {
            return Err(MessageProcessingError::Encrypted);
        }

        if message.is_compressed() {
            message = message
                .decompress()
                .map_err(MessageProcessingError::Decompression)?;
            if message.is_compressed() {
                return Err(MessageProcessingError::Compression);
            }
        }

        let mut cleartext = message.as_data_vec()?;

        let verified_signatures = message.verify_nested_to_verified_signatures(
            self.date,
            &self.verification_keys,
            self.verification_context.as_deref(),
            &self.profile,
        )?;

        if self.native_newlines_utf8 {
            cleartext = check_and_sanitize_text(cleartext.as_slice())?;
        }

        let verification_result = VerificationResultCreator::with_signatures(verified_signatures);

        Ok(VerifiedData {
            data: cleartext,
            verification_result,
        })
    }
}

impl Default for Verifier<'_> {
    fn default() -> Self {
        Self::new(DEFAULT_PROFILE.clone())
    }
}

/// The result of verifying signed data in an `OpenPGP` message.
#[derive(Debug, Clone)]
pub struct VerifiedData {
    /// The verified data.
    pub data: Vec<u8>,

    /// The verification result of verifying the underlying signature.
    pub verification_result: VerificationResult,
}

fn handle_signature_decoding<'a>(
    buffer: &'a mut Vec<u8>,
    signature: &'a [u8],
    signature_encoding: ResolvedDataEncoding,
) -> Result<PacketParser<&'a [u8]>, VerificationError> {
    match signature_encoding {
        ResolvedDataEncoding::Unarmored => Ok(PacketParser::new(signature)),
        ResolvedDataEncoding::Armored => {
            armor::decode_to_buffer(signature, Some(BlockType::Signature), buffer)
                .map_err(|err| VerificationError::RuntimeError(err.to_string()))?;
            Ok(PacketParser::new(Box::new(BufReader::new(reader))))
        }
    }
}
