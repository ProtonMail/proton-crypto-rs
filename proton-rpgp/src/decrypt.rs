use std::io::{self, Read};

use pgp::{
    composed::Message, line_writer::LineBreak, normalize_lines::NormalizedReader,
    packet::SignatureType,
};

use crate::{
    DataEncoding, DecryptionError, MessageVerificationExt, PrivateKey, Profile, PublicKey,
    UnixTime, VerificationResultCreator, VerifiedData, DEFAULT_PROFILE,
};

mod message;
pub use message::*;

/// A decryptor for decrypting messages.
#[derive(Debug, Clone)]
pub struct Decryptor<'a> {
    /// The profile to use for the signer.
    profile: &'a Profile,

    /// The signing keys to create signatures with.
    decryption_keys: Vec<&'a PrivateKey>,

    /// The signing keys to create signatures with.
    verification_keys: Vec<&'a PublicKey>,

    /// The date to use for verfying the signatures.
    date: UnixTime,
}

impl<'a> Decryptor<'a> {
    /// Creates a new decryptor with the given profile.
    pub fn new(profile: &'a Profile) -> Self {
        Self {
            profile,
            decryption_keys: Vec::new(),
            verification_keys: Vec::new(),
            date: UnixTime::default(),
        }
    }

    /// Adds a decryption key to the decryptor.
    pub fn with_decryption_key(mut self, key: &'a PrivateKey) -> Self {
        self.decryption_keys.push(key);
        self
    }

    /// Adds multiple decryption keys to the decryptor.
    pub fn with_decryption_keys(mut self, keys: impl IntoIterator<Item = &'a PrivateKey>) -> Self {
        self.decryption_keys.extend(keys);
        self
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

    /// Set the date to verify the signature against.
    ///
    /// In default mode, the system clock is used.
    pub fn at_date(mut self, date: UnixTime) -> Self {
        self.date = date;
        self
    }

    /// Decrypts the given data and tries to verify the included signatures.
    ///
    /// # Example
    ///
    /// ```
    /// use proton_rpgp::{PrivateKey, Decryptor, DataEncoding, AsPublicKeyRef, UnixTime};
    /// let message: &str = include_str!("../test-data/messages/encrypted_message_v4.asc");
    /// let date = UnixTime::new(1_752_572_300);
    ///
    /// let key = PrivateKey::import_unlocked(
    ///     include_str!("../test-data/keys/private_key_v4.asc").as_bytes(),
    ///     DataEncoding::Armored,
    /// ).expect("Failed to import key");
    ///
    /// let verified_data = Decryptor::default()
    ///     .with_decryption_key(&key)
    ///     .with_verification_key(key.as_public_key())
    ///     .at_date(date)
    ///     .decrypt(message.as_bytes(), DataEncoding::Armored)
    ///     .expect("Failed to decrypt");
    ///
    /// assert_eq!(verified_data.data, b"hello world");
    /// assert!(verified_data.verification_result.is_ok());
    /// ```
    pub fn decrypt(
        self,
        data: impl AsRef<[u8]>,
        data_encoding: DataEncoding,
    ) -> Result<VerifiedData, DecryptionError> {
        let mut message = match data_encoding {
            DataEncoding::Armored => {
                Message::from_armor(data.as_ref())
                    .map_err(DecryptionError::MessageParsing)?
                    .0
            }
            DataEncoding::Unarmored => {
                Message::from_bytes(data.as_ref()).map_err(DecryptionError::MessageParsing)?
            }
        };

        if message.is_compressed() {
            message = message.decompress()?;
            if message.is_compressed() {
                return Err(DecryptionError::Compression);
            }
        }

        if message.is_encrypted() {
            message = message.decrypt_with_decryptor(&self)?;
        }

        // We only accept one layer of compression
        if message.is_compressed() {
            message = message.decompress()?;
            if message.is_compressed() {
                return Err(DecryptionError::Compression);
            }
        }

        let mut cleartext = message.as_data_vec()?;

        let verified_signatures = message.verify_nested_to_verified_signatures(
            self.date,
            &self.verification_keys,
            self.profile,
        )?;

        let automatic_sanitization = verified_signatures
            .iter()
            .any(|sig| matches!(sig.signature.typ(), Some(SignatureType::Text)));

        if automatic_sanitization {
            cleartext = sanitize_cleartext(cleartext.as_slice())?;
        }

        let verification_result = VerificationResultCreator::with_signatures(verified_signatures);

        Ok(VerifiedData {
            data: cleartext,
            verification_result,
        })
    }
}

impl Default for Decryptor<'_> {
    fn default() -> Self {
        Self::new(&DEFAULT_PROFILE)
    }
}

fn sanitize_cleartext(cleartext: &[u8]) -> io::Result<Vec<u8>> {
    let mut buffer = Vec::with_capacity(cleartext.len());
    NormalizedReader::new(cleartext, LineBreak::Lf).read_to_end(&mut buffer)?;
    Ok(buffer)
}
