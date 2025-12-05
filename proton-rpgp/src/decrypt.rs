use std::{
    borrow::Cow,
    fmt,
    io::{self, BufRead, BufReader, Read},
    mem,
};

use pgp::{
    composed::decrypt_session_key_with_password,
    packet::{Packet, PacketParser},
    types::Password,
};

use crate::{
    armor, CheckUnixTime, CloneablePasswords, DataEncoding, DecryptionError,
    ExternalDetachedSignature, PrivateKey, Profile, PublicKey, SessionKey, VerificationContext,
    VerificationResult, VerifiedData, Verifier, VerifyingReader, DEFAULT_PROFILE,
};

mod message;
pub use message::*;

/// A decryptor for decrypting messages.
#[derive(Debug, Clone)]
pub struct Decryptor<'a> {
    /// The signing keys to create signatures with.
    decryption_keys: Vec<&'a PrivateKey>,

    /// The passphrases to decrypt the message with.
    passphrases: CloneablePasswords,

    /// The session keys to decrypt the message with.
    session_keys: Vec<Cow<'a, SessionKey>>,

    /// The verifier to use for verifying the message.
    verifier: Verifier<'a>,

    /// Allows to specify an external detached signature to verify over the decrypted data.
    ///
    /// When supplied only this signature is consider and message signatures are ignored.
    detached_signature: Option<ExternalDetachedSignature<'a>>,

    /// Indicates wether forwading decryption is allowed.
    allow_forwarding_decryption: bool,
}

impl<'a> Decryptor<'a> {
    /// Creates a new decryptor with the given profile.
    pub fn new(profile: Profile) -> Self {
        Self {
            decryption_keys: Vec::new(),
            passphrases: CloneablePasswords::default(),
            session_keys: Vec::new(),
            verifier: Verifier::new(profile),
            detached_signature: None,
            allow_forwarding_decryption: false,
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
        self.verifier = self.verifier.with_verification_key(key);
        self
    }

    /// Set the verification keys to use.
    pub fn with_verification_keys(mut self, keys: impl IntoIterator<Item = &'a PublicKey>) -> Self {
        self.verifier = self.verifier.with_verification_keys(keys);
        self
    }

    /// Adds a passphrase to the decryptor to decrypt the message with.
    pub fn with_passphrase(mut self, passphrase: impl AsRef<[u8]>) -> Self {
        self.passphrases.0.push(Password::from(passphrase.as_ref()));
        self
    }

    /// Adds multiple passphrases to the decryptor to decrypt the message with.
    pub fn with_passphrases(
        mut self,
        passphrases: impl IntoIterator<Item = impl AsRef<[u8]>>,
    ) -> Self {
        self.passphrases
            .0
            .extend(passphrases.into_iter().map(|p| Password::from(p.as_ref())));
        self
    }

    /// Adds a session key to the decryptor to decrypt the message with.
    pub fn with_session_key(mut self, key: impl Into<Cow<'a, SessionKey>>) -> Self {
        self.session_keys.push(key.into());
        self
    }

    /// Adds multiple session keys to the decryptor to decrypt the message with.
    pub fn with_session_keys(mut self, keys: impl IntoIterator<Item = &'a SessionKey>) -> Self {
        self.session_keys.extend(keys.into_iter().map(Into::into));
        self
    }

    /// Allows to specify the expected application context of a signature.
    ///
    /// The [`VerificationContext`] encodes how the signature context should be checked.
    pub fn with_verification_context(
        mut self,
        context: impl Into<Cow<'a, VerificationContext>>,
    ) -> Self {
        self.verifier = self.verifier.with_verification_context(context);
        self
    }

    /// Allows to specify an external detached signature to verify over the decrypted data.
    ///
    /// When supplied only this signature is considered and message signatures are ignored
    /// for the verification result.
    pub fn with_external_detached_signature(
        mut self,
        detached_signature: ExternalDetachedSignature<'a>,
    ) -> Self {
        self.detached_signature = Some(detached_signature);
        self
    }

    /// Set the date to verify the signature against.
    ///
    /// In default mode, the system clock is used.
    pub fn at_date(mut self, date: CheckUnixTime) -> Self {
        self.verifier = self.verifier.at_date(date);
        self
    }

    /// Setting output Utf8 indicates if the output plaintext is Utf8 encoded and
    /// should be sanitized from canonicalised line endings.
    ///
    /// If this setting is enabled, the decryptor throws an error if the output is
    /// not Utf-8 encoded.
    /// Further, the decryptor replaces canonical newlines (`\r\n`) with native newlines (`\n`).
    pub fn output_utf8(mut self) -> Self {
        self.verifier = self.verifier.output_utf8();
        self
    }

    /// If enabled, allows to use `OpenPGP` keys marked as forwarding keys for decryption.
    ///
    /// Forwading key decryption is disabled by default.
    pub fn allow_forwarding_decryption(mut self, allow: bool) -> Self {
        self.allow_forwarding_decryption = allow;
        self
    }

    /// Decrypts the given data and tries to verify the included signatures.
    ///
    /// # Example
    ///
    /// ```
    /// use proton_rpgp::{PrivateKey, Decryptor, DataEncoding, AsPublicKeyRef, CheckUnixTime};
    /// let message: &str = include_str!("../test-data/messages/encrypted_message_v4.asc");
    /// let date = CheckUnixTime::new(1_752_572_300);
    ///
    /// let key = PrivateKey::import_unlocked(
    ///     include_str!("../test-data/keys/private_key_v4.asc").as_bytes(),
    ///     DataEncoding::Armored,
    /// ).expect("Failed to import key");
    ///
    /// let verified_data = Decryptor::default()
    ///     .with_decryption_key(&key)
    ///     .with_verification_key(key.as_public_key())
    ///     .at_date(date.into())
    ///     .decrypt(message.as_bytes(), DataEncoding::Armored)
    ///     .expect("Failed to decrypt");
    ///
    /// assert_eq!(verified_data.data, b"hello world");
    /// assert!(verified_data.verification_result.is_ok());
    /// ```
    pub fn decrypt(
        mut self,
        data: impl AsRef<[u8]>,
        data_encoding: DataEncoding,
    ) -> crate::Result<VerifiedData> {
        let resolved_data_encoding = data_encoding.resolve_for_read(data.as_ref());
        let message = armor::decode_to_message(data.as_ref(), resolved_data_encoding)
            .map_err(DecryptionError::MessageProcessing)?;

        if !message.is_encrypted() {
            return Err(DecryptionError::NoEncryption.into());
        }

        let message = message.decrypt_with_decryptor(&self)?;

        if let Some(detached_signature) = self.detached_signature.take() {
            let mut verified_data = self
                .verifier
                .verify_message(message)
                .map_err(DecryptionError::MessageProcessing)?;
            verified_data.verification_result =
                self.verify_detached_signature(detached_signature, &verified_data.data)?;
            Ok(verified_data)
        } else {
            self.verifier
                .verify_message(message)
                .map_err(DecryptionError::MessageProcessing)
                .map_err(Into::into)
        }
    }

    /// Decrypts the given data and tries to verify the included signatures.
    ///
    /// Instead of directly returning the decrypted and verified data,
    /// this method returns a reader that can be used to read the decrypted data from the input source.
    /// Once all data has been read, the verification result can be
    /// obtained by calling the `verification_result` method on the reader.
    ///
    /// # Example
    ///
    /// ```
    /// use std::io;
    /// use proton_rpgp::{PrivateKey, Decryptor, DataEncoding, AsPublicKeyRef, UnixTime};
    ///
    /// const INPUT_DATA: &str = include_str!("../test-data/messages/encrypted_message_v4.asc");
    /// let date = UnixTime::new(1_752_572_300);
    ///
    /// let key = PrivateKey::import_unlocked(
    ///     include_str!("../test-data/keys/private_key_v4.asc").as_bytes(),
    ///     DataEncoding::Armored,
    /// ).expect("Failed to import key");
    ///
    /// let mut verifying_reader = Decryptor::default()
    ///     .with_decryption_key(&key)
    ///     .with_verification_key(key.as_public_key())
    ///     .at_date(date.into())
    ///     .decrypt_stream(INPUT_DATA.as_bytes(), DataEncoding::Armored)
    ///     .expect("Failed to decrypt");
    ///
    /// let mut buffer = Vec::new();
    /// io::copy(&mut verifying_reader, &mut buffer).expect("Failed to copy");
    /// let verification_result = verifying_reader.verification_result();
    ///
    /// assert_eq!(buffer, b"hello world");
    /// assert!(verification_result.is_ok());
    /// ```
    pub fn decrypt_stream(
        mut self,
        data: impl Read + Send + 'a,
        data_encoding: DataEncoding,
    ) -> crate::Result<VerifyingReader<'a>> {
        let mut buffered_reader = BufReaderWithDebug::new(data);
        let resolved_data_encoding = data_encoding.resolve_for_read_stream(&mut buffered_reader);
        let message = armor::decode_to_message_reader(buffered_reader, resolved_data_encoding)
            .map_err(DecryptionError::MessageProcessing)?;

        if !message.is_encrypted() {
            return Err(DecryptionError::NoEncryption.into());
        }

        let message = message.decrypt_with_decryptor(&self)?;

        if let Some(detached_signature) = self.detached_signature.take() {
            let message_reader = self
                .clone()
                .verifier
                .verify_message_stream(message)
                .map_err(DecryptionError::MessageProcessing)?;
            let reader =
                self.verify_detached_signature_stream(detached_signature, message_reader)?;
            Ok(reader)
        } else {
            self.verifier
                .verify_message_stream(message)
                .map_err(DecryptionError::MessageProcessing)
                .map_err(Into::into)
        }
    }

    /// Decrypts the session key from the given key packets.
    ///
    /// The key packets are encoded as raw bytes.
    pub fn decrypt_session_key(self, key_packets: impl AsRef<[u8]>) -> crate::Result<SessionKey> {
        let packet_parser = PacketParser::new(key_packets.as_ref());

        let mut errors = Vec::new();
        for packet in packet_parser.flatten() {
            match packet {
                Packet::PublicKeyEncryptedSessionKey(pkesk) => {
                    match handle_pkesk_decryption(
                        &pkesk,
                        self.decryption_keys.iter().copied(),
                        self.allow_forwarding_decryption,
                        self.profile(),
                    ) {
                        Ok(session_key) => return Ok(session_key.into()),
                        Err(err) => errors.push(err),
                    }
                }
                Packet::SymKeyEncryptedSessionKey(skesk) => {
                    for passphrase in &*self.passphrases {
                        match decrypt_session_key_with_password(&skesk, passphrase) {
                            Ok(session_key) => return Ok(session_key.into()),
                            Err(err) => errors.push(DecryptionError::SkeskDecryption(err)),
                        }
                    }
                }
                _ => (),
            }
        }

        if errors.is_empty() {
            errors.push(DecryptionError::NoKeyPackets);
        }

        Err(DecryptionError::SessionKeyDecryption(errors.into()).into())
    }

    pub(crate) fn profile(&self) -> &Profile {
        &self.verifier.profile
    }

    /// Helper function to verify external detached signature on the decrypted data.
    fn verify_detached_signature(
        mut self,
        signature: ExternalDetachedSignature,
        data: &[u8],
    ) -> Result<VerificationResult, DecryptionError> {
        let verification_result = match signature {
            ExternalDetachedSignature::Unencrypted(signature, signature_data_encoding) => self
                .verifier
                .verify_detached(data, signature, signature_data_encoding.into()),
            ExternalDetachedSignature::Encrypted(signature, signature_data_encoding) => {
                let profile = self.verifier.profile.clone();
                let verifier = mem::replace(&mut self.verifier, Verifier::new(profile));
                let decrypted_signature =
                    self.decrypt(signature.as_ref(), signature_data_encoding.into())?;
                verifier.verify_detached(data, &decrypted_signature.data, DataEncoding::Unarmored)
            }
        };
        Ok(verification_result)
    }

    /// Helper function to verify an external detached signature with a reader.
    fn verify_detached_signature_stream(
        mut self,
        signature: ExternalDetachedSignature,
        data: impl Read + 'a,
    ) -> Result<VerifyingReader<'a>, DecryptionError> {
        let reader = match signature {
            ExternalDetachedSignature::Unencrypted(signature, signature_data_encoding) => self
                .verifier
                .verify_detached_stream(data, signature, signature_data_encoding.into()),
            ExternalDetachedSignature::Encrypted(signature, signature_data_encoding) => {
                let profile = self.verifier.profile.clone();
                let verifier = mem::replace(&mut self.verifier, Verifier::new(profile));
                let decrypted_signature =
                    self.decrypt(signature.as_ref(), signature_data_encoding.into())?;
                verifier.verify_detached_stream(
                    data,
                    &decrypted_signature.data,
                    DataEncoding::Unarmored,
                )
            }
        };
        Ok(reader?)
    }
}

impl Default for Decryptor<'_> {
    fn default() -> Self {
        Self::new(DEFAULT_PROFILE.clone())
    }
}

impl<'a> From<Decryptor<'a>> for Verifier<'a> {
    fn from(decryptor: Decryptor<'a>) -> Self {
        decryptor.verifier
    }
}

/// Helper struct to wrap a reader without requiring it to implement the `Debug` trait.
struct BufReaderWithDebug<R: Read + Send>(BufReader<R>);

impl<R: Read + Send> BufReaderWithDebug<R> {
    fn new(inner: R) -> Self {
        Self(BufReader::new(inner))
    }
}

impl<R: Read + Send> fmt::Debug for BufReaderWithDebug<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Encryted data")
    }
}

impl<R: Read + Send> Read for BufReaderWithDebug<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl<R: Read + Send> BufRead for BufReaderWithDebug<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.0.fill_buf()
    }

    fn consume(&mut self, amount: usize) {
        self.0.consume(amount);
    }
}
