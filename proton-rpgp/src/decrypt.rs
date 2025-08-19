use std::borrow::Cow;

use pgp::{
    composed::decrypt_session_key_with_password,
    packet::{Packet, PacketParser},
    types::Password,
};

use crate::{
    armor, CloneablePasswords, DataEncoding, DecryptionError, ExternalDetachedSignature,
    PrivateKey, Profile, PublicKey, SessionKey, UnixTime, VerificationContext, VerificationResult,
    VerifiedData, Verifier, DEFAULT_PROFILE,
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

    /// Allows to specify an external detached signature to verify over the decrytped data.
    ///
    /// When supplied only this signature is consider and message signatures are ignored.
    detached_signature: Option<ExternalDetachedSignature<'a>>,
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

    /// Allows to specify an external detached signature to verify over the decytped data.
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
    pub fn at_date(mut self, date: UnixTime) -> Self {
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
        mut self,
        data: impl AsRef<[u8]>,
        data_encoding: DataEncoding,
    ) -> Result<VerifiedData, DecryptionError> {
        let resolved_data_encoding = data_encoding.resolve_for_read(data.as_ref());
        let message = armor::decode_to_message(data.as_ref(), resolved_data_encoding)?;

        if !message.is_encrypted() {
            return Err(DecryptionError::NoEncryption);
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
        }
    }

    /// Decrypts the session key from the given key packets.
    ///
    /// The key packets are encoded as raw bytes.
    pub fn decrypt_session_key(
        self,
        key_packets: impl AsRef<[u8]>,
    ) -> Result<SessionKey, DecryptionError> {
        let packet_parser = PacketParser::new(key_packets.as_ref());

        let mut errors = Vec::new();
        for packet in packet_parser.flatten() {
            match packet {
                Packet::PublicKeyEncryptedSessionKey(pkesk) => {
                    match handle_pkesk_decryption(
                        &pkesk,
                        self.decryption_keys.iter().copied(),
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

        Err(DecryptionError::SessionKeyDecryption(errors.into()))
    }

    pub(crate) fn profile(&self) -> &Profile {
        &self.verifier.profile
    }

    /// Helper function to verify external detached signature on the decrypted data.
    fn verify_detached_signature(
        self,
        signature: ExternalDetachedSignature,
        data: &[u8],
    ) -> Result<VerificationResult, DecryptionError> {
        let verification_result = match signature {
            ExternalDetachedSignature::Plain(signature, signature_data_encoding) => self
                .verifier
                .verify_detached(data, signature, signature_data_encoding),
            ExternalDetachedSignature::Encrypted(signature, signature_data_encoding) => {
                let verifier = self.verifier.clone();
                let decrytped_siganture =
                    self.decrypt(signature.as_ref(), signature_data_encoding)?;
                verifier.verify_detached(data, &decrytped_siganture.data, DataEncoding::Unarmored)
            }
        };
        Ok(verification_result)
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
