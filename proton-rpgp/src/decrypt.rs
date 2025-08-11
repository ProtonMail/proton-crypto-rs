use pgp::{
    composed::decrypt_session_key_with_password,
    packet::{Packet, PacketParser},
    types::Password,
};

use crate::{
    armor, CloneablePasswords, DataEncoding, DecryptionError, PrivateKey, Profile, PublicKey,
    SessionKey, UnixTime, VerifiedData, Verifier, DEFAULT_PROFILE,
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
    session_keys: Vec<&'a SessionKey>,

    /// The verifier to use for verifying the message.
    verifier: Verifier<'a>,
}

impl<'a> Decryptor<'a> {
    /// Creates a new decryptor with the given profile.
    pub fn new(profile: Profile) -> Self {
        Self {
            decryption_keys: Vec::new(),
            passphrases: CloneablePasswords::default(),
            session_keys: Vec::new(),
            verifier: Verifier::new(profile),
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
    pub fn with_session_key(mut self, key: &'a SessionKey) -> Self {
        self.session_keys.push(key);
        self
    }

    /// Adds multiple session keys to the decryptor to decrypt the message with.
    pub fn with_session_keys(mut self, keys: impl IntoIterator<Item = &'a SessionKey>) -> Self {
        self.session_keys.extend(keys);
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
        self,
        data: impl AsRef<[u8]>,
        data_encoding: DataEncoding,
    ) -> Result<VerifiedData, DecryptionError> {
        let message = armor::decode_to_message(data.as_ref(), data_encoding)?;

        if !message.is_encrypted() {
            return Err(DecryptionError::NoEncryption);
        }

        let message = message.decrypt_with_decryptor(&self)?;

        self.verifier
            .verify_message(message)
            .map_err(DecryptionError::MessageProcessing)
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
}

impl Default for Decryptor<'_> {
    fn default() -> Self {
        Self::new(DEFAULT_PROFILE.clone())
    }
}
