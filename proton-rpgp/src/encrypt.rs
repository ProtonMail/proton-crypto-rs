use std::io::{self, Read};

use pgp::{
    armor::{self, BlockType},
    composed::{ArmorOptions, Encryption, MessageBuilder, PlainSessionKey},
    crypto::{aead::AeadAlgorithm, sym::SymmetricKeyAlgorithm},
    packet::{PacketTrait, PublicKeyEncryptedSessionKey, SymKeyEncryptedSessionKey},
    ser::Serialize,
    types::{CompressionAlgorithm, KeyDetails, KeyVersion, Password},
};
use rand::{CryptoRng, Rng};

use crate::{
    preferences::{EncryptionMechanism, RecipientsAlgorithms},
    ArmorError, CipherSuite, DataEncoding, EncryptionError, KeySelectionError, PrivateKey, Profile,
    PublicComponentKey, PublicKey, PublicKeySelectionExt, SessionKey, Signer, UnixTime,
    DEFAULT_PROFILE,
};

/// Encrypted message type which allows to query information about the encrypted message.
/// TODO: To fulfill the higher level API contract we are going to need
/// `fn as_key_packets(&self) -> &[u8];`
/// `fn as_data_packet(&self) -> &[u8];`
pub struct EncryptedMessage {
    /// The encrypted data.
    pub encrypted_data: Vec<u8>,

    /// The revealed session key if any.
    revealed_session_key: Option<SessionKey>,
}

impl EncryptedMessage {
    fn new(encrypted_data: Vec<u8>, revealed_session_key: Option<SessionKey>) -> Self {
        Self {
            encrypted_data,
            revealed_session_key,
        }
    }

    /// Returns the revealed session key if enabled
    pub fn revealed_session_key(&self) -> Option<&SessionKey> {
        self.revealed_session_key.as_ref()
    }

    /// Returns the armored message.
    pub fn armor(&self) -> Result<Vec<u8>, ArmorError> {
        let mut output = Vec::with_capacity(self.encrypted_data.len());
        armor::write(self, BlockType::Message, &mut output, None, true)
            .map_err(ArmorError::Encode)?;
        Ok(output)
    }
}

impl Serialize for EncryptedMessage {
    fn to_writer<W: io::Write>(&self, w: &mut W) -> pgp::errors::Result<()> {
        w.write_all(&self.encrypted_data)?;
        Ok(())
    }

    fn write_len(&self) -> usize {
        self.encrypted_data.len()
    }
}

impl AsRef<[u8]> for EncryptedMessage {
    fn as_ref(&self) -> &[u8] {
        &self.encrypted_data
    }
}

/// The encryptor to use to perform `OpenPGP` encryption/signcryption operations.
pub struct Encryptor<'a> {
    /// The encryption keys to use.
    encryption_keys: Vec<&'a PublicKey>,

    /// The passphrases to encrypt the message with.
    passphrases: Vec<Password>,

    /// The session keys to use.
    session_key: Option<PlainSessionKey>,

    /// Message compression preference.
    message_compression: CompressionAlgorithm,

    /// Message symmetric algorithm preference.
    message_symmetric_algorithm: SymmetricKeyAlgorithm,

    /// Message AEAD cipher suite preference.
    message_cipher_suite: Option<CipherSuite>,

    /// The internal signer to use for the signing part.
    signer: Signer<'a>,
}

impl<'a> Encryptor<'a> {
    /// Creates a new encryptor with the given profile.
    pub fn new(profile: &'a Profile) -> Self {
        Self {
            encryption_keys: Vec::new(),
            passphrases: Vec::new(),
            session_key: None,
            message_compression: profile.message_compression(),
            message_symmetric_algorithm: profile.message_symmetric_algorithm(),
            message_cipher_suite: profile.message_aead_cipher_suite(),
            signer: Signer::new(profile),
        }
    }

    /// Adds a encryption key to the encryptor.
    pub fn with_encryption_key(mut self, key: &'a PublicKey) -> Self {
        self.encryption_keys.push(key);
        self
    }

    /// Adds multiple encryption keys to the encryptor.
    pub fn with_encryption_keys(mut self, keys: impl IntoIterator<Item = &'a PublicKey>) -> Self {
        self.encryption_keys.extend(keys);
        self
    }

    /// Adds a signing key to the signer.
    pub fn with_signing_key(mut self, key: &'a PrivateKey) -> Self {
        self.signer = self.signer.with_signing_key(key);
        self
    }

    /// Adds multiple signing keys to the signer.
    ///
    /// For each key, a signature will be created.
    pub fn with_signing_keys(mut self, keys: impl IntoIterator<Item = &'a PrivateKey>) -> Self {
        self.signer = self.signer.with_signing_keys(keys);
        self
    }

    /// Adds a passphrase to the encryptor.
    ///
    /// If a password is set, the output message will contain a key packet encrypted
    /// with the password.
    pub fn with_passphrase(mut self, passphrase: impl AsRef<[u8]>) -> Self {
        self.passphrases.push(Password::from(passphrase.as_ref()));
        self
    }

    /// Adds multiple passphrases to the encryptor.
    pub fn with_passphrases(
        mut self,
        passphrases: impl IntoIterator<Item = impl AsRef<[u8]>>,
    ) -> Self {
        self.passphrases
            .extend(passphrases.into_iter().map(|p| Password::from(p.as_ref())));
        self
    }

    /// TODO: Add datapacket session key encryption.
    pub fn with_session_key(mut self, key: &SessionKey) -> Self {
        self.session_key = Some(key.clone().into());
        self
    }

    /// Sets the signature type to text.
    ///
    /// TODO(CRYPTO-296): This option should also trigger the utf-8 literal data packet type.
    pub fn as_utf8(mut self) -> Self {
        self.signer = self.signer.as_utf8();
        self
    }

    /// Sets the date to use for the signatures and keys selection.
    pub fn at_date(mut self, date: UnixTime) -> Self {
        self.signer = self.signer.at_date(date);
        self
    }

    /// Enables compression for the encryption.
    ///
    /// The default is determined by the profile (most likely uncompressed).
    /// Compression affects security and should be used with care.
    pub fn compress(mut self) -> Self {
        self.message_compression = CompressionAlgorithm::ZLIB;
        self
    }

    /// Encrypts and optionally signs the given data and returns an `OpenPGP` message type.
    ///
    /// If no signing key is provided, the data will be encrypted without a signature.
    /// If a signing key is provided, the data will be signed before encryption.
    ///
    /// # Example
    ///
    /// ```rust
    /// use proton_rpgp::{AsPublicKeyRef, DataEncoding, Decryptor, Encryptor, PrivateKey};
    ///
    /// let key = PrivateKey::import_unlocked(include_bytes!("../test-data/keys/private_key_v4.asc"), DataEncoding::Armored)
    ///     .expect("Failed to import key");
    ///
    /// let encrypted_message = Encryptor::default()
    ///     .with_encryption_key(key.as_public_key())
    ///     .with_signing_key(&key)
    ///     .encrypt(b"Hello world!")
    ///     .expect("Failed to encrypt");
    /// ```
    pub fn encrypt(self, data: &'a [u8]) -> Result<EncryptedMessage, EncryptionError> {
        self.write_and_signcrypt(data, DataEncoding::Unarmored, true)
            .map(|(encrypted_data, revealed_session_key)| {
                EncryptedMessage::new(encrypted_data, revealed_session_key)
            })
    }

    /// Encrypts the session key and returns the encrypted session key packets (Key packets).
    pub fn encrypt_session_key(self, session_key: &SessionKey) -> Result<Vec<u8>, EncryptionError> {
        let encryption_keys = self.select_encryption_keys()?;

        let recipients_algo = RecipientsAlgorithms::select(
            self.message_symmetric_algorithm,
            self.message_cipher_suite,
            self.message_compression,
            &encryption_keys,
            self.profile(),
        );

        let mut rng = self.profile().rng();
        let mut pkesks = Vec::with_capacity(encryption_keys.len());
        let mut skesks = Vec::with_capacity(self.passphrases.len());

        let encryption_mechanism = match &session_key.inner {
            PlainSessionKey::V3_4 { sym_alg, .. } => EncryptionMechanism::SeipdV1(*sym_alg),
            PlainSessionKey::V6 { .. } => {
                // The algorithms are only used for v6 password based encryption.
                // Thus, it would not matter if the session does not match the symmetric algorithm.
                let (symmetric_algorithm, aead_algorithm) = recipients_algo
                    .aead_ciphersuite
                    .unwrap_or((SymmetricKeyAlgorithm::AES256, AeadAlgorithm::Gcm));
                EncryptionMechanism::SeipdV2(symmetric_algorithm, aead_algorithm)
            }
            PlainSessionKey::Unknown { sym_alg, .. } => {
                let mechanism = recipients_algo.encryption_mechanism();
                match mechanism {
                    EncryptionMechanism::SeipdV1(_) => EncryptionMechanism::SeipdV1(*sym_alg),
                    EncryptionMechanism::SeipdV2(_, aead_algorithm) => {
                        EncryptionMechanism::SeipdV2(*sym_alg, aead_algorithm)
                    }
                }
            }
            PlainSessionKey::V5 { .. } => {
                return Err(EncryptionError::NotSupported(
                    "V5 session key is not supported for encryption".to_string(),
                ));
            }
        };

        let session_key_bytes = session_key.as_bytes();
        for encryption_key in &encryption_keys {
            let pkesk = match encryption_mechanism {
                EncryptionMechanism::SeipdV1(symmetric_key_algorithm) => {
                    PublicKeyEncryptedSessionKey::from_session_key_v3(
                        &mut rng,
                        session_key_bytes,
                        symmetric_key_algorithm,
                        &encryption_key.public_key,
                    )
                    .map_err(EncryptionError::PkeskEncryption)?
                }
                EncryptionMechanism::SeipdV2(_, _) => {
                    PublicKeyEncryptedSessionKey::from_session_key_v6(
                        &mut rng,
                        session_key_bytes,
                        &encryption_key.public_key,
                    )
                    .map_err(EncryptionError::PkeskEncryption)?
                }
            };
            pkesks.push(pkesk);
        }

        for password in &self.passphrases {
            let skesk = match encryption_mechanism {
                EncryptionMechanism::SeipdV1(sym_alg) => {
                    let s2k = self.profile().message_s2k_params();
                    SymKeyEncryptedSessionKey::encrypt_v4(password, session_key_bytes, s2k, sym_alg)
                        .map_err(EncryptionError::SkeskEncryption)?
                }
                EncryptionMechanism::SeipdV2(sym_alg, aead_alg) => {
                    let s2k = self.profile().message_s2k_params();
                    SymKeyEncryptedSessionKey::encrypt_v6(
                        &mut rng,
                        password,
                        session_key_bytes,
                        s2k,
                        sym_alg,
                        aead_alg,
                    )
                    .map_err(EncryptionError::SkeskEncryption)?
                }
            };
            skesks.push(skesk);
        }

        let mut output = Vec::new();
        for pkesk in pkesks {
            pkesk
                .to_writer_with_header(&mut output)
                .map_err(EncryptionError::DataEncryption)?;
        }
        for skesk in skesks {
            skesk
                .to_writer_with_header(&mut output)
                .map_err(EncryptionError::DataEncryption)?;
        }
        Ok(output)
    }

    /// Encrypts and optionally signs the given data and returns a serialized `OpenPGP` message.
    ///
    /// If no signing key is provided, the data will be encrypted without a signature.
    /// If a signing key is provided, the data will be signed before encryption.
    ///
    /// # Example
    ///
    /// ```rust
    /// use proton_rpgp::{AsPublicKeyRef, DataEncoding, Decryptor, Encryptor, PrivateKey};
    ///
    /// let key = PrivateKey::import_unlocked(include_bytes!("../test-data/keys/private_key_v4.asc"), DataEncoding::Armored)
    ///     .expect("Failed to import key");
    ///
    /// let encrypted_data = Encryptor::default()
    ///     .with_encryption_key(key.as_public_key())
    ///     .with_signing_key(&key)
    ///     .encrypt_raw(b"Hello world!", DataEncoding::Armored)
    ///     .expect("Failed to encrypt");
    /// ```
    pub fn encrypt_raw(
        self,
        data: &'a [u8],
        data_encoding: DataEncoding,
    ) -> Result<Vec<u8>, EncryptionError> {
        self.write_and_signcrypt(data, data_encoding, false)
            .map(|(data, _)| data)
    }

    fn write_and_signcrypt(
        self,
        data: &'a [u8],
        data_encoding: DataEncoding,
        extract_session_key: bool,
    ) -> Result<(Vec<u8>, Option<SessionKey>), EncryptionError> {
        let encryption_keys = self.select_encryption_keys()?;

        let recipients_algorithm_selection = RecipientsAlgorithms::select(
            self.message_symmetric_algorithm,
            self.message_cipher_suite,
            self.message_compression,
            &encryption_keys,
            self.profile(),
        );

        let mut message_builder = MessageBuilder::from_reader("", data);

        // Set the compression algorithm if any.
        message_builder.compression(recipients_algorithm_selection.compression_algorithm);

        // Check that the input data is valid for signature type text if enabled.
        self.signer.check_input_data(data)?;

        let mut rng = self.profile().rng();
        let mut output = Vec::new();
        let mut revealed_session_key = None;
        match recipients_algorithm_selection.encryption_mechanism() {
            EncryptionMechanism::SeipdV1(symmetric_key_algorithm) => {
                let mut seipd_v1_builder =
                    message_builder.seipd_v1(&mut rng, symmetric_key_algorithm);

                for encryption_key in &encryption_keys {
                    seipd_v1_builder
                        .encrypt_to_key(&mut rng, &encryption_key.public_key)
                        .map_err(EncryptionError::PkeskEncryption)?;
                }

                for passphrase in &self.passphrases {
                    let s2k = self.profile().message_s2k_params();
                    seipd_v1_builder
                        .encrypt_with_password(s2k, passphrase)
                        .map_err(EncryptionError::SkeskEncryption)?;
                }

                if extract_session_key {
                    let session_key = SessionKey::new_v4(
                        seipd_v1_builder.session_key().as_slice(),
                        symmetric_key_algorithm,
                    );
                    revealed_session_key = Some(session_key);
                }

                self.write_and_sign(
                    seipd_v1_builder,
                    &encryption_keys,
                    &recipients_algorithm_selection,
                    data_encoding,
                    rng,
                    &mut output,
                )?;
            }
            EncryptionMechanism::SeipdV2(symmetric_key_algorithm, aead_algorithm) => {
                let mut seipd_v2_builder = message_builder.seipd_v2(
                    &mut rng,
                    symmetric_key_algorithm,
                    aead_algorithm,
                    self.profile().message_aead_chunk_size(),
                );

                for encryption_key in &encryption_keys {
                    seipd_v2_builder
                        .encrypt_to_key(&mut rng, &encryption_key.public_key)
                        .map_err(EncryptionError::PkeskEncryption)?;
                }

                for passphrase in &self.passphrases {
                    let s2k = self.profile().message_s2k_params();
                    seipd_v2_builder
                        .encrypt_with_password(&mut rng, s2k, passphrase)
                        .map_err(EncryptionError::SkeskEncryption)?;
                }

                if extract_session_key {
                    revealed_session_key = Some(SessionKey::new_v6(
                        seipd_v2_builder.session_key().as_slice(),
                    ));
                }

                self.write_and_sign(
                    seipd_v2_builder,
                    &encryption_keys,
                    &recipients_algorithm_selection,
                    data_encoding,
                    rng,
                    &mut output,
                )?;
            }
        }

        Ok((output, revealed_session_key))
    }

    /// Helper function to optionally sign the message and write it to the output.
    fn write_and_sign<RAND, W, R, E>(
        &self,
        message_builder: MessageBuilder<R, E>,
        encryption_keys: &[PublicComponentKey<'_>],
        recipients_algorithm_selection: &RecipientsAlgorithms,
        data_encoding: DataEncoding,
        rng: RAND,
        output: W,
    ) -> Result<(), EncryptionError>
    where
        RAND: Rng + CryptoRng,
        W: io::Write,
        R: Read,
        E: Encryption,
    {
        let signing_keys = self
            .signer
            .select_signing_keys()
            .map_err(EncryptionError::SigningKeySelection)?;

        let signed_builder = self.signer.sign_message(
            message_builder,
            &signing_keys,
            Some(recipients_algorithm_selection),
        );

        to_writer(encryption_keys, signed_builder, data_encoding, rng, output)?;

        Ok(())
    }

    /// Helper function to select the encryption keys to use for the encryption.
    fn select_encryption_keys(&self) -> Result<Vec<PublicComponentKey<'_>>, KeySelectionError> {
        self.encryption_keys
            .iter()
            .map(|key| key.inner.encryption_key(self.signer.date, self.profile()))
            .collect()
    }

    /// Returns the internally set profile.
    fn profile(&self) -> &Profile {
        self.signer.profile()
    }
}

impl Default for Encryptor<'_> {
    fn default() -> Self {
        Self::new(&DEFAULT_PROFILE)
    }
}

fn to_writer<'a, RAND, W, R, E>(
    encryption_keys: &'a [PublicComponentKey<'a>],
    message_builder: MessageBuilder<R, E>,
    data_encoding: DataEncoding,
    rng: RAND,
    output: W,
) -> Result<(), EncryptionError>
where
    RAND: Rng + CryptoRng,
    W: io::Write,
    R: Read,
    E: Encryption,
{
    match data_encoding {
        DataEncoding::Armored => {
            let all_v6 = encryption_keys
                .iter()
                .all(|key| key.public_key.version() == KeyVersion::V6);
            message_builder
                .to_armored_writer(
                    rng,
                    ArmorOptions {
                        headers: None,
                        include_checksum: !all_v6,
                    },
                    output,
                )
                .map_err(EncryptionError::DataEncryption)?;
        }
        DataEncoding::Unarmored => message_builder
            .to_writer(rng, output)
            .map_err(EncryptionError::DataEncryption)?,
    }
    Ok(())
}
