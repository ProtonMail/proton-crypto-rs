use std::io::{self, Read};

use pgp::{
    armor::{self, BlockType},
    composed::{
        ArmorOptions, CleartextSignedMessage, Encryption, MessageBuilder, StandaloneSignature,
        SubpacketConfig,
    },
    packet::SignatureVersion,
    ser::Serialize,
    types::{CompressionAlgorithm, KeyDetails, KeyVersion, Password},
};
use rand::{CryptoRng, Rng};

use crate::{
    core::signature_subpackets,
    preferences::{self, RecipientsAlgorithms},
    DataEncoding, KeySelectionError, PrivateComponentKey, PrivateKey, PrivateKeySelectionExt,
    Profile, SignError, SignatureContext, SignatureMode, SignatureUsage, UnixTime, DEFAULT_PROFILE,
};

/// A signer that can create `OpenPGP` signatures over data.
#[derive(Debug, Clone)]
pub struct Signer<'a> {
    /// The profile to use for the signer.
    pub(crate) profile: Profile,

    /// The signing keys to create signatures with.
    pub(crate) signing_keys: Vec<&'a PrivateKey>,

    /// The date to use for the signatures.
    pub(crate) date: UnixTime,

    /// The signature type to use for the signatures.
    ///
    /// Either binary or text.
    pub(crate) signature_type: SignatureMode,

    /// The signature context to use for the message signatures.
    pub(crate) signature_context: Option<SignatureContext>,
}

impl<'a> Signer<'a> {
    /// Create a new verifier with the given profile.
    pub fn new(profile: Profile) -> Self {
        Self {
            profile,
            signing_keys: Vec::new(),
            date: UnixTime::now().unwrap_or_default(),
            signature_type: SignatureMode::default(),
            signature_context: None,
        }
    }

    /// Adds a signing key to the signer.
    pub fn with_signing_key(mut self, key: &'a PrivateKey) -> Self {
        self.signing_keys.push(key);
        self
    }

    /// Adds multiple signing keys to the signer.
    ///
    /// For each key, a signature will be created.
    pub fn with_signing_keys(mut self, keys: impl IntoIterator<Item = &'a PrivateKey>) -> Self {
        self.signing_keys.extend(keys);
        self
    }

    /// Sets the date to use for the signatures.
    pub fn at_date(mut self, date: UnixTime) -> Self {
        self.date = date;
        self
    }

    /// Sets the application signature context to use for the message signatures.
    pub fn with_signature_context(mut self, context: SignatureContext) -> Self {
        self.signature_context = Some(context);
        self
    }

    /// Sets the signature type to text.
    ///
    /// If this is set, `OpenPGP` will canonicalize the line endings in the signature data before signing.
    pub fn as_utf8(mut self) -> Self {
        self.signature_type = SignatureMode::Text;
        self
    }

    /// Creates an inline-signed `OpenPGP` message.
    ///
    /// # Example
    ///
    /// ```
    /// use proton_rpgp::{Signer, DataEncoding, UnixTime, PrivateKey};
    ///
    /// let key = PrivateKey::import_unlocked(include_bytes!("../test-data/keys/private_key_v4.asc"), DataEncoding::Armored)
    ///     .expect("Failed to import key");
    ///
    /// let message = Signer::default()
    ///     .with_signing_key(&key)
    ///     .sign("hello world", DataEncoding::Armored)
    ///     .expect("Failed to sign");
    /// ```
    pub fn sign(
        self,
        data: impl AsRef<[u8]>,
        message_encoding: DataEncoding,
    ) -> Result<Vec<u8>, SignError> {
        let mut message_builder = MessageBuilder::from_reader("", data.as_ref());

        let signing_keys = self.select_signing_keys()?;

        // Compression is determined by the profile.
        if self.profile.message_compression() != CompressionAlgorithm::Uncompressed {
            message_builder.compression(self.profile.message_compression());
        }

        let signed_builder = self.sign_message(message_builder, &signing_keys, None)?;

        let mut buffer = Vec::new();
        let rng = self.profile.rng();
        to_writer(
            &signing_keys,
            signed_builder,
            message_encoding,
            rng,
            &mut buffer,
        )?;

        Ok(buffer)
    }

    /// Signs the given data and returns the signature.
    ///
    /// # Example
    ///
    /// ```
    /// use proton_rpgp::{Signer, DataEncoding, UnixTime, PrivateKey};
    /// let key_data = include_str!("../test-data/keys/private_key_v4.asc");
    /// let key = PrivateKey::import_unlocked(key_data.as_bytes(), DataEncoding::Armored)
    ///     .expect("Failed to import key");
    ///
    /// let signature_bytes = Signer::default()
    ///     .with_signing_key(&key)
    ///     .sign_detached(b"hello world", DataEncoding::Armored)
    ///     .unwrap();
    /// ```
    pub fn sign_detached(
        self,
        data: impl AsRef<[u8]>,
        signature_encoding: DataEncoding,
    ) -> Result<Vec<u8>, SignError> {
        self.check_input_data(data.as_ref())?;

        let signing_keys = self.select_signing_keys()?;

        // Determine which hash algorithm to use for each key.
        let hash_algorithms = preferences::select_hash_algorithm_from_keys(
            self.profile.message_hash_algorithm(),
            &signing_keys,
            None,
            &self.profile,
        );

        // Create a signature for each key.
        let signatures: Result<Vec<_>, SignError> = signing_keys
            .iter()
            .zip(hash_algorithms)
            .map(|(signing_key, hash_algorithm)| {
                signing_key
                    .sign_data(
                        data.as_ref(),
                        self.date,
                        self.signature_type,
                        hash_algorithm,
                        self.signature_context.as_ref(),
                        &self.profile,
                    )
                    .map(StandaloneSignature::new)
            })
            .collect();

        handle_signature_encoding(signatures?.as_slice(), signature_encoding)
    }

    /// Creates a cleartext signed message.
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
    ///
    /// # Example
    ///
    /// ```
    /// use proton_rpgp::{Signer, DataEncoding, PrivateKey};
    /// let input_data = "hello world\n hello\n";
    ///
    /// let key = PrivateKey::import_unlocked(include_bytes!("../test-data/keys/private_key_v4.asc"), DataEncoding::Armored)
    ///     .expect("Failed to import key");
    ///
    /// let message = Signer::default()
    ///     .with_signing_key(&key)
    ///     .sign_cleartext(input_data.as_bytes())
    ///     .expect("Failed to sign");
    /// ```
    pub fn sign_cleartext(self, data: impl AsRef<[u8]>) -> Result<Vec<u8>, SignError> {
        let str_data = std::str::from_utf8(data.as_ref()).map_err(SignError::InvalidInputData)?;

        let signing_keys = self.select_signing_keys()?;
        // Determine which hash algorithm to use for each key.
        let hash_algorithms = preferences::select_hash_algorithm_from_keys(
            self.profile.message_hash_algorithm(),
            &signing_keys,
            None,
            &self.profile,
        );

        // Closure to create the signatures in rPGP.
        let create_signatures = |text: &str| {
            signing_keys
                .iter()
                .zip(hash_algorithms.iter())
                .map(|(signing_key, hash_algorithm)| {
                    signing_key
                        .sign_data(
                            text.as_bytes(),
                            self.date,
                            SignatureMode::Text,
                            *hash_algorithm,
                            self.signature_context.as_ref(),
                            &self.profile,
                        )
                        .map_err(|err| pgp::errors::Error::Message {
                            message: err.to_string(),
                            backtrace: None,
                        })
                })
                .collect()
        };

        let cleartext_message = CleartextSignedMessage::new_many(str_data, create_signatures)
            .map_err(SignError::Sign)?;

        let all_v6 = signing_keys
            .iter()
            .all(|key| key.private_key.version() == KeyVersion::V6);

        cleartext_message
            .to_armored_bytes(ArmorOptions {
                headers: None,
                include_checksum: !all_v6,
            })
            .map_err(SignError::Serialize)
    }

    pub(crate) fn check_input_data(&self, data: &[u8]) -> Result<(), SignError> {
        match self.signature_type {
            SignatureMode::Text => std::str::from_utf8(data)
                .map(|_| ())
                .map_err(SignError::InvalidInputData),
            SignatureMode::Binary => Ok(()),
        }
    }

    pub(crate) fn select_signing_keys(
        &self,
    ) -> Result<Vec<PrivateComponentKey<'_>>, KeySelectionError> {
        self.signing_keys
            .iter()
            .map(|key| {
                key.secret
                    .signing_key(self.date, None, SignatureUsage::Sign, &self.profile)
            })
            .collect()
    }

    /// Prepares the message builder to sign the message with the given signing keys.
    pub(crate) fn sign_message<R: Read, E: Encryption>(
        &self,
        mut message_builder: MessageBuilder<'a, R, E>,
        signing_keys: &'a [PrivateComponentKey<'a>],
        recipient_preferences_opt: Option<&RecipientsAlgorithms>,
    ) -> Result<MessageBuilder<'a, R, E>, SignError> {
        let hash_algorithms = if let Some(recipient_preferences) = recipient_preferences_opt {
            recipient_preferences.select_hash_algorithm(
                self.profile.message_hash_algorithm(),
                signing_keys,
                &self.profile,
            )
        } else {
            preferences::select_hash_algorithm_from_keys(
                self.profile.message_hash_algorithm(),
                signing_keys,
                None,
                &self.profile,
            )
        };

        match self.signature_type {
            SignatureMode::Binary => message_builder.sign_binary(),
            SignatureMode::Text => message_builder.sign_text(),
        };

        let mut rng = self.profile.rng();
        for (signing_key, hash_algorithm) in signing_keys.iter().zip(hash_algorithms) {
            let (hashed, unhashed) = signature_subpackets(
                &signing_key.private_key,
                self.date,
                hash_algorithm,
                self.signature_context.as_ref(),
                &mut rng,
            )?;
            message_builder.sign_with_subpackets(
                &signing_key.private_key,
                Password::default(),
                hash_algorithm,
                SubpacketConfig::UserDefined { hashed, unhashed },
            );
        }

        Ok(message_builder)
    }

    pub(crate) fn profile(&self) -> &Profile {
        &self.profile
    }
}

impl Default for Signer<'_> {
    fn default() -> Self {
        Self::new(DEFAULT_PROFILE.clone())
    }
}

fn handle_signature_encoding(
    signatures: &[StandaloneSignature],
    signature_encoding: DataEncoding,
) -> Result<Vec<u8>, SignError> {
    match signature_encoding {
        DataEncoding::Armored => {
            let all_v6 = signatures
                .iter()
                .all(|s| s.signature.version() == SignatureVersion::V6);
            let mut buffer = Vec::with_capacity(signatures.write_len());
            armor::write(
                &signatures,
                BlockType::Signature,
                &mut buffer,
                None,
                !all_v6,
            )
            .map_err(SignError::Serialize)?;
            Ok(buffer)
        }
        DataEncoding::Unarmored => {
            let mut buffer = Vec::with_capacity(signatures.write_len());
            signatures
                .to_writer(&mut buffer)
                .map_err(SignError::Serialize)?;
            Ok(buffer)
        }
    }
}

fn to_writer<'a, RAND, W, R, E>(
    signing_keys: &'a [PrivateComponentKey<'a>],
    message_builder: MessageBuilder<R, E>,
    data_encoding: DataEncoding,
    rng: RAND,
    output: W,
) -> Result<(), SignError>
where
    RAND: Rng + CryptoRng,
    W: io::Write,
    R: Read,
    E: Encryption,
{
    match data_encoding {
        DataEncoding::Armored => {
            let all_v6 = signing_keys
                .iter()
                .all(|key| key.private_key.version() == KeyVersion::V6);
            message_builder
                .to_armored_writer(
                    rng,
                    ArmorOptions {
                        headers: None,
                        include_checksum: !all_v6,
                    },
                    output,
                )
                .map_err(SignError::Serialize)?;
        }
        DataEncoding::Unarmored => message_builder
            .to_writer(rng, output)
            .map_err(SignError::Serialize)?,
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use pgp::{
        crypto::hash::HashAlgorithm,
        packet::{Packet, PacketParser, Signature, SignatureType, SignatureVersion},
    };

    use crate::{AccessKeyInfo, DataEncoding, PrivateKey, SignatureExt, Signer, UnixTime};

    pub const TEST_KEY: &str = include_str!("../test-data/keys/private_key_v4.asc");

    #[test]
    pub fn create_detached_signature_v4_binary() {
        let date = UnixTime::new(1_752_476_259);
        let input_data = b"hello world";

        let key = PrivateKey::import_unlocked(TEST_KEY.as_bytes(), DataEncoding::Armored)
            .expect("Failed to import key");

        let signature_bytes = Signer::default()
            .with_signing_key(&key)
            .at_date(date)
            .sign_detached(input_data, DataEncoding::Unarmored)
            .expect("Failed to sign");

        let signature = load_signature(&signature_bytes);
        assert_eq!(signature.version(), SignatureVersion::V4);
        assert_eq!(signature.typ(), Some(SignatureType::Binary));
        assert_eq!(signature.hash_alg(), Some(HashAlgorithm::Sha512));
        assert_eq!(
            signature.issuer_fingerprint().first().copied(),
            Some(&key.fingerprint())
        );
        assert_eq!(signature.issuer().first().copied(), Some(&key.key_id()));
        assert_eq!(signature.unix_created_at().unwrap(), date);
        assert_eq!(signature.notations().len(), 1);
    }

    #[test]
    pub fn create_detached_signature_v4_text() {
        let date = UnixTime::new(1_752_476_259);
        let input_data = b"hello world\n";

        let key = PrivateKey::import_unlocked(TEST_KEY.as_bytes(), DataEncoding::Armored)
            .expect("Failed to import key");

        let signature_bytes = Signer::default()
            .with_signing_key(&key)
            .at_date(date)
            .as_utf8()
            .sign_detached(input_data, DataEncoding::Unarmored)
            .expect("Failed to sign");

        let signature = load_signature(&signature_bytes);
        assert_eq!(signature.version(), SignatureVersion::V4);
        assert_eq!(signature.typ(), Some(SignatureType::Text));
        assert_eq!(signature.hash_alg(), Some(HashAlgorithm::Sha512));
        assert_eq!(
            signature.issuer_fingerprint().first().copied(),
            Some(&key.fingerprint())
        );
        assert_eq!(signature.issuer().first().copied(), Some(&key.key_id()));
        assert_eq!(signature.unix_created_at().unwrap(), date);
        assert_eq!(signature.notations().len(), 1);
    }

    #[test]
    pub fn create_detached_signature_v6() {
        const TEST_KEY_V6: &str = include_str!("../test-data/keys/private_key_v6.asc");

        let date = UnixTime::new(1_752_476_259);
        let input_data = b"hello world";

        let key = PrivateKey::import_unlocked(TEST_KEY_V6.as_bytes(), DataEncoding::Armored)
            .expect("Failed to import key");

        let signature_bytes = Signer::default()
            .with_signing_key(&key)
            .at_date(date)
            .sign_detached(input_data, DataEncoding::Unarmored)
            .expect("Failed to sign");

        let signature = load_signature(&signature_bytes);
        assert_eq!(signature.version(), SignatureVersion::V6);
        assert_eq!(signature.typ(), Some(SignatureType::Binary));
        assert_eq!(signature.hash_alg(), Some(HashAlgorithm::Sha512));
        assert_eq!(
            signature.issuer_fingerprint().first().copied(),
            Some(&key.fingerprint())
        );
        assert!(signature.issuer().is_empty());
        assert!(signature.notations().is_empty());
    }

    #[test]
    pub fn create_inline_signature_v4_binary() {
        let date = UnixTime::new(1_752_476_259);
        let input_data = b"hello world";

        let key = PrivateKey::import_unlocked(TEST_KEY.as_bytes(), DataEncoding::Armored)
            .expect("Failed to import key");

        let data_bytes = Signer::default()
            .with_signing_key(&key)
            .at_date(date)
            .sign(input_data, DataEncoding::Unarmored)
            .expect("Failed to sign");

        let signature = load_signatures_inline(&data_bytes)
            .into_iter()
            .next()
            .unwrap();

        assert_eq!(signature.version(), SignatureVersion::V4);
        assert_eq!(signature.typ(), Some(SignatureType::Binary));
        assert_eq!(signature.hash_alg(), Some(HashAlgorithm::Sha512));
        assert_eq!(
            signature.issuer_fingerprint().first().copied(),
            Some(&key.fingerprint())
        );
        assert_eq!(signature.issuer().first().copied(), Some(&key.key_id()));
        assert_eq!(signature.unix_created_at().unwrap(), date);
        assert_eq!(signature.notations().len(), 1);
    }

    #[test]
    pub fn create_inline_signature_v6() {
        const TEST_KEY_V6: &str = include_str!("../test-data/keys/private_key_v6.asc");

        let date = UnixTime::new(1_752_476_259);
        let input_data = b"hello world";

        let key = PrivateKey::import_unlocked(TEST_KEY_V6.as_bytes(), DataEncoding::Armored)
            .expect("Failed to import key");

        let data_bytes = Signer::default()
            .with_signing_key(&key)
            .at_date(date)
            .sign_detached(input_data, DataEncoding::Unarmored)
            .expect("Failed to sign");

        let signature = load_signatures_inline(&data_bytes)
            .into_iter()
            .next()
            .unwrap();
        assert_eq!(signature.version(), SignatureVersion::V6);
        assert_eq!(signature.typ(), Some(SignatureType::Binary));
        assert_eq!(signature.hash_alg(), Some(HashAlgorithm::Sha512));
        assert_eq!(
            signature.issuer_fingerprint().first().copied(),
            Some(&key.fingerprint())
        );
        assert!(signature.issuer().is_empty());
        assert!(signature.notations().is_empty());
    }

    fn load_signatures_inline(inline_message: &[u8]) -> Vec<Signature> {
        PacketParser::new(inline_message)
            .filter_map(|parse_result| match parse_result {
                Ok(Packet::Signature(signature)) => Some(signature),
                _ => None,
            })
            .collect()
    }

    fn load_signature(signature: &[u8]) -> Signature {
        let mut parser = PacketParser::new(signature);
        let packet = parser.next().unwrap().unwrap();
        match packet {
            Packet::Signature(signature) => signature,
            _ => panic!("Expected a signature packet"),
        }
    }
}
