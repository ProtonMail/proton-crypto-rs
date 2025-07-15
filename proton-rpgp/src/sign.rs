use pgp::{
    armor::{self, BlockType},
    composed::StandaloneSignature,
    packet::SignatureVersion,
    ser::Serialize,
};

use crate::{
    preferences, DataEncoding, PrivateKey, PrivateKeySelectionExt, Profile, SignError,
    SignatureMode, UnixTime, DEFAULT_PROFILE,
};

/// A signer that can create `OpenPGP` signatures over data.
#[derive(Debug, Clone)]
pub struct Signer<'a> {
    /// The profile to use for the signer.
    profile: &'a Profile,

    /// The signing keys to create signatures with.
    signing_keys: Vec<&'a PrivateKey>,

    /// The date to use for the signatures.
    date: UnixTime,

    /// The signature type to use for the signatures.
    ///
    /// Either binary or text.
    signature_type: SignatureMode,
}

impl<'a> Signer<'a> {
    /// Create a new verifier with the given profile.
    pub fn new(profile: &'a Profile) -> Self {
        Self {
            profile,
            signing_keys: Vec::new(),
            date: UnixTime::now().unwrap_or_default(),
            signature_type: SignatureMode::default(),
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

    /// Sets the signature type to text.
    ///
    /// If this is set, `OpenPGP` will canonicalize the line endings in the signature data before signing.
    pub fn as_utf8(mut self) -> Self {
        self.signature_type = SignatureMode::Text;
        self
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

        // Determine which hash algorithm to use for each key.
        let hash_algorithms = preferences::select_hash_algorithm_from_keys(
            self.date,
            self.profile.message_hash_algorithm(),
            &self.signing_keys,
            self.profile,
        )?;

        // Create a signature for each key.
        let signatures: Result<Vec<_>, SignError> = self
            .signing_keys
            .iter()
            .zip(hash_algorithms)
            .map(|(key, hash_algorithm)| {
                // Select the signing key.
                let signing_key = key.secret.signing_key(
                    self.date,
                    None,
                    crate::SignatureUsage::Sign,
                    self.profile,
                )?;

                // Sign the data.
                let signature = signing_key.sign_data(
                    data.as_ref(),
                    self.date,
                    self.signature_type,
                    hash_algorithm,
                    self.profile,
                )?;
                Ok(StandaloneSignature::new(signature))
            })
            .collect();

        handle_signature_encoding(signatures?.as_slice(), signature_encoding)
    }

    fn check_input_data(&self, data: &[u8]) -> Result<(), SignError> {
        match self.signature_type {
            SignatureMode::Text => std::str::from_utf8(data)
                .map(|_| ())
                .map_err(SignError::InvalidInputData),
            SignatureMode::Binary => Ok(()),
        }
    }
}

impl Default for Signer<'_> {
    fn default() -> Self {
        Self::new(&DEFAULT_PROFILE)
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

    fn load_signature(signature: &[u8]) -> Signature {
        let mut parser = PacketParser::new(signature);
        let packet = parser.next().unwrap().unwrap();
        match packet {
            Packet::Signature(signature) => signature,
            _ => panic!("Expected a signature packet"),
        }
    }
}
