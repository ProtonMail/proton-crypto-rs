use std::fmt::Display;

use pgp::{
    composed::{SignedSecretKey, SignedSecretSubKey},
    packet::{self, KeyFlags, PubKeyInner, UserId},
    types::{KeyVersion, PacketHeaderVersion},
};
use rand::{CryptoRng, Rng};

use crate::{
    KeyGenerationError, KeyGenerationType, PacketPublicSubkeyExt, PrivateKey, Profile, UnixTime,
    DEFAULT_PROFILE,
};

/// Internal representation of a user-id.
#[derive(Debug, Clone, PartialEq, Eq)]
struct KeyUserId {
    name: String,
    email: String,
}

impl KeyUserId {
    fn try_to_user_id(&self) -> Result<UserId, KeyGenerationError> {
        UserId::from_str(PacketHeaderVersion::default(), self.to_string())
            .map_err(|err| KeyGenerationError::InvalidUserId(self.to_string(), err))
    }
}

impl Display for KeyUserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} <{}>", self.name, self.email)
    }
}

/// A key generator that can be used to generate `OpenPGP` private keys.
#[derive(Debug)]
pub struct KeyGenerator {
    /// The profile to use for the key generation.
    profile: Profile,

    /// The user-ids to use for the key generation.
    user_ids: Vec<KeyUserId>,

    /// The algorithm type to use for the key generation.
    algorithm: KeyGenerationType,

    /// The date of the key generation for the self-certifications and key creation time.
    date: UnixTime,
}

impl KeyGenerator {
    /// Create a new key generator with the given profile.
    pub fn new(profile: Profile) -> Self {
        Self {
            profile,
            user_ids: Vec::new(),
            algorithm: KeyGenerationType::default(),
            date: UnixTime::now().unwrap_or_default(),
        }
    }

    /// Set the user-id to use for the key generation.
    ///
    /// The user-id will be included as a `name <email>` formatted string.
    pub fn with_user_id(mut self, name: &str, email: &str) -> Self {
        self.user_ids.push(KeyUserId {
            name: name.to_string(),
            email: email.to_string(),
        });
        self
    }

    /// Set the algorithm type to use for the key generation.
    pub fn with_key_type(mut self, algorithm: KeyGenerationType) -> Self {
        self.algorithm = algorithm;
        self
    }

    /// Set the date of the key generation for the self-certifications and key creation time.
    pub fn at_date(mut self, date: UnixTime) -> Self {
        self.date = date;
        self
    }

    /// Generate a `OpenPGP` private key for the given generation configuration.
    ///
    /// # Example
    ///
    /// ```rust
    /// use proton_rpgp::{KeyGenerator, KeyGenerationType};
    ///
    /// let key = KeyGenerator::default()
    ///     .with_user_id("test", "test@test.test")
    ///     .with_key_type(KeyGenerationType::ECC)
    ///     .generate()
    ///     .unwrap();
    /// ```
    pub fn generate(self) -> Result<PrivateKey, KeyGenerationError> {
        let mut rng = self.profile.rng();
        let key_generation_options = self.algorithm.key_generation_profile();
        let preferred_hash = self.profile.key_hash_algorithm();
        let (primary_user_id, non_primary_user_ids) = convert_user_ids(&self.user_ids)?;

        if primary_user_id.is_none() && key_generation_options.key_version == KeyVersion::V4 {
            return Err(KeyGenerationError::NoUserId);
        }
        // Primary key
        let primary_flags = primary_key_flags();
        let key_version = key_generation_options.key_version;
        let key_details_config = key_generation_options.create_key_details_config(
            primary_user_id,
            non_primary_user_ids,
            primary_flags,
        );

        let (primary_secret_key, primary_pub_key) =
            generate_primary_key(self.algorithm, key_version, self.date, &mut rng)?;

        // Encryption subkey
        let subkey_flags = encryption_subkey_flags();
        let (subkey_secret, subkey_public) =
            generate_encryption_subkey(self.algorithm, key_version, self.date, &mut rng)?;

        // Create self-certifications.
        let subkey_binding_signature = subkey_public.custom_sign(
            &primary_secret_key,
            &primary_pub_key,
            self.date,
            preferred_hash,
            subkey_flags,
            None,
            &mut rng,
            &self.profile,
        )?;

        let singed_subkey_secret =
            SignedSecretSubKey::new(subkey_secret, vec![subkey_binding_signature]);

        let signed_key_details = key_details_config.sign(
            rng,
            &primary_secret_key,
            self.date,
            preferred_hash,
            &primary_pub_key,
            &self.profile,
        )?;

        let signed_secret_key = SignedSecretKey::new(
            primary_secret_key,
            signed_key_details,
            Vec::new(),
            vec![singed_subkey_secret],
        );

        Ok(PrivateKey::new(signed_secret_key))
    }
}

impl Default for KeyGenerator {
    fn default() -> Self {
        Self::new(DEFAULT_PROFILE.clone())
    }
}

fn generate_primary_key(
    algorithm: KeyGenerationType,
    key_version: KeyVersion,
    date: UnixTime,
    rng: impl Rng + CryptoRng,
) -> Result<(packet::SecretKey, packet::PublicKey), KeyGenerationError> {
    let (primary_public_params, primary_secret_params) =
        algorithm.primary_key_type().generate(rng)?;
    let pub_key = PubKeyInner::new(
        key_version,
        algorithm.primary_key_type().to_alg(),
        date.into(),
        None,
        primary_public_params,
    )?;
    let primary_pub_key = packet::PublicKey::from_inner(pub_key)?;
    let primary_key = packet::SecretKey::new(primary_pub_key.clone(), primary_secret_params)?;
    Ok((primary_key, primary_pub_key))
}

fn generate_encryption_subkey(
    algorithm: KeyGenerationType,
    key_version: KeyVersion,
    date: UnixTime,
    rng: impl Rng + CryptoRng,
) -> Result<(packet::SecretSubkey, packet::PublicSubkey), KeyGenerationError> {
    let (subkey_public_params, subkey_secret_params) =
        algorithm.encryption_key_type().generate(rng)?;
    let pub_key = PubKeyInner::new(
        key_version,
        algorithm.encryption_key_type().to_alg(),
        date.into(),
        None,
        subkey_public_params,
    )?;
    let subkey_public = packet::PublicSubkey::from_inner(pub_key)?;
    let subkey_secret = packet::SecretSubkey::new(subkey_public.clone(), subkey_secret_params)?;
    Ok((subkey_secret, subkey_public))
}

fn primary_key_flags() -> KeyFlags {
    let mut flags = KeyFlags::default();
    flags.set_sign(true);
    flags.set_certify(true);
    flags
}

fn encryption_subkey_flags() -> KeyFlags {
    let mut flags = KeyFlags::default();
    flags.set_encrypt_comms(true);
    flags.set_encrypt_storage(true);
    flags
}

fn convert_user_ids(
    user_ids: &[KeyUserId],
) -> Result<(Option<UserId>, Vec<UserId>), KeyGenerationError> {
    let user_ids_converted = user_ids
        .iter()
        .map(KeyUserId::try_to_user_id)
        .collect::<Result<Vec<_>, KeyGenerationError>>()?;
    let primary = user_ids_converted.first().cloned();
    let non_primary = user_ids_converted.iter().skip(1).cloned().collect();
    Ok((primary, non_primary))
}

#[cfg(test)]
mod tests {
    use pgp::{
        crypto::hash::HashAlgorithm,
        packet::{Packet, PacketParser, Signature, SignatureType, SignatureVersion},
        types::PublicKeyTrait,
    };

    use crate::{AccessKeyInfo, DataEncoding, SignatureExt};

    use super::*;

    #[test]
    fn test_key_generation_details_v4() {
        let date = UnixTime::new(1_756_196_260);
        let key = KeyGenerator::default()
            .with_user_id("test", "test@test.test")
            .with_key_type(KeyGenerationType::ECC)
            .at_date(date)
            .generate()
            .unwrap();

        assert_eq!(key.version(), 4);
        assert_eq!(UnixTime::from(key.public.inner.created_at()), date);
        assert_eq!(key.secret.expires_at(), None);

        let exported = key
            .export_unlocked(DataEncoding::Unarmored)
            .expect("Failed to export key");

        let key_info_signature = load_user_id_signature(&exported);
        assert_eq!(key_info_signature.version(), SignatureVersion::V4);
        assert_eq!(key_info_signature.hash_alg(), Some(HashAlgorithm::Sha512));
        assert_eq!(
            key_info_signature.issuer_fingerprint().first().copied(),
            Some(&key.fingerprint())
        );
        assert_eq!(
            key_info_signature.issuer().first().copied(),
            Some(&key.key_id())
        );
        assert_eq!(key_info_signature.unix_created_at().unwrap(), date);
        assert!(key_info_signature.key_flags().certify() && key_info_signature.key_flags().sign());
        assert!(
            key_info_signature.features().unwrap().seipd_v1()
                && !key_info_signature.features().unwrap().seipd_v2()
        );

        let user_id = load_user_id(&exported).unwrap();
        assert_eq!(user_id.as_str().unwrap(), "test <test@test.test>");

        let subkey_signature = load_sub_key_signature(&exported);
        assert_eq!(subkey_signature.version(), SignatureVersion::V4);
        assert_eq!(subkey_signature.hash_alg(), Some(HashAlgorithm::Sha512));
        assert_eq!(subkey_signature.unix_created_at().unwrap(), date);
        assert_eq!(
            subkey_signature.issuer_fingerprint().first().copied(),
            Some(&key.fingerprint())
        );
        assert!(
            subkey_signature.key_flags().encrypt_comms()
                && subkey_signature.key_flags().encrypt_storage()
        );
    }

    #[test]
    fn test_key_generation_details_v6() {
        let date = UnixTime::new(1_756_196_260);
        let key = KeyGenerator::default()
            .with_user_id("test", "test@test.test")
            .with_key_type(KeyGenerationType::PQC)
            .at_date(date)
            .generate()
            .unwrap();

        assert_eq!(key.version(), 6);
        assert_eq!(UnixTime::from(key.public.inner.created_at()), date);
        assert_eq!(key.secret.expires_at(), None);

        let exported = key
            .export_unlocked(DataEncoding::Unarmored)
            .expect("Failed to export key");

        let key_info_signature = load_direct_key_info_signature(&exported);
        assert_eq!(key_info_signature.version(), SignatureVersion::V6);
        assert_eq!(key_info_signature.hash_alg(), Some(HashAlgorithm::Sha512));
        assert_eq!(
            key_info_signature.issuer_fingerprint().first().copied(),
            Some(&key.fingerprint())
        );
        assert_eq!(key_info_signature.unix_created_at().unwrap(), date);
        assert!(key_info_signature.key_flags().certify() && key_info_signature.key_flags().sign());
        assert!(
            key_info_signature.features().unwrap().seipd_v1()
                && !key_info_signature.features().unwrap().seipd_v2()
        );

        let user_id = load_user_id(&exported).unwrap();
        assert_eq!(user_id.as_str().unwrap(), "test <test@test.test>");

        let subkey_signature = load_sub_key_signature(&exported);
        assert_eq!(subkey_signature.version(), SignatureVersion::V6);
        assert_eq!(subkey_signature.hash_alg(), Some(HashAlgorithm::Sha512));
        assert_eq!(subkey_signature.unix_created_at().unwrap(), date);
        assert_eq!(
            subkey_signature.issuer_fingerprint().first().copied(),
            Some(&key.fingerprint())
        );
        assert!(
            subkey_signature.key_flags().encrypt_comms()
                && subkey_signature.key_flags().encrypt_storage()
        );

        let user_id_signature = load_user_id_signature(&exported);
        assert_eq!(user_id_signature.version(), SignatureVersion::V6);
        assert_eq!(user_id_signature.hash_alg(), Some(HashAlgorithm::Sha512));
        assert_eq!(
            user_id_signature.issuer_fingerprint().first().copied(),
            Some(&key.fingerprint())
        );
        assert_eq!(user_id_signature.unix_created_at().unwrap(), date);
        assert!(user_id_signature.features().is_none());
        assert!(user_id_signature.preferred_symmetric_algs().is_empty());
    }

    fn load_user_id_signature(signature: &[u8]) -> Signature {
        let parser = PacketParser::new(signature);
        for packet in parser.flatten() {
            if let Packet::Signature(signature) = packet {
                if let Some(SignatureType::CertPositive) = signature.typ() {
                    return signature;
                }
            }
        }
        panic!("Expected a signature packet");
    }

    fn load_direct_key_info_signature(signature: &[u8]) -> Signature {
        let parser = PacketParser::new(signature);
        for packet in parser.flatten() {
            if let Packet::Signature(signature) = packet {
                if let Some(SignatureType::Key) = signature.typ() {
                    return signature;
                }
            }
        }
        panic!("Expected a signature packet");
    }

    fn load_sub_key_signature(signature: &[u8]) -> Signature {
        let parser = PacketParser::new(signature);
        for packet in parser.flatten() {
            if let Packet::Signature(signature) = packet {
                if let Some(SignatureType::SubkeyBinding) = signature.typ() {
                    return signature;
                }
            }
        }
        panic!("Expected a signature packet");
    }

    fn load_user_id(signature: &[u8]) -> Option<UserId> {
        let parser = PacketParser::new(signature);
        for packet in parser.flatten() {
            if let Packet::UserId(user_id) = packet {
                return Some(user_id);
            }
        }
        None
    }
}
