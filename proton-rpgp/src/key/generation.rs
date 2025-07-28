use std::fmt::Display;

use pgp::{
    composed::{KeyType, SecretKeyParamsBuilder, SubkeyParamsBuilder},
    crypto::{
        aead::AeadAlgorithm, ecc_curve::ECCCurve, hash::HashAlgorithm, sym::SymmetricKeyAlgorithm,
    },
    types::{CompressionAlgorithm, KeyVersion, Password},
};
use smallvec::SmallVec;

use crate::{KeyGenerationError, PrivateKey, Profile, UnixTime, DEFAULT_PROFILE};

const KEY_PREFERRED_SYMMETRIC_KEY_ALGORITHMS: &[SymmetricKeyAlgorithm] =
    &[SymmetricKeyAlgorithm::AES256, SymmetricKeyAlgorithm::AES128];

const KEY_PREFERRED_HASH_ALGORITHMS: &[HashAlgorithm] =
    &[HashAlgorithm::Sha256, HashAlgorithm::Sha512];

const KEY_PREFERRED_AEAD_ALGORITHMS: &[(SymmetricKeyAlgorithm, AeadAlgorithm)] = &[];

const PREFERRED_COMPRESSION_ALGORITHMS: &[CompressionAlgorithm] = &[
    CompressionAlgorithm::Uncompressed,
    CompressionAlgorithm::ZLIB,
    CompressionAlgorithm::ZIP,
];

/// The algorithm type to use for the key generation.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyGenerationType {
    /// An RSA 4096-bit v4 signing and encryption key.
    RSA,

    /// An ECC v4 signing (`EdDsaLegacy`) and encryption key (`ECDH` with `Curve25519` legacy).
    #[default]
    ECC,

    /// A PQC v6 signing (`ML-DSA`) and encryption key (`ML-KEM)`.
    PQC,
}

impl KeyGenerationType {
    fn encryption_key_type(self) -> KeyType {
        match self {
            KeyGenerationType::RSA => KeyType::Rsa(4096),
            KeyGenerationType::ECC => KeyType::ECDH(ECCCurve::Curve25519),
            KeyGenerationType::PQC => KeyType::MlKem768X25519,
        }
    }

    fn primary_key_type(self) -> KeyType {
        match self {
            KeyGenerationType::RSA => KeyType::Rsa(4096),
            KeyGenerationType::ECC => KeyType::Ed25519Legacy,
            KeyGenerationType::PQC => KeyType::MlDsa65Ed25519,
        }
    }
}

/// The profile to use for the key generation.
pub struct KeyGenerationProfile {
    /// The key version to use for the key generation.
    pub key_version: KeyVersion,

    /// The preferred symmetric algorithms to use for the key generation.
    pub preferred_symmetric_algorithms: SmallVec<[SymmetricKeyAlgorithm; 8]>,

    /// The preferred hash algorithms to use for the key generation.
    pub preferred_hash_algorithms: SmallVec<[HashAlgorithm; 8]>,

    /// The preferred compression algorithms to use for the key generation.
    pub preferred_compression_algorithms: SmallVec<[CompressionAlgorithm; 8]>,

    /// The preferred AEAD algorithms to use for the key generation.
    pub preferred_aead_algorithms: SmallVec<[(SymmetricKeyAlgorithm, AeadAlgorithm); 4]>,

    /// Whether to signal support for SEIPD v2.
    pub seipd_v2: bool,
}

impl Default for KeyGenerationProfile {
    fn default() -> Self {
        Self {
            key_version: KeyVersion::V4,
            preferred_symmetric_algorithms: KEY_PREFERRED_SYMMETRIC_KEY_ALGORITHMS.into(),
            preferred_hash_algorithms: KEY_PREFERRED_HASH_ALGORITHMS.into(),
            preferred_compression_algorithms: PREFERRED_COMPRESSION_ALGORITHMS.into(),
            preferred_aead_algorithms: KEY_PREFERRED_AEAD_ALGORITHMS.into(),
            seipd_v2: false,
        }
    }
}

impl KeyGenerationProfile {
    fn apply_to_primary_builder(self, builder: &mut SecretKeyParamsBuilder) {
        builder
            .version(self.key_version)
            .can_certify(true)
            .can_sign(true)
            .preferred_symmetric_algorithms(self.preferred_symmetric_algorithms)
            .preferred_hash_algorithms(self.preferred_hash_algorithms)
            .preferred_compression_algorithms(self.preferred_compression_algorithms)
            .preferred_aead_algorithms(self.preferred_aead_algorithms)
            .feature_seipd_v1(true)
            .feature_seipd_v2(self.seipd_v2);
    }
}

/// Internal representation of a user-id.
#[derive(Debug, Clone, PartialEq, Eq)]
struct KeyUserId {
    name: String,
    email: String,
}

impl Display for KeyUserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} <{}>", self.name, self.email)
    }
}

/// A key generator that can be used to generate `OpenPGP` private keys.
#[derive(Debug)]
pub struct KeyGenerator<'a> {
    /// The profile to use for the key generation.
    profile: &'a Profile,

    /// The user-ids to use for the key generation.
    user_ids: Vec<KeyUserId>,

    /// The algorithm type to use for the key generation.
    algorithm: KeyGenerationType,

    /// The date of the key generation for the self-certifications and key creation time.
    date: UnixTime,
}

impl<'a> KeyGenerator<'a> {
    /// Create a new key generator with the given profile.
    pub fn new(profile: &'a Profile) -> Self {
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
    ///
    /// This is currently no doable without re-implementing low level logic.
    /// TODO(CRYPTO-302): Use our custom signature config.
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
        let key_generation_options = self.profile.key_generation_options(self.algorithm);

        let subkey = SubkeyParamsBuilder::default()
            .version(key_generation_options.key_version)
            .key_type(self.algorithm.encryption_key_type())
            .can_encrypt(true)
            .build()?;

        let mut key_params = SecretKeyParamsBuilder::default();
        key_generation_options.apply_to_primary_builder(&mut key_params);

        if let Some(primary_user_id) = self.user_ids.first() {
            key_params.primary_user_id(primary_user_id.to_string());
        }

        key_params
            .key_type(self.algorithm.primary_key_type())
            .user_ids(
                self.user_ids
                    .iter()
                    .skip(1)
                    .map(ToString::to_string)
                    .collect(),
            )
            .subkey(subkey);

        let secret_key_params = key_params.build()?;
        let secret_key = secret_key_params.generate(&mut rng)?;

        // TODO(CRYPTO-302): Use our custom signature config.
        let signed_secret_key = secret_key
            .sign(&mut rng, &Password::empty())
            .map_err(KeyGenerationError::Signing)?;

        Ok(PrivateKey::new(signed_secret_key))
    }
}

impl Default for KeyGenerator<'_> {
    fn default() -> Self {
        Self::new(&DEFAULT_PROFILE)
    }
}
