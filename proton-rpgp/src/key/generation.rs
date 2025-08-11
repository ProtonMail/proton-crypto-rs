use std::fmt::Display;

use pgp::{
    composed::{SecretKeyParamsBuilder, SubkeyParamsBuilder},
    types::Password,
};

use crate::{
    KeyGenerationError, KeyGenerationType, PrivateKey, Profile, UnixTime, DEFAULT_PROFILE,
};

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
        let key_generation_options = self.algorithm.key_generation_profile();

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

impl Default for KeyGenerator {
    fn default() -> Self {
        Self::new(DEFAULT_PROFILE.clone())
    }
}
