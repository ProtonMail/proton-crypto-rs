use std::fmt::Display;

use pgp::{
    composed::{
        KeyDetails as ComposedKeyDetails, SecretKey, SecretKeyParamsBuilder, SignedKeyDetails,
        SignedPublicSubKey, SignedSecretKey, SignedSecretSubKey, SubkeyParamsBuilder,
    },
    crypto::hash::HashAlgorithm,
    packet::{
        KeyFlags, PacketTrait, PublicSubkey as PacketPublicSubkey,
        SecretSubkey as PacketSecretSubkey, Signature, SignatureType, Subpacket, SubpacketData,
    },
    ser::Serialize,
    types::{KeyVersion, Password, PublicKeyTrait, SecretKeyTrait},
};
use rand::{CryptoRng, Rng};

use crate::{
    core::{key_details_configure_signature, sub_key_configure_signature},
    KeyGenerationError, KeyGenerationType, KeySigningError, PrivateKey, Profile, UnixTime,
    DEFAULT_PROFILE,
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

        let hash_algorithm = self.profile.key_hash_algorithm();
        let signed_secret_key =
            secret_key.custom_sign(&mut rng, self.date, hash_algorithm, &self.profile)?;

        Ok(PrivateKey::new(signed_secret_key))
    }
}

impl Default for KeyGenerator {
    fn default() -> Self {
        Self::new(DEFAULT_PROFILE.clone())
    }
}

trait KeyDetailsExt {
    fn custom_sign<R, K, P>(
        self,
        rng: R,
        key: &K,
        at_date: UnixTime,
        selected_hash: HashAlgorithm,
        pub_key: &P,
        profile: &Profile,
    ) -> Result<SignedKeyDetails, KeySigningError>
    where
        R: CryptoRng + Rng,
        K: SecretKeyTrait,
        P: PublicKeyTrait + Serialize;
}

impl KeyDetailsExt for ComposedKeyDetails {
    fn custom_sign<R, K, P>(
        self,
        mut rng: R,
        key: &K,
        at_date: UnixTime,
        preferred_hash: HashAlgorithm,
        pub_key: &P,
        profile: &Profile,
    ) -> Result<SignedKeyDetails, KeySigningError>
    where
        R: CryptoRng + Rng,
        K: SecretKeyTrait,
        P: PublicKeyTrait + Serialize,
    {
        let direct_signatures = match key.version() {
            KeyVersion::V6 => {
                let config = key_details_configure_signature(
                    key,
                    pub_key,
                    at_date,
                    preferred_hash,
                    SignatureType::CertPositive,
                    &self,
                    false,
                    profile,
                    &mut rng,
                )?;
                let direct_key_signature = config
                    .sign_key(key, &Password::empty(), pub_key)
                    .map_err(KeySigningError::SignKeyDetails)?;

                vec![direct_key_signature]
            }
            _ => Vec::new(),
        };

        let mut users = Vec::with_capacity(self.non_primary_user_ids.len() + 1);
        if let Some(primary_user_id) = &self.primary_user_id {
            let config = key_details_configure_signature(
                key,
                pub_key,
                at_date,
                preferred_hash,
                SignatureType::CertPositive,
                &self,
                true,
                profile,
                &mut rng,
            )?;

            let sig = config
                .sign_certification(
                    key,
                    pub_key,
                    &Password::empty(),
                    primary_user_id.tag(),
                    &primary_user_id,
                )
                .map_err(KeySigningError::SignKeyDetails)?;

            users.push(primary_user_id.clone().into_signed(sig));
        }

        users.extend(
            self.non_primary_user_ids
                .iter()
                .map(|id| {
                    let config = key_details_configure_signature(
                        key,
                        pub_key,
                        at_date,
                        preferred_hash,
                        SignatureType::CertPositive,
                        &self,
                        false,
                        profile,
                        &mut rng,
                    )?;

                    let sig = config
                        .sign_certification(key, pub_key, &Password::empty(), id.tag(), &id)
                        .map_err(KeySigningError::SignKeyDetails)?;

                    Ok(id.clone().into_signed(sig))
                })
                .collect::<Result<Vec<_>, KeySigningError>>()?,
        );

        Ok(SignedKeyDetails {
            revocation_signatures: Vec::default(),
            direct_signatures,
            users,
            user_attributes: Vec::default(),
        })
    }
}

trait PacketPublicSubkeyExt {
    #[allow(clippy::too_many_arguments)]
    fn custom_sign<R: CryptoRng + Rng, K, P>(
        &self,
        rng: R,
        primary_sec_key: &K,
        primary_pub_key: &P,
        at_date: UnixTime,
        selected_hash: HashAlgorithm,
        keyflags: KeyFlags,
        embedded: Option<Signature>,
        profile: &Profile,
    ) -> Result<Signature, KeySigningError>
    where
        K: SecretKeyTrait,
        P: PublicKeyTrait + Serialize;
}

impl PacketPublicSubkeyExt for PacketPublicSubkey {
    fn custom_sign<R: CryptoRng + Rng, K, P>(
        &self,
        mut rng: R,
        primary_sec_key: &K,
        primary_pub_key: &P,
        at_date: UnixTime,
        selected_hash: HashAlgorithm,
        keyflags: KeyFlags,
        embedded: Option<Signature>,
        profile: &Profile,
    ) -> Result<Signature, KeySigningError>
    where
        K: SecretKeyTrait,
        P: PublicKeyTrait + Serialize,
    {
        let mut config = sub_key_configure_signature(
            primary_sec_key,
            primary_pub_key,
            at_date,
            selected_hash,
            SignatureType::SubkeyBinding,
            keyflags,
            profile,
            &mut rng,
        )?;

        if let Some(embedded) = embedded {
            config.hashed_subpackets.push(
                Subpacket::regular(SubpacketData::EmbeddedSignature(Box::new(embedded)))
                    .map_err(KeySigningError::SignSubkey)?,
            );
        }

        config
            .sign_subkey_binding(primary_sec_key, primary_pub_key, &Password::empty(), &self)
            .map_err(KeySigningError::SignSubkey)
    }
}

impl PacketPublicSubkeyExt for PacketSecretSubkey {
    fn custom_sign<R: CryptoRng + Rng, K, P>(
        &self,
        rng: R,
        primary_sec_key: &K,
        primary_pub_key: &P,
        at_date: UnixTime,
        selected_hash: HashAlgorithm,
        keyflags: KeyFlags,
        embedded: Option<Signature>,
        profile: &Profile,
    ) -> Result<Signature, KeySigningError>
    where
        K: SecretKeyTrait,
        P: PublicKeyTrait + Serialize,
    {
        self.public_key().custom_sign(
            rng,
            primary_sec_key,
            primary_pub_key,
            at_date,
            selected_hash,
            keyflags,
            embedded,
            profile,
        )
    }
}

trait SecretKeyExt {
    fn custom_sign<R>(
        self,
        rng: R,
        at_date: UnixTime,
        selected_hash: HashAlgorithm,
        profile: &Profile,
    ) -> Result<SignedSecretKey, KeySigningError>
    where
        R: CryptoRng + Rng;
}

impl SecretKeyExt for SecretKey {
    fn custom_sign<R>(
        self,
        mut rng: R,
        at_date: UnixTime,
        selected_hash: HashAlgorithm,
        profile: &Profile,
    ) -> Result<SignedSecretKey, KeySigningError>
    where
        R: CryptoRng + Rng,
    {
        let primary_key = self.primary_key;
        let details = self.details.custom_sign(
            &mut rng,
            &primary_key,
            at_date,
            selected_hash,
            primary_key.public_key(),
            profile,
        )?;
        let public_subkeys = self
            .public_subkeys
            .into_iter()
            .map(|k| {
                let sig = k.key.custom_sign(
                    &mut rng,
                    &primary_key,
                    primary_key.public_key(),
                    at_date,
                    selected_hash,
                    k.keyflags,
                    k.embedded,
                    profile,
                )?;

                Ok(SignedPublicSubKey {
                    key: k.key,
                    signatures: vec![sig],
                })
            })
            .collect::<Result<Vec<_>, KeySigningError>>()?;
        let secret_subkeys = self
            .secret_subkeys
            .into_iter()
            .map(|k| {
                let sig = k.key.custom_sign(
                    &mut rng,
                    &primary_key,
                    primary_key.public_key(),
                    at_date,
                    selected_hash,
                    k.keyflags,
                    k.embedded,
                    profile,
                )?;

                Ok(SignedSecretSubKey {
                    key: k.key,
                    signatures: vec![sig],
                })
            })
            .collect::<Result<Vec<_>, KeySigningError>>()?;

        Ok(SignedSecretKey {
            primary_key,
            details,
            public_subkeys,
            secret_subkeys,
        })
    }
}
