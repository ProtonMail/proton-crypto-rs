use pgp::{
    composed::SignedSecretKey,
    packet::{self, KeyFlags, PubKeyInner},
    types::{KeyDetails, PublicKeyTrait},
};

use crate::{
    convert_user_ids, primary_key_flags, CertificationSelectionExt, CheckUnixTime,
    KeyGenerationProfileBuilder, KeyModificationError, KeyUserId, PacketPublicSubkeyExt,
    PrivateKey, PrivateKeySelectionExt, Profile, PublicKeySelectionExt, UnixTime, DEFAULT_PROFILE,
};

pub struct KeyModifier {
    /// The key to modify.
    key_to_modify: SignedSecretKey,

    /// The profile to use for the key modification.
    profile: Profile,

    /// The new user-ids to add to the key.
    new_user_ids: Vec<KeyUserId>,

    /// Whether to remove the old user-ids from the key.
    remove_old_user_ids: bool,

    /// Whether reset and create new signatures for user-ids/direct-key/subkeys.
    ///
    /// All existing signatures on these parts are removed and new signatures are created.
    reset_signatures: bool,

    /// The date of the key generation for the self-certifications and key creation time.
    date: UnixTime,

    /// Override the key creation time of the primary key and subkeys.
    key_time: Option<UnixTime>,
}

impl KeyModifier {
    pub fn new(profile: &Profile, key_to_modify: &PrivateKey) -> Self {
        Self {
            key_to_modify: key_to_modify.secret.clone(),
            profile: profile.clone(),
            new_user_ids: Vec::new(),
            remove_old_user_ids: false,
            reset_signatures: false,
            date: UnixTime::now().unwrap_or_default(),
            key_time: None,
        }
    }

    pub fn new_default(key_to_modify: &PrivateKey) -> Self {
        Self::new(&DEFAULT_PROFILE, key_to_modify)
    }

    /// Add a new user-id to the key.
    pub fn add_user_id(mut self, name: &str, email: &str) -> Self {
        self.new_user_ids.push(KeyUserId {
            name: name.to_string(),
            email: email.to_string(),
        });
        self
    }

    /// Remove all existing user-ids from the key.
    pub fn erase_existing_user_ids(mut self, remove_all: bool) -> Self {
        self.remove_old_user_ids = remove_all;
        self
    }

    /// Resets and regenerates signatures for user-IDs, direct-key info, and subkeys.
    ///
    /// When enabled, all existing signatures related to these components are removed,
    /// and new self-signatures are created according to the modification configuration.
    pub fn reset_signatures(mut self, resign: bool) -> Self {
        self.reset_signatures = resign;
        self
    }

    /// Override the key creation time of the primary key and subkeys.  
    ///
    /// Automatically triggers a signature reset.
    pub fn update_key_creation_time(mut self, key_time: UnixTime) -> Self {
        self.reset_signatures = true;
        self.key_time = Some(key_time);
        self
    }

    /// Set the date of the key modification.
    pub fn at_date(mut self, date: UnixTime) -> Self {
        self.date = date;
        self
    }

    /// Modify the key according to the configuration.
    pub fn modify(self) -> crate::Result<PrivateKey> {
        let sub_key_flags = self.collect_sub_key_flags()?;
        let modifier = self
            .inner_modify_primary_key()?
            .inner_modify_subkeys(sub_key_flags)?;
        Ok(PrivateKey::new(modifier.key_to_modify))
    }

    fn collect_sub_key_flags(&self) -> Result<Vec<KeyFlags>, KeyModificationError> {
        if self.reset_signatures {
            self.key_to_modify
                .secret_subkeys
                .iter()
                .map(|sub_key| {
                    let self_sig = sub_key.latest_valid_self_certification(
                        self.key_to_modify.primary_key(),
                        CheckUnixTime::disable(),
                        &self.profile,
                    )?;
                    Ok(self_sig.key_flags())
                })
                .collect()
        } else {
            Ok(Vec::default())
        }
    }

    fn inner_modify_primary_key(mut self) -> Result<Self, KeyModificationError> {
        let mut rng = self.profile.rng();
        let preferred_hash = self.profile.key_hash_algorithm();

        if self.remove_old_user_ids {
            self.key_to_modify.details.users.clear();
        }

        if self.reset_signatures {
            if let Some(key_time) = self.key_time {
                let pub_key = PubKeyInner::new(
                    self.key_to_modify.primary_key().version(),
                    self.key_to_modify.primary_key().algorithm(),
                    key_time.into(),
                    None,
                    self.key_to_modify.primary_key().public_params().clone(),
                )
                .map_err(KeyModificationError::PrimaryKeyModification)?;
                let primary_pub_key = packet::PublicKey::from_inner(pub_key)
                    .map_err(KeyModificationError::PrimaryKeyModification)?;
                let primary_secret_key = packet::SecretKey::new(
                    primary_pub_key.clone(),
                    self.key_to_modify
                        .primary_secret_key()
                        .secret_params()
                        .clone(),
                )
                .map_err(KeyModificationError::PrimaryKeyModification)?;
                self.key_to_modify.primary_key = primary_secret_key;
            }
        }

        let key_gen_config = KeyGenerationProfileBuilder::default()
            .key_version(self.key_to_modify.version())
            .build();

        let (primary_user_id, non_primary_user_ids) = if self.key_to_modify.details.users.is_empty()
        {
            convert_user_ids(&self.new_user_ids)?
        } else {
            let mut old_user_ids = if self.reset_signatures {
                std::mem::take(&mut self.key_to_modify.details.users)
                    .into_iter()
                    .map(|user| user.id)
                    .collect::<Vec<_>>()
            } else {
                Vec::with_capacity(self.new_user_ids.len())
            };
            for user_id in &self.new_user_ids {
                old_user_ids.push(user_id.try_to_user_id()?);
            }

            (None, old_user_ids)
        };

        let key_details_config = key_gen_config.create_key_details_config(
            primary_user_id,
            non_primary_user_ids,
            primary_key_flags(),
        );

        let updated_signed_key_details = key_details_config
            .sign_with(
                self.key_to_modify.primary_secret_key(),
                self.key_to_modify.primary_key(),
                self.date,
                preferred_hash,
                &mut rng,
                &self.profile,
            )
            .map_err(KeyModificationError::Signing)?;

        let mut new_users = Vec::with_capacity(
            updated_signed_key_details.users.len() + self.key_to_modify.details.users.len(),
        );
        new_users.extend(updated_signed_key_details.users);
        new_users.extend(self.key_to_modify.details.users);
        self.key_to_modify.details.users = new_users;

        if self.reset_signatures {
            self.key_to_modify.details.revocation_signatures.clear();
            self.key_to_modify.details.direct_signatures.clear();
            self.key_to_modify
                .details
                .direct_signatures
                .extend(updated_signed_key_details.direct_signatures);
        }

        Ok(self)
    }

    fn inner_modify_subkeys(
        mut self,
        sub_key_flags: Vec<KeyFlags>,
    ) -> Result<Self, KeyModificationError> {
        if self.reset_signatures {
            let mut rng = self.profile.rng();
            let preferred_hash = self.profile.key_hash_algorithm();

            let updated_subkeys: Vec<_> = self
                .key_to_modify
                .secret_subkeys
                .iter()
                .map(|sub_key| {
                    if let Some(key_time) = self.key_time {
                        let pub_key = PubKeyInner::new(
                            sub_key.key.version(),
                            sub_key.key.algorithm(),
                            key_time.into(),
                            None,
                            sub_key.key.public_key().public_params().clone(),
                        )
                        .map_err(KeyModificationError::SubkeyModification)?;
                        let subkey_public = packet::PublicSubkey::from_inner(pub_key)
                            .map_err(KeyModificationError::SubkeyModification)?;
                        packet::SecretSubkey::new(subkey_public, sub_key.secret_params().clone())
                            .map_err(KeyModificationError::SubkeyModification)
                    } else {
                        Ok(sub_key.key.clone())
                    }
                })
                .collect::<Result<_, _>>()?;

            let new_subkey_signatures = updated_subkeys
                .iter()
                .zip(sub_key_flags)
                .map(|(sub_key, subkey_flag)| {
                    sub_key
                        .public_key()
                        .sign_with(
                            self.key_to_modify.primary_secret_key(),
                            self.key_to_modify.primary_key(),
                            self.date,
                            preferred_hash,
                            subkey_flag,
                            None,
                            &mut rng,
                            &self.profile,
                        )
                        .map_err(KeyModificationError::Signing)
                })
                .collect::<Result<Vec<_>, _>>()?;

            for (sub_key, (updated_subkey, signature)) in self
                .key_to_modify
                .secret_subkeys
                .iter_mut()
                .zip(updated_subkeys.into_iter().zip(new_subkey_signatures))
            {
                sub_key.key = updated_subkey;
                sub_key.signatures.clear();
                sub_key.signatures.push(signature);
            }
        }

        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        AccessKeyInfo, DataEncoding, PrivateKey, UnixTime, DEFAULT_PROFILE,
        PREFERRED_KEY_GEN_COMPRESSION_ALGORITHMS, PREFERRED_KEY_GEN_HASH_ALGORITHMS,
    };

    const TEST_PRIVATE_KEY: &str = include_str!("../../test-data/keys/locked_private_key_v6.asc");
    const TEST_PRIVATE_KEY_PASSWORD: &str = "password";

    #[test]
    fn key_modification_user_id_v4() {
        let key = PrivateKey::import(
            include_str!("../../test-data/keys/private_key_v4.asc").as_bytes(),
            TEST_PRIVATE_KEY_PASSWORD.as_bytes(),
            DataEncoding::Armored,
        )
        .expect("Failed to import key");

        let date = UnixTime::new(1_756_196_260);

        let modified_key = key
            .modify_default()
            .erase_existing_user_ids(true)
            .add_user_id("test2", "test2@test.com")
            .at_date(date)
            .modify()
            .expect("Failed to modify key");

        assert!(modified_key
            .check_can_encrypt(&DEFAULT_PROFILE, date.into())
            .is_ok());

        assert_eq!(modified_key.as_signed_public_key().details.users.len(), 1);
        let user_id = modified_key
            .as_signed_public_key()
            .details
            .users
            .first()
            .unwrap();
        assert_eq!(user_id.id.as_str().unwrap(), "test2 <test2@test.com>");
        let user_id_signature = user_id.signatures.first().unwrap();
        assert_eq!(
            user_id_signature.preferred_hash_algs(),
            PREFERRED_KEY_GEN_HASH_ALGORITHMS
        );
        assert_eq!(
            user_id_signature.preferred_compression_algs(),
            PREFERRED_KEY_GEN_COMPRESSION_ALGORITHMS,
        );

        assert_eq!(UnixTime::from(user_id_signature.created().unwrap()), date);
    }

    #[test]
    fn key_modification_user_id_v6() {
        let key = PrivateKey::import(
            TEST_PRIVATE_KEY.as_bytes(),
            TEST_PRIVATE_KEY_PASSWORD.as_bytes(),
            DataEncoding::Armored,
        )
        .expect("Failed to import key");

        let date = UnixTime::new(1_756_196_260);

        let modified_key = key
            .modify_default()
            .erase_existing_user_ids(true)
            .add_user_id("test2", "test2@test.com")
            .at_date(date)
            .modify()
            .expect("Failed to modify key");

        assert!(modified_key
            .check_can_encrypt(&DEFAULT_PROFILE, date.into())
            .is_ok());

        assert_eq!(modified_key.as_signed_public_key().details.users.len(), 1);
        let user_id = modified_key
            .as_signed_public_key()
            .details
            .users
            .first()
            .unwrap();
        assert_eq!(user_id.id.as_str().unwrap(), "test2 <test2@test.com>");

        let user_id_signature = user_id.signatures.first().unwrap();
        assert!(user_id_signature.preferred_hash_algs().is_empty());
        assert_eq!(UnixTime::from(user_id_signature.created().unwrap()), date);
    }

    #[test]
    fn key_modification_user_id_v4_reset() {
        let key = PrivateKey::import(
            include_str!("../../test-data/keys/private_key_v4.asc").as_bytes(),
            TEST_PRIVATE_KEY_PASSWORD.as_bytes(),
            DataEncoding::Armored,
        )
        .expect("Failed to import key");

        let date = UnixTime::new(1_756_196_260);

        let modified_key = key
            .modify_default()
            .add_user_id("test2", "test2@test.com")
            .reset_signatures(true)
            .update_key_creation_time(date)
            .at_date(date)
            .modify()
            .expect("Failed to modify key");

        assert!(modified_key
            .check_can_encrypt(&DEFAULT_PROFILE, date.into())
            .is_ok());

        assert_eq!(modified_key.as_signed_public_key().details.users.len(), 2);
        let users = &modified_key.as_signed_public_key().details.users;
        let new_user_id = &users[1].id;
        let old_user_id = &users[0].id;
        assert_eq!(new_user_id.as_str().unwrap(), "test2 <test2@test.com>");
        assert_eq!(
            old_user_id.as_str().unwrap(),
            "rust-test <rust-test@test.test>"
        );
    }
}
