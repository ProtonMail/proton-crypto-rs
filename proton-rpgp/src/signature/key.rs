use pgp::{
    composed::SignedKeyDetails,
    crypto::{aead::AeadAlgorithm, hash::HashAlgorithm, sym::SymmetricKeyAlgorithm},
    packet::{
        self, Features, KeyFlags, PacketTrait, Signature, SignatureType, Subpacket, SubpacketData,
        UserId,
    },
    ser::Serialize,
    types::{CompressionAlgorithm, KeyVersion, Password, PublicKeyTrait, SecretKeyTrait},
};
use rand::{CryptoRng, Rng};
use smallvec::SmallVec;

use crate::{
    core::{key_details_configure_signature, sub_key_configure_signature},
    Profile, SignError, UnixTime,
};

/// The key detail data to be signed for a key.
///
/// The key details are either stored in the direct key signature
/// or in a self-certification of the primary User-Id.
pub(crate) struct KeyDetailsConfig {
    pub(crate) primary_user_id: Option<UserId>,
    pub(crate) non_primary_user_ids: Vec<UserId>,
    pub(crate) keyflags: KeyFlags,
    pub(crate) features: Features,
    pub(crate) preferred_symmetric_algorithms: SmallVec<[SymmetricKeyAlgorithm; 8]>,
    pub(crate) preferred_hash_algorithms: SmallVec<[HashAlgorithm; 8]>,
    pub(crate) preferred_compression_algorithms: SmallVec<[CompressionAlgorithm; 8]>,
    pub(crate) preferred_aead_algorithms: SmallVec<[(SymmetricKeyAlgorithm, AeadAlgorithm); 4]>,
}

impl KeyDetailsConfig {
    pub(crate) fn sign_with<R, K, P>(
        self,
        primary_secret_key: &K,
        primary_pub_key: &P,
        at_date: UnixTime,
        preferred_hash: HashAlgorithm,
        mut rng: R,
        profile: &Profile,
    ) -> Result<SignedKeyDetails, SignError>
    where
        R: CryptoRng + Rng,
        K: SecretKeyTrait,
        P: PublicKeyTrait + Serialize,
    {
        let direct_signatures = if primary_secret_key.version() == KeyVersion::V6 {
            let config = key_details_configure_signature(
                primary_secret_key,
                primary_pub_key,
                at_date,
                preferred_hash,
                SignatureType::Key,
                &self,
                false,
                true,
                profile,
                &mut rng,
            )?;
            let direct_key_signature = config
                .sign_key(primary_secret_key, &Password::empty(), primary_pub_key)
                .map_err(SignError::Sign)?;
            vec![direct_key_signature]
        } else {
            Vec::new()
        };

        let mut users = Vec::with_capacity(1 + self.non_primary_user_ids.len());
        if let Some(primary_user_id) = &self.primary_user_id {
            let config = key_details_configure_signature(
                primary_secret_key,
                primary_pub_key,
                at_date,
                preferred_hash,
                SignatureType::CertPositive,
                &self,
                true,
                primary_secret_key.version() < KeyVersion::V6,
                profile,
                &mut rng,
            )?;

            let sig = config
                .sign_certification(
                    primary_secret_key,
                    primary_pub_key,
                    &Password::empty(),
                    primary_user_id.tag(),
                    primary_user_id,
                )
                .map_err(SignError::Sign)?;

            users.push(primary_user_id.clone().into_signed(sig));
        }

        // Certify all non-primary user IDs.
        for id in &self.non_primary_user_ids {
            let config = key_details_configure_signature(
                primary_secret_key,
                primary_pub_key,
                at_date,
                preferred_hash,
                SignatureType::CertPositive,
                &self,
                false,
                primary_secret_key.version() < KeyVersion::V6,
                profile,
                &mut rng,
            )?;

            let sig = config
                .sign_certification(
                    primary_secret_key,
                    primary_pub_key,
                    &Password::empty(),
                    id.tag(),
                    id,
                )
                .map_err(SignError::Sign)?;

            users.push(id.clone().into_signed(sig));
        }

        Ok(SignedKeyDetails {
            revocation_signatures: Vec::new(),
            direct_signatures,
            users,
            user_attributes: Vec::new(),
        })
    }
}

pub(crate) trait PacketPublicSubkeyExt {
    #[allow(clippy::too_many_arguments)]
    fn sign_with<R, K, P>(
        &self,
        primary_sec_key: &K,
        primary_pub_key: &P,
        at_date: UnixTime,
        selected_hash: HashAlgorithm,
        keyflags: KeyFlags,
        embedded: Option<Signature>,
        rng: R,
        profile: &Profile,
    ) -> Result<Signature, SignError>
    where
        K: SecretKeyTrait,
        P: PublicKeyTrait + Serialize,
        R: CryptoRng + Rng;
}

impl PacketPublicSubkeyExt for packet::PublicSubkey {
    fn sign_with<R, K, P>(
        &self,
        primary_sec_key: &K,
        primary_pub_key: &P,
        at_date: UnixTime,
        selected_hash: HashAlgorithm,
        keyflags: KeyFlags,
        embedded: Option<Signature>,
        mut rng: R,
        profile: &Profile,
    ) -> Result<Signature, SignError>
    where
        K: SecretKeyTrait,
        P: PublicKeyTrait + Serialize,
        R: CryptoRng + Rng,
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
                    .map_err(SignError::Sign)?,
            );
        }

        config
            .sign_subkey_binding(primary_sec_key, primary_pub_key, &Password::empty(), &self)
            .map_err(SignError::Sign)
    }
}
