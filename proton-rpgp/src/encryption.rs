use pgp::{
    crypto::{aead::AeadAlgorithm, hash::HashAlgorithm, sym::SymmetricKeyAlgorithm},
    types::{CompressionAlgorithm, PublicParams},
};

use crate::{
    types::UnixTime, DataEncoding, EncryptionError, Profile, PublicComponentKey, PublicKey,
    PublicKeySelectionExt,
};

pub struct Encryptor<'a> {
    profile: Profile,
    encryption_keys: Vec<&'a PublicKey>,
}

impl<'a> Encryptor<'a> {
    pub fn new(profile: Profile) -> Self {
        Self {
            profile,
            encryption_keys: Vec::new(),
        }
    }

    pub fn with_encryption_key(mut self, key: &'a PublicKey) -> Self {
        self.encryption_keys.push(key);
        self
    }

    pub fn with_encryption_keys(mut self, keys: Vec<&'a PublicKey>) -> Self {
        self.encryption_keys.extend(keys);
        self
    }

    pub fn encrypt_raw(
        self,
        data: &[u8],
        data_encoding: DataEncoding,
    ) -> Result<Vec<u8>, EncryptionError> {
        let now = UnixTime::now().unwrap();

        let mut selection_errors = Vec::new();
        let encryption_keys: Vec<PublicComponentKey<'_>> = self
            .encryption_keys
            .iter()
            .filter_map(|key| match key.inner.encryption_key(now, &self.profile) {
                Ok(key) => Some(key),
                Err(e) => {
                    selection_errors.push(e);
                    None
                }
            })
            .collect();

        if !selection_errors.is_empty() {
            return Err(EncryptionError::EncryptionKeySelection(
                selection_errors.into(),
            ));
        }

        todo!()
    }
}

#[derive(Debug, Default, Clone)]
pub struct RecipientsSelection {
    pub hash_algorithm: HashAlgorithm,

    pub compression_algorithm: Option<CompressionAlgorithm>,

    pub symmetric_algorithm: SymmetricKeyAlgorithm,

    pub aead_algorithm: Option<AeadAlgorithm>,
}

impl RecipientsSelection {
    pub fn select(profile: &Profile, keys: &[PublicComponentKey<'_>]) -> Self {
        let mut selection = Self::default();

        let mut candidate_hashes_to_sign = profile.hash_algorithms().to_vec();
        let mut candidate_symmetric_algorithms = profile.symmetric_key_algorithms().to_vec();
        let mut candidate_compression_algorithms = profile.compression_algorithms().to_vec();
        let mut candidate_aead_algorithms = profile.aead_algorithms().to_vec();
        for key in keys {
            let self_sig = key.primary_self_certification;
            intersect(
                &mut candidate_hashes_to_sign,
                self_sig.preferred_hash_algs(),
            );
            intersect(
                &mut candidate_symmetric_algorithms,
                self_sig.preferred_symmetric_algs(),
            );
            intersect(
                &mut candidate_compression_algorithms,
                self_sig.preferred_compression_algs(),
            );
            intersect(
                &mut candidate_aead_algorithms,
                self_sig.preferred_aead_algs(),
            );
        }
        todo!()
    }
}

fn intersect<T: Copy + PartialEq>(order_determining: &mut Vec<T>, to_intersect: &[T]) {
    order_determining.retain(|alg| to_intersect.contains(alg));
}

const HASH_ALGORITHMS_MID: &[HashAlgorithm] = &[
    HashAlgorithm::Sha512,
    HashAlgorithm::Sha3_512,
    HashAlgorithm::Sha384,
];

const HASH_ALGORITHMS_HIGH: &[HashAlgorithm] = &[HashAlgorithm::Sha512, HashAlgorithm::Sha3_512];

fn acceptable_sign_hash_algorithms<'a>(
    public_params: &'a PublicParams,
    profile: &'a Profile,
) -> &'a [HashAlgorithm] {
    match public_params {
        PublicParams::ECDSA(ecdsa_public_params) => match ecdsa_public_params {
            pgp::types::EcdsaPublicParams::P384 { key: _ } => HASH_ALGORITHMS_MID,
            pgp::types::EcdsaPublicParams::P521 { key: _ } => HASH_ALGORITHMS_HIGH,
            _ => profile.hash_algorithms(),
        },
        PublicParams::Ed448(_) | PublicParams::MlDsa87Ed448(_) => HASH_ALGORITHMS_HIGH,
        _ => profile.hash_algorithms(),
    }
}
