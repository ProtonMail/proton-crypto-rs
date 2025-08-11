use pgp::{
    composed::{KeyType, SecretKeyParamsBuilder},
    crypto::{
        aead::AeadAlgorithm, ecc_curve::ECCCurve, hash::HashAlgorithm, sym::SymmetricKeyAlgorithm,
    },
    types::{CompressionAlgorithm, KeyVersion},
};
use smallvec::SmallVec;

use crate::{
    PREFERRED_COMPRESSION_ALGORITHMS, PREFERRED_HASH_ALGORITHMS, PREFERRED_SYMMETRIC_KEY_ALGORITHMS,
};

/// The algorithm type to use for the key generation.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyGenerationType {
    /// An RSA 4096-bit v4 signing and encryption key.
    RSA,

    /// An ECC v4 signing (`EdDsaLegacy`) and encryption key (`ECDH` with `Curve25519` legacy).
    #[default]
    ECC,

    /// A PQC v6 signing (`ML-DSA`) and encryption key (`ML-KEM`).
    PQC,
}

impl KeyGenerationType {
    pub(crate) fn primary_key_type(self) -> KeyType {
        match self {
            KeyGenerationType::RSA => KeyType::Rsa(4096),
            KeyGenerationType::ECC => KeyType::Ed25519Legacy,
            KeyGenerationType::PQC => KeyType::MlDsa65Ed25519,
        }
    }

    pub(crate) fn encryption_key_type(self) -> KeyType {
        match self {
            KeyGenerationType::RSA => KeyType::Rsa(4096),
            KeyGenerationType::ECC => KeyType::ECDH(ECCCurve::Curve25519),
            KeyGenerationType::PQC => KeyType::MlKem768X25519,
        }
    }

    pub(crate) fn key_generation_profile(self) -> KeyGenerationProfile {
        match self {
            KeyGenerationType::RSA | KeyGenerationType::ECC => KeyGenerationProfile::default(),
            KeyGenerationType::PQC => KeyGenerationProfileBuilder::default()
                .key_version(KeyVersion::V6)
                .build(),
        }
    }
}

/// The profile to use for the key generation.
#[derive(Debug, Clone)]
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
    pub preferred_aead_ciphersuites: SmallVec<[(SymmetricKeyAlgorithm, AeadAlgorithm); 4]>,

    /// Whether to signal support for SEIPD v2.
    pub support_seipd_v2: bool,
}

impl Default for KeyGenerationProfile {
    fn default() -> Self {
        Self {
            key_version: KeyVersion::V4,
            preferred_symmetric_algorithms: PREFERRED_SYMMETRIC_KEY_ALGORITHMS.into(),
            preferred_hash_algorithms: PREFERRED_HASH_ALGORITHMS.into(),
            preferred_compression_algorithms: PREFERRED_COMPRESSION_ALGORITHMS.into(),
            preferred_aead_ciphersuites: SmallVec::new(),
            support_seipd_v2: false,
        }
    }
}

impl KeyGenerationProfile {
    pub(crate) fn apply_to_primary_builder(self, builder: &mut SecretKeyParamsBuilder) {
        builder
            .version(self.key_version)
            .can_certify(true)
            .can_sign(true)
            .preferred_symmetric_algorithms(self.preferred_symmetric_algorithms)
            .preferred_hash_algorithms(self.preferred_hash_algorithms)
            .preferred_compression_algorithms(self.preferred_compression_algorithms)
            .preferred_aead_algorithms(self.preferred_aead_ciphersuites)
            .feature_seipd_v1(true)
            .feature_seipd_v2(self.support_seipd_v2);
    }
}

/// A builder for the key generation profile.
#[derive(Default, Debug, Clone)]
pub struct KeyGenerationProfileBuilder {
    profile: KeyGenerationProfile,
}

impl KeyGenerationProfileBuilder {
    pub fn new() -> Self {
        Self {
            profile: KeyGenerationProfile::default(),
        }
    }

    pub fn key_version(mut self, key_version: KeyVersion) -> Self {
        self.profile.key_version = key_version;
        self
    }

    pub fn preferred_symmetric_algorithms(
        mut self,
        syms: impl Into<SmallVec<[SymmetricKeyAlgorithm; 8]>>,
    ) -> Self {
        self.profile.preferred_symmetric_algorithms = syms.into();
        self
    }

    pub fn preferred_hash_algorithms(
        mut self,
        hashes: impl Into<SmallVec<[HashAlgorithm; 8]>>,
    ) -> Self {
        self.profile.preferred_hash_algorithms = hashes.into();
        self
    }

    pub fn preferred_compression_algorithms(
        mut self,
        compressions: impl Into<SmallVec<[CompressionAlgorithm; 8]>>,
    ) -> Self {
        self.profile.preferred_compression_algorithms = compressions.into();
        self
    }

    pub fn preferred_aead_algorithms(
        mut self,
        aeads: impl Into<SmallVec<[(SymmetricKeyAlgorithm, AeadAlgorithm); 4]>>,
    ) -> Self {
        self.profile.preferred_aead_ciphersuites = aeads.into();
        self
    }

    pub fn seipd_v2(mut self, seipd_v2: bool) -> Self {
        self.profile.support_seipd_v2 = seipd_v2;
        self
    }

    pub fn build(self) -> KeyGenerationProfile {
        self.profile
    }
}
