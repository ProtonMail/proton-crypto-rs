use pgp::{
    crypto::{
        aead::{AeadAlgorithm, ChunkSize},
        ecc_curve::ECCCurve,
        hash::HashAlgorithm,
        public_key::PublicKeyAlgorithm,
        sym::SymmetricKeyAlgorithm,
    },
    packet::Notation,
    types::{CompressionAlgorithm, KeyVersion, S2kParams},
};
use rand::{CryptoRng, Rng};

/// Preferred symmetric-key algorithms (in descending order of preference)
pub const PREFERRED_SYMMETRIC_KEY_ALGORITHMS: &[SymmetricKeyAlgorithm] =
    &[SymmetricKeyAlgorithm::AES256, SymmetricKeyAlgorithm::AES128];

/// Preferred AEAD algorithms (in descending order of preference)
pub const PREFERRED_AEAD_ALGORITHMS: &[(SymmetricKeyAlgorithm, AeadAlgorithm)] = &[
    (SymmetricKeyAlgorithm::AES256, AeadAlgorithm::Gcm),
    (SymmetricKeyAlgorithm::AES256, AeadAlgorithm::Ocb),
    (SymmetricKeyAlgorithm::AES256, AeadAlgorithm::Eax),
    (SymmetricKeyAlgorithm::AES128, AeadAlgorithm::Gcm),
    (SymmetricKeyAlgorithm::AES128, AeadAlgorithm::Ocb),
    (SymmetricKeyAlgorithm::AES128, AeadAlgorithm::Eax),
];

/// Preferred hash algorithms (in descending order of preference)
pub const PREFERRED_HASH_ALGORITHMS: &[HashAlgorithm] = &[
    HashAlgorithm::Sha256,
    HashAlgorithm::Sha384,
    HashAlgorithm::Sha512,
    HashAlgorithm::Sha3_256,
    HashAlgorithm::Sha3_512,
];

pub const PREFERRED_COMPRESSION_ALGORITHMS: &[CompressionAlgorithm] = &[
    CompressionAlgorithm::Uncompressed,
    CompressionAlgorithm::ZIP,
    CompressionAlgorithm::ZLIB,
];

use std::sync::LazyLock;

use crate::preferences::EncryptionAlgorithmPreference;

pub static DEFAULT_PROFILE: LazyLock<Profile> = LazyLock::new(Profile::new);

#[derive(Debug, Clone)]
pub struct Profile {
    pub min_rsa_bits: usize,
}

impl Profile {
    pub fn new() -> Self {
        Self { min_rsa_bits: 1024 }
    }

    pub fn rng(&self) -> impl Rng + CryptoRng {
        rand::thread_rng()
    }

    pub fn hash_algorithms(&self) -> &[HashAlgorithm] {
        PREFERRED_HASH_ALGORITHMS
    }

    pub fn message_hash_algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::Sha512
    }

    pub fn message_aead_chunk_size(&self) -> ChunkSize {
        ChunkSize::default()
    }

    pub fn message_encryption_preferences(&self) -> EncryptionAlgorithmPreference {
        EncryptionAlgorithmPreference {
            symmetric: SymmetricKeyAlgorithm::AES256,
            aead: None,
            compression: CompressionAlgorithm::Uncompressed,
        }
    }

    pub fn symmetric_key_algorithms(&self) -> &[SymmetricKeyAlgorithm] {
        PREFERRED_SYMMETRIC_KEY_ALGORITHMS
    }

    pub fn compression_algorithms(&self) -> &[CompressionAlgorithm] {
        PREFERRED_COMPRESSION_ALGORITHMS
    }

    pub fn aead_algorithms(&self) -> &[(SymmetricKeyAlgorithm, AeadAlgorithm)] {
        PREFERRED_AEAD_ALGORITHMS
    }

    pub fn reject_hash_algorithm(&self, _hash: Option<HashAlgorithm>) -> bool {
        false
    }

    pub fn accept_critical_notation(&self, _notation: &Notation) -> bool {
        true
    }

    pub fn reject_public_key_algorithm(&self, _algorithm: PublicKeyAlgorithm) -> bool {
        false
    }

    pub fn reject_ecc_curve(&self, _curve: &ECCCurve) -> bool {
        false
    }

    pub fn max_recursion_depth(&self) -> usize {
        1024
    }

    pub fn ignore_key_flags(&self) -> bool {
        false
    }

    pub fn min_rsa_bits(&self) -> usize {
        self.min_rsa_bits
    }

    pub fn key_s2k_params(&self) -> S2kParams {
        S2kParams::new_default(self.rng(), KeyVersion::V4)
    }
}

impl Default for Profile {
    fn default() -> Self {
        Self::new()
    }
}
