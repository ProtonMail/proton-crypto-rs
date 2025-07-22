use pgp::{
    bytes::Bytes,
    crypto::{
        aead::{AeadAlgorithm, ChunkSize},
        ecc_curve::ECCCurve,
        hash::HashAlgorithm,
        public_key::PublicKeyAlgorithm,
        sym::SymmetricKeyAlgorithm,
    },
    packet::Notation,
    types::{CompressionAlgorithm, S2kParams, StringToKey},
};
use rand::{CryptoRng, Rng, RngCore};

/// AEAD ciphersuite.
pub type CipherSuite = (SymmetricKeyAlgorithm, AeadAlgorithm);

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

pub static DEFAULT_PROFILE: LazyLock<Profile> = LazyLock::new(Profile::new);

#[derive(Debug, Clone)]
pub struct Profile {
    pub min_rsa_bits: usize,
    pub cipher_suite: Option<CipherSuite>,
}

impl Profile {
    pub fn new() -> Self {
        Self {
            min_rsa_bits: 1024,
            cipher_suite: None,
        }
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

    pub fn message_aead_cipher_suite(&self) -> Option<CipherSuite> {
        self.cipher_suite
    }

    pub fn message_symmetric_algorithm(&self) -> SymmetricKeyAlgorithm {
        SymmetricKeyAlgorithm::AES256
    }

    pub fn message_compression(&self) -> CompressionAlgorithm {
        CompressionAlgorithm::Uncompressed
    }

    pub fn message_aead_chunk_size(&self) -> ChunkSize {
        ChunkSize::default()
    }

    pub fn symmetric_key_algorithms(&self) -> &[SymmetricKeyAlgorithm] {
        PREFERRED_SYMMETRIC_KEY_ALGORITHMS
    }

    pub fn compression_algorithms(&self) -> &[CompressionAlgorithm] {
        PREFERRED_COMPRESSION_ALGORITHMS
    }

    pub fn aead_ciphersuites(&self) -> &[(SymmetricKeyAlgorithm, AeadAlgorithm)] {
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
        // TODO(CRYPTO-292): Rand generation logic should not be handled here.
        let mut salt = [0; 8];
        let mut iv = [0; 16];
        self.rng().fill_bytes(&mut salt);
        self.rng().fill_bytes(&mut iv);
        let s2k = StringToKey::IteratedAndSalted {
            hash_alg: HashAlgorithm::Sha256,
            salt,
            count: 96,
        };
        S2kParams::Cfb {
            sym_alg: SymmetricKeyAlgorithm::AES256,
            s2k,
            iv: Bytes::from(iv.to_vec()),
        }
    }

    pub fn message_s2k_params(&self) -> StringToKey {
        // TODO(CRYPTO-292): Rand generation logic should not be handled here.
        let mut salt = [0; 8];
        self.rng().fill_bytes(&mut salt);
        StringToKey::IteratedAndSalted {
            hash_alg: HashAlgorithm::Sha256,
            salt,
            count: 96,
        }
    }
}

impl Default for Profile {
    fn default() -> Self {
        Self::new()
    }
}
