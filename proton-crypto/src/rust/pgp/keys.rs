use std::sync::Arc;

use crate::crypto::{
    AccessKeyInfo, AsPublicKeyRef, DataEncoding, KeyGenerator, KeyGeneratorAlgorithm,
    KeyGeneratorAsync, KeyGeneratorSync, OpenPGPFingerprint, OpenPGPKeyID, PrivateKey, PublicKey,
    SHA256Fingerprint, SessionKey, SessionKeyAlgorithm, UnixTimestamp,
};
use crate::CryptoInfoError;
use proton_rpgp::pgp::crypto::sym::SymmetricKeyAlgorithm as RustSessionKeyAlgorithm;
use proton_rpgp::pgp::types::{Fingerprint as RustFingerprint, KeyId as RustKeyId};
use proton_rpgp::{
    AccessKeyInfo as _, AsPublicKeyRef as _, FingerprintSha256 as RustSHA256Fingerprint,
    KeyGenerationType, Profile, SessionKey as RustSessionKey, DEFAULT_PROFILE,
};

impl SessionKey for RustSessionKey {
    fn export(&self) -> impl AsRef<[u8]> {
        self.export_bytes()
    }

    fn algorithm(&self) -> SessionKeyAlgorithm {
        self.algorithm().into()
    }
}

impl From<Option<RustSessionKeyAlgorithm>> for SessionKeyAlgorithm {
    fn from(algorithm: Option<RustSessionKeyAlgorithm>) -> Self {
        match algorithm {
            Some(RustSessionKeyAlgorithm::AES128) => SessionKeyAlgorithm::Aes128,
            Some(RustSessionKeyAlgorithm::AES256) => SessionKeyAlgorithm::Aes256,
            _ => SessionKeyAlgorithm::Unknown,
        }
    }
}

impl TryFrom<SessionKeyAlgorithm> for RustSessionKeyAlgorithm {
    type Error = CryptoInfoError;

    fn try_from(value: SessionKeyAlgorithm) -> Result<Self, Self::Error> {
        match value {
            SessionKeyAlgorithm::Aes128 => Ok(RustSessionKeyAlgorithm::AES128),
            SessionKeyAlgorithm::Aes256 => Ok(RustSessionKeyAlgorithm::AES256),
            SessionKeyAlgorithm::Unknown => {
                Err(CryptoInfoError::new("invalid session key algorithm"))
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct RustPublicKey(pub(super) Arc<proton_rpgp::PublicKey>);

impl RustPublicKey {
    pub fn import(public_key: impl AsRef<[u8]>, encoding: DataEncoding) -> crate::Result<Self> {
        proton_rpgp::PublicKey::import(public_key.as_ref(), encoding.into())
            .map(Into::into)
            .map_err(Into::into)
    }

    pub fn export(&self, encoding: DataEncoding) -> crate::Result<impl AsRef<[u8]>> {
        self.0.export(encoding.into()).map_err(Into::into)
    }
}

impl PublicKey for RustPublicKey {}

impl AsPublicKeyRef<RustPublicKey> for RustPublicKey {
    fn as_public_key(&self) -> &RustPublicKey {
        self
    }
}

impl AccessKeyInfo for RustPublicKey {
    fn version(&self) -> u8 {
        self.0.version()
    }

    fn key_id(&self) -> OpenPGPKeyID {
        self.0.key_id().into()
    }

    fn key_fingerprint(&self) -> OpenPGPFingerprint {
        self.0.fingerprint().into()
    }

    fn sha256_key_fingerprints(&self) -> Vec<SHA256Fingerprint> {
        self.0
            .fingerprints_sha256()
            .into_iter()
            .map(Into::into)
            .collect()
    }

    fn can_encrypt(&self, unix_time: UnixTimestamp) -> bool {
        self.0
            .check_can_encrypt(&DEFAULT_PROFILE, unix_time.into())
            .is_ok()
    }

    fn can_verify(&self, unix_time: UnixTimestamp) -> bool {
        self.0
            .check_can_verify(&DEFAULT_PROFILE, unix_time.into())
            .is_ok()
    }

    fn is_expired(&self, unix_time: UnixTimestamp) -> bool {
        self.0.is_expired(&DEFAULT_PROFILE, unix_time.into())
    }

    fn is_revoked(&self, unix_time: UnixTimestamp) -> bool {
        self.0.is_revoked(&DEFAULT_PROFILE, unix_time.into())
    }
}

impl From<proton_rpgp::PublicKey> for RustPublicKey {
    fn from(value: proton_rpgp::PublicKey) -> Self {
        Self(Arc::new(value))
    }
}

#[derive(Debug, Clone)]
pub struct RustPrivateKey(pub(super) Arc<proton_rpgp::PrivateKey>);

impl RustPrivateKey {
    pub fn import(
        private_key: impl AsRef<[u8]>,
        passphrase: impl AsRef<[u8]>,
        encoding: DataEncoding,
    ) -> crate::Result<Self> {
        proton_rpgp::PrivateKey::import(private_key.as_ref(), passphrase.as_ref(), encoding.into())
            .map(Into::into)
            .map_err(Into::into)
    }

    pub fn import_unlocked(
        private_key: impl AsRef<[u8]>,
        encoding: DataEncoding,
    ) -> crate::Result<Self> {
        proton_rpgp::PrivateKey::import_unlocked(private_key.as_ref(), encoding.into())
            .map(Into::into)
            .map_err(Into::into)
    }

    pub fn export(
        &self,
        passphrase: impl AsRef<[u8]>,
        encoding: DataEncoding,
        profile: &Profile,
    ) -> crate::Result<impl AsRef<[u8]>> {
        self.0
            .export(profile, passphrase.as_ref(), encoding.into())
            .map_err(Into::into)
    }

    pub fn export_unlocked(&self, encoding: DataEncoding) -> crate::Result<impl AsRef<[u8]>> {
        self.0.export_unlocked(encoding.into()).map_err(Into::into)
    }

    #[allow(clippy::unnecessary_wraps)]
    pub fn to_public_key(&self) -> crate::Result<RustPublicKey> {
        Ok(RustPublicKey::from(self.0.as_public_key().clone()))
    }
}

impl PrivateKey for RustPrivateKey {}

impl AccessKeyInfo for RustPrivateKey {
    fn version(&self) -> u8 {
        self.0.version()
    }

    fn key_id(&self) -> OpenPGPKeyID {
        self.0.key_id().into()
    }

    fn key_fingerprint(&self) -> OpenPGPFingerprint {
        self.0.fingerprint().into()
    }

    fn sha256_key_fingerprints(&self) -> Vec<SHA256Fingerprint> {
        self.0
            .fingerprints_sha256()
            .into_iter()
            .map(Into::into)
            .collect()
    }

    fn can_encrypt(&self, unix_time: UnixTimestamp) -> bool {
        self.0
            .check_can_encrypt(&DEFAULT_PROFILE, unix_time.into())
            .is_ok()
    }

    fn can_verify(&self, unix_time: UnixTimestamp) -> bool {
        self.0
            .check_can_verify(&DEFAULT_PROFILE, unix_time.into())
            .is_ok()
    }

    fn is_expired(&self, unix_time: UnixTimestamp) -> bool {
        self.0.is_expired(&DEFAULT_PROFILE, unix_time.into())
    }

    fn is_revoked(&self, unix_time: UnixTimestamp) -> bool {
        self.0.is_revoked(&DEFAULT_PROFILE, unix_time.into())
    }
}

impl AsRef<RustPrivateKey> for RustPrivateKey {
    fn as_ref(&self) -> &RustPrivateKey {
        self
    }
}

impl From<proton_rpgp::PrivateKey> for RustPrivateKey {
    fn from(value: proton_rpgp::PrivateKey) -> Self {
        Self(Arc::new(value))
    }
}

impl From<RustKeyId> for OpenPGPKeyID {
    fn from(value: RustKeyId) -> Self {
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(value.as_ref());
        Self(u64::from_be_bytes(bytes))
    }
}

impl From<RustFingerprint> for OpenPGPFingerprint {
    fn from(value: RustFingerprint) -> Self {
        Self::new(value.to_string())
    }
}

impl From<RustSHA256Fingerprint> for SHA256Fingerprint {
    fn from(value: RustSHA256Fingerprint) -> Self {
        Self::new(value.to_hex())
    }
}

#[derive(Debug)]
pub struct RustKeyGenerator {
    pub(super) inner: proton_rpgp::KeyGenerator,
}

impl RustKeyGenerator {
    pub fn new() -> Self {
        Self {
            inner: proton_rpgp::KeyGenerator::default(),
        }
    }
}

impl KeyGenerator for RustKeyGenerator {
    fn with_user_id(mut self, name: &str, email: &str) -> Self {
        self.inner = self.inner.with_user_id(name, email);
        self
    }

    fn with_generation_time(mut self, unix_time: UnixTimestamp) -> Self {
        self.inner = self.inner.at_date(unix_time.into());
        self
    }

    fn with_algorithm(mut self, option: KeyGeneratorAlgorithm) -> Self {
        self.inner = self.inner.with_key_type(option.into());
        self
    }
}

impl KeyGeneratorSync<RustPrivateKey> for RustKeyGenerator {
    fn generate(self) -> crate::Result<RustPrivateKey> {
        self.inner.generate().map(Into::into).map_err(Into::into)
    }
}

impl KeyGeneratorAsync<RustPrivateKey> for RustKeyGenerator {
    async fn generate_async(self) -> crate::Result<RustPrivateKey> {
        self.inner.generate().map(Into::into).map_err(Into::into)
    }
}

impl From<KeyGeneratorAlgorithm> for KeyGenerationType {
    fn from(value: KeyGeneratorAlgorithm) -> Self {
        match value {
            KeyGeneratorAlgorithm::ECC => KeyGenerationType::ECC,
            KeyGeneratorAlgorithm::RSA => KeyGenerationType::RSA,
        }
    }
}
