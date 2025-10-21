use std::sync::Arc;

use proton_rpgp::{
    pgp::crypto::sym::SymmetricKeyAlgorithm, CheckUnixTime as RustCheckUnixTime,
    DataEncoding as RustDataEncoding, Profile, SessionKey as RustSessionKey,
    UnixTime as RustUnixTime, DEFAULT_PROFILE,
};

use crate::{
    crypto::{
        DataEncoding, Decryptor as _, Encryptor, KeyGenerator as _, PGPProvider, PGPProviderAsync,
        PGPProviderSync, SessionKeyAlgorithm, Signer as _, UnixTimestamp, Verifier as _,
    },
    rust::pgp::{
        RustArmorer, RustDecryptor, RustEncryptor, RustKeyGenerator, RustPGPMessage,
        RustPrivateKey, RustPublicKey, RustSigner, RustSigningContext, RustVerificationContext,
        RustVerifiedData,
    },
    CryptoClock, CryptoError, CryptoInfoError,
};

pub mod keys;
pub use keys::*;
pub mod encrypt;
pub use encrypt::*;
pub mod sign;
pub use sign::*;
pub mod verify;
pub use verify::*;
pub mod decrypt;
pub use decrypt::*;
pub mod armor;
pub use armor::*;

pub const VERSION: &str = "0.1.0";

pub(crate) const INIT_BUFFER_SIZE: usize = 1024;

impl From<RustUnixTime> for UnixTimestamp {
    fn from(value: RustUnixTime) -> Self {
        Self(value.unix_seconds())
    }
}

impl From<UnixTimestamp> for RustUnixTime {
    fn from(value: UnixTimestamp) -> Self {
        Self::new(value.0)
    }
}

impl From<RustCheckUnixTime> for UnixTimestamp {
    fn from(value: RustCheckUnixTime) -> Self {
        Self(value.at().unwrap_or_default().unix_seconds())
    }
}

impl From<UnixTimestamp> for RustCheckUnixTime {
    fn from(value: UnixTimestamp) -> Self {
        if value.is_zero() {
            Self::disable()
        } else {
            Self::enable(value.into())
        }
    }
}

impl From<DataEncoding> for RustDataEncoding {
    fn from(value: DataEncoding) -> Self {
        match value {
            DataEncoding::Bytes => RustDataEncoding::Unarmored,
            DataEncoding::Armor => RustDataEncoding::Armored,
            DataEncoding::Auto => RustDataEncoding::Auto,
        }
    }
}

pub struct RustPGPProvider {
    pub clock: &'static CryptoClock,
    pub profile: Profile,
}

impl RustPGPProvider {
    pub fn new(clock: &'static CryptoClock) -> Self {
        Self {
            clock,
            profile: DEFAULT_PROFILE.clone(),
        }
    }
}

impl PGPProvider for RustPGPProvider {
    type SessionKey = RustSessionKey;
    type PrivateKey = RustPrivateKey;
    type PublicKey = RustPublicKey;
    type SigningContext = RustSigningContext;
    type VerificationContext = RustVerificationContext;
    type PGPMessage = RustPGPMessage;
    type VerifiedData = RustVerifiedData;

    fn provider_version(&self) -> String {
        format!("proton-rpgp {VERSION}")
    }

    fn new_signing_context(&self, value: String, is_critical: bool) -> Self::SigningContext {
        RustSigningContext::new(value, is_critical)
    }

    fn new_verification_context(
        &self,
        value: String,
        is_required: bool,
        required_after_unix: UnixTimestamp,
    ) -> Self::VerificationContext {
        RustVerificationContext::new(value, is_required, required_after_unix)
    }
}

impl PGPProviderSync for RustPGPProvider {
    type Encryptor<'a> = RustEncryptor<'a>;
    type Decryptor<'a> = RustDecryptor<'a>;
    type Signer<'a> = RustSigner<'a>;
    type Verifier<'a> = RustVerifier<'a>;
    type Armorer = RustArmorer;
    type KeyGenerator = RustKeyGenerator;

    fn session_key_generate(
        &self,
        algorithm: SessionKeyAlgorithm,
    ) -> crate::Result<Self::SessionKey> {
        Ok(RustSessionKey::generate_for_seipdv1(
            algorithm.try_into()?,
            &self.profile,
        ))
    }

    fn session_key_import(
        &self,
        data: impl AsRef<[u8]>,
        algorithm: SessionKeyAlgorithm,
    ) -> crate::Result<Self::SessionKey> {
        Ok(match algorithm {
            SessionKeyAlgorithm::Aes128 => {
                RustSessionKey::new(data.as_ref(), SymmetricKeyAlgorithm::AES128)
            }
            SessionKeyAlgorithm::Aes256 => {
                RustSessionKey::new(data.as_ref(), SymmetricKeyAlgorithm::AES256)
            }
            SessionKeyAlgorithm::Unknown => RustSessionKey::new_for_seipdv2(data.as_ref()),
        })
    }

    fn session_key_export(
        &self,
        session_key: &Self::SessionKey,
    ) -> crate::Result<(impl AsRef<[u8]>, SessionKeyAlgorithm)> {
        let data = session_key.export_bytes();
        let algorithm = session_key.algorithm();
        Ok((data, algorithm.into()))
    }

    fn public_key_import(
        &self,
        public_key: impl AsRef<[u8]>,
        encoding: DataEncoding,
    ) -> crate::Result<Self::PublicKey> {
        RustPublicKey::import(public_key, encoding)
    }

    fn public_key_export(
        &self,
        public_key: &Self::PublicKey,
        encoding: DataEncoding,
    ) -> crate::Result<impl AsRef<[u8]>> {
        public_key.export(encoding)
    }

    fn private_key_import(
        &self,
        private_key: impl AsRef<[u8]>,
        passphrase: impl AsRef<[u8]>,
        encoding: DataEncoding,
    ) -> crate::Result<Self::PrivateKey> {
        RustPrivateKey::import(private_key, passphrase, encoding)
    }

    fn private_key_export(
        &self,
        private_key: &Self::PrivateKey,
        passphrase: impl AsRef<[u8]>,
        encoding: DataEncoding,
    ) -> crate::Result<impl AsRef<[u8]>> {
        private_key.export(passphrase, encoding, &self.profile)
    }

    fn private_key_import_unlocked(
        &self,
        private_key: impl AsRef<[u8]>,
        encoding: DataEncoding,
    ) -> crate::Result<Self::PrivateKey> {
        RustPrivateKey::import_unlocked(private_key, encoding)
    }

    fn private_key_export_unlocked(
        &self,
        private_key: &Self::PrivateKey,
        encoding: DataEncoding,
    ) -> crate::Result<impl AsRef<[u8]>> {
        private_key.export_unlocked(encoding)
    }

    fn private_key_to_public_key(
        &self,
        private_key: &Self::PrivateKey,
    ) -> crate::Result<Self::PublicKey> {
        private_key.to_public_key()
    }

    fn pgp_message_import(
        &self,
        pgp_message: impl AsRef<[u8]>,
        encoding: DataEncoding,
    ) -> crate::Result<Self::PGPMessage> {
        match encoding {
            DataEncoding::Bytes => RustPGPMessage::from_unarmored(pgp_message.as_ref()),
            DataEncoding::Armor | DataEncoding::Auto => {
                RustPGPMessage::from_armored(pgp_message.as_ref())
            }
        }
    }

    fn new_encryptor<'a>(&self) -> Self::Encryptor<'a> {
        RustEncryptor::new(self.profile.clone()).at_signing_time(self.clock.unix_time())
    }

    fn new_decryptor<'a>(&self) -> Self::Decryptor<'a> {
        RustDecryptor::new(self.profile.clone()).at_verification_time(self.clock.unix_time())
    }

    fn new_signer<'a>(&self) -> Self::Signer<'a> {
        RustSigner::new(self.profile.clone()).at_signing_time(self.clock.unix_time())
    }

    fn new_verifier<'a>(&self) -> Self::Verifier<'a> {
        RustVerifier::new(self.profile.clone()).at_verification_time(self.clock.unix_time())
    }

    fn new_key_generator(&self) -> Self::KeyGenerator {
        RustKeyGenerator::new().with_generation_time(self.clock.unix_time())
    }

    fn armorer(&self) -> Self::Armorer {
        RustArmorer::default()
    }
}

impl PGPProviderAsync for RustPGPProvider {
    type Encryptor<'a> = RustEncryptor<'a>;
    type Decryptor<'a> = RustDecryptor<'a>;
    type Signer<'a> = RustSigner<'a>;
    type Verifier<'a> = RustVerifier<'a>;
    type KeyGenerator = RustKeyGenerator;

    async fn session_key_generate_async(
        &self,
        algorithm: SessionKeyAlgorithm,
    ) -> crate::Result<Self::SessionKey> {
        self.session_key_generate(algorithm)
    }

    async fn session_key_import_async(
        &self,
        data: impl AsRef<[u8]>,
        algorithm: SessionKeyAlgorithm,
    ) -> crate::Result<Self::SessionKey> {
        self.session_key_import(data, algorithm)
    }

    async fn session_key_export_async(
        &self,
        session_key: &Self::SessionKey,
    ) -> crate::Result<(impl AsRef<[u8]>, SessionKeyAlgorithm)> {
        self.session_key_export(session_key)
    }

    async fn public_key_import_async(
        &self,
        public_key: impl AsRef<[u8]>,
        encoding: DataEncoding,
    ) -> crate::Result<Self::PublicKey> {
        self.public_key_import(public_key, encoding)
    }

    async fn public_key_export_async(
        &self,
        public_key: &Self::PublicKey,
        encoding: DataEncoding,
    ) -> crate::Result<impl AsRef<[u8]>> {
        self.public_key_export(public_key, encoding)
    }

    async fn private_key_import_async(
        &self,
        private_key: impl AsRef<[u8]>,
        passphrase: impl AsRef<[u8]>,
        encoding: DataEncoding,
    ) -> crate::Result<Self::PrivateKey> {
        self.private_key_import(private_key, passphrase, encoding)
    }

    async fn private_key_export_async(
        &self,
        private_key: &Self::PrivateKey,
        passphrase: impl AsRef<[u8]>,
        encoding: DataEncoding,
    ) -> crate::Result<impl AsRef<[u8]>> {
        self.private_key_export(private_key, passphrase, encoding)
    }

    async fn private_key_import_unlocked_async(
        &self,
        private_key: impl AsRef<[u8]>,
        encoding: DataEncoding,
    ) -> crate::Result<Self::PrivateKey> {
        self.private_key_import_unlocked(private_key, encoding)
    }

    async fn private_key_export_unlocked_async(
        &self,
        private_key: &Self::PrivateKey,
        encoding: DataEncoding,
    ) -> crate::Result<impl AsRef<[u8]>> {
        self.private_key_export_unlocked(private_key, encoding)
    }

    async fn private_key_to_public_key_async(
        &self,
        private_key: &Self::PrivateKey,
    ) -> crate::Result<Self::PublicKey> {
        self.private_key_to_public_key(private_key)
    }

    async fn pgp_message_import_async(
        &self,
        pgp_message: impl AsRef<[u8]>,
        encoding: DataEncoding,
    ) -> crate::Result<Self::PGPMessage> {
        self.pgp_message_import(pgp_message, encoding)
    }

    fn new_encryptor_async<'a>(&self) -> Self::Encryptor<'a> {
        self.new_encryptor()
    }

    fn new_decryptor_async<'a>(&self) -> Self::Decryptor<'a> {
        self.new_decryptor()
    }

    fn new_signer_async<'a>(&self) -> Self::Signer<'a> {
        self.new_signer()
    }

    fn new_verifier_async<'a>(&self) -> Self::Verifier<'a> {
        self.new_verifier()
    }

    fn new_key_generator_async(&self) -> Self::KeyGenerator {
        self.new_key_generator()
    }
}

impl From<&'static str> for CryptoError {
    fn from(value: &'static str) -> Self {
        Self(Arc::new(CryptoInfoError::new(value)))
    }
}

impl From<String> for CryptoError {
    fn from(value: String) -> Self {
        Self(Arc::new(CryptoInfoError(value)))
    }
}

impl From<proton_rpgp::Error> for CryptoError {
    fn from(value: proton_rpgp::Error) -> Self {
        Self(Arc::new(value))
    }
}
