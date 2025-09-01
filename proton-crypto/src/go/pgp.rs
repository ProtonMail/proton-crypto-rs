//! This module implements the [`PGPProvider`] with the
//! the `gopenpgp-sys` crate. The underlying `OpenPGP` library is
//! `GopenPGP` v3.
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

use crate::crypto::{
    DataEncoding, PGPProvider, PGPProviderAsync, PGPProviderSync, SessionKeyAlgorithm,
};
use crate::{CryptoClock, UnixTimestamp};
use std::sync::Arc;

pub const VERSION: &str = "0.3.1";

#[allow(clippy::module_name_repetitions)]
pub struct GoPGPProvider(pub &'static CryptoClock);

impl PGPProvider for GoPGPProvider {
    type SessionKey = GoSessionKey;
    type PrivateKey = GoPrivateKey;
    type PublicKey = GoPublicKey;
    type VerifiedData = GoVerifiedData;
    type VerificationContext = GoVerificationContext;
    type SigningContext = GoSigningContext;
    type PGPMessage = GoPGPMessage;

    fn provider_version(&self) -> String {
        format!("gopenpgp-sys {VERSION}")
    }

    fn new_signing_context(&self, value: String, is_critical: bool) -> Self::SigningContext {
        GoSigningContext(gopenpgp_sys::SigningContext::new(
            value.as_str(),
            is_critical,
        ))
    }

    fn new_verification_context(
        &self,
        value: String,
        is_required: bool,
        required_after_unix: UnixTimestamp,
    ) -> Self::VerificationContext {
        GoVerificationContext(gopenpgp_sys::VerificationContext::new(
            value.as_str(),
            is_required,
            required_after_unix.value(),
        ))
    }
}

impl PGPProviderSync for GoPGPProvider {
    type Encryptor<'a> = GoEncryptor<'a>;
    type Decryptor<'a> = GoDecryptor<'a>;
    type Signer<'a> = GoSigner<'a>;
    type Verifier<'a> = GoVerifier<'a>;
    type KeyGenerator = GoKeyGenerator;
    type Armorer = GoArmorer;

    fn session_key_generate(
        &self,
        algorithm: SessionKeyAlgorithm,
    ) -> crate::Result<Self::SessionKey> {
        generate_session_key(algorithm)
    }

    fn session_key_import(
        &self,
        data: impl AsRef<[u8]>,
        algorithm: SessionKeyAlgorithm,
    ) -> crate::Result<Self::SessionKey> {
        Ok(session_key_import(data, algorithm))
    }

    fn session_key_export(
        &self,
        session_key: &Self::SessionKey,
    ) -> crate::Result<(impl AsRef<[u8]>, SessionKeyAlgorithm)> {
        session_key_export(session_key)
    }

    fn public_key_import(
        &self,
        public_key: impl AsRef<[u8]>,
        encoding: DataEncoding,
    ) -> crate::Result<Self::PublicKey> {
        public_key_import(public_key, encoding)
    }

    fn public_key_export(
        &self,
        public_key: &Self::PublicKey,
        encoding: DataEncoding,
    ) -> crate::Result<impl AsRef<[u8]>> {
        public_key_export(public_key, encoding)
    }

    fn private_key_import(
        &self,
        private_key: impl AsRef<[u8]>,
        passphrase: impl AsRef<[u8]>,
        encoding: DataEncoding,
    ) -> crate::Result<Self::PrivateKey> {
        private_key_import(private_key, passphrase, encoding)
    }

    fn private_key_export(
        &self,
        private_key: &Self::PrivateKey,
        passphrase: impl AsRef<[u8]>,
        encoding: DataEncoding,
    ) -> crate::Result<impl AsRef<[u8]>> {
        private_key_export(private_key, passphrase, encoding)
    }

    fn private_key_import_unlocked(
        &self,
        private_key: impl AsRef<[u8]>,
        encoding: DataEncoding,
    ) -> crate::Result<Self::PrivateKey> {
        private_key_import_unlocked(private_key, encoding)
    }

    fn private_key_export_unlocked(
        &self,
        private_key: &Self::PrivateKey,
        encoding: DataEncoding,
    ) -> crate::Result<impl AsRef<[u8]>> {
        private_key_export_unlocked(private_key, encoding)
    }

    fn private_key_to_public_key(
        &self,
        private_key: &Self::PrivateKey,
    ) -> crate::Result<Self::PublicKey> {
        private_key_to_public_key(private_key)
    }

    fn pgp_message_import(
        &self,
        pgp_message: impl AsRef<[u8]>,
        encoding: DataEncoding,
    ) -> crate::Result<Self::PGPMessage> {
        pgp_message_import(pgp_message, encoding)
    }

    fn new_encryptor<'a>(&self) -> Self::Encryptor<'a> {
        GoEncryptor(gopenpgp_sys::Encryptor::new().at_signing_time(self.0.unix_time().value()))
    }

    fn new_decryptor<'a>(&self) -> Self::Decryptor<'a> {
        GoDecryptor(gopenpgp_sys::Decryptor::new().at_verification_time(self.0.unix_time().value()))
    }

    fn new_signer<'a>(&self) -> Self::Signer<'a> {
        GoSigner(gopenpgp_sys::Signer::new().at_signing_time(self.0.unix_time().value()))
    }

    fn new_verifier<'a>(&self) -> Self::Verifier<'a> {
        GoVerifier(gopenpgp_sys::Verifier::new().at_verification_time(self.0.unix_time().value()))
    }

    fn armorer(&self) -> Self::Armorer {
        GoArmorer {}
    }

    fn new_key_generator(&self) -> Self::KeyGenerator {
        GoKeyGenerator(
            gopenpgp_sys::KeyGenerator::new().with_generation_time(self.0.unix_time().value()),
        )
    }
}

impl PGPProviderAsync for GoPGPProvider {
    type Encryptor<'a> = GoEncryptor<'a>;
    type Decryptor<'a> = GoDecryptor<'a>;
    type Signer<'a> = GoSigner<'a>;
    type Verifier<'a> = GoVerifier<'a>;
    type KeyGenerator = GoKeyGenerator;

    async fn session_key_generate_async(
        &self,
        algorithm: SessionKeyAlgorithm,
    ) -> crate::Result<GoSessionKey> {
        generate_session_key(algorithm)
    }

    async fn session_key_import_async(
        &self,
        data: impl AsRef<[u8]>,
        algorithm: SessionKeyAlgorithm,
    ) -> crate::Result<Self::SessionKey> {
        Ok(session_key_import(data, algorithm))
    }

    async fn session_key_export_async(
        &self,
        session_key: &Self::SessionKey,
    ) -> crate::Result<(impl AsRef<[u8]>, SessionKeyAlgorithm)> {
        session_key_export(session_key)
    }

    async fn public_key_import_async(
        &self,
        public_key: impl AsRef<[u8]>,
        encoding: DataEncoding,
    ) -> crate::Result<Self::PublicKey> {
        public_key_import(public_key, encoding)
    }

    async fn public_key_export_async(
        &self,
        public_key: &Self::PublicKey,
        encoding: DataEncoding,
    ) -> crate::Result<impl AsRef<[u8]>> {
        public_key_export(public_key, encoding)
    }

    async fn private_key_import_async(
        &self,
        private_key: impl AsRef<[u8]>,
        passphrase: impl AsRef<[u8]>,
        encoding: DataEncoding,
    ) -> crate::Result<GoPrivateKey> {
        private_key_import(private_key, passphrase, encoding)
    }

    async fn private_key_export_async(
        &self,
        private_key: &Self::PrivateKey,
        passphrase: impl AsRef<[u8]>,
        encoding: DataEncoding,
    ) -> crate::Result<impl AsRef<[u8]>> {
        private_key_export(private_key, passphrase, encoding)
    }

    async fn private_key_import_unlocked_async(
        &self,
        private_key: impl AsRef<[u8]>,
        encoding: DataEncoding,
    ) -> crate::Result<Self::PrivateKey> {
        private_key_import_unlocked(private_key, encoding)
    }

    async fn private_key_export_unlocked_async(
        &self,
        private_key: &Self::PrivateKey,
        encoding: DataEncoding,
    ) -> crate::Result<impl AsRef<[u8]>> {
        private_key_export_unlocked(private_key, encoding)
    }

    async fn private_key_to_public_key_async(
        &self,
        private_key: &Self::PrivateKey,
    ) -> crate::Result<Self::PublicKey> {
        private_key_to_public_key(private_key)
    }

    async fn pgp_message_import_async(
        &self,
        pgp_message: impl AsRef<[u8]>,
        encoding: DataEncoding,
    ) -> crate::Result<Self::PGPMessage> {
        pgp_message_import(pgp_message, encoding)
    }

    fn new_encryptor_async<'a>(&self) -> Self::Encryptor<'a> {
        GoEncryptor(gopenpgp_sys::Encryptor::new().at_signing_time(self.0.unix_time().value()))
    }

    fn new_decryptor_async<'a>(&self) -> Self::Decryptor<'a> {
        GoDecryptor(gopenpgp_sys::Decryptor::new().at_verification_time(self.0.unix_time().value()))
    }

    fn new_signer_async<'a>(&self) -> Self::Signer<'a> {
        GoSigner(gopenpgp_sys::Signer::new().at_signing_time(self.0.unix_time().value()))
    }

    fn new_verifier_async<'a>(&self) -> Self::Verifier<'a> {
        GoVerifier(gopenpgp_sys::Verifier::new().at_verification_time(self.0.unix_time().value()))
    }

    fn new_key_generator_async(&self) -> Self::KeyGenerator {
        GoKeyGenerator(
            gopenpgp_sys::KeyGenerator::new().with_generation_time(self.0.unix_time().value()),
        )
    }
}

impl From<gopenpgp_sys::PGPError> for crate::CryptoError {
    fn from(value: gopenpgp_sys::PGPError) -> Self {
        Self(Arc::new(value))
    }
}

impl From<DataEncoding> for gopenpgp_sys::DataEncoding {
    fn from(val: DataEncoding) -> Self {
        match val {
            DataEncoding::Armor => gopenpgp_sys::DataEncoding::Armor,
            DataEncoding::Bytes => gopenpgp_sys::DataEncoding::Bytes,
            DataEncoding::Auto => gopenpgp_sys::DataEncoding::Auto,
        }
    }
}
