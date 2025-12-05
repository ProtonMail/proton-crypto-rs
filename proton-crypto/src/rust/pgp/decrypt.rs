use std::{
    borrow::Cow,
    io::{self},
};

use proton_rpgp::{
    DataEncoding as RustDataEncoding, ExternalDetachedSignature, Profile,
    SessionKey as RustSessionKey,
};

use crate::{
    crypto::{
        AsPublicKeyRef, DataEncoding, Decryptor, DecryptorAsync, DecryptorSync,
        DetachedSignatureVariant, UnixTimestamp,
    },
    rust::pgp::{
        RustPrivateKey, RustPublicKey, RustVerificationContext, RustVerifiedData,
        RustVerifiedDataReader,
    },
};

#[derive(Debug)]
pub struct RustDecryptor<'a> {
    pub(super) inner: proton_rpgp::Decryptor<'a>,
}

impl RustDecryptor<'_> {
    pub fn new(profile: Profile) -> Self {
        // Enabled forwarding decryption by default to be compatible with the Go API.
        let inner = proton_rpgp::Decryptor::new(profile).allow_forwarding_decryption(true);
        Self { inner }
    }
}

impl<'a> Decryptor<'a> for RustDecryptor<'a> {
    type SessionKey = RustSessionKey;
    type PrivateKey = RustPrivateKey;
    type PublicKey = RustPublicKey;
    type VerifiedData = RustVerifiedData;
    type VerifiedDataReader<'b, T: io::Read + 'b> = RustVerifiedDataReader<'b, T>;
    type VerificationContext = RustVerificationContext;

    fn with_decryption_key(mut self, decryption_key: &'a Self::PrivateKey) -> Self {
        self.inner = self.inner.with_decryption_key(&decryption_key.0);
        self
    }

    fn with_decryption_keys(mut self, decryption_keys: &'a [Self::PrivateKey]) -> Self {
        self.inner = self
            .inner
            .with_decryption_keys(decryption_keys.iter().map(|k| k.0.as_ref()));
        self
    }

    fn with_decryption_key_refs(
        mut self,
        decryption_keys: &'a [impl AsRef<Self::PrivateKey>],
    ) -> Self {
        self.inner = self
            .inner
            .with_decryption_keys(decryption_keys.iter().map(|k| k.as_ref().0.as_ref()));
        self
    }

    fn with_verification_key(mut self, verification_key: &'a Self::PublicKey) -> Self {
        self.inner = self.inner.with_verification_key(&verification_key.0);
        self
    }

    fn with_verification_keys(mut self, verification_keys: &'a [Self::PublicKey]) -> Self {
        self.inner = self
            .inner
            .with_verification_keys(verification_keys.iter().map(|k| k.0.as_ref()));
        self
    }

    fn with_verification_key_refs(
        mut self,
        verification_keys: &'a [impl AsPublicKeyRef<Self::PublicKey>],
    ) -> Self {
        self.inner = self.inner.with_verification_keys(
            verification_keys
                .iter()
                .map(|k| k.as_public_key().0.as_ref()),
        );
        self
    }

    fn with_session_key_ref(mut self, session_key: &'a Self::SessionKey) -> Self {
        self.inner = self.inner.with_session_key(session_key);
        self
    }

    fn with_session_key(mut self, session_key: Self::SessionKey) -> Self {
        self.inner = self.inner.with_session_key(session_key);
        self
    }

    fn with_passphrase(mut self, passphrase: &'a str) -> Self {
        self.inner = self.inner.with_passphrase(passphrase);
        self
    }

    fn with_verification_context(
        mut self,
        verification_context: &'a Self::VerificationContext,
    ) -> Self {
        self.inner = self
            .inner
            .with_verification_context(&verification_context.inner);
        self
    }

    fn at_verification_time(mut self, unix_timestamp: UnixTimestamp) -> Self {
        self.inner = self.inner.at_date(unix_timestamp.into());
        self
    }

    fn with_ut8_sanitization(mut self) -> Self {
        self.inner = self.inner.output_utf8();
        self
    }

    fn with_detached_signature_ref(
        mut self,
        detached_signature: &'a [u8],
        variant: DetachedSignatureVariant,
        armored: bool,
    ) -> Self {
        let detached_signature =
            new_external_detached_signature(detached_signature, variant, armored);
        self.inner = self
            .inner
            .with_external_detached_signature(detached_signature);
        self
    }

    fn with_detached_signature(
        mut self,
        detached_signature: Vec<u8>,
        variant: DetachedSignatureVariant,
        armored: bool,
    ) -> Self {
        let detached_signature =
            new_external_detached_signature(detached_signature, variant, armored);
        self.inner = self
            .inner
            .with_external_detached_signature(detached_signature);
        self
    }
}

impl<'a> DecryptorSync<'a> for RustDecryptor<'a> {
    fn decrypt(
        self,
        data: impl AsRef<[u8]>,
        data_encoding: DataEncoding,
    ) -> crate::Result<Self::VerifiedData> {
        self.inner
            .decrypt(data, data_encoding.into())
            .map(Into::into)
            .map_err(Into::into)
    }

    fn decrypt_session_key(self, key_packets: impl AsRef<[u8]>) -> crate::Result<Self::SessionKey> {
        self.inner
            .decrypt_session_key(key_packets)
            .map_err(Into::into)
    }

    fn decrypt_stream<T: io::Read + Send + 'a>(
        self,
        data: T,
        data_encoding: DataEncoding,
    ) -> crate::Result<Self::VerifiedDataReader<'a, T>> {
        self.inner
            .decrypt_stream(data, data_encoding.into())
            .map(RustVerifiedDataReader::new)
            .map_err(Into::into)
    }
}

impl<'a> DecryptorAsync<'a> for RustDecryptor<'a> {
    async fn decrypt_async(
        self,
        data: impl AsRef<[u8]>,
        data_encoding: DataEncoding,
    ) -> crate::Result<Self::VerifiedData> {
        self.inner
            .decrypt(data, data_encoding.into())
            .map(Into::into)
            .map_err(Into::into)
    }

    async fn decrypt_session_key_async(
        self,
        key_packets: impl AsRef<[u8]>,
    ) -> crate::Result<Self::SessionKey> {
        self.inner
            .decrypt_session_key(key_packets)
            .map_err(Into::into)
    }
}

fn new_external_detached_signature<'b>(
    detached_signature: impl Into<Cow<'b, [u8]>>,
    variant: DetachedSignatureVariant,
    armored: bool,
) -> ExternalDetachedSignature<'b> {
    match (variant, armored) {
        (DetachedSignatureVariant::Encrypted, true) => {
            ExternalDetachedSignature::new_encrypted(detached_signature, RustDataEncoding::Armored)
        }
        (DetachedSignatureVariant::Encrypted, false) => ExternalDetachedSignature::new_encrypted(
            detached_signature,
            RustDataEncoding::Unarmored,
        ),
        (DetachedSignatureVariant::Plaintext, true) => ExternalDetachedSignature::new_unencrypted(
            detached_signature,
            RustDataEncoding::Armored,
        ),
        (DetachedSignatureVariant::Plaintext, false) => ExternalDetachedSignature::new_unencrypted(
            detached_signature,
            RustDataEncoding::Unarmored,
        ),
    }
}
