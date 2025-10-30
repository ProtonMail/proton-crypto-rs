use std::{
    io::{self},
    marker::PhantomData,
};

use proton_rpgp::Profile;

use crate::{
    crypto::{
        AsPublicKeyRef, DataEncoding, VerificationContext, VerificationError,
        VerificationInformation, VerificationResult, VerifiedData, VerifiedDataReader, Verifier,
        VerifierAsync, VerifierSync,
    },
    rust::pgp::RustPublicKey,
    CryptoInfoError, UnixTimestamp,
};

pub struct RustVerifiedData(pub(super) proton_rpgp::VerifiedData);

impl AsRef<[u8]> for RustVerifiedData {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl VerifiedData for RustVerifiedData {
    fn as_bytes(&self) -> &[u8] {
        &self.0.data
    }

    fn is_verified(&self) -> bool {
        true
    }

    fn verification_result(&self) -> VerificationResult {
        transform_verification_result(self.0.verification_result.clone())
    }

    fn into_vec(self) -> Vec<u8> {
        self.0.data
    }

    fn signatures(&self) -> crate::Result<Vec<u8>> {
        Err(CryptoInfoError::new("not implemented").into())
    }
}

impl From<proton_rpgp::VerifiedData> for RustVerifiedData {
    fn from(value: proton_rpgp::VerifiedData) -> Self {
        Self(value)
    }
}

impl From<proton_rpgp::VerificationInformation> for VerificationInformation {
    fn from(value: proton_rpgp::VerificationInformation) -> Self {
        Self {
            key_id: value.key_id.into(),
            signature_creation_time: value.signature_creation_time.into(),
            signature: value.signature_bytes().unwrap_or_default(),
        }
    }
}

impl From<Box<proton_rpgp::VerificationInformation>> for VerificationInformation {
    fn from(value: Box<proton_rpgp::VerificationInformation>) -> Self {
        Self {
            key_id: value.key_id.into(),
            signature_creation_time: value.signature_creation_time.into(),
            signature: value.signature_bytes().unwrap_or_default(),
        }
    }
}

impl From<proton_rpgp::VerificationError> for VerificationError {
    fn from(value: proton_rpgp::VerificationError) -> Self {
        match value {
            proton_rpgp::VerificationError::NotSigned => {
                VerificationError::NotSigned("No signature found".into())
            }
            proton_rpgp::VerificationError::NoVerifier(_, error) => {
                VerificationError::NoVerifier(error.into())
            }
            proton_rpgp::VerificationError::Failed(verification_information, error) => {
                VerificationError::Failed(verification_information.into(), error.into())
            }
            proton_rpgp::VerificationError::BadContext(verification_information, error) => {
                VerificationError::BadContext(verification_information.into(), error.into())
            }
            proton_rpgp::VerificationError::RuntimeError(error) => {
                VerificationError::RuntimeError(error.into())
            }
        }
    }
}

fn transform_verification_result(result: proton_rpgp::VerificationResult) -> VerificationResult {
    match result {
        Ok(verification_information) => Ok(verification_information.into()),
        Err(error) => Err(error.into()),
    }
}

/// Currently mocks the streaming API by buffering data in memory.
pub struct RustVerifiedDataReader<'a, T: io::Read + 'a> {
    pub(super) reader: proton_rpgp::VerifyingReader<'a>,
    pub(super) source: PhantomData<T>,
}

impl<'a, T: io::Read + 'a> RustVerifiedDataReader<'a, T> {
    pub fn new(reader: proton_rpgp::VerifyingReader<'a>) -> Self {
        Self {
            reader,
            source: PhantomData,
        }
    }
}

impl<'a, T: io::Read + 'a> io::Read for RustVerifiedDataReader<'a, T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.reader.read(buf)
    }
}

impl<'a, T: io::Read + 'a> VerifiedDataReader<'a, T> for RustVerifiedDataReader<'a, T> {
    fn verification_result(self) -> VerificationResult {
        transform_verification_result(self.reader.verification_result())
    }
}

#[derive(Debug, Clone)]
pub struct RustVerificationContext {
    pub(crate) inner: proton_rpgp::VerificationContext,
}

impl RustVerificationContext {
    pub fn new(value: String, is_required: bool, required_after: UnixTimestamp) -> Self {
        Self {
            inner: proton_rpgp::VerificationContext {
                value,
                is_required,
                required_after: (!required_after.is_zero()).then_some(required_after.into()),
            },
        }
    }
}

impl VerificationContext for RustVerificationContext {
    fn value(&self) -> impl AsRef<str> {
        &self.inner.value
    }

    fn is_required(&self) -> bool {
        self.inner.is_required
    }

    fn is_required_after(&self) -> UnixTimestamp {
        self.inner.required_after.unwrap_or_default().into()
    }
}

impl From<proton_rpgp::VerificationContext> for RustVerificationContext {
    fn from(value: proton_rpgp::VerificationContext) -> Self {
        Self { inner: value }
    }
}

impl From<RustVerificationContext> for proton_rpgp::VerificationContext {
    fn from(value: RustVerificationContext) -> Self {
        value.inner
    }
}

#[derive(Debug)]
pub struct RustVerifier<'a> {
    pub(super) inner: proton_rpgp::Verifier<'a>,
}

impl RustVerifier<'_> {
    pub fn new(profile: Profile) -> Self {
        Self {
            inner: proton_rpgp::Verifier::new(profile),
        }
    }
}

impl<'a> Verifier<'a> for RustVerifier<'a> {
    type PublicKey = RustPublicKey;
    type VerifiedData = RustVerifiedData;
    type VerificationContext = RustVerificationContext;

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

    fn with_utf8_out(mut self) -> Self {
        self.inner = self.inner.output_utf8();
        self
    }
}

impl<'a> VerifierSync<'a> for RustVerifier<'a> {
    fn verify_detached(
        self,
        data: impl AsRef<[u8]>,
        signature: impl AsRef<[u8]>,
        signature_encoding: DataEncoding,
    ) -> VerificationResult {
        let result = self
            .inner
            .verify_detached(data, signature, signature_encoding.into());
        transform_verification_result(result)
    }

    fn verify_inline(
        self,
        message: impl AsRef<[u8]>,
        message_encoding: DataEncoding,
    ) -> crate::Result<Self::VerifiedData> {
        self.inner
            .verify(message, message_encoding.into())
            .map(Into::into)
            .map_err(Into::into)
    }

    fn verify_cleartext(self, message: impl AsRef<[u8]>) -> crate::Result<Self::VerifiedData> {
        self.inner
            .verify_cleartext(message)
            .map(Into::into)
            .map_err(Into::into)
    }

    fn verify_detached_stream<T: io::Read + 'a>(
        self,
        data: T,
        signature: impl AsRef<[u8]>,
        signature_encoding: DataEncoding,
    ) -> VerificationResult {
        let mut reader = self
            .inner
            .verify_detached_stream(data, signature, signature_encoding.into())
            .map_err(|err| VerificationError::RuntimeError(err.into()))?;
        reader
            .discard_all_data()
            .map_err(|err| VerificationError::RuntimeError(err.into()))?;
        transform_verification_result(reader.verification_result())
    }
}

impl<'a> VerifierAsync<'a> for RustVerifier<'a> {
    async fn verify_detached_async(
        self,
        data: impl AsRef<[u8]>,
        signature: impl AsRef<[u8]>,
        data_encoding: DataEncoding,
    ) -> VerificationResult {
        let result = self
            .inner
            .verify_detached(data, signature, data_encoding.into());
        transform_verification_result(result)
    }

    async fn verify_inline_async(
        self,
        message: impl AsRef<[u8]>,
        data_encoding: DataEncoding,
    ) -> crate::Result<Self::VerifiedData> {
        self.inner
            .verify(message, data_encoding.into())
            .map(Into::into)
            .map_err(Into::into)
    }

    async fn verify_cleartext_async(
        self,
        message: impl AsRef<[u8]>,
    ) -> crate::Result<Self::VerifiedData> {
        self.inner
            .verify_cleartext(message)
            .map(Into::into)
            .map_err(Into::into)
    }
}
