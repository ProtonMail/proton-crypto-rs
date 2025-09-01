use std::io;

use super::GoPublicKey;
use crate::crypto::{
    AsPublicKeyRef, DataEncoding, OpenPGPKeyID, VerificationContext, VerificationError,
    VerificationInformation, VerificationResult, VerifiedData, VerifiedDataReader, Verifier,
    VerifierAsync, VerifierSync,
};
use crate::{CryptoInfoError, UnixTimestamp};

#[allow(clippy::module_name_repetitions)]
pub struct GoVerifiedData(pub(super) gopenpgp_sys::VerifiedData);

impl AsRef<[u8]> for GoVerifiedData {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl VerifiedData for GoVerifiedData {
    fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    fn is_verified(&self) -> bool {
        self.0.verification_result().is_some()
    }

    fn verification_result(&self) -> VerificationResult {
        go_verification_result_to_result(self.0.verification_result())
    }

    fn into_vec(self) -> Vec<u8> {
        self.0.into_vec()
    }

    fn signatures(&self) -> crate::Result<Vec<u8>> {
        let result = self.0.verification_result();
        let Some(verification_result) = result else {
            return Ok(Vec::new());
        };
        verification_result
            .signatures()
            .map(|signatures| signatures.to_vec())
            .map_err(Into::into)
    }
}

pub struct GoVerifiedDataReader<'a, T>(pub(super) gopenpgp_sys::VerifiedDataReader<'a, T>);

impl<T: io::Read> io::Read for GoVerifiedDataReader<'_, T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl<'a, T: io::Read + 'a> VerifiedDataReader<'a, T> for GoVerifiedDataReader<'a, T> {
    fn verification_result(self) -> VerificationResult {
        let verification_result = self
            .0
            .verification_result()
            .map_err(|err| VerificationError::RuntimeError(err.into()))?;
        go_verification_result_to_result(Some(&verification_result))
    }
}

#[derive(Debug, Clone)]
pub struct GoVerificationContext(pub(super) gopenpgp_sys::VerificationContext);

impl VerificationContext for GoVerificationContext {
    fn value(&self) -> impl AsRef<str> {
        self.0.get_value()
    }
    fn is_required(&self) -> bool {
        self.0.is_required()
    }
    fn is_required_after(&self) -> UnixTimestamp {
        UnixTimestamp::new(self.0.is_required_after())
    }
}

impl AsRef<gopenpgp_sys::VerificationContext> for GoVerificationContext {
    fn as_ref(&self) -> &gopenpgp_sys::VerificationContext {
        &self.0
    }
}

pub struct GoVerifier<'a>(pub(super) gopenpgp_sys::Verifier<'a>);

impl<'a> Verifier<'a> for GoVerifier<'a> {
    type PublicKey = GoPublicKey;
    type VerifiedData = GoVerifiedData;
    type VerificationContext = GoVerificationContext;

    fn with_verification_key(self, verification_key: &'a Self::PublicKey) -> Self {
        GoVerifier(self.0.with_verification_key(verification_key))
    }

    fn with_verification_keys(self, verification_keys: &'a [Self::PublicKey]) -> Self {
        GoVerifier(self.0.with_verification_keys(verification_keys))
    }

    fn with_verification_key_refs(
        self,
        verification_keys: &'a [impl AsPublicKeyRef<Self::PublicKey>],
    ) -> Self {
        let mut decryptor = self.0;
        for verification_key in verification_keys {
            decryptor = decryptor.with_verification_key(verification_key.as_public_key());
        }
        GoVerifier(decryptor)
    }

    fn with_verification_context(
        self,
        verification_context: &'a Self::VerificationContext,
    ) -> Self {
        GoVerifier(
            self.0
                .with_verification_context(verification_context.as_ref()),
        )
    }

    fn at_verification_time(self, unix_timestamp: UnixTimestamp) -> Self {
        GoVerifier(self.0.at_verification_time(unix_timestamp.value()))
    }

    fn with_utf8_out(self) -> Self {
        GoVerifier(self.0.with_utf8_out())
    }
}

impl<'a> VerifierSync<'a> for GoVerifier<'a> {
    fn verify_detached(
        self,
        data: impl AsRef<[u8]>,
        signature: impl AsRef<[u8]>,
        data_encoding: DataEncoding,
    ) -> VerificationResult {
        verify_detached(self.0, data, signature, data_encoding)
    }

    fn verify_inline(
        self,
        message: impl AsRef<[u8]>,
        data_encoding: DataEncoding,
    ) -> crate::Result<Self::VerifiedData> {
        verify_inline(self.0, message, data_encoding)
    }

    fn verify_cleartext(self, message: impl AsRef<[u8]>) -> crate::Result<Self::VerifiedData> {
        verify_cleartext(self.0, message)
    }

    fn verify_detached_stream<T: io::Read + 'a>(
        self,
        data: T,
        signature: impl AsRef<[u8]>,
        signature_encoding: DataEncoding,
    ) -> VerificationResult {
        verify_detached_stream(self.0, data, signature, signature_encoding)
    }
}

impl<'a> VerifierAsync<'a> for GoVerifier<'a> {
    async fn verify_detached_async(
        self,
        data: impl AsRef<[u8]>,
        signature: impl AsRef<[u8]>,
        data_encoding: DataEncoding,
    ) -> VerificationResult {
        verify_detached(self.0, data, signature, data_encoding)
    }

    async fn verify_inline_async(
        self,
        message: impl AsRef<[u8]>,
        data_encoding: DataEncoding,
    ) -> crate::Result<Self::VerifiedData> {
        verify_inline(self.0, message, data_encoding)
    }

    async fn verify_cleartext_async(
        self,
        message: impl AsRef<[u8]>,
    ) -> crate::Result<Self::VerifiedData> {
        verify_cleartext(self.0, message)
    }
}

/// Verifies a detached signature against the provided data.
fn verify_detached(
    verifier: gopenpgp_sys::Verifier,
    data: impl AsRef<[u8]>,
    signature: impl AsRef<[u8]>,
    data_encoding: DataEncoding,
) -> VerificationResult {
    let verification_result = verifier
        .verify_detached(data.as_ref(), signature.as_ref(), data_encoding.into())
        .map_err(|err| VerificationError::RuntimeError(err.into()))?;
    go_verification_result_to_result(Some(&verification_result))
}

/// Verifies an inline signature within the provided message.
fn verify_inline(
    verifier: gopenpgp_sys::Verifier,
    message: impl AsRef<[u8]>,
    data_encoding: DataEncoding,
) -> crate::Result<GoVerifiedData> {
    verifier
        .verify_inline(message.as_ref(), data_encoding.into())
        .map(GoVerifiedData)
        .map_err::<crate::Error, _>(Into::into)
}

/// Verifies a cleartext-signed message.
fn verify_cleartext(
    verifier: gopenpgp_sys::Verifier,
    message: impl AsRef<[u8]>,
) -> crate::Result<GoVerifiedData> {
    verifier
        .verify_cleartext(message.as_ref())
        .map(GoVerifiedData)
        .map_err::<crate::Error, _>(Into::into)
}

/// Verifies a detached signature against a stream of data.
fn verify_detached_stream<'a, T: io::Read + 'a>(
    verifier: gopenpgp_sys::Verifier,
    data: T,
    signature: impl AsRef<[u8]>,
    signature_encoding: DataEncoding,
) -> VerificationResult {
    let verification_result = verifier
        .verify_detached_stream(data, signature.as_ref(), signature_encoding.into())
        .map_err(|err| VerificationError::RuntimeError(err.into()))?;
    go_verification_result_to_result(Some(&verification_result))
}

/// Transforms a `gopenpgp_sys` verification result to a [`VerificationResult`].
pub(super) fn go_verification_result_to_result(
    verification_result_option: Option<&gopenpgp_sys::VerificationResult>,
) -> VerificationResult {
    let verification_result = verification_result_option.ok_or(VerificationError::RuntimeError(
        CryptoInfoError::new("No verification result found").into(),
    ))?;
    let status = verification_result.status();
    match status {
        gopenpgp_sys::VerificationStatus::Ok => {
            let sig_info = verification_result
                .signature_info()
                .map_err(|err| VerificationError::RuntimeError(err.into()))?;
            sig_info.try_into().map_err(VerificationError::RuntimeError)
        }
        gopenpgp_sys::VerificationStatus::NotSigned(err) => {
            Err(VerificationError::NotSigned(err.into()))
        }
        gopenpgp_sys::VerificationStatus::NoVerifier(err) => {
            Err(VerificationError::NoVerifier(err.into()))
        }
        gopenpgp_sys::VerificationStatus::Error(err) => {
            Err(VerificationError::RuntimeError(err.into()))
        }
        gopenpgp_sys::VerificationStatus::BadContext(err) => {
            let sig_info = verification_result
                .signature_info()
                .map_err(|err| VerificationError::RuntimeError(err.into()))?;
            Err(VerificationError::BadContext(
                sig_info
                    .try_into()
                    .map_err(VerificationError::RuntimeError)?,
                err.into(),
            ))
        }
        gopenpgp_sys::VerificationStatus::Failed(err) => {
            let sig_info = verification_result
                .signature_info()
                .map_err(|err| VerificationError::RuntimeError(err.into()))?;
            Err(VerificationError::Failed(
                sig_info
                    .try_into()
                    .map_err(VerificationError::RuntimeError)?,
                err.into(),
            ))
        }
    }
}

impl TryFrom<gopenpgp_sys::SignatureInfo> for VerificationInformation {
    type Error = crate::Error;

    fn try_from(value: gopenpgp_sys::SignatureInfo) -> Result<Self, Self::Error> {
        let Some(selected_signature) = value.selected_signature() else {
            return Err(CryptoInfoError::new("No selected signature found").into());
        };
        Ok(VerificationInformation {
            key_id: OpenPGPKeyID(value.key_id()),
            signature_creation_time: UnixTimestamp::new(value.creation_time()),
            signature: selected_signature.to_vec(),
        })
    }
}
