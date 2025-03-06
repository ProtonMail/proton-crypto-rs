use std::io;

use super::{GoEncryptorWriter, GoPrivateKey};
use crate::{Signer, SignerAsync, SignerSync, SigningContext};

#[derive(Debug, Clone)]
pub struct GoSigningContext(pub(super) gopenpgp_sys::SigningContext);

impl SigningContext for GoSigningContext {}

impl AsRef<gopenpgp_sys::SigningContext> for GoSigningContext {
    fn as_ref(&self) -> &gopenpgp_sys::SigningContext {
        &self.0
    }
}

pub struct GoSigner<'a>(pub(super) gopenpgp_sys::Signer<'a>);

impl<'a> Signer<'a> for GoSigner<'a> {
    type PrivateKey = GoPrivateKey;
    type SigningContext = GoSigningContext;
    type SignerWriter<'b, T: io::Write + 'b> = GoEncryptorWriter<'b, T>;

    fn with_signing_key(self, signing_key: &'a Self::PrivateKey) -> Self {
        Self(self.0.with_signing_key(signing_key))
    }

    fn with_signing_keys(self, signing_keys: &'a [Self::PrivateKey]) -> Self {
        Self(self.0.with_signing_keys(signing_keys))
    }

    fn with_signing_key_refs(self, signing_keys: &'a [impl AsRef<Self::PrivateKey>]) -> Self {
        let mut encryptor = self.0;
        for signing_key in signing_keys {
            encryptor = encryptor.with_signing_key(signing_key.as_ref());
        }
        Self(encryptor)
    }

    fn with_signing_context(self, signing_context: &'a Self::SigningContext) -> Self {
        Self(self.0.with_signing_context(&signing_context.0))
    }

    fn at_signing_time(self, unix_timestamp: crate::UnixTimestamp) -> Self {
        Self(self.0.at_signing_time(unix_timestamp.value()))
    }

    fn with_utf8(self) -> Self {
        Self(self.0.as_utf8())
    }
}

impl<'a> SignerSync<'a> for GoSigner<'a> {
    fn sign_inline(
        self,
        data: impl AsRef<[u8]>,
        out_encoding: crate::DataEncoding,
    ) -> crate::Result<Vec<u8>> {
        self.0
            .sign(data.as_ref(), false, out_encoding.into())
            .map_err(Into::into)
    }

    fn sign_detached(
        self,
        data: impl AsRef<[u8]>,
        out_encoding: crate::DataEncoding,
    ) -> crate::Result<Vec<u8>> {
        self.0
            .sign(data.as_ref(), true, out_encoding.into())
            .map_err(Into::into)
    }

    fn sign_cleartext(self, data: impl AsRef<[u8]>) -> crate::Result<Vec<u8>> {
        self.0.sign_cleartext(data.as_ref()).map_err(Into::into)
    }

    fn sing_stream<T: io::Write + 'a>(
        self,
        sign_writer: T,
        detached: bool,
        data_encoding: crate::DataEncoding,
    ) -> crate::Result<Self::SignerWriter<'a, T>> {
        self.0
            .sing_stream(sign_writer, detached, data_encoding.into())
            .map(GoEncryptorWriter)
            .map_err(Into::into)
    }
}

impl<'a> SignerAsync<'a> for GoSigner<'a> {
    async fn sign_inline_async(
        self,
        data: impl AsRef<[u8]>,
        out_encoding: crate::DataEncoding,
    ) -> crate::Result<Vec<u8>> {
        self.0
            .sign(data.as_ref(), false, out_encoding.into())
            .map_err(Into::into)
    }

    async fn sign_detached_async(
        self,
        data: impl AsRef<[u8]>,
        out_encoding: crate::DataEncoding,
    ) -> crate::Result<Vec<u8>> {
        self.0
            .sign(data.as_ref(), true, out_encoding.into())
            .map_err(Into::into)
    }

    async fn sign_cleartext_async(self, data: impl AsRef<[u8]>) -> crate::Result<Vec<u8>> {
        self.0.sign_cleartext(data.as_ref()).map_err(Into::into)
    }
}
