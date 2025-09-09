use std::io;

use proton_rpgp::Profile;

use crate::{
    crypto::{
        DataEncoding, EncryptorWriter, Signer, SignerAsync, SignerSync, SigningContext,
        UnixTimestamp,
    },
    rust::pgp::{RustPrivateKey, INIT_BUFFER_SIZE},
};

#[derive(Debug, Clone)]
pub struct RustSigningContext {
    pub(crate) inner: proton_rpgp::SignatureContext,
}

impl RustSigningContext {
    pub fn new(value: String, is_critical: bool) -> Self {
        Self {
            inner: proton_rpgp::SignatureContext::new(value, is_critical),
        }
    }
}

impl SigningContext for RustSigningContext {}

impl From<proton_rpgp::SignatureContext> for RustSigningContext {
    fn from(value: proton_rpgp::SignatureContext) -> Self {
        Self { inner: value }
    }
}

impl From<RustSigningContext> for proton_rpgp::SignatureContext {
    fn from(value: RustSigningContext) -> Self {
        value.inner
    }
}

/// Currently mocks the streaming API by buffering data in memory.
pub struct RustSignerWriter<'a, T: io::Write + 'a> {
    signer: RustSigner<'a>,
    buffer: Vec<u8>,
    result_writer: T,
    detached: bool,
    data_encoding: DataEncoding,
}

impl<'a, T: io::Write + 'a> io::Write for RustSignerWriter<'a, T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buffer.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a, T: io::Write + 'a> EncryptorWriter<'a, T> for RustSignerWriter<'a, T> {
    fn finalize(mut self) -> crate::Result<()> {
        let data = if self.detached {
            self.signer.sign_detached(self.buffer, self.data_encoding)?
        } else {
            self.signer.sign_inline(self.buffer, self.data_encoding)?
        };
        self.result_writer.write_all(&data)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct RustSigner<'a> {
    pub(super) inner: proton_rpgp::Signer<'a>,
}

impl RustSigner<'_> {
    pub fn new(profile: Profile) -> Self {
        Self {
            inner: proton_rpgp::Signer::new(profile),
        }
    }
}

impl<'a> Signer<'a> for RustSigner<'a> {
    type PrivateKey = RustPrivateKey;
    type SigningContext = RustSigningContext;
    type SignerWriter<'b, T: io::Write + 'b> = RustSignerWriter<'b, T>;

    fn with_signing_key(mut self, signing_key: &'a Self::PrivateKey) -> Self {
        self.inner = self.inner.with_signing_key(&signing_key.0);
        self
    }

    fn with_signing_keys(mut self, signing_keys: &'a [Self::PrivateKey]) -> Self {
        self.inner = self
            .inner
            .with_signing_keys(signing_keys.iter().map(|k| k.0.as_ref()));
        self
    }

    fn with_signing_key_refs(mut self, signing_keys: &'a [impl AsRef<Self::PrivateKey>]) -> Self {
        self.inner = self
            .inner
            .with_signing_keys(signing_keys.iter().map(|k| k.as_ref().0.as_ref()));
        self
    }

    fn with_signing_context(mut self, signing_context: &'a Self::SigningContext) -> Self {
        self.inner = self.inner.with_signature_context(&signing_context.inner);
        self
    }

    fn at_signing_time(mut self, unix_timestamp: UnixTimestamp) -> Self {
        self.inner = self.inner.at_date(unix_timestamp.into());
        self
    }

    fn with_utf8(mut self) -> Self {
        self.inner = self.inner.as_utf8();
        self
    }
}

impl<'a> SignerSync<'a> for RustSigner<'a> {
    fn sign_inline(
        self,
        data: impl AsRef<[u8]>,
        out_encoding: DataEncoding,
    ) -> crate::Result<Vec<u8>> {
        self.inner
            .sign(data.as_ref(), out_encoding.into())
            .map_err(Into::into)
    }

    fn sign_detached(
        self,
        data: impl AsRef<[u8]>,
        out_encoding: DataEncoding,
    ) -> crate::Result<Vec<u8>> {
        self.inner
            .sign_detached(data.as_ref(), out_encoding.into())
            .map_err(Into::into)
    }

    fn sign_cleartext(self, data: impl AsRef<[u8]>) -> crate::Result<Vec<u8>> {
        self.inner.sign_cleartext(data.as_ref()).map_err(Into::into)
    }

    fn sign_stream<T: io::Write + 'a>(
        self,
        sign_writer: T,
        detached: bool,
        data_encoding: DataEncoding,
    ) -> crate::Result<Self::SignerWriter<'a, T>> {
        // No streaming support yet, buffering data in memory.
        Ok(RustSignerWriter {
            signer: self,
            buffer: Vec::with_capacity(INIT_BUFFER_SIZE),
            result_writer: sign_writer,
            data_encoding,
            detached,
        })
    }
}

impl<'a> SignerAsync<'a> for RustSigner<'a> {
    async fn sign_inline_async(
        self,
        data: impl AsRef<[u8]>,
        out_encoding: DataEncoding,
    ) -> crate::Result<Vec<u8>> {
        self.inner
            .sign(data.as_ref(), out_encoding.into())
            .map_err(Into::into)
    }

    async fn sign_detached_async(
        self,
        data: impl AsRef<[u8]>,
        out_encoding: DataEncoding,
    ) -> crate::Result<Vec<u8>> {
        self.inner
            .sign_detached(data.as_ref(), out_encoding.into())
            .map_err(Into::into)
    }

    async fn sign_cleartext_async(self, data: impl AsRef<[u8]>) -> crate::Result<Vec<u8>> {
        self.inner.sign_cleartext(data.as_ref()).map_err(Into::into)
    }
}
