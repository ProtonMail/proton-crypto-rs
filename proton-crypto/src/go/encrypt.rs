use std::io;

use super::{GoPrivateKey, GoPublicKey, GoSessionKey, GoSigningContext};
use crate::{
    crypto::{
        DataEncoding, DetachedSignatureVariant, EncryptorDetachedSignatureWriter,
        SessionKeyAlgorithm,
    },
    Encryptor, EncryptorAsync, EncryptorSync, EncryptorWriter, PGPMessage,
};

pub struct GoPGPMessage(pub(super) gopenpgp_sys::PGPMessage);

impl AsRef<[u8]> for GoPGPMessage {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl PGPMessage for GoPGPMessage {
    fn armor(&self) -> crate::Result<Vec<u8>> {
        self.0.armored().map_err(Into::into)
    }

    fn as_key_packets(&self) -> &[u8] {
        self.0.key_packet()
    }

    fn as_data_packet(&self) -> &[u8] {
        self.0.data_packet()
    }

    fn encryption_key_ids(&self) -> Vec<crate::OpenPGPKeyID> {
        let ids_option = self.0.encryption_key_ids();
        let Some(ids) = ids_option else {
            return Vec::new();
        };
        let mut ids_out = Vec::with_capacity(ids.as_ref().len());
        ids_out.extend(ids.as_ref().iter().map(|id| crate::OpenPGPKeyID(*id)));
        ids_out
    }
}

pub struct GoEncryptorWriter<'a, T>(pub(super) gopenpgp_sys::PGPEncryptorWriteCloser<'a, T>);

impl<T: io::Write> io::Write for GoEncryptorWriter<'_, T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl<'a, T: io::Write + 'a> EncryptorWriter<'a, T> for GoEncryptorWriter<'a, T> {
    fn finalize(mut self) -> crate::Result<()> {
        self.0.close().map_err(Into::into)
    }
}

pub struct GoEncryptorDetachedSignatureWriter<'a, T>(
    gopenpgp_sys::PGPEncryptorWithDetachedSigWriteCloser<'a, T>,
);

impl<T: io::Write> io::Write for GoEncryptorDetachedSignatureWriter<'_, T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl<'a, T: io::Write + 'a> EncryptorDetachedSignatureWriter<'a, T>
    for GoEncryptorDetachedSignatureWriter<'a, T>
{
    fn finalize_with_detached_signature(mut self) -> crate::Result<Vec<u8>> {
        self.0
            .close()
            .map_err(Into::<crate::Error>::into)
            .map(|_c| self.0.take_detached_signature())
    }
}

pub struct GoEncryptor<'a>(pub(super) gopenpgp_sys::Encryptor<'a>);

impl<'a> Encryptor<'a> for GoEncryptor<'a> {
    type SessionKey = GoSessionKey;
    type PrivateKey = GoPrivateKey;
    type PublicKey = GoPublicKey;
    type SigningContext = GoSigningContext;
    type PGPMessage = GoPGPMessage;
    type EncryptorWriter<'b, T: io::Write + 'b> = GoEncryptorWriter<'b, T>;
    type EncryptorDetachedSignatureWriter<'b, T: io::Write + 'b> =
        GoEncryptorDetachedSignatureWriter<'b, T>;

    fn with_encryption_key(self, encryption_key: &'a Self::PublicKey) -> Self {
        Self(self.0.with_encryption_key(encryption_key))
    }

    fn with_encryption_keys(self, encryption_keys: &'a [Self::PublicKey]) -> Self {
        Self(self.0.with_encryption_keys(encryption_keys))
    }

    fn with_encryption_key_refs(
        self,
        encryption_keys: &'a [impl crate::AsPublicKeyRef<Self::PublicKey>],
    ) -> Self {
        let mut encryptor = self.0;
        for encryption_key in encryption_keys {
            encryptor = encryptor.with_encryption_key(encryption_key.as_public_key());
        }
        Self(encryptor)
    }

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

    fn with_session_key(self, session_key: Self::SessionKey) -> Self {
        Self(self.0.with_session_key_move(session_key.0))
    }

    fn with_session_key_ref(self, session_key: &'a Self::SessionKey) -> Self {
        Self(self.0.with_session_key(&session_key.0))
    }
    fn with_passphrase(self, passphrase: &'a str) -> Self {
        Self(self.0.with_passphrase(passphrase))
    }

    fn with_compression(self) -> Self {
        Self(self.0.with_compression())
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

impl<'a> EncryptorSync<'a> for GoEncryptor<'a> {
    fn encrypt_raw(
        self,
        data: impl AsRef<[u8]>,
        data_encoding: DataEncoding,
    ) -> crate::Result<Vec<u8>> {
        self.0
            .encrypt_raw(data.as_ref(), data_encoding.into())
            .map_err(Into::into)
    }

    fn encrypt(self, data: impl AsRef<[u8]>) -> crate::Result<Self::PGPMessage> {
        self.0
            .encrypt(data.as_ref())
            .map(GoPGPMessage)
            .map_err(Into::into)
    }

    fn encrypt_session_key(self, session_key: &Self::SessionKey) -> crate::Result<Vec<u8>> {
        self.0
            .encrypt_session_key(&session_key.0)
            .map_err(Into::into)
    }

    fn encrypt_stream<T: io::Write + 'a>(
        self,
        output_writer: T,
        output_encoding: DataEncoding,
    ) -> crate::Result<Self::EncryptorWriter<'a, T>> {
        self.0
            .encrypt_stream(output_writer, output_encoding.into())
            .map(GoEncryptorWriter)
            .map_err(Into::into)
    }

    fn encrypt_stream_split<T: io::Write + 'a>(
        self,
        output_writer: T,
    ) -> crate::Result<(Vec<u8>, Self::EncryptorWriter<'a, T>)> {
        self.0
            .encrypt_stream_split(output_writer)
            .map(|(kp, writer)| (kp, GoEncryptorWriter(writer)))
            .map_err(Into::into)
    }

    fn encrypt_stream_split_with_detached_signature<T: io::Write + 'a>(
        self,
        output_writer: T,
        variant: DetachedSignatureVariant,
    ) -> crate::Result<(Vec<u8>, Self::EncryptorDetachedSignatureWriter<'a, T>)> {
        self.0
            .encrypt_stream_split_with_detached_signature(output_writer, variant.is_encrypted())
            .map(|(kp, writer)| (kp, GoEncryptorDetachedSignatureWriter(writer)))
            .map_err(Into::into)
    }

    fn encrypt_stream_with_detached_signature<T: io::Write + 'a>(
        self,
        output_writer: T,
        variant: DetachedSignatureVariant,
        output_encoding: DataEncoding,
    ) -> crate::Result<Self::EncryptorDetachedSignatureWriter<'a, T>> {
        self.0
            .encrypt_stream_with_detached_signature(
                output_writer,
                variant.is_encrypted(),
                output_encoding.into(),
            )
            .map(GoEncryptorDetachedSignatureWriter)
            .map_err(Into::into)
    }

    fn generate_session_key(self) -> crate::Result<Self::SessionKey> {
        // TODO: Currently GopenPGP does not offer a dedicated session key generation based on recipient keys
        // we used the default here.
        super::generate_session_key(SessionKeyAlgorithm::Aes256)
    }
}

impl<'a> EncryptorAsync<'a> for GoEncryptor<'a> {
    async fn encrypt_raw_async(
        self,
        data: impl AsRef<[u8]>,
        data_encoding: DataEncoding,
    ) -> crate::Result<Vec<u8>> {
        self.0
            .encrypt_raw(data.as_ref(), data_encoding.into())
            .map_err(Into::into)
    }

    async fn encrypt_async(self, data: impl AsRef<[u8]>) -> crate::Result<Self::PGPMessage> {
        self.0
            .encrypt(data.as_ref())
            .map(GoPGPMessage)
            .map_err(Into::into)
    }

    async fn encrypt_session_key_async(
        self,
        session_key: &Self::SessionKey,
    ) -> crate::Result<Vec<u8>> {
        self.0
            .encrypt_session_key(&session_key.0)
            .map_err(Into::into)
    }
}

/// Imports an `OpenPGP` message.
pub(super) fn pgp_message_import(
    pgp_message: impl AsRef<[u8]>,
    encoding: DataEncoding,
) -> crate::Result<GoPGPMessage> {
    let message = match encoding {
        DataEncoding::Armor => gopenpgp_sys::PGPMessage::new_from_armored(pgp_message.as_ref())?,
        DataEncoding::Bytes => gopenpgp_sys::PGPMessage::new_from_slice(pgp_message.as_ref()),
        DataEncoding::Auto => {
            if gopenpgp_sys::armor::is_armored(pgp_message.as_ref()) {
                gopenpgp_sys::PGPMessage::new_from_armored(pgp_message.as_ref())?
            } else {
                gopenpgp_sys::PGPMessage::new_from_slice(pgp_message.as_ref())
            }
        }
    };
    Ok(GoPGPMessage(message))
}
