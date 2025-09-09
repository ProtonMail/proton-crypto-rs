use std::io;

use proton_rpgp::{EncryptedMessage, Profile, SessionKey as RustSessionKey};

use crate::{
    crypto::{
        DataEncoding, DetachedSignatureVariant, Encryptor, EncryptorAsync,
        EncryptorDetachedSignatureWriter, EncryptorSync, EncryptorWriter, PGPKeyPackets,
        PGPMessage, RawDetachedSignature, RawEncryptedMessage,
    },
    rust::pgp::{RustPrivateKey, RustPublicKey, RustSigningContext, INIT_BUFFER_SIZE},
    CryptoInfoError,
};

pub struct RustPGPMessage(pub(super) EncryptedMessage);

impl RustPGPMessage {
    pub fn from_unarmored(bytes: &[u8]) -> crate::Result<Self> {
        Ok(Self(EncryptedMessage::from_bytes(bytes)?))
    }

    pub fn from_armored(bytes: &[u8]) -> crate::Result<Self> {
        Ok(Self(EncryptedMessage::from_armor(bytes)?))
    }

    fn detached_signature(&self, encoding: DataEncoding) -> Option<RawDetachedSignature> {
        self.0.detached_signature().and_then(|s| match encoding {
            DataEncoding::Armor => s.armored().ok(),
            _ => s.unarmored().ok(),
        })
    }
}

impl AsRef<[u8]> for RustPGPMessage {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl PGPMessage for RustPGPMessage {
    fn armor(&self) -> crate::Result<Vec<u8>> {
        self.0.armor().map_err(Into::into)
    }

    fn as_key_packets(&self) -> &[u8] {
        self.0.as_key_packets_unchecked()
    }

    fn as_data_packet(&self) -> &[u8] {
        self.0.as_data_packet_unchecked()
    }

    fn encryption_key_ids(&self) -> Vec<crate::crypto::OpenPGPKeyID> {
        self.0
            .encryption_key_ids()
            .into_iter()
            .map(Into::into)
            .collect()
    }
}

impl From<EncryptedMessage> for RustPGPMessage {
    fn from(value: EncryptedMessage) -> Self {
        Self(value)
    }
}

enum RustEncryptorType {
    Split(proton_rpgp::SessionKey),
    NoSplit,
}

/// Currently mocks the streaming API by buffering data in memory.
pub struct RustEncryptorWriter<'a, T: io::Write + 'a> {
    encryptor: RustEncryptor<'a>,
    output_writer: T,
    buffer: Vec<u8>,
    data_encoding: DataEncoding,
    session_key: RustEncryptorType,
}

impl<'a, T: io::Write + 'a> RustEncryptorWriter<'a, T> {
    pub fn init(
        encryptor: RustEncryptor<'a>,
        output_writer: T,
        data_encoding: DataEncoding,
    ) -> Self {
        Self {
            encryptor,
            output_writer,
            buffer: Vec::with_capacity(INIT_BUFFER_SIZE),
            data_encoding,
            session_key: RustEncryptorType::NoSplit,
        }
    }

    pub fn init_split(
        encryptor: RustEncryptor<'a>,
        output_writer: T,
    ) -> Result<(Vec<u8>, Self), crate::CryptoError> {
        let (session_key, key_packet) = Self::create_key_packet(encryptor.inner.clone())?;

        let writer = Self {
            encryptor,
            output_writer,
            buffer: Vec::with_capacity(INIT_BUFFER_SIZE),
            data_encoding: DataEncoding::Bytes,
            session_key: RustEncryptorType::Split(session_key),
        };

        Ok((key_packet, writer))
    }

    fn create_key_packet(
        encryptor: proton_rpgp::Encryptor<'a>,
    ) -> Result<(proton_rpgp::SessionKey, Vec<u8>), proton_rpgp::Error> {
        let session_key = encryptor.clone().generate_session_key()?;
        let key_packet = encryptor.encrypt_session_key(&session_key)?;
        Ok((session_key, key_packet))
    }
}

impl<'a, T: io::Write + 'a> io::Write for RustEncryptorWriter<'a, T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buffer.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a, T: io::Write + 'a> EncryptorWriter<'a, T> for RustEncryptorWriter<'a, T> {
    fn finalize(mut self) -> crate::Result<()> {
        match self.session_key {
            RustEncryptorType::Split(session_key) => {
                let message = self
                    .encryptor
                    .with_session_key(session_key)
                    .encrypt(self.buffer)?;
                self.output_writer.write_all(message.as_data_packet())?;
                Ok(())
            }
            RustEncryptorType::NoSplit => {
                let message = self
                    .encryptor
                    .encrypt_raw(self.buffer, self.data_encoding)?;
                self.output_writer.write_all(&message)?;
                Ok(())
            }
        }
    }
}

/// Currently mocks the streaming API by buffering data in memory.
pub struct RustEncryptorDetachedSignatureWriter<'a, T: io::Write + 'a> {
    encryptor: RustEncryptor<'a>,
    output_writer: T,
    buffer: Vec<u8>,
    data_encoding: DataEncoding,
    detached_signature_variant: DetachedSignatureVariant,
    session_key: RustEncryptorType,
}

impl<'a, T: io::Write + 'a> RustEncryptorDetachedSignatureWriter<'a, T> {
    pub fn init(
        encryptor: RustEncryptor<'a>,
        output_writer: T,
        data_encoding: DataEncoding,
        detached_signature_variant: DetachedSignatureVariant,
    ) -> Self {
        Self {
            encryptor,
            output_writer,
            buffer: Vec::with_capacity(INIT_BUFFER_SIZE),
            data_encoding,
            detached_signature_variant,
            session_key: RustEncryptorType::NoSplit,
        }
    }

    pub fn init_split(
        encryptor: RustEncryptor<'a>,
        output_writer: T,
        detached_signature_variant: DetachedSignatureVariant,
    ) -> Result<(Vec<u8>, Self), crate::CryptoError> {
        let (session_key, key_packet) = Self::create_key_packet(encryptor.inner.clone())?;

        let writer = Self {
            encryptor,
            output_writer,
            buffer: Vec::with_capacity(INIT_BUFFER_SIZE),
            data_encoding: DataEncoding::Bytes,
            detached_signature_variant,
            session_key: RustEncryptorType::Split(session_key),
        };

        Ok((key_packet, writer))
    }

    fn create_key_packet(
        encryptor: proton_rpgp::Encryptor<'a>,
    ) -> Result<(proton_rpgp::SessionKey, Vec<u8>), proton_rpgp::Error> {
        let session_key = encryptor.clone().generate_session_key()?;
        let key_packet = encryptor.encrypt_session_key(&session_key)?;
        Ok((session_key, key_packet))
    }
}

impl<'a, T: io::Write + 'a> io::Write for RustEncryptorDetachedSignatureWriter<'a, T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buffer.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a, T: io::Write + 'a> EncryptorDetachedSignatureWriter<'a, T>
    for RustEncryptorDetachedSignatureWriter<'a, T>
{
    fn finalize_with_detached_signature(mut self) -> crate::Result<RawDetachedSignature> {
        match self.session_key {
            RustEncryptorType::Split(session_key) => {
                let message = self
                    .encryptor
                    .with_detached_signature(self.detached_signature_variant)
                    .with_session_key(session_key)
                    .encrypt(self.buffer)?;
                self.output_writer.write_all(message.as_data_packet())?;
                let detached_signature = message
                    .detached_signature(DataEncoding::Bytes)
                    .ok_or(CryptoInfoError::new("failed to load detached signature"))?;
                Ok(detached_signature)
            }
            RustEncryptorType::NoSplit => {
                let message = self
                    .encryptor
                    .with_detached_signature(self.detached_signature_variant)
                    .encrypt(self.buffer)?;
                match self.data_encoding {
                    DataEncoding::Armor => {
                        let armored_message = message.armor()?;
                        self.output_writer.write_all(&armored_message)?;
                    }
                    _ => {
                        self.output_writer.write_all(message.as_ref())?;
                    }
                }
                let detached_signature = message
                    .detached_signature(self.data_encoding)
                    .ok_or(CryptoInfoError::new("failed to load detached signature"))?;
                Ok(detached_signature)
            }
        }
    }
}

pub struct RustEncryptor<'a> {
    pub(super) inner: proton_rpgp::Encryptor<'a>,
}

impl RustEncryptor<'_> {
    pub fn new(profile: Profile) -> Self {
        Self {
            inner: proton_rpgp::Encryptor::new(profile),
        }
    }

    fn with_detached_signature(mut self, detached_signature: DetachedSignatureVariant) -> Self {
        let variant = match detached_signature {
            DetachedSignatureVariant::Encrypted => true,
            DetachedSignatureVariant::Plaintext => false,
        };
        self.inner = self.inner.using_detached_signature(variant);
        self
    }
}

impl<'a> Encryptor<'a> for RustEncryptor<'a> {
    type SessionKey = RustSessionKey;
    type PrivateKey = RustPrivateKey;
    type PublicKey = RustPublicKey;
    type PGPMessage = RustPGPMessage;
    type SigningContext = RustSigningContext;
    type EncryptorWriter<'b, T: io::Write + 'b> = RustEncryptorWriter<'b, T>;
    type EncryptorDetachedSignatureWriter<'b, T: io::Write + 'b> =
        RustEncryptorDetachedSignatureWriter<'b, T>;

    fn with_encryption_key(mut self, encryption_key: &'a Self::PublicKey) -> Self {
        self.inner = self.inner.with_encryption_key(&encryption_key.0);
        self
    }

    fn with_encryption_keys(mut self, encryption_keys: &'a [Self::PublicKey]) -> Self {
        self.inner = self
            .inner
            .with_encryption_keys(encryption_keys.iter().map(|k| k.0.as_ref()));
        self
    }

    fn with_encryption_key_refs(
        mut self,
        encryption_keys: &'a [impl crate::crypto::AsPublicKeyRef<Self::PublicKey>],
    ) -> Self {
        self.inner = self
            .inner
            .with_encryption_keys(encryption_keys.iter().map(|k| k.as_public_key().0.as_ref()));
        self
    }

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

    fn with_compression(mut self) -> Self {
        self.inner = self.inner.compress();
        self
    }

    fn at_signing_time(mut self, unix_timestamp: crate::crypto::UnixTimestamp) -> Self {
        self.inner = self.inner.at_date(unix_timestamp.into());
        self
    }

    fn with_utf8(mut self) -> Self {
        self.inner = self.inner.as_utf8();
        self
    }
}

impl<'a> EncryptorSync<'a> for RustEncryptor<'a> {
    fn generate_session_key(self) -> crate::Result<Self::SessionKey> {
        self.inner.generate_session_key().map_err(Into::into)
    }

    fn encrypt(self, data: impl AsRef<[u8]>) -> crate::Result<Self::PGPMessage> {
        self.inner
            .encrypt(data.as_ref())
            .map(Into::into)
            .map_err(Into::into)
    }

    fn encrypt_raw(
        self,
        data: impl AsRef<[u8]>,
        armored: DataEncoding,
    ) -> crate::Result<RawEncryptedMessage> {
        self.inner
            .encrypt_raw(data.as_ref(), armored.into())
            .map_err(Into::into)
    }

    fn encrypt_session_key(self, session_key: &Self::SessionKey) -> crate::Result<PGPKeyPackets> {
        self.inner
            .encrypt_session_key(session_key)
            .map_err(Into::into)
    }

    fn encrypt_stream<T: io::Write + 'a>(
        self,
        output_writer: T,
        output_encoding: DataEncoding,
    ) -> crate::Result<Self::EncryptorWriter<'a, T>> {
        // No streaming support yet, buffering data in memory.
        Ok(RustEncryptorWriter::init(
            self,
            output_writer,
            output_encoding,
        ))
    }

    fn encrypt_stream_split<T: io::Write + 'a>(
        self,
        output_writer: T,
    ) -> crate::Result<(Vec<u8>, Self::EncryptorWriter<'a, T>)> {
        // No streaming support yet, buffering data in memory.
        RustEncryptorWriter::init_split(self, output_writer)
    }

    fn encrypt_stream_with_detached_signature<T: io::Write + 'a>(
        self,
        output_writer: T,
        variant: DetachedSignatureVariant,
        output_encoding: DataEncoding,
    ) -> crate::Result<Self::EncryptorDetachedSignatureWriter<'a, T>> {
        // No streaming support yet, buffering data in memory.
        Ok(RustEncryptorDetachedSignatureWriter::init(
            self,
            output_writer,
            output_encoding,
            variant,
        ))
    }

    fn encrypt_stream_split_with_detached_signature<T: io::Write + 'a>(
        self,
        output_writer: T,
        variant: DetachedSignatureVariant,
    ) -> crate::Result<(Vec<u8>, Self::EncryptorDetachedSignatureWriter<'a, T>)> {
        RustEncryptorDetachedSignatureWriter::init_split(self, output_writer, variant)
    }
}

impl<'a> EncryptorAsync<'a> for RustEncryptor<'a> {
    async fn encrypt_raw_async(
        self,
        data: impl AsRef<[u8]>,
        armored: DataEncoding,
    ) -> crate::Result<RawEncryptedMessage> {
        self.encrypt_raw(data, armored)
    }

    async fn encrypt_session_key_async(
        self,
        session_key: &Self::SessionKey,
    ) -> crate::Result<PGPKeyPackets> {
        self.encrypt_session_key(session_key)
    }

    async fn encrypt_async(self, data: impl AsRef<[u8]>) -> crate::Result<Self::PGPMessage> {
        self.encrypt(data)
    }
}
