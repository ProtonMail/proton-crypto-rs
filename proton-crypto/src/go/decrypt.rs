use std::io;

use super::{
    GoPrivateKey, GoPublicKey, GoSessionKey, GoVerificationContext, GoVerifiedData,
    GoVerifiedDataReader,
};
use crate::{
    crypto::DetachedSignatureVariant, AsPublicKeyRef, Decryptor, DecryptorAsync, DecryptorSync,
    UnixTimestamp,
};

pub struct GoDecryptor<'a>(pub(super) gopenpgp_sys::Decryptor<'a>);

impl<'a> Decryptor<'a> for GoDecryptor<'a> {
    type SessionKey = GoSessionKey;
    type PrivateKey = GoPrivateKey;
    type PublicKey = GoPublicKey;
    type VerifiedData = GoVerifiedData;
    type VerificationContext = GoVerificationContext;
    type VerifiedDataReader<'b, T: io::Read + 'b> = GoVerifiedDataReader<'b, T>;

    fn with_decryption_key(self, decryption_key: &'a Self::PrivateKey) -> Self {
        GoDecryptor(self.0.with_decryption_key(decryption_key))
    }

    fn with_decryption_keys(self, decryption_keys: &'a [Self::PrivateKey]) -> Self {
        GoDecryptor(self.0.with_decryption_keys(decryption_keys))
    }

    fn with_decryption_key_refs(self, decryption_keys: &'a [impl AsRef<Self::PrivateKey>]) -> Self {
        let mut decryptor = self.0;
        for decryption_key in decryption_keys {
            decryptor = decryptor.with_decryption_key(decryption_key.as_ref());
        }
        GoDecryptor(decryptor)
    }

    fn with_verification_key(self, verification_key: &'a Self::PublicKey) -> Self {
        GoDecryptor(self.0.with_verification_key(verification_key))
    }

    fn with_verification_keys(self, verification_keys: &'a [Self::PublicKey]) -> Self {
        GoDecryptor(self.0.with_verification_keys(verification_keys))
    }

    fn with_verification_key_refs(
        self,
        verification_keys: &'a [impl AsPublicKeyRef<Self::PublicKey>],
    ) -> Self {
        let mut decryptor = self.0;
        for verification_key in verification_keys {
            decryptor = decryptor.with_verification_key(verification_key.as_public_key());
        }
        GoDecryptor(decryptor)
    }

    fn with_session_key_ref(self, session_key: &'a Self::SessionKey) -> Self {
        GoDecryptor(self.0.with_session_key(&session_key.0))
    }

    fn with_session_key(self, session_key: Self::SessionKey) -> Self {
        GoDecryptor(self.0.with_session_key_move(session_key.0))
    }

    fn with_passphrase(self, passphrase: &'a str) -> Self {
        GoDecryptor(self.0.with_passphrase(passphrase))
    }

    fn with_verification_context(
        self,
        verification_context: &'a Self::VerificationContext,
    ) -> Self {
        GoDecryptor(
            self.0
                .with_verification_context(verification_context.as_ref()),
        )
    }

    fn at_verification_time(self, unix_timestamp: UnixTimestamp) -> Self {
        GoDecryptor(self.0.at_verification_time(unix_timestamp.value()))
    }

    fn with_ut8_sanitization(self) -> Self {
        GoDecryptor(self.0.with_utf8_out())
    }

    fn with_detached_signature_ref(
        self,
        detached_signature: &'a [u8],
        variant: DetachedSignatureVariant,
        armored: bool,
    ) -> Self {
        GoDecryptor(self.0.with_detached_signature_ref(
            detached_signature,
            variant.is_encrypted(),
            armored,
        ))
    }

    fn with_detached_signature(
        self,
        detached_signature: Vec<u8>,
        variant: DetachedSignatureVariant,
        armored: bool,
    ) -> Self {
        GoDecryptor(self.0.with_detached_signature(
            detached_signature,
            variant.is_encrypted(),
            armored,
        ))
    }
}

impl<'a> DecryptorSync<'a> for GoDecryptor<'a> {
    fn decrypt(
        self,
        data: impl AsRef<[u8]>,
        data_encoding: crate::DataEncoding,
    ) -> crate::Result<Self::VerifiedData> {
        decrypt(self.0, data, data_encoding)
    }

    fn decrypt_session_key(self, key_packets: impl AsRef<[u8]>) -> crate::Result<Self::SessionKey> {
        decrypt_session_key(self.0, key_packets)
    }

    fn decrypt_stream<T: io::Read + 'a>(
        self,
        data: T,
        data_encoding: crate::DataEncoding,
    ) -> crate::Result<Self::VerifiedDataReader<'a, T>> {
        decrypt_stream(self.0, data, data_encoding)
    }
}

impl<'a> DecryptorAsync<'a> for GoDecryptor<'a> {
    async fn decrypt_async(
        self,
        data: impl AsRef<[u8]>,
        data_encoding: crate::DataEncoding,
    ) -> crate::Result<GoVerifiedData> {
        decrypt(self.0, data, data_encoding)
    }

    async fn decrypt_session_key_async(
        self,
        key_packets: impl AsRef<[u8]>,
    ) -> crate::Result<Self::SessionKey> {
        decrypt_session_key(self.0, key_packets)
    }
}

/// Decrypts data using the provided decryptor and data encoding.
fn decrypt(
    decryptor: gopenpgp_sys::Decryptor,
    data: impl AsRef<[u8]>,
    data_encoding: crate::DataEncoding,
) -> crate::Result<GoVerifiedData> {
    decryptor
        .decrypt(data.as_ref(), data_encoding.into())
        .map(GoVerifiedData)
        .map_err(Into::into)
}

/// Decrypts a stream of data using the provided decryptor and data encoding.
fn decrypt_stream<T: io::Read>(
    decryptor: gopenpgp_sys::Decryptor<'_>,
    reader: T,
    data_encoding: crate::DataEncoding,
) -> crate::Result<GoVerifiedDataReader<'_, T>> {
    decryptor
        .decrypt_stream(reader, data_encoding.into())
        .map(GoVerifiedDataReader)
        .map_err(Into::into)
}

/// Decrypts a session key from the provided key packets using the decryptor.
fn decrypt_session_key(
    decryptor: gopenpgp_sys::Decryptor,
    key_packets: impl AsRef<[u8]>,
) -> crate::Result<GoSessionKey> {
    decryptor
        .decrypt_session_key(key_packets.as_ref())
        .map(GoSessionKey)
        .map_err(Into::into)
}
