use gopenpgp_sys::PublicKeyReference as _;

use crate::crypto::{
    AccessKeyInfo, AsPublicKeyRef, DataEncoding, KeyGenerator, KeyGeneratorAlgorithm,
    KeyGeneratorAsync, KeyGeneratorSync, OpenPGPFingerprint, OpenPGPKeyID, PrivateKey, PublicKey,
    SHA256Fingerprint, SessionKey, SessionKeyAlgorithm,
};
use crate::UnixTimestamp;

#[derive(Debug, Clone)]
#[allow(clippy::module_name_repetitions)]
pub struct GoSessionKey(pub(super) gopenpgp_sys::SessionKey);

impl SessionKey for GoSessionKey {
    fn export(&self) -> impl AsRef<[u8]> {
        self.0.export_token()
    }

    fn algorithm(&self) -> SessionKeyAlgorithm {
        let Some(algorithm) = self.0.algorithm().map(Into::into).ok() else {
            return SessionKeyAlgorithm::Unknown;
        };
        algorithm
    }
}

#[derive(Debug, Clone)]
#[allow(clippy::module_name_repetitions)]
pub struct GoPublicKey(pub(super) gopenpgp_sys::PublicKey);

impl PublicKey for GoPublicKey {}

impl AsPublicKeyRef<GoPublicKey> for GoPublicKey {
    fn as_public_key(&self) -> &GoPublicKey {
        self
    }
}

impl gopenpgp_sys::PublicKeyReference for GoPublicKey {
    fn public_ref(&self) -> &gopenpgp_sys::GoKey {
        self.0.public_ref()
    }
}

impl AccessKeyInfo for GoPublicKey {
    fn version(&self) -> u8 {
        self.0.version().try_into().unwrap_or_default()
    }

    fn key_id(&self) -> OpenPGPKeyID {
        OpenPGPKeyID(self.0.key_id())
    }

    fn key_fingerprint(&self) -> OpenPGPFingerprint {
        OpenPGPFingerprint::new(hex::encode(self.0.key_fingerprint()))
    }

    fn sha256_key_fingerprints(&self) -> Vec<SHA256Fingerprint> {
        let fingerprints = self.0.sha256_key_fingerprints();
        let mut result = Vec::with_capacity(fingerprints.len());
        result.extend(fingerprints.into_iter().map(|fp| {
            SHA256Fingerprint::new(String::from_utf8(fp.as_ref().to_vec()).unwrap_or_default())
        }));
        result
    }

    fn can_encrypt(&self, unix_time: UnixTimestamp) -> bool {
        self.0.can_encrypt(unix_time.value())
    }

    fn can_verify(&self, unix_time: UnixTimestamp) -> bool {
        self.0.can_verify(unix_time.value())
    }

    fn is_expired(&self, unix_time: UnixTimestamp) -> bool {
        self.0.is_expired(unix_time.value())
    }

    fn is_revoked(&self, unix_time: UnixTimestamp) -> bool {
        self.0.is_revoked(unix_time.value())
    }
}

#[derive(Debug, Clone)]
#[allow(clippy::module_name_repetitions)]
pub struct GoPrivateKey(pub(super) gopenpgp_sys::PrivateKey);

impl PrivateKey for GoPrivateKey {}

impl AsRef<GoPrivateKey> for GoPrivateKey {
    fn as_ref(&self) -> &GoPrivateKey {
        self
    }
}

impl AccessKeyInfo for GoPrivateKey {
    fn version(&self) -> u8 {
        self.0.version().try_into().unwrap_or_default()
    }

    fn key_id(&self) -> OpenPGPKeyID {
        OpenPGPKeyID(self.0.key_id())
    }

    fn key_fingerprint(&self) -> OpenPGPFingerprint {
        OpenPGPFingerprint::new(hex::encode(self.0.key_fingerprint()))
    }

    fn sha256_key_fingerprints(&self) -> Vec<SHA256Fingerprint> {
        let fingerprints = self.0.sha256_key_fingerprints();
        let mut result = Vec::with_capacity(fingerprints.len());
        result.extend(fingerprints.into_iter().map(|fp| {
            SHA256Fingerprint::new(String::from_utf8(fp.as_ref().to_vec()).unwrap_or_default())
        }));
        result
    }

    fn can_encrypt(&self, unix_time: UnixTimestamp) -> bool {
        self.0.can_encrypt(unix_time.value())
    }

    fn can_verify(&self, unix_time: UnixTimestamp) -> bool {
        self.0.can_verify(unix_time.value())
    }

    fn is_expired(&self, unix_time: UnixTimestamp) -> bool {
        self.0.is_expired(unix_time.value())
    }

    fn is_revoked(&self, unix_time: UnixTimestamp) -> bool {
        self.0.is_revoked(unix_time.value())
    }
}

impl gopenpgp_sys::PublicKeyReference for GoPrivateKey {
    fn public_ref(&self) -> &gopenpgp_sys::GoKey {
        self.0.public_ref()
    }
}

impl gopenpgp_sys::PrivateKeyReference for GoPrivateKey {
    fn private_ref(&self) -> &gopenpgp_sys::GoKey {
        self.0.private_ref()
    }
}

impl gopenpgp_sys::PublicKeyReference for &GoPrivateKey {
    fn public_ref(&self) -> &gopenpgp_sys::GoKey {
        self.0.public_ref()
    }
}

impl gopenpgp_sys::PrivateKeyReference for &GoPrivateKey {
    fn private_ref(&self) -> &gopenpgp_sys::GoKey {
        self.0.private_ref()
    }
}

#[allow(clippy::module_name_repetitions)]
pub struct GoKeyGenerator(pub(super) gopenpgp_sys::KeyGenerator);

impl KeyGenerator for GoKeyGenerator {
    fn with_user_id(self, name: &str, email: &str) -> Self {
        Self(self.0.with_user_id(name, email))
    }

    fn with_generation_time(self, unix_time: UnixTimestamp) -> Self {
        Self(self.0.with_generation_time(unix_time.value()))
    }

    fn with_algorithm(self, algorithm: KeyGeneratorAlgorithm) -> Self {
        Self(self.0.with_algorithm(algorithm.into()))
    }
}

impl KeyGeneratorSync<GoPrivateKey> for GoKeyGenerator {
    fn generate(self) -> crate::Result<GoPrivateKey> {
        self.0.generate().map(GoPrivateKey).map_err(Into::into)
    }
}

impl KeyGeneratorAsync<GoPrivateKey> for GoKeyGenerator {
    async fn generate_async(self) -> crate::Result<GoPrivateKey> {
        self.0.generate().map(GoPrivateKey).map_err(Into::into)
    }
}

impl From<KeyGeneratorAlgorithm> for gopenpgp_sys::KeyGenerationOptions {
    fn from(value: KeyGeneratorAlgorithm) -> Self {
        match value {
            KeyGeneratorAlgorithm::ECC => gopenpgp_sys::KeyGenerationOptions::ECCurve25519,
            KeyGeneratorAlgorithm::RSA => gopenpgp_sys::KeyGenerationOptions::RSA4096,
        }
    }
}

impl From<SessionKeyAlgorithm> for gopenpgp_sys::SessionKeyAlgorithm {
    fn from(val: SessionKeyAlgorithm) -> Self {
        match val {
            SessionKeyAlgorithm::Aes128 => gopenpgp_sys::SessionKeyAlgorithm::Aes128,
            SessionKeyAlgorithm::Aes256 | SessionKeyAlgorithm::Unknown => {
                gopenpgp_sys::SessionKeyAlgorithm::Aes256
            }
        }
    }
}

impl From<gopenpgp_sys::SessionKeyAlgorithm> for SessionKeyAlgorithm {
    fn from(value: gopenpgp_sys::SessionKeyAlgorithm) -> Self {
        match value {
            gopenpgp_sys::SessionKeyAlgorithm::Aes128 => SessionKeyAlgorithm::Aes128,
            gopenpgp_sys::SessionKeyAlgorithm::Aes256 => SessionKeyAlgorithm::Aes256,
            _ => SessionKeyAlgorithm::Unknown,
        }
    }
}

/// Generates a new session key using the specified algorithm.
pub(super) fn generate_session_key(algorithm: SessionKeyAlgorithm) -> crate::Result<GoSessionKey> {
    gopenpgp_sys::SessionKey::generate(algorithm.into())
        .map(GoSessionKey)
        .map_err(Into::into)
}

/// Imports a session key from a byte slice using the specified algorithm.
pub(super) fn session_key_import(
    session_key: impl AsRef<[u8]>,
    algorithm: SessionKeyAlgorithm,
) -> GoSessionKey {
    GoSessionKey(gopenpgp_sys::SessionKey::from_token(
        session_key.as_ref(),
        algorithm.into(),
    ))
}

/// Exports a session key into a byte slice and retrieves its algorithm.
pub(super) fn session_key_export(
    session_key: &GoSessionKey,
) -> crate::Result<(impl AsRef<[u8]>, SessionKeyAlgorithm)> {
    let data = session_key.0.export_token();
    let algorithm = session_key.0.algorithm()?;
    Ok((data, algorithm.into()))
}

/// Imports a public key from a byte slice with the specified encoding.
pub(super) fn public_key_import(
    public_key: impl AsRef<[u8]>,
    encoding: DataEncoding,
) -> crate::Result<GoPublicKey> {
    let public_key = gopenpgp_sys::PublicKey::import(public_key.as_ref(), encoding.into())?;
    Ok(GoPublicKey(public_key))
}

/// Exports a public key into a byte slice using the specified encoding.
pub(super) fn public_key_export(
    public_key: &GoPublicKey,
    encoding: DataEncoding,
) -> crate::Result<impl AsRef<[u8]>> {
    (match encoding {
        DataEncoding::Bytes => public_key.0.export(false),
        _ => public_key.0.export(true),
    })
    .map_err(Into::into)
}

/// Imports a private key from a byte slice using the specified encoding and passphrase.
pub(super) fn private_key_import(
    private_key: impl AsRef<[u8]>,
    passphrase: impl AsRef<[u8]>,
    encoding: DataEncoding,
) -> crate::Result<GoPrivateKey> {
    let private_key = gopenpgp_sys::PrivateKey::import(
        private_key.as_ref(),
        passphrase.as_ref(),
        encoding.into(),
    )?;
    Ok(GoPrivateKey(private_key))
}

/// Exports a private key into a byte slice using the specified encoding and passphrase.
pub(super) fn private_key_export(
    private_key: &GoPrivateKey,
    passphrase: impl AsRef<[u8]>,
    encoding: DataEncoding,
) -> crate::Result<impl AsRef<[u8]>> {
    (match encoding {
        DataEncoding::Bytes => private_key.0.export(passphrase.as_ref(), false),
        _ => private_key.0.export(passphrase.as_ref(), true),
    })
    .map_err(Into::into)
}

/// Imports an unlocked private key from a byte slice using the specified encoding.
pub(super) fn private_key_import_unlocked(
    private_key: impl AsRef<[u8]>,
    encoding: DataEncoding,
) -> crate::Result<GoPrivateKey> {
    let private_key =
        gopenpgp_sys::PrivateKey::import_unlocked(private_key.as_ref(), encoding.into())?;
    Ok(GoPrivateKey(private_key))
}

/// Exports an unlocked private key into a byte slice using the specified encoding.
pub(super) fn private_key_export_unlocked(
    private_key: &GoPrivateKey,
    encoding: DataEncoding,
) -> crate::Result<impl AsRef<[u8]>> {
    (match encoding {
        DataEncoding::Bytes => private_key.0.export_unlocked(false),
        _ => private_key.0.export_unlocked(true),
    })
    .map_err(Into::into)
}

/// Converts a private key into a public key.
pub(super) fn private_key_to_public_key(private_key: &GoPrivateKey) -> crate::Result<GoPublicKey> {
    private_key
        .0
        .to_public_key()
        .map(GoPublicKey)
        .map_err(Into::into)
}
