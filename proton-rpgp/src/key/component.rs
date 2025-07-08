use pgp::{
    composed::PlainSessionKey,
    crypto::public_key::PublicKeyAlgorithm,
    packet::{self, PublicKeyEncryptedSessionKey},
    types::{
        Fingerprint, KeyDetails, KeyId, KeyVersion, PkeskVersion, PublicKeyTrait, SecretKeyTrait,
        SecretParams,
    },
};

use crate::DecryptionError;

/// Represents a view on a selected pulic component key in an `OpenPGP` key.
///
/// Since an `OpenPGP` key can contain multiple actual keys, an operation must
/// select one. A public component key represenst such a selected key.

#[derive(Debug)]
pub(crate) struct PublicComponentKey<'a> {
    /// The public key part of the component key (either a primary or subkey).
    pub(crate) public_key: &'a dyn PublicKeyTrait,

    /// The primary self-certification of the component key.
    pub(crate) primary_self_certification: &'a packet::Signature,

    /// The self-certification of the component key.
    ///
    /// If the component key is a primary key, it points to the same signature
    /// as `primary_self_certification`
    pub(crate) self_certification: &'a packet::Signature,
}

impl<'a> PublicComponentKey<'a> {
    pub fn new(
        public_key: &'a dyn PublicKeyTrait,
        primary_self_certification: &'a packet::Signature,
        self_certification: &'a packet::Signature,
    ) -> Self {
        Self {
            public_key,
            primary_self_certification,
            self_certification,
        }
    }
}

/// Represents a view on a selected secret component key in an `OpenPGP` key.
///
/// Since an `OpenPGP` key can contain multiple actual keys, an operation must
/// select one. A secret component key represenst such a selected key.
#[derive(Debug)]
pub(crate) struct PrivateComponentKey<'a> {
    /// The secret key part of the component key (either a primary or subkey).
    ///
    /// We use a custom enum type because the secret key trait [`SecretKeyTrait`]
    /// does not include any decryption methods.
    pub(crate) private_key: AnySecretKey<'a>,

    /// The primary self-certification of the component key.
    pub(crate) primary_self_certification: &'a packet::Signature,

    /// The self-certification of the component key.
    ///
    pub(crate) self_certification: &'a packet::Signature,
}

impl<'a> PrivateComponentKey<'a> {
    pub(crate) fn new(
        private_key: AnySecretKey<'a>,
        primary_self_certification: &'a packet::Signature,
        self_certification: &'a packet::Signature,
    ) -> Self {
        Self {
            private_key,
            primary_self_certification,
            self_certification,
        }
    }
}

/// The [`SecretKeyTrait`] does not expose decryption methods. Thus, we
/// need an explicit enum type covering all secret key types.
/// [`AnySecretKey`] either represents a secret primary or secret subkey.
#[derive(Debug, Clone)]
pub enum AnySecretKey<'a> {
    /// A secret primary key.
    PrimarySecretKey(&'a packet::SecretKey),

    /// A secret subkey.
    SecretSubKey(&'a packet::SecretSubkey),
}

impl KeyDetails for AnySecretKey<'_> {
    fn version(&self) -> KeyVersion {
        match self {
            AnySecretKey::PrimarySecretKey(key) => key.version(),
            AnySecretKey::SecretSubKey(key) => key.version(),
        }
    }

    fn fingerprint(&self) -> Fingerprint {
        match self {
            AnySecretKey::PrimarySecretKey(key) => key.fingerprint(),
            AnySecretKey::SecretSubKey(key) => key.fingerprint(),
        }
    }

    fn key_id(&self) -> KeyId {
        match self {
            AnySecretKey::PrimarySecretKey(key) => key.key_id(),
            AnySecretKey::SecretSubKey(key) => key.key_id(),
        }
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        match &self {
            AnySecretKey::PrimarySecretKey(key) => key.algorithm(),
            AnySecretKey::SecretSubKey(key) => key.algorithm(),
        }
    }
}

impl SecretKeyTrait for AnySecretKey<'_> {
    fn create_signature(
        &self,
        key_pw: &pgp::types::Password,
        hash: pgp::crypto::hash::HashAlgorithm,
        data: &[u8],
    ) -> pgp::errors::Result<pgp::types::SignatureBytes> {
        match self {
            AnySecretKey::PrimarySecretKey(key) => key.create_signature(key_pw, hash, data),
            AnySecretKey::SecretSubKey(key) => key.create_signature(key_pw, hash, data),
        }
    }

    fn hash_alg(&self) -> pgp::crypto::hash::HashAlgorithm {
        match self {
            AnySecretKey::PrimarySecretKey(key) => key.hash_alg(),
            AnySecretKey::SecretSubKey(key) => key.hash_alg(),
        }
    }
}

#[allow(clippy::match_wildcard_for_single_variants)]
impl AnySecretKey<'_> {
    fn decrypt_session_key(
        &self,
        pkesk: &PublicKeyEncryptedSessionKey,
    ) -> Result<PlainSessionKey, DecryptionError> {
        let esk_type = match pkesk.version() {
            PkeskVersion::V3 => pgp::types::EskType::V3_4,
            PkeskVersion::V6 => pgp::types::EskType::V6,
            v => return Err(DecryptionError::InvalidPkesk(v)),
        };
        match self {
            AnySecretKey::PrimarySecretKey(secret_key) => match secret_key.secret_params() {
                SecretParams::Plain(plain_secret_params) => {
                    let public_key = secret_key.public_key();
                    plain_secret_params
                        .decrypt(
                            public_key.public_params(),
                            pkesk.values()?,
                            esk_type,
                            public_key,
                        )
                        .map_err(DecryptionError::Pkesk)
                }
                SecretParams::Encrypted(_) => Err(DecryptionError::LockedKey),
            },
            AnySecretKey::SecretSubKey(secret_subkey) => match secret_subkey.secret_params() {
                SecretParams::Plain(plain_secret_params) => {
                    let public_key = secret_subkey.public_key();
                    plain_secret_params
                        .decrypt(
                            public_key.public_params(),
                            pkesk.values()?,
                            esk_type,
                            public_key,
                        )
                        .map_err(DecryptionError::Pkesk)
                }
                SecretParams::Encrypted(_) => Err(DecryptionError::LockedKey),
            },
        }
    }
}
