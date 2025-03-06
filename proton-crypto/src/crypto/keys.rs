use std::future::Future;

use crate::{OpenPGPFingerprint, OpenPGPKeyID, SHA256Fingerprint, UnixTimestamp};

use super::SessionKeyAlgorithm;

/// Represents a PGP session key.
pub trait SessionKey: Clone + Send + Sync {
    /// Export the session key as bytes.
    fn export(&self) -> impl AsRef<[u8]>;

    /// Returns the algorithm of the session key.
    ///
    /// Can be unknown if extracted from a v6 PKESK packet.
    fn algorithm(&self) -> SessionKeyAlgorithm;
}

/// Represents a PGP key containing public keys.
pub trait PublicKey: AccessKeyInfo + Clone + AsPublicKeyRef<Self> + Send + Sync {}

/// Represents a PGP key containing unlocked private keys.
pub trait PrivateKey: AccessKeyInfo + Clone + AsRef<Self> + Send + Sync {}

/// A customized `AsRef` trait for public keys to avoid conflicting implementations.
///
/// Some higher level key data types might contain a private and a public key.
/// To allow providing such data types in the API as public keys, the API introduces
/// a customized trait that the type implements.
/// For private keys `AsRef` is used instead.
pub trait AsPublicKeyRef<T: PublicKey> {
    /// Returns a reference to a public key.
    fn as_public_key(&self) -> &T;
}

/// Also implement [`AsPublicKeyRef`] on the reference of a type that implements it.
impl<Pub: PublicKey, PubKeyRefImpl: AsPublicKeyRef<Pub>> AsPublicKeyRef<Pub> for &PubKeyRefImpl {
    fn as_public_key(&self) -> &Pub {
        PubKeyRefImpl::as_public_key(self)
    }
}

/// Defines how information can be accessed from `OpenPGP` keys.
pub trait AccessKeyInfo {
    /// Returns the `OpenPGP` version of the key.
    fn version(&self) -> u8;

    /// Returns the `OpenPGP` key ID of the primary key.
    fn key_id(&self) -> OpenPGPKeyID;

    /// Returns the `OpenPGP` key fingerprint of the primary key.
    fn key_fingerprint(&self) -> OpenPGPFingerprint;

    /// Returns the SHA256 key fingerprints of all keys within the `OpenPGP` key.
    fn sha256_key_fingerprints(&self) -> Vec<SHA256Fingerprint>;

    /// Indicates if the `OpenPGP` key can encrypt.
    fn can_encrypt(&self, unix_time: UnixTimestamp) -> bool;

    /// Indicates if the `OpenPGP` key can verify a signature.
    fn can_verify(&self, unix_time: UnixTimestamp) -> bool;

    /// Indicates if the `OpenPGP` key is expired.
    fn is_expired(&self, unix_time: UnixTimestamp) -> bool;

    /// Indicates if the `OpenPGP` key is revoked.
    fn is_revoked(&self, unix_time: UnixTimestamp) -> bool;
}

/// The key algorithm type.
#[derive(Default, Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum KeyGeneratorAlgorithm {
    /// Keys generated will be for use with elliptic curve cryptography
    #[default]
    ECC,
    /// A key with RSA.
    RSA,
}

/// Provides a builder API to generate `OpenPGP` keys.
pub trait KeyGenerator {
    /// Add a `OpenPGP` user id to the key that will be generated.
    fn with_user_id(self, name: &str, email: &str) -> Self;

    /// Override the key generation time to the provided unix time stamp.
    fn with_generation_time(self, unix_time: UnixTimestamp) -> Self;

    /// Set the key algorithm type that should be used.
    fn with_algorithm(self, option: KeyGeneratorAlgorithm) -> Self;
}

pub trait KeyGeneratorSync<PrivKey: PrivateKey>: KeyGenerator {
    /// Generates the `OpenPGP` private key.
    ///
    /// Generates a Proton compatible `OpenPGP` private key with the system's
    /// secure random number generator.
    ///
    /// # Examples
    ///
    /// ```
    /// use proton_crypto::new_pgp_provider;
    /// use proton_crypto::crypto::{PGPProviderSync, KeyGenerator, KeyGeneratorSync};
    /// let pgp_provider = new_pgp_provider();
    /// let key = pgp_provider
    ///     .new_key_generator()
    ///     .with_user_id("test", "test@test.test")
    ///     .generate();
    /// ```
    fn generate(self) -> crate::Result<PrivKey>;
}

pub trait KeyGeneratorAsync<PrivKey: PrivateKey>: KeyGenerator {
    /// Generates the `OpenPGP` private key.
    ///
    /// Generates a Proton compatible `OpenPGP` private key with the system's
    /// secure random number generator.
    ///
    /// # Examples
    ///
    /// ```
    /// use proton_crypto::new_pgp_provider_async;
    /// use proton_crypto::crypto::{PGPProviderAsync, KeyGenerator, KeyGeneratorAsync};
    /// let pgp_provider = new_pgp_provider_async();
    /// let key_future = pgp_provider
    ///     .new_key_generator_async()
    ///     .with_user_id("test", "test@test.test")
    ///     .generate_async();
    /// ```
    fn generate_async(self) -> impl Future<Output = crate::Result<PrivKey>>;
}
