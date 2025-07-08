use pgp::types::{Fingerprint, Imprint, KeyDetails, KeyId, KeyVersion};
use sha2::Sha256;

use crate::{
    check_key_expired, AsPublicKeyRef, CertifiationSelectionExt, FingerprintSha256,
    KeySelectionError, Profile, PublicKeySelectionExt, SignatureUsage, UnixTime,
};

/// A trait for types that can provide information about an `OpenPGP` key.
pub trait KeyInfo {
    /// Returns the `OpenPGP` key version.
    fn version(&self) -> u8;

    /// Returns the key id of the `OpenPGP` primary key.
    fn key_id(&self) -> KeyId;

    /// Returns the fingerprint of the `OpenPGP` primary key.
    fn fingerprint(&self) -> Fingerprint;

    /// Returns the key ids of the `OpenPGP` primary key and its subkeys.
    fn key_ids(&self) -> Vec<KeyId>;

    /// Returns the fingerprints of the `OpenPGP` primary key and its subkeys.
    fn fingerprints(&self) -> Vec<Fingerprint>;

    /// Returns sha256 fingerprints of the key and its subkeys.
    ///
    /// If creation fails, the fingerprint is set to the zero value.
    fn fingerprints_sha256(&self) -> Vec<FingerprintSha256>;

    /// Checks if the key can encrypt at the given unixtime.
    ///
    /// Returns an error if no valid encryption key can be found.
    fn can_encrypt(&self, profile: &Profile, date: UnixTime) -> Result<(), KeySelectionError>;

    /// Checks if any of the keys can be used for verification at the given date.
    ///
    /// Returns an error if no valid verification keys can be found.
    fn can_verify(&self, profile: &Profile, date: UnixTime) -> Result<(), KeySelectionError>;

    /// Checks if the primray key is expired at the given date.
    ///
    /// Also retruns `true` if no valid primary self-certification can be found.
    fn is_expired(&self, profile: &Profile, date: UnixTime) -> bool;

    /// Checks if the primary key is revoked at the given date.
    ///
    /// Note that third-party revocation signatures are not supported.
    /// Note also that Identity and Subkey revocation should be checked separately.
    fn is_revoked(&self, profile: &Profile, date: UnixTime) -> bool;
}

// Implement the `KeyInfo` trait for types that can access a `PublicKey` reference.
impl<T: AsPublicKeyRef> KeyInfo for T {
    /// Returns the `OpenPGP` key version.
    fn version(&self) -> u8 {
        let version = self.as_public_key().as_signed_public_key().version();
        match version {
            KeyVersion::V2 => 2,
            KeyVersion::V3 => 3,
            KeyVersion::V4 => 4,
            KeyVersion::V5 => 5,
            KeyVersion::V6 => 6,
            KeyVersion::Other(other) => other,
        }
    }

    /// Returns the key id of the `OpenPGP` primary key.
    fn key_id(&self) -> KeyId {
        self.as_public_key().as_signed_public_key().key_id()
    }

    /// Returns the fingerprint of the `OpenPGP` primary key.
    fn fingerprint(&self) -> Fingerprint {
        self.as_public_key().as_signed_public_key().fingerprint()
    }

    /// Returns the key ids of the `OpenPGP` primary key and its subkeys.
    fn key_ids(&self) -> Vec<KeyId> {
        let pub_key_ref = &self.as_public_key().as_signed_public_key();
        let mut output = Vec::with_capacity(pub_key_ref.public_subkeys.len() + 1);
        output.push(pub_key_ref.key_id());
        for subkey in &pub_key_ref.public_subkeys {
            output.push(subkey.key_id());
        }
        output
    }

    /// Returns the fingerprints of the `OpenPGP` primary key and its subkeys.
    fn fingerprints(&self) -> Vec<Fingerprint> {
        let pub_key_ref = &self.as_public_key().as_signed_public_key();
        let mut output = Vec::with_capacity(pub_key_ref.public_subkeys.len() + 1);
        output.push(pub_key_ref.fingerprint());
        for subkey in &pub_key_ref.public_subkeys {
            output.push(subkey.fingerprint());
        }
        output
    }

    /// Returns sha256 fingerprints of the key and its subkeys.
    ///
    /// If creation fails, the fingerprint is set to the zero value.
    fn fingerprints_sha256(&self) -> Vec<FingerprintSha256> {
        let mut fingerprints =
            Vec::with_capacity(self.as_public_key().inner.public_subkeys.len() + 1);
        let primary_fp = self
            .as_public_key()
            .inner
            .imprint::<Sha256>()
            .unwrap_or_default();
        fingerprints.push(FingerprintSha256(primary_fp.into()));
        for subkey in &self.as_public_key().inner.public_subkeys {
            let subkey_fp = subkey.imprint::<Sha256>().unwrap_or_default();
            fingerprints.push(FingerprintSha256(subkey_fp.into()));
        }
        fingerprints
    }

    /// Checks if the key can encrypt at the given unixtime.
    ///
    /// Returns an error if no valid encryption key can be found.
    fn can_encrypt(&self, profile: &Profile, date: UnixTime) -> Result<(), KeySelectionError> {
        self.as_public_key()
            .as_signed_public_key()
            .encryption_key(date, profile)
            .map(|_| ())
    }

    /// Checks if any of the keys can be used for verification at the given date.
    ///
    /// Returns an error if no valid verification keys can be found.
    fn can_verify(&self, profile: &Profile, date: UnixTime) -> Result<(), KeySelectionError> {
        self.as_public_key()
            .as_signed_public_key()
            .verification_keys(date, None, SignatureUsage::Sign, profile)
            .map(|_| ())
    }

    /// Checks if the primray key is expired at the given date.
    ///
    /// Also retruns `true` if no valid primary self-certification can be found.
    fn is_expired(&self, profile: &Profile, date: UnixTime) -> bool {
        let pub_key_ref = self.as_public_key().as_signed_public_key();
        let Ok(self_signature) = pub_key_ref.primary_self_signature(date, profile) else {
            return true;
        };

        check_key_expired(pub_key_ref, self_signature, date).is_err()
    }

    /// Checks if the primary key is revoked at the given date.
    ///
    /// Note that third-party revocation signatures are not supported.
    /// Note also that Identity and Subkey revocation should be checked separately.
    fn is_revoked(&self, profile: &Profile, date: UnixTime) -> bool {
        let pub_key_ref = self.as_public_key().as_signed_public_key();
        pub_key_ref.revoked(pub_key_ref.primary_key(), None, date, profile)
    }
}
