use base64::{prelude::BASE64_STANDARD, Engine as _};
use proton_crypto::crypto::{
    AsPublicKeyRef, DataEncoding, Decryptor, DecryptorSync, Encryptor, EncryptorSync,
    PGPProviderSync, Signer, SignerSync, Verifier, VerifierSync,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    errors::RecoverySecretError,
    keys::{UnlockedUserKey, UnlockedUserKeys},
};

/// The unverified recovery secret loaded from the server.
#[derive(Clone)]
pub struct UnverifiedRecoverySecret {
    pub base64_secret: Zeroizing<String>,
    pub armored_signature: String,
}

impl UnverifiedRecoverySecret {
    pub fn new(base64_secret: impl Into<Zeroizing<String>>, armored_signature: String) -> Self {
        Self {
            base64_secret: base64_secret.into(),
            armored_signature,
        }
    }

    /// Verifies the recovery secret signature and transforms it into a verified recovery secret.
    pub fn verify<P: PGPProviderSync>(
        self,
        pgp: &P,
        unlocked_key: &UnlockedUserKey<P>,
    ) -> Result<VerifiedRecoverySecret, RecoverySecretError> {
        pgp.new_verifier()
            .with_verification_key(unlocked_key.as_public_key())
            .verify_detached(
                &self.base64_secret,
                self.armored_signature.as_bytes(),
                DataEncoding::Armor,
            )
            .map_err(RecoverySecretError::VerifySignature)?;

        Ok(VerifiedRecoverySecret {
            base64_secret: self.base64_secret,
            armored_signature: self.armored_signature,
        })
    }
}

/// A recovery secret that has been successfully verified.
#[derive(Clone)]
pub struct VerifiedRecoverySecret {
    pub base64_secret: Zeroizing<String>,
    pub armored_signature: String,
}

impl VerifiedRecoverySecret {
    /// Generates a new recovery secret and signs it with the primary user key.
    pub fn generate<P: PGPProviderSync>(
        pgp: &P,
        unlocked_keys: &UnlockedUserKeys<P>,
    ) -> Result<Self, RecoverySecretError> {
        let raw = Zeroizing::new(proton_crypto::generate_secure_random_bytes::<32>());
        let base64_secret = Zeroizing::new(BASE64_STANDARD.encode(raw));

        let primary_key = unlocked_keys
            .primary()
            .ok_or(RecoverySecretError::NoPrimary)?;

        let signature = pgp
            .new_signer()
            .with_signing_key(primary_key.as_ref())
            .with_utf8()
            .sign_detached(base64_secret.as_bytes(), DataEncoding::Armor)
            .map_err(RecoverySecretError::SignatureCreation)?;

        let armored_signature =
            String::from_utf8(signature).map_err(|_| RecoverySecretError::SignatureEncoding)?;

        Ok(Self {
            base64_secret,
            armored_signature,
        })
    }

    /// Serializes the unlocked user keys and encrypts them with the recovery secret.
    pub fn create_recovery_data<P: PGPProviderSync>(
        &self,
        pgp: &P,
        unlocked_keys: &UnlockedUserKeys<P>,
    ) -> Result<Vec<u8>, RecoverySecretError> {
        let blob = unlocked_keys
            .serialize_to_recovery_blob(pgp)
            .map_err(RecoverySecretError::ExportKey)?;

        let encrypted = pgp
            .new_encryptor()
            .with_passphrase(&self.base64_secret)
            .encrypt_raw(&blob, DataEncoding::Bytes)
            .map_err(RecoverySecretError::Encrypt)?;

        Ok(encrypted)
    }

    /// Computes the SHA-256 hash of the recovery secret.
    pub fn secret_hash(&self) -> String {
        let hash = Sha256::digest(self.base64_secret.as_bytes());
        BASE64_STANDARD.encode(hash)
    }
}

/// Tries to decrypt the recovery data with the provided recovery secrets
/// and returns the unlocked user keys.
pub fn decrypt_recovery_data<'a, P: PGPProviderSync>(
    pgp: &P,
    encrypted: &[u8],
    recovery_secrets: impl IntoIterator<Item = &'a str>,
) -> Result<UnlockedUserKeys<P>, RecoverySecretError> {
    let mut last_error = None;

    for recovery_secret in recovery_secrets {
        let decrypted_result = pgp
            .new_decryptor()
            .with_passphrase(recovery_secret)
            .decrypt(encrypted, DataEncoding::Bytes);

        match decrypted_result {
            Ok(decrypted) => {
                return UnlockedUserKeys::deserialize_from_recovery_blob(pgp, decrypted.as_ref())
                    .map_err(RecoverySecretError::ImportKey);
            }
            Err(e) => {
                last_error = Some(RecoverySecretError::Decrypt(e));
            }
        }
    }

    Err(last_error.unwrap_or(RecoverySecretError::NoMatchingSecret))
}
