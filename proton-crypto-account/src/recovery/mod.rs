use base64::{prelude::BASE64_STANDARD, Engine as _};
use proton_crypto::crypto::{
    DataEncoding, Decryptor, DecryptorSync, Encryptor, EncryptorSync, PGPProviderSync, Signer,
    SignerSync, Verifier, VerifierSync,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::keys::UnlockedUserKeys;

#[derive(Debug, thiserror::Error)]
pub enum RecoverySecretError {
    #[error("failed to sign recovery secret")]
    Sign,

    #[error("failed to encrypt recovery data")]
    Encrypt,

    #[error("failed to decrypt recovery data")]
    Decrypt,

    #[error("failed to verify recovery secret signature")]
    VerifySignature,

    #[error("failed to export private key")]
    ExportKey,
}

pub struct UnverifiedRecoverySecret {
    pub base64_secret: Zeroizing<String>,
    pub armored_signature: String,
}

impl UnverifiedRecoverySecret {
    pub fn verify<P: PGPProviderSync>(
        self,
        pgp: &P,
        unlocked_keys: &UnlockedUserKeys<P>,
    ) -> Result<VerifiedRecoverySecret, RecoverySecretError> {
        let primary_key = unlocked_keys
            .primary()
            .ok_or(RecoverySecretError::VerifySignature)?;

        pgp.new_verifier()
            .with_verification_key(&primary_key.public_key)
            .verify_detached(
                self.base64_secret.as_bytes(),
                self.armored_signature.as_bytes(),
                DataEncoding::Armor,
            )
            .map_err(|_| RecoverySecretError::VerifySignature)?;

        Ok(VerifiedRecoverySecret {
            base64_secret: self.base64_secret,
            armored_signature: self.armored_signature,
        })
    }
}

pub struct VerifiedRecoverySecret {
    pub base64_secret: Zeroizing<String>,
    pub armored_signature: String,
}

impl VerifiedRecoverySecret {
    pub fn generate<P: PGPProviderSync>(
        pgp: &P,
        unlocked_keys: &UnlockedUserKeys<P>,
    ) -> Result<Self, RecoverySecretError> {
        let raw = Zeroizing::new(proton_crypto::generate_secure_random_bytes::<32>());
        let base64_secret = Zeroizing::new(BASE64_STANDARD.encode(*raw));

        let primary_key = unlocked_keys.primary().ok_or(RecoverySecretError::Sign)?;

        let signature = pgp
            .new_signer()
            .with_signing_key(primary_key.as_ref())
            .with_utf8()
            .sign_detached(base64_secret.as_bytes(), DataEncoding::Armor)
            .map_err(|_| RecoverySecretError::Sign)?;

        let armored_signature =
            String::from_utf8(signature).map_err(|_| RecoverySecretError::Sign)?;

        Ok(Self {
            base64_secret,
            armored_signature,
        })
    }

    pub fn create_recovery_data<P: PGPProviderSync>(
        &self,
        pgp: &P,
        unlocked_keys: &UnlockedUserKeys<P>,
    ) -> Result<Vec<u8>, RecoverySecretError> {
        let blob = unlocked_keys
            .serialize_to_recovery_blob(pgp)
            .map_err(|_| RecoverySecretError::ExportKey)?;

        let encrypted = pgp
            .new_encryptor()
            .with_passphrase(self.base64_secret.as_str())
            .encrypt_raw(&blob, DataEncoding::Bytes)
            .map_err(|_| RecoverySecretError::Encrypt)?;

        Ok(encrypted)
    }

    pub fn decrypt_recovery_data<P: PGPProviderSync>(
        pgp: &P,
        encrypted: &[u8],
        recovery_secret: &str,
    ) -> Result<UnlockedUserKeys<P>, RecoverySecretError> {
        let decrypted = pgp
            .new_decryptor()
            .with_passphrase(recovery_secret)
            .decrypt(encrypted, DataEncoding::Bytes)
            .map_err(|_| RecoverySecretError::Decrypt)?;

        UnlockedUserKeys::deserialize_from_recovery_blob(pgp, decrypted.as_ref())
            .map_err(|_| RecoverySecretError::Decrypt)
    }

    pub fn secret_hash(&self) -> String {
        let hash = Sha256::digest(self.base64_secret.as_bytes());
        BASE64_STANDARD.encode(hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{DecryptedUserKey, KeyId, UnlockedUserKeys};
    use proton_crypto::crypto::{
        AccessKeyInfo, KeyGenerator, KeyGeneratorSync, PrivateKey, PublicKey,
    };
    use proton_crypto::new_pgp_provider;

    impl VerifiedRecoverySecret {
        pub fn from_secret(secret: &str) -> Self {
            Self {
                base64_secret: Zeroizing::new(secret.to_owned()),
                armored_signature: String::new(),
            }
        }
    }

    fn generate_unlocked_user_key<P: PGPProviderSync>(
        pgp: &P,
        id: &str,
    ) -> DecryptedUserKey<P::PrivateKey, P::PublicKey>
    where
        P::PrivateKey: PrivateKey,
        P::PublicKey: PublicKey,
    {
        let private_key = pgp
            .new_key_generator()
            .with_user_id("test", "test@test.test")
            .generate()
            .unwrap();
        let public_key = pgp.private_key_to_public_key(&private_key).unwrap();
        DecryptedUserKey {
            id: KeyId::from(id),
            private_key,
            public_key,
        }
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let pgp = new_pgp_provider();
        let secret = "dGVzdC1yZWNvdmVyeS1zZWNyZXQtYmFzZTY0LWVuYw=="; // nosemgrep: generic-secret
        let keys = UnlockedUserKeys::from(vec![
            generate_unlocked_user_key(&pgp, "key-1"),
            generate_unlocked_user_key(&pgp, "key-2"),
        ]);

        let rs = VerifiedRecoverySecret::from_secret(secret);
        let encrypted = rs.create_recovery_data(&pgp, &keys).unwrap();
        let decrypted =
            VerifiedRecoverySecret::decrypt_recovery_data(&pgp, &encrypted, secret).unwrap();

        assert_eq!(decrypted.len(), keys.len());

        let original_fingerprints: Vec<_> = keys
            .iter()
            .map(|k| k.public_key.key_fingerprint().to_string())
            .collect();
        let recovered_ids: Vec<_> = decrypted.iter().map(|k| k.id.0.clone()).collect();
        assert_eq!(original_fingerprints, recovered_ids);
    }

    #[test]
    fn decrypt_with_wrong_secret_fails() {
        let pgp = new_pgp_provider();
        let keys = UnlockedUserKeys::from(vec![generate_unlocked_user_key(&pgp, "key-1")]);

        let rs = VerifiedRecoverySecret::from_secret("correct-secret");
        let encrypted = rs.create_recovery_data(&pgp, &keys).unwrap();
        let result =
            VerifiedRecoverySecret::decrypt_recovery_data(&pgp, &encrypted, "wrong-secret");

        assert!(result.is_err());
    }

    #[test]
    fn generate_returns_verified_secret() {
        let pgp = new_pgp_provider();
        let key = generate_unlocked_user_key(&pgp, "key-1");
        let keys = UnlockedUserKeys::from(vec![key]);

        let secret = VerifiedRecoverySecret::generate(&pgp, &keys);

        assert!(secret.is_ok());
    }

    #[test]
    fn verify_secret_with_wrong_signature_fails() {
        let pgp = new_pgp_provider();
        let key = generate_unlocked_user_key(&pgp, "key-1");
        let keys = UnlockedUserKeys::from(vec![key]);

        let verified = VerifiedRecoverySecret::generate(&pgp, &keys).unwrap();
        let bad = UnverifiedRecoverySecret {
            base64_secret: verified.base64_secret,
            armored_signature: "bad-signature".to_string(),
        };
        let result = bad.verify(&pgp, &keys);

        assert!(result.is_err());
    }

    #[test]
    fn verify_secret_with_different_key_fails() {
        let pgp = new_pgp_provider();
        let key_a = generate_unlocked_user_key(&pgp, "key-a");
        let key_b = generate_unlocked_user_key(&pgp, "key-b");

        let verified =
            VerifiedRecoverySecret::generate(&pgp, &UnlockedUserKeys::from(vec![key_a])).unwrap();
        let unverified = UnverifiedRecoverySecret {
            base64_secret: verified.base64_secret,
            armored_signature: verified.armored_signature,
        };
        let result = unverified.verify(&pgp, &UnlockedUserKeys::from(vec![key_b]));

        assert!(result.is_err());
    }

    #[test]
    fn verify_secret_with_empty_keys_fails() {
        let pgp = new_pgp_provider();
        let key = generate_unlocked_user_key(&pgp, "key-1");
        let verified =
            VerifiedRecoverySecret::generate(&pgp, &UnlockedUserKeys::from(vec![key])).unwrap();

        let unverified = UnverifiedRecoverySecret {
            base64_secret: verified.base64_secret,
            armored_signature: verified.armored_signature,
        };
        let result = unverified.verify(&pgp, &UnlockedUserKeys::from(vec![]));

        assert!(result.is_err());
    }
}
