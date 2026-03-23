use proton_crypto::{crypto::AccessKeyInfo, ProtonPGP};
use proton_crypto_account::{
    keys::UnlockedUserKeys,
    recovery::{decrypt_recovery_data, UnverifiedRecoverySecret, VerifiedRecoverySecret},
};
use zeroize::Zeroizing;

use crate::common::{get_test_decrypted_user_key, TEST_USER_KEY, TEST_USER_KEY_CHANGED};

mod common;

#[test]
fn encrypt_decrypt_roundtrip() {
    let pgp = ProtonPGP::new_sync();
    let secret = "dGVzdC1yZWNvdmVyeS1zZWNyZXQtYmFzZTY0LWVuYw=="; // nosemgrep: generic-secret
    let keys = UnlockedUserKeys::from(get_test_decrypted_user_key(&pgp, TEST_USER_KEY));

    let rs = VerifiedRecoverySecret {
        base64_secret: Zeroizing::new(secret.to_string()),
        armored_signature: String::new(), // Ignore signature.
    };
    let encrypted = rs.create_recovery_data(&pgp, &keys).unwrap();
    let decrypted = decrypt_recovery_data(&pgp, &encrypted, [secret]).unwrap();

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
    let pgp = ProtonPGP::new_sync();
    let keys = UnlockedUserKeys::from(get_test_decrypted_user_key(&pgp, TEST_USER_KEY));

    let rs = VerifiedRecoverySecret {
        base64_secret: Zeroizing::new("correct-secret".to_string()),
        armored_signature: String::new(),
    };
    let encrypted = rs.create_recovery_data(&pgp, &keys).unwrap();
    let result = decrypt_recovery_data(&pgp, &encrypted, ["wrong-secret"]);

    assert!(result.is_err());
}

#[test]
fn generate_returns_verified_secret() {
    let pgp = ProtonPGP::new_sync();
    let key = get_test_decrypted_user_key(&pgp, TEST_USER_KEY);
    let keys = UnlockedUserKeys::from(key);

    let secret = VerifiedRecoverySecret::generate(&pgp, &keys);

    assert!(secret.is_ok());
}

#[test]
fn verify_secret_with_correct_signature_succeeds() {
    let pgp = ProtonPGP::new_sync();
    let key = get_test_decrypted_user_key(&pgp, TEST_USER_KEY);
    let keys = UnlockedUserKeys::from(key);

    let verified = VerifiedRecoverySecret::generate(&pgp, &keys).unwrap();
    let bad = UnverifiedRecoverySecret {
        base64_secret: verified.base64_secret,
        armored_signature: verified.armored_signature,
    };
    let result = bad.verify(&pgp, keys.first().unwrap());

    assert!(result.is_ok());
}

#[test]
fn verify_secret_with_wrong_signature_fails() {
    let pgp = ProtonPGP::new_sync();
    let key = get_test_decrypted_user_key(&pgp, TEST_USER_KEY);
    let keys = UnlockedUserKeys::from(key);

    let verified = VerifiedRecoverySecret::generate(&pgp, &keys).unwrap();
    let bad = UnverifiedRecoverySecret {
        base64_secret: verified.base64_secret,
        armored_signature: "bad-signature".to_string(),
    };
    let result = bad.verify(&pgp, keys.first().unwrap());

    assert!(result.is_err());
}

#[test]
fn verify_secret_with_different_key_fails() {
    let pgp = ProtonPGP::new_sync();
    let key_a = get_test_decrypted_user_key(&pgp, TEST_USER_KEY);
    let key_b = get_test_decrypted_user_key(&pgp, TEST_USER_KEY_CHANGED);

    let verified = VerifiedRecoverySecret::generate(&pgp, &UnlockedUserKeys::from(key_a)).unwrap();
    let unverified = UnverifiedRecoverySecret {
        base64_secret: verified.base64_secret,
        armored_signature: verified.armored_signature,
    };
    let result = unverified.verify(&pgp, key_b.first().unwrap());

    assert!(result.is_err());
}
