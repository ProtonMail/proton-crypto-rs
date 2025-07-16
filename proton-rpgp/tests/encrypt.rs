use proton_rpgp::{
    AsPublicKeyRef, DataEncoding, DecryptionError, Decryptor, Encryptor, PrivateKey,
    VerificationError,
};

pub const TEST_KEY: &str = include_str!("../test-data/keys/private_key_v4.asc");
pub const TEST_KEY_V6: &str = include_str!("../test-data/keys/private_key_v6.asc");

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn encrypt_message_v4() {
    let input_data = b"hello world";
    let key = PrivateKey::import_unlocked(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let encrypted_data = Encryptor::default()
        .with_encryption_key(key.as_public_key())
        .encrypt_raw(input_data, DataEncoding::Armored)
        .expect("Failed to encrypt");

    let verified_data = Decryptor::default()
        .with_decryption_key(&key)
        .decrypt(encrypted_data.as_slice(), DataEncoding::Armored)
        .expect("Failed to decrypt");

    assert_eq!(verified_data.data, input_data);
    assert!(matches!(
        verified_data.verification_result,
        Err(VerificationError::NotSigned)
    ));
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn encrypt_and_sign_message_v4() {
    let input_data = b"hello world";
    let key = PrivateKey::import_unlocked(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let encrypted_data = Encryptor::default()
        .with_encryption_key(key.as_public_key())
        .with_signing_key(&key)
        .encrypt_raw(input_data, DataEncoding::Armored)
        .expect("Failed to encrypt");

    let verified_data = Decryptor::default()
        .with_decryption_key(&key)
        .with_verification_key(key.as_public_key())
        .decrypt(encrypted_data.as_slice(), DataEncoding::Armored)
        .expect("Failed to decrypt");

    assert_eq!(verified_data.data, input_data);
    assert!(verified_data.verification_result.is_ok());
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn encrypt_and_sign_message_v6() {
    let input_data = b"hello world";
    let key = PrivateKey::import_unlocked(TEST_KEY_V6.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let encrypted_data = Encryptor::default()
        .with_encryption_key(key.as_public_key())
        .with_signing_key(&key)
        .encrypt_raw(input_data, DataEncoding::Armored)
        .expect("Failed to encrypt");

    let verified_data = Decryptor::default()
        .with_decryption_key(&key)
        .with_verification_key(key.as_public_key())
        .decrypt(encrypted_data.as_slice(), DataEncoding::Armored)
        .expect("Failed to decrypt");

    assert_eq!(verified_data.data, input_data);
    assert!(verified_data.verification_result.is_ok());
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn encrypt_and_sign_message_v4_message_api() {
    let input_data = b"hello world";
    let key = PrivateKey::import_unlocked(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let encrypted_data = Encryptor::default()
        .with_encryption_key(key.as_public_key())
        .with_signing_key(&key)
        .encrypt(input_data)
        .expect("Failed to encrypt");

    let armored_message = encrypted_data.armor().expect("Failed to armor");
    let revealed_session_key = encrypted_data
        .revealed_session_key()
        .expect("Failed to get revealed session key");

    let verified_data = Decryptor::default()
        .with_decryption_key(&key)
        .with_verification_key(key.as_public_key())
        .decrypt(armored_message.as_slice(), DataEncoding::Armored)
        .expect("Failed to decrypt");

    assert!(revealed_session_key.len() > 16);
    assert_eq!(verified_data.data, input_data);
    assert!(verified_data.verification_result.is_ok());
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn encrypt_message_to_multiple_recipients() {
    let input_data = b"hello world";
    let key_alice = PrivateKey::import_unlocked(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");
    let key_bob = PrivateKey::import_unlocked(TEST_KEY_V6.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let encrypted_data = Encryptor::default()
        .with_encryption_keys([key_alice.as_public_key(), key_bob.as_public_key()])
        .encrypt_raw(input_data, DataEncoding::Armored)
        .expect("Failed to encrypt");

    let verified_data = Decryptor::default()
        .with_decryption_key(&key_alice)
        .decrypt(encrypted_data.as_slice(), DataEncoding::Armored)
        .expect("Failed to decrypt");

    assert_eq!(verified_data.data, input_data);
    assert!(matches!(
        verified_data.verification_result,
        Err(VerificationError::NotSigned)
    ));

    let verified_data = Decryptor::default()
        .with_decryption_key(&key_bob)
        .decrypt(encrypted_data.as_slice(), DataEncoding::Armored)
        .expect("Failed to decrypt");

    assert_eq!(verified_data.data, input_data);
    assert!(matches!(
        verified_data.verification_result,
        Err(VerificationError::NotSigned)
    ));
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn encrypt_message_and_sign_with_multiple_keys() {
    let input_data = b"hello world";
    let key_alice = PrivateKey::import_unlocked(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");
    let key_bob = PrivateKey::import_unlocked(TEST_KEY_V6.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let encrypted_data = Encryptor::default()
        .with_encryption_key(key_alice.as_public_key())
        .with_signing_keys([&key_alice, &key_bob])
        .encrypt_raw(input_data, DataEncoding::Armored)
        .expect("Failed to encrypt");

    let verified_data = Decryptor::default()
        .with_decryption_key(&key_alice)
        .with_verification_key(key_alice.as_public_key())
        .decrypt(encrypted_data.as_slice(), DataEncoding::Armored)
        .expect("Failed to decrypt");

    assert_eq!(verified_data.data, input_data);
    assert!(verified_data.verification_result.is_ok());

    let verified_data = Decryptor::default()
        .with_decryption_key(&key_alice)
        .with_verification_key(key_bob.as_public_key())
        .decrypt(encrypted_data.as_slice(), DataEncoding::Armored)
        .expect("Failed to decrypt");

    assert_eq!(verified_data.data, input_data);
    assert!(verified_data.verification_result.is_ok());
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn encrypt_message_v4_decrypt_wrong_key() {
    let input_data = b"hello world";
    let key = PrivateKey::import_unlocked(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");
    let key_v6 = PrivateKey::import_unlocked(TEST_KEY_V6.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let encrypted_data = Encryptor::default()
        .with_encryption_key(key.as_public_key())
        .encrypt_raw(input_data, DataEncoding::Armored)
        .expect("Failed to encrypt");

    let failed_decryption = Decryptor::default()
        .with_decryption_key(&key_v6)
        .decrypt(encrypted_data.as_slice(), DataEncoding::Armored);

    assert!(matches!(
        failed_decryption,
        Err(DecryptionError::SessionKeyDecryption(_))
    ));
}
