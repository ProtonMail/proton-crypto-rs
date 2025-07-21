use std::{fs, path::PathBuf};

use proton_rpgp::{
    AsPublicKeyRef, DataEncoding, DecryptionError, Decryptor, PrivateKey, UnixTime,
    VerificationError,
};

pub const TEST_KEY: &str = include_str!("../test-data/keys/private_key_v4.asc");
pub const TEST_KEY_V6: &str = include_str!("../test-data/keys/private_key_v6.asc");

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn decrypt_and_verify_encrypted_message_v4() {
    const INPUT_DATA: &str = include_str!("../test-data/messages/encrypted_message_v4.asc");
    let date = UnixTime::new(1_752_572_300);

    let key = PrivateKey::import_unlocked(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let verified_data = Decryptor::default()
        .with_decryption_key(&key)
        .with_verification_key(key.as_public_key())
        .at_date(date)
        .decrypt(INPUT_DATA, DataEncoding::Armored)
        .expect("Failed to decrypt");

    assert_eq!(verified_data.data, b"hello world");
    assert!(verified_data.verification_result.is_ok());
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn decrypt_and_verify_encrypted_message_v6() {
    const INPUT_DATA: &str = include_str!("../test-data/messages/encrypted_message_v6.asc");
    let date = UnixTime::new(1_752_589_888);

    let key = PrivateKey::import_unlocked(TEST_KEY_V6.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let verified_data = Decryptor::default()
        .with_decryption_key(&key)
        .with_verification_key(key.as_public_key())
        .at_date(date)
        .decrypt(INPUT_DATA, DataEncoding::Armored)
        .expect("Failed to decrypt");

    assert_eq!(verified_data.data, b"hello world");
    assert!(verified_data.verification_result.is_ok());
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn decrypt_encrypted_message_wrong_key() {
    const INPUT_DATA: &str = include_str!("../test-data/messages/encrypted_message_v6.asc");
    let date = UnixTime::new(1_752_572_300);

    let key = PrivateKey::import_unlocked(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let decryption_result = Decryptor::default()
        .with_decryption_key(&key)
        .at_date(date)
        .decrypt(INPUT_DATA, DataEncoding::Armored);

    match decryption_result {
        Err(DecryptionError::SessionKeyDecryption(err)) => {
            let first_error = err.0.first().unwrap();
            assert!(matches!(
                first_error,
                DecryptionError::PkeskNoMatchingKey(_)
            ));
        }
        _ => panic!("Expected decryption to fail"),
    }
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn decrypt_encrypted_message_v4_text() {
    const INPUT_DATA: &str = include_str!("../test-data/messages/encrypted_message_v4_text.asc");
    let date = UnixTime::new(1_752_589_888);

    let key = PrivateKey::import_unlocked(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let verified_data = Decryptor::default()
        .with_decryption_key(&key)
        .with_verification_key(key.as_public_key())
        .at_date(date)
        .output_utf8()
        .decrypt(INPUT_DATA, DataEncoding::Armored)
        .expect("Failed to decrypt");

    assert_eq!(verified_data.data, b"hello world\n     \n");
    assert!(verified_data.verification_result.is_ok());
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn decrypt_and_verify_encrypted_message_v4_fail_due_to_past_date() {
    const INPUT_DATA: &str = include_str!("../test-data/messages/encrypted_message_v4.asc");
    let date = UnixTime::new(963_723_185);

    let key = PrivateKey::import_unlocked(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let verified_data = Decryptor::default()
        .with_decryption_key(&key)
        .with_verification_key(key.as_public_key())
        .at_date(date)
        .decrypt(INPUT_DATA, DataEncoding::Armored)
        .expect("Failed to decrypt");

    assert_eq!(verified_data.data, b"hello world");
    assert!(matches!(
        verified_data.verification_result,
        Err(VerificationError::Failed(_, _))
    ));
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn decrypt_and_verify_encrypted_message_v4_multi_key_packets() {
    const INPUT_DATA: &str =
        include_str!("../test-data/messages/encrypted_message_v4_multi_key_packets.asc");
    let date = UnixTime::new(1_752_650_039);

    let key = PrivateKey::import_unlocked(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let verified_data = Decryptor::default()
        .with_decryption_key(&key)
        .with_verification_key(key.as_public_key())
        .at_date(date)
        .decrypt(INPUT_DATA, DataEncoding::Armored)
        .expect("Failed to decrypt");

    assert_eq!(verified_data.data, b"hello world");
    assert!(verified_data.verification_result.is_ok());
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn decrypt_and_verify_encrypted_message_v4_multiple_keys() {
    const INPUT_DATA: &str = include_str!("../test-data/messages/encrypted_message_v4.asc");
    let date = UnixTime::new(1_752_650_039);

    let key_v4 = PrivateKey::import_unlocked(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");
    let key_v6 = PrivateKey::import_unlocked(TEST_KEY_V6.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let keys = vec![key_v6, key_v4];

    let verified_data = Decryptor::default()
        .with_decryption_keys(&keys)
        .with_verification_keys(keys.iter().map(AsPublicKeyRef::as_public_key))
        .at_date(date)
        .decrypt(INPUT_DATA, DataEncoding::Armored)
        .expect("Failed to decrypt");

    assert_eq!(verified_data.data, b"hello world");
    assert!(verified_data.verification_result.is_ok());
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn decrypt_and_verify_encrypted_message_v4_wrong_verification_key() {
    const INPUT_DATA: &str = include_str!("../test-data/messages/encrypted_message_v4.asc");
    let date = UnixTime::new(1_752_650_039);

    let key_v4 = PrivateKey::import_unlocked(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");
    let key_v6 = PrivateKey::import_unlocked(TEST_KEY_V6.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let keys = [&key_v6, &key_v4];

    let verified_data = Decryptor::default()
        .with_decryption_keys(keys.iter().copied())
        .with_verification_key(key_v6.as_public_key())
        .at_date(date)
        .decrypt(INPUT_DATA, DataEncoding::Armored)
        .expect("Failed to decrypt");

    assert_eq!(verified_data.data, b"hello world");
    assert!(matches!(
        verified_data.verification_result,
        Err(VerificationError::NoVerifier(_, _))
    ));
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn decrypt_encrypted_message_v4_text_mail() {
    let input_data_path: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "test-data",
        "messages",
        "encrypted_message_v4_mail.bin",
    ]
    .iter()
    .collect();

    let expected_output_path: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "test-data",
        "messages",
        "expected_decrypted_message_v4_mail.expected",
    ]
    .iter()
    .collect();
    let input_data = fs::read(input_data_path).unwrap();
    let expected_output = fs::read(expected_output_path).unwrap();

    let date = UnixTime::new(1_752_572_300);

    let key = PrivateKey::import_unlocked(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let verified_data = Decryptor::default()
        .with_decryption_key(&key)
        .at_date(date)
        .output_utf8()
        .decrypt(input_data, DataEncoding::Unarmored)
        .expect("Failed to decrypt");

    assert_eq!(verified_data.data, expected_output);
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn decrypt_message_v4_with_password() {
    const INPUT_DATA: &str =
        include_str!("../test-data/messages/encrypted_message_v4_password.asc");
    let password = "password";

    let verified_data = Decryptor::default()
        .with_passphrase(password)
        .decrypt(INPUT_DATA, DataEncoding::Armored)
        .expect("Failed to decrypt");

    assert_eq!(verified_data.data, b"hello world");
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn decrypt_message_v6_with_password() {
    const INPUT_DATA: &str =
        include_str!("../test-data/messages/encrypted_message_v6_password.asc");
    let password = "password";

    let verified_data = Decryptor::default()
        .with_passphrase(password)
        .decrypt(INPUT_DATA, DataEncoding::Armored)
        .expect("Failed to decrypt");

    assert_eq!(verified_data.data, b"Hello, world!");
}
