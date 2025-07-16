use proton_rpgp::{
    AsPublicKeyRef, DataEncoding, DecryptionError, Decryptor, PrivateKey, UnixTime,
    VerificationError,
};

pub const TEST_KEY: &str = include_str!("../test-data/keys/private_key_v4.asc");

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
    const KEY: &str = include_str!("../test-data/keys/private_key_v6.asc");
    let date = UnixTime::new(1_752_589_888);

    let key = PrivateKey::import_unlocked(KEY.as_bytes(), DataEncoding::Armored)
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
