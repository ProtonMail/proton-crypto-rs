use std::{fs, path::PathBuf};

use pgp::crypto::sym::SymmetricKeyAlgorithm;
use proton_rpgp::{
    AsPublicKeyRef, DataEncoding, DecryptionError, Decryptor, Error, ExternalDetachedSignature,
    PrivateKey, UnixTime, VerificationContext, VerificationError,
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
    let date = UnixTime::new(1_753_705_263);

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
        Err(Error::Decrypt(DecryptionError::SessionKeyDecryption(err))) => {
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

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn decrypt_and_verify_encrypted_message_v4_with_session_key() {
    const INPUT_DATA: &str = include_str!("../test-data/messages/encrypted_message_v4.asc");
    const KEY_PACKETS: &str = "c15e0327b3a9160a712c9612010740c514efd8a8e313979cb9533800343f79e895b754606bc3d7963ca8b9e6bb4c4130c61dd36450613b81c42ad53719c94906139e00d5a297ab44f76d8874afeb63a612310935a3e773884e972aec0aa3085c";
    const EXPECTED_SESSION_KEY: &str =
        "53eec178ce77003c4ede036f3c042f4d6719c6214457bdc6dbe276e3e4e21c1c";
    let date = UnixTime::new(1_752_572_300);

    let key = PrivateKey::import_unlocked(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let session_key = Decryptor::default()
        .with_decryption_key(&key)
        .decrypt_session_key(hex::decode(KEY_PACKETS).unwrap())
        .expect("Failed to decrypt session key");

    assert_eq!(
        session_key.as_ref(),
        hex::decode(EXPECTED_SESSION_KEY).unwrap()
    );

    assert!(matches!(
        session_key.algorithm(),
        Some(SymmetricKeyAlgorithm::AES256)
    ));

    let verified_data = Decryptor::default()
        .with_session_key(&session_key)
        .with_verification_key(key.as_public_key())
        .at_date(date)
        .decrypt(INPUT_DATA, DataEncoding::Armored)
        .expect("Failed to decrypt");

    assert_eq!(verified_data.data, b"hello world");
    assert!(verified_data.verification_result.is_ok());
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn decrypt_message_v4_with_password_and_session_key() {
    const INPUT_DATA: &str =
        include_str!("../test-data/messages/encrypted_message_v4_password.asc");
    const KEY_PACKETS: &str = "c32e04090308a33cce68dccd58056095bf69bfbd763de38d5db8a1e0f174c18d162bcd0a0bd730b7398995e5c4896613";
    const EXPECTED_SESSION_KEY: &str =
        "a4f328a8f283b1b7cdac4053e111654728d5cf7067037ebaebaa270843a7b86c";
    let password = "password";

    let session_key = Decryptor::default()
        .with_passphrase(password)
        .decrypt_session_key(hex::decode(KEY_PACKETS).unwrap())
        .expect("Failed to decrypt session key");

    assert_eq!(
        session_key.as_ref(),
        hex::decode(EXPECTED_SESSION_KEY).unwrap()
    );

    assert!(matches!(
        session_key.algorithm(),
        Some(SymmetricKeyAlgorithm::AES256)
    ));

    let verified_data = Decryptor::default()
        .with_session_key(&session_key)
        .decrypt(INPUT_DATA, DataEncoding::Armored)
        .expect("Failed to decrypt");

    assert_eq!(verified_data.data, b"hello world");
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn decrypt_encrypted_message_v4_wildcard() {
    const INPUT_DATA: &str =
        include_str!("../test-data/messages/encrypted_message_v4_wildcard.asc");
    const WILDCARD_KEY: &str = include_str!("../test-data/keys/private_key_v4_for_wildcard.asc");
    let date = UnixTime::new(1_752_572_300);

    let key = PrivateKey::import_unlocked(WILDCARD_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let verified_data = Decryptor::default()
        .with_decryption_key(&key)
        .at_date(date)
        .decrypt(INPUT_DATA, DataEncoding::Armored)
        .expect("Failed to decrypt");

    assert_eq!(verified_data.data, b"Hello World :)");
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn decrypt_and_verify_encrypted_message_with_detached_signature() {
    const INPUT_DATA: &str =
        include_str!("../test-data/messages/encrypted_message_v6_detached_signature.asc");
    const SIGNATURE: &str = include_str!("../test-data/signatures/signature_v6_for_message.asc");
    const KEY: &str = include_str!("../test-data/keys/private_key_v6_detached_sig_message.asc");
    let date = UnixTime::new(1_752_572_300);

    let key = PrivateKey::import_unlocked(KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let verified_data = Decryptor::default()
        .with_decryption_key(&key)
        .with_verification_key(key.as_public_key())
        .with_verification_context(VerificationContext::new("test".to_owned(), true, None))
        .with_external_detached_signature(ExternalDetachedSignature::new_unencrypted(
            SIGNATURE.as_bytes(),
            DataEncoding::Armored,
        ))
        .at_date(date)
        .decrypt(INPUT_DATA, DataEncoding::Armored)
        .expect("Failed to decrypt");

    assert_eq!(verified_data.data, b"Hello World :)");
    assert!(verified_data.verification_result.is_ok());
}
