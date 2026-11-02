use std::{fs, path::PathBuf};

use pgp::crypto::sym::SymmetricKeyAlgorithm;
use proton_rpgp::{
    AsPublicKeyRef, DataEncoding, DecryptionError, Decryptor, EncryptedMessage, Encryptor, Error,
    ExternalDetachedSignature, PrivateKey, Profile, ProfileSettings, UnixTime, VerificationContext,
    VerificationError,
};

pub const TEST_KEY: &str = include_str!("../test-data/keys/private_key_v4.asc");
pub const TEST_KEY_V6: &str = include_str!("../test-data/keys/private_key_v6.asc");

mod utils;

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
        .at_date(date.into())
        .decrypt(INPUT_DATA, DataEncoding::Armored)
        .expect("Failed to decrypt");

    assert_eq!(verified_data.data, b"hello world");
    assert!(verified_data.verification_result.is_ok());
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn decrypt_and_verify_encrypted_message_v4_stream() {
    const INPUT_DATA: &str = include_str!("../test-data/messages/encrypted_message_v4.asc");
    let date = UnixTime::new(1_752_572_300);

    let key = PrivateKey::import_unlocked(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let mut verifying_reader = Decryptor::default()
        .with_decryption_key(&key)
        .with_verification_key(key.as_public_key())
        .at_date(date.into())
        .decrypt_stream(INPUT_DATA.as_bytes(), DataEncoding::Armored)
        .expect("Failed to decrypt");

    let mut buffer = Vec::new();
    utils::test_copy(&mut verifying_reader, &mut buffer, 3).expect("Failed to copy");
    let verification_result = verifying_reader.verification_result();

    assert_eq!(buffer, b"hello world");
    assert!(verification_result.is_ok());
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
        .at_date(date.into())
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
        .at_date(date.into())
        .decrypt(INPUT_DATA, DataEncoding::Armored);

    match decryption_result {
        Err(Error::Decryption(DecryptionError::SessionKeyDecryption(err))) => {
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
        .at_date(date.into())
        .output_utf8()
        .decrypt(INPUT_DATA, DataEncoding::Armored)
        .expect("Failed to decrypt");

    assert_eq!(verified_data.data, b"hello world\n     \n");
    assert!(verified_data.verification_result.is_ok());
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn decrypt_encrypted_message_v4_text_stream() {
    const INPUT_DATA: &str = include_str!("../test-data/messages/encrypted_message_v4_text.asc");
    let date = UnixTime::new(1_752_589_888);

    let key = PrivateKey::import_unlocked(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let mut verifying_reader = Decryptor::default()
        .with_decryption_key(&key)
        .with_verification_key(key.as_public_key())
        .at_date(date.into())
        .output_utf8()
        .decrypt_stream(INPUT_DATA.as_bytes(), DataEncoding::Armored)
        .expect("Failed to decrypt");

    let mut buffer = Vec::new();
    utils::test_copy(&mut verifying_reader, &mut buffer, 3).expect("Failed to copy");
    let verification_result = verifying_reader.verification_result();

    assert_eq!(buffer, b"hello world\n     \n");
    assert!(verification_result.is_ok());
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
        .at_date(date.into())
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
        .at_date(date.into())
        .decrypt(INPUT_DATA, DataEncoding::Armored)
        .expect("Failed to decrypt");

    assert_eq!(verified_data.data, b"hello world");
    assert!(verified_data.verification_result.is_ok());
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn decrypt_message_v4_prefers_pkesk_over_skesk() {
    const SKESK_BEFORE_PKESK_MESSAGE: &str =
        include_str!("../test-data/messages/encrypted_message_v4_skesk_before_pkesk.asc");
    let key = PrivateKey::import_unlocked(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let verified_data = Decryptor::default()
        .with_decryption_key(&key)
        .with_passphrase("password")
        .decrypt(SKESK_BEFORE_PKESK_MESSAGE, DataEncoding::Armored)
        .expect("Failed to decrypt");

    assert_eq!(verified_data.data, b"hello world");

    let failed_decryption = Decryptor::default()
        .with_passphrase("password")
        .decrypt(SKESK_BEFORE_PKESK_MESSAGE, DataEncoding::Armored)
        .expect_err("Should fail to decrypt");

    assert!(matches!(
        failed_decryption,
        Error::Decryption(DecryptionError::InvalidSessionKey(_))
    ));
    assert_eq!(
        failed_decryption.to_string(),
        "Proton-rPGP: Failed to decrypt with session key: IO error: Modification Detection Code error"
    );

    let verified_data = Decryptor::default()
        .with_passphrase("other-password")
        .decrypt(SKESK_BEFORE_PKESK_MESSAGE, DataEncoding::Armored)
        .expect("Failed to decrypt");

    assert_eq!(verified_data.data, b"hello world");
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
        .at_date(date.into())
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
        .at_date(date.into())
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
        .at_date(date.into())
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
        .at_date(date.into())
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
        .at_date(date.into())
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
        .at_date(date.into())
        .decrypt(INPUT_DATA, DataEncoding::Armored)
        .expect("Failed to decrypt");

    assert_eq!(verified_data.data, b"Hello World :)");
    assert!(verified_data.verification_result.is_ok());
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn decrypt_encrypted_message_v4_forwarding() {
    const INPUT_DATA: &str =
        include_str!("../test-data/messages/encrypted_message_v4_forwarded.asc");
    const FORWARDEE_KEY: &str = include_str!("../test-data/keys/private_key_v4_forwardee.asc");
    let date = UnixTime::new(1_679_044_110);

    let key = PrivateKey::import_unlocked(FORWARDEE_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let verified_data = Decryptor::default()
        .with_decryption_key(&key)
        .at_date(date.into())
        .allow_forwarding_decryption(true)
        .decrypt(INPUT_DATA, DataEncoding::Armored)
        .expect("Failed to decrypt");

    assert_eq!(verified_data.data, b"Message for Bob");
    assert!(verified_data.verification_result.is_err());

    Decryptor::default()
        .with_decryption_key(&key)
        .at_date(date.into())
        .decrypt(INPUT_DATA, DataEncoding::Armored)
        .expect_err("Forwarding decryption must fail if not explicelty allowed");
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn decrypt_and_verify_encrypted_message_with_detached_signature_stream() {
    const INPUT_DATA: &str =
        include_str!("../test-data/messages/encrypted_message_v6_detached_signature.asc");
    const SIGNATURE: &str = include_str!("../test-data/signatures/signature_v6_for_message.asc");
    const KEY: &str = include_str!("../test-data/keys/private_key_v6_detached_sig_message.asc");
    let date = UnixTime::new(1_752_572_300);

    let key = PrivateKey::import_unlocked(KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let mut verifying_reader = Decryptor::default()
        .with_decryption_key(&key)
        .with_verification_key(key.as_public_key())
        .with_verification_context(VerificationContext::new("test".to_owned(), true, None))
        .with_external_detached_signature(ExternalDetachedSignature::new_unencrypted(
            SIGNATURE.as_bytes(),
            DataEncoding::Armored,
        ))
        .at_date(date.into())
        .decrypt_stream(INPUT_DATA.as_bytes(), DataEncoding::Armored)
        .expect("Failed to decrypt");

    let mut buffer = Vec::new();
    utils::test_copy(&mut verifying_reader, &mut buffer, 3).expect("Failed to copy");
    let verification_result = verifying_reader.verification_result();

    assert_eq!(buffer, b"Hello World :)");
    assert!(verification_result.is_ok());
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn decrypt_encrypted_message_v4_sign_only_key() {
    const INPUT_DATA: &str =
        include_str!("../test-data/messages/encrypted_message_v4_sign_only.asc");
    const SIGN_ONLY: &str = include_str!("../test-data/keys/private_key_v4_sign_only.asc");
    let key = PrivateKey::import_unlocked(SIGN_ONLY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let enabled = Profile::new(
        ProfileSettings::builder()
            .allow_insecure_decryption_with_signing_keys(true)
            .build(),
    );

    let verified_data = Decryptor::new(enabled)
        .with_decryption_key(&key)
        .decrypt(INPUT_DATA, DataEncoding::Armored)
        .expect("Failed to decrypt");

    assert_eq!(verified_data.data, b"hi");
    assert!(verified_data.verification_result.is_err());

    let disabled = Profile::new(
        ProfileSettings::builder()
            .allow_insecure_decryption_with_signing_keys(false)
            .build(),
    );

    Decryptor::new(disabled)
        .with_decryption_key(&key)
        .decrypt(INPUT_DATA, DataEncoding::Armored)
        .expect_err("Should not decrypt with signing key.");
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn decrypt_encrypted_message_v4_compressed() {
    // Message decompressed is 4 KB long
    const INPUT_DATA: &str =
        include_str!("../test-data/messages/encrypted_message_v4_compressed.asc");
    let key = PrivateKey::import_unlocked(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let profile_with_limit_pass = ProfileSettings::builder()
        .max_reading_size(Some(4 * 1024))
        .build_into_profile();

    let profile_with_limit = ProfileSettings::builder()
        .max_reading_size(Some(2 * 1024))
        .build_into_profile();

    // Non-streaming
    Decryptor::new(profile_with_limit_pass.clone())
        .with_decryption_key(&key)
        .decrypt(INPUT_DATA, DataEncoding::Armored)
        .expect("Failed to decrypt");

    Decryptor::new(profile_with_limit_pass.clone())
        .with_decryption_key(&key)
        .with_max_message_reading_size(Some(1024))
        .decrypt(INPUT_DATA, DataEncoding::Armored)
        .expect_err("should fail as message is too large, profile overridden");

    Decryptor::new(profile_with_limit.clone())
        .with_decryption_key(&key)
        .decrypt(INPUT_DATA, DataEncoding::Armored)
        .expect_err("should fail as message is too large");

    Decryptor::new(profile_with_limit.clone())
        .with_decryption_key(&key)
        .with_max_message_reading_size(None)
        .decrypt(INPUT_DATA, DataEncoding::Armored)
        .expect("Failed to decrypt, with exception");

    // Streaming
    let mut reader = Decryptor::new(profile_with_limit_pass)
        .with_decryption_key(&key)
        .decrypt_stream(INPUT_DATA.as_bytes(), DataEncoding::Armored)
        .expect("Failed to decrypt stream");
    reader.discard_all_data().expect("Failed to read all data");

    let mut reader = Decryptor::new(profile_with_limit)
        .with_decryption_key(&key)
        .decrypt_stream(INPUT_DATA.as_bytes(), DataEncoding::Armored)
        .expect("Failed to decrypt stream");
    reader
        .discard_all_data()
        .expect_err("should fail as message is too large");
}

#[test]
#[allow(clippy::missing_panics_doc)]
#[allow(clippy::indexing_slicing)]
pub fn decrypt_stream_detects_modification() {
    let input_data = b"hello world".repeat(64);
    let key = PrivateKey::import_unlocked(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let message = Encryptor::default()
        .with_encryption_key(key.as_public_key())
        .encrypt(&input_data)
        .expect("Failed to encrypt");

    let mut tampered = message.as_key_packets_unchecked().to_vec();
    let mut data_packet = message.as_data_packet_unchecked().to_vec();
    let last = data_packet.len() - 1;
    data_packet[last] ^= 0xFF;
    tampered.extend_from_slice(&data_packet);

    let failed = match Decryptor::default()
        .with_decryption_key(&key)
        .decrypt_stream(&tampered[..], DataEncoding::Unarmored)
    {
        Ok(mut reader) => reader.discard_all_data().is_err(),
        Err(_) => true,
    };

    assert!(failed, "Decryption of a tampered message must fail");
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn decrypt_message_v4_with_password_limit_fails() {
    const INPUT_DATA: &str =
        include_str!("../test-data/messages/encrypted_message_v4_password.asc");
    let password = "password";

    let profile = ProfileSettings::builder()
        .max_s2k_trials_per_passphrase(0)
        .build_into_profile();

    Decryptor::new(profile)
        .with_passphrase(password)
        .decrypt(INPUT_DATA, DataEncoding::Armored)
        .expect_err("should fail");
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn decrypt_rejects_non_integrity_protected_message() {
    const KEY: &str = include_str!("../test-data/keys/private_key_v4_for_no_mdc.asc");
    const INPUT_DATA: &str = include_str!("../test-data/messages/encrypted_message_v4_no_mdc.asc");

    let key = PrivateKey::import_unlocked(KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let decryption_result = Decryptor::default()
        .with_decryption_key(&key)
        .with_verification_key(key.as_public_key())
        .decrypt(INPUT_DATA, DataEncoding::Armored);

    assert!(matches!(
        decryption_result,
        Err(Error::Decryption(DecryptionError::InvalidSessionKey(_)))
    ));
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn decrypt_output_utf8_verifies_detached_signature_over_raw_data() {
    let input_data = b"a\r\nb\r\n";
    let key = PrivateKey::import_unlocked(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    // Binary signatures are verified over the raw data, text signatures over normalized data.
    for text_signature in [false, true] {
        for encrypted_signature in [false, true] {
            let mut encryptor = Encryptor::default()
                .with_encryption_key(key.as_public_key())
                .with_signing_key(&key)
                .using_detached_signature(encrypted_signature);
            if text_signature {
                encryptor = encryptor.as_utf8();
            }
            let (message, detached_signature) = encryptor
                .encrypt(input_data)
                .map(EncryptedMessage::split_detached_signature)
                .expect("Failed to encrypt");
            let detached_signature = detached_signature.expect("Missing detached signature");

            let decryptor = || {
                Decryptor::default()
                    .with_decryption_key(&key)
                    .with_verification_key(key.as_public_key())
                    .with_external_detached_signature(detached_signature.clone())
                    .output_utf8()
            };
            let case = format!("text={text_signature} encrypted={encrypted_signature}");

            let verified_data = decryptor()
                .decrypt(message.as_bytes(), DataEncoding::Unarmored)
                .expect("Failed to decrypt");
            assert_eq!(verified_data.data, b"a\nb\n", "{case}");
            assert!(verified_data.verification_result.is_ok(), "{case}");

            let mut reader = decryptor()
                .decrypt_stream(message.as_bytes(), DataEncoding::Unarmored)
                .expect("Failed to decrypt");
            let mut output = Vec::new();
            std::io::Read::read_to_end(&mut reader, &mut output).expect("Failed to read");
            assert_eq!(output, b"a\nb\n", "{case}");
            assert!(reader.verification_result().is_ok(), "{case}");
        }
    }
}
