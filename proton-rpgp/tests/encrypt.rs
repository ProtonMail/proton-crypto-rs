use std::sync::LazyLock;

use pgp::crypto::{aead::AeadAlgorithm, hash::HashAlgorithm, sym::SymmetricKeyAlgorithm};
use proton_rpgp::{
    AsPublicKeyRef, DataEncoding, DecryptionError, Decryptor, EncryptedMessage,
    EncryptedMessageInfo, EncryptionError, Encryptor, Error, KeyGenerator, PrivateKey, Profile,
    ProfileSettingsBuilder, SessionKey, StringToKeyOption, UnixTime, VerificationError,
};

mod utils;

pub const TEST_KEY: &str = include_str!("../test-data/keys/private_key_v4.asc");
pub const TEST_KEY_V6: &str = include_str!("../test-data/keys/private_key_v6.asc");

pub static TEST_PW_PROFILE: LazyLock<Profile> = LazyLock::new(|| {
    let s2k = StringToKeyOption::IteratedAndSalted {
        sym_alg: SymmetricKeyAlgorithm::AES256,
        hash_alg: HashAlgorithm::Sha256,
        count: 0,
    };
    ProfileSettingsBuilder::new()
        .message_encryption_s2k_params(s2k)
        .build()
        .into()
});

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
pub fn encrypt_message_v4_stream() {
    let input_data = b"hello world".repeat(1024);
    let key = PrivateKey::import_unlocked(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let mut buffer = Vec::new();
    Encryptor::default()
        .with_encryption_key(key.as_public_key())
        .encrypt_stream(&input_data[..], DataEncoding::Armored, &mut buffer)
        .expect("Failed to encrypt");

    let verified_data = Decryptor::default()
        .with_decryption_key(&key)
        .decrypt(buffer.as_slice(), DataEncoding::Armored)
        .expect("Failed to decrypt");

    assert_eq!(verified_data.data, input_data);
    assert!(matches!(
        verified_data.verification_result,
        Err(VerificationError::NotSigned)
    ));
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn encrypt_message_v4_text() {
    let input_data = b"hello world\n ds   \n";
    let key = PrivateKey::import_unlocked(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let encrypted_data = Encryptor::default()
        .with_encryption_key(key.as_public_key())
        .with_signing_key(&key)
        .as_utf8()
        .encrypt_raw(input_data, DataEncoding::Armored)
        .expect("Failed to encrypt");

    let verified_data = Decryptor::default()
        .with_decryption_key(&key)
        .with_verification_key(key.as_public_key())
        .output_utf8()
        .decrypt(encrypted_data.as_slice(), DataEncoding::Armored)
        .expect("Failed to decrypt");

    assert_eq!(verified_data.data, input_data);
    assert!(verified_data.verification_result.is_ok());

    let verified_data = Decryptor::default()
        .with_decryption_key(&key)
        .with_verification_key(key.as_public_key())
        .decrypt(encrypted_data.as_slice(), DataEncoding::Armored)
        .expect("Failed to decrypt");

    assert_eq!(verified_data.data, b"hello world\r\n ds   \r\n");
    assert!(verified_data.verification_result.is_ok());
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn encrypt_message_v4_text_stream() {
    let input_string = "a \n ".repeat(32 * 1024);
    let key = PrivateKey::import_unlocked(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let mut buffer = Vec::new();
    Encryptor::default()
        .with_encryption_key(key.as_public_key())
        .with_signing_key(&key)
        .as_utf8()
        .encrypt_stream(input_string.as_bytes(), DataEncoding::Armored, &mut buffer)
        .expect("Failed to encrypt");

    let mut verifying_reader = Decryptor::default()
        .with_decryption_key(&key)
        .with_verification_key(key.as_public_key())
        .output_utf8()
        .decrypt_stream(&buffer[..], DataEncoding::Armored)
        .expect("Failed to decrypt");

    let mut output = Vec::new();
    utils::test_copy(&mut verifying_reader, &mut output, 3).expect("Failed to copy");
    assert_eq!(output, input_string.as_bytes());
    assert!(verifying_reader.verification_result().is_ok());
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn encrypt_message_v4_passphrase() {
    let input_data = b"hello world";
    let passphrase: &'static str = "password";

    let encrypted_data = Encryptor::new(TEST_PW_PROFILE.clone())
        .with_passphrase(passphrase)
        .encrypt_raw(input_data, DataEncoding::Armored)
        .expect("Failed to encrypt");

    let decrypted_data = Decryptor::new(TEST_PW_PROFILE.clone())
        .with_passphrase(passphrase)
        .decrypt(encrypted_data, DataEncoding::Armored)
        .expect("Failed to decrypt");

    assert_eq!(decrypted_data.data, input_data);
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn encrypt_message_v4_passphrase_stream() {
    let input_data = b"hello world".repeat(1024);
    let passphrase: &'static str = "password";

    let mut buffer = Vec::new();
    Encryptor::new(TEST_PW_PROFILE.clone())
        .with_passphrase(passphrase)
        .encrypt_stream(&input_data[..], DataEncoding::Armored, &mut buffer)
        .expect("Failed to encrypt");

    let decrypted_data = Decryptor::new(TEST_PW_PROFILE.clone())
        .with_passphrase(passphrase)
        .decrypt(&buffer, DataEncoding::Armored)
        .expect("Failed to decrypt");

    assert_eq!(decrypted_data.data, input_data);
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn encrypt_message_v4_multi_passphrase() {
    let input_data = b"hello world";
    let passphrase1: &str = "password1";
    let passphrase2: &str = "password2";

    let encrypted_data = Encryptor::new(TEST_PW_PROFILE.clone())
        .with_passphrase(passphrase1)
        .with_passphrase(passphrase2)
        .encrypt_raw(input_data, DataEncoding::Armored)
        .expect("Failed to encrypt");

    let decrypted_data = Decryptor::new(TEST_PW_PROFILE.clone())
        .with_passphrase(passphrase1)
        .decrypt(&encrypted_data, DataEncoding::Armored)
        .expect("Failed to decrypt");
    assert_eq!(decrypted_data.data, input_data);

    let decrypted_data = Decryptor::new(TEST_PW_PROFILE.clone())
        .with_passphrase(passphrase2)
        .decrypt(&encrypted_data, DataEncoding::Armored)
        .expect("Failed to decrypt");
    assert_eq!(decrypted_data.data, input_data);
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn encrypt_message_v4_multi_passphrase_stream() {
    let input_data = b"hello world".repeat(1024);
    let passphrase1: &str = "password1";
    let passphrase2: &str = "password2";

    let mut buffer = Vec::new();
    Encryptor::new(TEST_PW_PROFILE.clone())
        .with_passphrase(passphrase1)
        .with_passphrase(passphrase2)
        .encrypt_stream(&input_data[..], DataEncoding::Armored, &mut buffer)
        .expect("Failed to encrypt");

    let decrypted_data = Decryptor::new(TEST_PW_PROFILE.clone())
        .with_passphrase(passphrase1)
        .decrypt(&buffer, DataEncoding::Armored)
        .expect("Failed to decrypt");
    assert_eq!(decrypted_data.data, input_data);

    let decrypted_data = Decryptor::new(TEST_PW_PROFILE.clone())
        .with_passphrase(passphrase2)
        .decrypt(&buffer, DataEncoding::Armored)
        .expect("Failed to decrypt");
    assert_eq!(decrypted_data.data, input_data);
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
pub fn encrypt_and_sign_message_v4_stream() {
    let input_string = "a".repeat(1024 * 1024); // 1 MB string

    let key = PrivateKey::import_unlocked(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let mut buffer = Vec::new();
    Encryptor::default()
        .with_encryption_key(key.as_public_key())
        .with_signing_key(&key)
        .encrypt_stream(input_string.as_bytes(), DataEncoding::Armored, &mut buffer)
        .expect("Failed to encrypt");

    let mut verifying_reader = Decryptor::default()
        .with_decryption_key(&key)
        .with_verification_key(key.as_public_key())
        .decrypt_stream(&buffer[..], DataEncoding::Armored)
        .expect("Failed to decrypt");

    let mut out_buffer = Vec::new();
    utils::test_copy(&mut verifying_reader, &mut out_buffer, 3).expect("Failed to copy");
    let verification_result = verifying_reader.verification_result();

    assert_eq!(out_buffer, input_string.as_bytes());
    assert!(verification_result.is_ok());
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
pub fn encrypt_and_sign_message_v6_stream() {
    let input_data = b"hello world".repeat(1024);
    let key = PrivateKey::import_unlocked(TEST_KEY_V6.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let mut buffer = Vec::new();
    Encryptor::default()
        .with_encryption_key(key.as_public_key())
        .with_signing_key(&key)
        .encrypt_stream(&input_data[..], DataEncoding::Armored, &mut buffer)
        .expect("Failed to encrypt");

    let mut verifying_reader = Decryptor::default()
        .with_decryption_key(&key)
        .with_verification_key(key.as_public_key())
        .decrypt_stream(&buffer[..], DataEncoding::Armored)
        .expect("Failed to decrypt");

    let mut output = Vec::new();
    utils::test_copy(&mut verifying_reader, &mut output, 3).expect("Failed to copy");
    let verification_result = verifying_reader.verification_result();

    assert_eq!(output, input_data);
    assert!(verification_result.is_ok());
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

    assert!(revealed_session_key.export_bytes().len() > 16);
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
pub fn encrypt_message_to_multiple_recipients_stream() {
    let input_data = b"hello world".repeat(1024);
    let key_alice = PrivateKey::import_unlocked(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");
    let key_bob = PrivateKey::import_unlocked(TEST_KEY_V6.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let mut buffer = Vec::new();
    Encryptor::default()
        .with_encryption_keys([key_alice.as_public_key(), key_bob.as_public_key()])
        .encrypt_stream(&input_data[..], DataEncoding::Armored, &mut buffer)
        .expect("Failed to encrypt");

    let verified_data = Decryptor::default()
        .with_decryption_key(&key_alice)
        .decrypt(buffer.as_slice(), DataEncoding::Armored)
        .expect("Failed to decrypt");
    assert_eq!(verified_data.data, input_data);

    let verified_data = Decryptor::default()
        .with_decryption_key(&key_bob)
        .decrypt(buffer.as_slice(), DataEncoding::Armored)
        .expect("Failed to decrypt");
    assert_eq!(verified_data.data, input_data);
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
pub fn encrypt_message_and_sign_with_multiple_keys_stream() {
    let input_data = b"hello world".repeat(1024);
    let key_alice = PrivateKey::import_unlocked(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");
    let key_bob = PrivateKey::import_unlocked(TEST_KEY_V6.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let mut buffer = Vec::new();
    Encryptor::default()
        .with_encryption_key(key_alice.as_public_key())
        .with_signing_keys([&key_alice, &key_bob])
        .encrypt_stream(&input_data[..], DataEncoding::Armored, &mut buffer)
        .expect("Failed to encrypt");

    let verified_data = Decryptor::default()
        .with_decryption_key(&key_alice)
        .with_verification_key(key_alice.as_public_key())
        .decrypt(buffer.as_slice(), DataEncoding::Armored)
        .expect("Failed to decrypt");
    assert_eq!(verified_data.data, input_data);

    let verified_data = Decryptor::default()
        .with_decryption_key(&key_alice)
        .with_verification_key(key_bob.as_public_key())
        .decrypt(buffer.as_slice(), DataEncoding::Armored)
        .expect("Failed to decrypt");
    assert_eq!(verified_data.data, input_data);
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
        Err(Error::Decryption(DecryptionError::SessionKeyDecryption(_)))
    ));
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn encrypt_session_key_v4() {
    let session_key = dummy_session_key(false);

    let key = PrivateKey::import_unlocked(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let key_packets = Encryptor::default()
        .with_encryption_key(key.as_public_key())
        .encrypt_session_key(&session_key)
        .expect("Failed to encrypt");

    let output_session_key = Decryptor::default()
        .with_decryption_key(&key)
        .decrypt_session_key(&key_packets)
        .expect("Failed to decrypt session key");

    assert_eq!(
        session_key.export_bytes(),
        output_session_key.export_bytes()
    );

    assert_eq!(session_key.algorithm(), output_session_key.algorithm());
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn encrypt_session_key_v6_seipdv2() {
    let session_key = dummy_session_key(true);

    let key = PrivateKey::import_unlocked(TEST_KEY_V6.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let profile = Profile::new(
        ProfileSettingsBuilder::new()
            .preferred_aead_ciphersuite(Some((SymmetricKeyAlgorithm::AES128, AeadAlgorithm::Gcm)))
            .build(),
    );

    let key_packets = Encryptor::new(profile)
        .with_encryption_key(key.as_public_key())
        .encrypt_session_key(&session_key)
        .expect("Failed to encrypt");

    let output_session_key = Decryptor::default()
        .with_decryption_key(&key)
        .decrypt_session_key(&key_packets)
        .expect("Failed to decrypt session key");

    assert_eq!(
        session_key.export_bytes(),
        output_session_key.export_bytes()
    );
    assert!(output_session_key.algorithm().is_none());
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn encrypt_session_key_passphrase() {
    let session_key = dummy_session_key(false);

    let passphrase: &'static str = "password";

    let key_packets = Encryptor::default()
        .with_passphrase(passphrase)
        .encrypt_session_key(&session_key)
        .expect("Failed to encrypt");

    let output_session_key = Decryptor::default()
        .with_passphrase(passphrase)
        .decrypt_session_key(&key_packets)
        .expect("Failed to decrypt");

    assert_eq!(
        session_key.export_bytes(),
        output_session_key.export_bytes()
    );

    assert_eq!(session_key.algorithm(), output_session_key.algorithm());
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn encrypt_session_key_passphrase_seipdv2() {
    let session_key = dummy_session_key(true);
    let passphrase: &'static str = "password";

    let profile = Profile::new(
        ProfileSettingsBuilder::new()
            .preferred_aead_ciphersuite(Some((SymmetricKeyAlgorithm::AES128, AeadAlgorithm::Gcm)))
            .build(),
    );

    let key_packets = Encryptor::new(profile)
        .with_passphrase(passphrase)
        .encrypt_session_key(&session_key)
        .expect("Failed to encrypt");

    let output_session_key = Decryptor::default()
        .with_passphrase(passphrase)
        .decrypt_session_key(&key_packets)
        .expect("Failed to decrypt session key");

    assert_eq!(
        session_key.export_bytes(),
        output_session_key.export_bytes()
    );
    assert!(output_session_key.algorithm().is_none());
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn generate_session_key_for_encryption() {
    let key = PrivateKey::import_unlocked(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let session_key = Encryptor::default()
        .with_encryption_key(key.as_public_key())
        .generate_session_key()
        .expect("Failed to generate session key");

    assert_eq!(session_key.algorithm(), Some(SymmetricKeyAlgorithm::AES256));
    assert_eq!(session_key.export_bytes().len(), 32);
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn encrypt_data_with_session_key_seipdv1() {
    let session_key = dummy_session_key(false);
    let plain_data = b"hello world";

    let key = PrivateKey::import_unlocked(TEST_KEY_V6.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let mut message = Encryptor::default()
        .with_encryption_key(key.as_public_key())
        .encrypt_session_key(&session_key)
        .expect("Failed to encrypt");

    let data_packet = Encryptor::default()
        .with_session_key(&session_key)
        .encrypt_raw(plain_data, DataEncoding::Unarmored)
        .expect("Failed to encrypt");

    message.extend(data_packet.iter());

    let output_data = Decryptor::default()
        .with_decryption_key(&key)
        .decrypt(message, DataEncoding::Unarmored)
        .expect("Failed to decrypt session key");

    assert_eq!(output_data.data, plain_data);

    let output_data = Decryptor::default()
        .with_session_key(&session_key)
        .decrypt(data_packet, DataEncoding::Unarmored)
        .expect("Failed to decrypt session key");

    assert_eq!(output_data.data, plain_data);
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn encrypt_data_with_session_key_seipdv1_stream() {
    let session_key = dummy_session_key(false);
    let plain_data = b"hello world".repeat(1024);

    let key = PrivateKey::import_unlocked(TEST_KEY_V6.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    // First generate encrypted session key packets
    let mut message = Encryptor::default()
        .with_encryption_key(key.as_public_key())
        .encrypt_session_key(&session_key)
        .expect("Failed to encrypt");

    // Encrypt data packet in streaming fashion
    let mut data_packet = Vec::new();
    Encryptor::default()
        .with_session_key(&session_key)
        .encrypt_stream(&plain_data[..], DataEncoding::Unarmored, &mut data_packet)
        .expect("Failed to encrypt");

    message.extend(data_packet.iter());

    let output_data = Decryptor::default()
        .with_decryption_key(&key)
        .decrypt(message, DataEncoding::Unarmored)
        .expect("Failed to decrypt session key");

    assert_eq!(output_data.data, plain_data);

    let output_data = Decryptor::default()
        .with_session_key(&session_key)
        .decrypt(data_packet, DataEncoding::Unarmored)
        .expect("Failed to decrypt session key");

    assert_eq!(output_data.data, plain_data);
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn encrypt_data_with_session_key_seipdv2() {
    let session_key = dummy_session_key(true);
    let plain_data = b"hello world";

    let key = PrivateKey::import_unlocked(TEST_KEY_V6.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let mut message = Encryptor::default()
        .with_encryption_key(key.as_public_key())
        .encrypt_session_key(&session_key)
        .expect("Failed to encrypt");

    let data_packet = Encryptor::default()
        .with_session_key(&session_key)
        .encrypt_raw(plain_data, DataEncoding::Unarmored)
        .expect("Failed to encrypt");

    message.extend(data_packet.iter());

    let output_data = Decryptor::default()
        .with_decryption_key(&key)
        .decrypt(&message, DataEncoding::Unarmored)
        .expect("Failed to decrypt session key");

    assert_eq!(output_data.data, plain_data);

    let output_data = Decryptor::default()
        .with_session_key(&session_key)
        .decrypt(data_packet, DataEncoding::Unarmored)
        .expect("Failed to decrypt session key");

    assert_eq!(output_data.data, plain_data);
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn encrypt_data_with_session_key_seipdv2_stream() {
    let session_key = dummy_session_key(true);
    let plain_data = b"hello world".repeat(1024);

    let key = PrivateKey::import_unlocked(TEST_KEY_V6.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let mut message = Encryptor::default()
        .with_encryption_key(key.as_public_key())
        .encrypt_session_key(&session_key)
        .expect("Failed to encrypt");

    let mut data_packet = Vec::new();
    Encryptor::default()
        .with_session_key(&session_key)
        .encrypt_stream(&plain_data[..], DataEncoding::Unarmored, &mut data_packet)
        .expect("Failed to encrypt");

    message.extend(data_packet.iter());

    let output_data = Decryptor::default()
        .with_decryption_key(&key)
        .decrypt(&message, DataEncoding::Unarmored)
        .expect("Failed to decrypt session key");

    assert_eq!(output_data.data, plain_data);

    let output_data = Decryptor::default()
        .with_session_key(&session_key)
        .decrypt(data_packet, DataEncoding::Unarmored)
        .expect("Failed to decrypt session key");

    assert_eq!(output_data.data, plain_data);
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn encrypt_and_then_decrypt_with_session_key() {
    let input_data = b"hello world";
    let key = PrivateKey::import_unlocked(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let encrypted_data = Encryptor::default()
        .with_encryption_key(key.as_public_key())
        .encrypt(input_data)
        .expect("Failed to encrypt");

    let sk = Decryptor::default()
        .with_decryption_key(&key)
        .decrypt_session_key(encrypted_data.as_key_packets_unchecked())
        .expect("Failed to decrypt");

    let verified_data = Decryptor::default()
        .with_session_key(&sk)
        .decrypt(
            encrypted_data.as_data_packet_unchecked(),
            DataEncoding::Unarmored,
        )
        .expect("Failed to decrypt");

    assert_eq!(verified_data.data, input_data);
    assert!(matches!(
        verified_data.verification_result,
        Err(VerificationError::NotSigned)
    ));
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn encrypt_and_then_decrypt_with_session_key_stream() {
    let input_data = b"hello world".repeat(128);
    let key = PrivateKey::import_unlocked(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let mut buffer = Vec::new();
    Encryptor::default()
        .with_encryption_key(key.as_public_key())
        .encrypt_stream(&input_data[..], DataEncoding::Unarmored, &mut buffer)
        .expect("Failed to encrypt");

    let sk = Decryptor::default()
        .with_decryption_key(&key)
        .decrypt_session_key(
            EncryptedMessage::from_bytes(&buffer)
                .unwrap()
                .as_key_packets_unchecked(),
        )
        .expect("Failed to decrypt");

    let verified_data = Decryptor::default()
        .with_session_key(&sk)
        .decrypt(
            EncryptedMessage::from_bytes(&buffer)
                .unwrap()
                .as_data_packet_unchecked(),
            DataEncoding::Unarmored,
        )
        .expect("Failed to decrypt");

    assert_eq!(verified_data.data, input_data);
    assert!(matches!(
        verified_data.verification_result,
        Err(VerificationError::NotSigned)
    ));
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn encrypt_and_sign_message_v4_with_detached_signature() {
    let input_data = b"hello world";
    let key = PrivateKey::import_unlocked(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let test = |encrypt: bool| {
        let (encrypted_data, detached_signature) = Encryptor::default()
            .with_encryption_key(key.as_public_key())
            .with_signing_key(&key)
            .using_detached_signature(encrypt)
            .encrypt(input_data)
            .map(EncryptedMessage::split_detached_signature)
            .expect("Failed to encrypt");

        let verified_data = Decryptor::default()
            .with_decryption_key(&key)
            .with_verification_key(key.as_public_key())
            .with_external_detached_signature(detached_signature.unwrap())
            .decrypt(encrypted_data.armor().unwrap(), DataEncoding::Armored)
            .expect("Failed to decrypt");

        assert_eq!(verified_data.data, input_data);
        assert!(verified_data.verification_result.is_ok());

        let verified_data = Decryptor::default()
            .with_decryption_key(&key)
            .with_verification_key(key.as_public_key())
            .decrypt(encrypted_data.armor().unwrap(), DataEncoding::Armored)
            .expect("Failed to decrypt");
        assert!(verified_data.verification_result.is_err());
    };

    test(true);
    test(false);
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn encrypt_and_sign_message_v4_with_detached_signature_stream() {
    let input_data = b"hello world".repeat(1024);
    let key = PrivateKey::import_unlocked(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let test = |encrypt: bool| {
        let mut buffer = Vec::new();
        let (_, detached_signature) = Encryptor::default()
            .with_encryption_key(key.as_public_key())
            .with_signing_key(&key)
            .using_detached_signature(encrypt)
            .encrypt_stream(&input_data[..], DataEncoding::Armored, &mut buffer)
            .map(EncryptedMessageInfo::split_detached_signature)
            .expect("Failed to encrypt");

        let verified_data = Decryptor::default()
            .with_decryption_key(&key)
            .with_verification_key(key.as_public_key())
            .with_external_detached_signature(detached_signature.unwrap())
            .decrypt(&buffer[..], DataEncoding::Armored)
            .expect("Failed to decrypt");

        assert_eq!(verified_data.data, input_data);
        assert!(verified_data.verification_result.is_ok());

        let verified_data = Decryptor::default()
            .with_decryption_key(&key)
            .with_verification_key(key.as_public_key())
            .decrypt(&buffer[..], DataEncoding::Armored)
            .expect("Failed to decrypt");
        assert!(verified_data.verification_result.is_err());
    };

    test(true);
    test(false);
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn encrypt_and_sign_message_v4_with_detached_signature_text() {
    let input_data = b"hello world\n ds   \n";
    let key = PrivateKey::import_unlocked(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let test = |encrypt: bool| {
        let (encrypted_data, detached_signature) = Encryptor::default()
            .with_encryption_key(key.as_public_key())
            .with_signing_key(&key)
            .using_detached_signature(encrypt)
            .as_utf8()
            .encrypt(input_data)
            .map(EncryptedMessage::split_detached_signature)
            .expect("Failed to encrypt");

        let verified_data = Decryptor::default()
            .with_decryption_key(&key)
            .with_verification_key(key.as_public_key())
            .with_external_detached_signature(detached_signature.unwrap())
            .output_utf8()
            .decrypt(encrypted_data.armor().unwrap(), DataEncoding::Armored)
            .expect("Failed to decrypt");

        assert_eq!(verified_data.data, input_data);
        assert!(verified_data.verification_result.is_ok());
    };
    test(false);
    test(true);
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn encrypt_and_sign_message_v4_with_detached_signature_text_stream() {
    let input_string = "hello world\n ds   \n".repeat(1024);
    let key = PrivateKey::import_unlocked(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let test = |encrypt: bool| {
        let mut buffer = Vec::new();
        let (_, detached_signature) = Encryptor::default()
            .with_encryption_key(key.as_public_key())
            .with_signing_key(&key)
            .using_detached_signature(encrypt)
            .as_utf8()
            .encrypt_stream(input_string.as_bytes(), DataEncoding::Armored, &mut buffer)
            .map(EncryptedMessageInfo::split_detached_signature)
            .expect("Failed to encrypt");

        let mut verifying_reader = Decryptor::default()
            .with_decryption_key(&key)
            .with_verification_key(key.as_public_key())
            .with_external_detached_signature(detached_signature.unwrap())
            .output_utf8()
            .decrypt_stream(&buffer[..], DataEncoding::Armored)
            .expect("Failed to decrypt");

        let mut out = Vec::new();
        utils::test_copy(&mut verifying_reader, &mut out, 4).expect("Failed to copy");
        assert_eq!(out, input_string.as_bytes());
        assert!(verifying_reader.verification_result().is_ok());
    };
    test(false);
    test(true);
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn encrypt_with_future_key() {
    let future_key = KeyGenerator::default()
        .at_date(UnixTime::new(2_139_650_917))
        .with_user_id("test", "test@test.test")
        .generate()
        .unwrap();
    let input_data = b"hello world";
    let encrypted_data = Encryptor::default()
        .with_encryption_key(future_key.as_public_key())
        .encrypt_raw(input_data, DataEncoding::Armored)
        .expect("Failed to encrypt");

    let verified_data = Decryptor::default()
        .with_decryption_key(&future_key)
        .decrypt(encrypted_data.as_slice(), DataEncoding::Armored)
        .expect("Failed to decrypt");

    assert_eq!(verified_data.data, input_data);
    assert!(matches!(
        verified_data.verification_result,
        Err(VerificationError::NotSigned)
    ));

    let disabled_profile = Profile::new(
        ProfileSettingsBuilder::new()
            .allow_encryption_with_future_and_expired_keys(false)
            .build(),
    );

    Encryptor::new(disabled_profile)
        .with_encryption_key(future_key.as_public_key())
        .encrypt_raw(input_data, DataEncoding::Armored)
        .expect_err("expect encryption to fail");
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn encrypt_with_future_key_stream() {
    let future_key = KeyGenerator::default()
        .at_date(UnixTime::new(2_139_650_917))
        .with_user_id("test", "test@test.test")
        .generate()
        .unwrap();
    let input_data = b"hello world".repeat(512);
    let mut buffer = Vec::new();
    Encryptor::default()
        .with_encryption_key(future_key.as_public_key())
        .encrypt_stream(&input_data[..], DataEncoding::Armored, &mut buffer)
        .expect("Failed to encrypt");

    let verified_data = Decryptor::default()
        .with_decryption_key(&future_key)
        .decrypt(buffer.as_slice(), DataEncoding::Armored)
        .expect("Failed to decrypt");

    assert_eq!(verified_data.data, input_data);
    assert!(matches!(
        verified_data.verification_result,
        Err(VerificationError::NotSigned)
    ));

    let disabled_profile = Profile::new(
        ProfileSettingsBuilder::new()
            .allow_encryption_with_future_and_expired_keys(false)
            .build(),
    );

    let mut dst = Vec::new();
    Encryptor::new(disabled_profile)
        .with_encryption_key(future_key.as_public_key())
        .encrypt_stream(&input_data[..], DataEncoding::Armored, &mut dst)
        .expect_err("expect encryption to fail");
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn encrypt_message_v4_text_utf8_fail() {
    let non_utf8_data = b"abc\xFFdef";
    let key = PrivateKey::import_unlocked(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let mut buffer = Vec::new();
    let err = Encryptor::default()
        .with_encryption_key(key.as_public_key())
        .with_signing_key(&key)
        .as_utf8()
        .encrypt_stream(&non_utf8_data[..], DataEncoding::Armored, &mut buffer);

    assert!(matches!(
        err,
        Err(Error::Encryption(
            EncryptionError::DataEncryption(
                pgp::errors::Error::IO { source, .. }
            )
        )) if matches!(source.kind(), std::io::ErrorKind::InvalidData) && source.to_string().contains("Invalid UTF-8 data")
    ));

    Encryptor::default()
        .with_encryption_key(key.as_public_key())
        .with_signing_key(&key)
        .as_utf8()
        .encrypt_raw(&non_utf8_data[..], DataEncoding::Armored)
        .expect_err("expect encryption to fail");
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn encrypt_message_v4_stream_split() {
    let input_data = b"hello world".repeat(1024);
    let key = PrivateKey::import_unlocked(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let mut buffer = Vec::new();
    let (key_packets, _) = Encryptor::new(TEST_PW_PROFILE.clone())
        .with_encryption_key(key.as_public_key())
        .with_passphrase("password")
        .encrypt_stream_split(&input_data[..], &mut buffer)
        .expect("Failed to encrypt");

    Decryptor::default()
        .with_decryption_key(&key)
        .decrypt_session_key(key_packets.as_slice())
        .expect("Failed to decrypt session key");

    let sk = Decryptor::default()
        .with_passphrase("password")
        .decrypt_session_key(key_packets.as_slice())
        .expect("Failed to decrypt session key");

    let verified_data = Decryptor::default()
        .with_session_key(sk)
        .decrypt(buffer.as_slice(), DataEncoding::Unarmored)
        .expect("Failed to decrypt");

    assert_eq!(verified_data.data, input_data);
    assert!(matches!(
        verified_data.verification_result,
        Err(VerificationError::NotSigned)
    ));
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn encrypt_message_v4_stream_split_no_key_packets() {
    let input_data = b"hello world".repeat(1024);
    let sk = dummy_session_key(false);

    let mut buffer = Vec::new();
    let (key_packets, _) = Encryptor::new(TEST_PW_PROFILE.clone())
        .with_session_key(&sk)
        .encrypt_stream_split(&input_data[..], &mut buffer)
        .expect("Failed to encrypt");
    assert!(key_packets.is_empty());
}

fn dummy_session_key(seipdv2: bool) -> SessionKey {
    // NOT SECURE! This is only used for testing.
    const DUMMY_SK: &[u8] = b"00000000000000000000000000000000";
    if seipdv2 {
        SessionKey::new_for_seipdv2(DUMMY_SK)
    } else {
        SessionKey::new(DUMMY_SK, SymmetricKeyAlgorithm::AES256)
    }
}
