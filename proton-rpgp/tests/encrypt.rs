use std::sync::{Arc, LazyLock, Mutex};

use pgp::{
    crypto::{
        aead::{AeadAlgorithm, ChunkSize},
        hash::HashAlgorithm,
        sym::SymmetricKeyAlgorithm,
    },
    packet::PacketParser,
};
use proton_rpgp::{
    component::{PrivateComponentKeyPublicView, PublicComponentKey},
    AccessKeyInfo, AeadCiphersuite, AsPublicKeyRef, DataEncoding, DecryptionError, Decryptor,
    EncryptedMessage, EncryptedMessageInfo, EncryptionError, EncryptionMechanism,
    EncryptionObserver, Encryptor, Error, ExternalDetachedSignature, KeyGenerator, PrivateKey,
    Profile, ProfileSettings, PublicKey, SessionKey, SignatureContext, StringToKeyOption, UnixTime,
    VerificationContext, VerificationError, HAZARD_AEAD_PROFILE,
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
    ProfileSettings::builder()
        .message_encryption_s2k_params(s2k)
        .build_into_profile()
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
pub fn encrypt_message_v4_mixed() {
    let input_data = b"hello world";
    let passphrase: &str = "password";
    let key = PrivateKey::import_unlocked(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let encrypted_data = Encryptor::new(TEST_PW_PROFILE.clone())
        .with_passphrase(passphrase)
        .with_encryption_key(key.as_public_key())
        .encrypt_raw(input_data, DataEncoding::Armored)
        .expect("Failed to encrypt");

    let decrypted_data = Decryptor::new(TEST_PW_PROFILE.clone())
        .with_passphrase(passphrase)
        .decrypt(&encrypted_data, DataEncoding::Armored)
        .expect("Failed to decrypt");
    assert_eq!(decrypted_data.data, input_data);

    let decrypted_data = Decryptor::new(TEST_PW_PROFILE.clone())
        .with_decryption_key(&key)
        .decrypt(&encrypted_data, DataEncoding::Armored)
        .expect("Failed to decrypt");
    assert_eq!(decrypted_data.data, input_data);
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn encrypt_message_v4_mixed_stream() {
    let input_data = b"hello world".repeat(1024);
    let passphrase: &str = "password";
    let key = PrivateKey::import_unlocked(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let mut buffer = Vec::new();
    Encryptor::new(TEST_PW_PROFILE.clone())
        .with_passphrase(passphrase)
        .with_encryption_key(key.as_public_key())
        .encrypt_stream(&input_data[..], DataEncoding::Armored, &mut buffer)
        .expect("Failed to encrypt");

    let decrypted_data = Decryptor::new(TEST_PW_PROFILE.clone())
        .with_passphrase(passphrase)
        .decrypt(&buffer, DataEncoding::Armored)
        .expect("Failed to decrypt");
    assert_eq!(decrypted_data.data, input_data);

    let decrypted_data = Decryptor::new(TEST_PW_PROFILE.clone())
        .with_decryption_key(&key)
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

    let profile = ProfileSettings::builder()
        .preferred_aead_ciphersuite(Some((SymmetricKeyAlgorithm::AES128, AeadAlgorithm::Gcm)))
        .build_into_profile();

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

    let profile = ProfileSettings::builder()
        .preferred_aead_ciphersuite(Some((SymmetricKeyAlgorithm::AES128, AeadAlgorithm::Gcm)))
        .build_into_profile();

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
pub fn encrypt_with_generated_session_key_from_recipient_preferences() {
    let plain_data = b"hello world";

    let key = PrivateKey::import_unlocked(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let session_key = Encryptor::default()
        .with_encryption_key(key.as_public_key())
        .generate_session_key()
        .expect("Failed to generate session key");

    assert_eq!(session_key.algorithm(), Some(SymmetricKeyAlgorithm::AES256));
    assert_eq!(session_key.export_bytes().len(), 32);

    let mut message = Encryptor::default()
        .with_encryption_key(key.as_public_key())
        .encrypt_session_key(&session_key)
        .expect("Failed to encrypt session key");

    let data_packet = Encryptor::default()
        .with_session_key(&session_key)
        .encrypt_raw(plain_data, DataEncoding::Unarmored)
        .expect("Failed to encrypt");

    message.extend(data_packet.iter());

    let output_data = Decryptor::default()
        .with_decryption_key(&key)
        .with_verification_key(key.as_public_key())
        .decrypt(message, DataEncoding::Unarmored)
        .expect("Failed to decrypt");

    assert_eq!(output_data.data, plain_data);
    assert!(matches!(
        output_data.verification_result,
        Err(VerificationError::NotSigned)
    ));
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn encrypt_and_decrypt_with_signature_context() {
    let date = UnixTime::new(1_752_476_259);
    let plain_data = b"hello world";
    let ctx_name = "test-context";

    let key = PrivateKey::import_unlocked(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let encrypted_data = Encryptor::default()
        .with_encryption_key(key.as_public_key())
        .with_signing_key(&key)
        .with_signature_context(SignatureContext::new(ctx_name.into(), true))
        .at_date(date.into())
        .encrypt_raw(plain_data, DataEncoding::Armored)
        .expect("Failed to encrypt");

    let output_data = Decryptor::default()
        .with_decryption_key(&key)
        .with_verification_key(key.as_public_key())
        .with_verification_context(VerificationContext::new_required(ctx_name.into()))
        .at_date(date.into())
        .decrypt(encrypted_data.as_slice(), DataEncoding::Armored)
        .expect("Failed to decrypt");
    assert_eq!(output_data.data, plain_data);
    assert!(output_data.verification_result.is_ok());

    let output_data = Decryptor::default()
        .with_decryption_key(&key)
        .with_verification_key(key.as_public_key())
        .with_verification_context(VerificationContext::new_required("wrong".into()))
        .at_date(date.into())
        .decrypt(encrypted_data.as_slice(), DataEncoding::Armored)
        .expect("Failed to decrypt");
    assert_eq!(output_data.data, plain_data);
    assert!(matches!(
        output_data.verification_result,
        Err(VerificationError::BadContext(_, _))
    ));
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

    let disabled_profile = ProfileSettings::builder()
        .allow_encryption_with_future_and_expired_keys(false)
        .build_into_profile();

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

    let disabled_profile = ProfileSettings::builder()
        .allow_encryption_with_future_and_expired_keys(false)
        .build_into_profile();

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

#[derive(Debug, Default)]
struct MechanismObserver(Mutex<Option<EncryptionMechanism>>);

impl EncryptionObserver for MechanismObserver {
    fn observe_encryption_keys(&self, _keys: &[PublicComponentKey<'_>]) {}

    fn observe_signing_keys(&self, _key_views: &[PrivateComponentKeyPublicView<'_>]) {}

    fn observe_encryption_mechanism(&self, mechanism: &EncryptionMechanism) {
        *self.0.lock().unwrap() = Some(*mechanism);
    }
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn encrypt_negotiates_seipdv2_for_aead_recipient() {
    let input_data = b"hello world";
    let key = PrivateKey::import_unlocked(TEST_KEY_V6.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let profile = ProfileSettings::builder()
        .preferred_aead_ciphersuite(Some((SymmetricKeyAlgorithm::AES256, AeadAlgorithm::Ocb)))
        .build_into_profile();

    let observer = Arc::new(MechanismObserver::default());

    let encrypted_data = Encryptor::new(profile)
        .with_encryption_key(key.as_public_key())
        .with_observer(observer.clone())
        .encrypt_raw(input_data, DataEncoding::Armored)
        .expect("Failed to encrypt");

    assert!(matches!(
        observer.0.lock().unwrap().expect("mechanism observed"),
        EncryptionMechanism::SeipdV2(_, _)
    ));

    let verified_data = Decryptor::default()
        .with_decryption_key(&key)
        .decrypt(encrypted_data.as_slice(), DataEncoding::Armored)
        .expect("Failed to decrypt");
    assert_eq!(verified_data.data, input_data);
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn encrypt_uses_seipdv1_by_default() {
    let input_data = b"hello world";
    let key = PrivateKey::import_unlocked(TEST_KEY_V6.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let observer = Arc::new(MechanismObserver::default());

    let encrypted_data = Encryptor::default()
        .with_encryption_key(key.as_public_key())
        .with_observer(observer.clone())
        .encrypt_raw(input_data, DataEncoding::Armored)
        .expect("Failed to encrypt");

    assert!(matches!(
        observer.0.lock().unwrap().expect("mechanism observed"),
        EncryptionMechanism::SeipdV1(_)
    ));

    let verified_data = Decryptor::default()
        .with_decryption_key(&key)
        .decrypt(encrypted_data.as_slice(), DataEncoding::Armored)
        .expect("Failed to decrypt");
    assert_eq!(verified_data.data, input_data);
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn encrypt_negotiates_seipdv1_for_mixed_recipients() {
    let input_data = b"hello world";
    let key_v4 = PrivateKey::import_unlocked(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");
    let key_v6 = PrivateKey::import_unlocked(TEST_KEY_V6.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let profile = ProfileSettings::builder()
        .preferred_aead_ciphersuite(Some((SymmetricKeyAlgorithm::AES256, AeadAlgorithm::Ocb)))
        .build_into_profile();

    let observer = Arc::new(MechanismObserver::default());

    let encrypted_data = Encryptor::new(profile)
        .with_encryption_keys([key_v4.as_public_key(), key_v6.as_public_key()])
        .with_observer(observer.clone())
        .encrypt_raw(input_data, DataEncoding::Armored)
        .expect("Failed to encrypt");

    assert!(matches!(
        observer.0.lock().unwrap().expect("mechanism observed"),
        EncryptionMechanism::SeipdV1(_)
    ));

    // Both recipients can decrypt the SEIPD v1 message.
    for key in [&key_v4, &key_v6] {
        let verified_data = Decryptor::default()
            .with_decryption_key(key)
            .decrypt(encrypted_data.as_slice(), DataEncoding::Armored)
            .expect("Failed to decrypt");
        assert_eq!(verified_data.data, input_data);
    }
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn encrypt_message_with_multiple_passphrases() {
    let input_data = b"hello world";
    let passphrases = ["first-password", "second-password"];

    let encrypted_data = Encryptor::new(TEST_PW_PROFILE.clone())
        .with_passphrases(passphrases)
        .encrypt_raw(input_data, DataEncoding::Armored)
        .expect("Failed to encrypt");

    // Each individual passphrase decrypts the message.
    for passphrase in passphrases {
        let decrypted_data = Decryptor::new(TEST_PW_PROFILE.clone())
            .with_passphrase(passphrase)
            .decrypt(encrypted_data.as_slice(), DataEncoding::Armored)
            .expect("Failed to decrypt");
        assert_eq!(decrypted_data.data, input_data);
    }

    // Decryption succeeds when the correct passphrase is tried among others.
    let decrypted_data = Decryptor::new(TEST_PW_PROFILE.clone())
        .with_passphrases(["wrong-password", "second-password"])
        .decrypt(encrypted_data.as_slice(), DataEncoding::Armored)
        .expect("Failed to decrypt");
    assert_eq!(decrypted_data.data, input_data);

    // Decryption fails when none of the passphrases match.
    Decryptor::new(TEST_PW_PROFILE.clone())
        .with_passphrases(["wrong-1", "wrong-2"])
        .decrypt(encrypted_data.as_slice(), DataEncoding::Armored)
        .expect_err("Decryption must fail with wrong passphrases");
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

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn encrypt_message_v4_with_observer() {
    /// Observer for testing
    #[derive(Debug)]
    struct TestEncryptionObserver {
        key: PrivateKey,
    }

    impl EncryptionObserver for TestEncryptionObserver {
        fn observe_encryption_keys(&self, keys: &[PublicComponentKey<'_>]) {
            let observed_key = keys.first().unwrap();
            assert_eq!(
                self.key.key_id(),
                observed_key
                    .primary_self_certification
                    .issuer_key_id()
                    .into_iter()
                    .next()
                    .copied()
                    .unwrap()
            );
        }

        fn observe_signing_keys(&self, key_views: &[PrivateComponentKeyPublicView<'_>]) {
            let observed_key = key_views.first().unwrap();
            assert_eq!(
                self.key.fingerprint(),
                observed_key.key_details.fingerprint()
            );
        }

        fn observe_encryption_mechanism(&self, mechanism: &EncryptionMechanism) {
            assert!(matches!(mechanism, EncryptionMechanism::SeipdV1(_)));
        }
    }

    let input_data = b"hello world";
    let key = PrivateKey::import_unlocked(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let observer = TestEncryptionObserver { key: key.clone() };

    let _ = Encryptor::default()
        .with_encryption_key(key.as_public_key())
        .with_signing_key(&key)
        .with_observer(Arc::new(observer))
        .encrypt_raw(input_data, DataEncoding::Armored)
        .expect("Failed to encrypt");
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn encrypt_message_v4_with_compression() {
    let input_data = b"hello world";
    let key = PrivateKey::import_unlocked(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let encrypted_data = Encryptor::default()
        .compress()
        .with_encryption_key(key.as_public_key())
        .encrypt(input_data)
        .expect("Failed to encrypt");

    let session_key = encrypted_data
        .revealed_session_key()
        .expect("Failed to get session key");

    assert!(has_compression(
        encrypted_data.as_bytes(),
        session_key.export_bytes().as_ref(),
    ));

    let encrypted_data = Encryptor::default()
        .with_encryption_key(key.as_public_key())
        .encrypt(input_data)
        .expect("Failed to encrypt");

    let session_key = encrypted_data
        .revealed_session_key()
        .expect("Failed to get session key");

    assert!(!has_compression(
        encrypted_data.as_bytes(),
        session_key.export_bytes().as_ref(),
    ));
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn encrypt_message_v4_compression_only_when_enabled() {
    const PUBLIC_KEY_NO_UNCOMPRESSED: &str =
        include_str!("../test-data/keys/public_key_v4_no_uncompressed.asc");
    let input_data = b"hello world";
    let public_key =
        PublicKey::import(PUBLIC_KEY_NO_UNCOMPRESSED.as_bytes(), DataEncoding::Armored)
            .expect("Failed to import key");

    let encrypted_data = Encryptor::default()
        .compress()
        .with_encryption_key(&public_key)
        .encrypt(input_data)
        .expect("Failed to encrypt");

    let session_key = encrypted_data
        .revealed_session_key()
        .expect("Failed to get session key");

    assert!(has_compression(
        encrypted_data.as_bytes(),
        session_key.export_bytes().as_ref(),
    ));

    let encrypted_data = Encryptor::default()
        .with_encryption_key(&public_key)
        .encrypt(input_data)
        .expect("Failed to encrypt");

    let session_key = encrypted_data
        .revealed_session_key()
        .expect("Failed to get session key");

    assert!(!has_compression(
        encrypted_data.as_bytes(),
        session_key.export_bytes().as_ref(),
    ));
}

// Test helper to check if the message is internally compressed.
fn has_compression(encrypted_message: &[u8], session_key_bytes: &[u8]) -> bool {
    use pgp::composed::{DecryptionOptions, Message, PlainSessionKey, TheRing};

    let msg = Message::from_bytes(encrypted_message).expect("Failed to parse message");

    let session_key = PlainSessionKey::V3_4 {
        sym_alg: SymmetricKeyAlgorithm::AES256,
        key: session_key_bytes.into(),
    };

    let the_ring = TheRing {
        session_keys: vec![session_key],
        decrypt_options: DecryptionOptions::default().enable_gnupg_aead(),
        ..Default::default()
    };

    let (decrypted, _) = msg
        .decrypt_the_ring(the_ring, false)
        .expect("Failed to decrypt message");

    matches!(decrypted, Message::Compressed { .. })
}

const TEST_PRIVATE_KEY_WITH_AEAD: &str =
    include_str!("../test-data/keys/locked_private_key_v4_seipdv2.asc");

const TEST_PRIVATE_KEY_WITHOUT_AEAD: &str =
    include_str!("../test-data/keys/locked_private_key_v4_no_seipdv2.asc");

const TEST_PRIVATE_KEY_AEAD_PASSWORD: &[u8] = b"password";

#[test]
#[allow(clippy::indexing_slicing)]
#[allow(clippy::missing_panics_doc)]
fn aead_seipdv2_encryption_with_session_key() {
    // Key with SEIPDv2 flag.
    let key_aead = PrivateKey::import(
        TEST_PRIVATE_KEY_WITH_AEAD.as_bytes(),
        TEST_PRIVATE_KEY_AEAD_PASSWORD,
        DataEncoding::Armored,
    )
    .expect("Failed to import key");

    // Key without SEIPDv2 flag.
    let key = PrivateKey::import(
        TEST_PRIVATE_KEY_WITHOUT_AEAD.as_bytes(),
        TEST_PRIVATE_KEY_AEAD_PASSWORD,
        DataEncoding::Armored,
    )
    .expect("Failed to import key");

    let content = b"hello";

    // The AEAD key advertises SEIPDv2 support, so the generated session key is an AEAD session key.
    let sk_aead = Encryptor::default()
        .with_aead_allowed(Some(AeadCiphersuite::default()))
        .with_encryption_key(key_aead.as_public_key())
        .generate_session_key()
        .expect("Failed to generate session key");
    assert!(sk_aead.is_seipdv2_aead());

    // If AEAD is not enabled, the session key should not be an AEAD with a default profile.
    let sk_should_not_be_aead = Encryptor::default()
        .with_encryption_key(key_aead.as_public_key())
        .generate_session_key()
        .expect("Failed to generate session key");
    assert!(!sk_should_not_be_aead.is_seipdv2_aead());

    // The non-AEAD key does not advertise SEIPDv2 support, so AEAD is not used.
    let sk = Encryptor::default()
        .with_aead_allowed(Some(AeadCiphersuite::default()))
        .with_encryption_key(key.as_public_key())
        .generate_session_key()
        .expect("Failed to generate session key");
    assert!(!sk.is_seipdv2_aead());

    let mut key_packet_aead = Encryptor::default()
        .with_encryption_key(key_aead.as_public_key())
        .encrypt_session_key(&sk_aead)
        .expect("encrypt session key failed");
    let key_packet = Encryptor::default()
        .with_encryption_key(key.as_public_key())
        .encrypt_session_key(&sk)
        .expect("encrypt session key failed");

    let session_key_decrypted_aead = Decryptor::default()
        .with_decryption_key(&key_aead)
        .decrypt_session_key(&key_packet_aead)
        .expect("Failed to decrypt session key");

    // An AEAD session key is always encrypted into a PKESKv6 packet, independent of the recipient.
    let key_packet_pkeskv6 = Encryptor::default()
        .with_encryption_key(key.as_public_key())
        .encrypt_session_key(&session_key_decrypted_aead)
        .expect("encrypt session key failed");
    assert_eq!(key_packet_pkeskv6[2], 6); // PKESKv6

    let key_packet_pkeskv6 = Encryptor::default()
        .with_encryption_key(key_aead.as_public_key())
        .encrypt_session_key(&session_key_decrypted_aead)
        .expect("encrypt session key failed");
    assert_eq!(key_packet_pkeskv6[2], 6); // PKESKv6

    let data_packet_aead = Encryptor::default()
        .with_session_key(&sk_aead)
        .encrypt_raw(content, DataEncoding::Unarmored)
        .expect("encryption failed");
    let data_packet = Encryptor::default()
        .with_session_key(&sk)
        .encrypt_raw(content, DataEncoding::Unarmored)
        .expect("encryption failed");

    key_packet_aead.extend_from_slice(&data_packet_aead);

    // Check decryption.
    let output = Decryptor::default()
        .with_decryption_key(&key_aead)
        .decrypt(&key_packet_aead, DataEncoding::Unarmored)
        .expect("decryption failed");
    assert_eq!(output.data, content);

    // Check packets.
    assert_eq!(key_packet_aead[2], 6); // PKESKv6
    assert_eq!(data_packet_aead[2], 2); // SEIPDv2
    assert_eq!(key_packet[2], 3); // PKESKv3
    assert_eq!(data_packet[2], 1); // SEIPDv1
}

#[test]
#[allow(clippy::indexing_slicing)]
#[allow(clippy::missing_panics_doc)]
fn aead_seipdv2_encryption_with_aead_profile() {
    // Key with SEIPDv2 flag.
    let key_aead = PrivateKey::import(
        TEST_PRIVATE_KEY_WITH_AEAD.as_bytes(),
        TEST_PRIVATE_KEY_AEAD_PASSWORD,
        DataEncoding::Armored,
    )
    .expect("Failed to import key");

    // Key without SEIPDv2 flag.
    let key = PrivateKey::import(
        TEST_PRIVATE_KEY_WITHOUT_AEAD.as_bytes(),
        TEST_PRIVATE_KEY_AEAD_PASSWORD,
        DataEncoding::Armored,
    )
    .expect("Failed to import key");

    let content = b"hello";

    // The AEAD key advertises SEIPDv2 support, so the generated session key is an AEAD session key.
    let sk_aead = Encryptor::new(HAZARD_AEAD_PROFILE.clone())
        .with_encryption_key(key_aead.as_public_key())
        .generate_session_key()
        .expect("Failed to generate session key");
    assert!(sk_aead.is_seipdv2_aead());

    // If AEAD is not enabled, the session key should not be an AEAD with a default profile.
    let sk_should_not_be_aead = Encryptor::default()
        .with_encryption_key(key_aead.as_public_key())
        .generate_session_key()
        .expect("Failed to generate session key");
    assert!(!sk_should_not_be_aead.is_seipdv2_aead());

    // The non-AEAD key does not advertise SEIPDv2 support, so AEAD is not used.
    let sk = Encryptor::new(HAZARD_AEAD_PROFILE.clone())
        .with_encryption_key(key.as_public_key())
        .generate_session_key()
        .expect("Failed to generate session key");
    assert!(!sk.is_seipdv2_aead());

    let mut key_packet_aead = Encryptor::default()
        .with_encryption_key(key_aead.as_public_key())
        .encrypt_session_key(&sk_aead)
        .expect("encrypt session key failed");
    let key_packet = Encryptor::default()
        .with_encryption_key(key.as_public_key())
        .encrypt_session_key(&sk)
        .expect("encrypt session key failed");

    let session_key_decrypted_aead = Decryptor::default()
        .with_decryption_key(&key_aead)
        .decrypt_session_key(&key_packet_aead)
        .expect("Failed to decrypt session key");

    // An AEAD session key is always encrypted into a PKESKv6 packet, independent of the recipient.
    let key_packet_pkeskv6 = Encryptor::default()
        .with_encryption_key(key.as_public_key())
        .encrypt_session_key(&session_key_decrypted_aead)
        .expect("encrypt session key failed");
    assert_eq!(key_packet_pkeskv6[2], 6); // PKESKv6

    let key_packet_pkeskv6 = Encryptor::default()
        .with_encryption_key(key_aead.as_public_key())
        .encrypt_session_key(&session_key_decrypted_aead)
        .expect("encrypt session key failed");
    assert_eq!(key_packet_pkeskv6[2], 6); // PKESKv6

    let data_packet_aead = Encryptor::default()
        .with_session_key(&sk_aead)
        .encrypt_raw(content, DataEncoding::Unarmored)
        .expect("encryption failed");
    let data_packet = Encryptor::default()
        .with_session_key(&sk)
        .encrypt_raw(content, DataEncoding::Unarmored)
        .expect("encryption failed");

    key_packet_aead.extend_from_slice(&data_packet_aead);

    // Check decryption.
    let output = Decryptor::default()
        .with_decryption_key(&key_aead)
        .decrypt(&key_packet_aead, DataEncoding::Unarmored)
        .expect("decryption failed");
    assert_eq!(output.data, content);

    // Check packets.
    assert_eq!(key_packet_aead[2], 6); // PKESKv6
    assert_eq!(data_packet_aead[2], 2); // SEIPDv2
    assert_eq!(key_packet[2], 3); // PKESKv3
    assert_eq!(data_packet[2], 1); // SEIPDv1
}

#[test]
#[allow(clippy::indexing_slicing)]
#[allow(clippy::missing_panics_doc)]
fn aead_seipd_v2_encryption_with_session_key_import() {
    // Key without SEIPDv2 flag.
    let key = PrivateKey::import(
        TEST_PRIVATE_KEY_WITHOUT_AEAD.as_bytes(),
        TEST_PRIVATE_KEY_AEAD_PASSWORD,
        DataEncoding::Armored,
    )
    .expect("Failed to import key");

    let dummy_sk =
        SessionKey::generate_for_seipdv1(SymmetricKeyAlgorithm::AES256, &Profile::default());
    let content = b"hello";

    let exported = dummy_sk.export_bytes();

    // The session key encodes AEAD and forces it independent of the profile.
    let sk_aead = SessionKey::new_for_seipdv2(exported.as_ref());
    let sk = SessionKey::new(exported.as_ref(), SymmetricKeyAlgorithm::AES256);

    let key_packet_aead = Encryptor::default()
        .with_encryption_key(key.as_public_key())
        .encrypt_session_key(&sk_aead)
        .expect("encrypt session key failed");
    let key_packet = Encryptor::default()
        .with_encryption_key(key.as_public_key())
        .encrypt_session_key(&sk)
        .expect("encrypt session key failed");

    let data_packet_aead = Encryptor::default()
        .with_session_key(&sk_aead)
        .encrypt_raw(content, DataEncoding::Unarmored)
        .expect("encryption failed");
    let data_packet = Encryptor::default()
        .with_session_key(&sk)
        .encrypt_raw(content, DataEncoding::Unarmored)
        .expect("encryption failed");

    // Check packets.
    assert_eq!(key_packet_aead[2], 6); // PKESKv6
    assert_eq!(data_packet_aead[2], 2); // SEIPDv2
    assert_eq!(key_packet[2], 3); // PKESKv3
    assert_eq!(data_packet[2], 1); // SEIPDv1
}

#[test]
#[allow(clippy::missing_panics_doc)]
fn aead_seipd_v2_chunk_size_override() {
    let sk_seipdv2 =
        SessionKey::generate_for_seipdv2(SymmetricKeyAlgorithm::AES256, &Profile::default());

    let default_chunk_size = Profile::default().message_aead_chunk_size();
    let message = Encryptor::default()
        .with_session_key(&sk_seipdv2)
        .encrypt_raw(b"hello", DataEncoding::Unarmored)
        .expect("encryption failed");
    assert_eq!(seipd_v2_chunk_size(&message), default_chunk_size);

    let message = Encryptor::default()
        .with_session_key(&sk_seipdv2)
        .with_aead_chunk_size(ChunkSize::C1MiB)
        .encrypt_raw(b"hello", DataEncoding::Unarmored)
        .expect("encryption failed");
    assert_eq!(seipd_v2_chunk_size(&message), ChunkSize::C1MiB);

    let message = Encryptor::default()
        .with_session_key(&sk_seipdv2)
        .with_aead_chunk_size(ChunkSize::C512KiB)
        .encrypt_raw(b"hello", DataEncoding::Unarmored)
        .expect("encryption failed");
    assert_eq!(seipd_v2_chunk_size(&message), ChunkSize::C512KiB);

    let qkbyte = [42_u8; 1024];
    let message = Encryptor::default()
        .with_session_key(&sk_seipdv2)
        .with_aead_chunk_size(ChunkSize::C64B)
        .encrypt_raw(&qkbyte, DataEncoding::Unarmored)
        .expect("encryption failed");
    assert_eq!(seipd_v2_chunk_size(&message), ChunkSize::C64B);
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn encrypt_utf8_normalizes_line_endings() {
    let date = UnixTime::new(1_752_476_259);
    let input_data = b"line one\nline two\n";

    let key = PrivateKey::import_unlocked(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let encrypted_data = Encryptor::default()
        .with_encryption_key(key.as_public_key())
        .with_signing_key(&key)
        .at_date(date.into())
        .as_utf8()
        .encrypt_raw(input_data, DataEncoding::Armored)
        .expect("Failed to encrypt");

    let native = Decryptor::default()
        .with_decryption_key(&key)
        .with_verification_key(key.as_public_key())
        .at_date(date.into())
        .output_utf8()
        .decrypt(encrypted_data.as_slice(), DataEncoding::Armored)
        .expect("Failed to decrypt");
    assert_eq!(native.data, b"line one\nline two\n");
    assert!(native.verification_result.is_ok());

    let canonical = Decryptor::default()
        .with_decryption_key(&key)
        .with_verification_key(key.as_public_key())
        .at_date(date.into())
        .decrypt(encrypted_data.as_slice(), DataEncoding::Armored)
        .expect("Failed to decrypt");
    assert_eq!(canonical.data, b"line one\r\nline two\r\n");
    assert!(canonical.verification_result.is_ok());
}

fn seipd_v2_chunk_size(encrypted_message: &[u8]) -> ChunkSize {
    let pgp::packet::Packet::SymEncryptedProtectedData(seipd) =
        PacketParser::new(encrypted_message)
            .next()
            .expect("no packet")
            .expect("packet parse failed")
    else {
        panic!("Expected SEIPD v2 SymEncryptedProtectedData packet");
    };
    let pgp::packet::SymEncryptedProtectedDataConfig::V2 { chunk_size, .. } = seipd.config() else {
        panic!("Expected SEIPD v2 SymEncryptedProtectedData packet");
    };
    *chunk_size
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn encrypt_and_sign_message_v4_empty() {
    let input_data = b"";
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

fn encrypt_sign_decrypt_verify_roundtrip(locked_key: &str) {
    let input_data = b"hello world";
    let key = PrivateKey::import(locked_key.as_bytes(), b"password", DataEncoding::Armored)
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
pub fn encrypt_sign_decrypt_verify_rsa_1023() {
    const TEST_KEY_RSA_1023: &str =
        include_str!("../test-data/keys/locked_private_key_v4_rsa_1023.asc");
    encrypt_sign_decrypt_verify_roundtrip(TEST_KEY_RSA_1023);
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn encrypt_sign_decrypt_verify_nist_p256() {
    const TEST_KEY_NIST_P256: &str =
        include_str!("../test-data/keys/locked_private_key_v4_nist_p256.asc");
    encrypt_sign_decrypt_verify_roundtrip(TEST_KEY_NIST_P256);
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn encrypt_sign_decrypt_verify_nist_p521() {
    const TEST_KEY_NIST_P521: &str =
        include_str!("../test-data/keys/locked_private_key_v4_nist_p521.asc");
    encrypt_sign_decrypt_verify_roundtrip(TEST_KEY_NIST_P521);
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn encrypt_sign_decrypt_verify_v6_curve448() {
    const TEST_KEY_V6_CURVE448: &str =
        include_str!("../test-data/keys/locked_private_key_v6_curve448.asc");
    encrypt_sign_decrypt_verify_roundtrip(TEST_KEY_V6_CURVE448);
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn encrypt_sign_brainpool_p256_is_unsupported() {
    const TEST_KEY_BRAINPOOL_P256: &str =
        include_str!("../test-data/keys/locked_private_key_v4_brainpool_p256.asc");
    let input_data = b"hello world";
    let key = PrivateKey::import(
        TEST_KEY_BRAINPOOL_P256.as_bytes(),
        b"password",
        DataEncoding::Armored,
    )
    .expect("Failed to import key");

    let result = Encryptor::default()
        .with_encryption_key(key.as_public_key())
        .with_signing_key(&key)
        .encrypt_raw(input_data, DataEncoding::Armored);

    assert!(matches!(
        result,
        Err(Error::Encryption(EncryptionError::EncryptionKeySelection(
            _
        )))
    ));
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn encrypt_message_v4_key_with_malformed_mpi_subkey() {
    const PUBLIC_KEY: &str =
        include_str!("../test-data/keys/public_key_v4_mpi_malformed_subkey.asc");
    let input_data = b"hello world";
    let public_key = PublicKey::import(PUBLIC_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    Encryptor::default()
        .with_encryption_key(&public_key)
        .encrypt(input_data)
        .expect("Failed to encrypt");
}

/// Checks that the message and its encrypted detached signature share one session key.
fn check_detached_signature_shares_session_key(
    key: &PrivateKey,
    input_data: &[u8],
    message: &[u8],
    session_key: &SessionKey,
    signature: &[u8],
) {
    // Session key only (e.g., Drive).
    let verified_data = Decryptor::default()
        .with_session_key(session_key)
        .with_verification_key(key.as_public_key())
        .with_external_detached_signature(ExternalDetachedSignature::new_encrypted(
            signature,
            DataEncoding::Unarmored,
        ))
        .decrypt(message, DataEncoding::Unarmored)
        .expect("Failed to decrypt with session key");
    assert_eq!(verified_data.data, input_data);
    assert!(verified_data.verification_result.is_ok());

    let sig_session_key = Decryptor::default()
        .with_decryption_key(key)
        .decrypt_session_key(message)
        .expect("Failed to decrypt session key");
    assert_eq!(sig_session_key.export_bytes(), session_key.export_bytes());
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn encrypt_detached_signature_shares_session_key() {
    let input_data = b"hello world".repeat(16);
    for key_data in [TEST_KEY, TEST_KEY_V6] {
        let key = PrivateKey::import_unlocked(key_data.as_bytes(), DataEncoding::Armored)
            .expect("Failed to import key");

        let encryptor = || {
            Encryptor::default()
                .with_encryption_key(key.as_public_key())
                .with_signing_key(&key)
                .using_detached_signature(true)
        };

        // One-shot.
        let (message, signature) = encryptor()
            .encrypt(&input_data)
            .map(EncryptedMessage::split_detached_signature)
            .expect("Failed to encrypt");
        let signature = signature.unwrap().unarmored().unwrap();
        let session_key = message.revealed_session_key().unwrap();
        check_detached_signature_shares_session_key(
            &key,
            &input_data,
            message.as_bytes(),
            session_key,
            &signature,
        );
        // The signature is a standalone message with its own key packets.
        Decryptor::default()
            .with_decryption_key(&key)
            .decrypt(&signature, DataEncoding::Unarmored)
            .expect("Failed to decrypt signature with key");

        // Stream.
        let mut message = Vec::new();
        let (info, signature) = encryptor()
            .encrypt_stream(&input_data[..], DataEncoding::Unarmored, &mut message)
            .map(EncryptedMessageInfo::split_detached_signature)
            .expect("Failed to encrypt");
        let signature = signature.unwrap().unarmored().unwrap();
        check_detached_signature_shares_session_key(
            &key,
            &input_data,
            &message,
            info.revealed_session_key().unwrap(),
            &signature,
        );

        // Stream split: the signature only contains the data packet.
        let mut data_packet = Vec::new();
        let (key_packets, info) = encryptor()
            .encrypt_stream_split(&input_data[..], &mut data_packet)
            .expect("Failed to encrypt");
        let (info, signature) = info.split_detached_signature();
        let signature = signature.unwrap().unarmored().unwrap();
        let message = [key_packets.as_slice(), data_packet.as_slice()].concat();
        check_detached_signature_shares_session_key(
            &key,
            &input_data,
            &message,
            info.revealed_session_key().unwrap(),
            &signature,
        );
        assert!(Decryptor::default()
            .with_decryption_key(&key)
            .decrypt(&signature, DataEncoding::Unarmored)
            .is_err());

        // Prepending the message key packets to the signature.
        let signature_with_key_packets = [key_packets.as_slice(), signature.as_slice()].concat();
        let verified_data = Decryptor::default()
            .with_decryption_key(&key)
            .with_verification_key(key.as_public_key())
            .with_external_detached_signature(ExternalDetachedSignature::new_encrypted(
                signature_with_key_packets,
                DataEncoding::Unarmored,
            ))
            .decrypt(&message, DataEncoding::Unarmored)
            .expect("Failed to decrypt");
        assert_eq!(verified_data.data, input_data);
        assert!(verified_data.verification_result.is_ok());
    }
}
