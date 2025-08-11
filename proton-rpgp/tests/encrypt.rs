use std::sync::LazyLock;

use pgp::crypto::{aead::AeadAlgorithm, hash::HashAlgorithm, sym::SymmetricKeyAlgorithm};
use proton_rpgp::{
    AsPublicKeyRef, DataEncoding, DecryptionError, Decryptor, Encryptor, PrivateKey, Profile,
    ProfileSettingsBuilder, SessionKey, StringToKeyOption, VerificationError,
};

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

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn encrypt_session_key_v4() {
    let session_key = SessionKey::new(b"0000000000000000", SymmetricKeyAlgorithm::AES128);

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
    let session_key = SessionKey::new_for_seipdv2(b"0000000000000000");

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
    let session_key = SessionKey::new(b"0000000000000000", SymmetricKeyAlgorithm::AES128);

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
    let session_key = SessionKey::new_for_seipdv2(b"0000000000000000");
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
    let session_key = SessionKey::new(b"0000000000000000", SymmetricKeyAlgorithm::AES128);
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
pub fn encrypt_data_with_session_key_seipdv2() {
    let session_key = SessionKey::new_for_seipdv2(b"0000000000000000");
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
