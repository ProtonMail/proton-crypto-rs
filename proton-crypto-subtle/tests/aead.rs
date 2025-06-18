use proton_crypto_subtle::{
    aead::{AesGcmCiphertext, AesGcmKey},
    SubtleError,
};

const CONTEXT: &str = "subtle.test";

#[test]
fn encrypt_decrypt_successful() {
    let key = AesGcmKey::generate();
    let plaintext = b"Hello, world!";
    let ciphertext = key
        .encrypt(plaintext, Some(CONTEXT))
        .expect("Expected no error in encrypting");

    let decrypted = key
        .decrypt(ciphertext, Some(CONTEXT))
        .expect("Expected no error in decrypting");
    assert_eq!(plaintext, decrypted.as_slice());
}

#[test]
fn encrypt_decrypt_with_encoded_ciphertext_successful() {
    let key = AesGcmKey::generate();
    let plaintext = b"Hello, world!";
    let ciphertext = key
        .encrypt(plaintext, Some(CONTEXT))
        .expect("Expected no error in encrypting");

    let encoded = ciphertext.encode();

    let decoded = AesGcmCiphertext::decode(&encoded).expect("Expected no error in decoding");
    let decrypted = key
        .decrypt(decoded, Some(CONTEXT))
        .expect("Expected no error in decrypting");
    assert_eq!(plaintext, decrypted.as_slice());
}

#[test]
fn encrypt_decrypt_wrong_context() {
    let key = AesGcmKey::generate();
    let plaintext = b"Hello, world!";
    let ciphertext = key
        .encrypt(plaintext, Some(CONTEXT))
        .expect("Expected no error in encrypting");

    let result = key.decrypt(ciphertext, Some("wrong_context"));
    assert!(
        matches!(result, Err(SubtleError::Decrypt(_))),
        "Expected decryption to fail with wrong context"
    );
}

#[test]
fn encrypt_decrypt_custom_encoding() {
    let key = AesGcmKey::generate();
    let plaintext = b"Hello, world!";
    let ciphertext = key
        .encrypt(plaintext, Some(CONTEXT))
        .expect("Expected no error in encrypting");
    let iv: &[u8] = ciphertext.iv.as_ref();
    let data: &[u8] = &ciphertext.data;

    let ciphertext =
        AesGcmCiphertext::new(iv, data).expect("Expected no error in creating ciphertext view");
    let plaintext = key
        .decrypt(ciphertext, Some(CONTEXT))
        .expect("Expected no error in decrypting");
    assert_eq!(plaintext, plaintext.as_slice());
}

#[test]
fn encrypt_decrypt_imported_key() {
    let key = AesGcmKey::from_bytes([0; 32]).expect("Import should succeed");
    let plaintext = b"Hello, world!";
    let ciphertext = key
        .encrypt(plaintext, Some(CONTEXT))
        .expect("Expected no error in encrypting");

    let decrypted = key
        .decrypt(ciphertext, Some(CONTEXT))
        .expect("Expected no error in decrypting");
    assert_eq!(plaintext, decrypted.as_slice());
}

#[cfg(feature = "legacy")]
pub mod legacy {
    use super::*;

    #[test]
    fn encrypt_decrypt_successful() {
        let key = AesGcmKey::generate();
        let plaintext = b"Hello, world!";
        let ciphertext = key
            .encrypt_legacy(plaintext, Some(CONTEXT))
            .expect("Expected no error in encrypting");

        let decrypted = key
            .decrypt_legacy(ciphertext, Some(CONTEXT))
            .expect("Expected no error in decrypting");
        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn encrypt_decrypt_wrong_context() {
        let key = AesGcmKey::generate();
        let plaintext = b"Hello, world!";
        let ciphertext = key
            .encrypt_legacy(plaintext, Some(CONTEXT))
            .expect("Expected no error in encrypting");

        let result = key.decrypt_legacy(ciphertext, Some("wrong_context"));
        assert!(
            matches!(result, Err(SubtleError::Decrypt(_))),
            "Expected decryption to fail with wrong context"
        );
    }

    #[test]
    fn encrypt_decrypt_wrong_ciphertext() {
        let key = AesGcmKey::generate();
        let plaintext = b"Hello, world!";
        let ciphertext = key
            .encrypt(plaintext, Some(CONTEXT))
            .expect("Expected no error in encrypting");

        let result = key.decrypt_legacy(ciphertext, Some(CONTEXT));
        assert!(
            matches!(result, Err(SubtleError::InvalidCiphertext)),
            "Expected decryption to fail with wrong ciphertext format"
        );
    }
}
