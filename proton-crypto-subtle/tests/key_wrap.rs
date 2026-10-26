use proton_crypto_subtle::{
    aead::AesGcmKey,
    hkdf,
    key_wrap::{AesKwKey, WrappedAesKey},
    SubtleError,
};

#[test]
fn wrap_unwrap_roundtrip() {
    let kek = AesKwKey::generate();
    let secret = AesGcmKey::generate();
    let encoded = kek.wrap(&secret).unwrap().to_vec();
    let decoded = WrappedAesKey::from_bytes(&encoded).unwrap();
    assert_eq!(kek.unwrap(&decoded).unwrap().as_bytes(), secret.as_bytes());
}

#[test]
fn wrapped_key_rejects_invalid_lengths() {
    for len in [0, 24, 32, 39, 41, 48] {
        let wrapped = vec![0_u8; len];
        assert!(
            matches!(
                WrappedAesKey::from_bytes(&wrapped),
                Err(SubtleError::InvalidWrappedKey)
            ),
            "length {len} should be rejected"
        );
    }
}

#[test]
fn unwrap_with_wrong_key_fails() {
    let kek = AesKwKey::generate();
    let other_kek = AesKwKey::generate();
    let wrapped = kek.wrap(&AesGcmKey::generate()).unwrap();

    assert!(matches!(
        other_kek.unwrap(&wrapped),
        Err(SubtleError::KeyUnwrap)
    ));
}

#[test]
fn unwrap_tampered_wrapped_key_fails() {
    let kek = AesKwKey::generate();
    let mut encoded = kek.wrap(&AesGcmKey::generate()).unwrap().into_array();
    encoded[20] ^= 1;

    assert!(matches!(
        kek.unwrap(&WrappedAesKey::from(encoded)),
        Err(SubtleError::KeyUnwrap)
    ));
}

#[test]
fn key_from_bytes_rejects_invalid_length() {
    assert!(matches!(
        AesKwKey::from_bytes([0_u8; 16]),
        Err(SubtleError::InvalidKeyLength)
    ));
    assert!(AesKwKey::try_from([0_u8; 32].as_slice()).is_ok());
}

#[test]
fn unwrapped_key_feeds_hkdf() {
    let kek = AesKwKey::generate();
    let secret = AesGcmKey::from([0x42; 32]);
    let unwrapped = kek.unwrap(&kek.wrap(&secret).unwrap()).unwrap();
    let derived = hkdf::derive_aes_gcm_key(unwrapped.as_bytes(), &[], b"data-key").unwrap();
    let expected = hkdf::derive_aes_gcm_key(secret.as_bytes(), &[], b"data-key").unwrap();
    assert_eq!(derived.as_bytes(), expected.as_bytes());
}

#[test]
fn wrap_unwrap_aes_gcm_key() {
    let kek = AesKwKey::generate();
    let gcm_key = AesGcmKey::generate();
    let ciphertext = gcm_key.encrypt(b"hello", None).unwrap();

    let wrapped = kek.wrap(&gcm_key).unwrap();
    let unwrapped_gcm_key = kek.unwrap(&wrapped).unwrap();

    let plaintext = unwrapped_gcm_key.decrypt(ciphertext, None).unwrap();
    assert_eq!(plaintext, b"hello");
}
