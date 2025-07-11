use proton_rpgp::{AsPublicKeyRef, DataEncoding, PrivateKey, Signer, UnixTime, Verifier};

pub const TEST_KEY: &str = include_str!("../test-data/keys/private_key_v4.asc");

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn sign_create_detached_signature_v4_binary() {
    let date = UnixTime::new(1_752_476_259);
    let input_data = b"hello world";

    let key = PrivateKey::import_unlocked(TEST_KEY.as_bytes(), DataEncoding::Armor)
        .expect("Failed to import key");

    let signature_bytes = Signer::default()
        .with_signing_key(&key)
        .at_date(date)
        .sign_detached(input_data, DataEncoding::Armor)
        .expect("Failed to sign");

    let verification_result = Verifier::default()
        .with_verification_key(key.as_public_key())
        .at_date(date)
        .verify_detached(input_data, &signature_bytes, DataEncoding::Armor);

    assert!(verification_result.is_ok());
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn sign_create_detached_signature_v4_text() {
    let date = UnixTime::new(1_752_476_259);
    let text = "hello world\n sdf    \n   ";

    let key = PrivateKey::import_unlocked(TEST_KEY.as_bytes(), DataEncoding::Armor)
        .expect("Failed to import key");

    let signature_bytes = Signer::default()
        .with_signing_key(&key)
        .at_date(date)
        .as_utf8()
        .sign_detached(text.as_bytes(), DataEncoding::Armor)
        .expect("Failed to sign");

    let verification_result = Verifier::default()
        .with_verification_key(key.as_public_key())
        .at_date(date)
        .verify_detached(text.as_bytes(), &signature_bytes, DataEncoding::Armor);

    assert!(verification_result.is_ok());
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn sign_create_detached_signature_multi() {
    const TEST_KEY_V6: &str = include_str!("../test-data/keys/private_key_v6.asc");
    let date = UnixTime::new(1_752_476_259);
    let input_data = b"hello world";

    let key = PrivateKey::import_unlocked(TEST_KEY.as_bytes(), DataEncoding::Armor)
        .expect("Failed to import key");
    let key_v6 = PrivateKey::import_unlocked(TEST_KEY_V6.as_bytes(), DataEncoding::Armor)
        .expect("Failed to import key");

    let signature_bytes = Signer::default()
        .with_signing_key(&key_v6)
        .with_signing_key(&key)
        .at_date(date)
        .sign_detached(input_data, DataEncoding::Armor)
        .expect("Failed to sign");

    let verification_result = Verifier::default()
        .with_verification_key(key.as_public_key())
        .at_date(date)
        .verify_detached(input_data, &signature_bytes, DataEncoding::Armor);

    assert!(verification_result.is_ok());

    let verification_result = Verifier::default()
        .with_verification_key(key_v6.as_public_key())
        .at_date(date)
        .verify_detached(input_data, &signature_bytes, DataEncoding::Armor);

    assert!(verification_result.is_ok());
}
