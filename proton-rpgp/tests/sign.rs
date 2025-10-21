use proton_rpgp::{
    AsPublicKeyRef, DataEncoding, Error, PrivateKey, SignatureContext, Signer, SigningError,
    UnixTime, VerificationContext, VerificationError, Verifier,
};

pub const TEST_KEY: &str = include_str!("../test-data/keys/private_key_v4.asc");
pub const TEST_KEY_V6: &str = include_str!("../test-data/keys/private_key_v6.asc");

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn sign_create_detached_signature_v4_binary() {
    let date = UnixTime::new(1_752_476_259);
    let input_data = b"hello world";

    let key = PrivateKey::import_unlocked(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let signature_bytes = Signer::default()
        .with_signing_key(&key)
        .at_date(date.into())
        .sign_detached(input_data, DataEncoding::Armored)
        .expect("Failed to sign");

    let verification_result = Verifier::default()
        .with_verification_key(key.as_public_key())
        .at_date(date.into())
        .verify_detached(input_data, &signature_bytes, DataEncoding::Armored);

    assert!(verification_result.is_ok());
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn sign_create_detached_signature_v4_text() {
    let date = UnixTime::new(1_752_476_259);
    let text = "hello world\n sdf    \n   ";

    let key = PrivateKey::import_unlocked(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let signature_bytes = Signer::default()
        .with_signing_key(&key)
        .at_date(date.into())
        .as_utf8()
        .sign_detached(text.as_bytes(), DataEncoding::Armored)
        .expect("Failed to sign");

    let verification_result = Verifier::default()
        .with_verification_key(key.as_public_key())
        .at_date(date.into())
        .verify_detached(text.as_bytes(), &signature_bytes, DataEncoding::Armored);

    assert!(verification_result.is_ok());
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn sign_create_detached_signature_multi() {
    const TEST_KEY_V6: &str = include_str!("../test-data/keys/private_key_v6.asc");
    let date = UnixTime::new(1_752_476_259);
    let input_data = b"hello world";

    let key = PrivateKey::import_unlocked(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");
    let key_v6 = PrivateKey::import_unlocked(TEST_KEY_V6.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let signature_bytes = Signer::default()
        .with_signing_key(&key_v6)
        .with_signing_key(&key)
        .at_date(date.into())
        .sign_detached(input_data, DataEncoding::Armored)
        .expect("Failed to sign");

    let verification_result = Verifier::default()
        .with_verification_key(key.as_public_key())
        .at_date(date.into())
        .verify_detached(input_data, &signature_bytes, DataEncoding::Armored);

    assert!(verification_result.is_ok());

    let verification_result = Verifier::default()
        .with_verification_key(key_v6.as_public_key())
        .at_date(date.into())
        .verify_detached(input_data, &signature_bytes, DataEncoding::Armored);

    assert!(verification_result.is_ok());
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn sign_create_detached_signature_rsa_1023() {
    const TEST_KEY_V4: &str = include_str!("../test-data/keys/locked_private_key_v4_rsa_1023.asc");
    let date = UnixTime::new(1_752_476_259);
    let input_data = b"hello world";

    let key = PrivateKey::import(TEST_KEY_V4.as_bytes(), b"password", DataEncoding::Armored)
        .expect("Failed to import key");

    let signature_bytes = Signer::default()
        .with_signing_key(&key)
        .at_date(date.into())
        .sign_detached(input_data, DataEncoding::Armored)
        .expect("Failed to sign");

    let verification_result = Verifier::default()
        .with_verification_key(key.as_public_key())
        .at_date(date.into())
        .verify_detached(input_data, &signature_bytes, DataEncoding::Armored);

    assert!(verification_result.is_ok());
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn sign_create_text_signature_with_non_utf8_data_should_fail() {
    let date = UnixTime::new(1_752_476_259);
    let input_data = b"hello world\x80";

    let key = PrivateKey::import_unlocked(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    // Text mode should fail.
    let result = Signer::default()
        .with_signing_key(&key)
        .as_utf8()
        .at_date(date.into())
        .sign_detached(input_data, DataEncoding::Armored);

    assert!(matches!(
        result,
        Err(Error::Signing(SigningError::InvalidInputData(_)))
    ));

    // Binary mode should not fail.
    let result = Signer::default()
        .with_signing_key(&key)
        .at_date(date.into())
        .sign_detached(input_data, DataEncoding::Armored);

    assert!(result.is_ok());
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn sign_create_detached_signature_v6_pqc() {
    const KEY: &str = include_str!("../test-data/keys/private_key_v6_pqc.asc");
    let input_data = b"hello world";

    let date = UnixTime::new(1_752_237_138);

    let key = PrivateKey::import_unlocked(KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let signature_bytes = Signer::default()
        .with_signing_key(&key)
        .at_date(date.into())
        .sign_detached(input_data, DataEncoding::Armored)
        .expect("Failed to sign");

    let verification_result = Verifier::default()
        .with_verification_key(key.as_public_key())
        .at_date(date.into())
        .verify_detached(input_data, &signature_bytes, DataEncoding::Armored);

    assert!(verification_result.is_ok());
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn sign_verify_inline_message_v4() {
    let input_data = b"hello world";

    let key = PrivateKey::import_unlocked(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let message = Signer::default()
        .with_signing_key(&key)
        .sign(input_data, DataEncoding::Armored)
        .expect("Failed to sign");

    let verified_data = Verifier::default()
        .with_verification_key(key.as_public_key())
        .verify(&message, DataEncoding::Armored)
        .expect("Failed to verify");

    assert_eq!(verified_data.data, input_data);
    assert!(verified_data.verification_result.is_ok());

    // Fail to verify with wrong key.
    let wrong_key = PrivateKey::import_unlocked(TEST_KEY_V6.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let result = Verifier::default()
        .with_verification_key(wrong_key.as_public_key())
        .verify(&message, DataEncoding::Armored)
        .expect("Verify failed");

    assert!(matches!(
        result.verification_result,
        Err(VerificationError::NoVerifier(_, _))
    ));
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn sign_verify_inline_message_v6() {
    let input_data = b"hello world";

    let key = PrivateKey::import_unlocked(TEST_KEY_V6.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let message = Signer::default()
        .with_signing_key(&key)
        .sign(input_data, DataEncoding::Armored)
        .expect("Failed to sign");

    let verified_data = Verifier::default()
        .with_verification_key(key.as_public_key())
        .verify(message, DataEncoding::Armored)
        .expect("Failed to verify");

    assert_eq!(verified_data.data, input_data);
    assert!(verified_data.verification_result.is_ok());
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn sign_verify_inline_message_v4_text() {
    let input_data = b"hello\n world \n   \n   \n ";

    let key = PrivateKey::import_unlocked(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let message = Signer::default()
        .with_signing_key(&key)
        .as_utf8()
        .sign(input_data, DataEncoding::Armored)
        .expect("Failed to sign");

    let verified_data = Verifier::default()
        .with_verification_key(key.as_public_key())
        .output_utf8()
        .verify(&message, DataEncoding::Armored)
        .expect("Failed to verify");

    assert_eq!(verified_data.data, input_data);
    assert!(verified_data.verification_result.is_ok());

    let verified_data = Verifier::default()
        .with_verification_key(key.as_public_key())
        .verify(message, DataEncoding::Armored)
        .expect("Failed to verify");

    assert_eq!(verified_data.data, b"hello\r\n world \r\n   \r\n   \r\n ");
    assert!(verified_data.verification_result.is_ok());
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn sign_verify_inline_message_multiple_keys() {
    let input_data = b"hello world";

    let key = PrivateKey::import_unlocked(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let key_v6 = PrivateKey::import_unlocked(TEST_KEY_V6.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let message = Signer::default()
        .with_signing_key(&key)
        .with_signing_key(&key_v6)
        .sign(input_data, DataEncoding::Armored)
        .expect("Failed to sign");

    let verified_data = Verifier::default()
        .with_verification_key(key.as_public_key())
        .verify(&message, DataEncoding::Armored)
        .expect("Failed to verify");

    assert_eq!(verified_data.data, input_data);
    assert!(verified_data.verification_result.is_ok());

    let verified_data = Verifier::default()
        .with_verification_key(key_v6.as_public_key())
        .verify(&message, DataEncoding::Armored)
        .expect("Failed to verify");

    assert_eq!(verified_data.data, input_data);
    assert!(verified_data.verification_result.is_ok());
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn sign_verify_inline_cleartext_message_v4() {
    let input_data = "hello world\n hello\n";

    let key = PrivateKey::import_unlocked(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let message = Signer::default()
        .with_signing_key(&key)
        .sign_cleartext(input_data.as_bytes())
        .expect("Failed to sign");

    let verified_data = Verifier::default()
        .with_verification_key(key.as_public_key())
        .verify_cleartext(&message)
        .expect("Failed to verify");

    assert_eq!(verified_data.data, input_data.as_bytes());
    assert!(verified_data.verification_result.is_ok());

    // Fail to verify with wrong key.
    let wrong_key = PrivateKey::import_unlocked(TEST_KEY_V6.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let result = Verifier::default()
        .with_verification_key(wrong_key.as_public_key())
        .verify_cleartext(&message)
        .expect("Verify failed");

    assert!(matches!(
        result.verification_result,
        Err(VerificationError::NoVerifier(_, _))
    ));
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn sign_check_signature_context() {
    let date = UnixTime::new(1_752_476_259);
    let input_data = b"hello world";
    let key = PrivateKey::import_unlocked(TEST_KEY.as_bytes(), DataEncoding::Armored).unwrap();
    let signature_critical = Signer::default()
        .with_signing_key(&key)
        .with_signature_context(SignatureContext::new("test".into(), true))
        .at_date(date.into())
        .sign_detached(input_data, DataEncoding::Armored)
        .unwrap();

    let pubkey = key.as_public_key();

    let verify = |ctx: Option<VerificationContext>, signature: &[u8], expect_ok: bool| {
        let mut verifier = Verifier::default().with_verification_key(pubkey);
        if let Some(ctx) = ctx {
            verifier = verifier.with_verification_context(ctx);
        }
        let result = verifier.at_date(date.into()).verify_detached(
            input_data,
            signature,
            DataEncoding::Armored,
        );
        if expect_ok {
            assert!(result.is_ok());
        } else {
            assert!(matches!(result, Err(VerificationError::BadContext(_, _))));
        }
    };

    // correct context
    verify(
        Some(VerificationContext::new_required("test".into())),
        &signature_critical,
        true,
    );

    // wrong context
    verify(
        Some(VerificationContext::new(
            "test_fail".into(),
            true,
            Some(date),
        )),
        &signature_critical,
        false,
    );

    // missing context
    verify(None, &signature_critical, false);

    // required_after is after signature date
    verify(
        Some(VerificationContext::new(
            "test_wrong".into(),
            true,
            Some(UnixTime::new(1_752_476_260)),
        )),
        &signature_critical,
        true,
    );

    // not required context
    verify(
        Some(VerificationContext::new("test_wrong".into(), false, None)),
        &signature_critical,
        true,
    );

    let signature_non_critical = Signer::default()
        .with_signing_key(&key)
        .with_signature_context(SignatureContext::new("test".into(), false))
        .at_date(date.into())
        .sign_detached(input_data, DataEncoding::Armored)
        .unwrap();

    // correct context
    verify(
        Some(VerificationContext::new_required("test".into())),
        &signature_non_critical,
        true,
    );

    // wrong context
    verify(
        Some(VerificationContext::new(
            "test_fail".into(),
            true,
            Some(date),
        )),
        &signature_non_critical,
        false,
    );

    // missing context
    verify(None, &signature_non_critical, true);
}
