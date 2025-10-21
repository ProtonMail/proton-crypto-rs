use proton_rpgp::{
    AccessKeyInfo, AsPublicKeyRef, DataEncoding, PrivateKey, Profile, ProfileSettingsBuilder,
    PublicKey, UnixTime, VerificationError, Verifier,
};

pub const TEST_KEY: &str = include_str!("../test-data/keys/public_key_v4.asc");
pub const TEST_KEY_V6: &str = include_str!("../test-data/keys/public_key_v6.asc");

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn verify_detached_signature_v4() {
    const SIGANTURE: &str = include_str!("../test-data/signatures/signature_v4.asc");

    let date = UnixTime::new(1_752_153_651);

    let verification_key = PublicKey::import(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let verification_result = Verifier::default()
        .with_verification_key(&verification_key)
        .at_date(date.into())
        .verify_detached(b"hello world", SIGANTURE.as_bytes(), DataEncoding::Armored);

    match verification_result {
        Ok(verification_information) => {
            assert_eq!(verification_information.key_id, verification_key.key_id());
            assert_eq!(
                verification_information.signature_creation_time,
                UnixTime::new(1_752_153_549)
            );
        }
        Err(verification_error) => {
            panic!("Verification failed: {verification_error}");
        }
    }
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn verify_detached_signature_v4_fails() {
    const SIGANTURE: &str = include_str!("../test-data/signatures/signature_v4_corrupt.asc");

    let date = UnixTime::new(1_752_153_651);

    let verification_key = PublicKey::import(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let verification_result = Verifier::default()
        .with_verification_key(&verification_key)
        .at_date(date.into())
        .verify_detached(b"hello world", SIGANTURE.as_bytes(), DataEncoding::Armored);

    match verification_result {
        Ok(_) => {
            panic!("Verification should have failed");
        }
        Err(verification_error) => match verification_error {
            VerificationError::Failed(verification_information, _) => {
                assert_eq!(verification_information.key_id, verification_key.key_id());
                assert_eq!(
                    verification_information.signature_creation_time,
                    UnixTime::new(1_752_153_549)
                );
            }
            _ => {
                panic!("Wrong verification error: {verification_error:?}");
            }
        },
    }
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn verify_detached_signature_v4_fails_rsa_512() {
    const SIGANTURE: &str = include_str!("../test-data/signatures/signature_v4_rsa_512.asc");
    const KEY: &str = include_str!("../test-data/keys/private_key_rsa_512.asc");

    let date = UnixTime::new(1_752_153_651);

    let verification_key = PrivateKey::import_unlocked(KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let verification_result = Verifier::default()
        .with_verification_key(verification_key.as_public_key())
        .at_date(date.into())
        .verify_detached(
            b"Hello World :)",
            SIGANTURE.as_bytes(),
            DataEncoding::Armored,
        );

    assert!(matches!(
        verification_result,
        Err(VerificationError::NoVerifier(_, _))
    ));

    let profile = Profile::new(ProfileSettingsBuilder::new().min_rsa_bits(512).build());

    let verification_result = Verifier::new(profile)
        .with_verification_key(verification_key.as_public_key())
        .at_date(date.into())
        .verify_detached(
            b"Hello World :)",
            SIGANTURE.as_bytes(),
            DataEncoding::Armored,
        );

    assert!(verification_result.is_ok());
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn verify_detached_signature_multiple_signatures() {
    // Contains 3 signatures: random v6 key, random v4 key, and the test key.
    const SIGANTURE: &str = include_str!("../test-data/signatures/signature_multiple.asc");

    let date = UnixTime::new(1_752_648_785);

    let verification_key = PublicKey::import(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let verification_result = Verifier::default()
        .with_verification_key(&verification_key)
        .at_date(date.into())
        .verify_detached(b"hello world", SIGANTURE.as_bytes(), DataEncoding::Armored);

    match verification_result {
        Ok(verification_information) => {
            assert_eq!(verification_information.key_id, verification_key.key_id());
            assert_eq!(
                verification_information.signature_creation_time,
                UnixTime::new(1_752_220_880)
            );
        }
        Err(verification_error) => {
            panic!("Verification failed: {verification_error}");
        }
    }
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn verify_detached_signature_v4_text() {
    const SIGANTURE: &str = include_str!("../test-data/signatures/signature_v4_text.asc");
    const TEXT: &[u8] = b"hello world\n with line endings.   \n";

    let date = UnixTime::new(1_752_223_468);

    let verification_key = PublicKey::import(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let verification_result = Verifier::default()
        .with_verification_key(&verification_key)
        .at_date(date.into())
        .verify_detached(TEXT, SIGANTURE.as_bytes(), DataEncoding::Armored);

    match verification_result {
        Ok(verification_information) => {
            assert_eq!(verification_information.key_id, verification_key.key_id());
            assert_eq!(
                verification_information.signature_creation_time,
                UnixTime::new(1_752_223_419)
            );
        }
        Err(verification_error) => {
            panic!("Verification failed: {verification_error}");
        }
    }
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn verify_detached_signature_v6() {
    const SIGANTURE: &str = include_str!("../test-data/signatures/signature_v6.asc");

    let date = UnixTime::new(1_752_648_785);

    let verification_key = PublicKey::import(TEST_KEY_V6.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let verification_result = Verifier::default()
        .with_verification_key(&verification_key)
        .at_date(date.into())
        .verify_detached(b"hello world", SIGANTURE.as_bytes(), DataEncoding::Armored);

    assert!(verification_result.is_ok());
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn verify_detached_signature_v6_pqc() {
    const SIGANTURE: &str = include_str!("../test-data/signatures/signature_v6_pqc.asc");
    const KEY: &str = include_str!("../test-data/keys/private_key_v6_pqc.asc");

    let date = UnixTime::new(1_752_237_138);

    let verification_key = PrivateKey::import_unlocked(KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let verification_result = Verifier::default()
        .with_verification_key(verification_key.as_public_key())
        .at_date(date.into())
        .verify_detached(b"hello world", SIGANTURE.as_bytes(), DataEncoding::Armored);

    assert!(verification_result.is_ok());
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn verify_inline_signed_message_v4() {
    const INPUT_DATA: &str = include_str!("../test-data/messages/signed_message_v4.asc");
    let date = UnixTime::new(1_753_088_183);

    let key = PublicKey::import(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let verified_data = Verifier::default()
        .with_verification_key(key.as_public_key())
        .at_date(date.into())
        .verify(INPUT_DATA, DataEncoding::Armored)
        .expect("Failed to decrypt");

    assert_eq!(verified_data.data, b"hello world");
    assert!(verified_data.verification_result.is_ok());
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn verify_inline_signed_message_v4_fail_no_matching_key() {
    const INPUT_DATA: &str = include_str!("../test-data/messages/signed_message_v4.asc");
    let date = UnixTime::new(1_753_088_183);

    let key = PublicKey::import(TEST_KEY_V6.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let verified_data = Verifier::default()
        .with_verification_key(&key)
        .at_date(date.into())
        .verify(INPUT_DATA, DataEncoding::Armored)
        .expect("Failed to verify");

    assert_eq!(verified_data.data, b"hello world");
    assert!(matches!(
        verified_data.verification_result,
        Err(VerificationError::NoVerifier(_, _))
    ));
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn verify_inline_signed_message_v4_text() {
    const INPUT_DATA: &str = include_str!("../test-data/messages/signed_message_v4_text.asc");
    let date = UnixTime::new(1_753_088_470);

    let key = PublicKey::import(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let verified_data = Verifier::default()
        .with_verification_key(key.as_public_key())
        .at_date(date.into())
        .output_utf8()
        .verify(INPUT_DATA, DataEncoding::Armored)
        .expect("Failed to decrypt");

    assert_eq!(verified_data.data, b"hello world \n    \n ");
    assert!(verified_data.verification_result.is_ok());
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn verify_inline_signed_cleartext_message_v4() {
    const INPUT_DATA: &str = include_str!("../test-data/messages/signed_cleartext_message_v4.asc");
    let date = UnixTime::new(1_753_099_790);

    let key = PublicKey::import(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let verified_data = Verifier::default()
        .with_verification_key(key.as_public_key())
        .at_date(date.into())
        .verify_cleartext(INPUT_DATA)
        .expect("Failed to verifiy");

    assert_eq!(
        verified_data.data,
        b"hello world\n    with multiple lines\n"
    );
    assert!(verified_data.verification_result.is_ok());
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn verify_inline_signed_cleartext_message_v4_escaped() {
    const INPUT_DATA: &str =
        include_str!("../test-data/messages/signed_cleartext_message_v4_escaped.asc");
    const KEY: &str = include_str!("../test-data/keys/public_key_v4_cleartext_escaped.asc");
    let expected_data = hex::decode("46726f6d207468652067726f636572792073746f7265207765206e6565643a0a0a2d20746f66750a2d20766567657461626c65730a2d206e6f6f646c65730a0a").unwrap();
    let date = UnixTime::new(1_755_528_534);

    let key =
        PublicKey::import(KEY.as_bytes(), DataEncoding::Armored).expect("Failed to import key");

    let verified_data = Verifier::default()
        .with_verification_key(key.as_public_key())
        .at_date(date.into())
        .verify_cleartext(INPUT_DATA)
        .expect("Failed to verifiy");

    assert_eq!(verified_data.data, expected_data);
    assert!(verified_data.verification_result.is_ok());
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn verify_inline_signed_message_v4_with_reformatted_key() {
    const INPUT_DATA: &str =
        include_str!("../test-data/messages/signed_message_v4_reformatted_key.asc");
    const REFORMATTED_KEY: &str = include_str!("../test-data/keys/private_key_v4_reformatted.asc");
    let date = UnixTime::new(1_753_088_183);

    let key = PrivateKey::import_unlocked(REFORMATTED_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let profile = Profile::new(
        ProfileSettingsBuilder::new()
            .allow_insecure_verification_with_reformatted_keys(true)
            .build(),
    );

    let verified_data = Verifier::new(profile)
        .with_verification_key(key.as_public_key())
        .at_date(date.into())
        .verify(INPUT_DATA, DataEncoding::Armored)
        .expect("Failed to decrypt");

    assert_eq!(verified_data.data, b"plaintext");
    assert!(verified_data.verification_result.is_ok());

    let profile = Profile::new(
        ProfileSettingsBuilder::new()
            .allow_insecure_verification_with_reformatted_keys(false)
            .build(),
    );

    let verified_data = Verifier::new(profile)
        .with_verification_key(key.as_public_key())
        .at_date(date.into())
        .verify(INPUT_DATA, DataEncoding::Armored)
        .expect("Failed to decrypt");

    assert_eq!(verified_data.data, b"plaintext");
    assert!(verified_data.verification_result.is_err());
}
