use proton_rpgp::{
    AccessKeyInfo, AsPublicKeyRef, DataEncoding, PrivateKey, ProfileSettings, PublicKey, Signer,
    UnixTime, VerificationContext, VerificationError, VerificationInformation,
    VerificationResultUtility, Verifier,
};
use std::io::{self};

pub const TEST_KEY: &str = include_str!("../test-data/keys/public_key_v4.asc");
pub const TEST_KEY_V6: &str = include_str!("../test-data/keys/public_key_v6.asc");
pub const TEST_PRIVATE_KEY: &str = include_str!("../test-data/keys/private_key_v4.asc");

mod utils;

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn verify_detached_signature_v4() {
    const SIGNATURE: &str = include_str!("../test-data/signatures/signature_v4.asc");

    let date = UnixTime::new(1_752_153_651);

    let verification_key = PublicKey::import(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let verification_result = Verifier::default()
        .with_verification_key(&verification_key)
        .at_date(date.into())
        .verify_detached(b"hello world", SIGNATURE.as_bytes(), DataEncoding::Armored);

    match verification_result {
        Ok(verification_information) => {
            assert_eq!(verification_information.key_id, verification_key.key_id());
            assert_eq!(
                verification_information.signature_creation_time,
                UnixTime::new(1_752_153_549)
            );
            check_signatures(&verification_information, 1);
        }
        Err(verification_error) => {
            panic!("Verification failed: {verification_error}");
        }
    }
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn verify_detached_signature_v4_stream() {
    const SIGNATURE: &str = include_str!("../test-data/signatures/signature_v4.asc");

    let data = b"hello world";

    let test_date = UnixTime::new(1_752_153_651);

    let verification_key = PublicKey::import(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let mut reader = Verifier::default()
        .with_verification_key(&verification_key)
        .at_date(test_date.into())
        .verify_detached_stream(&data[..], SIGNATURE.as_bytes(), DataEncoding::Armored)
        .expect("Failed to create verifying reader");

    reader.discard_all_data().expect("Failed to discard data");

    let verification_result = reader.verification_result();

    match verification_result {
        Ok(verification_information) => {
            assert_eq!(verification_information.key_id, verification_key.key_id());
            assert_eq!(
                verification_information.signature_creation_time,
                UnixTime::new(1_752_153_549)
            );
            check_signatures(&verification_information, 1);
        }
        Err(verification_error) => {
            panic!("Verification failed: {verification_error}");
        }
    }
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn verify_detached_signature_v4_stream_empty() {
    const SIGNATURE: &str = include_str!("../test-data/signatures/signature_v4_empty.asc");

    let data = b"";

    let test_date = UnixTime::new(1_780_401_662);

    let verification_key = PublicKey::import(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let mut reader = Verifier::default()
        .with_verification_key(&verification_key)
        .at_date(test_date.into())
        .verify_detached_stream(&data[..], SIGNATURE.as_bytes(), DataEncoding::Armored)
        .expect("Failed to create verifying reader");

    reader.discard_all_data().expect("Failed to discard data");

    let verification_result = reader.verification_result();

    match verification_result {
        Ok(verification_information) => {
            assert_eq!(verification_information.key_id, verification_key.key_id());
            assert_eq!(
                verification_information.signature_creation_time,
                UnixTime::new(1_752_476_259)
            );
            check_signatures(&verification_information, 1);
        }
        Err(verification_error) => {
            panic!("Verification failed: {verification_error}");
        }
    }
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn verify_detached_signature_v4_fails() {
    const SIGNATURE: &str = include_str!("../test-data/signatures/signature_v4_corrupt.asc");

    let date = UnixTime::new(1_752_153_651);

    let verification_key = PublicKey::import(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let verification_result = Verifier::default()
        .with_verification_key(&verification_key)
        .at_date(date.into())
        .verify_detached(b"hello world", SIGNATURE.as_bytes(), DataEncoding::Armored);

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
                check_signatures(&verification_information, 1);
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
    const SIGNATURE: &str = include_str!("../test-data/signatures/signature_v4_rsa_512.asc");
    const KEY: &str = include_str!("../test-data/keys/private_key_rsa_512.asc");

    let date = UnixTime::new(1_752_153_651);

    let verification_key = PrivateKey::import_unlocked(KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let verification_result = Verifier::default()
        .with_verification_key(verification_key.as_public_key())
        .at_date(date.into())
        .verify_detached(
            b"Hello World :)",
            SIGNATURE.as_bytes(),
            DataEncoding::Armored,
        );

    assert!(matches!(
        verification_result,
        Err(VerificationError::NoVerifier(_, _))
    ));

    let profile = ProfileSettings::builder()
        .min_rsa_bits(512)
        .build_into_profile();

    let verification_result = Verifier::new(profile)
        .with_verification_key(verification_key.as_public_key())
        .at_date(date.into())
        .verify_detached(
            b"Hello World :)",
            SIGNATURE.as_bytes(),
            DataEncoding::Armored,
        );

    assert!(verification_result.is_ok());
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn verify_detached_signature_multiple_signatures() {
    // Contains 3 signatures: random v6 key, random v4 key, and the test key.
    const SIGNATURE: &str = include_str!("../test-data/signatures/signature_multiple.asc");

    let date = UnixTime::new(1_752_648_785);

    let verification_key = PublicKey::import(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let verification_result = Verifier::default()
        .with_verification_key(&verification_key)
        .at_date(date.into())
        .verify_detached(b"hello world", SIGNATURE.as_bytes(), DataEncoding::Armored);

    match verification_result {
        Ok(verification_information) => {
            assert_eq!(verification_information.key_id, verification_key.key_id());
            assert_eq!(
                verification_information.signature_creation_time,
                UnixTime::new(1_752_220_880)
            );
            check_signatures(&verification_information, 3);
        }
        Err(verification_error) => {
            panic!("Verification failed: {verification_error}");
        }
    }
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn verify_detached_signature_multiple_signatures_stream() {
    // Contains 3 signatures: random v6 key, random v4 key, and the test key.
    const SIGNATURE: &str = include_str!("../test-data/signatures/signature_multiple.asc");

    let date = UnixTime::new(1_752_648_785);

    let verification_key = PublicKey::import(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let mut reader = Verifier::default()
        .with_verification_key(&verification_key)
        .at_date(date.into())
        .verify_detached_stream(
            "hello world".as_bytes(),
            SIGNATURE.as_bytes(),
            DataEncoding::Armored,
        )
        .expect("Failed to create verifying reader");

    reader.discard_all_data().expect("Failed to discard data");

    let verification_result = reader.verification_result();

    match verification_result {
        Ok(verification_information) => {
            assert_eq!(verification_information.key_id, verification_key.key_id());
            assert_eq!(
                verification_information.signature_creation_time,
                UnixTime::new(1_752_220_880)
            );
            check_signatures(&verification_information, 3);
        }
        Err(verification_error) => {
            panic!("Verification failed: {verification_error}");
        }
    }
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn verify_detached_signature_v4_text() {
    const SIGNATURE: &str = include_str!("../test-data/signatures/signature_v4_text.asc");
    const TEXT: &[u8] = b"hello world\n with line endings.   \n";

    let date = UnixTime::new(1_752_223_468);

    let verification_key = PublicKey::import(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let verification_result = Verifier::default()
        .with_verification_key(&verification_key)
        .at_date(date.into())
        .verify_detached(TEXT, SIGNATURE.as_bytes(), DataEncoding::Armored);

    match verification_result {
        Ok(verification_information) => {
            assert_eq!(verification_information.key_id, verification_key.key_id());
            assert_eq!(
                verification_information.signature_creation_time,
                UnixTime::new(1_752_223_419)
            );
            check_signatures(&verification_information, 1);
        }
        Err(verification_error) => {
            panic!("Verification failed: {verification_error}");
        }
    }
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn verify_detached_signature_v6() {
    const SIGNATURE: &str = include_str!("../test-data/signatures/signature_v6.asc");

    let date = UnixTime::new(1_752_648_785);

    let verification_key = PublicKey::import(TEST_KEY_V6.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let verification_result = Verifier::default()
        .with_verification_key(&verification_key)
        .at_date(date.into())
        .verify_detached(b"hello world", SIGNATURE.as_bytes(), DataEncoding::Armored);

    assert!(verification_result.is_ok());
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn verify_detached_signature_v6_pqc() {
    const SIGNATURE: &str = include_str!("../test-data/signatures/signature_v6_pqc.asc");
    const KEY: &str = include_str!("../test-data/keys/private_key_v6_pqc.asc");

    let date = UnixTime::new(1_752_237_138);

    let verification_key = PrivateKey::import_unlocked(KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let verification_result = Verifier::default()
        .with_verification_key(verification_key.as_public_key())
        .at_date(date.into())
        .verify_detached(b"hello world", SIGNATURE.as_bytes(), DataEncoding::Armored);

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
pub fn verify_inline_signed_message_v4_stream() {
    const INPUT_DATA: &str = include_str!("../test-data/messages/signed_message_v4.asc");
    let date = UnixTime::new(1_753_088_183);

    let key = PublicKey::import(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let mut reader = Verifier::default()
        .with_verification_key(key.as_public_key())
        .at_date(date.into())
        .verify_stream(INPUT_DATA.as_bytes(), DataEncoding::Armored)
        .expect("Failed to decrypt");

    let mut buffer = Vec::new();
    io::copy(&mut reader, &mut buffer).expect("Failed to copy");
    let verification_result = reader.verification_result();

    assert_eq!(buffer, b"hello world");
    assert!(verification_result.is_ok());
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
pub fn verify_inline_signed_message_v4_text_stream() {
    const INPUT_DATA: &str = include_str!("../test-data/messages/signed_message_v4_text.asc");
    let date = UnixTime::new(1_753_088_470);

    let verification_key = PublicKey::import(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let mut reader = Verifier::default()
        .with_verification_key(&verification_key)
        .at_date(date.into())
        .output_utf8()
        .verify_stream(INPUT_DATA.as_bytes(), DataEncoding::Armored)
        .expect("Failed to create verifying reader");

    let mut buffer = Vec::new();
    utils::test_copy(&mut reader, &mut buffer, 3).expect("Failed to copy");
    let verification_result = reader.verification_result();

    assert_eq!(buffer, b"hello world \n    \n ");
    assert!(verification_result.is_ok());
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

    let profile = ProfileSettings::builder()
        .allow_insecure_verification_with_reformatted_keys(true)
        .build_into_profile();

    let verified_data = Verifier::new(profile)
        .with_verification_key(key.as_public_key())
        .at_date(date.into())
        .verify(INPUT_DATA, DataEncoding::Armored)
        .expect("Failed to verify");

    assert_eq!(verified_data.data, b"plaintext");
    assert!(verified_data.verification_result.is_ok());

    let profile = ProfileSettings::builder()
        .allow_insecure_verification_with_reformatted_keys(false)
        .build_into_profile();

    let verified_data = Verifier::new(profile)
        .with_verification_key(key.as_public_key())
        .at_date(date.into())
        .verify(INPUT_DATA, DataEncoding::Armored)
        .expect("Failed to verify");

    assert_eq!(verified_data.data, b"plaintext");
    assert!(verified_data.verification_result.is_err());
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn verify_inline_signed_message_v4_compressed() {
    const INPUT_DATA: &str = include_str!("../test-data/messages/signed_message_v4_compressed.asc");
    let date = UnixTime::new(1_764_579_580);

    let profile_with_limit = ProfileSettings::builder()
        .max_reading_size(Some(2 * 1024))
        .build_into_profile();

    let key = PublicKey::import(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    Verifier::default()
        .with_verification_key(key.as_public_key())
        .at_date(date.into())
        .verify(INPUT_DATA, DataEncoding::Armored)
        .expect("Failed to verify");

    Verifier::new(profile_with_limit)
        .with_verification_key(key.as_public_key())
        .at_date(date.into())
        .verify(INPUT_DATA, DataEncoding::Armored)
        .expect_err("should fail as message is too large");
}

#[test]
#[allow(clippy::missing_panics_doc)]
#[allow(clippy::indexing_slicing)]
pub fn verificarion_result_utility() {
    const SIGNATURE: &str = include_str!("../test-data/signatures/signature_multiple.asc");
    let date = UnixTime::new(1_752_648_785);
    let verification_key = PublicKey::import(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");
    let verification_result = Verifier::default()
        .with_verification_key(&verification_key)
        .at_date(date.into())
        .verify_detached(b"hello world", SIGNATURE.as_bytes(), DataEncoding::Armored);

    let utility = VerificationResultUtility::from(&verification_result);
    assert!(utility.verification_success());
    assert!(utility.verification_information().is_some());

    let selected_signature = utility
        .selected_signature_bytes()
        .expect("Failed to get selected signature");
    let count = pgp::packet::PacketParser::new(&selected_signature[..])
        .filter_map(|parse_result| match parse_result {
            Ok(pgp::packet::Packet::Signature(signature)) => Some(signature),
            _ => None,
        })
        .count();
    assert_eq!(count, 1, "Expected 1  signatures, got {count}");

    let all_signatures = utility
        .all_signature_bytes()
        .expect("Failed to get all signature bytes");
    let count = pgp::packet::PacketParser::new(&all_signatures[selected_signature.len()..])
        .filter_map(|parse_result| match parse_result {
            Ok(pgp::packet::Packet::Signature(signature)) => Some(signature),
            _ => None,
        })
        .count();
    assert_eq!(count, 2, "Expected 2 signatures, got {count}");
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn verify_rejects_unsigned_notation_context() {
    const SIGNATURE: &str =
        include_str!("../test-data/signatures/signature_v4_unsigned_context.asc");
    const KEY: &str = include_str!("../test-data/keys/public_key_v4_unsigned_context.asc");
    const TEXT: &[u8] = b"message with unsigned context";
    let date = UnixTime::new(1_700_000_000);

    let key = PublicKey::import(KEY.as_bytes(), DataEncoding::Armored).expect("Failed to import");

    // Required context is not present in the signed data -> verification fails.
    let with_context = Verifier::default()
        .with_verification_key(&key)
        .with_verification_context(VerificationContext::new(
            "test-context-unsigned".to_owned(),
            true,
            None,
        ))
        .at_date(date.into())
        .verify_detached(TEXT, SIGNATURE.as_bytes(), DataEncoding::Armored);
    assert!(matches!(
        with_context,
        Err(VerificationError::BadContext(_, _))
    ));

    // Without a required context the unsigned notation is ignored and the
    // (otherwise valid) signature verifies.
    let without_context = Verifier::default()
        .with_verification_key(&key)
        .at_date(date.into())
        .verify_detached(TEXT, SIGNATURE.as_bytes(), DataEncoding::Armored);
    assert!(without_context.is_ok());
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn verify_detached_signature_wrong_key() {
    let date = UnixTime::new(1_752_476_259);

    let signing_key =
        PrivateKey::import_unlocked(TEST_PRIVATE_KEY.as_bytes(), DataEncoding::Armored)
            .expect("Failed to import key");
    let wrong_key = PublicKey::import(TEST_KEY_V6.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let signature_bytes = Signer::default()
        .with_signing_key(&signing_key)
        .at_date(date.into())
        .sign_detached(b"hello world", DataEncoding::Armored)
        .expect("Failed to sign");

    let verification_result = Verifier::default()
        .with_verification_key(&wrong_key)
        .at_date(date.into())
        .verify_detached(b"hello world", &signature_bytes, DataEncoding::Armored);

    assert!(matches!(
        verification_result,
        Err(VerificationError::NoVerifier(_, _))
    ));
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn verify_cleartext_signature_wrong_key() {
    let date = UnixTime::new(1_752_476_259);

    let signing_key =
        PrivateKey::import_unlocked(TEST_PRIVATE_KEY.as_bytes(), DataEncoding::Armored)
            .expect("Failed to import key");
    let wrong_key = PublicKey::import(TEST_KEY_V6.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let cleartext = Signer::default()
        .with_signing_key(&signing_key)
        .at_date(date.into())
        .sign_cleartext(b"hello world")
        .expect("Failed to sign");

    let verified_data = Verifier::default()
        .with_verification_key(&wrong_key)
        .at_date(date.into())
        .verify_cleartext(std::str::from_utf8(&cleartext).expect("Invalid utf8"))
        .expect("Failed to verify");

    assert_eq!(verified_data.data, b"hello world");
    assert!(matches!(
        verified_data.verification_result,
        Err(VerificationError::NoVerifier(_, _))
    ));
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn verify_detects_missing_signature() {
    let date = UnixTime::new(1_752_476_259);

    let key = PublicKey::import(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let builder = pgp::composed::MessageBuilder::from_bytes("", &b"hello world"[..]);
    let mut unsigned_message = Vec::new();
    builder
        .to_armored_writer(
            rand::thread_rng(),
            pgp::composed::ArmorOptions::default(),
            &mut unsigned_message,
        )
        .expect("Failed to build message");

    let verified_data = Verifier::default()
        .with_verification_key(&key)
        .at_date(date.into())
        .verify(&unsigned_message, DataEncoding::Armored)
        .expect("Failed to verify");

    assert_eq!(verified_data.data, b"hello world");
    assert!(matches!(
        verified_data.verification_result,
        Err(VerificationError::NotSigned)
    ));
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn verify_detached_signature_reused_with_different_message_fails() {
    let date = UnixTime::new(1_752_476_259);

    let signing_key =
        PrivateKey::import_unlocked(TEST_PRIVATE_KEY.as_bytes(), DataEncoding::Armored)
            .expect("Failed to import key");

    let signature_bytes = Signer::default()
        .with_signing_key(&signing_key)
        .at_date(date.into())
        .sign_detached(b"hello world", DataEncoding::Armored)
        .expect("Failed to sign");

    let verification_result = Verifier::default()
        .with_verification_key(signing_key.as_public_key())
        .at_date(date.into())
        .verify_detached(b"goodbye world", &signature_bytes, DataEncoding::Armored);

    assert!(matches!(
        verification_result,
        Err(VerificationError::Failed(_, _))
    ));
}

fn check_signatures(info: &VerificationInformation, expected_number: usize) {
    let signature_bytes = info
        .all_signature_bytes()
        .expect("Failed to get signature bytes");
    let count = pgp::packet::PacketParser::new(&signature_bytes[..])
        .filter_map(|parse_result| match parse_result {
            Ok(pgp::packet::Packet::Signature(signature)) => Some(signature),
            _ => None,
        })
        .count();
    assert_eq!(
        count, expected_number,
        "Expected {expected_number} signatures, got {count}"
    );

    let selected_signature = info
        .signature_bytes()
        .expect("Failed to get signature bytes");
    let count = pgp::packet::PacketParser::new(&selected_signature[..])
        .filter_map(|parse_result| match parse_result {
            Ok(pgp::packet::Packet::Signature(signature)) => Some(signature),
            _ => None,
        })
        .count();
    assert_eq!(count, 1, "Expected 1 signatures, got {count}");
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn verify_rejects_non_message_signature_types() {
    const SIGNATURES: [(&str, &str); 3] = [
        (
            "standalone",
            include_str!("../test-data/signatures/signature_v4_type_standalone.asc"),
        ),
        (
            "timestamp",
            include_str!("../test-data/signatures/signature_v4_type_timestamp.asc"),
        ),
        (
            "cert_generic",
            include_str!("../test-data/signatures/signature_v4_type_cert_generic.asc"),
        ),
    ];
    const BINARY_SIGNATURE: &str = include_str!("../test-data/signatures/signature_v4.asc");

    let date = UnixTime::new(1_752_153_651);
    let key = PublicKey::import(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let verify = |data: &[u8], signature: &str| {
        let result = Verifier::default()
            .with_verification_key(&key)
            .at_date(date.into())
            .verify_detached(data, signature, DataEncoding::Armored);
        let mut reader = Verifier::default()
            .with_verification_key(&key)
            .at_date(date.into())
            .verify_detached_stream(data, signature, DataEncoding::Armored)
            .expect("Failed to create reader");
        io::copy(&mut reader, &mut io::sink()).expect("Failed to read");
        (result, reader.verification_result())
    };

    // Control: a binary signature over the data verifies.
    let (result, stream_result) = verify(b"hello world", BINARY_SIGNATURE);
    assert!(result.is_ok(), "{result:?}");
    assert!(stream_result.is_ok(), "{stream_result:?}");

    for (name, signature) in SIGNATURES {
        let (result, stream_result) = verify(b"hEVIL DATA", signature);
        assert!(
            matches!(result, Err(VerificationError::Failed(..))),
            "{name}: {result:?}"
        );
        assert!(
            matches!(stream_result, Err(VerificationError::Failed(..))),
            "{name}: {stream_result:?}"
        );
    }
}
