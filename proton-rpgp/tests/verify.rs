use proton_rpgp::{
    AccessKeyInfo, AsPublicKeyRef, DataEncoding, PrivateKey, Profile, PublicKey, UnixTime,
    VerificationError, Verifier,
};

pub const TEST_KEY: &str = include_str!("../test-data/keys/public_key_v4.asc");

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn verify_detached_signature_v4() {
    const SIGANTURE: &str = include_str!("../test-data/signatures/signature_v4.asc");

    let date = UnixTime::new(1_752_153_651);

    let verification_key = PublicKey::import(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let verification_result = Verifier::default()
        .with_verification_key(&verification_key)
        .at_date(date)
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
        .at_date(date)
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
        .at_date(date)
        .verify_detached(
            b"Hello World :)",
            SIGANTURE.as_bytes(),
            DataEncoding::Armored,
        );

    assert!(matches!(
        verification_result,
        Err(VerificationError::NoVerifier(_, _))
    ));

    let mut profile = Profile::new();
    profile.min_rsa_bits = 512;

    let verification_result = Verifier::new(&profile)
        .with_verification_key(verification_key.as_public_key())
        .at_date(date)
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

    let date = UnixTime::new(1_752_153_651);

    let verification_key = PublicKey::import(TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let verification_result = Verifier::default()
        .with_verification_key(&verification_key)
        .at_date(date)
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
        .at_date(date)
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
    const KEY: &str = include_str!("../test-data/keys/private_key_v6.asc");

    let date = UnixTime::new(1_752_237_138);

    let verification_key = PrivateKey::import_unlocked(KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let verification_result = Verifier::default()
        .with_verification_key(verification_key.as_public_key())
        .at_date(date)
        .verify_detached(b"hello world", SIGANTURE.as_bytes(), DataEncoding::Armored);

    assert!(verification_result.is_ok());
}

// TODO: Update rpgp to accept ml-dsa as a valid signature algorithm.
/*#[test]
#[allow(clippy::missing_panics_doc)]
pub fn verify_detached_signature_v6_pqc() {
    const SIGANTURE: &str = include_str!("../test-data/signatures/signature_v6_pqc.asc");
    const KEY: &str = include_str!("../test-data/keys/private_key_v6_pqc.asc");

    let date = UnixTime::new(1_752_237_138);

    let verification_key = PrivateKey::import_unlocked(KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let verification_result = Verifier::default()
        .with_verification_key(verification_key.as_public_key())
        .at_date(date)
        .verify_detached(b"hello world", SIGANTURE.as_bytes(), DataEncoding::Armored);

    assert!(verification_result.is_ok());
}*/
