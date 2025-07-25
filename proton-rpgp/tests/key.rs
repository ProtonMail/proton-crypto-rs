use proton_rpgp::{
    AccessKeyInfo, DataEncoding, KeyGenerationType, KeyGenerator, KeyOperationError,
    LockedPrivateKey, PrivateKey, Profile, PublicKey, UnixTime,
};

pub const TEST_PRIVATE_KEY: &str = include_str!("../test-data/keys/locked_private_key_v6.asc");
pub const TEST_PUBLIC_KEY: &str = include_str!("../test-data/keys/public_key_v4.asc");
pub const TEST_PRIVATE_KEY_PASSWORD: &str = "password";

#[test]
fn key_import_and_unlock_private_key() {
    let key = LockedPrivateKey::import(TEST_PRIVATE_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let unlocked = key
        .unlock(TEST_PRIVATE_KEY_PASSWORD.as_bytes())
        .expect("Failed to unlock key");
    assert_eq!(unlocked.key_id(), key.key_id());
}

#[test]
fn key_import_and_unlock_private_key_fail() {
    let key = LockedPrivateKey::import(TEST_PRIVATE_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let unlocked = key.unlock(b"wrong_password");
    assert!(matches!(unlocked, Err(KeyOperationError::Unlock(_, _))));
}

#[test]
fn key_import_public_key() {
    let key = PublicKey::import(TEST_PUBLIC_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    assert_eq!(
        key.fingerprint().to_string(),
        "c8e74badf4d2221719212f994faefe8fff37c1e7"
    );
}

#[test]
fn key_export_import_locked_key() {
    let key = LockedPrivateKey::import(TEST_PRIVATE_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let exported = key
        .export(DataEncoding::Armored)
        .expect("Failed to export key");

    let key2 =
        LockedPrivateKey::import(&exported, DataEncoding::Armored).expect("Failed to import key");

    assert_eq!(key.fingerprint(), key2.fingerprint());
    assert_eq!(String::from_utf8(exported).unwrap(), TEST_PRIVATE_KEY);
}

#[test]
fn key_export_import_unlock_key() {
    let key = LockedPrivateKey::import(TEST_PRIVATE_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let unlocked_key = key
        .unlock(TEST_PRIVATE_KEY_PASSWORD.as_bytes())
        .expect("Failed to unlock key");

    let exported = unlocked_key
        .export(
            &Profile::default(),
            TEST_PRIVATE_KEY_PASSWORD.as_bytes(),
            DataEncoding::Armored,
        )
        .expect("Failed to export key");

    let key2 = PrivateKey::import(
        &exported,
        TEST_PRIVATE_KEY_PASSWORD.as_bytes(),
        DataEncoding::Armored,
    )
    .expect("Failed to import key");

    assert_eq!(key.fingerprint(), key2.fingerprint());
}

#[test]
fn key_export_import_unlocked_key() {
    let key = LockedPrivateKey::import(TEST_PRIVATE_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let unlocked_key = key
        .unlock(TEST_PRIVATE_KEY_PASSWORD.as_bytes())
        .expect("Failed to unlock key");

    let exported = unlocked_key
        .export_unlocked(DataEncoding::Armored)
        .expect("Failed to export key");

    let key2 = PrivateKey::import_unlocked(&exported, DataEncoding::Armored)
        .expect("Failed to import key");

    assert_eq!(key.fingerprint(), key2.fingerprint());

    let failure_result =
        PrivateKey::import_unlocked(TEST_PRIVATE_KEY.as_bytes(), DataEncoding::Armored);
    assert!(matches!(failure_result, Err(KeyOperationError::Locked)));
}

#[test]
fn key_is_revoked() {
    const LOCAL_TEST_KEY: &str = include_str!("../test-data/keys/public_key_v4_revoked.asc");

    let date = UnixTime::new(1_751_881_317);

    let key_revoked = PublicKey::import(LOCAL_TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");
    let key = PublicKey::import(TEST_PUBLIC_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let expect_is_revoked = key_revoked.is_revoked(&Profile::default(), date);
    let expect_is_not_revoked = key.is_revoked(&Profile::default(), date);

    assert!(expect_is_revoked && !expect_is_not_revoked);
}

#[test]
fn key_is_expired() {
    const LOCAL_TEST_KEY: &str = include_str!("../test-data/keys/public_key_v4_expired.asc");
    let profile = Profile::default();

    let not_expired = UnixTime::new(1_635_464_783);
    let expired = UnixTime::new(1_751_881_317);

    let key = PublicKey::import(LOCAL_TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let expect_expired = key.is_expired(&profile, expired);
    let expect_not_expired = key.is_expired(&profile, not_expired);

    assert!(expect_expired && !expect_not_expired);
}

#[test]
fn key_can_encrypt() {
    const LOCAL_TEST_KEY: &str = include_str!("../test-data/keys/public_key_v4_subkey_revoked.asc");
    let profile = Profile::default();
    let date = UnixTime::new(1_751_984_424);

    let sub_key_revoked = PublicKey::import(LOCAL_TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");
    let key = PublicKey::import(TEST_PUBLIC_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let expect_can_encrypt = key.check_can_encrypt(&profile, date);
    let expect_cannot_encrypt = sub_key_revoked.check_can_encrypt(&profile, date);

    assert!(expect_can_encrypt.is_ok() && expect_cannot_encrypt.is_err());
}

#[test]
fn key_can_verify() {
    const LOCAL_TEST_KEY: &str = include_str!("../test-data/keys/public_key_v4_revoked.asc");
    let profile = Profile::default();
    let date = UnixTime::new(1_751_984_424);

    let key_revoked = PublicKey::import(LOCAL_TEST_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");
    let key = PublicKey::import(TEST_PUBLIC_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let expect_can_verify = key.check_can_verify(&profile, date);
    let expect_cannot_verify = key_revoked.check_can_verify(&profile, date);

    assert!(expect_can_verify.is_ok() && expect_cannot_verify.is_err());
}

#[test]
fn key_sha256_fingerprints() {
    const EXPECTED_FINGERPRINTS: [&str; 2] = [
        "c661eb295d86ca96733f4a18237f0e7b0bbf599e0060795302546fc644f3c9e3",
        "361d3c849b69bdd269cd0054f9dcee6df5f45f23c758ec3f805457684683996d",
    ];

    let key = PublicKey::import(TEST_PUBLIC_KEY.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key");

    let fingerprints = key.fingerprints_sha256();
    assert_eq!(fingerprints.len(), EXPECTED_FINGERPRINTS.len());
    for (i, fingerprint) in fingerprints.iter().enumerate() {
        assert_eq!(fingerprint.to_string(), EXPECTED_FINGERPRINTS[i]);
    }
}

#[test]
fn key_generation_default() {
    let key = KeyGenerator::default()
        .with_user_id("test", "test@test.com")
        .with_key_type(KeyGenerationType::RSA)
        .generate()
        .expect("Failed to generate key");

    let _exported = key
        .export_unlocked(DataEncoding::Armored)
        .expect("Failed to export key");

    key.check_can_encrypt(&Profile::default(), UnixTime::now().unwrap())
        .expect("Cannot encrypt");

    key.check_can_verify(&Profile::default(), UnixTime::now().unwrap())
        .expect("Cannot verify");

    assert_eq!(key.version(), 4);
}
