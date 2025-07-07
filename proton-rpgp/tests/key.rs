use proton_rpgp::{
    DataEncoding, KeyOperationError, LockedPrivateKey, PrivateKey, Profile, PublicKey,
};

pub const TEST_PRIVATE_KEY: &str = include_str!("../test-data/keys/locked_private_key_v6.asc");
pub const TEST_PUBLIC_KEY: &str = include_str!("../test-data/keys/public_key_v4.asc");
pub const TEST_PRIVATE_KEY_PASSWORD: &str = "password";

#[test]
fn import_and_unlock_private_key() {
    let key = LockedPrivateKey::import(TEST_PRIVATE_KEY.as_bytes(), DataEncoding::Armor)
        .expect("Failed to import key");

    let unlocked = key
        .unlock(TEST_PRIVATE_KEY_PASSWORD.as_bytes())
        .expect("Failed to unlock key");
    assert_eq!(unlocked.key_id(), key.key_id());
}

#[test]
fn import_and_unlock_private_key_fail() {
    let key = LockedPrivateKey::import(TEST_PRIVATE_KEY.as_bytes(), DataEncoding::Armor)
        .expect("Failed to import key");

    let unlocked = key.unlock(b"wrong_password");
    assert!(matches!(unlocked, Err(KeyOperationError::Unlock(_, _))));
}

#[test]
fn import_public_key() {
    let key = PublicKey::import(TEST_PUBLIC_KEY.as_bytes(), DataEncoding::Armor)
        .expect("Failed to import key");

    assert_eq!(key.key_id().to_string(), "1900ce9499886588");
}

#[test]
fn export_import_locked_key() {
    let key = LockedPrivateKey::import(TEST_PRIVATE_KEY.as_bytes(), DataEncoding::Armor)
        .expect("Failed to import key");

    let exported = key
        .export(DataEncoding::Armor)
        .expect("Failed to export key");

    let key2 =
        LockedPrivateKey::import(&exported, DataEncoding::Armor).expect("Failed to import key");

    assert_eq!(key.fingerprint(), key2.fingerprint());
    assert_eq!(String::from_utf8(exported).unwrap(), TEST_PRIVATE_KEY);
}

#[test]
fn export_import_unlock_key() {
    let key = LockedPrivateKey::import(TEST_PRIVATE_KEY.as_bytes(), DataEncoding::Armor)
        .expect("Failed to import key");

    let unlocked_key = key
        .unlock(TEST_PRIVATE_KEY_PASSWORD.as_bytes())
        .expect("Failed to unlock key");

    let exported = unlocked_key
        .export(
            &Profile {},
            TEST_PRIVATE_KEY_PASSWORD.as_bytes(),
            DataEncoding::Armor,
        )
        .expect("Failed to export key");

    let key2 = PrivateKey::import(
        &exported,
        TEST_PRIVATE_KEY_PASSWORD.as_bytes(),
        DataEncoding::Armor,
    )
    .expect("Failed to import key");

    assert_eq!(key.fingerprint(), key2.fingerprint());
}

#[test]
fn export_import_unlocked_key() {
    let key = LockedPrivateKey::import(TEST_PRIVATE_KEY.as_bytes(), DataEncoding::Armor)
        .expect("Failed to import key");

    let unlocked_key = key
        .unlock(TEST_PRIVATE_KEY_PASSWORD.as_bytes())
        .expect("Failed to unlock key");

    let exported = unlocked_key
        .export_unlocked(DataEncoding::Armor)
        .expect("Failed to export key");

    let key2 =
        PrivateKey::import_unlocked(&exported, DataEncoding::Armor).expect("Failed to import key");

    assert_eq!(key.fingerprint(), key2.fingerprint());

    let failure_result =
        PrivateKey::import_unlocked(TEST_PRIVATE_KEY.as_bytes(), DataEncoding::Armor);
    assert!(matches!(failure_result, Err(KeyOperationError::Locked)));
}
