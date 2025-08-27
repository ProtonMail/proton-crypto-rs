use proton_rpgp::{
    armor::{armor_message, armor_private_key, armor_public_key, armor_signature, unarmor},
    ArmorError, Error,
};

const TEST_PUBLIC_KEY: &[u8] = b"dummy public key bytes";
const TEST_PRIVATE_KEY: &[u8] = b"dummy private key bytes";
const TEST_SIGNATURE: &[u8] = b"dummy signature bytes";
const TEST_MESSAGE: &[u8] = b"dummy message bytes";

fn is_armored_with_header(armored: &[u8], header: &str) -> bool {
    let armored_str = std::str::from_utf8(armored).unwrap();
    armored_str.starts_with(header)
}

#[test]
fn test_armor_public_key_and_unarmor() {
    let armored = armor_public_key(TEST_PUBLIC_KEY).expect("armor_public_key failed");
    assert!(
        is_armored_with_header(&armored, "-----BEGIN PGP PUBLIC KEY BLOCK-----"),
        "Missing public key armor header"
    );
    let unarmored = unarmor(&armored).expect("unarmor failed");
    assert_eq!(unarmored, TEST_PUBLIC_KEY);
}

#[test]
fn test_armor_private_key_and_unarmor() {
    let armored = armor_private_key(TEST_PRIVATE_KEY).expect("armor_private_key failed");
    assert!(
        is_armored_with_header(&armored, "-----BEGIN PGP PRIVATE KEY BLOCK-----"),
        "Missing private key armor header"
    );
    let unarmored = unarmor(&armored).expect("unarmor failed");
    assert_eq!(unarmored, TEST_PRIVATE_KEY);
}

#[test]
fn test_armor_signature_and_unarmor() {
    let armored = armor_signature(TEST_SIGNATURE).expect("armor_signature failed");
    assert!(
        is_armored_with_header(&armored, "-----BEGIN PGP SIGNATURE-----"),
        "Missing signature armor header"
    );
    let unarmored = unarmor(&armored).expect("unarmor failed");
    assert_eq!(unarmored, TEST_SIGNATURE);
}

#[test]
fn test_armor_message_and_unarmor() {
    let armored = armor_message(TEST_MESSAGE).expect("armor_message failed");
    assert!(
        is_armored_with_header(&armored, "-----BEGIN PGP MESSAGE-----"),
        "Missing message armor header"
    );
    let unarmored = unarmor(&armored).expect("unarmor failed");
    assert_eq!(unarmored, TEST_MESSAGE);
}

#[test]
fn test_unarmor_invalid_input() {
    let invalid = b"not an armored message";
    let result = unarmor(invalid);
    assert!(matches!(
        result,
        Err(Error::Armor(ArmorError::DecodeHeader))
    ));
}
