use super::*;

#[test]
fn test_key_encode() {
    let key = KeyGenerator::new()
        .with_user_id("name", "name@proton.me")
        .generate()
        .unwrap();
    let expected_key_id = key.key_id();
    let exported_key = key.export("password".as_bytes(), true).unwrap();
    let exported_key_str = std::str::from_utf8(&exported_key).unwrap();
    assert!(exported_key_str.contains("BEGIN PGP PRIVATE KEY BLOCK"));
    let imported_key = PrivateKey::import(
        exported_key_str.as_bytes(),
        "password".as_bytes(),
        DataEncoding::Armor,
    )
    .unwrap();
    assert_eq!(imported_key.key_id(), expected_key_id);
}

#[test]
fn test_key_encode_public() {
    let key = KeyGenerator::new()
        .with_user_id("name", "name@proton.me")
        .generate()
        .unwrap();
    let public_key = key.to_public_key().unwrap();
    let exported_key = public_key.export(true).unwrap();
    let exported_key_str = std::str::from_utf8(exported_key.as_slice()).unwrap();
    assert!(exported_key_str.contains("BEGIN PGP PUBLIC KEY BLOCK"));
}

#[test]
fn test_session_key_from_token() {
    let zero_token = [0; 32];
    let sk = SessionKey::from_token(&zero_token, SessionKeyAlgorithm::Aes256);
    let exported_token = sk.export_token();
    let algorithm = sk.algorithm().unwrap();
    assert_eq!(exported_token.as_ref(), zero_token.as_ref());
    assert_eq!(algorithm, SessionKeyAlgorithm::Aes256);
}

#[test]
fn test_session_key_generate() {
    let sk = SessionKey::generate(SessionKeyAlgorithm::Aes128).unwrap();
    let algorithm = sk.algorithm().unwrap();
    assert_eq!(algorithm, SessionKeyAlgorithm::Aes128);
}

#[test]
fn test_pgp_key_generation() {
    let key = KeyGenerator::new()
        .with_user_id("name", "name@proton.me")
        .generate()
        .unwrap();
    assert!(key.key_id() > 0)
}
