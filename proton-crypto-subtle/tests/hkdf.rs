use proton_crypto_subtle::hkdf;
use rand::Rng as _;

fn high_entropy_secret() -> [u8; 32] {
    let mut secret = [0_u8; 32];
    let mut rng = rand::thread_rng();
    rng.fill(&mut secret);
    secret
}

#[test]
fn derive_aes_gcm_key_successful() {
    let secret = high_entropy_secret();
    let salt = [0_u8; 32];
    let info = b"my-info";

    let key = hkdf::derive_aes_gcm_key(&secret, &salt, info).unwrap();

    assert!(
        !key.as_bytes().iter().all(|&b| b == 0),
        "Key should not be all zeros"
    );
}

#[test]
fn derive_aes_gcm_key_without_salt() {
    let secret = high_entropy_secret();
    let salt = [0_u8; 32];
    let info = b"my-info";

    let key = hkdf::derive_aes_gcm_key(&secret, &salt, info).unwrap();

    assert!(
        !key.as_bytes().iter().all(|&b| b == 0),
        "Key should not be all zeros"
    );
}

#[test]
fn derive_aes_gcm_key_different_inputs_produce_different_keys() {
    let secret1 = high_entropy_secret();
    let secret2 = high_entropy_secret();

    let salt = [0_u8; 32];
    let info = b"my-info";

    let key1 = hkdf::derive_aes_gcm_key(&secret1, &salt, info).unwrap();
    let key2 = hkdf::derive_aes_gcm_key(&secret2, &salt, info).unwrap();

    assert_ne!(
        key1.as_bytes(),
        key2.as_bytes(),
        "Different secrets should produce different keys"
    );
}

#[test]
fn derive_aes_gcm_key_different_salts_produce_different_keys() {
    let secret = high_entropy_secret();
    let salt1 = [0_u8; 32];
    let mut salt2 = [0_u8; 32];
    salt2[0] = 1;
    let info = b"my-info";

    let key1 = hkdf::derive_aes_gcm_key(&secret, &salt1, info).unwrap();
    let key2 = hkdf::derive_aes_gcm_key(&secret, &salt2, info).unwrap();

    assert_ne!(
        key1.as_bytes(),
        key2.as_bytes(),
        "Different salts should produce different keys"
    );
}

#[test]
fn derive_aes_gcm_key_different_info_produce_different_keys() {
    let secret = high_entropy_secret();
    let salt = [0_u8; 32];
    let info1 = b"my-info-1";
    let info2 = b"my-info-2";

    let key1 = hkdf::derive_aes_gcm_key(&secret, &salt, info1).unwrap();
    let key2 = hkdf::derive_aes_gcm_key(&secret, &salt, info2).unwrap();

    assert_ne!(
        key1.as_bytes(),
        key2.as_bytes(),
        "Different info should produce different keys"
    );
}

#[test]
fn derive_aes_gcm_key_same_inputs_produce_same_keys() {
    let secret = high_entropy_secret();
    let salt = [0_u8; 32];
    let info = b"my-info";

    let key1 = hkdf::derive_aes_gcm_key(&secret, &salt, info).unwrap();
    let key2 = hkdf::derive_aes_gcm_key(&secret, &salt, info).unwrap();

    assert_eq!(
        key1.as_bytes(),
        key2.as_bytes(),
        "Same inputs should produce same keys"
    );
}
