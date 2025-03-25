use proton_crypto::crypto::{DataEncoding, KeyGeneratorAlgorithm, PGPProviderSync};
use proton_crypto::{new_pgp_provider, new_srp_provider};
use proton_crypto_account::keys::{
    AddressKeys, ArmoredPrivateKey, DecryptedUserKey, EncryptedKeyToken, KeyFlag, KeyId,
    KeyTokenSignature, LocalAddressKey, LocalUserKey, LockedKey, PGPDeviceKey, UnlockedAddressKeys,
    UserKeys,
};
use proton_crypto_account::salts::{KeySalt, KeySecret, Salt, Salts};

const TEST_USER_KEY: &str = "-----BEGIN PGP PRIVATE KEY BLOCK-----

xYYEZXrEuBYJKwYBBAHaRw8BAQdAd3SP+S82mvNYec99IYXXy02QlEtWOwCX
G+VRoWMTJgT+CQMIAuL1Bl1uoZBgAAAAAAAAAAAAAAAAAAAAAP8Kb+34nsOQ
jVlCUF4Rco6I2xectxdUsuCm6X+Emq+S+8JsPw/rwVxAmClvKJaeWIfZIV/u
yc07bm90X2Zvcl9lbWFpbF91c2VAZG9tYWluLnRsZCA8bm90X2Zvcl9lbWFp
bF91c2VAZG9tYWluLnRsZD7CjAQQFgoAPgWCZXrEuAQLCQcICZD98eusToQD
awMVCAoEFgACAQIZAQKbAwIeARYhBMZ9T6whFVji9dBihP3x66xOhANrAADW
1QEA4TDQcWcCskhIbAyLj3eFN9oO4cAv01QnTYuW5p5LvMYA/AyngETI6OGC
+/8UR3hKvmZMnThBMRfbzqg5B96KTIcBx4sEZXrEuBIKKwYBBAGXVQEFAQEH
QCmW61ll1IgTcm8TuNuh92qEGoIzYrRs0fb6ivPBz7YJAwEIB/4JAwh2VqMV
7EJ4WmAAAAAAAAAAAAAAAAAAAAAAjDFyvMguSeKDXNNvviwSK+nf7uqvbUNJ
EEuxjr48kR2A6Cc4OavQJbAAHIVwUG8UQ+PYW/PvwngEGBYKACoFgmV6xLgJ
kP3x66xOhANrApsMFiEExn1PrCEVWOL10GKE/fHrrE6EA2sAAIGYAQCzpA2U
R18gbFL3k6xUaUaRHxZoxBZQ2crLRO1GhgxTxQEAhYFyb7k/0S4XwcDpSgJO
YJWp7nLYBj9YSh4+qOa/5QM=
-----END PGP PRIVATE KEY BLOCK-----
";

const TEST_USER_KEY_CHANGED: &str = "-----BEGIN PGP PRIVATE KEY BLOCK-----

xYYEZkI9XRYJKwYBBAHaRw8BAQdAqWn9T/nEzBz31DqsXAUdtIGUnrIHNrfD
ZOuvtEIf8G/+CQMI8okkwdBKjuxgKBsLTTZH6cHgAlro1OnVNykZFiG6qASZ
Omwsl9FjZdozMlq/4AyPwDG2tkwzyEHKzn+4/Daw+FBs9ve/2Z2kOq9aEn6I
nc07bm90X2Zvcl9lbWFpbF91c2VAZG9tYWluLnRsZCA8bm90X2Zvcl9lbWFp
bF91c2VAZG9tYWluLnRsZD7CjAQQFgoAPgWCZkI9XQQLCQcICZBICuUpsYEG
ZQMVCAoEFgACAQIZAQKbAwIeARYhBCF533Bw13ukWKtNIUgK5SmxgQZlAADY
pAD+NXPfGC0v116+xHi9HIcdDUXrQpd8pRbKRcHHKZ94DF0BAOYorJa1OHzk
wzjxWQEz5Y82SLRYLNmlIVF+hHXlLtYAx4sEZkI9XRIKKwYBBAGXVQEFAQEH
QKm+vMMpfMo45etkNw3LR+jFgMrbe4hZ9zPVZCxJUZtRAwEIB/4JAwg+PXvg
gHJFA2ApL3+4HL9kuK3+HzOdTrWAGQ2dET1V4aV84gxW25FBTZbb+QqLhIym
+sYefVPntt6M/VNupYyXRs27abjPqm2YtH+rLnhwwngEGBYKACoFgmZCPV0J
kEgK5SmxgQZlApsMFiEEIXnfcHDXe6RYq00hSArlKbGBBmUAANN3AP9s1V6S
Lg9ogdrlmtTwuZhRXHQzUqC2AoLCv/lW0hz0ZQD+LBAeT7ymSyrwRtIvUh0b
qnK1SNfocPNfh//OecgiqA4=
=LMjL
-----END PGP PRIVATE KEY BLOCK-----
";

const TEST_KEY_PASSWORD: &str = "password";

fn get_test_decrypted_user_key<T: PGPProviderSync>(
    provider: &T,
    test_key: &str,
) -> Vec<DecryptedUserKey<T::PrivateKey, T::PublicKey>> {
    let private_key = provider
        .private_key_import(test_key, TEST_KEY_PASSWORD.as_bytes(), DataEncoding::Armor)
        .unwrap();
    let public_key = provider.private_key_to_public_key(&private_key).unwrap();
    vec![DecryptedUserKey {
        id: KeyId::from("G8URRzoYaBW6mSPQjbbo2yYgwI828DVcEs8dDRKxByd1A_qSRYF49TOtw_m4wvDGb76M-r3AVdXuDzSHObR5hQ=="),
        private_key,
        public_key,
    }]
}

#[must_use]
pub fn get_test_locked_address_key() -> AddressKeys {
    AddressKeys::new(
        vec![LockedKey {
            id:KeyId::from("ssbW3i5egXM4F-2uqNc2qACsxtKnuYaWMYJsso5IKTLQXLwEDFc_Hib0QaK6QODlGryyLhBH679-UkMkRBSz9w=="),
            version:3,
            private_key: ArmoredPrivateKey::from("-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: ProtonMail\n\nxYYEZWRmVhYJKwYBBAHaRw8BAQdA5Y8bUHq5hTJBWZEa/mxOKJkOOd4h9CVo\n2vISFQLcccD+CQMI0hvANzTOSIJggUFyUgQsMpsQzh9uqDb7IbbFWLnI63C1\nm3lKZ4tICeQV4tVFRvHlVRNzJIuTGjFiFbYO1t5ZgcJJgiPEiL5kORqWMOBp\n680pbHVidXg0QHByb3Rvbi5ibGFjayA8bHVidXg0QHByb3Rvbi5ibGFjaz7C\njAQQFgoAPgWCZWRmVgQLCQcICZDvQqbsF76qjAMVCAoEFgACAQIZAQKbAwIe\nARYhBKcQ8sEYupYe38hwRu9CpuwXvqqMAAB5OQD/XyIK1r+JOFT3cYiBcaFx\niox1yFrsr4uTg8kL1fQPyuoBAIG92J1MoimhMPuYvvTmIvNrvWPZvutw+BF2\nhJvRYDYCx4sEZWRmVhIKKwYBBAGXVQEFAQEHQIaaQMB4FXy/xC3qgmlhtnvR\nWceanT3nlzFjIrS96RUmAwEIB/4JAwj8w5GKSR+H62BnDPr48nwPGpA+jvPg\nXG2m4wseURUjdhnVmnLNkC4gJH6wQRz4sqBPye2fHWp+loh+LEDyeBawvkbS\n/FQXNwP7NLSkn84dwngEGBYIACoFgmVkZlYJkO9CpuwXvqqMApsMFiEEpxDy\nwRi6lh7fyHBG70Km7Be+qowAAHeFAP91gCl/VD/zHEvYIpWEK672jkPUPDpP\nLl+erDsL2C10mgEA5fbBK09OVIjtYUJxiId1YYfn/4/ym92WNEAT20prLww=\n=Eckc\n-----END PGP PRIVATE KEY BLOCK-----\n"),
            token:Some(EncryptedKeyToken::from("-----BEGIN PGP MESSAGE-----\nVersion: ProtonMail\n\nwV4DcsIsGT18EWcSAQdARTz8SqnWI4HNr+g19xu794pnOQaV0u0GIKbmByr1\n7w8wkWeiYBLW0RmVRP6EPgYLWZoFagItzfCtQYd30RNAKFq33/fjYPDsIXsf\np42uiZ5Q0nEBJb2mMkj8HFEpNw+oeKQUx13OetooxcCald6kVnVQsxx9ZYJ/\np+tmXIoiQmdqSHmqfS6UyAJlyv3T6xqiU7ts5aUTDgS1siMr0UVw6rRLgFp6\npuf9bxNdGMlcmZlvxrMKH+TCodwOQJSXA0IoPDB9Qw==\n=qVb4\n-----END PGP MESSAGE-----\n")),
            signature:Some(KeyTokenSignature::from("-----BEGIN PGP SIGNATURE-----\nVersion: ProtonMail\n\nwnUEABYKACcFgmV6xP0JkP3x66xOhANrFiEExn1PrCEVWOL10GKE/fHrrE6E\nA2sAACw3AQDJcE5rLsObFILcYBnMMtMIRgk1yJC89wUEmC7HsUUu3wD9FBPO\nasM3eXktszZDtVlk9Yfd+AIxLINr98z/wm1CrgY=\n=2skj\n-----END PGP SIGNATURE-----\n")),
            primary: true,
            active: true,
            flags:Some(KeyFlag::from(3_u32)),
            activation: None,
            recovery_secret: None,
            recovery_secret_signature: None,
            address_forwarding_id: None,
        }]
    )
}

#[must_use]
pub fn get_test_locked_legacy_address_key() -> AddressKeys {
    AddressKeys::new(
        vec![LockedKey {
            id:KeyId::from("ssbW3i5egXM4F-2uqNc2qACsxtKnuYaWMYJsso5IKTLQXLwEDFc_Hib0QaK6QODlGryyLhBH679-UkMkRBSz9w=="),
            version:3,
            private_key: ArmoredPrivateKey::from(TEST_USER_KEY),
            token: None,
            signature: None,
            primary: true,
            active: true,
            flags:Some(KeyFlag::from(3_u32)),
            activation: None,
            recovery_secret: None,
            recovery_secret_signature: None,
            address_forwarding_id: None,
        }]
    )
}

fn get_test_locked_user_keys() -> UserKeys {
    let key = LockedKey {
        id: KeyId::from("aTdvCsWuv2V_YQQ5nLKsWPkHWMrlHfUxL9aTWakz6blhwI0q_j4MKnxO29xMQ4slCRvo3lFLE8ljb3kvMP2PQQ=="),
        version: 3,
        private_key: ArmoredPrivateKey::from("-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: ProtonMail\n\nxYYEZie3jRYJKwYBBAHaRw8BAQdAAp+4PE1Sf5V95XrIY/P2dUNk1TOojoEG\nLuuOzULTa1v+CQMINYn0u3DCV01gjT+Noe2HzLxwP2hieZC1aoGCxSrLn0fs\nLeShqv2pCPZ+SdrjXB5s5Rq7OP5Kr/2gN+0KS0yLGdyirFZWe6m5T8j20UQ5\n0M07bm90X2Zvcl9lbWFpbF91c2VAZG9tYWluLnRsZCA8bm90X2Zvcl9lbWFp\nbF91c2VAZG9tYWluLnRsZD7CjAQQFgoAPgWCZie3jQQLCQcICZA4nKgbRZBl\nGQMVCAoEFgACAQIZAQKbAwIeARYhBOZJEArPLqrMMxX8fzicqBtFkGUZAADk\n/AD+LA6NW1K+Z3IT66/DEtjH0cmw6HNqxkBdT7kaL2o5pAMA/j9b4JCurWk/\n62MBM4I9RwXzSo8lmgPiYwPp4d/xgEsMx4sEZie3jRIKKwYBBAGXVQEFAQEH\nQHvLC7RWIDsorX5ZmYwjZbUhbXnEcO2sYt8OFaIh5KtHAwEIB/4JAwhKivkG\nshycUGA6wZtPR2HqO6+jvvSlRau/g2eZnWqhnvB4iIYTcD+CPpcPnWrrNgTz\nAU+kQ5sVrP6OiKKHIkUvHT5+MwelTbcpievGx2zGwngEGBYKACoFgmYnt40J\nkDicqBtFkGUZApsMFiEE5kkQCs8uqswzFfx/OJyoG0WQZRkAAJ6BAQDv4nBl\nNnj0W7XiAjiwRmVrY/sdybelB6j01p7UrcVAxQEAtEmT2cSIScVdWH1j3H9l\n0gGE7amH+cm6CjXOA7+Uwwc=\n=RGJ0\n-----END PGP PRIVATE KEY BLOCK-----\n"),
        token: None,
        signature: None,
        activation: None,
        primary: true,
        active: true,
        flags: None,
        recovery_secret: None,
        recovery_secret_signature: None,
        address_forwarding_id: None,
    };
    UserKeys(vec![key])
}

fn get_test_salts() -> Salts {
    let salt = Salt {
        id: KeyId::from("aTdvCsWuv2V_YQQ5nLKsWPkHWMrlHfUxL9aTWakz6blhwI0q_j4MKnxO29xMQ4slCRvo3lFLE8ljb3kvMP2PQQ=="),
        key_salt: Some(KeySalt::from("6bIzN4A8bOwmsiEuCPj74g==".to_owned())),
    };
    Salts::new(vec![salt])
}

fn get_test_key_id() -> KeyId {
    KeyId::from(
        "aTdvCsWuv2V_YQQ5nLKsWPkHWMrlHfUxL9aTWakz6blhwI0q_j4MKnxO29xMQ4slCRvo3lFLE8ljb3kvMP2PQQ==",
    )
}

fn get_unlocked_address_keys<Provider: PGPProviderSync>(
    provider: &Provider,
) -> UnlockedAddressKeys<Provider> {
    let user_keys = get_test_decrypted_user_key(provider, TEST_USER_KEY);
    let address_keys = get_test_locked_address_key();
    let unlock_result = address_keys.unlock(provider, user_keys.as_slice(), None);
    unlock_result.unlocked_keys.into()
}

#[test]
fn test_address_keys_decrypt() {
    let provider = new_pgp_provider();
    let user_keys = get_test_decrypted_user_key(&provider, TEST_USER_KEY);
    let address_keys = get_test_locked_address_key();
    let unlocked_keys = address_keys.unlock(&provider, user_keys.as_slice(), None);
    assert!(unlocked_keys.failed.is_empty());
    assert!(!unlocked_keys.unlocked_keys.is_empty());
}

#[test]
fn test_address_keys_legacy_decrypt() {
    let provider = new_pgp_provider();
    let srp_provider = new_srp_provider();
    let key_id = get_test_key_id();
    let salts = get_test_salts();
    let user_keys = get_test_decrypted_user_key(&provider, TEST_USER_KEY);
    let address_keys = get_test_locked_address_key();

    let key_secret = salts
        .salt_for_key(&srp_provider, &key_id, "password".as_bytes())
        .unwrap();
    // Legacy keys are just encrypted with the key secret.
    let unlocked_keys = address_keys.unlock(&provider, user_keys.as_slice(), Some(&key_secret));
    assert!(unlocked_keys.failed.is_empty());
    assert!(!unlocked_keys.unlocked_keys.is_empty());
}

#[test]
fn test_user_keys_decrypt() {
    let provider = new_pgp_provider();
    let srp_provider = new_srp_provider();
    let user_keys = get_test_locked_user_keys();
    let key_id = get_test_key_id();
    let salts = get_test_salts();
    // Ok
    let key_secret = salts
        .salt_for_key(&srp_provider, &key_id, "password".as_bytes())
        .unwrap();
    let unlocked_user_key = user_keys.unlock(&provider, &key_secret);
    assert!(unlocked_user_key.unlocked_keys.len() == 1);
    // Fail
    let key_secret = salts
        .salt_for_key(&srp_provider, &key_id, "password1".as_bytes())
        .unwrap();
    let unlocked_user_key = user_keys.unlock(&provider, &key_secret);
    assert!(unlocked_user_key.unlocked_keys.is_empty());
    assert!(unlocked_user_key.failed.len() == 1);
}

#[test]
fn test_user_key_generate() {
    let provider = new_pgp_provider();
    let srp_provider = new_srp_provider();
    let salt = KeySalt::generate();
    let key_secret = salt
        .salted_key_passphrase(&srp_provider, "password".as_bytes())
        .unwrap();
    let key = LocalUserKey::generate(&provider, KeyGeneratorAlgorithm::default(), &key_secret)
        .expect("key generation failed");
    // Unlock ok
    key.unlock_and_assign_key_id(&provider, KeyId(String::default()), &key_secret)
        .expect("unlock should succeed");
    // Unlock fail
    let unlock_result = key.unlock_and_assign_key_id(
        &provider,
        KeyId(String::default()),
        &KeySecret::new("hello".into()),
    );
    assert!(unlock_result.is_err());
}

#[test]
fn test_user_key_change_secret() {
    let provider = new_pgp_provider();
    let test_user_key = get_test_decrypted_user_key(&provider, TEST_USER_KEY)
        .into_iter()
        .next()
        .unwrap();
    let test_secret = KeySecret::new("test_secret".into());
    let locked_key = LocalUserKey::relock_user_key(&provider, &test_user_key, &test_secret)
        .expect("lock should succeed");
    // Unlock ok
    locked_key
        .unlock_and_assign_key_id(&provider, KeyId(String::default()), &test_secret)
        .expect("unlock should succeed");

    // Unlock fail
    let unlock_result = locked_key.unlock_and_assign_key_id(
        &provider,
        KeyId(String::new()),
        &KeySecret::new("test_secret_wrong".into()),
    );
    assert!(unlock_result.is_err());
}

#[test]
fn test_address_key_generate() {
    let provider = new_pgp_provider();
    let srp_provider = new_srp_provider();
    let salt = KeySalt::generate();
    let key_secret = salt
        .salted_key_passphrase(&srp_provider, "password".as_bytes())
        .unwrap();
    let key = LocalUserKey::generate(&provider, KeyGeneratorAlgorithm::default(), &key_secret)
        .expect("key generation failed");
    let unlocked_user_key = key
        .unlock_and_assign_key_id(&provider, KeyId(String::default()), &key_secret)
        .expect("unlock should succeed");

    let fresh_address_key = LocalAddressKey::generate(
        &provider,
        "test@test.test",
        KeyGeneratorAlgorithm::default(),
        KeyFlag::default(),
        true,
        &unlocked_user_key,
    )
    .expect("ok");
    // Unlock ok
    fresh_address_key
        .unlock_and_assign_key_id(&provider, KeyId(String::new()), &unlocked_user_key)
        .expect("unlock should not fail");

    // Unlock fail
    let wrong_key = get_test_decrypted_user_key(&provider, TEST_USER_KEY)
        .into_iter()
        .next()
        .unwrap();
    let unlock_result =
        fresh_address_key.unlock_and_assign_key_id(&provider, KeyId(String::new()), &wrong_key);
    assert!(unlock_result.is_err());
}

#[test]
fn test_address_key_change_parent_key() {
    // Init test data
    let provider = new_pgp_provider();
    let user_keys = get_test_decrypted_user_key(&provider, TEST_USER_KEY);
    let address_keys = get_test_locked_address_key();
    let unlocked_keys = address_keys.unlock(&provider, user_keys.as_slice(), None);
    assert!(unlocked_keys.failed.is_empty());
    assert!(!unlocked_keys.unlocked_keys.is_empty());

    let other_user_key = get_test_decrypted_user_key(&provider, TEST_USER_KEY_CHANGED)
        .into_iter()
        .next()
        .unwrap();
    // Non-Legacy
    let test_address_key = unlocked_keys.unlocked_keys.into_iter().next().unwrap();
    let locked_address_key =
        LocalAddressKey::relock_address_key(&provider, &test_address_key, &other_user_key)
            .expect("lock should work");

    // Unlock ok
    locked_address_key
        .unlock_and_assign_key_id(&provider, KeyId(String::new()), &other_user_key)
        .expect("unlock should not fail");

    // Unlock fail
    let unlock_result = locked_address_key.unlock_and_assign_key_id(
        &provider,
        KeyId(String::new()),
        user_keys.first().unwrap(),
    );
    assert!(unlock_result.is_err());

    // Legacy
    let test_secret = KeySecret::new("test_secret".into());
    let locked_address_key =
        LocalAddressKey::relock_address_key_legacy(&provider, &test_address_key, &test_secret)
            .expect("lock should work");

    // Unlock ok
    locked_address_key
        .unlock_legacy_and_assign_key_id(&provider, KeyId(String::new()), &test_secret)
        .expect("unlock should not fail");

    // Unlock fail
    let unlock_result = locked_address_key.unlock_legacy_and_assign_key_id(
        &provider,
        KeyId(String::new()),
        &KeySecret::new("test_secret_wrong".into()),
    );
    assert!(unlock_result.is_err());
}

#[test]
fn test_address_key_export() {
    let provider = new_pgp_provider();
    let address_keys = get_unlocked_address_keys(&provider);
    let primary = address_keys.primary_for_mail().expect("No key found");
    let (fingerprint, exported_public_key) = primary
        .export_public_key(&provider)
        .expect("Export should not fail");

    let primary = address_keys.primary_default().expect("No key found");
    let (fingerprint_default, exported_public_key_default) = primary
        .export_public_key(&provider)
        .expect("Export should not fail");

    assert!(exported_public_key.contains("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
    assert!(exported_public_key.contains("-----END PGP PUBLIC KEY BLOCK-----"));
    assert_eq!(exported_public_key, exported_public_key_default);
    assert_eq!(fingerprint, fingerprint_default);
}

#[test]
fn test_device_key() {
    let pgp_provider = new_pgp_provider();
    let device_key = PGPDeviceKey::generate(&pgp_provider).expect("key generation failed");
    let exported_public_key = device_key
        .export_public_key(&pgp_provider)
        .expect("Export should not fail");

    assert!(exported_public_key.contains("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
    assert!(exported_public_key.contains("-----END PGP PUBLIC KEY BLOCK-----"));

    let serialized = device_key
        .serialize_to_secure_storage(&pgp_provider)
        .expect("failed to serialize");
    let device_key_after =
        PGPDeviceKey::deserialize_from_secure_storage(&pgp_provider, serialized.as_ref())
            .expect("failed to deserialize");
    let exported_public_key_after = device_key_after
        .export_public_key(&pgp_provider)
        .expect("Export should not fail");

    assert_eq!(exported_public_key, exported_public_key_after);
}
