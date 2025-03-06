use proton_crypto_account::keys::{
    APIPublicAddressKeyGroup, APIPublicAddressKeys, APIPublicKey, APIPublicKeySource, KeyFlag,
    PublicAddressKeys, SKLSignature, SignedKeyList,
};
use proton_crypto_account::keys::{AddressType, RecipientType};
use proton_crypto_account::proton_crypto::{crypto::PGPProviderSync, new_pgp_provider};

fn get_test_public_key<T: PGPProviderSync>(provider: &T) -> PublicAddressKeys<T::PublicKey> {
    let address_keys = vec![APIPublicKey {
        source: APIPublicKeySource::Proton,
        flags: KeyFlag::from(3_u32),
        primary: true,
        public_key: "-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: ProtonMail\n\nxjMEZW86jxYJKwYBBAHaRw8BAQdAQOc3jVxw1ISyaSKde3UJ7ZH5foMrjeCV\nNWNm8uHmqOnNKWx1YnV4MkBwcm90b24uYmxhY2sgPGx1YnV4MkBwcm90b24u\nYmxhY2s+wowEEBYKAD4FgmVvOo8ECwkHCAmQGQDOlJmIZYgDFQgKBBYAAgEC\nGQECmwMCHgEWIQTSZZlb0pFeKO6tpwcZAM6UmYhliAAADqcBAMBEiBTMSpoW\n0RiXd8wOVl37EyGd39rx0IlGsjsI77AQAP9VsjMZLAD6HU2SYwiL5EF2wHpP\nOUcDZqVMpnL9aaJeBsKoBBAWCABaBQJlbzrpCRDU0hoFUaey7BYhBDYVQ78N\npW2mDLPalNTSGgVRp7LsLBxUZXN0IE9wZW5QR1AgQ0EgPHRlc3Qtb3BlbnBn\ncC1jYUBwcm90b24ubWU+BYMA7U4AAABVpgEApRWyrfiiJKsSl+Y/kWApsHgN\nAgSLLTsXXFxjpUg88ggA/iAIkVfZBOvLlDMdcuGPXliZythV5A292gekdlH+\n0SoIzjgEZW86jxIKKwYBBAGXVQEFAQEHQLVv/2vApjXs2rWnbzfkqDWiBA5X\nj46YndFrAia0Fa10AwEIB8J4BBgWCgAqBYJlbzqPCZAZAM6UmYhliAKbDBYh\nBNJlmVvSkV4o7q2nBxkAzpSZiGWIAAAFkgEApdB1yTmSFV+QcrgsGSZ7veyF\nTupI/rjj+Y8rceHcBkcBALaLyrpX7cUeY0yX2MZhPmpiJeE4+4Rot8PIGkVa\nX08A\n=fBDT\n-----END PGP PUBLIC KEY BLOCK-----\n".into(),
    }];
    let skl = SignedKeyList {
        min_epoch_id: Some(837),
        max_epoch_id: Some(1407),
        expected_min_epoch_id: None,
        data: Some("Data".into()),
        obsolescence_token: None,
        signature: Some(SKLSignature::from("signature")),
        revision: 31,
    };
    let address_key_keygroup = APIPublicAddressKeyGroup {
        keys: address_keys,
        signed_key_list: Some(skl),
    };
    let api_keys = APIPublicAddressKeys {
        address_keys: address_key_keygroup,
        catch_all_keys: None,
        unverified_keys: None,
        warnings: vec![String::from("this is a warning")],
        proton_mx: true,
        is_proton: false,
    };
    api_keys.import(provider).unwrap()
}

#[test]
fn test_api_keys_to_inbox() {
    let provider = new_pgp_provider();
    let test_api_imported_keys = get_test_public_key(&provider);
    let expected_num_keys = test_api_imported_keys.address.keys.len();
    let expected_warnings = test_api_imported_keys.warnings.clone();
    let inbox_keys = test_api_imported_keys.into_inbox_keys(false);
    assert_eq!(inbox_keys.public_keys.len(), expected_num_keys);
    assert_eq!(inbox_keys.warnings, expected_warnings);
    assert_eq!(inbox_keys.recipient_type, RecipientType::Internal);
    assert_eq!(inbox_keys.address_type, AddressType::Normal);
    assert!(!inbox_keys.is_internal_with_disabled_e2ee);
}
