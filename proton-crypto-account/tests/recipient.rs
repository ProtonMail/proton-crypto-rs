use proton_crypto::{
    crypto::{AccessKeyInfo, DataEncoding, OpenPGPFingerprint, PGPProviderSync, UnixTimestamp},
    new_pgp_provider,
};
use proton_crypto_account::keys::{
    APIPublicAddressKeyGroup, APIPublicAddressKeys, APIPublicKey, APIPublicKeySource,
    EmailMimeType, KeyFlag, PinnedPublicKeys, RecipientPublicKeyModel, SKLSignature, SignedKeyList,
};

// v4 key
const PUBLIC_KEY_0: &str = include_str!("data/pub_key_0.armor");
const PUBLIC_KEY_0_FP: &str = "ae084a8a4ce4d123c7e972f8a541a2caa89d2e7c";

// v6 pqc key
const PUBLIC_KEY_1: &str = include_str!("data/pub_key_1.armor");
const PUBLIC_KEY_1_FP: &str = "2a1aa0ec5a23c07f8500dd543f58479f2ed7034d0fd7909f0d1d32a2a0ca8fd9";

// v4 key
const PUBLIC_KEY_2: &str = include_str!("data/pub_key_2.armor");
const PUBLIC_KEY_2_FP: &str = "8572fd1d45adf544b2c8e9ff260c15dedebfa4de";

#[test]
fn test_internal_recipient_key_order() {
    let pgp = new_pgp_provider();
    let api_keys = test_public_keys().import(&pgp).unwrap();
    let api_keys_fingerprints = test_public_key_fingerprints();

    let model = RecipientPublicKeyModel::from_public_keys_at_time(
        api_keys.clone(),
        None,
        UnixTimestamp::new(1_751_372_229),
        true,
    );

    let api_key = model.api_keys.first().unwrap();
    let api_key_expected = api_keys_fingerprints.first().unwrap();
    assert_eq!(&api_key.key_fingerprint(), api_key_expected);
}

#[test]
fn test_internal_recipient_key_order_prefer_pinned() {
    let pgp = new_pgp_provider();
    let api_keys = test_public_keys().import(&pgp).unwrap();
    let api_keys_fingerprints = test_public_key_fingerprints();
    let pinned = create_test_pinned_key(&pgp, PUBLIC_KEY_2);

    let model = RecipientPublicKeyModel::from_public_keys_at_time(
        api_keys.clone(),
        Some(pinned),
        UnixTimestamp::new(1_751_372_229),
        true,
    );

    let api_key = model.api_keys.first().unwrap();
    let api_key_expected = api_keys_fingerprints.get(2).unwrap();
    assert_eq!(&api_key.key_fingerprint(), api_key_expected);
}

#[test]
#[allow(clippy::indexing_slicing)]
fn test_internal_recipient_key_order_prefer_v6() {
    let pgp = new_pgp_provider();
    let mut api_keys_data = test_public_keys();
    api_keys_data.address_keys.keys[1].primary = true;
    let api_keys = api_keys_data.import(&pgp).unwrap();
    let api_keys_fingerprints = test_public_key_fingerprints();

    // Prefer v6
    let model = RecipientPublicKeyModel::from_public_keys_at_time(
        api_keys.clone(),
        None,
        UnixTimestamp::new(1_751_372_229),
        true,
    );

    let api_key = model.api_keys.first().unwrap();
    let api_key_expected = api_keys_fingerprints.get(1).unwrap();
    assert_eq!(&api_key.key_fingerprint(), api_key_expected);

    // Prefer v4
    let model = RecipientPublicKeyModel::from_public_keys_at_time(
        api_keys.clone(),
        None,
        UnixTimestamp::new(1_751_372_229),
        false,
    );

    let api_key = model.api_keys.first().unwrap();
    let api_key_expected = api_keys_fingerprints.first().unwrap();
    assert_eq!(&api_key.key_fingerprint(), api_key_expected);
}

fn create_test_pinned_key<T: PGPProviderSync>(
    provider: &T,
    test_key: &str,
) -> PinnedPublicKeys<T::PublicKey> {
    let key = provider
        .public_key_import(test_key, DataEncoding::Armor)
        .unwrap();
    PinnedPublicKeys {
        pinned_keys: vec![key],
        encrypt_to_pinned: Some(true),
        encrypt_to_untrusted: Some(true),
        sign: Some(true),
        scheme: None,
        mime_type: Some(EmailMimeType::Html),
        contact_signature_verified: true,
        signature_timestamp: None,
    }
}

fn test_public_key_fingerprints() -> [OpenPGPFingerprint; 3] {
    [
        OpenPGPFingerprint::new(PUBLIC_KEY_0_FP.to_string()),
        OpenPGPFingerprint::new(PUBLIC_KEY_1_FP.to_string()),
        OpenPGPFingerprint::new(PUBLIC_KEY_2_FP.to_string()),
    ]
}

fn test_public_keys() -> APIPublicAddressKeys {
    let address_keys = vec![
        APIPublicKey {
            source: APIPublicKeySource::Proton,
            flags: KeyFlag::from(3_u32),
            primary: true,
            public_key: PUBLIC_KEY_0.to_string(),
        },
        APIPublicKey {
            source: APIPublicKeySource::Proton,
            flags: KeyFlag::from(3_u32),
            public_key: PUBLIC_KEY_1.to_string(),
            primary: false,
        },
        APIPublicKey {
            source: APIPublicKeySource::Proton,
            flags: KeyFlag::from(3_u32),
            public_key: PUBLIC_KEY_2.to_string(),
            primary: false,
        },
    ];
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
    APIPublicAddressKeys {
        address_keys: address_key_keygroup,
        catch_all_keys: None,
        unverified_keys: None,
        warnings: vec![String::from("this is a warning")],
        proton_mx: true,
        is_proton: false,
    }
}
