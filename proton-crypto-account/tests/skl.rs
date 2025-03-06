use proton_crypto::{
    crypto::{DataEncoding, PGPProviderSync},
    new_pgp_provider,
};

use proton_crypto_account::keys::{
    APIPublicAddressKeyGroup, APIPublicKey, APIPublicKeySource, DecryptedAddressKey, KeyFlag,
    KeyId, LocalSignedKeyList, PublicAddressKeyGroup, SKLDataJson, SKLSignature, SignedKeyList,
    UnlockedAddressKeys,
};

const TEST_ADDRESS_KEY_PRIVATE: &str = "-----BEGIN PGP PRIVATE KEY BLOCK-----

xYYEZie3jRYJKwYBBAHaRw8BAQdA0lnAs/zJxwALYyLq9jnthTTJauaqwvLQ
od3cCVOua+v+CQMIhZwosaEFrVdgBWld0b0A2Buch+gTvX4AigO5y8rRErRs
c1KjMyUGUmU5qmJpR3lmX7lWFK9zHZV+u7ybTBX/9fvkFcVLugS2z+I0dE3K
Ds0vcnVzdF90ZXN0QHByb3Rvbi5ibGFjayA8cnVzdF90ZXN0QHByb3Rvbi5i
bGFjaz7CjAQQFgoAPgWCZie3jQQLCQcICZDD5SnHczmG6wMVCAoEFgACAQIZ
AQKbAwIeARYhBBGxOGij+OleubdsX8PlKcdzOYbrAABxyQEA53ij2BO8KHOi
lmhaB9qeaNDnZhlvNazM9O87r2Cm03UA/jLgvtPQe+HgIDbguMFSeacvAKSG
2A5jl6AAPWjifF4Jx4sEZie3jRIKKwYBBAGXVQEFAQEHQLJ401cWczKQigvx
jfQ5DxVXvA9p+HRuW16642Ybd99+AwEIB/4JAwiZPoLcohue0mAid4zMemsH
gvqoauEgGIdKuWpBcLT7PQFkgzxlbveHdKwVDjiAhDPE4RV2LZ36QKbDVqhk
/5rwCfSqircDl8fDO/RPzUKBwngEGBYKACoFgmYnt40JkMPlKcdzOYbrApsM
FiEEEbE4aKP46V65t2xfw+Upx3M5husAAPU7AQCMKF564vtdGCY/KIGqAhm2
SNUnK5w6MkGKgrztbAhvngD/VK3t0WB8mUqXC3JoS2xC6rtyiyciAjQvuwWT
2ePDxgI=
=bOcf
-----END PGP PRIVATE KEY BLOCK-----
";

const TEST_ADDRESS_KEY_PRIVATE_V6: &str = "-----BEGIN PGP PRIVATE KEY BLOCK-----

xX0GZ1g5cxsAAAAgNZbQcSMtbiRSg6xMvM8ZCaX3p8LP3TG5+cC2MZ4drEj+HQkL
AwgQjyMiy81qWWCcWR6htqofAyKuKGePyeqxL4G8opCXZ9c2NEjGAdfx37xvc86e
2B45RtXz8WV6dV3w1htWxYpX8l6sfCvGjKfP5BU61MKwBh8bCgAAAEEFgmdYOXMD
CwkHAxUKCAMWAAICmwMCHgkioQaEU365+JMtkj6IznT4yWAEJcbFv6fUkOrbl8Qe
rTkqwQUnCQIHAgAAAAAFTCDqQieusIZ7bHqzVmIQseD5m2frS4NlnpR+2CI1XtvE
3MioCMjc25bjRhnmQHKnMIXq7m+ZDbeNksh5ZoF1/MeYzaoOseH3Obfwvuzag4yu
2Cl2bDK3UUujP6p/RCrwfw7NH3J1c3RfdGVzdCA8cnVzdF90ZXN0QHByb3Rvbi5t
ZT7CmwYTGwoAAAAsBYJnWDlzAhkBIqEGhFN+ufiTLZI+iM50+MlgBCXGxb+n1JDq
25fEHq05KsEAAAAAO+8g19DO9IlJPpXqrQYmB+n1zP1FERx04guxRBRCMho/Qu54
5LxHkdI7u+Lh4omVBWGMXtvrNWqxk4DWpNB4d/Vvf7nmEPxLIh73qCA3MjGty5w2
1tcxSWgjVJDbzjeNHwsHx30GZ1g5cxkAAAAgwh+DK1Ho+O8s0yNV5+BX9GXwano4
Y7uXOM3LZwxW6gD+HQkLAwgQjyMiy81qWWA9H+iweaVzKuAnwV/TcJ8Jp4GGkKuZ
2+7bAIuMHlLVAjwImZpzLOWAa8K0DcV71P4900J9+FhTPR2KNy53wtmEXxsTOcKb
BhgbCgAAACwFgmdYOXMCmwwioQaEU365+JMtkj6IznT4yWAEJcbFv6fUkOrbl8Qe
rTkqwQAAAADkZiA7fBlrC518qQfBuTDZ6ZAejdFATGGQs+dCcsxOpbHEHBELs/7c
Q0R+gtvwjDnTgL9dXewcwu6CfKAy4IYiL3wup9cYTZe9jPnXk3183zMVhNUCTkFB
aRIU+dk6LILLIgE=
-----END PGP PRIVATE KEY BLOCK-----
";

fn get_test_keys<T: PGPProviderSync>(provider: &T) -> PublicAddressKeyGroup<T::PublicKey> {
    let api_address_keys = APIPublicAddressKeyGroup{
        keys: vec![
            APIPublicKey{
                source:APIPublicKeySource::Proton,
                flags: KeyFlag::from(3_u32),
                primary: true,
                public_key: "-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: ProtonMail\n\nxjMEYV78vBYJKwYBBAHaRw8BAQdATzuHJEfffnkkxR6voPu8hMI30ZleJZrF\nci81cphX+9jNL3Rlc3RrdEBrdC5wcm90b24uYmxhY2sgPHRlc3RrdEBrdC5w\ncm90b24uYmxhY2s+wo8EEBYKACAFAmFe/LwGCwkHCAMCBBUICgIEFgIBAAIZ\nAQIbAwIeAQAhCRAk1S96jDVEmRYhBAkUoLQ3MQGw5M9DtyTVL3qMNUSZo6UB\nAPzhGjHv//jl43mqXEo2/V47nREbm9MofSMOh+nqfg6wAP94opkrY95h9WVu\nG5+63MJWeHfVChrtYGLdE5PuSeSBBc44BGFe/LwSCisGAQQBl1UBBQEBB0B8\nQ43HsvkQ2JimHPujgpIcwDyMAnVxjoYJWHiDyZ9yKgMBCAfCeAQYFggACQUC\nYV78vAIbDAAhCRAk1S96jDVEmRYhBAkUoLQ3MQGw5M9DtyTVL3qMNUSZ9kkA\n/jzoeQgc7VnhdliB5VvOk7dKQBI4kqGpK7at8ThZHPXYAP9g7k0OjUeMfnh/\nNP1i3leIoG0QRT9lJ4XM0qcrhVqjBg==\n=XfZT\n-----END PGP PUBLIC KEY BLOCK-----\n".to_owned() 
            },
        ],
        signed_key_list: None
    };
    api_address_keys.import(provider).unwrap()
}

fn get_test_skl() -> SignedKeyList {
    SignedKeyList {
        min_epoch_id: Some(32),
        max_epoch_id: Some(35),
        data: Some(SKLDataJson::from("[{\"Primary\":1,\"Flags\":3,\"Fingerprint\":\"0914a0b4373101b0e4cf43b724d52f7a8c354499\",\"SHA256Fingerprints\":[\"99dfe8acfa4e091fb81c88dca947cf05fc2e764332cd20484ddea016f3ef1c35\",\"ac0f9568fc061b980cb02fb5b29471460f065353a2375c6f30fc4465c903f26e\"]},{\"Primary\":0,\"Flags\":3,\"Fingerprint\":\"59f1af56b673645834574e705ffcf74f485dc81a\",\"SHA256Fingerprints\":[\"8ccca8278be421752a659eadffd0b1d3a7a0cf778d97254b2cea2f4ab7faef93\",\"9e967080956e786bb098423853062b9c26193de48fb83107df8332828d0973c3\"]},{\"Primary\":0,\"Flags\":3,\"Fingerprint\":\"68ec39a2f0c0bf87c1a3ee6c03301a8551e6040c\",\"SHA256Fingerprints\":[\"57d5299ce1d187f1b606b6a7f45d8b21a4154fcd94e87d39cdd60aa11207129a\",\"490afb29e10416fcac60889a3e8841b7063eb4eeb6f843abf6ffc83d14d7c1ea\"]}]")),
        signature: Some(SKLSignature("-----BEGIN PGP SIGNATURE-----\r\nVersion: OpenPGP.js v4.10.10\r\nComment: https://openpgpjs.org\r\n\r\nwnUEARYKAAYFAmFfBeIAIQkQJNUveow1RJkWIQQJFKC0NzEBsOTPQ7ck1S96\r\njDVEmWQ1AQC1mZcKKhL9Ub9gX/HI6s3QeCG40zKG57g64BhmcNM2dAD/UhZv\r\nT2eWnpQ5JeboHlSsw1m+RRGwtqQ+u4al9F6o7Ac=\r\n=CiSs\r\n-----END PGP SIGNATURE-----\r\n".to_owned())),
        expected_min_epoch_id: None,
        obsolescence_token: None,
        revision: 1,
    }
}

fn create_test_private_keys_with_skl<Provider: PGPProviderSync>(
    provider: &Provider,
) -> (UnlockedAddressKeys<Provider>, SignedKeyList) {
    let private_key = provider
        .private_key_import(TEST_ADDRESS_KEY_PRIVATE, "password", DataEncoding::Armor)
        .unwrap();
    let public_key = provider.private_key_to_public_key(&private_key).unwrap();
    let key = DecryptedAddressKey {
        id: KeyId::from("gzKDANARz0i8OHhGuZV-oFfURju0I3XeW_hNn09g13dS_NJ57UbW420UAcWb-0s93xoav22O_jARq61FyL3guw=="),
        flags: KeyFlag::from(3_u32),
        primary: true,
        private_key,
        public_key,
        is_v6: false,
    };
    let skl = SignedKeyList {
        min_epoch_id: Some(3),
        max_epoch_id: Some(283),
        data: Some(SKLDataJson::from("[{\"Primary\":1,\"Flags\":3,\"Fingerprint\":\"11b13868a3f8e95eb9b76c5fc3e529c7733986eb\",\"SHA256Fingerprints\":[\"f16446135c9380b623bb201a1409bcfd6cb5144fe463b45d08b51e9e335e39ad\",\"ffb76afa704c9a6808bf67009f3a4f0155becf34ff395e3be2e557960b9a4e1c\"]}]")),
        signature: Some(SKLSignature::from("-----BEGIN PGP SIGNATURE-----\nVersion: ProtonMail\n\nwqkEARYKAFsFgmYnt8kJkMPlKcdzOYbrMxSAAAAAABEAGWNvbnRleHRAcHJv\ndG9uLmNoa2V5LXRyYW5zcGFyZW5jeS5rZXktbGlzdBYhBBGxOGij+Oleubds\nX8PlKcdzOYbrAABnFwD+JukILCsHB7JxsMY4zP9EU8SGhu5/Gwx2aLod9GR1\nfucBANdiI900lTkhTRMHDof4aZ/8Ef5uV1pmQ/CFHQYTcj4P\n=QEZt\n-----END PGP SIGNATURE-----\n")),
        expected_min_epoch_id: None,
        obsolescence_token: None,
        revision: 1,
    };
    (UnlockedAddressKeys(Vec::from([key])), skl)
}

fn create_test_address_keys_v6<Provider: PGPProviderSync>(
    provider: &Provider,
) -> UnlockedAddressKeys<Provider> {
    let private_key = provider
        .private_key_import(TEST_ADDRESS_KEY_PRIVATE, "password", DataEncoding::Armor)
        .unwrap();
    let public_key = provider.private_key_to_public_key(&private_key).unwrap();
    let key = DecryptedAddressKey {
        id: KeyId::from("1"),
        flags: KeyFlag::from(3_u32),
        primary: true,
        private_key,
        public_key,
        is_v6: false,
    };

    let private_key_v6 = provider
        .private_key_import(TEST_ADDRESS_KEY_PRIVATE_V6, "password", DataEncoding::Armor)
        .unwrap();
    let public_key_v6 = provider.private_key_to_public_key(&private_key_v6).unwrap();
    let key_v6 = DecryptedAddressKey {
        id: KeyId::from("2"),
        flags: KeyFlag::from(3_u32),
        primary: true,
        private_key: private_key_v6,
        public_key: public_key_v6,
        is_v6: true,
    };
    UnlockedAddressKeys(Vec::from([key, key_v6]))
}

#[test]
fn test_retrieve_skl_data() {
    let skl = get_test_skl();
    let skl_data_result = skl.signed_key_list_data();
    assert!(skl_data_result.is_ok());
}

#[test]
fn test_verify_skl_data() {
    let provider = new_pgp_provider();
    let skl = get_test_skl();
    let public_keys = get_test_keys(&provider);
    skl.verify_signature(&provider, public_keys.as_ref(), None)
        .unwrap();
}

#[test]
fn test_create_skl_data() {
    let provider = new_pgp_provider();
    let (address_keys, skl) = create_test_private_keys_with_skl(&provider);
    let local_skl = LocalSignedKeyList::generate(&provider, &address_keys)
        .expect("SKL generation must not fail");
    assert_eq!(&local_skl.data, skl.data.as_ref().unwrap());
    let dummy_skl = SignedKeyList {
        min_epoch_id: None,
        max_epoch_id: None,
        expected_min_epoch_id: None,
        data: Some(local_skl.data),
        obsolescence_token: None,
        signature: Some(local_skl.signature),
        revision: 1,
    };
    dummy_skl
        .verify_signature(&provider, &address_keys, None)
        .expect("signature should verify");
}

#[test]
fn test_create_skl_data_v6() {
    let provider = new_pgp_provider();
    let address_keys = create_test_address_keys_v6(&provider);
    let local_skl = LocalSignedKeyList::generate(&provider, &address_keys)
        .expect("SKL generation must not fail");
    let dummy_skl = SignedKeyList {
        min_epoch_id: None,
        max_epoch_id: None,
        expected_min_epoch_id: None,
        data: Some(local_skl.data),
        obsolescence_token: None,
        signature: Some(local_skl.signature),
        revision: 1,
    };
    let primary_address_key_v6 = address_keys.primary_for_mail().expect("no primary");
    assert!(primary_address_key_v6.is_v6);
    dummy_skl
        .verify_signature(&provider, &[primary_address_key_v6.for_encryption()], None)
        .expect("signature v6 should verify");

    let primary_address_key_v4 = address_keys.primary_default().unwrap();
    assert!(!primary_address_key_v4.is_v6);
    dummy_skl
        .verify_signature(&provider, &[primary_address_key_v4], None)
        .expect("signature v4 should verify");
}
