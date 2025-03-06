use proton_crypto::crypto::{DataEncoding, PGPProvider, PGPProviderSync};
use proton_crypto::new_pgp_provider;
use proton_crypto_account::contacts::{
    ContactCardType, DecryptableVerifiableCard, EncryptableAndSignableCard,
};
use proton_crypto_account::keys::{DecryptedUserKey, KeyId};

const PRIVATE_KEY: &str = "-----BEGIN PGP PRIVATE KEY BLOCK-----

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

const ENCRYPTED_AND_SIGNED_DATA: &str = "-----BEGIN PGP MESSAGE-----\nVersion: ProtonMail\n\nwV4D+/QBrSbx5h0SAQdAo85FIPb2zNkcGaXxLgeGr7JDeyt7oRNedt91nrMQ\nXh8w4FyEVqfVgYWg/NJ16UHUplqk8QMfZ7MDGloj3UynrmfiMB4D61IusigX\nPBbOC4R00ncBe3t89HKRigE/OJPDfERNQUPHHQDDxD+5TZ4zo6IWTuM7Sywk\nyYtNSezc15HYX/Y2dMuCc8ihIJNJQgJ0H5hGLflDZVWMwtWSqUCzZ/M/MZ6V\n/eju7buxvpBKV76ONVEMm0wJ7MbeizhNDiwjvaS0W4SpdewSww==\n=zhyX\n-----END PGP MESSAGE-----\n";
const ENCRYPTED_AND_SIGNED_SIGNATURE: &str = "-----BEGIN PGP SIGNATURE-----\nVersion: ProtonMail\n\nwnUEARYKACcFgmZPSJAJkEgK5SmxgQZlFiEEIXnfcHDXe6RYq00hSArlKbGB\nBmUAAOyWAP0SKaiJJx8XzBKWGwBph8MtQDKkiSmPpf+3UnZJNHtnLQD+KeCq\ncCSz/TrhSygmJuiwSUqN7DcUeqOrmAK87GmAYw4=\n=bg4m\n-----END PGP SIGNATURE-----\n";

const ENCRYPTED_AND_SIGNED_SIGNATURE_INVALID: &str = "-----BEGIN PGP SIGNATURE-----\nVersion: ProtonMail\n\nwnUEARYKACcFgmZPSJAJkEgK5SmxgQZlFiEEIXnfcHDXe6RYq00hWONTPASS\nBmUAAOyWAP0SKaiJJx8XzBKWGwBph8MtQDKkiSmPpf+3UnZJNHtnWONTPASS\ncCSz/TrhSygmJuiwSUqN7DcUeqOrmAK87GmAYw4=\n=bg4m\n-----END PGP SIGNATURE-----\n";

const ENCRYPTED_AND_SIGNED_DATA_PLAINTEXT: &str =
    "BEGIN:VCARD\r\nVERSION:4.0\r\nN:;;;;\r\nBDAY:20080523\r\nNOTE:hello\r\nEND:VCARD";

const SIGNED_DATA: &str = "BEGIN:VCARD\r\nVERSION:4.0\r\nFN;PREF=1:lubuxtest\r\nUID:proton-web-3675257f-cdc4-aaaf-742e-091096acf8b4\r\nITEM1.EMAIL;PREF=1:lubuxtest@proton.me\r\nITEM1.KEY;PREF=1:data:application/pgp-keys;base64,xjMEZcSYxBYJKwYBBAHaRw8BA\r\n QdAo6kNBgxZll8/Zf/5MS+xEvXCRxMSbhuLEqgxc/TPAQfNKWx1YnV4dGVzdEBwcm90b24ubWUg\r\n PGx1YnV4dGVzdEBwcm90b24ubWU+wowEEBYKAD4FgmXEmMQECwkHCAmQzY7Fx15PZDQDFQgKBBY\r\n AAgECGQECmwMCHgEWIQSsiS19zXY7Xi6ku07NjsXHXk9kNAAA58YA/3mcSsy8DaoRyqmKiri0ym\r\n wymWy0mgBSEKjFS1eXBUFzAP98vgzDiZXkFQw8jI9D11ykD3RPj4Xzub9pddpT4WvVAMKoBBAWC\r\n ABaBQJlxJkACRDYBsGvWXjoxxYhBAqGUv5dUzhgV4mf6dgGwa9ZeOjHLBxvcGVucGdwLWNhQHBy\r\n b3Rvbi5tZSA8b3BlbnBncC1jYUBwcm90b24ubWU+BYMA7U4AAAA/OAEAk0w7ExGM9OWR9L17Itp\r\n 8ERuTFkkJTvSnGIEmFHCnf64BAOC+F/aaWQ2RrclPg8EyGuY9aAhwdGlK53BhqmC8XeUAzjgEZc\r\n SYxBIKKwYBBAGXVQEFAQEHQIXYa1iz0juvJgD4u4x6q4l5tFlaufpterQEqKhPDYl3AwEIB8J4B\r\n BgWCgAqBYJlxJjECZDNjsXHXk9kNAKbDBYhBKyJLX3NdjteLqS7Ts2OxcdeT2Q0AABfyQD+IFDT\r\n lLtjvoFqji9ZvsYv7VvbI48wc2ti9SEgEnV9Gs0A/3LvPmBFhM+FY5LRVmlVGHXVIBo5DIFlTRw\r\n qUIsTNAQH\r\nEND:VCARD";
const SIGNED_SIGNATURE: &str = "-----BEGIN PGP SIGNATURE-----\nVersion: ProtonMail\n\nwnUEARYKACcFgmZPSJAJkEgK5SmxgQZlFiEEIXnfcHDXe6RYq00hSArlKbGB\nBmUAAN4YAQDw6/SL9HvDQ1xAbDqiIWFMLlIeu3xrqdjKr0Lr2J7ZXgEA4Bi+\nPVzWDK4s9zMO5FUjt5iWpAMm9Xsu5N0aHahWDQc=\n=NSAd\n-----END PGP SIGNATURE-----\n";

const SIGNED_SIGNATURE_INVALID: &str = "-----BEGIN PGP SIGNATURE-----\nVersion: ProtonMail\n\nwnUEARYKACcFgmZPSJAJkEgK5SmxgQZlFiEEIXnfcHDXe6RYq00hWONTPASS\nBmUAAN4YAQDw6/SL9HvDQ1xAbDqiIWFMLlIeu3xrqdjKr0Lr2J7ZXgEA4Bi+\nPVzWDK4s9zMO5FUjt5iWpAMm9Xsu5N0aHahWDQc=\n=NSAd\n-----END PGP SIGNATURE-----\n";

struct TestDecryptableCard(pub ContactCardType, pub String, pub String);

impl DecryptableVerifiableCard for TestDecryptableCard {
    fn card_type(&self) -> ContactCardType {
        self.0
    }

    fn card_data(&self) -> &[u8] {
        self.1.as_bytes()
    }

    fn card_signature(&self) -> Option<&[u8]> {
        Some(self.2.as_bytes())
    }
}

struct TestEncryptableCard(pub String);

impl EncryptableAndSignableCard for TestEncryptableCard {
    fn plaintext_card_data(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

#[test]
fn test_encrypted_card() {
    let provider = new_pgp_provider();
    let private_key = provider
        .private_key_import(
            PRIVATE_KEY.as_bytes(),
            "password".as_bytes(),
            DataEncoding::Armor,
        )
        .unwrap();
    let verification_key = provider.private_key_to_public_key(&private_key).unwrap();

    let card = TestDecryptableCard(
        ContactCardType::Encrypted,
        ENCRYPTED_AND_SIGNED_DATA.to_owned(),
        String::default(),
    );
    let test_result = card.decrypt_and_verify_sync(&provider, &[private_key], &[verification_key]);

    assert!(test_result.is_ok());
    let test_result = String::from_utf8(test_result.unwrap());
    assert!(test_result.is_ok());
    let test_result = test_result.unwrap();
    assert_eq!(&test_result, ENCRYPTED_AND_SIGNED_DATA_PLAINTEXT);
}

#[test]
fn test_signed_card() {
    let provider = new_pgp_provider();
    let private_key = provider
        .private_key_import(
            PRIVATE_KEY.as_bytes(),
            "password".as_bytes(),
            DataEncoding::Armor,
        )
        .unwrap();
    let verification_key = provider.private_key_to_public_key(&private_key).unwrap();

    let card = TestDecryptableCard(
        ContactCardType::Signed,
        SIGNED_DATA.to_owned(),
        SIGNED_SIGNATURE.to_owned(),
    );
    let test_result = card.decrypt_and_verify_sync(&provider, &[private_key], &[verification_key]);

    assert!(test_result.is_ok());
}

#[test]
fn test_signed_card_whitespace() {
    let provider = new_pgp_provider();
    let private_key = provider
        .private_key_import(
            PRIVATE_KEY.as_bytes(),
            "password".as_bytes(),
            DataEncoding::Armor,
        )
        .unwrap();
    let verification_key = provider.private_key_to_public_key(&private_key).unwrap();

    // Trailing whitespaces should be stripped.
    let mut data_to_sign = SIGNED_DATA.to_owned();
    data_to_sign.push_str("    ");
    let card = TestDecryptableCard(
        ContactCardType::Signed,
        data_to_sign,
        SIGNED_SIGNATURE.to_owned(),
    );
    let test_result = card.decrypt_and_verify_sync(&provider, &[private_key], &[verification_key]);

    assert!(test_result.is_ok());
}

#[test]
fn test_signed_card_invalid_signature() {
    let provider = new_pgp_provider();
    let private_key = provider
        .private_key_import(
            PRIVATE_KEY.as_bytes(),
            "password".as_bytes(),
            DataEncoding::Armor,
        )
        .unwrap();
    let verification_key = provider.private_key_to_public_key(&private_key).unwrap();

    let card = TestDecryptableCard(
        ContactCardType::Signed,
        SIGNED_DATA.to_owned(),
        SIGNED_SIGNATURE_INVALID.to_owned(),
    );
    let test_result = card.decrypt_and_verify_sync(&provider, &[private_key], &[verification_key]);

    assert!(test_result.is_err());
}

#[test]
fn test_signed_and_encrypted_card() {
    let provider = new_pgp_provider();
    let private_key = provider
        .private_key_import(
            PRIVATE_KEY.as_bytes(),
            "password".as_bytes(),
            DataEncoding::Armor,
        )
        .unwrap();
    let verification_key = provider.private_key_to_public_key(&private_key).unwrap();

    let card = TestDecryptableCard(
        ContactCardType::EncryptedAndSigned,
        ENCRYPTED_AND_SIGNED_DATA.to_owned(),
        ENCRYPTED_AND_SIGNED_SIGNATURE.to_owned(),
    );
    let test_result = card.decrypt_and_verify_sync(&provider, &[private_key], &[verification_key]);

    assert!(test_result.is_ok());
    let test_result = String::from_utf8(test_result.unwrap());
    assert!(test_result.is_ok());
    let test_result = test_result.unwrap();
    assert_eq!(&test_result, ENCRYPTED_AND_SIGNED_DATA_PLAINTEXT);
}

#[test]
fn test_signed_and_encrypted_card_invalid_signature() {
    let provider = new_pgp_provider();
    let private_key = provider
        .private_key_import(
            PRIVATE_KEY.as_bytes(),
            "password".as_bytes(),
            DataEncoding::Armor,
        )
        .unwrap();
    let verification_key = provider.private_key_to_public_key(&private_key).unwrap();

    let card = TestDecryptableCard(
        ContactCardType::EncryptedAndSigned,
        ENCRYPTED_AND_SIGNED_DATA.to_owned(),
        ENCRYPTED_AND_SIGNED_SIGNATURE_INVALID.to_owned(),
    );
    let test_result = card.decrypt_and_verify_sync(&provider, &[private_key], &[verification_key]);

    assert!(test_result.is_err());
}

#[test]
fn test_signed_card_no_verification_keys() {
    let provider = new_pgp_provider();
    let card = TestDecryptableCard(
        ContactCardType::Signed,
        SIGNED_DATA.to_owned(),
        SIGNED_SIGNATURE.to_owned(),
    );
    let test_result = card.decrypt_and_verify_sync(
        &provider,
        &provider.empty_private_keys(),
        &provider.empty_public_keys(),
    );

    assert!(test_result.is_err());
}

#[test]
fn test_signed_and_encrypted_card_no_decryption_keys() {
    let provider = new_pgp_provider();
    let private_key = provider
        .private_key_import(
            PRIVATE_KEY.as_bytes(),
            "password".as_bytes(),
            DataEncoding::Armor,
        )
        .unwrap();
    let verification_keys = vec![provider.private_key_to_public_key(&private_key).unwrap()];
    let decryption_keys = provider.empty_private_keys();

    let card = TestDecryptableCard(
        ContactCardType::EncryptedAndSigned,
        ENCRYPTED_AND_SIGNED_DATA.to_owned(),
        ENCRYPTED_AND_SIGNED_SIGNATURE.to_owned(),
    );
    let test_result = card.decrypt_and_verify_sync(&provider, &decryption_keys, &verification_keys);

    assert!(test_result.is_err());
}

#[test]
fn test_sign_plaintext_card() {
    let provider = new_pgp_provider();
    let private_key = provider
        .private_key_import(
            PRIVATE_KEY.as_bytes(),
            "password".as_bytes(),
            DataEncoding::Armor,
        )
        .unwrap();
    let public_key = provider.private_key_to_public_key(&private_key).unwrap();
    let verification_public_key = provider.private_key_to_public_key(&private_key).unwrap();

    let unlocked_address_key = DecryptedUserKey {
        id: KeyId("hello".to_owned()),
        private_key,
        public_key,
    };

    let card = TestEncryptableCard(SIGNED_DATA.to_owned());
    let signature = card
        .sign_sync(&provider, &unlocked_address_key)
        .expect("signing should not fail");

    TestDecryptableCard(ContactCardType::Signed, SIGNED_DATA.to_owned(), signature.0)
        .decrypt_and_verify_sync(
            &provider,
            &provider.empty_private_keys(),
            &[verification_public_key],
        )
        .expect("signature verification should not fail");
}

#[test]
fn test_encrypt_and_sign_card() {
    let provider = new_pgp_provider();
    let private_key = provider
        .private_key_import(
            PRIVATE_KEY.as_bytes(),
            "password".as_bytes(),
            DataEncoding::Armor,
        )
        .unwrap();
    let public_key = provider.private_key_to_public_key(&private_key).unwrap();
    let verification_public_key = provider.private_key_to_public_key(&private_key).unwrap();

    let unlocked_address_key = DecryptedUserKey {
        id: KeyId("hello".to_owned()),
        private_key,
        public_key,
    };

    let card = TestEncryptableCard(SIGNED_DATA.to_owned());
    let (signed_data, detached_signature) = card
        .encrypt_and_sign_sync(&provider, &unlocked_address_key)
        .expect("encrypt and sign should not fail");

    let decrypted_plaintext = TestDecryptableCard(
        ContactCardType::EncryptedAndSigned,
        signed_data.0,
        detached_signature.0,
    )
    .decrypt_and_verify_sync(
        &provider,
        &[unlocked_address_key.as_ref()],
        &[verification_public_key],
    )
    .expect("decrypting and verifying signed and encrypted card should not fail");

    assert_eq!(
        SIGNED_DATA,
        String::from_utf8(decrypted_plaintext).expect("encoding decrypted card should not fail")
    );
}
