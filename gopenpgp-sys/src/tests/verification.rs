use super::*;
use crate::PrivateKey;

const PRIVATE_KEY: &str = "-----BEGIN PGP PRIVATE KEY BLOCK-----

xX0GY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laP+HQcL
Awgr/Ssmlogji+ACZVkAJhSw8ixv8qOdigzBa/6C38y9kNF+6z8p0p7QogkBoptJ
eKSRqtw0fpcZZwpOEsKMV8PvmPFD0U8VMG9kvGMU7cKxBh8bCgAAAEIFgmOHf+MD
CwkHBRUKDggMAhYAApsDAh4JIiEGyxhsTwYJppfk1S36bHIrDB8eJ8GKVnCPZSXs
J7rZrMkFJwkCBwIAAAAArSggED4tfSJ+wObXzkRx2za/yXCDJTaQJxSYp+8FdsB/
quFFhbO5A7ASfsT9ovAjBFoux2vLT5VxqWUeFK7hE3odZoRCyI+VHjPE/9M/uaF9
UR7tdY/G2cxQy1/Xk7IDnVgEx30GY4d/4xkAAAAghpMkg2f55QFduSL49ICV3aeE
mH8tWYWxL7rRbK9eRDX+HQcLAwgr/Ssmlogji+ByP40pWjHluaiB3cUHpIU3h69K
TXWNUyIsltFCLkpnGCJk3tj8D267qpVCcJS5Q8s0dd5tyyENmsfpodQTyMzGKM2U
N8KbBhgbCgAAACwFgmOHf+MCmwwiIQbLGGxPBgmml+TVLfpscisMHx4nwYpWcI9l
JewnutmsyQAAAAAEASCm6RhtnVk1/I/lYxTNtSdIalpRIPm3YqI1pynwOQEKVlFr
ZzcAxDNINdr2MaFjPGPNVvmxwcPNOSPJFlZF1OrxTovh1r7/4q2u6HybtejZ6FJI
XJZFK5NJl7m2b8peBgY=
-----END PGP PRIVATE KEY BLOCK-----";

const PRIVATE_KEY_PASSWORD: &str = "password";

#[test]
fn test_verify_detached() {
    let test_time: u64 = 1706018465;
    let plaintext = "Hello World :)";
    let signature = "-----BEGIN PGP SIGNATURE-----

wqcGABsIAAAASAUCZa/DhyKhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6
2azJHpSAAAAAABEABGNvbnRleHRAcHJvdG9uLmNodGVzdAAAAAAQbhBZghwcBr02
75BCQl4seeJvmdGeWQKO4N0ulJLuzfa+7ShKa/e+m8Rrl6TgfMLeIL28riXcN3wx
nproj7RYMeZFcY19iwjIZNfzzY4WVcpeBA==
=8lWY
-----END PGP SIGNATURE-----
";
    let key = PrivateKey::import(
        PRIVATE_KEY.as_bytes(),
        PRIVATE_KEY_PASSWORD.as_bytes(),
        DataEncoding::Armor,
    )
    .unwrap();
    let verification_context = VerificationContext::new("test", true, 0);
    let verification_result: VerificationResult = Verifier::new()
        .with_verification_key(&key)
        .with_verification_context(&verification_context)
        .at_verification_time(test_time)
        .verify_detached(
            plaintext.as_bytes(),
            signature.as_bytes(),
            DataEncoding::Armor,
        )
        .unwrap();
    let verification_status = verification_result.status();
    assert!(matches!(verification_status, VerificationStatus::Ok));
    let signature_info = verification_result.signature_info().unwrap();

    assert!(
        signature_info.creation_time() > 0,
        "there should be a signature"
    );
    assert!(signature_info.key_id() > 0, "there should be a key id");
}

#[test]
fn test_verify_inline() {
    let test_time: u64 = 1706019172;
    let expected_plaintext = "Hello World :)";
    let message = "-----BEGIN PGP MESSAGE-----

xDYGAAgbEL06kU9nTY1Qg5b8owGd/QrLGGxPBgmml+TVLfpscisMHx4nwYpWcI9l
JewnutmsyQHLFGIAAAAAAEhlbGxvIFdvcmxkIDopwqcGABsIAAAASAUCZa/JYyKh
BssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce62azJHpSAAAAAABEABGNvbnRl
eHRAcHJvdG9uLmNodGVzdAAAAACgvRC9OpFPZ02NUIOW/KMBnf0KbJ78+unDUfIm
OhGu7RUhA7l5j1hXz7nR8lGsXKdA6edwcW7iTL1XbqEOeA5qXA7itU99Mytu5j9M
FCoLfOuDAA==
-----END PGP MESSAGE-----
";
    let key = PrivateKey::import(
        PRIVATE_KEY.as_bytes(),
        PRIVATE_KEY_PASSWORD.as_bytes(),
        DataEncoding::Armor,
    )
    .unwrap();
    let verification_context = VerificationContext::new("test", true, 0);
    let result: VerifiedData = Verifier::new()
        .with_verification_key(&key)
        .with_verification_context(&verification_context)
        .at_verification_time(test_time)
        .verify_inline(message.as_bytes(), DataEncoding::Armor)
        .unwrap();
    assert_eq!(result.as_bytes(), expected_plaintext.as_bytes());
    let verification_result = result.verification_result().unwrap();
    let verification_status = verification_result.status();
    assert!(matches!(verification_status, VerificationStatus::Ok));
    let signature_info = verification_result.signature_info().unwrap();

    assert!(
        signature_info.creation_time() > 0,
        "there should be a signature"
    );
    assert!(signature_info.key_id() > 0, "there should be a key id");
}

#[test]
fn test_verify_cleartext() {
    let test_time: u64 = 1706020327;
    let expected_plaintext = "Hello World :)";
    let message = "-----BEGIN PGP SIGNED MESSAGE-----

Hello World :)
-----BEGIN PGP SIGNATURE-----

wogGARsIAAAAKQUCZa/JYyKhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6
2azJAAAAAA6DEPh3utfrfUTAtd2whIsNPjdI1nZ/RGekkTFsSmuojvobUqT41jHc
qH+18lbt07G4TaKHio0k3ZeISm5Yej5h42Lh4SfVq65l0vVa/40XmNII
-----END PGP SIGNATURE-----
";
    let key = PrivateKey::import(
        PRIVATE_KEY.as_bytes(),
        PRIVATE_KEY_PASSWORD.as_bytes(),
        DataEncoding::Armor,
    )
    .unwrap();
    let result: VerifiedData = Verifier::new()
        .with_verification_key(&key)
        .at_verification_time(test_time)
        .verify_cleartext(message.as_bytes())
        .unwrap();
    assert_eq!(result.as_bytes(), expected_plaintext.as_bytes());
    let verification_result: &VerificationResult = result.verification_result().unwrap();
    let verification_status = verification_result.status();
    assert!(matches!(verification_status, VerificationStatus::Ok));
    let signature_info = verification_result.signature_info().unwrap();

    assert!(
        signature_info.creation_time() > 0,
        "there should be a signature"
    );
    assert!(signature_info.key_id() > 0, "there should be a key id");
}

#[test]
fn test_verify_detached_stream() {
    let test_time: u64 = 1706018465;
    let plaintext = "Hello World :)";
    let signature = "-----BEGIN PGP SIGNATURE-----

wqcGABsIAAAASAUCZa/DhyKhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6
2azJHpSAAAAAABEABGNvbnRleHRAcHJvdG9uLmNodGVzdAAAAAAQbhBZghwcBr02
75BCQl4seeJvmdGeWQKO4N0ulJLuzfa+7ShKa/e+m8Rrl6TgfMLeIL28riXcN3wx
nproj7RYMeZFcY19iwjIZNfzzY4WVcpeBA==
=8lWY
-----END PGP SIGNATURE-----
";
    let key = PrivateKey::import(
        PRIVATE_KEY.as_bytes(),
        PRIVATE_KEY_PASSWORD.as_bytes(),
        DataEncoding::Armor,
    )
    .unwrap();
    let verification_context: VerificationContext = VerificationContext::new("test", true, 0);
    let reader = Box::new(plaintext.as_bytes());
    let verification_result: VerificationResult = Verifier::new()
        .with_verification_key(&key)
        .with_verification_context(&verification_context)
        .at_verification_time(test_time)
        .verify_detached_stream(reader, signature.as_bytes(), DataEncoding::Armor)
        .unwrap();
    let verification_status = verification_result.status();
    assert!(matches!(verification_status, VerificationStatus::Ok));
    let signature_info = verification_result.signature_info().unwrap();

    assert!(
        signature_info.creation_time() > 0,
        "there should be a signature"
    );
    assert!(signature_info.key_id() > 0, "there should be a key id");
}
