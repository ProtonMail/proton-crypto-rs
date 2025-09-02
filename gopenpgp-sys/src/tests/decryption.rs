use std::io::Read;

use super::*;
use crate::{PrivateKey, SessionKeyAlgorithm, VerificationStatus};

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
fn test_decrypt_password() {
    let password = "password";
    let expected_plaintext = "Hello, world!";
    let message = "-----BEGIN PGP MESSAGE-----

wzwGGgcDCwMI6dOXhbIHAAj/tC58SD70iERXyzcmubPbn/d25fTZpAlS4kRymIUa
v/91Jt8t1VRBdXmneZ/SaQIHAwb8uUSQvLmLvcnRBsYJAmaUD3LontwhtVlrFXax
Ae0Pn/xvxtZbv9JNzQeQlm5tHoWjAFN4TLHYtqBpnvEhVaeyrWJYUxtXZR/Xd3kS
+pXjXZtAIW9ppMJI2yj/QzHxYykHOZ5v+Q==
-----END PGP MESSAGE-----
";
    let result: VerifiedData = Decryptor::new()
        .with_passphrase(password)
        .decrypt(message.as_bytes(), DataEncoding::Armor)
        .unwrap();
    assert_eq!(result.as_bytes(), expected_plaintext.as_bytes())
}

#[test]
fn test_decrypt_session_key() {
    let session_key =
        hex::decode("7E0CE7CEF3C4373B9391BB016ECDD36945328A0D86C54FF359FA3F13D0655CCA").unwrap();
    let expected_plaintext = "Hello World :)";
    let message = "-----BEGIN PGP MESSAGE-----

wVQDEsg/HnBvYwgZINpK4GxzTNMazRr6yBqAGyFJQHRxYTt7NJfwydUouQgpCfgD
mbpnZOeEG02cJmlfk9v8v7jK+IKsL1mSmtVRrMH+fRb32/O87GrSPwGm+ZZV/vQV
0C/XmMDQwijPPKNILpBIREqvwvxvkBifhPPP1uI+JVSJtCTKkf4ee2zCYZV4inJt
KNvdUjAExQ==
-----END PGP MESSAGE-----
";
    let session_key = SessionKey::from_token(session_key.as_slice(), SessionKeyAlgorithm::Aes256);
    let result: VerifiedData = Decryptor::new()
        .with_session_key(&session_key)
        .decrypt(message.as_bytes(), DataEncoding::Armor)
        .unwrap();
    assert_eq!(result.as_bytes(), expected_plaintext.as_bytes())
}

#[test]
fn test_decrypt_asymmetric_and_verify_signature() {
    let test_time: u64 = 1705997506;
    let expected_plaintext = "Hello World :)";
    let message = "-----BEGIN PGP MESSAGE-----

wW0GIQYSyD8ecG9jCP4VGkF3Q6HwM3kOk+mXhIjR2zeNqZMIhRl6yIEDumXwlQsJ
YrLksFPugM3ByG52mbo1fOpj3s1/QyjV/emxE0uQhRb2A6/SKUUr4YmD9rdPG1Kj
YH1NXJdKHYG+ZPVUOLeV0sCfAgkCDNkBquPxWTU0eiAWDaAPvP2Tl1i6/iX9n5IO
LUSBbdZ3UsCFxWq5U6dOcdFMj6ctllTit6ks4KrGlBdw0tdI3VWuetUH06lAoF5z
1hcKwkdn0RxzBhparDbawpSr4+kMVHqiPaWJxQ5o3/wOVOVW6HeuvfPpZVgFYisu
MwVGXl8E+L+vh7BIw3kz458eC9/oOjW5Pdf3d+QnLLf/xKdavPNqOG2TFiE1C2lA
d4dBkf7zwBIDUC5pFDocaCWMkKL4yH31Ni4S9/XP7Z4KQXQ3QBQYNxYUwcSuzOQI
pk4IxzNK9FLKGG0rak+x0g/g4acXWjhjpIgR+McMGAQAi7RlMFBzQWeVcejUnOlv
bBbI7KaJnDPEjaNQaWKHjEFE4jU2wHW1Mb1HZqYGKeYMb8HnlY5u04peyFpjJHHX
TSkt0PzJOy9X3DTvGrAynfANSZg3a6DQfEIGtUxkRDd+
-----END PGP MESSAGE-----
";
    let key = PrivateKey::import(
        PRIVATE_KEY.as_bytes(),
        PRIVATE_KEY_PASSWORD.as_bytes(),
        DataEncoding::Armor,
    )
    .unwrap();
    let verification_context = VerificationContext::new("test", true, 0);
    let result: VerifiedData = Decryptor::new()
        .with_decryption_key(&key)
        .with_verification_key(&key)
        .with_verification_context(&verification_context)
        .at_verification_time(test_time)
        .decrypt(message.as_bytes(), DataEncoding::Armor)
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
fn test_decrypt_asymmetric_and_verify_detached_signature() {
    let test_time: u64 = 1706018465;
    let expected_plaintext = "Hello World :)";
    let detached_signature = "-----BEGIN PGP SIGNATURE-----

wqcGABsIAAAASAUCZa/DhyKhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6
2azJHpSAAAAAABEABGNvbnRleHRAcHJvdG9uLmNodGVzdAAAAAAQbhBZghwcBr02
75BCQl4seeJvmdGeWQKO4N0ulJLuzfa+7ShKa/e+m8Rrl6TgfMLeIL28riXcN3wx
nproj7RYMeZFcY19iwjIZNfzzY4WVcpeBA==
=8lWY
-----END PGP SIGNATURE-----
";
    let message = "-----BEGIN PGP MESSAGE-----

wVQDEsg/HnBvYwgZINpK4GxzTNMazRr6yBqAGyFJQHRxYTt7NJfwydUouQgpCfgD
mbpnZOeEG02cJmlfk9v8v7jK+IKsL1mSmtVRrMH+fRb32/O87GrSPwGm+ZZV/vQV
0C/XmMDQwijPPKNILpBIREqvwvxvkBifhPPP1uI+JVSJtCTKkf4ee2zCYZV4inJt
KNvdUjAExQ==
-----END PGP MESSAGE-----";
    let key = PrivateKey::import(
        PRIVATE_KEY.as_bytes(),
        PRIVATE_KEY_PASSWORD.as_bytes(),
        DataEncoding::Armor,
    )
    .unwrap();
    let verification_context: VerificationContext = VerificationContext::new("test", true, 0);
    let result: VerifiedData = Decryptor::new()
        .with_decryption_key(&key)
        .with_verification_key(&key)
        .with_verification_context(&verification_context)
        .with_detached_signature_ref(detached_signature.as_bytes(), false, true)
        .at_verification_time(test_time)
        .decrypt(message.as_bytes(), DataEncoding::Armor)
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
fn test_decrypt_password_stream() {
    let password = "password";
    let expected_plaintext = "Hello, world!";
    let message = "-----BEGIN PGP MESSAGE-----

wzwGGgcDCwMI6dOXhbIHAAj/tC58SD70iERXyzcmubPbn/d25fTZpAlS4kRymIUa
v/91Jt8t1VRBdXmneZ/SaQIHAwb8uUSQvLmLvcnRBsYJAmaUD3LontwhtVlrFXax
Ae0Pn/xvxtZbv9JNzQeQlm5tHoWjAFN4TLHYtqBpnvEhVaeyrWJYUxtXZR/Xd3kS
+pXjXZtAIW9ppMJI2yj/QzHxYykHOZ5v+Q==
-----END PGP MESSAGE-----
";
    let mut result = Decryptor::new()
        .with_passphrase(password)
        .decrypt_stream(message.as_bytes(), DataEncoding::Armor)
        .unwrap();
    let mut buffer = Vec::with_capacity(expected_plaintext.len());
    result.read_to_end(&mut buffer).unwrap();
    assert_eq!(buffer.as_slice(), expected_plaintext.as_bytes())
}

#[test]
fn test_decrypt_asymmetric_and_verify_signature_stream() {
    let test_time: u64 = 1705997506;
    let expected_plaintext = "Hello World :)";
    let message = "-----BEGIN PGP MESSAGE-----

wW0GIQYSyD8ecG9jCP4VGkF3Q6HwM3kOk+mXhIjR2zeNqZMIhRl6yIEDumXwlQsJ
YrLksFPugM3ByG52mbo1fOpj3s1/QyjV/emxE0uQhRb2A6/SKUUr4YmD9rdPG1Kj
YH1NXJdKHYG+ZPVUOLeV0sCfAgkCDNkBquPxWTU0eiAWDaAPvP2Tl1i6/iX9n5IO
LUSBbdZ3UsCFxWq5U6dOcdFMj6ctllTit6ks4KrGlBdw0tdI3VWuetUH06lAoF5z
1hcKwkdn0RxzBhparDbawpSr4+kMVHqiPaWJxQ5o3/wOVOVW6HeuvfPpZVgFYisu
MwVGXl8E+L+vh7BIw3kz458eC9/oOjW5Pdf3d+QnLLf/xKdavPNqOG2TFiE1C2lA
d4dBkf7zwBIDUC5pFDocaCWMkKL4yH31Ni4S9/XP7Z4KQXQ3QBQYNxYUwcSuzOQI
pk4IxzNK9FLKGG0rak+x0g/g4acXWjhjpIgR+McMGAQAi7RlMFBzQWeVcejUnOlv
bBbI7KaJnDPEjaNQaWKHjEFE4jU2wHW1Mb1HZqYGKeYMb8HnlY5u04peyFpjJHHX
TSkt0PzJOy9X3DTvGrAynfANSZg3a6DQfEIGtUxkRDd+
-----END PGP MESSAGE-----
";
    let key = PrivateKey::import(
        PRIVATE_KEY.as_bytes(),
        PRIVATE_KEY_PASSWORD.as_bytes(),
        DataEncoding::Armor,
    )
    .unwrap();
    let verification_context = VerificationContext::new("test", true, 0);
    let mut result = Decryptor::new()
        .with_decryption_key(&key)
        .with_verification_key(&key)
        .with_verification_context(&verification_context)
        .at_verification_time(test_time)
        .decrypt_stream(message.as_bytes(), DataEncoding::Armor)
        .unwrap();
    let mut buffer = Vec::with_capacity(expected_plaintext.len());
    result.read_to_end(&mut buffer).unwrap();
    assert_eq!(buffer.as_slice(), expected_plaintext.as_bytes());
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
fn test_decrypt_asymmetric_and_verify_detached_signature_stream() {
    let test_time: u64 = 1706018465;
    let expected_plaintext = "Hello World :)";
    let detached_signature = "-----BEGIN PGP SIGNATURE-----

wqcGABsIAAAASAUCZa/DhyKhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6
2azJHpSAAAAAABEABGNvbnRleHRAcHJvdG9uLmNodGVzdAAAAAAQbhBZghwcBr02
75BCQl4seeJvmdGeWQKO4N0ulJLuzfa+7ShKa/e+m8Rrl6TgfMLeIL28riXcN3wx
nproj7RYMeZFcY19iwjIZNfzzY4WVcpeBA==
=8lWY
-----END PGP SIGNATURE-----
";
    let message = "-----BEGIN PGP MESSAGE-----

wVQDEsg/HnBvYwgZINpK4GxzTNMazRr6yBqAGyFJQHRxYTt7NJfwydUouQgpCfgD
mbpnZOeEG02cJmlfk9v8v7jK+IKsL1mSmtVRrMH+fRb32/O87GrSPwGm+ZZV/vQV
0C/XmMDQwijPPKNILpBIREqvwvxvkBifhPPP1uI+JVSJtCTKkf4ee2zCYZV4inJt
KNvdUjAExQ==
-----END PGP MESSAGE-----";
    let key = PrivateKey::import(
        PRIVATE_KEY.as_bytes(),
        PRIVATE_KEY_PASSWORD.as_bytes(),
        DataEncoding::Armor,
    )
    .unwrap();
    let verification_context = VerificationContext::new("test", true, 0);
    let mut result = Decryptor::new()
        .with_decryption_key(&key)
        .with_verification_key(&key)
        .with_verification_context(&verification_context)
        .at_verification_time(test_time)
        .with_detached_signature_ref(detached_signature.as_bytes(), false, true)
        .decrypt_stream(message.as_bytes(), DataEncoding::Armor)
        .unwrap();
    let mut buffer = Vec::with_capacity(expected_plaintext.len());
    result.read_to_end(&mut buffer).unwrap();
    assert_eq!(buffer.as_slice(), expected_plaintext.as_bytes());
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
