use std::io::{Read, Write};

use crate::{
    DataEncoding, Decryptor, PrivateKey, SessionKeyAlgorithm, VerificationContext,
    VerificationStatus, VerifiedData,
};

use super::*;

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

const PQC_PRIVATE_KEY: &str = "-----BEGIN PGP PRIVATE KEY BLOCK-----

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
-----END PGP PRIVATE KEY BLOCK-----";

#[test]
fn test_encrypt_password() {
    let password = "password";
    let plaintext = "Hello, world!";
    let result: PGPMessage = Encryptor::new()
        .with_passphrase(password)
        .encrypt(plaintext.as_bytes())
        .unwrap();
    let armored: Vec<u8> = result.armored().unwrap();
    let bytes = result.as_ref();
    let kp = result.key_packet();
    let dp = result.data_packet();
    assert!(!kp.is_empty());
    assert!(!dp.is_empty());
    assert!(!armored.is_empty());
    assert!(!bytes.is_empty());

    let decrypted_pt = Decryptor::new()
        .with_passphrase(password)
        .decrypt(bytes, DataEncoding::Bytes)
        .unwrap();
    assert_eq!(plaintext.as_bytes(), decrypted_pt.as_bytes())
}

#[test]
fn test_encrypt_session_key() {
    let session_key =
        hex::decode("7E0CE7CEF3C4373B9391BB016ECDD36945328A0D86C54FF359FA3F13D0655CCA").unwrap();
    let plaintext = "Hello World :)";
    let session_key = SessionKey::from_token(&session_key, SessionKeyAlgorithm::Aes256);

    let pgp_message: PGPMessage = Encryptor::new()
        .with_session_key(&session_key)
        .encrypt(plaintext.as_bytes())
        .unwrap();

    let result: VerifiedData = Decryptor::new()
        .with_session_key(&session_key)
        .decrypt(pgp_message.as_ref(), DataEncoding::Bytes)
        .unwrap();
    assert_eq!(result.as_bytes(), plaintext.as_bytes())
}

#[test]
fn test_encrypt_session_key_large() {
    let session_key =
        hex::decode("7E0CE7CEF3C4373B9391BB016ECDD36945328A0D86C54FF359FA3F13D0655CCA").unwrap();
    // 1 MB encryption
    let plaintext: Vec<u8> = std::iter::repeat_n(1, 1024 * 1024).collect();
    let session_key = SessionKey::from_token(&session_key, SessionKeyAlgorithm::Aes256);

    let pgp_message: PGPMessage = Encryptor::new()
        .with_session_key(&session_key)
        .encrypt(&plaintext)
        .unwrap();

    let result: VerifiedData = Decryptor::new()
        .with_session_key(&session_key)
        .decrypt(pgp_message.as_ref(), DataEncoding::Bytes)
        .unwrap();
    assert_eq!(result.as_bytes(), &plaintext)
}

#[test]
fn test_encrypt_asymmetric_with_signature() {
    let test_time: u64 = 1705997506;
    let plaintext = "Hello World :)";

    let key = PrivateKey::import(
        PRIVATE_KEY.as_bytes(),
        PRIVATE_KEY_PASSWORD.as_bytes(),
        DataEncoding::Armor,
    )
    .unwrap();
    let signing_context = SigningContext::new("test", true);

    let pgp_message: PGPMessage = Encryptor::new()
        .with_encryption_key(&key)
        .with_signing_key(&key)
        .with_signing_context(&signing_context)
        .at_signing_time(test_time - 1)
        .encrypt(plaintext.as_bytes())
        .unwrap();

    let armored: Vec<u8> = pgp_message.armored().unwrap();
    let bytes = pgp_message.as_ref();
    let kp = pgp_message.key_packet();
    let dp = pgp_message.data_packet();
    assert!(!kp.is_empty());
    assert!(!dp.is_empty());
    assert!(!armored.is_empty());
    assert!(!bytes.is_empty());
    let enc_key_ids = pgp_message.encryption_key_ids().unwrap();
    assert!(enc_key_ids.as_ref().len() == 1);

    let verification_context = VerificationContext::new("test", true, 0);
    let result: VerifiedData = Decryptor::new()
        .with_decryption_key(&key)
        .with_verification_key(&key)
        .with_verification_context(&verification_context)
        .at_verification_time(test_time)
        .decrypt(pgp_message.as_ref(), DataEncoding::Bytes)
        .unwrap();
    assert_eq!(result.as_bytes(), plaintext.as_bytes());
    let verification_result = result.verification_result().unwrap();
    let verification_status = verification_result.status();
    assert!(matches!(verification_status, VerificationStatus::Ok));
}

#[test]
fn test_encrypt_asymmetric_raw_with_signature() {
    let test_time: u64 = 1705997506;
    let plaintext = "Hello World :)";

    let key = PrivateKey::import(
        PRIVATE_KEY.as_bytes(),
        PRIVATE_KEY_PASSWORD.as_bytes(),
        DataEncoding::Armor,
    )
    .unwrap();
    let signing_context = SigningContext::new("test", true);

    for encoding in [DataEncoding::Bytes, DataEncoding::Armor] {
        let raw_pgp_message = Encryptor::new()
            .with_encryption_key(&key)
            .with_signing_key(&key)
            .with_signing_context(&signing_context)
            .at_signing_time(test_time - 1)
            .encrypt_raw(plaintext.as_bytes(), encoding)
            .unwrap();
        let verification_context = VerificationContext::new("test", true, 0);
        let result: VerifiedData = Decryptor::new()
            .with_decryption_key(&key)
            .with_verification_key(&key)
            .with_verification_context(&verification_context)
            .at_verification_time(test_time)
            .decrypt(raw_pgp_message.as_ref(), encoding)
            .unwrap();
        assert_eq!(result.as_bytes(), plaintext.as_bytes());
        let verification_result = result.verification_result().unwrap();
        let verification_status = verification_result.status();
        assert!(matches!(verification_status, VerificationStatus::Ok));
    }
}

#[test]
fn test_pqc_encrypt_asymmetric_raw_with_signature() {
    let test_time: u64 = 1748263786;
    let plaintext = "Hello World :)";

    let key = PrivateKey::import_unlocked(PQC_PRIVATE_KEY.as_bytes(), DataEncoding::Armor).unwrap();
    let signing_context = SigningContext::new("pqc-test", true);

    for encoding in [DataEncoding::Bytes, DataEncoding::Armor] {
        let raw_pgp_message = Encryptor::new()
            .with_encryption_key(&key)
            .with_signing_key(&key)
            .with_signing_context(&signing_context)
            .at_signing_time(test_time - 1)
            .encrypt_raw(plaintext.as_bytes(), encoding)
            .unwrap();
        let verification_context = VerificationContext::new("pqc-test", true, 0);
        let result: VerifiedData = Decryptor::new()
            .with_decryption_key(&key)
            .with_verification_key(&key)
            .with_verification_context(&verification_context)
            .at_verification_time(test_time)
            .decrypt(raw_pgp_message.as_ref(), encoding)
            .unwrap();
        assert_eq!(result.as_bytes(), plaintext.as_bytes());
        let verification_result = result.verification_result().unwrap();
        let verification_status = verification_result.status();
        assert!(matches!(verification_status, VerificationStatus::Ok));
    }
}

#[test]
fn test_encrypt_asymmetric_raw_with_detached_signature() {
    let test_time: u64 = 1705997506;
    let plaintext = "Hello World :)";

    let key = PrivateKey::import(
        PRIVATE_KEY.as_bytes(),
        PRIVATE_KEY_PASSWORD.as_bytes(),
        DataEncoding::Armor,
    )
    .unwrap();
    let signing_context = SigningContext::new("test", true);

    for encoding in [DataEncoding::Bytes, DataEncoding::Armor] {
        for encrypt_detached in [false, true] {
            let (raw_pgp_message, raw_sig_message) = Encryptor::new()
                .with_encryption_key(&key)
                .with_signing_key(&key)
                .with_signing_context(&signing_context)
                .at_signing_time(test_time - 1)
                .encrypt_raw_with_detached_signature(
                    plaintext.as_bytes(),
                    encrypt_detached,
                    encoding,
                )
                .unwrap();
            let verification_context = VerificationContext::new("test", true, 0);
            let result: VerifiedData = Decryptor::new()
                .with_decryption_key(&key)
                .with_verification_key(&key)
                .with_verification_context(&verification_context)
                .at_verification_time(test_time)
                .with_detached_signature(
                    raw_sig_message,
                    encrypt_detached,
                    encoding == DataEncoding::Armor,
                )
                .decrypt(raw_pgp_message.as_ref(), encoding)
                .unwrap();
            assert_eq!(result.as_bytes(), plaintext.as_bytes());
            let verification_result = result.verification_result().unwrap();
            let verification_status = verification_result.status();
            assert!(matches!(verification_status, VerificationStatus::Ok));
        }
    }
}

#[test]
fn test_encrypt_password_stream() {
    let password = "password";
    let plaintext = "Hello, world!";
    for encoding in [DataEncoding::Bytes, DataEncoding::Armor] {
        let mut buffer = Vec::with_capacity(plaintext.len());
        {
            let mut pt_writer = Encryptor::new()
                .with_passphrase(password)
                .encrypt_stream(&mut buffer, encoding)
                .unwrap();
            pt_writer.write_all(plaintext.as_bytes()).unwrap();
            pt_writer.close().unwrap();
        }
        let mut result = Decryptor::new()
            .with_passphrase(password)
            .decrypt_stream(buffer.as_slice(), encoding)
            .unwrap();
        let mut out = Vec::with_capacity(plaintext.len());
        result.read_to_end(&mut out).unwrap();
        assert_eq!(out.as_slice(), plaintext.as_bytes())
    }
}

#[test]
fn test_encrypt_session_key_stream() {
    let session_key =
        hex::decode("7E0CE7CEF3C4373B9391BB016ECDD36945328A0D86C54FF359FA3F13D0655CCA").unwrap();
    let plaintext = "Hello World :)";
    let session_key = SessionKey::from_token(&session_key, SessionKeyAlgorithm::Aes256);
    for encoding in [DataEncoding::Bytes, DataEncoding::Armor] {
        let mut buffer = Vec::with_capacity(plaintext.len());
        {
            let mut pt_writer = Encryptor::new()
                .with_session_key(&session_key)
                .encrypt_stream(&mut buffer, encoding)
                .unwrap();
            pt_writer.write_all(plaintext.as_bytes()).unwrap();
            pt_writer.close().unwrap();
        }
        let mut result = Decryptor::new()
            .with_session_key(&session_key)
            .decrypt_stream(buffer.as_slice(), encoding)
            .unwrap();
        let mut out = Vec::with_capacity(plaintext.len());
        result.read_to_end(&mut out).unwrap();
        assert_eq!(out.as_slice(), plaintext.as_bytes())
    }
}

#[test]
fn test_encrypt_asymmetric_stream() {
    let test_time: u64 = 1705997506;
    let plaintext = "Hello World :)";

    let key = PrivateKey::import(
        PRIVATE_KEY.as_bytes(),
        PRIVATE_KEY_PASSWORD.as_bytes(),
        DataEncoding::Armor,
    )
    .unwrap();
    for encoding in [DataEncoding::Bytes, DataEncoding::Armor] {
        let signing_context = SigningContext::new("test", true);
        let mut buffer: Vec<u8> = Vec::with_capacity(plaintext.len());
        {
            let mut pt_writer = Encryptor::new()
                .with_encryption_key(&key)
                .with_signing_key(&key)
                .with_signing_context(&signing_context)
                .at_signing_time(test_time - 1)
                .encrypt_stream(&mut buffer, encoding)
                .unwrap();
            pt_writer.write_all(plaintext.as_bytes()).unwrap();
            pt_writer.close().unwrap();
        }
        let verification_context = VerificationContext::new("test", true, 0);
        let mut result = Decryptor::new()
            .with_decryption_key(&key)
            .with_verification_key(&key)
            .with_verification_context(&verification_context)
            .at_verification_time(test_time)
            .decrypt_stream(buffer.as_slice(), encoding)
            .unwrap();
        let mut out = Vec::with_capacity(plaintext.len());
        result.read_to_end(&mut out).unwrap();
        assert_eq!(out.as_slice(), plaintext.as_bytes());
        let verification_result = result.verification_result().unwrap();
        let verification_status = verification_result.status();
        assert!(matches!(verification_status, VerificationStatus::Ok));
    }
}

#[test]
fn test_encrypt_asymmetric_stream_with_detached_signature() {
    let test_time: u64 = 1705997506;
    let plaintext = "Hello World :)";

    let key = PrivateKey::import(
        PRIVATE_KEY.as_bytes(),
        PRIVATE_KEY_PASSWORD.as_bytes(),
        DataEncoding::Armor,
    )
    .unwrap();
    for encoding in [DataEncoding::Bytes, DataEncoding::Armor] {
        for encrypt_detached in [false, true] {
            let signing_context = SigningContext::new("test", true);
            let mut buffer: Vec<u8> = Vec::with_capacity(plaintext.len());
            let detached_signature = {
                let mut pt_writer = Encryptor::new()
                    .with_encryption_key(&key)
                    .with_signing_key(&key)
                    .with_signing_context(&signing_context)
                    .at_signing_time(test_time - 1)
                    .encrypt_stream_with_detached_signature(&mut buffer, encrypt_detached, encoding)
                    .unwrap();
                pt_writer.write_all(plaintext.as_bytes()).unwrap();
                pt_writer.close().unwrap();
                pt_writer.take_detached_signature()
            };
            let verification_context = VerificationContext::new("test", true, 0);
            let mut result = Decryptor::new()
                .with_decryption_key(&key)
                .with_verification_key(&key)
                .with_verification_context(&verification_context)
                .at_verification_time(test_time)
                .with_detached_signature(
                    detached_signature,
                    encrypt_detached,
                    encoding == DataEncoding::Armor,
                )
                .decrypt_stream(buffer.as_slice(), encoding)
                .unwrap();
            let mut out = Vec::with_capacity(plaintext.len());
            result.read_to_end(&mut out).unwrap();
            assert_eq!(out.as_slice(), plaintext.as_bytes());
            let verification_result = result.verification_result().unwrap();
            let verification_status = verification_result.status();
            assert!(matches!(verification_status, VerificationStatus::Ok));
        }
    }
}

#[test]
fn test_encrypt_session_key_with_pgp_key() {
    let session_key_token =
        hex::decode("7E0CE7CEF3C4373B9391BB016ECDD36945328A0D86C54FF359FA3F13D0655CCA").unwrap();
    let session_key = SessionKey::from_token(&session_key_token, SessionKeyAlgorithm::Aes256);
    let key = PrivateKey::import(
        PRIVATE_KEY.as_bytes(),
        PRIVATE_KEY_PASSWORD.as_bytes(),
        DataEncoding::Armor,
    )
    .unwrap();
    let key_packets = Encryptor::new()
        .with_encryption_key(&key)
        .encrypt_session_key(&session_key)
        .unwrap();
    let decrypted_session_key = Decryptor::new()
        .with_decryption_key(&key)
        .decrypt_session_key(&key_packets)
        .unwrap();
    assert_eq!(
        decrypted_session_key.export_token().as_ref(),
        &session_key_token
    )
}

#[test]
fn test_encrypt_password_stream_split() {
    let password = "password";
    let plaintext = "Hello, world!";
    let mut buffer = Vec::with_capacity(plaintext.len());
    let mut key_packets = {
        let (key_packets, mut pt_writer) = Encryptor::new()
            .with_passphrase(password)
            .encrypt_stream_split(&mut buffer)
            .unwrap();
        pt_writer.write_all(plaintext.as_bytes()).unwrap();
        pt_writer.close().unwrap();
        key_packets
    };
    assert!(!key_packets.is_empty());
    key_packets.extend(buffer.iter());
    let mut result = Decryptor::new()
        .with_passphrase(password)
        .decrypt_stream(key_packets.as_slice(), DataEncoding::Bytes)
        .unwrap();
    let mut out = Vec::with_capacity(plaintext.len());
    result.read_to_end(&mut out).unwrap();
    assert_eq!(out.as_slice(), plaintext.as_bytes())
}

#[test]
fn test_encrypt_asymmetric_stream_split() {
    let plaintext = "Hello World :)";

    let key = PrivateKey::import(
        PRIVATE_KEY.as_bytes(),
        PRIVATE_KEY_PASSWORD.as_bytes(),
        DataEncoding::Armor,
    )
    .unwrap();
    let mut buffer: Vec<u8> = Vec::with_capacity(plaintext.len());
    let mut key_packets = {
        let (key_packets, mut pt_writer) = Encryptor::new()
            .with_encryption_key(&key)
            .encrypt_stream_split(&mut buffer)
            .unwrap();
        pt_writer.write_all(plaintext.as_bytes()).unwrap();
        pt_writer.close().unwrap();
        key_packets
    };
    assert!(!key_packets.is_empty());
    key_packets.extend(buffer.iter());
    let result = Decryptor::new()
        .with_decryption_key(&key)
        .decrypt(key_packets.as_slice(), DataEncoding::Bytes)
        .unwrap();
    assert_eq!(result.as_bytes(), plaintext.as_bytes());
}

#[test]
fn test_encrypt_asymmetric_stream_split_with_detached_signature() {
    let plaintext = "Hello World :)";

    let key = PrivateKey::import(
        PRIVATE_KEY.as_bytes(),
        PRIVATE_KEY_PASSWORD.as_bytes(),
        DataEncoding::Armor,
    )
    .unwrap();
    for encrypt_detached in [false, true] {
        let mut buffer: Vec<u8> = Vec::with_capacity(plaintext.len());
        let (mut key_packets, detached_signature) = {
            let (key_packets, mut pt_writer) = Encryptor::new()
                .with_encryption_key(&key)
                .with_signing_key(&key)
                .encrypt_stream_split_with_detached_signature(&mut buffer, encrypt_detached)
                .unwrap();
            pt_writer.write_all(plaintext.as_bytes()).unwrap();
            pt_writer.close().unwrap();
            (key_packets, pt_writer.take_detached_signature())
        };
        assert!(!key_packets.is_empty());
        assert!(!detached_signature.is_empty());
        let mut full_sig = key_packets.clone();
        full_sig.extend(detached_signature.iter());
        key_packets.extend(buffer.iter());
        let result = Decryptor::new()
            .with_decryption_key(&key)
            .with_verification_key(&key)
            .with_detached_signature(full_sig, encrypt_detached, false)
            .decrypt(key_packets.as_slice(), DataEncoding::Bytes)
            .unwrap();
        assert_eq!(result.as_bytes(), plaintext.as_bytes());
        let verification_result = result.verification_result().unwrap();
        let verification_status = verification_result.status();
        assert!(matches!(verification_status, VerificationStatus::Ok));
    }
}
