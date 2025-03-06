use std::{
    io::{Read, Write},
    iter,
};

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
    let plaintext: Vec<u8> = iter::repeat(1).take(1024 * 1024).collect();
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
