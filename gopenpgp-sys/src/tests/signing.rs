use std::io::{Read, Write};

use super::*;
use crate::{
    PrivateKey, VerificationContext, VerificationResult, VerificationStatus, VerifiedData, Verifier,
};

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
fn test_sign_detached() {
    let test_time: u64 = 1706018465;
    let plaintext = "Hello World :)";
    let key = PrivateKey::import(
        PRIVATE_KEY.as_bytes(),
        PRIVATE_KEY_PASSWORD.as_bytes(),
        DataEncoding::Armor,
    )
    .unwrap();

    let signing_context = SigningContext::new("test", true);
    let signature: Vec<u8> = Signer::new()
        .with_signing_key(&key)
        .with_signing_context(&signing_context)
        .at_signing_time(test_time - 1)
        .sign(plaintext.as_bytes(), true, DataEncoding::Armor)
        .unwrap();

    let verification_context = VerificationContext::new("test", true, 0);
    let verification_result: VerificationResult = Verifier::new()
        .with_verification_key(&key)
        .with_verification_context(&verification_context)
        .at_verification_time(test_time)
        .verify_detached(
            plaintext.as_bytes(),
            signature.as_slice(),
            DataEncoding::Armor,
        )
        .unwrap();
    let verification_status = verification_result.status();
    assert!(matches!(verification_status, VerificationStatus::Ok));
}

#[test]
fn test_sign_inline() {
    let test_time: u64 = 1706018465;

    let plaintext = "Hello World :)";
    let key = PrivateKey::import(
        PRIVATE_KEY.as_bytes(),
        PRIVATE_KEY_PASSWORD.as_bytes(),
        DataEncoding::Armor,
    )
    .unwrap();

    let signing_context = SigningContext::new("test", true);
    let message: Vec<u8> = Signer::new()
        .with_signing_key(&key)
        .with_signing_context(&signing_context)
        .at_signing_time(test_time - 1)
        .sign(plaintext.as_bytes(), false, DataEncoding::Armor)
        .unwrap();

    let verification_context = VerificationContext::new("test", true, 0);
    let verification_result: VerifiedData = Verifier::new()
        .with_verification_key(&key)
        .with_verification_context(&verification_context)
        .at_verification_time(test_time)
        .verify_inline(message.as_slice(), DataEncoding::Armor)
        .unwrap();
    let verification_status = verification_result.verification_result().unwrap().status();
    assert!(matches!(verification_status, VerificationStatus::Ok));
}

#[test]
fn test_sign_cleartext() {
    let test_time: u64 = 1706018465;

    let plaintext = "Hello World :)";
    let key = PrivateKey::import(
        PRIVATE_KEY.as_bytes(),
        PRIVATE_KEY_PASSWORD.as_bytes(),
        DataEncoding::Armor,
    )
    .unwrap();

    let message: Vec<u8> = Signer::new()
        .with_signing_key(&key)
        .at_signing_time(test_time - 1)
        .sign_cleartext(plaintext.as_bytes())
        .unwrap();

    let verification_result: VerifiedData = Verifier::new()
        .with_verification_key(&key)
        .at_verification_time(test_time)
        .verify_cleartext(message.as_slice())
        .unwrap();
    let verification_status = verification_result.verification_result().unwrap().status();
    assert!(matches!(verification_status, VerificationStatus::Ok));
}

#[test]
fn test_sign_inline_stream() {
    let test_time: u64 = 1706018465;

    let plaintext = "Hello World :)";
    let key = PrivateKey::import(
        PRIVATE_KEY.as_bytes(),
        PRIVATE_KEY_PASSWORD.as_bytes(),
        DataEncoding::Armor,
    )
    .unwrap();

    let mut signature_buffer = Vec::with_capacity(plaintext.len());
    {
        let signing_context = SigningContext::new("test", true);
        let mut pt_writer = Signer::new()
            .with_signing_key(&key)
            .with_signing_context(&signing_context)
            .at_signing_time(test_time - 1)
            .sing_stream(&mut signature_buffer, false, DataEncoding::Armor)
            .unwrap();
        pt_writer.write_all(plaintext.as_bytes()).unwrap();
        pt_writer.close().unwrap();
    }

    let verification_context = VerificationContext::new("test", true, 0);
    let reader = Box::new(signature_buffer.as_slice());
    let mut verify_reader = Verifier::new()
        .with_verification_key(&key)
        .with_verification_context(&verification_context)
        .at_verification_time(test_time)
        .verify_inline_stream(reader, DataEncoding::Armor)
        .unwrap();
    let mut discard_message = Vec::with_capacity(signature_buffer.len());
    verify_reader.read_to_end(&mut discard_message).unwrap();
    let verification_status = verify_reader.verification_result().unwrap().status();
    assert!(matches!(verification_status, VerificationStatus::Ok));
}

#[test]
fn test_sign_detached_stream() {
    let test_time: u64 = 1706018465;

    let plaintext = "Hello World :)";
    let key = PrivateKey::import(
        PRIVATE_KEY.as_bytes(),
        PRIVATE_KEY_PASSWORD.as_bytes(),
        DataEncoding::Armor,
    )
    .unwrap();

    let mut signature_buffer = Vec::with_capacity(plaintext.len());
    {
        let signing_context = SigningContext::new("test", true);
        let mut pt_writer = Signer::new()
            .with_signing_key(&key)
            .with_signing_context(&signing_context)
            .at_signing_time(test_time - 1)
            .sing_stream(&mut signature_buffer, true, DataEncoding::Armor)
            .unwrap();
        pt_writer.write_all(plaintext.as_bytes()).unwrap();
        pt_writer.close().unwrap();
    }

    let verification_context = VerificationContext::new("test", true, 0);
    let reader = Box::new(plaintext.as_bytes());
    let verification_result: VerificationResult = Verifier::new()
        .with_verification_key(&key)
        .with_verification_context(&verification_context)
        .at_verification_time(test_time)
        .verify_detached_stream(reader, signature_buffer.as_slice(), DataEncoding::Armor)
        .unwrap();
    let verification_status = verification_result.status();
    assert!(matches!(verification_status, VerificationStatus::Ok));
}
