use proton_crypto::crypto::{
    AccessKeyInfo, DataEncoding, Decryptor, DecryptorSync, DetachedSignatureVariant, Encryptor,
    EncryptorDetachedSignatureWriter, EncryptorSync, EncryptorWriter, KeyGenerator,
    KeyGeneratorSync, OpenPGPFingerprint, OpenPGPKeyID, PGPMessage, PGPProvider, PGPProviderSync,
    SHA256Fingerprint, SessionKey, SessionKeyAlgorithm, Signer, SignerSync, UnixTimestamp,
    VerifiedData, VerifiedDataReader, Verifier, VerifierSync,
};
use std::io::{Read, Write};

mod common;
use common::{
    TEST_EXPECTED_PLAINTEXT, TEST_PGP_PUBLIC_KEY, TEST_PRIVATE_KEY, TEST_PRIVATE_KEY_PASSWORD,
    TEST_SESSION_KEY, TEST_SIGNATURE, TEST_SIGNCRYPTED_MESSAGE, TEST_TIME,
};

use crate::common::{TEST_CLEARTEXT_MESSAGE, TEST_INLINE_SIGNATURE_MESSAGE, TEST_RSA_1023_KEY};

fn get_test_private_key<T: PGPProviderSync>(provider: &T) -> T::PrivateKey {
    provider
        .private_key_import(
            TEST_PRIVATE_KEY.as_bytes(),
            TEST_PRIVATE_KEY_PASSWORD.as_bytes(),
            DataEncoding::Armor,
        )
        .unwrap()
}

fn get_test_public_key<T: PGPProviderSync>(provider: &T) -> T::PublicKey {
    provider
        .public_key_import(TEST_PGP_PUBLIC_KEY.as_bytes(), DataEncoding::Armor)
        .unwrap()
}

#[test]
fn test_api_session_key_encrypt_decrypt() {
    let provider = proton_crypto::new_pgp_provider();
    let data = "hello";
    let sk = provider
        .session_key_generate(SessionKeyAlgorithm::Aes256)
        .unwrap();
    let ct = provider
        .new_encryptor()
        .with_session_key_ref(&sk)
        .encrypt_raw(data.as_bytes(), DataEncoding::Bytes)
        .unwrap();

    let pt = provider
        .new_decryptor()
        .with_session_key_ref(&sk)
        .decrypt(ct, DataEncoding::Bytes)
        .unwrap();
    assert_eq!(pt.as_bytes(), data.as_bytes());
}

#[test]
fn test_api_decrypt_and_verify() {
    let provider = proton_crypto::new_pgp_provider();
    let test_time = UnixTimestamp::new(TEST_TIME);
    let expected_plaintext = TEST_EXPECTED_PLAINTEXT;
    let message = TEST_SIGNCRYPTED_MESSAGE;
    let imported_private_key = get_test_private_key(&provider);
    let public_key = provider
        .private_key_to_public_key(&imported_private_key)
        .unwrap();
    let verification_context =
        provider.new_verification_context("test".to_owned(), true, UnixTimestamp::new(0));
    let verified_data = provider
        .new_decryptor()
        .with_decryption_key(&imported_private_key)
        .with_verification_key(&public_key)
        .with_verification_context(&verification_context)
        .at_verification_time(test_time)
        .decrypt(message.as_bytes(), DataEncoding::Armor)
        .unwrap();
    let verification_result = verified_data.verification_result();
    assert_eq!(verified_data.as_bytes(), expected_plaintext.as_bytes());
    assert!(verification_result.is_ok());
}

#[test]
fn test_api_decrypt_stream_and_verify() {
    let provider = proton_crypto::new_pgp_provider();
    let test_time = UnixTimestamp::new(TEST_TIME);
    let expected_plaintext = TEST_EXPECTED_PLAINTEXT;
    let message = TEST_SIGNCRYPTED_MESSAGE;
    let imported_private_key = get_test_private_key(&provider);
    let public_key = provider
        .private_key_to_public_key(&imported_private_key)
        .unwrap();
    let verification_context =
        provider.new_verification_context("test".to_owned(), true, UnixTimestamp::new(0));
    let mut pt_reader = provider
        .new_decryptor()
        .with_decryption_key(&imported_private_key)
        .with_verification_key(&public_key)
        .at_verification_time(test_time)
        .with_verification_context(&verification_context)
        .decrypt_stream(message.as_bytes(), DataEncoding::Armor)
        .unwrap();
    let mut buffer = Vec::with_capacity(expected_plaintext.len());
    pt_reader.read_to_end(&mut buffer).unwrap();
    let verification_result = pt_reader.verification_result();
    assert_eq!(buffer.as_slice(), expected_plaintext.as_bytes());
    assert!(verification_result.is_ok());
}

#[test]
fn test_api_session_key_import_export() {
    let provider = proton_crypto::new_pgp_provider();
    let session_key_data = hex::decode(TEST_SESSION_KEY).unwrap();
    let imported_session_key = provider
        .session_key_import(&session_key_data, SessionKeyAlgorithm::Aes256)
        .unwrap();
    let (exported_session_key, algorithm) =
        provider.session_key_export(&imported_session_key).unwrap();
    assert_eq!(
        algorithm,
        SessionKeyAlgorithm::Aes256,
        "session key algorithm must be equal"
    );
    assert_eq!(
        exported_session_key.as_ref(),
        &session_key_data,
        "session key data must be equal"
    );
}

#[test]
fn test_api_public_key_import_export() {
    let provider = proton_crypto::new_pgp_provider();
    let imported_public_key = provider
        .public_key_import(TEST_PGP_PUBLIC_KEY.as_bytes(), DataEncoding::Armor)
        .unwrap();
    let exported_public_key = provider
        .public_key_export(&imported_public_key, DataEncoding::Armor)
        .map(|export| String::from_utf8_lossy(export.as_ref()).to_string())
        .unwrap();
    // Compare only the armored body, ignoring the checksum line (which starts with '=')
    let exported_lines: Vec<&str> = exported_public_key
        .lines()
        .filter(|line| !line.trim_start().starts_with('='))
        .collect();
    let test_lines: Vec<&str> = TEST_PGP_PUBLIC_KEY
        .lines()
        .filter(|line| !line.trim_start().starts_with('='))
        .collect();
    assert_eq!(exported_lines, test_lines);
}

#[test]
fn test_api_private_key_import_export() {
    let provider = proton_crypto::new_pgp_provider();
    let imported_private_key = get_test_private_key(&provider);
    let exported_private_key = provider
        .private_key_export(
            &imported_private_key,
            TEST_PRIVATE_KEY_PASSWORD.as_bytes(),
            DataEncoding::Armor,
        )
        .unwrap();
    let exported_private_key_str = std::str::from_utf8(exported_private_key.as_ref()).unwrap();
    assert!(exported_private_key_str.contains("BEGIN PGP PRIVATE KEY"));
}

#[test]
fn test_api_private_key_import_export_unlocked() {
    let provider = proton_crypto::new_pgp_provider();
    let imported_private_key = get_test_private_key(&provider);
    let exported_private_key = provider
        .private_key_export_unlocked(&imported_private_key, DataEncoding::Armor)
        .unwrap();
    let exported_private_key_str = std::str::from_utf8(exported_private_key.as_ref()).unwrap();
    assert!(exported_private_key_str.contains("BEGIN PGP PRIVATE KEY"));
    provider
        .private_key_import_unlocked(exported_private_key.as_ref(), DataEncoding::Armor)
        .expect("Should be importable");
}

#[test]
fn test_api_verify_detached_signature() {
    let provider = proton_crypto::new_pgp_provider();
    let test_time = UnixTimestamp::new(1_706_018_465);
    let public_key = get_test_public_key(&provider);
    let verification_context =
        provider.new_verification_context("test".to_owned(), true, UnixTimestamp::new(0));
    let verification_result = provider
        .new_verifier()
        .with_verification_key(&public_key)
        .with_verification_context(&verification_context)
        .at_verification_time(test_time)
        .verify_detached(TEST_EXPECTED_PLAINTEXT, TEST_SIGNATURE, DataEncoding::Armor);
    assert!(verification_result.is_ok());
}

#[test]
fn test_api_verify_detached_signature_stream() {
    let provider = proton_crypto::new_pgp_provider();
    let test_time = UnixTimestamp::new(1_706_018_465);
    let public_key = get_test_public_key(&provider);
    let verification_context =
        provider.new_verification_context("test".to_owned(), true, UnixTimestamp::new(0));
    let verification_result = provider
        .new_verifier()
        .with_verification_key(&public_key)
        .with_verification_context(&verification_context)
        .at_verification_time(test_time)
        .verify_detached_stream(
            TEST_EXPECTED_PLAINTEXT.as_bytes(),
            TEST_SIGNATURE,
            DataEncoding::Armor,
        );
    assert!(verification_result.is_ok());
}

#[test]
fn test_api_verify_inline_signature() {
    let provider = proton_crypto::new_pgp_provider();
    let test_time = UnixTimestamp::new(1_706_019_172);
    let public_key = get_test_public_key(&provider);
    let verification_context =
        provider.new_verification_context("test".to_owned(), true, UnixTimestamp::new(0));
    let verified_data = provider
        .new_verifier()
        .with_verification_key(&public_key)
        .with_verification_context(&verification_context)
        .at_verification_time(test_time)
        .verify_inline(TEST_INLINE_SIGNATURE_MESSAGE, DataEncoding::Armor)
        .unwrap();
    assert!(verified_data.verification_result().is_ok());
    assert_eq!(verified_data.as_bytes(), TEST_EXPECTED_PLAINTEXT.as_bytes());
}

#[test]
fn test_api_verify_cleartext_signature() {
    let provider = proton_crypto::new_pgp_provider();
    let test_time = UnixTimestamp::new(1_706_020_327);
    let public_key = get_test_public_key(&provider);
    let verified_data = provider
        .new_verifier()
        .with_verification_key(&public_key)
        .at_verification_time(test_time)
        .verify_cleartext(TEST_CLEARTEXT_MESSAGE)
        .unwrap();
    assert!(verified_data.verification_result().is_ok());
    assert_eq!(verified_data.as_bytes(), TEST_EXPECTED_PLAINTEXT.as_bytes());
}

#[test]
fn test_api_access_key_info() {
    let provider = proton_crypto::new_pgp_provider();
    let expected_key_id = OpenPGPKeyID::from_hex("CB186C4F0609A697").unwrap();
    let expected_fingerprint = OpenPGPFingerprint::from(
        "CB186C4F0609A697E4D52DFA6C722B0C1F1E27C18A56708F6525EC27BAD9ACC9",
    );
    let expected_sha_fp = [
        SHA256Fingerprint::from("cb186C4f0609a697e4d52dfa6c722b0c1f1e27c18a56708f6525ec27bad9acc9"),
        SHA256Fingerprint::from("12c83f1E706f6308fe151a417743a1f033790e93e9978488d1db378da9930885"),
    ];
    let public_key = get_test_public_key(&provider);
    let key_id = public_key.key_id();
    assert_eq!(key_id, expected_key_id);
    let key_fp = public_key.key_fingerprint();
    assert_eq!(key_fp, expected_fingerprint);
    assert_eq!(public_key.version(), 6);
    assert!(public_key.is_expired(UnixTimestamp::new(1_615_448_497)));
    assert!(!public_key.is_expired(UnixTimestamp::new(1_710_146_573)));
    assert!(!public_key.is_revoked(UnixTimestamp::new(1_710_146_573)));
    let key_sha256_fp: Vec<SHA256Fingerprint> = public_key.sha256_key_fingerprints();
    assert_eq!(key_sha256_fp, expected_sha_fp);
}

#[test]
fn test_api_encrypt_decrypt() {
    let provider = proton_crypto::new_pgp_provider();
    let plaintext = TEST_EXPECTED_PLAINTEXT;
    let private_key = get_test_private_key(&provider);
    let public_key = provider.private_key_to_public_key(&private_key).unwrap();
    let signing_context = provider.new_signing_context("test".to_owned(), true);
    let pgp_message = provider
        .new_encryptor()
        .with_encryption_key(&public_key)
        .with_signing_key(&private_key)
        .with_signing_context(&signing_context)
        .encrypt(plaintext)
        .unwrap();
    let verification_context =
        provider.new_verification_context("test".to_owned(), true, UnixTimestamp::new(0));
    let verified_data = provider
        .new_decryptor()
        .with_decryption_key(&private_key)
        .with_verification_key(&public_key)
        .with_verification_context(&verification_context)
        .decrypt(pgp_message.armor().unwrap(), DataEncoding::Armor)
        .unwrap();
    let verification_result = verified_data.verification_result();
    assert_eq!(verified_data.as_bytes(), plaintext.as_bytes());
    assert!(verification_result.is_ok());
}

#[test]
fn test_api_encrypt_decrypt_rsa1023() {
    let provider = proton_crypto::new_pgp_provider();
    let plaintext = TEST_EXPECTED_PLAINTEXT;
    let private_key = provider
        .private_key_import_unlocked(TEST_RSA_1023_KEY.as_bytes(), DataEncoding::Armor)
        .unwrap();
    let public_key = provider.private_key_to_public_key(&private_key).unwrap();
    let signing_context = provider.new_signing_context("test".to_owned(), true);
    let pgp_message = provider
        .new_encryptor()
        .with_encryption_key(&public_key)
        .with_signing_key(&private_key)
        .with_signing_context(&signing_context)
        .encrypt(plaintext)
        .unwrap();
    let verification_context =
        provider.new_verification_context("test".to_owned(), true, UnixTimestamp::new(0));
    let verified_data = provider
        .new_decryptor()
        .with_decryption_key(&private_key)
        .with_verification_key(&public_key)
        .with_verification_context(&verification_context)
        .decrypt(pgp_message.armor().unwrap(), DataEncoding::Armor)
        .unwrap();
    let verification_result = verified_data.verification_result();
    assert_eq!(verified_data.as_bytes(), plaintext.as_bytes());
    assert!(verification_result.is_ok());
}

#[test]
fn test_api_encrypt_stream_decrypt() {
    let provider = proton_crypto::new_pgp_provider();
    let plaintext = TEST_EXPECTED_PLAINTEXT;
    let private_key = get_test_private_key(&provider);
    let public_key = provider.private_key_to_public_key(&private_key).unwrap();
    let signing_context = provider.new_signing_context("test".to_owned(), true);
    let mut buffer = Vec::with_capacity(plaintext.len());
    let mut pgp_message_writer = provider
        .new_encryptor()
        .with_encryption_key(&public_key)
        .with_signing_key(&private_key)
        .with_signing_context(&signing_context)
        .encrypt_stream(&mut buffer, DataEncoding::Armor)
        .unwrap();
    pgp_message_writer.write_all(plaintext.as_bytes()).unwrap();
    pgp_message_writer.finalize().unwrap();

    let verification_context =
        provider.new_verification_context("test".to_owned(), true, UnixTimestamp::new(0));
    let verified_data = provider
        .new_decryptor()
        .with_decryption_key(&private_key)
        .with_verification_key(&public_key)
        .with_verification_context(&verification_context)
        .decrypt(buffer.as_slice(), DataEncoding::Armor)
        .unwrap();
    let verification_result = verified_data.verification_result();
    assert_eq!(verified_data.as_bytes(), plaintext.as_bytes());
    assert!(verification_result.is_ok());
}

#[test]
fn test_api_encrypt_stream_split_decrypt() {
    let provider = proton_crypto::new_pgp_provider();
    let plaintext = TEST_EXPECTED_PLAINTEXT;
    let private_key = get_test_private_key(&provider);
    let public_key = provider.private_key_to_public_key(&private_key).unwrap();
    let signing_context = provider.new_signing_context("test".to_owned(), true);
    let mut buffer = Vec::with_capacity(plaintext.len());
    let (mut key_packets, mut pgp_message_writer) = provider
        .new_encryptor()
        .with_encryption_key(&public_key)
        .with_signing_key(&private_key)
        .with_signing_context(&signing_context)
        .encrypt_stream_split(&mut buffer)
        .unwrap();
    pgp_message_writer.write_all(plaintext.as_bytes()).unwrap();
    pgp_message_writer.finalize().unwrap();

    key_packets.extend(buffer.iter());
    let verification_context =
        provider.new_verification_context("test".to_owned(), true, UnixTimestamp::new(0));
    let verified_data = provider
        .new_decryptor()
        .with_decryption_key(&private_key)
        .with_verification_key(&public_key)
        .with_verification_context(&verification_context)
        .decrypt(key_packets, DataEncoding::Bytes)
        .unwrap();
    let verification_result = verified_data.verification_result();
    assert_eq!(verified_data.as_bytes(), plaintext.as_bytes());
    assert!(verification_result.is_ok());
}

#[test]
fn test_api_encrypt_stream_split_decrypt_with_detached_signature() {
    let provider = proton_crypto::new_pgp_provider();
    let plaintext = TEST_EXPECTED_PLAINTEXT;
    let private_key = get_test_private_key(&provider);
    let public_key = provider.private_key_to_public_key(&private_key).unwrap();
    let signing_context = provider.new_signing_context("test".to_owned(), true);
    let mut buffer = Vec::with_capacity(plaintext.len());
    let (mut key_packets, mut pgp_message_writer) = provider
        .new_encryptor()
        .with_encryption_key(&public_key)
        .with_signing_key(&private_key)
        .with_signing_context(&signing_context)
        .encrypt_stream_split_with_detached_signature(
            &mut buffer,
            DetachedSignatureVariant::Plaintext,
        )
        .unwrap();
    pgp_message_writer.write_all(plaintext.as_bytes()).unwrap();
    let detached_signature = pgp_message_writer
        .finalize_with_detached_signature()
        .unwrap();

    key_packets.extend(buffer.iter());
    let verification_context =
        provider.new_verification_context("test".to_owned(), true, UnixTimestamp::new(0));
    let verified_data = provider
        .new_decryptor()
        .with_decryption_key(&private_key)
        .with_verification_key(&public_key)
        .with_verification_context(&verification_context)
        .with_detached_signature(
            detached_signature,
            DetachedSignatureVariant::Plaintext,
            false,
        )
        .decrypt(key_packets, DataEncoding::Bytes)
        .unwrap();
    let verification_result = verified_data.verification_result();
    assert_eq!(verified_data.as_bytes(), plaintext.as_bytes());
    assert!(verification_result.is_ok());
}

#[test]
fn test_api_encrypt_decrypt_session_key() {
    let provider = proton_crypto::new_pgp_provider();
    let sk = provider
        .session_key_generate(SessionKeyAlgorithm::Aes256)
        .unwrap();
    let private_key = get_test_private_key(&provider);
    let public_key = provider.private_key_to_public_key(&private_key).unwrap();
    let key_packets = provider
        .new_encryptor()
        .with_encryption_key(&public_key)
        .encrypt_session_key(&sk)
        .unwrap();
    let sk_out = provider
        .new_decryptor()
        .with_decryption_key(&private_key)
        .decrypt_session_key(key_packets)
        .unwrap();
    assert_eq!(sk_out.export().as_ref(), sk.export().as_ref());
}

#[test]
fn test_api_sign_verify_detached() {
    let provider = proton_crypto::new_pgp_provider();
    let private_key = get_test_private_key(&provider);
    let public_key = provider.private_key_to_public_key(&private_key).unwrap();
    let test_time = UnixTimestamp::new(1_706_018_465);

    let signing_context = provider.new_signing_context("test".to_owned(), true);
    let signature: Vec<u8> = provider
        .new_signer()
        .with_signing_key(&private_key)
        .with_signing_context(&signing_context)
        .at_signing_time(test_time)
        .sign_detached(TEST_EXPECTED_PLAINTEXT, DataEncoding::Armor)
        .unwrap();
    let verification_context =
        provider.new_verification_context("test".to_owned(), true, UnixTimestamp::new(0));
    let verification_result = provider
        .new_verifier()
        .with_verification_key(&public_key)
        .with_verification_context(&verification_context)
        .at_verification_time(test_time)
        .verify_detached(TEST_EXPECTED_PLAINTEXT, signature, DataEncoding::Armor);
    assert!(verification_result.is_ok());
}

#[test]
fn test_api_sign_verify_inline() {
    let provider = proton_crypto::new_pgp_provider();
    let private_key = get_test_private_key(&provider);
    let public_key = provider.private_key_to_public_key(&private_key).unwrap();
    let test_time = UnixTimestamp::new(1_706_018_465);

    let signing_context = provider.new_signing_context("test".to_owned(), true);
    let inline_message: Vec<u8> = provider
        .new_signer()
        .with_signing_key(&private_key)
        .with_signing_context(&signing_context)
        .at_signing_time(test_time)
        .sign_inline(TEST_EXPECTED_PLAINTEXT, DataEncoding::Armor)
        .unwrap();
    let verification_context =
        provider.new_verification_context("test".to_owned(), true, UnixTimestamp::new(0));
    let verified_data = provider
        .new_verifier()
        .with_verification_key(&public_key)
        .with_verification_context(&verification_context)
        .at_verification_time(test_time)
        .verify_inline(inline_message, DataEncoding::Armor)
        .unwrap();
    let verification_result = verified_data.verification_result();
    assert!(verification_result.is_ok());
    assert_eq!(verified_data.as_bytes(), TEST_EXPECTED_PLAINTEXT.as_bytes());
}

#[test]
fn test_api_sign_verify_cleartext() {
    let provider = proton_crypto::new_pgp_provider();
    let private_key = get_test_private_key(&provider);
    let public_key = provider.private_key_to_public_key(&private_key).unwrap();
    let test_time = UnixTimestamp::new(1_706_018_465);
    let cleartext_message: Vec<u8> = provider
        .new_signer()
        .with_signing_key(&private_key)
        .at_signing_time(test_time)
        .sign_cleartext(TEST_EXPECTED_PLAINTEXT)
        .unwrap();
    let verified_data = provider
        .new_verifier()
        .with_verification_key(&public_key)
        .at_verification_time(test_time)
        .verify_cleartext(cleartext_message)
        .unwrap();
    let verification_result = verified_data.verification_result();
    assert!(verification_result.is_ok());
    assert_eq!(verified_data.as_bytes(), TEST_EXPECTED_PLAINTEXT.as_bytes());
}

#[test]
fn test_api_sign_detached_stream() {
    let provider = proton_crypto::new_pgp_provider();
    let private_key = get_test_private_key(&provider);
    let public_key = provider.private_key_to_public_key(&private_key).unwrap();
    let test_time = UnixTimestamp::new(1_706_018_465);

    let mut buffer = Vec::with_capacity(TEST_EXPECTED_PLAINTEXT.len());
    let signing_context = provider.new_signing_context("test".to_owned(), true);
    let mut signature_writer = provider
        .new_signer()
        .with_signing_key(&private_key)
        .with_signing_context(&signing_context)
        .at_signing_time(test_time)
        .sign_stream(&mut buffer, true, DataEncoding::Bytes)
        .unwrap();
    signature_writer
        .write_all(TEST_EXPECTED_PLAINTEXT.as_bytes())
        .unwrap();
    signature_writer.finalize().unwrap();

    let verification_context =
        provider.new_verification_context("test".to_owned(), true, UnixTimestamp::new(0));
    let verification_result = provider
        .new_verifier()
        .with_verification_key(&public_key)
        .with_verification_context(&verification_context)
        .at_verification_time(test_time)
        .verify_detached(TEST_EXPECTED_PLAINTEXT, buffer, DataEncoding::Bytes);
    assert!(verification_result.is_ok());
}

#[test]
fn test_api_sign_inline_stream() {
    let provider = proton_crypto::new_pgp_provider();
    let private_key = get_test_private_key(&provider);
    let public_key = provider.private_key_to_public_key(&private_key).unwrap();
    let test_time = UnixTimestamp::new(1_706_018_465);

    let mut buffer = Vec::with_capacity(TEST_EXPECTED_PLAINTEXT.len());
    let signing_context = provider.new_signing_context("test".to_owned(), true);
    let mut signature_writer = provider
        .new_signer()
        .with_signing_key(&private_key)
        .with_signing_context(&signing_context)
        .at_signing_time(test_time)
        .sign_stream(&mut buffer, false, DataEncoding::Armor)
        .unwrap();
    signature_writer
        .write_all(TEST_EXPECTED_PLAINTEXT.as_bytes())
        .unwrap();
    signature_writer.finalize().unwrap();

    let verification_context =
        provider.new_verification_context("test".to_owned(), true, UnixTimestamp::new(0));
    let verified_data = provider
        .new_verifier()
        .with_verification_key(&public_key)
        .with_verification_context(&verification_context)
        .at_verification_time(test_time)
        .verify_inline(buffer, DataEncoding::Armor)
        .unwrap();
    let verification_result = verified_data.verification_result();
    assert!(verification_result.is_ok());
    assert_eq!(verified_data.as_bytes(), TEST_EXPECTED_PLAINTEXT.as_bytes());
}

#[test]
fn test_key_generation() {
    let provider = proton_crypto::new_pgp_provider();
    let generated_key = provider
        .new_key_generator()
        .with_user_id("test", "test@test.test")
        .generate()
        .expect("key should be generated");
    let armored = provider
        .private_key_export_unlocked(&generated_key, DataEncoding::Armor)
        .map(|value| String::from_utf8(value.as_ref().to_vec()).unwrap())
        .unwrap();
    assert!(armored.contains("PGP PRIVATE KEY"));
}

#[test]
fn test_pgp_message_import() {
    let provider = proton_crypto::new_pgp_provider();
    let message = provider
        .pgp_message_import(TEST_SIGNCRYPTED_MESSAGE.as_bytes(), DataEncoding::Armor)
        .expect("import should work");
    assert_ne!(message.as_key_packets(), message.as_data_packet());
}

#[test]
fn test_api_passphrase_encrypt_decrypt() {
    let provider = proton_crypto::new_pgp_provider();
    let data = "hello";
    let password = "password";
    let ct = provider
        .new_encryptor()
        .with_passphrase(password)
        .encrypt_raw(data.as_bytes(), DataEncoding::Bytes)
        .unwrap();

    let pt = provider
        .new_decryptor()
        .with_passphrase(password)
        .decrypt(ct, DataEncoding::Bytes)
        .unwrap();
    assert_eq!(pt.as_bytes(), data.as_bytes());
}

#[test]
fn test_api_passphrase_encrypt_decrypt_session_key() {
    let provider = proton_crypto::new_pgp_provider();
    let password = "password";
    let sk = provider
        .session_key_generate(SessionKeyAlgorithm::Aes256)
        .unwrap();
    let ct = provider
        .new_encryptor()
        .with_passphrase(password)
        .encrypt_session_key(&sk)
        .unwrap();

    let sk_out = provider
        .new_decryptor()
        .with_passphrase(password)
        .decrypt_session_key(&ct)
        .unwrap();
    assert_eq!(sk.export().as_ref(), sk_out.export().as_ref());
}
