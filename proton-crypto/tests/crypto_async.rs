use proton_crypto::crypto::{
    DataEncoding, Decryptor, DecryptorAsync, Encryptor, EncryptorAsync, PGPMessage, PGPProvider,
    PGPProviderAsync, SessionKeyAlgorithm, Signer, SignerAsync, UnixTimestamp, VerifiedData,
    Verifier, VerifierAsync,
};

pub mod common;
use common::{
    TEST_EXPECTED_PLAINTEXT, TEST_PRIVATE_KEY, TEST_PRIVATE_KEY_PASSWORD, TEST_SESSION_KEY,
    TEST_SIGNATURE, TEST_SIGNCRYPTED_MESSAGE, TEST_TIME,
};

use crate::common::TEST_PGP_PUBLIC_KEY;

async fn get_test_private_key<T: PGPProviderAsync>(provider: &T) -> T::PrivateKey {
    provider
        .private_key_import_async(
            TEST_PRIVATE_KEY.as_bytes(),
            TEST_PRIVATE_KEY_PASSWORD.as_bytes(),
            DataEncoding::Armor,
        )
        .await
        .unwrap()
}

async fn get_test_public_key<T: PGPProviderAsync>(provider: &T) -> T::PublicKey {
    provider
        .public_key_import_async(TEST_PGP_PUBLIC_KEY.as_bytes(), DataEncoding::Armor)
        .await
        .unwrap()
}

#[test]
fn test_api_async_encrypt_decrypt_session_key() {
    let provider = proton_crypto::new_pgp_provider_async();
    let data = "hello";
    let pt = smol::block_on(async {
        let sk = provider
            .session_key_generate_async(SessionKeyAlgorithm::Aes256)
            .await
            .unwrap();
        let ct = provider
            .new_encryptor_async()
            .with_session_key_ref(&sk)
            .encrypt_raw_async(data.as_bytes(), DataEncoding::Bytes)
            .await
            .unwrap();

        let pt = provider
            .new_decryptor_async()
            .with_session_key_ref(&sk)
            .decrypt_async(ct, DataEncoding::Bytes)
            .await
            .unwrap();
        pt.as_bytes().to_vec()
    });
    assert_eq!(&pt, data.as_bytes());
}

#[test]
fn test_api_async_decrypt_and_verify() {
    let provider = proton_crypto::new_pgp_provider_async();
    let test_time = UnixTimestamp::new(TEST_TIME);
    let expected_plaintext = TEST_EXPECTED_PLAINTEXT;
    let message = TEST_SIGNCRYPTED_MESSAGE;
    smol::block_on(async {
        let imported_private_key = get_test_private_key(&provider).await;
        let public_key = get_test_public_key(&provider).await;
        let verification_context =
            provider.new_verification_context("test".to_owned(), true, UnixTimestamp::new(0));
        let verified_data = provider
            .new_decryptor_async()
            .with_decryption_key(&imported_private_key)
            .with_verification_key(&public_key)
            .at_verification_time(test_time)
            .with_verification_context(&verification_context)
            .decrypt_async(message.as_bytes(), DataEncoding::Armor)
            .await
            .unwrap();
        let verification_result = verified_data.verification_result();
        assert_eq!(verified_data.as_bytes(), expected_plaintext.as_bytes());
        assert!(verification_result.is_ok());
    });
}

#[test]
fn test_api_async_session_key_import_export() {
    let provider = proton_crypto::new_pgp_provider_async();
    let session_key_data = hex::decode(TEST_SESSION_KEY).unwrap();
    smol::block_on(async {
        let imported_session_key = provider
            .session_key_import_async(&session_key_data, SessionKeyAlgorithm::Aes256)
            .await
            .unwrap();
        let (exported_session_key, algorithm) = provider
            .session_key_export_async(&imported_session_key)
            .await
            .unwrap();
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
    });
}

#[test]
fn test_api_async_public_key_import_export() {
    let provider = proton_crypto::new_pgp_provider_async();
    smol::block_on(async {
        let imported_public_key = provider
            .public_key_import_async(TEST_PGP_PUBLIC_KEY.as_bytes(), DataEncoding::Armor)
            .await
            .unwrap();
        let exported_public_key = provider
            .public_key_export_async(&imported_public_key, DataEncoding::Armor)
            .await
            .unwrap();
        assert_eq!(exported_public_key.as_ref(), TEST_PGP_PUBLIC_KEY.as_bytes());
    });
}

#[test]
fn test_api_async_private_key_import_export() {
    let provider = proton_crypto::new_pgp_provider_async();
    smol::block_on(async {
        let imported_private_key = provider
            .private_key_import_async(
                TEST_PRIVATE_KEY.as_bytes(),
                TEST_PRIVATE_KEY_PASSWORD.as_bytes(),
                DataEncoding::Armor,
            )
            .await
            .unwrap();
        let exported_private_key = provider
            .private_key_export_async(
                &imported_private_key,
                TEST_PRIVATE_KEY_PASSWORD.as_bytes(),
                DataEncoding::Armor,
            )
            .await
            .unwrap();
        let exported_private_key_str = std::str::from_utf8(exported_private_key.as_ref()).unwrap();
        assert!(exported_private_key_str.contains("BEGIN PGP PRIVATE KEY"));
    });
}

#[test]
fn test_api_verify_detached_signature_async() {
    let provider = proton_crypto::new_pgp_provider_async();
    let test_time = UnixTimestamp::new(1_706_018_465);
    smol::block_on(async {
        let public_key = get_test_public_key(&provider).await;
        let verification_context =
            provider.new_verification_context("test".to_owned(), true, UnixTimestamp::new(0));
        let verification_result = provider
            .new_verifier_async()
            .with_verification_key(&public_key)
            .with_verification_context(&verification_context)
            .at_verification_time(test_time)
            .verify_detached_async(TEST_EXPECTED_PLAINTEXT, TEST_SIGNATURE, DataEncoding::Armor)
            .await;
        assert!(verification_result.is_ok());
    });
}

#[test]
fn test_api_encrypt_decrypt() {
    let provider = proton_crypto::new_pgp_provider_async();
    let plaintext = TEST_EXPECTED_PLAINTEXT;
    smol::block_on(async {
        let private_key = get_test_private_key(&provider).await;
        let public_key = get_test_public_key(&provider).await;
        let signing_context = provider.new_signing_context("test".to_owned(), true);
        let pgp_message = provider
            .new_encryptor_async()
            .with_encryption_key(&public_key)
            .with_signing_key(&private_key)
            .with_signing_context(&signing_context)
            .encrypt_async(plaintext)
            .await
            .unwrap();
        let verification_context =
            provider.new_verification_context("test".to_owned(), true, UnixTimestamp::new(0));
        let verified_data = provider
            .new_decryptor_async()
            .with_decryption_key(&private_key)
            .with_verification_key(&public_key)
            .with_verification_context(&verification_context)
            .decrypt_async(pgp_message.armor().unwrap(), DataEncoding::Armor)
            .await
            .unwrap();
        let verification_result = verified_data.verification_result();
        assert_eq!(verified_data.as_bytes(), plaintext.as_bytes());
        assert!(verification_result.is_ok());
    });
}

#[test]
fn test_api_sign_verify_detached() {
    let provider = proton_crypto::new_pgp_provider_async();
    smol::block_on(async {
        let private_key = get_test_private_key(&provider).await;
        let public_key = get_test_public_key(&provider).await;
        let test_time = UnixTimestamp::new(1_706_018_465);
        let signing_context = provider.new_signing_context("test".to_owned(), true);
        let signature: Vec<u8> = provider
            .new_signer_async()
            .with_signing_key(&private_key)
            .with_signing_context(&signing_context)
            .at_signing_time(test_time)
            .sign_detached_async(TEST_EXPECTED_PLAINTEXT, DataEncoding::Armor)
            .await
            .unwrap();
        let verification_context =
            provider.new_verification_context("test".to_owned(), true, UnixTimestamp::new(0));
        let verification_result = provider
            .new_verifier_async()
            .with_verification_key(&public_key)
            .with_verification_context(&verification_context)
            .at_verification_time(test_time)
            .verify_detached_async(TEST_EXPECTED_PLAINTEXT, signature, DataEncoding::Armor)
            .await;
        assert!(verification_result.is_ok());
    });
}

#[test]
fn test_api_sign_verify_inline() {
    let provider = proton_crypto::new_pgp_provider_async();
    smol::block_on(async {
        let private_key = get_test_private_key(&provider).await;
        let public_key = get_test_public_key(&provider).await;
        let test_time = UnixTimestamp::new(1_706_018_465);
        let signing_context = provider.new_signing_context("test".to_owned(), true);
        let inline_message: Vec<u8> = provider
            .new_signer_async()
            .with_signing_key(&private_key)
            .with_signing_context(&signing_context)
            .at_signing_time(test_time)
            .sign_inline_async(TEST_EXPECTED_PLAINTEXT, DataEncoding::Armor)
            .await
            .unwrap();
        let verification_context =
            provider.new_verification_context("test".to_owned(), true, UnixTimestamp::new(0));
        let verified_data = provider
            .new_verifier_async()
            .with_verification_key(&public_key)
            .with_verification_context(&verification_context)
            .at_verification_time(test_time)
            .verify_inline_async(inline_message, DataEncoding::Armor)
            .await
            .unwrap();
        let verification_result = verified_data.verification_result();
        assert!(verification_result.is_ok());
        assert_eq!(verified_data.as_bytes(), TEST_EXPECTED_PLAINTEXT.as_bytes());
    });
}

#[test]
fn test_pgp_message_import_async() {
    let provider = proton_crypto::new_pgp_provider_async();
    smol::block_on(async {
        let message = provider
            .pgp_message_import_async(TEST_SIGNCRYPTED_MESSAGE.as_bytes(), DataEncoding::Armor)
            .await
            .expect("import should work");
        let key_ids = message.encryption_key_ids();
        assert!(!key_ids.is_empty());
    });
}
