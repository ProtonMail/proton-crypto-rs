use pgp::{
    composed::{
        EncryptionCaps, KeyType, MessageBuilder, SecretKeyParamsBuilder, SubkeyParamsBuilder,
    },
    crypto::{ecc_curve::ECCCurve, sym::SymmetricKeyAlgorithm},
    packet::{Packet, PacketParser, PublicKeyEncryptedSessionKey, Signature, SignatureType},
    ser::Serialize,
    types::{
        EcdhKdfType, EcdhPublicParams, Fingerprint, ForwardingProxyParameter, KeyDetails, KeyId,
        KeyVersion, PublicParams,
    },
};
use proton_rpgp::{
    AccessKeyInfo, AsPublicKeyRef, DataEncoding, Decryptor, EncryptedMessage, Encryptor, Error,
    FingerprintExt, ForwardingInstance, ForwardingInstanceError, ForwardingKeyGenerationError,
    ForwardingKeyValidationError, ForwardingPkesk, ForwardingTransformError,
    KeyCertificationSelectionError, KeyGenerationType, KeyGenerator, KeyValidationError,
    PrivateKey, Profile, UnixTime,
};

const FORWARDEE_KEY: &str = include_str!("../test-data/keys/private_key_v4_forwardee.asc");
const FORWARDED_MESSAGE: &str =
    include_str!("../test-data/messages/encrypted_message_v4_forwarded.asc");
const SIGN_ONLY_KEY: &str = include_str!("../test-data/keys/private_key_v4_sign_only.asc");
const REGULAR_KEY: &str = include_str!("../test-data/keys/private_key_v4.asc");
const KEY_V6: &str = include_str!("../test-data/keys/private_key_v6.asc");
const LOCKED_KEY_NIST_P256: &str =
    include_str!("../test-data/keys/locked_private_key_v4_nist_p256.asc");
const LOCKED_KEY_RSA_1023: &str =
    include_str!("../test-data/keys/locked_private_key_v4_rsa_1023.asc");
const SUBKEYS_EXPIRED_KEY: &str =
    include_str!("../test-data/keys/private_key_v4_subkeys_expired.asc");
const MESSAGE_V6: &str = include_str!("../test-data/messages/encrypted_message_v6.asc");
pub const TEST_KEY_V4: &str = include_str!("../test-data/keys/private_key_v4.asc");

fn test_date() -> UnixTime {
    UnixTime::new(1_787_919_498)
}

fn import_unlocked(key: &str) -> PrivateKey {
    PrivateKey::import_unlocked(key.as_bytes(), DataEncoding::Armored)
        .expect("Failed to import key")
}

fn import_locked(key: &str) -> PrivateKey {
    PrivateKey::import(key.as_bytes(), b"password", DataEncoding::Armored)
        .expect("Failed to import key")
}

fn encrypt_to(key: &PrivateKey, data: &[u8]) -> EncryptedMessage {
    Encryptor::default()
        .with_encryption_key(key.as_public_key())
        .at_date(test_date().into())
        .encrypt(data)
        .expect("Failed to encrypt")
}

fn proxy_forward_message(
    message: &EncryptedMessage,
    instances: &[ForwardingInstance],
) -> Result<Vec<u8>, Error> {
    let pkesk = ForwardingPkesk::from_bytes(message.as_key_packets_unchecked())?;
    let mut forwarded_message = Vec::new();
    for forwarded in pkesk.proxy_forward(instances)? {
        forwarded_message.extend_from_slice(&forwarded.to_vec()?);
    }
    forwarded_message.extend_from_slice(message.as_data_packet_unchecked());
    Ok(forwarded_message)
}

fn generate_key_with_subkeys(subkey_types: &[KeyType]) -> PrivateKey {
    let mut rng = Profile::default().rng();
    let subkeys = subkey_types
        .iter()
        .map(|key_type| {
            SubkeyParamsBuilder::default()
                .key_type(key_type.clone())
                .can_encrypt(EncryptionCaps::All)
                .build()
                .expect("Failed to build subkey params")
        })
        .collect();

    let secret_key_params = SecretKeyParamsBuilder::default()
        .key_type(KeyType::Ed25519Legacy)
        .can_certify(true)
        .can_sign(true)
        .primary_user_id("Multi <multi@test.test>".into())
        .preferred_symmetric_algorithms(smallvec::smallvec![SymmetricKeyAlgorithm::AES256])
        .preferred_hash_algorithms(smallvec::smallvec![
            pgp::crypto::hash::HashAlgorithm::Sha256
        ])
        .preferred_compression_algorithms(smallvec::smallvec![])
        .subkeys(subkeys)
        .build()
        .expect("Failed to build key params");

    let signed_secret_key = secret_key_params
        .generate(&mut rng)
        .expect("Failed to generate key");
    let bytes = signed_secret_key.to_bytes().expect("Failed to encode key");

    PrivateKey::import_unlocked(&bytes, DataEncoding::Unarmored).expect("Failed to import key")
}

fn subkey_ecdh_params(key: &PrivateKey, index: usize) -> EcdhPublicParams {
    let subkey = key
        .as_signed_public_key()
        .public_subkeys
        .get(index)
        .expect("Missing subkey");
    let PublicParams::ECDH(params) = subkey.public_params() else {
        panic!("Subkey is not an ECDH key");
    };
    params.clone()
}

fn subkey_binding_signature(key: &[u8]) -> Signature {
    PacketParser::new(key)
        .flatten()
        .find_map(|packet| match packet {
            Packet::Signature(signature)
                if signature.typ() == Some(SignatureType::SubkeyBinding) =>
            {
                Some(signature)
            }
            _ => None,
        })
        .expect("Missing subkey binding signature")
}

fn subkey_fingerprint(key: &PrivateKey, index: usize) -> Fingerprint {
    key.as_signed_public_key()
        .public_subkeys
        .get(index)
        .expect("Missing subkey")
        .fingerprint()
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn forwarding_refuses_encryption_to_forwarding_key() {
    let key = import_unlocked(FORWARDEE_KEY);

    let result = Encryptor::default()
        .with_encryption_key(key.as_public_key())
        .encrypt_raw(b"abc", DataEncoding::Armored);

    assert!(
        result.is_err(),
        "Encryption to a forwarding key must be refused"
    );
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn forwarding_key_serialization_preserves_kdf_params() {
    let profile = Profile::default();
    let date = UnixTime::new(1_679_044_110);

    let key = import_unlocked(FORWARDEE_KEY);
    assert!(key.is_forwarding_key(&profile));

    let exported = key
        .export_unlocked(DataEncoding::Armored)
        .expect("Failed to export key");

    let reimported = PrivateKey::import_unlocked(&exported, DataEncoding::Armored)
        .expect("Failed to re-import key");

    // Forwarding KDF params survived serialization.
    assert!(reimported.is_forwarding_key(&profile));

    // And the re-imported key still decrypts the forwarded ciphertext.
    let verified_data = Decryptor::default()
        .with_decryption_key(&reimported)
        .at_date(date.into())
        .allow_forwarding_decryption(true)
        .decrypt(FORWARDED_MESSAGE, DataEncoding::Armored)
        .expect("Failed to decrypt with re-imported forwarding key");

    assert_eq!(verified_data.data, b"Message for Bob");
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn forwarding_reformat_preserves_flag() {
    let profile = Profile::default();
    let key = import_unlocked(FORWARDEE_KEY);
    assert!(key.is_forwarding_key(&profile));

    let reformatted = key
        .modify()
        .add_user_id("test", "test@forwarding.it")
        .reset_signatures()
        .apply()
        .expect("Failed to reformat key");

    assert!(
        reformatted.is_forwarding_key(&profile),
        "Reformatting must preserve the forwarding flag"
    );
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn forwarding_detection_negative_cases() {
    let profile = Profile::default();

    let regular = import_unlocked(REGULAR_KEY);
    assert!(!regular.is_forwarding_key(&profile));

    let sign_only = import_unlocked(SIGN_ONLY_KEY);
    assert!(!sign_only.is_forwarding_key(&profile));
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn forwarding_generation_produces_valid_forwarding_key() {
    let profile = Profile::default();
    let forwarder = import_unlocked(TEST_KEY_V4);

    let (forwardee, instances) = forwarder
        .forwarding_key_generator()
        .with_user_id("forwardee", "forwardee@test.test")
        .at_date(test_date())
        .generate()
        .expect("Generation should succeed");

    assert_eq!(forwardee.version(), 4);
    assert!(forwardee.is_forwarding_key(&profile));
    assert_eq!(
        UnixTime::from(forwardee.as_signed_public_key().primary_key.created_at()),
        test_date(),
        "The key creation time must be the provided date"
    );

    // One instance and one forwardee subkey per forwarded encryption subkey.
    let forwarder_subkeys = forwarder.as_signed_public_key().public_subkeys.len();
    assert_eq!(instances.len(), forwarder_subkeys);
    assert_eq!(
        forwardee.as_signed_public_key().public_subkeys.len(),
        forwarder_subkeys
    );

    // The instances point at the forwarder and forwardee subkeys, in order.
    for (index, instance) in instances.iter().enumerate() {
        assert_eq!(
            instance.forwarder_fingerprint(),
            &subkey_fingerprint(&forwarder, index)
        );
        assert_eq!(
            instance.forwardee_fingerprint(),
            &subkey_fingerprint(&forwardee, index)
        );
    }

    // The forwardee subkey inherits the KDF parameters of the forwarder subkey
    // and replaces the fingerprint mixed into the KDF.
    let EcdhPublicParams::Curve25519Legacy {
        hash: forwarder_hash,
        alg_sym: forwarder_alg_sym,
        ..
    } = subkey_ecdh_params(&forwarder, 0)
    else {
        panic!("Forwarder subkey is not a legacy curve25519 key");
    };
    let EcdhPublicParams::Curve25519Legacy {
        hash,
        alg_sym,
        ecdh_kdf_type,
        ..
    } = subkey_ecdh_params(&forwardee, 0)
    else {
        panic!("Forwardee subkey is not a legacy curve25519 key");
    };
    assert_eq!(hash, forwarder_hash);
    assert_eq!(alg_sym, forwarder_alg_sym);
    let Fingerprint::V4(forwarder_fingerprint) = subkey_fingerprint(&forwarder, 0) else {
        panic!("Forwarder subkey is not a v4 key");
    };
    assert_eq!(
        ecdh_kdf_type,
        EcdhKdfType::Replaced {
            replacement_fingerprint: forwarder_fingerprint
        }
    );

    // The forwardee subkey is certified as a shared forwarding key and not as a
    // regular encryption key.
    let exported = forwardee
        .export_unlocked(DataEncoding::Unarmored)
        .expect("Failed to export key");
    let binding_signature = subkey_binding_signature(&exported);
    let key_flags = binding_signature.key_flags();
    assert!(key_flags.shared());
    assert!(key_flags.draft_decrypt_forwarded());
    assert!(!key_flags.encrypt_comms());
    assert!(!key_flags.encrypt_storage());
    assert_eq!(
        binding_signature.created().map(UnixTime::from),
        Some(test_date()),
        "The binding signature must be created at the provided date"
    );
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn forwarding_generation_with_multiple_user_ids() {
    let forwarder = import_unlocked(TEST_KEY_V4);

    let (forwardee, _) = forwarder
        .forwarding_key_generator()
        .with_user_id("first", "first@test.test")
        .with_user_id("second", "second@test.test")
        .at_date(test_date())
        .generate()
        .expect("Generation should succeed");

    let user_ids: Vec<String> = forwardee
        .as_signed_public_key()
        .details
        .users
        .iter()
        .map(|user| String::from_utf8_lossy(user.id.id()).to_string())
        .collect();

    assert_eq!(
        user_ids,
        vec![
            "first <first@test.test>".to_string(),
            "second <second@test.test>".to_string()
        ]
    );
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn forwarding_generation_without_user_id_fails() {
    let forwarder = import_unlocked(TEST_KEY_V4);

    let result = forwarder
        .forwarding_key_generator()
        .at_date(test_date())
        .generate();

    assert!(matches!(
        result,
        Err(Error::ForwardingKeyGeneration(
            ForwardingKeyGenerationError::NoUserId
        ))
    ));
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn forwarding_generation_from_v6_key_fails() {
    let forwarder = import_unlocked(KEY_V6);

    let result = forwarder
        .forwarding_key_generator()
        .with_user_id("forwardee", "forwardee@test.test")
        .at_date(test_date())
        .generate();

    assert!(matches!(
        result,
        Err(Error::ForwardingKeyGeneration(
            ForwardingKeyGenerationError::VersionMismatch(6)
        ))
    ));
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn forwarding_generation_from_sign_only_key_fails() {
    let forwarder = import_unlocked(SIGN_ONLY_KEY);

    let result = forwarder
        .forwarding_key_generator()
        .with_user_id("forwardee", "forwardee@test.test")
        .at_date(test_date())
        .generate();

    assert!(
        matches!(
            result,
            Err(Error::ForwardingKeyGeneration(
                ForwardingKeyGenerationError::KeyValidation(_)
            ))
        ),
        "A key without encryption subkey must be rejected up front, got {result:?}"
    );
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn forwarding_generation_from_non_curve25519_key_fails() {
    let forwarder = import_locked(LOCKED_KEY_NIST_P256);

    let result = forwarder
        .forwarding_key_generator()
        .with_user_id("forwardee", "forwardee@test.test")
        .at_date(test_date())
        .generate();

    let Err(Error::ForwardingKeyGeneration(ForwardingKeyGenerationError::SubKeyValidation(errors))) =
        result
    else {
        panic!("Expected a subkey validation error, got {result:?}");
    };
    assert!(matches!(
        errors.0.first(),
        Some(ForwardingKeyValidationError::SubKeyNoMatchingAlgorithm(_))
    ));
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn forwarding_generation_from_expired_subkey_fails() {
    // The primary key does not expire, the encryption subkey expires at 2026-01-01.
    let forwarder = import_unlocked(SUBKEYS_EXPIRED_KEY);

    forwarder
        .forwarding_key_generator()
        .with_user_id("forwardee", "forwardee@test.test")
        .at_date(UnixTime::new(1_748_736_000))
        .generate()
        .expect("Failed to generate forwarding key before subkey expiration");

    let result = forwarder
        .forwarding_key_generator()
        .with_user_id("forwardee", "forwardee@test.test")
        .at_date(UnixTime::new(1_780_272_000))
        .generate();

    let Err(Error::ForwardingKeyGeneration(ForwardingKeyGenerationError::SubKeyValidation(errors))) =
        result
    else {
        panic!("Expected a subkey validation error, got {result:?}");
    };
    assert!(matches!(
        errors.0.first(),
        Some(ForwardingKeyValidationError::KeyValidation(
            KeyValidationError::KeySelfCertification(
                KeyCertificationSelectionError::ExpiredKey { .. }
            )
        ))
    ));
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn forwarding_generation_skips_unsupported_subkeys() {
    let profile = Profile::default();
    // Only the legacy curve25519 subkey can be forwarded, the NIST subkey has to
    // be skipped without failing the whole generation.
    let forwarder = generate_key_with_subkeys(&[
        KeyType::ECDH(ECCCurve::Curve25519Legacy),
        KeyType::ECDH(ECCCurve::P256),
    ]);

    let (forwardee, instances) = forwarder
        .forwarding_key_generator()
        .with_user_id("forwardee", "forwardee@test.test")
        .generate()
        .expect("Generation should succeed for the supported subkey");

    assert_eq!(instances.len(), 1);
    assert_eq!(forwardee.as_signed_public_key().public_subkeys.len(), 1);
    assert!(forwardee.is_forwarding_key(&profile));
    assert_eq!(
        instances
            .first()
            .expect("Missing instance")
            .forwarder_fingerprint(),
        &subkey_fingerprint(&forwarder, 0)
    );
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn forwarding_generation_with_multiple_encryption_subkeys() {
    let forwarder = generate_key_with_subkeys(&[
        KeyType::ECDH(ECCCurve::Curve25519Legacy),
        KeyType::ECDH(ECCCurve::Curve25519Legacy),
    ]);

    let (forwardee, instances) = forwarder
        .forwarding_key_generator()
        .with_user_id("forwardee", "forwardee@test.test")
        .generate()
        .expect("Generation should succeed");

    assert_eq!(instances.len(), 2);
    assert_eq!(forwardee.as_signed_public_key().public_subkeys.len(), 2);

    // Every forwarder subkey must be forwardable with its matching instance.
    for index in 0..2 {
        let mut rng = Profile::default().rng();
        let subkey = forwarder
            .as_signed_public_key()
            .public_subkeys
            .get(index)
            .expect("Missing subkey");
        let mut builder = MessageBuilder::from_bytes("", &b"hello"[..])
            .seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);
        builder
            .encrypt_to_key(&mut rng, subkey)
            .expect("Failed to encrypt to subkey");
        let encrypted = builder.to_vec(&mut rng).expect("Failed to encrypt");
        let message = EncryptedMessage::from_bytes(&encrypted).expect("Failed to parse message");

        let forwarded_message =
            proxy_forward_message(&message, &instances).expect("Failed to forward");

        let decrypted = Decryptor::default()
            .allow_forwarding_decryption(true)
            .with_decryption_key(&forwardee)
            .decrypt(forwarded_message, DataEncoding::Unarmored)
            .expect("Failed to decrypt forwarded message");

        assert_eq!(decrypted.data, b"hello");
    }
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn forwarding_generated_key_cannot_encrypt() {
    let profile = Profile::default();
    let forwarder = import_unlocked(TEST_KEY_V4);

    let (forwardee, _) = forwarder
        .forwarding_key_generator()
        .with_user_id("forwardee", "forwardee@test.test")
        .at_date(test_date())
        .generate()
        .expect("Generation should succeed");

    assert!(forwardee
        .check_can_encrypt(&profile, test_date().into())
        .is_err());
    assert!(Encryptor::default()
        .with_encryption_key(forwardee.as_public_key())
        .at_date(test_date().into())
        .encrypt_raw(b"abc", DataEncoding::Armored)
        .is_err());
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn forwarding_generated_key_survives_export_import() {
    let profile = Profile::default();
    let forwarder = import_unlocked(TEST_KEY_V4);
    let encrypted = encrypt_to(&forwarder, b"hello");

    let (forwardee, instances) = forwarder
        .forwarding_key_generator()
        .with_user_id("forwardee", "forwardee@test.test")
        .at_date(test_date())
        .generate()
        .expect("Generation should succeed");

    let exported = forwardee
        .export_unlocked(DataEncoding::Armored)
        .expect("Failed to export key");
    let reimported = PrivateKey::import_unlocked(&exported, DataEncoding::Armored)
        .expect("Failed to re-import key");
    assert!(reimported.is_forwarding_key(&profile));

    let forwarded_message = proxy_forward_message(&encrypted, &instances).expect("Failed to fwd");

    let decrypted = Decryptor::default()
        .allow_forwarding_decryption(true)
        .with_decryption_key(&reimported)
        .at_date(test_date().into())
        .decrypt(forwarded_message, DataEncoding::Unarmored)
        .expect("Failed to decrypt with re-imported key");

    assert_eq!(decrypted.data, b"hello");
}

// --- Forwarding instances ---

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn forwarding_instance_can_be_rebuilt_from_its_parts() {
    let forwarder = import_unlocked(TEST_KEY_V4);
    let encrypted = encrypt_to(&forwarder, b"hello");

    let (forwardee, instances) = forwarder
        .forwarding_key_generator()
        .with_user_id("forwardee", "forwardee@test.test")
        .at_date(test_date())
        .generate()
        .expect("Generation should succeed");

    // Simulate the proxy persisting and restoring the instance.
    let instance = instances.first().expect("Missing instance");
    let restored = ForwardingInstance::new(
        instance.forwarder_fingerprint().clone(),
        instance.forwardee_fingerprint().clone(),
        ForwardingProxyParameter::from(*instance.proxy_parameter().as_ref()),
    )
    .expect("Failed to rebuild instance");

    assert_eq!(
        restored.forwarder_fingerprint(),
        instance.forwarder_fingerprint()
    );
    assert_eq!(
        restored.forwardee_fingerprint(),
        instance.forwardee_fingerprint()
    );
    assert_eq!(
        restored.proxy_parameter().as_ref(),
        instance.proxy_parameter().as_ref()
    );

    let forwarded_message =
        proxy_forward_message(&encrypted, &[restored]).expect("Failed to forward");

    let decrypted = Decryptor::default()
        .allow_forwarding_decryption(true)
        .with_decryption_key(&forwardee)
        .at_date(test_date().into())
        .decrypt(forwarded_message, DataEncoding::Unarmored)
        .expect("Failed to decrypt forwarded message");

    assert_eq!(decrypted.data, b"hello");
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn forwarding_instance_rejects_non_v4_fingerprints() {
    let v4 = Fingerprint::new(KeyVersion::V4, &[0x11_u8; 20]).expect("Failed to build fingerprint");
    let v6 = Fingerprint::new(KeyVersion::V6, &[0x22_u8; 32]).expect("Failed to build fingerprint");
    let forwarder_v6 = ForwardingInstance::new(
        v6.clone(),
        v4.clone(),
        ForwardingProxyParameter::from([0_u8; 32]),
    );
    assert!(matches!(
        forwarder_v6,
        Err(Error::ForwardingInstance(
            ForwardingInstanceError::UnsupportedForwarderKeyVersion(_)
        ))
    ));

    let forwardee_v6 = ForwardingInstance::new(v4, v6, ForwardingProxyParameter::from([0_u8; 32]));
    assert!(matches!(
        forwardee_v6,
        Err(Error::ForwardingInstance(
            ForwardingInstanceError::UnsupportedForwardeeKeyVersion(_)
        ))
    ));
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn forwarding_pkesk_parses_a_single_pkesk() {
    let forwarder = import_unlocked(TEST_KEY_V4);
    let encrypted = encrypt_to(&forwarder, b"hello");

    let pkesk = ForwardingPkesk::from_bytes(encrypted.as_key_packets_unchecked())
        .expect("Failed to parse PKESK");

    let inner = PublicKeyEncryptedSessionKey::from(pkesk.clone());
    assert_eq!(
        inner.id().expect("Missing key id"),
        encrypted
            .encryption_key_ids()
            .first()
            .expect("Missing key id")
    );
    // A valid PKESK can also be wrapped directly.
    ForwardingPkesk::try_from(inner.clone()).expect("Wrapping a valid PKESK must succeed");
    ForwardingPkesk::valid(&inner).expect("A v3 ECDH PKESK must be valid for forwarding");
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn forwarding_pkesk_rejects_input_without_pkesk() {
    let forwarder = import_unlocked(TEST_KEY_V4);
    let encrypted = encrypt_to(&forwarder, b"hello");

    // The data packet alone contains no PKESK.
    let result = ForwardingPkesk::from_bytes(encrypted.as_data_packet_unchecked());
    assert!(matches!(
        result,
        Err(Error::ForwardingTransform(
            ForwardingTransformError::NoPkeskFound
        ))
    ));

    let empty = ForwardingPkesk::from_bytes(&[][..]);
    assert!(matches!(
        empty,
        Err(Error::ForwardingTransform(
            ForwardingTransformError::NoPkeskFound
        ))
    ));
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn forwarding_pkesk_rejects_multiple_pkesks() {
    let first = import_unlocked(TEST_KEY_V4);
    let second = KeyGenerator::default()
        .with_user_id("second", "second@test.test")
        .with_key_type(KeyGenerationType::ECC)
        .at_date(test_date())
        .generate()
        .expect("Failed to generate key");

    let encrypted = Encryptor::default()
        .with_encryption_key(first.as_public_key())
        .with_encryption_key(second.as_public_key())
        .at_date(test_date().into())
        .encrypt(b"hello")
        .expect("Failed to encrypt");

    let result = ForwardingPkesk::from_bytes(encrypted.as_key_packets_unchecked());
    assert!(matches!(
        result,
        Err(Error::ForwardingTransform(
            ForwardingTransformError::MultiplePkesks
        ))
    ));

    // The iterator API on the other hand yields both PKESKs.
    let parsed =
        ForwardingPkesk::from_bytes_iter(encrypted.as_key_packets_unchecked()).collect::<Vec<_>>();
    assert_eq!(parsed.len(), 2);
    assert!(parsed.iter().all(Result::is_ok));
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn forwarding_pkesk_rejects_v6_pkesk() {
    let message =
        EncryptedMessage::from_armor(MESSAGE_V6.as_bytes()).expect("Failed to parse message");

    let result = ForwardingPkesk::from_bytes(message.as_key_packets_unchecked());

    assert!(
        matches!(
            result,
            Err(Error::ForwardingTransform(
                ForwardingTransformError::VersionMismatch(_)
            ))
        ),
        "Only v3 PKESKs can be forwarded, got {result:?}"
    );
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn forwarding_pkesk_rejects_non_ecdh_pkesk() {
    let rsa_key = import_locked(LOCKED_KEY_RSA_1023);
    let rsa_encrypted = encrypt_to(&rsa_key, b"hello");

    let result = ForwardingPkesk::from_bytes(rsa_encrypted.as_key_packets_unchecked());
    assert!(
        matches!(
            result,
            Err(Error::ForwardingTransform(
                ForwardingTransformError::AlgorithmMismatch(_)
            ))
        ),
        "Only ECDH PKESKs can be forwarded, got {result:?}"
    );

    // The same applies to the modern X25519 algorithm.
    let key_v6 = import_unlocked(KEY_V6);
    let x25519_encrypted = encrypt_to(&key_v6, b"hello");

    let result = ForwardingPkesk::from_bytes(x25519_encrypted.as_key_packets_unchecked());
    assert!(
        matches!(
            result,
            Err(Error::ForwardingTransform(
                ForwardingTransformError::AlgorithmMismatch(_)
            ))
        ),
        "Only ECDH PKESKs can be forwarded, got {result:?}"
    );
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn forwarding_pkesk_without_matching_instance_fails() {
    let forwarder = import_unlocked(TEST_KEY_V4);
    let other = KeyGenerator::default()
        .with_user_id("other", "other@test.test")
        .with_key_type(KeyGenerationType::ECC)
        .at_date(test_date())
        .generate()
        .expect("Failed to generate key");

    // The instances belong to `other`, but the message is encrypted to `forwarder`.
    let (_, instances) = other
        .forwarding_key_generator()
        .with_user_id("forwardee", "forwardee@test.test")
        .generate()
        .expect("Generation should succeed");

    let encrypted = encrypt_to(&forwarder, b"hello");
    let pkesk = ForwardingPkesk::from_bytes(encrypted.as_key_packets_unchecked())
        .expect("Failed to parse PKESK");

    let result = pkesk.proxy_forward(&instances);
    assert!(matches!(
        result,
        Err(Error::ForwardingTransform(
            ForwardingTransformError::NoMatchingInstance(_)
        ))
    ));

    // The same holds without any instance at all.
    let empty: [ForwardingInstance; 0] = [];
    assert!(matches!(
        pkesk.proxy_forward(&empty),
        Err(Error::ForwardingTransform(
            ForwardingTransformError::NoMatchingInstance(_)
        ))
    ));
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn forwarding_preserves_the_session_key() {
    let forwarder = import_unlocked(TEST_KEY_V4);
    let encrypted = encrypt_to(&forwarder, b"hello");

    let (forwardee, instances) = forwarder
        .forwarding_key_generator()
        .with_user_id("forwardee", "forwardee@test.test")
        .at_date(test_date())
        .generate()
        .expect("Generation should succeed");

    let pkesk = ForwardingPkesk::from_bytes(encrypted.as_key_packets_unchecked())
        .expect("Failed to parse PKESK");
    let [forwarded] = pkesk
        .proxy_forward(&instances)
        .expect("Failed to forward")
        .try_into()
        .expect("Expected exactly one forwarded PKESK");

    let original_session_key = Decryptor::default()
        .with_decryption_key(&forwarder)
        .at_date(test_date().into())
        .decrypt_session_key(encrypted.as_key_packets_unchecked())
        .expect("Failed to decrypt the session key");

    let forwarded_session_key = Decryptor::default()
        .allow_forwarding_decryption(true)
        .with_decryption_key(&forwardee)
        .at_date(test_date().into())
        .decrypt_session_key(forwarded.to_vec().expect("Failed to encode PKESK"))
        .expect("Failed to decrypt the forwarded session key");

    assert_eq!(
        forwarded_session_key.export_bytes(),
        original_session_key.export_bytes(),
        "Forwarding must not change the session key"
    );
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn forwarding_full() {
    let date = test_date();
    let msg = "hello";

    let forwarder = import_unlocked(TEST_KEY_V4);

    let encrypted = Encryptor::default()
        .with_encryption_key(forwarder.as_public_key())
        .encrypt(msg.as_bytes())
        .unwrap();

    let encrypted_bytes = encrypted.to_bytes().unwrap();

    let (forwardee_key, instances) = forwarder
        .forwarding_key_generator()
        .with_user_id("forwardee@example.com", "forwardee@example.com")
        .at_date(date)
        .generate()
        .expect("Generation should succeed");

    let pkesk = ForwardingPkesk::from_bytes(encrypted.as_key_packets_unchecked()).unwrap();

    let [forwarded] = pkesk
        .proxy_forward(&instances)
        .unwrap()
        .try_into()
        .expect("Expected exactly one forwarded PKESK");

    let mut forwarded_msg = forwarded.to_vec().unwrap();
    forwarded_msg.extend_from_slice(encrypted.as_data_packet_unchecked());

    let decrypted = Decryptor::default()
        .allow_forwarding_decryption(true)
        .with_decryption_key(&forwardee_key)
        .decrypt(forwarded_msg, DataEncoding::Unarmored)
        .unwrap();

    assert_eq!(decrypted.data, msg.as_bytes());

    // Old message decryption fails
    Decryptor::default()
        .allow_forwarding_decryption(true)
        .with_decryption_key(&forwardee_key)
        .decrypt(encrypted_bytes, DataEncoding::Unarmored)
        .expect_err("decryption should fail");
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn forwarding_full_preserves_the_signature() {
    let forwarder = import_unlocked(TEST_KEY_V4);
    let sender = KeyGenerator::default()
        .with_user_id("sender", "sender@test.test")
        .with_key_type(KeyGenerationType::ECC)
        .at_date(test_date())
        .generate()
        .expect("Failed to generate key");

    let encrypted = Encryptor::default()
        .with_encryption_key(forwarder.as_public_key())
        .with_signing_key(&sender)
        .at_date(test_date().into())
        .encrypt(b"signed and forwarded")
        .expect("Failed to encrypt");

    let (forwardee, instances) = forwarder
        .forwarding_key_generator()
        .with_user_id("forwardee", "forwardee@test.test")
        .at_date(test_date())
        .generate()
        .expect("Generation should succeed");

    let forwarded_message =
        proxy_forward_message(&encrypted, &instances).expect("Failed to forward");

    let decrypted = Decryptor::default()
        .allow_forwarding_decryption(true)
        .with_decryption_key(&forwardee)
        .with_verification_key(sender.as_public_key())
        .at_date(test_date().into())
        .decrypt(forwarded_message, DataEncoding::Unarmored)
        .expect("Failed to decrypt forwarded message");

    assert_eq!(decrypted.data, b"signed and forwarded");
    assert!(
        decrypted.verification_result.is_ok(),
        "The signature of the original sender must still verify: {:?}",
        decrypted.verification_result
    );
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn forwarding_decryption_requires_the_forwarding_flag() {
    let forwarder = import_unlocked(TEST_KEY_V4);
    let encrypted = encrypt_to(&forwarder, b"hello");

    let (forwardee, instances) = forwarder
        .forwarding_key_generator()
        .with_user_id("forwardee", "forwardee@test.test")
        .at_date(test_date())
        .generate()
        .expect("Generation should succeed");

    let forwarded_message =
        proxy_forward_message(&encrypted, &instances).expect("Failed to forward");

    let result = Decryptor::default()
        .with_decryption_key(&forwardee)
        .at_date(test_date().into())
        .decrypt(forwarded_message, DataEncoding::Unarmored);

    assert!(
        result.is_err(),
        "Forwarding decryption must be opt-in, got {result:?}"
    );
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn forwarding_generated_key_cannot_decrypt_the_original_message() {
    let forwarder = import_unlocked(TEST_KEY_V4);
    let encrypted = encrypt_to(&forwarder, b"hello");

    let (forwardee, _) = forwarder
        .forwarding_key_generator()
        .with_user_id("forwardee", "forwardee@test.test")
        .at_date(test_date())
        .generate()
        .expect("Generation should succeed");

    let result = Decryptor::default()
        .allow_forwarding_decryption(true)
        .with_decryption_key(&forwardee)
        .at_date(test_date().into())
        .decrypt(
            encrypted.to_bytes().expect("Failed to encode message"),
            DataEncoding::Unarmored,
        );

    assert!(
        result.is_err(),
        "The untransformed message must not be readable by the forwardee, got {result:?}"
    );

    // The forwarder however still decrypts its own message.
    let decrypted = Decryptor::default()
        .with_decryption_key(&forwarder)
        .at_date(test_date().into())
        .decrypt(
            encrypted.to_bytes().expect("Failed to encode message"),
            DataEncoding::Unarmored,
        )
        .expect("The forwarder must still decrypt its own message");
    assert_eq!(decrypted.data, b"hello");
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn forwarding_message_proxy_forward() {
    let forwarder = import_unlocked(TEST_KEY_V4);
    let encrypted = encrypt_to(&forwarder, b"hello");
    let data_packet = encrypted.as_data_packet_unchecked().to_vec();

    let (forwardee, instances) = forwarder
        .forwarding_key_generator()
        .with_user_id("forwardee", "forwardee@test.test")
        .at_date(test_date())
        .generate()
        .expect("Generation should succeed");

    let forwarded = encrypted
        .proxy_forward(&instances)
        .expect("Failed to forward message");

    assert_eq!(
        forwarded.as_data_packet_unchecked(),
        data_packet,
        "Forwarding must not change the data packet"
    );

    let decrypted = Decryptor::default()
        .allow_forwarding_decryption(true)
        .with_decryption_key(&forwardee)
        .at_date(test_date().into())
        .decrypt(
            forwarded.to_bytes().expect("Failed to encode message"),
            DataEncoding::Unarmored,
        )
        .expect("Failed to decrypt forwarded message");

    assert_eq!(decrypted.data, b"hello");
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn forwarding_message_proxy_forward_drops_unmatched_key_packets() {
    let forwarder = import_unlocked(TEST_KEY_V4);
    let other = KeyGenerator::default()
        .with_user_id("other", "other@test.test")
        .with_key_type(KeyGenerationType::ECC)
        .at_date(test_date())
        .generate()
        .expect("Failed to generate key");

    let encrypted = Encryptor::default()
        .with_encryption_key(forwarder.as_public_key())
        .with_encryption_key(other.as_public_key())
        .at_date(test_date().into())
        .encrypt(b"hello")
        .expect("Failed to encrypt");
    assert_eq!(encrypted.encryption_key_ids().len(), 2);

    let (forwardee, instances) = forwarder
        .forwarding_key_generator()
        .with_user_id("forwardee", "forwardee@test.test")
        .at_date(test_date())
        .generate()
        .expect("Generation should succeed");

    let forwarded = encrypted
        .proxy_forward(&instances)
        .expect("Failed to forward message");

    // Only the transformed PKESK for the forwardee remains.
    assert_eq!(forwarded.encryption_key_ids().len(), 1);

    let decrypted = Decryptor::default()
        .allow_forwarding_decryption(true)
        .with_decryption_key(&forwardee)
        .at_date(test_date().into())
        .decrypt(
            forwarded.to_bytes().expect("Failed to encode message"),
            DataEncoding::Unarmored,
        )
        .expect("Failed to decrypt forwarded message");

    assert_eq!(decrypted.data, b"hello");
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn forwarding_message_proxy_forward_without_matching_instance_fails() {
    let forwarder = import_unlocked(TEST_KEY_V4);
    let other = KeyGenerator::default()
        .with_user_id("other", "other@test.test")
        .with_key_type(KeyGenerationType::ECC)
        .at_date(test_date())
        .generate()
        .expect("Failed to generate key");
    let encrypted = encrypt_to(&other, b"hello");

    let (_, instances) = forwarder
        .forwarding_key_generator()
        .with_user_id("forwardee", "forwardee@test.test")
        .at_date(test_date())
        .generate()
        .expect("Generation should succeed");

    assert!(matches!(
        encrypted.clone().proxy_forward(&instances),
        Err(Error::ForwardingTransform(
            ForwardingTransformError::NoPkeskFound
        ))
    ));

    let empty: [ForwardingInstance; 0] = [];
    assert!(matches!(
        encrypted.proxy_forward(&empty),
        Err(Error::ForwardingTransform(
            ForwardingTransformError::NoPkeskFound
        ))
    ));
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn forwarding_recursive() {
    let profile = Profile::default();
    let alice = import_unlocked(TEST_KEY_V4);
    let encrypted = encrypt_to(&alice, b"hello charly");

    // Alice forwards to Bob.
    let (bob, alice_to_bob) = alice
        .forwarding_key_generator()
        .with_user_id("bob", "bob@test.test")
        .at_date(test_date())
        .generate()
        .expect("Generation of Bob's forwarding key should succeed");

    // Bob forwards his forwarding key to Charly.
    let (charly, bob_to_charly) = bob
        .forwarding_key_generator()
        .with_user_id("charly", "charly@test.test")
        .at_date(test_date())
        .generate()
        .expect("Generation of Charly's forwarding key should succeed");

    assert!(charly.is_forwarding_key(&profile));
    assert_eq!(bob_to_charly.len(), 1);

    // Charly's subkey must mix Alice's fingerprint into the KDF, since the
    // original message was encrypted to Alice.
    let EcdhPublicParams::Curve25519Legacy { ecdh_kdf_type, .. } = subkey_ecdh_params(&charly, 0)
    else {
        panic!("Forwardee subkey is not a legacy curve25519 key");
    };
    let Fingerprint::V4(alice_fingerprint) = subkey_fingerprint(&alice, 0) else {
        panic!("Forwarder subkey is not a v4 key");
    };
    assert_eq!(
        ecdh_kdf_type,
        EcdhKdfType::Replaced {
            replacement_fingerprint: alice_fingerprint
        }
    );

    // The proxy transforms the message twice.
    let to_bob = encrypted
        .proxy_forward(&alice_to_bob)
        .expect("Failed to forward to Bob");
    let to_charly = to_bob
        .clone()
        .proxy_forward(&bob_to_charly)
        .expect("Failed to forward to Charly");

    // Bob can still read the message forwarded to him.
    let decrypted = Decryptor::default()
        .allow_forwarding_decryption(true)
        .with_decryption_key(&bob)
        .at_date(test_date().into())
        .decrypt(
            to_bob.to_bytes().expect("Failed to encode message"),
            DataEncoding::Unarmored,
        )
        .expect("Bob failed to decrypt the forwarded message");
    assert_eq!(decrypted.data, b"hello charly");

    let decrypted = Decryptor::default()
        .allow_forwarding_decryption(true)
        .with_decryption_key(&charly)
        .at_date(test_date().into())
        .decrypt(
            to_charly.to_bytes().expect("Failed to encode message"),
            DataEncoding::Unarmored,
        )
        .expect("Charly failed to decrypt the recursively forwarded message");
    assert_eq!(decrypted.data, b"hello charly");

    // Charly cannot read the message that was only forwarded to Bob.
    let result = Decryptor::default()
        .allow_forwarding_decryption(true)
        .with_decryption_key(&charly)
        .at_date(test_date().into())
        .decrypt(
            to_bob.to_bytes().expect("Failed to encode message"),
            DataEncoding::Unarmored,
        );
    assert!(result.is_err());
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn forwarding_wildcard_pkesk_gets_forwardee_key_id() {
    let date = test_date();
    let forwarder = import_unlocked(TEST_KEY_V4);
    let encrypted = encrypt_to(&forwarder, b"hello wildcard");

    let (forwardee, instances) = forwarder
        .forwarding_key_generator()
        .with_user_id("forwardee", "forwardee@test.test")
        .at_date(date)
        .generate()
        .expect("Generation should succeed");

    let pkesk = ForwardingPkesk::from_bytes(encrypted.as_key_packets_unchecked())
        .expect("Failed to parse PKESK");
    let PublicKeyEncryptedSessionKey::V3 {
        packet_header,
        pk_algo,
        values,
        ..
    } = PublicKeyEncryptedSessionKey::from(pkesk)
    else {
        panic!("Expected a v3 PKESK");
    };
    let pkesk = ForwardingPkesk::try_from(PublicKeyEncryptedSessionKey::V3 {
        packet_header,
        id: KeyId::WILDCARD,
        pk_algo,
        values,
    })
    .expect("Wildcard PKESK must be valid for forwarding");

    let [forwarded] = pkesk
        .proxy_forward(&instances)
        .expect("Failed to forward")
        .try_into()
        .expect("Expected exactly one forwarded PKESK");

    let forwardee_key_id = instances
        .first()
        .expect("Missing forwarding instance")
        .forwardee_fingerprint()
        .key_id()
        .expect("Missing forwardee key id");
    assert_eq!(
        forwarded.pkesk().id().expect("Missing key id"),
        &forwardee_key_id
    );

    let mut forwarded_msg = forwarded.to_vec().expect("Failed to encode PKESK");
    forwarded_msg.extend_from_slice(encrypted.as_data_packet_unchecked());
    let decrypted = Decryptor::default()
        .allow_forwarding_decryption(true)
        .with_decryption_key(&forwardee)
        .at_date(date.into())
        .decrypt(forwarded_msg, DataEncoding::Unarmored)
        .expect("Forwardee failed to decrypt");
    assert_eq!(decrypted.data, b"hello wildcard");
}
