use pgp::{
    bytes::Bytes,
    composed::KeyDetails as ComposedKeyDetails,
    crypto::hash::HashAlgorithm,
    packet::{KeyFlags, Notation, SignatureConfig, SignatureType, Subpacket, SubpacketData},
    types::{KeyDetails, KeyVersion, PublicKeyTrait, SecretKeyTrait},
};
use rand::{CryptoRng, Rng};

use crate::{
    preferences::select_hash_to_sign_key_signatures, types::UnixTime, AnySecretKey,
    KeySigningError, Profile, SignError, SignatureContext, SignatureMode,
};

const SALT_NOTATION_NAME: &[u8] = b"salt@notations.openpgpjs.org";

/// Configures a Proton-specific signature config for a given private key.
///
/// The config is then used to create an `OpenPGP` signature over the input data.
pub fn configure_message_signature<R: Rng + CryptoRng>(
    private_key: &AnySecretKey<'_>,
    at_date: UnixTime,
    signature_mode: SignatureMode,
    hash_algorithm: HashAlgorithm,
    signature_context: Option<&SignatureContext>,
    mut rng: R,
) -> Result<SignatureConfig, SignError> {
    // Create a signature config based on the key version and hash algorithm.
    let mut config = match private_key.version() {
        KeyVersion::V4 => SignatureConfig::v4(
            signature_mode.into(),
            private_key.algorithm(),
            hash_algorithm,
        ),

        KeyVersion::V6 => SignatureConfig::v6(
            &mut rng,
            signature_mode.into(),
            private_key.algorithm(),
            hash_algorithm,
        )
        .map_err(SignError::Sign)?,
        _ => return Err(SignError::InvalidKeyVersion),
    };
    let (hashed_subpackets, unhashed_subpackets) = message_signature_subpackets(
        private_key,
        at_date,
        hash_algorithm,
        signature_context,
        &mut rng,
    )?;
    config.hashed_subpackets = hashed_subpackets;
    config.unhashed_subpackets = unhashed_subpackets;
    Ok(config)
}

pub fn message_signature_subpackets<R: Rng + CryptoRng>(
    private_key: &AnySecretKey<'_>,
    at_date: UnixTime,
    hash_algorithm: HashAlgorithm,
    signature_context: Option<&SignatureContext>,
    mut rng: R,
) -> Result<(Vec<Subpacket>, Vec<Subpacket>), SignError> {
    let mut hashed_subpackets = Vec::with_capacity(4);

    // Add the signature creation time subpacket.
    hashed_subpackets.push(
        Subpacket::critical(SubpacketData::SignatureCreationTime(at_date.into()))
            .map_err(SignError::Sign)?,
    );

    if private_key.version() < KeyVersion::V6 {
        // Add a regular Issuer (Key-Id) subpacket.
        hashed_subpackets.push(
            Subpacket::regular(SubpacketData::Issuer(private_key.key_id()))
                .map_err(SignError::Sign)?,
        );
        // Add a salt notation subpacket.
        hashed_subpackets.push(salt_notation(hash_algorithm, &mut rng).map_err(SignError::Sign)?);
        // Add an Issuer Fingerprint subpacket.
        hashed_subpackets.push(
            Subpacket::regular(SubpacketData::IssuerFingerprint(private_key.fingerprint()))
                .map_err(SignError::Sign)?,
        );
    } else {
        // Add a critical Issuer Fingerprint subpacket.
        hashed_subpackets.push(
            Subpacket::critical(SubpacketData::IssuerFingerprint(private_key.fingerprint()))
                .map_err(SignError::Sign)?,
        );
    }

    // Add the signature context if any.
    if let Some(signature_context) = signature_context {
        let notation = SubpacketData::Notation(Notation::from(signature_context.clone()));
        let subpacket_result = if signature_context.is_critical {
            Subpacket::critical(notation)
        } else {
            Subpacket::regular(notation)
        };
        hashed_subpackets.push(subpacket_result.map_err(SignError::Sign)?);
    }

    Ok((hashed_subpackets, Vec::new()))
}

#[allow(clippy::too_many_arguments)]
pub fn key_details_configure_signature<K, R, P>(
    private_key: &K,
    public_key: &P,
    at_date: UnixTime,
    preferred_hash: HashAlgorithm,
    typ: SignatureType,
    key_details: &ComposedKeyDetails,
    primary_user_id: bool,
    profile: &Profile,
    mut rng: R,
) -> Result<SignatureConfig, KeySigningError>
where
    P: PublicKeyTrait,
    K: SecretKeyTrait,
    R: Rng + CryptoRng,
{
    let hash_algorithm =
        select_hash_to_sign_key_signatures(preferred_hash, public_key.public_params(), profile);
    let mut config = match private_key.version() {
        KeyVersion::V4 => SignatureConfig::v4(typ, private_key.algorithm(), hash_algorithm),
        KeyVersion::V6 => {
            SignatureConfig::v6(&mut rng, typ, private_key.algorithm(), hash_algorithm)
                .map_err(KeySigningError::SignKeyDetails)?
        }
        _ => return Err(KeySigningError::InvalidKeyVersion),
    };

    config.hashed_subpackets = key_details_signature_subpackets(
        private_key,
        at_date,
        hash_algorithm,
        key_details,
        primary_user_id,
        &mut rng,
    )?;
    Ok(config)
}

pub fn key_details_signature_subpackets<K, R>(
    private_key: &K,
    at_date: UnixTime,
    hash_algorithm: HashAlgorithm,
    key_details: &ComposedKeyDetails,
    primary_user_id: bool,
    mut rng: R,
) -> Result<Vec<Subpacket>, KeySigningError>
where
    K: SecretKeyTrait,
    R: Rng + CryptoRng,
{
    let mut hashed_subpackets = Vec::with_capacity(11);

    hashed_subpackets.push(
        Subpacket::critical(SubpacketData::SignatureCreationTime(at_date.into()))
            .map_err(KeySigningError::SignKeyDetails)?,
    );

    hashed_subpackets.push(
        Subpacket::regular(SubpacketData::PreferredSymmetricAlgorithms(
            key_details.preferred_symmetric_algorithms.clone(),
        ))
        .map_err(KeySigningError::SignKeyDetails)?,
    );

    if private_key.version() < KeyVersion::V6 {
        hashed_subpackets.push(
            Subpacket::regular(SubpacketData::Issuer(private_key.key_id()))
                .map_err(KeySigningError::SignKeyDetails)?,
        );
        hashed_subpackets.push(
            salt_notation(hash_algorithm, &mut rng).map_err(KeySigningError::SignKeyDetails)?,
        );
    }

    hashed_subpackets.push(
        Subpacket::regular(SubpacketData::PreferredHashAlgorithms(
            key_details.preferred_hash_algorithms.clone(),
        ))
        .map_err(KeySigningError::SignKeyDetails)?,
    );

    hashed_subpackets.push(
        Subpacket::regular(SubpacketData::PreferredCompressionAlgorithms(
            key_details.preferred_compression_algorithms.clone(),
        ))
        .map_err(KeySigningError::SignKeyDetails)?,
    );

    if primary_user_id {
        hashed_subpackets.push(
            Subpacket::regular(SubpacketData::IsPrimary(true))
                .map_err(KeySigningError::SignKeyDetails)?,
        );
    }

    hashed_subpackets.push(
        Subpacket::regular(SubpacketData::KeyFlags(key_details.keyflags.clone()))
            .map_err(KeySigningError::SignKeyDetails)?,
    );

    hashed_subpackets.push(
        Subpacket::regular(SubpacketData::Features(key_details.features.clone()))
            .map_err(KeySigningError::SignKeyDetails)?,
    );

    if private_key.version() < KeyVersion::V6 {
        hashed_subpackets.push(
            Subpacket::regular(SubpacketData::IssuerFingerprint(private_key.fingerprint()))
                .map_err(KeySigningError::SignKeyDetails)?,
        );
    } else {
        hashed_subpackets.push(
            Subpacket::critical(SubpacketData::IssuerFingerprint(private_key.fingerprint()))
                .map_err(KeySigningError::SignKeyDetails)?,
        );
    }

    if !key_details.preferred_aead_algorithms.is_empty() {
        hashed_subpackets.push(
            Subpacket::regular(SubpacketData::PreferredAeadAlgorithms(
                key_details.preferred_aead_algorithms.clone(),
            ))
            .map_err(KeySigningError::SignKeyDetails)?,
        );
    }

    Ok(hashed_subpackets)
}

#[allow(clippy::too_many_arguments)]
pub fn sub_key_configure_signature<K, R, P>(
    private_key: &K,
    public_key: &P,
    at_date: UnixTime,
    preferred_hash: HashAlgorithm,
    typ: SignatureType,
    keyflags: KeyFlags,
    profile: &Profile,
    mut rng: R,
) -> Result<SignatureConfig, KeySigningError>
where
    P: PublicKeyTrait,
    K: SecretKeyTrait,
    R: Rng + CryptoRng,
{
    let hash_algorithm =
        select_hash_to_sign_key_signatures(preferred_hash, public_key.public_params(), profile);
    let mut config = match private_key.version() {
        KeyVersion::V4 => SignatureConfig::v4(typ, private_key.algorithm(), hash_algorithm),
        KeyVersion::V6 => {
            SignatureConfig::v6(&mut rng, typ, private_key.algorithm(), hash_algorithm)
                .map_err(KeySigningError::SignKeyDetails)?
        }
        _ => return Err(KeySigningError::InvalidKeyVersion),
    };

    config.hashed_subpackets =
        subkey_signature_subpackets(private_key, at_date, hash_algorithm, keyflags, &mut rng)?;
    Ok(config)
}

pub fn subkey_signature_subpackets<K, R>(
    private_key: &K,
    at_date: UnixTime,
    hash_algorithm: HashAlgorithm,
    keyflags: KeyFlags,
    mut rng: R,
) -> Result<Vec<Subpacket>, KeySigningError>
where
    K: SecretKeyTrait,
    R: Rng + CryptoRng,
{
    let mut hashed_subpackets = Vec::with_capacity(5);

    hashed_subpackets.push(
        Subpacket::critical(SubpacketData::SignatureCreationTime(at_date.into()))
            .map_err(KeySigningError::SignKeyDetails)?,
    );

    if private_key.version() < KeyVersion::V6 {
        hashed_subpackets.push(
            Subpacket::regular(SubpacketData::Issuer(private_key.key_id()))
                .map_err(KeySigningError::SignKeyDetails)?,
        );
        hashed_subpackets.push(
            salt_notation(hash_algorithm, &mut rng).map_err(KeySigningError::SignKeyDetails)?,
        );
    }

    hashed_subpackets.push(
        Subpacket::regular(SubpacketData::KeyFlags(keyflags))
            .map_err(KeySigningError::SignKeyDetails)?,
    );

    if private_key.version() < KeyVersion::V6 {
        hashed_subpackets.push(
            Subpacket::regular(SubpacketData::IssuerFingerprint(private_key.fingerprint()))
                .map_err(KeySigningError::SignKeyDetails)?,
        );
    } else {
        hashed_subpackets.push(
            Subpacket::critical(SubpacketData::IssuerFingerprint(private_key.fingerprint()))
                .map_err(KeySigningError::SignKeyDetails)?,
        );
    }

    Ok(hashed_subpackets)
}

/// Creates a salt notation for a v4 signature.
///
/// Example:
/// ```text
///   Notation: salt@notations.openpgpjs.org
///     00000000  33 fd e5 72 fa b0 1c 75  fa 59 a7 19 ab 09 f5 35
///     00000010  9a e8 81 b3 af f6 49 98  ec 1e c0 11 c1 10 1b 5b
/// ```
fn salt_notation<R: Rng + CryptoRng>(
    hash_algorithm: HashAlgorithm,
    rng: &mut R,
) -> Result<Subpacket, pgp::errors::Error> {
    let salt_size = hash_algorithm.salt_len().unwrap_or(16);
    let mut salt = vec![0; salt_size];
    rng.fill_bytes(&mut salt);

    Subpacket::regular(SubpacketData::Notation(Notation {
        name: Bytes::from(SALT_NOTATION_NAME.to_vec()),
        value: Bytes::from(salt),
        readable: false,
    }))
}
