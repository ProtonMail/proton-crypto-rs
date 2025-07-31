use pgp::{
    bytes::Bytes,
    crypto::hash::HashAlgorithm,
    packet::{Notation, SignatureConfig, Subpacket, SubpacketData},
    types::{KeyDetails, KeyVersion},
};
use rand::{CryptoRng, Rng};

use crate::{types::UnixTime, AnySecretKey, SignError, SignatureMode};

const SALT_NOTATION_NAME: &[u8] = b"salt@notations.openpgpjs.org";

/// Configures a Proton-specific signature config for a given private key.
///
/// The config is then used to create an `OpenPGP` signature over the input data.
pub fn configure_signature<R: Rng + CryptoRng>(
    private_key: &AnySecretKey<'_>,
    at_date: UnixTime,
    signature_mode: SignatureMode,
    hash_algorithm: HashAlgorithm,
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
    let (hashed_subpackets, unhashed_subpackets) =
        hashed_subpackets(private_key, at_date, hash_algorithm, &mut rng)?;
    config.hashed_subpackets = hashed_subpackets;
    config.unhashed_subpackets = unhashed_subpackets;
    Ok(config)
}

pub fn hashed_subpackets<R: Rng + CryptoRng>(
    private_key: &AnySecretKey<'_>,
    at_date: UnixTime,
    hash_algorithm: HashAlgorithm,
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
        hashed_subpackets.push(salt_notation(hash_algorithm, &mut rng)?);
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
    Ok((hashed_subpackets, Vec::new()))
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
) -> Result<Subpacket, SignError> {
    let salt_size = hash_algorithm.salt_len().unwrap_or(16);
    let mut salt = vec![0; salt_size];
    rng.fill_bytes(&mut salt);

    Subpacket::regular(SubpacketData::Notation(Notation {
        name: Bytes::from(SALT_NOTATION_NAME.to_vec()),
        value: Bytes::from(salt),
        readable: false,
    }))
    .map_err(SignError::Sign)
}
