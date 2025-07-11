use pgp::{
    crypto::hash::HashAlgorithm,
    types::{PublicKeyTrait, PublicParams},
};

use crate::{PrivateKey, Profile, PublicKeySelectionExt, SignHashSelectionError, UnixTime};

const HASH_ALGORITHMS_MID: &[HashAlgorithm] = &[
    HashAlgorithm::Sha512,
    HashAlgorithm::Sha3_512,
    HashAlgorithm::Sha384,
];

const HASH_ALGORITHMS_HIGH: &[HashAlgorithm] = &[HashAlgorithm::Sha512, HashAlgorithm::Sha3_512];

pub fn select_hash_algorithm_from_keys<'a>(
    date: UnixTime,
    preferred_hash: HashAlgorithm,
    keys: &'a [&'a PrivateKey],
    profile: &'a Profile,
) -> Result<Vec<HashAlgorithm>, SignHashSelectionError> {
    let mut selected_hashes = Vec::with_capacity(keys.len());
    for key in keys {
        let mut candidates = profile.hash_algorithms().to_vec();
        let primary_self_certification = key
            .as_signed_public_key()
            .primary_self_signature(date, profile)?;
        let preferences = primary_self_certification.preferred_hash_algs();
        if !preferences.is_empty() {
            intersect(&mut candidates, preferences);
        }
        let selected_hash = select_hash_to_sign(
            candidates,
            preferred_hash,
            key.as_signed_public_key().public_params(),
            profile,
        );
        selected_hashes.push(selected_hash);
    }
    Ok(selected_hashes)
}

pub fn select_hash_to_sign(
    mut candidates: Vec<HashAlgorithm>,
    preferred_hash: HashAlgorithm,
    public_params: &PublicParams,
    profile: &Profile,
) -> HashAlgorithm {
    let acceptable_hashes = acceptable_sign_hash_algorithms(public_params, profile);
    intersect(&mut candidates, acceptable_hashes);

    if candidates.contains(&preferred_hash) {
        return preferred_hash;
    }

    if let Some(selection) = candidates.first() {
        *selection
    } else {
        acceptable_hashes[0]
    }
}

fn intersect<T: Copy + PartialEq>(order_determining: &mut Vec<T>, to_intersect: &[T]) {
    order_determining.retain(|alg| to_intersect.contains(alg));
}

fn acceptable_sign_hash_algorithms<'a>(
    public_params: &'a PublicParams,
    profile: &'a Profile,
) -> &'a [HashAlgorithm] {
    match public_params {
        PublicParams::ECDSA(ecdsa_public_params) => match ecdsa_public_params {
            pgp::types::EcdsaPublicParams::P384 { key: _ } => HASH_ALGORITHMS_MID,
            pgp::types::EcdsaPublicParams::P521 { key: _ } => HASH_ALGORITHMS_HIGH,
            _ => profile.hash_algorithms(),
        },
        PublicParams::Ed448(_) | PublicParams::MlDsa87Ed448(_) => HASH_ALGORITHMS_HIGH,
        _ => profile.hash_algorithms(),
    }
}
