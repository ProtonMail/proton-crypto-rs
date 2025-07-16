use pgp::{
    packet::{RevocationCode, Signature, SignatureType, Subpacket, SubpacketData},
    ser::Serialize,
    types::PublicKeyTrait,
};

use crate::{types::UnixTime, GenericKeyIdentifier, Profile, SignatureError};

mod message;
pub use message::*;

pub(crate) mod core;

pub(crate) trait SignatureExt {
    fn is_issued_by<K: PublicKeyTrait + Serialize>(&self, key: &K) -> bool;

    fn is_revocation(&self) -> bool;

    fn is_hard_revocation(&self) -> bool;

    fn issuer_generic_identifier(&self) -> Vec<GenericKeyIdentifier>;

    fn unix_created_at(&self) -> Result<UnixTime, SignatureError>;

    fn check_not_expired(&self, date: UnixTime) -> Result<(), SignatureError>;
}

impl SignatureExt for Signature {
    fn is_issued_by<K: PublicKeyTrait + Serialize>(&self, key: &K) -> bool {
        self.issuer_fingerprint()
            .into_iter()
            .any(|fp| *fp == key.fingerprint())
            || self.issuer().into_iter().any(|fp| *fp == key.key_id())
    }

    fn is_revocation(&self) -> bool {
        matches!(
            self.typ(),
            Some(
                SignatureType::KeyRevocation
                    | SignatureType::CertRevocation
                    | SignatureType::SubkeyRevocation
            )
        )
    }

    fn is_hard_revocation(&self) -> bool {
        self.is_revocation()
            && matches!(
                self.revocation_reason_code(),
                Some(
                    RevocationCode::KeyRetired
                        | RevocationCode::CertUserIdInvalid
                        | RevocationCode::KeySuperseded
                )
            )
    }

    fn unix_created_at(&self) -> Result<UnixTime, SignatureError> {
        self.created()
            .map(UnixTime::from)
            .ok_or(SignatureError::NoCreationTime)
    }

    fn check_not_expired(&self, date: UnixTime) -> Result<(), SignatureError> {
        if date.checks_disabled() {
            return Ok(());
        }
        let creation_time = self.created().ok_or(SignatureError::NoCreationTime)?;
        let unix_creation_time = UnixTime::from(creation_time);
        if date < unix_creation_time {
            return Err(SignatureError::FutureSignature(unix_creation_time));
        }
        if let Some(expire_delta) = self.signature_expiration_time() {
            let expiration_date = UnixTime::from(*creation_time + *expire_delta);
            if expiration_date < date {
                return Err(SignatureError::Expired {
                    date,
                    creation: unix_creation_time,
                    expiration: expiration_date,
                });
            }
        }
        Ok(())
    }

    fn issuer_generic_identifier(&self) -> Vec<GenericKeyIdentifier> {
        let fingerprints = self.issuer_fingerprint();
        if !fingerprints.is_empty() {
            return fingerprints
                .into_iter()
                .map(|fp| GenericKeyIdentifier::Fingerprint(fp.clone()))
                .collect();
        }
        self.issuer()
            .into_iter()
            .map(|id| GenericKeyIdentifier::KeyId(*id))
            .collect()
    }
}

pub(crate) fn check_signature_details(
    signature: &Signature,
    date: UnixTime,
    profile: &Profile,
) -> Result<(), SignatureError> {
    // Check the used hash algorithm.
    if profile.reject_hash_algorithm(signature.hash_alg()) {
        return Err(SignatureError::InvalidHash(signature.hash_alg()));
    }

    // Check signature notations.
    let Some(config) = signature.config() else {
        return Err(SignatureError::ConfigAccess);
    };

    for sub_packet in &config.hashed_subpackets {
        if let Subpacket {
            is_critical: true,
            data: SubpacketData::Notation(notation),
            ..
        } = sub_packet
        {
            if !profile.accept_critical_notation(notation) {
                let name = String::from_utf8(notation.name.to_vec()).unwrap_or_default();
                return Err(SignatureError::CriticalNotation { name });
            }
        }
    }

    // Check signature expiration.
    signature.check_not_expired(date)?;
    Ok(())
}
