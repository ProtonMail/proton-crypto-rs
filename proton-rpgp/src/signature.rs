use pgp::{
    packet::{RevocationCode, Signature, SignatureType, Subpacket, SubpacketData},
    ser::Serialize,
    types::PublicKeyTrait,
};

use crate::{types::UnixTime, Profile, PublicComponentKey, SignatureError};

mod message;
pub use message::*;

pub(crate) trait SignatureExt {
    fn is_issued_by<K: PublicKeyTrait + Serialize>(&self, key: &K) -> bool;

    fn is_revocation(&self) -> bool;

    fn is_hard_revocation(&self) -> bool;

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
        if let Some(expire_delta) = self.signature_expiration_time() {
            let expiration_date = *creation_time + *expire_delta;
            if date < UnixTime::from(creation_time) || date > UnixTime::from(&expiration_date) {
                return Err(SignatureError::Expired {
                    date,
                    creation: UnixTime::from(creation_time),
                    expiration: UnixTime::from(&expiration_date),
                });
            }
        }
        Ok(())
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

pub(crate) fn check_message_signature_details(
    date: UnixTime,
    signature: &Signature,
    selected_key: &PublicComponentKey<'_>,
    profile: &Profile,
) -> Result<(), SignatureError> {
    // Check the siganture details of the signature.
    check_signature_details(signature, date, profile)?;

    // Check if the signature is older than the key.
    let signature_creation_time = signature.unix_created_at()?;
    let key_creation_time = selected_key.unix_created_at();
    if signature_creation_time < key_creation_time {
        return Err(SignatureError::SignatureOlderThanKey {
            signature_date: signature_creation_time,
            key_date: key_creation_time,
        });
    }

    // Check key signatures details at the signature creation time.
    let check_time = if date.checks_disabled() {
        date
    } else {
        // Todo: This is dangerous with a 0 unix time. We should change it to optional. CRYPTO-291.
        signature_creation_time
    };
    check_signature_details(selected_key.primary_self_certification, check_time, profile)?;
    check_signature_details(selected_key.self_certification, check_time, profile)?;

    Ok(())
}
