use pgp::{
    armor::BlockType,
    packet::{Packet, PacketParser},
};

use crate::{
    armor,
    signature::{
        VerificationError, VerificationResult, VerificationResultCreator, VerifiedSignature,
    },
    DataEncoding, Profile, PublicKey, UnixTime, DEFAULT_PROFILE,
};

/// Verifer type to verify `OpenPGP` signatures.
#[derive(Debug, Clone)]
pub struct Verifier<'a> {
    /// The profile to use for verification.
    profile: &'a Profile,

    /// The verification keys that are used to verify the signatures.
    verification_keys: Vec<&'a PublicKey>,

    /// The date to verify the signature against.
    date: UnixTime,
}

impl<'a> Verifier<'a> {
    /// Create a new verifier with the given profile.
    pub fn new(profile: &'a Profile) -> Self {
        Self {
            profile,
            verification_keys: Vec::new(),
            date: UnixTime::now().unwrap_or_default(),
        }
    }

    /// Set the verification key to use.
    pub fn with_verification_key(mut self, key: &'a PublicKey) -> Self {
        self.verification_keys.push(key);
        self
    }

    /// Set the verification keys to use.
    pub fn with_verification_keys(mut self, keys: impl IntoIterator<Item = &'a PublicKey>) -> Self {
        self.verification_keys.extend(keys);
        self
    }

    /// Set the date to verify the signature against.
    ///
    /// In default mode, the system clock is used.
    pub fn at_date(mut self, date: UnixTime) -> Self {
        self.date = date;
        self
    }

    /// Verifies a detached signature against the data.
    pub fn verify_detached(
        self,
        data: impl AsRef<[u8]>,
        signature: impl AsRef<[u8]>,
        signature_encoding: DataEncoding,
    ) -> VerificationResult {
        // The buffer is only used if the signature is encoded in armor.
        let mut buffer = Vec::new();

        // Check encoding.
        let parser =
            handle_signature_encoding(&mut buffer, signature.as_ref(), signature_encoding)?;

        // Verify signatures.
        let verified_signatures: Vec<_> = parser
            .filter_map(|packet_result| match packet_result {
                Ok(Packet::Signature(signature)) => Some(signature),
                _ => None,
            })
            .map(|signature| {
                VerifiedSignature::create_by_verifying(
                    self.date,
                    signature,
                    &self.verification_keys,
                    data.as_ref(),
                    self.profile,
                )
            })
            .collect();

        // Select the result.
        VerificationResultCreator::with_signatures(verified_signatures)
    }
}

impl Default for Verifier<'_> {
    fn default() -> Self {
        Self::new(&DEFAULT_PROFILE)
    }
}

fn handle_signature_encoding<'a>(
    buffer: &'a mut Vec<u8>,
    signature: &'a [u8],
    signature_encoding: DataEncoding,
) -> Result<PacketParser<&'a [u8]>, VerificationError> {
    match signature_encoding {
        DataEncoding::Binary => Ok(PacketParser::new(signature)),
        DataEncoding::Armor => {
            armor::decode_to_buffer(signature, Some(BlockType::Signature), buffer)
                .map_err(|err| VerificationError::RuntimeError(err.to_string()))?;
            Ok(PacketParser::new(buffer.as_slice()))
        }
    }
}
