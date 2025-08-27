use pgp::{
    composed::Message,
    packet::{Signature, Subpacket, SubpacketData},
    types::KeyId,
};

use crate::{
    check_signature_details, types::UnixTime, AsPublicKeyRef, GenericKeyIdentifierList, KeyInfo,
    MessageProcessingError, MessageSignatureError, Profile, PublicComponentKey,
    PublicKeySelectionExt, SignatureContextError, SignatureError, SignatureExt, SignatureUsage,
    VerificationContext, LIB_ERROR_PREFIX,
};

/// The result of verifying signature in an `OpenPGP` message.
pub type VerificationResult = Result<VerificationInformation, VerificationError>;

/// Gives information about the verified signature.
#[derive(Debug, Clone)]
pub struct VerificationInformation {
    /// The `OpenPGP` key ID that the selected signature is signed with.
    pub key_id: KeyId,

    /// The creation time of the selected signature.
    pub signature_creation_time: UnixTime,

    /// The `OpenPGP` signature that has been verified.
    pub signature: Signature,
}

impl From<Signature> for VerificationInformation {
    fn from(signature: Signature) -> Self {
        Self::new(signature, None)
    }
}

impl VerificationInformation {
    pub fn new(signature: Signature, info: Option<KeyInfo>) -> Self {
        let key_id = if let Some(info) = info {
            info.key_id
        } else {
            // Fallback to the first issuer if no key info is provided.
            signature
                .issuer()
                .into_iter()
                .next()
                .copied()
                .unwrap_or(KeyId::new([0_u8; 8]))
        };

        Self {
            key_id,
            signature_creation_time: signature.unix_created_at().unwrap_or_default(),
            signature,
        }
    }
}

/// Errors that can occur when verifying a signature.
#[derive(Debug, Clone, thiserror::Error)]
pub enum VerificationError {
    #[error("{LIB_ERROR_PREFIX}: No signature found")]
    NotSigned,

    #[error("{LIB_ERROR_PREFIX}: No valid verification keys found for signature {0}: {1}")]
    NoVerifier(GenericKeyIdentifierList, String),

    #[error("{LIB_ERROR_PREFIX}: Signature verification failed: {1}")]
    Failed(Box<VerificationInformation>, String),

    /// Signature context did not match verification context.
    #[error("{LIB_ERROR_PREFIX}: Signature context does not match the verification context: {1}")]
    BadContext(Box<VerificationInformation>, String),

    /// Unknown error occurred.
    #[error("{LIB_ERROR_PREFIX}: Runtime error: {0}")]
    RuntimeError(String),
}

/// A creator for verification results.
pub(crate) struct VerificationResultCreator {}

impl VerificationResultCreator {
    /// Create a verification result from a list of verified signatures.
    ///
    /// Selects result for the first signature that is valid or the last one if no valid signature is found.
    pub fn with_signatures(verifications: Vec<VerifiedSignature>) -> VerificationResult {
        let mut selected_signature = None;
        for verification in verifications {
            if verification.verification_result.is_ok() {
                selected_signature = Some(verification);
                break;
            }
            selected_signature = Some(verification);
        }

        if let Some(selected_signature) = selected_signature {
            selected_signature.into_verification_result()
        } else {
            Err(VerificationError::NotSigned)
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum VerificationInput<'a> {
    Message(&'a Message<'a>),
    Data(&'a [u8]),
}

/// Represents an internal verified signature.
#[derive(Debug)]
pub(crate) struct VerifiedSignature {
    /// The signature that has been verified.
    pub signature: Signature,

    /// The key information that has been used to verify the signature.
    pub verified_by: Option<KeyInfo>,

    /// The result of the verification.
    pub verification_result: Result<(), MessageSignatureError>,
}

impl VerifiedSignature {
    /// Create a verified signature by verifying the signature with the given public keys.
    pub fn create_by_verifying(
        date: UnixTime,
        signature: Signature,
        with_public_keys: &[impl AsPublicKeyRef],
        data_to_verify: VerificationInput<'_>,
        context: Option<&VerificationContext>,
        profile: &Profile,
    ) -> Self {
        // Select the verification keys from the list of public keys.
        // The keys are selected based on the signature issuer's key ID list.
        let verification_candidates =
            match Self::select_verification_keys(&signature, with_public_keys, profile) {
                Ok(candidates) => candidates,
                Err(error) => {
                    return Self {
                        signature,
                        verified_by: None,
                        verification_result: Err(error),
                    };
                }
            };

        // Try to verify the signature with the selected keys.
        // Most of the time, there is only one key in the list, but there
        // might be collisions on the key id.
        let mut verification_result = Ok(());
        let mut verified_by = None;
        for candidate in verification_candidates {
            verification_result = match data_to_verify {
                VerificationInput::Message(message) => candidate
                    .verify_message_signature_with_message(
                        date, &signature, message, context, profile,
                    ),
                VerificationInput::Data(input_data) => candidate
                    .verify_message_signature_with_data(
                        date, &signature, input_data, context, profile,
                    ),
            };
            if verification_result.is_ok() {
                verified_by = Some(candidate.into());
                break;
            }
        }

        Self {
            signature,
            verified_by,
            verification_result,
        }
    }

    /// Helper function to select verification keys for a signature.
    fn select_verification_keys<'a>(
        signature: &Signature,
        public_keys: &'a [impl AsPublicKeyRef],
        profile: &Profile,
    ) -> Result<Vec<PublicComponentKey<'a>>, MessageSignatureError> {
        let mut verification_candidates = Vec::new();
        let signature_creation_time = signature.unix_created_at()?;

        let mut key_selection_errors = Vec::new();
        for key in public_keys {
            let keys = match key
                .as_public_key()
                .as_signed_public_key()
                .verification_keys(
                    signature_creation_time,
                    signature.issuer_generic_identifier(),
                    SignatureUsage::Sign,
                    profile,
                ) {
                Ok(keys) => keys,
                Err(error) => {
                    key_selection_errors.push(error);
                    continue;
                }
            };
            verification_candidates.extend(keys);
        }
        if verification_candidates.is_empty() {
            return Err(MessageSignatureError::NoMatchingKey(
                key_selection_errors.into(),
            ));
        }
        Ok(verification_candidates)
    }

    /// Convert the verified signature to a verification result.
    pub fn into_verification_result(self) -> Result<VerificationInformation, VerificationError> {
        match self.verification_result {
            Ok(()) => Ok(VerificationInformation::new(
                self.signature,
                self.verified_by,
            )),
            Err(MessageSignatureError::Failed(err)) => Err(VerificationError::Failed(
                Box::new(VerificationInformation::new(
                    self.signature,
                    self.verified_by,
                )),
                err.to_string(),
            )),
            Err(MessageSignatureError::NoMatchingKey(err)) => Err(VerificationError::NoVerifier(
                self.signature.issuer_generic_identifier().into(),
                err.to_string(),
            )),
            Err(MessageSignatureError::Context(err)) => Err(VerificationError::BadContext(
                Box::new(VerificationInformation::new(
                    self.signature,
                    self.verified_by,
                )),
                err.to_string(),
            )),
        }
    }
}

/// Additional checks for signatures that are verified in a message.
pub(crate) fn check_message_signature_details(
    date: UnixTime,
    signature: &Signature,
    selected_key: &PublicComponentKey<'_>,
    context: Option<&VerificationContext>,
    profile: &Profile,
) -> Result<(), MessageSignatureError> {
    // Check the used message hash algorithm, might reject more than in the
    // default rejection.
    if profile.reject_message_hash_algorithm(signature.hash_alg()) {
        return Err(SignatureError::InvalidHash(signature.hash_alg()).into());
    }
    // Check the signature details of the signature.
    check_signature_details(signature, date, profile)?;

    // Check if the signature is older than the key.
    let signature_creation_time = signature.unix_created_at()?;
    let key_creation_time = selected_key.unix_created_at();
    if signature_creation_time < key_creation_time {
        return Err(SignatureError::SignatureOlderThanKey {
            signature_date: signature_creation_time,
            key_date: key_creation_time,
        }
        .into());
    }

    let Some(config) = signature.config() else {
        return Err(SignatureError::ConfigAccess.into());
    };

    // Check the Proton signature context.
    if let Some(verification_context) = context {
        // If there is a verification context, we check if signature notations match the verification context.
        verification_context.check_subpackets(&config.hashed_subpackets, date)?;
    } else if let Some(criticial_context) =
        // If there is no verification context, we check if there is a critical Proton context in the notations.
        VerificationContext::filter_context(
            &config.hashed_subpackets,
        )
        .find_map(|subpacket| match subpacket {
            Subpacket {
                is_critical: true,
                data: SubpacketData::Notation(notation),
                ..
            } => Some(String::from_utf8_lossy(notation.value.as_ref()).to_string()),
            _ => None,
        })
    {
        return Err(MessageSignatureError::Context(
            SignatureContextError::CriticialContext(criticial_context),
        ));
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

/// Extension trait for [`pgp::composed::Message`] to verify signatures with our logic.
pub(crate) trait MessageVerificationExt {
    /// Verifies the nested signatures of the message.
    fn verify_nested_to_verified_signatures(
        &self,
        date: UnixTime,
        keys: &[impl AsPublicKeyRef],
        context: Option<&VerificationContext>,
        profile: &Profile,
    ) -> Result<Vec<VerifiedSignature>, MessageProcessingError>;
}

impl MessageVerificationExt for Message<'_> {
    /// Verifies the nested signatures of the message.
    fn verify_nested_to_verified_signatures(
        &self,
        date: UnixTime,
        keys: &[impl AsPublicKeyRef],
        context: Option<&VerificationContext>,
        profile: &Profile,
    ) -> Result<Vec<VerifiedSignature>, MessageProcessingError> {
        let mut verification_results = Vec::new();

        let mut current_message = self;

        for _ in 0..profile.max_recursion_depth() {
            match current_message {
                Message::SignedOnePass { reader, .. } => {
                    let Some(signature) = reader.signature() else {
                        return Err(MessageProcessingError::NotFullyRead);
                    };
                    let result = VerifiedSignature::create_by_verifying(
                        date,
                        signature.clone(),
                        keys,
                        VerificationInput::Message(current_message),
                        context,
                        profile,
                    );
                    verification_results.push(result);
                    current_message = reader.get_ref();
                }
                Message::Signed { reader, .. } => {
                    let signature = reader.signature();
                    let result = VerifiedSignature::create_by_verifying(
                        date,
                        signature.clone(),
                        keys,
                        VerificationInput::Message(current_message),
                        context,
                        profile,
                    );
                    verification_results.push(result);
                    current_message = reader.get_ref();
                }
                Message::Literal { .. } => {
                    break;
                }
                Message::Compressed { .. } => {
                    return Err(MessageProcessingError::Compression);
                }
                Message::Encrypted { .. } => {
                    return Err(MessageProcessingError::Encrypted);
                }
            }
        }

        Ok(verification_results)
    }
}
