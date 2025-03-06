// TODO: This should be moved to a key transparency crate.

pub type KTVerificationResult = Result<(), VerificationError>;
pub const KT_UNVERIFIED: KTVerificationResult = Err(VerificationError::Unverified);
pub const KT_VERIFIED: KTVerificationResult = Ok(());

/// Represents a key transparency public key verification error
#[derive(Debug, Clone, thiserror::Error)]
pub enum VerificationError {
    /// No signature found.
    #[error("Key transparency verification failed: {0}")]
    Failed(#[from] KTFailure),
    #[error("No key transparency verification performed")]
    Unverified,
}

/// Represents a key transparency public key verification error
#[derive(Debug, Clone, thiserror::Error)]
pub enum KTFailure {}

impl VerificationError {
    pub fn failed(&self) -> bool {
        matches!(self, VerificationError::Failed(_))
    }

    pub fn unverified(&self) -> bool {
        matches!(self, VerificationError::Unverified)
    }
}
