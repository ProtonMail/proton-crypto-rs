use base64::DecodeError;

#[derive(Debug, thiserror::Error)]
pub enum ProofOfWorkError {
    #[error("Deadline exceeded")]
    DeadlineExceeded,
    #[error("Invalid challenge length")]
    InvalidChallengeLength,
    #[error("Failed decode base64 encoded challenge: {0}")]
    Base64Decode(#[from] DecodeError),
    #[error("An unexpected error occurred")]
    Unexpected,
    #[error("No solution found")]
    NoSolutionFound,
    #[error("Invalid challenge params")]
    InvalidChallengeParams,
}
