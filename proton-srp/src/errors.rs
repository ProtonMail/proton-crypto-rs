use base64::DecodeError;

use crate::ModulusVerifyError;

/// Errors thrown by by the SRP authenticator.
#[derive(Debug, thiserror::Error)]
pub enum SRPError {
    #[error("Failed decode base64 encoded parameter: {0}")]
    Base64Decode(#[from] DecodeError),
    #[error("bcrypt error: {0}")]
    BcryptError(#[from] bcrypt::BcryptError),
    /// `ModulusVerify` is thrown if modulus extraction/verification from
    /// the PGP message fails.
    ///
    /// See [`ModulusSignatureVerifier`].
    #[error("Invalid SRP modulus: {0}")]
    ModulusVerify(#[from] ModulusVerifyError),
    #[error("Invalid SRP multiplier")]
    InvalidMultiplier,
    #[error("Invalid SRP scrambling parameter")]
    InvalidScramblingParameter,
    #[error("Invalid SRP salt: {0}")]
    InvalidSalt(&'static str),
    #[error("Invalid SRP verifier")]
    InvalidVerifier,
    #[error("Invalid SRP generator")]
    InvalidGenerator,
    #[error("Invalid SRP server ephemeral")]
    InvalidServerEphemeral,
    #[error("Invalid SRP client ephemeral")]
    InvalidClientEphemeral,
    #[error("Invalid SRP client proof")]
    InvalidClientProof,
    #[error("Invalid SRP modulus: {0}")]
    InvalidModulus(&'static str),
    #[error("Failed to find client secret")]
    CannotFindClientSecret,
    #[error("The SRP protocol version is not supported by this implementation")]
    UnsupportedVersion,
}

/// Errors thrown by by the SRP authenticator.
#[derive(Debug, thiserror::Error)]
pub enum MailboxHashError {
    #[error("bcrypt error: {0}")]
    BcryptError(#[from] bcrypt::BcryptError),
    #[error("Invalid salt provided")]
    InvalidSalt,
}
