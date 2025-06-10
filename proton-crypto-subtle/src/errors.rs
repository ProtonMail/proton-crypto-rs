use std::io;

use aes_gcm::aead;

pub type SubtleResult<T> = Result<T, SubtleError>;

#[derive(Debug, thiserror::Error)]
pub enum SubtleError {
    #[error("Key has the wrong length")]
    InvalidKeyLength,

    #[error("The initialization vector has the wrong length")]
    InvalidIvLength,

    #[error("Failed to encrypt data: {0}")]
    Encrypt(aead::Error),

    #[error("Failed to decrypt data: {0}")]
    Decrypt(aead::Error),

    #[error("Failed to write data to the writer: {0}")]
    IoWrite(io::Error),
}
