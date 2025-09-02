//! This module provides functionality to verify the signature of the SRP modulus.
//!
//! In Proton's SRP protocol, the server supplies the SRP modulus that the client protocol operates with.
//! The server signs this modulus using its `OpenPGP` private key, and the client must verify the `OpenPGP` signature.
//!
//! Since `OpenPGP` is a large dependency, users of this library have the flexibility to either implement their own
//! [`ModulusSignatureVerifier`] or use the provided implementation, which leverages the `rPGP` library.
pub use verify_trait::*;

#[cfg(all(test, feature = "pgpinternal"))]
#[path = "tests/pgp_modulus.rs"]
mod tests;

/// Errors thrown by SRP modulus verification.
#[derive(Debug, thiserror::Error)]
pub enum ModulusVerifyError {
    #[error("Failed to import the server key for verifying the modulus: {0}")]
    KeyImport(String),
    #[error("Error occurred while processing the cleartext message of the modulus: {0}")]
    CleartextParse(String),
    #[error("Modulus signature verification failed: {0}")]
    SignatureVerification(String),
}

mod verify_trait {
    use crate::ModulusVerifyError;

    /// A trait for verifying the signature of an SRP modulus provided by the server.
    ///
    /// This trait is designed to allow flexibility in how the SRP modulus signature is verified. Implementers can
    /// choose to use a custom verifier with their own `OpenPGP` library or rely on a provided implementation that utilizes `rPGP`.
    pub trait ModulusSignatureVerifier {
        /// Verifies the signature of the modulus PGP message
        /// and extracts/returns the base64 encoded modulus.
        ///
        /// # Parameters
        ///
        /// * `modulus`     - A pgp message including the SRP modulus signed by the server.
        /// * `server_key`  - The server public key to verify the signature with.
        ///
        /// # Errors
        /// Returns a [`ModulusVerifyError`] if the verification fails in one of the steps.
        fn verify_and_extract_modulus(
            &self,
            modulus: &str,
            server_key: &str,
        ) -> Result<String, ModulusVerifyError>;
    }
}

#[cfg(feature = "pgpinternal")]
pub use rpgp_impl::*;

#[cfg(feature = "pgpinternal")]
mod rpgp_impl {
    use crate::{ModulusSignatureVerifier, ModulusVerifyError};
    use pgp::composed::{CleartextSignedMessage, Deserializable, SignedPublicKey};

    /// Implements [`ModulusSignatureVerifier`] by verifying the modulus with [`pgp`].
    #[derive(Default, Debug)]
    pub struct RPGPVerifier {}

    impl ModulusSignatureVerifier for RPGPVerifier {
        fn verify_and_extract_modulus(
            &self,
            modulus: &str,
            server_key: &str,
        ) -> Result<String, ModulusVerifyError> {
            let (public_key, _) = SignedPublicKey::from_string(server_key)
                .map_err(|err| ModulusVerifyError::KeyImport(err.to_string()))?;
            let (modulus_message, _) = CleartextSignedMessage::from_string(modulus)
                .map_err(|err| ModulusVerifyError::CleartextParse(err.to_string()))?;
            modulus_message
                .verify(&public_key)
                .map_err(|err| ModulusVerifyError::SignatureVerification(err.to_string()))?;
            Ok(modulus_message.text().to_owned())
        }
    }
}
