use base64::{prelude::BASE64_STANDARD as BASE_64, Engine as _};
use crypto_bigint::subtle::ConstantTimeEq;

use crate::{ModulusSignatureVerifier, SRPError, PROTON_SRP_VERSION};

#[cfg(test)]
#[path = "../tests/srp.rs"]
mod tests;

mod core;
use core::SRPAuthData;
pub use core::{SALT_LEN_BYTES, SRP_LEN_BYTES};

#[cfg(test)]
use core::TEST_CLIENT_SECRET_LEN;

/// Represents client SRP proof generated from a request by the SRP server.
#[derive(Debug, Clone)]
pub struct SRPProof {
    /// The client ephemeral encoded in bytes.
    pub client_ephemeral: [u8; SRP_LEN_BYTES],

    /// The client proof encoded in bytes.
    pub client_proof: [u8; SRP_LEN_BYTES],

    /// The expected server proof encoded in bytes.
    pub expected_server_proof: [u8; SRP_LEN_BYTES],
}

impl SRPProof {
    /// Compare in constant time that the server proof is equal to the client's computation
    #[must_use]
    pub fn compare_server_proof(&self, server_proof: &[u8]) -> bool {
        self.expected_server_proof.ct_eq(server_proof).into()
    }
}

/// The `SRPProofB64` type represents client proof generated from a request by the SRP server.
///
/// Internally stores the values in base64 encoding as required by the API.
#[derive(Debug, Clone)]
pub struct SRPProofB64 {
    /// The client ephemeral encoded as a base64 encoded string.
    pub client_ephemeral: String,

    /// The client proof encoded as a base64 encoded string.
    pub client_proof: String,

    /// The expected server proof encoded as a base64 encoded string.
    pub expected_server_proof: String,
}

impl From<SRPProof> for SRPProofB64 {
    fn from(value: SRPProof) -> Self {
        SRPProofB64 {
            client_ephemeral: BASE_64.encode(value.client_ephemeral),
            client_proof: BASE_64.encode(value.client_proof),
            expected_server_proof: BASE_64.encode(value.expected_server_proof),
        }
    }
}

impl SRPProofB64 {
    /// Compare that the server proof is equal to the client's computation
    #[must_use]
    pub fn compare_server_proof(&self, server_proof: &str) -> bool {
        // Note that b64 decode is not constant time for now.
        let Ok(expected_server_proof) = BASE_64.decode(&self.expected_server_proof) else {
            return false;
        };
        let Ok(server_proof_decoded) = BASE_64.decode(server_proof) else {
            return false;
        };
        expected_server_proof.ct_eq(&server_proof_decoded).into()
    }
}

/// The type represents a client SRP verifier that is required to register with the server.
///
/// A `SRPVerifier` is required for example on Proton account creation or password reset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SRPVerifier {
    /// The Proton SRP protocol version.
    pub version: u8,

    /// The randomly generated salt.
    pub salt: [u8; SALT_LEN_BYTES],

    /// The SRP verifier
    pub verifier: [u8; SRP_LEN_BYTES],
}

/// The type represents a client SRP verifier where the byte values are encoded as base64 strings.
///
/// A `SRPVerifier` is required for example on Proton account creation or password reset.
/// Internally stores the values in base64 encoding as required by the API.
#[derive(Debug, Clone)]
pub struct SRPVerifierB64 {
    /// The Proton SRP protocol version.
    pub version: u8,

    /// The randomly generated salt encoded as a base64 string.
    pub salt: String,

    /// The SRP verifier encoded as a base64 string.
    pub verifier: String,
}

impl From<SRPVerifier> for SRPVerifierB64 {
    fn from(value: SRPVerifier) -> Self {
        Self {
            version: value.version,
            salt: BASE_64.encode(value.salt),
            verifier: BASE_64.encode(value.verifier),
        }
    }
}

/// SRP client authentication type.
///
/// Can be created with `SRPAuth::new_from_api`.
#[derive(Debug)]
pub struct SRPAuth(SRPAuthData);

impl SRPAuth {
    /// Create a new SRP authentication.
    ///
    /// The protocol version, modulus, salt, and `server_ephemeral` should come from the `/auth/info` route
    /// and the password from the user.
    /// The `verifier` provides a type that implements the `ModulusSignatureVerifier` trait
    /// to verify and extract the modulus.
    ///
    /// # Parameters
    ///
    /// * `verifier`         - A type that implements `ModulusSignatureVerifier` using PGP (if feature `pgpinternal` is enabled use `&RPGPVerifier::default()`)
    /// * `password`         - The user password.
    /// * `version`          - The Proton SRP version.
    /// * `salt       `      - The SRP salt for hashing the password.
    /// * `modulus`          - A pgp message including the SRP modulus signed by the server.
    /// * `server_ephemeral` - The SRP server ephemeral retrieved from the server.
    ///
    /// # Errors
    ///
    /// Returns `Err` if one of the input arguments is not valid or SRP password hashing fails.
    pub fn new(
        modulus_verifier: &impl ModulusSignatureVerifier,
        password: &str,
        version: u8,
        salt: &str,
        modulus: &str,
        server_ephemeral: &str,
    ) -> Result<Self, SRPError> {
        Self::new_with_modulus_verifier(
            modulus_verifier,
            password,
            version,
            salt,
            modulus,
            server_ephemeral,
        )
    }

    /// Create a new SRP authentication using rPGP as the server modulus verifier.
    ///
    /// The protocol version, modulus, salt, and `server_ephemeral` should come from the `/auth/info` route
    /// and the password from the user.
    /// Internally uses rPGP to verify the signature of the modulus received from the server.
    ///
    /// # Parameters
    ///
    /// * `password`         - The user password.
    /// * `version`          - The Proton SRP version.
    /// * `salt       `      - The SRP salt for hashing the password.
    /// * `modulus`          - A pgp message including the SRP modulus signed by the server.
    /// * `server_ephemeral` - The SRP server ephemeral retrieved from the server.
    ///
    /// # Errors
    ///
    /// Returns `Err` if one of the input arguments is not valid or SRP password hashing fails.
    #[cfg(feature = "pgpinternal")]
    pub fn with_pgp(
        password: &str,
        version: u8,
        salt: &str,
        modulus: &str,
        server_ephemeral: &str,
    ) -> Result<Self, SRPError> {
        Self::new(
            &crate::RPGPVerifier::default(),
            password,
            version,
            salt,
            modulus,
            server_ephemeral,
        )
    }

    /// Generate the SRP client proofs.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the srp client proof generation fails with the given state.
    pub fn generate_proofs(&self) -> Result<SRPProof, SRPError> {
        self.0.generate_client_proof()
    }

    /// Generates an SRP verifier to register with the server.
    ///
    /// The SRP verifier is required for example if a new account is created or
    /// on a password change request.
    ///
    /// # Parameters
    ///
    /// * `verifier`         - A type that implements `ModulusSignatureVerifier` using PGP (if feature `pgpinternal` is enabled use `&RPGPVerifier::default()`)
    /// * `password`         - The user password.
    /// * `salt_opt`         - Some SRP salt for hashing the password, or None if a fresh salt should be generated.
    /// * `modulus`          - A pgp message including the SRP modulus signed by the server.
    ///
    /// # Errors
    ///
    /// Returns an error if modulus extraction or verification fails, or something
    /// goes wrong in the computation of the verifier.
    pub fn generate_verifier(
        modulus_verifier: &impl ModulusSignatureVerifier,
        password: &str,
        salt_opt: Option<&str>,
        modulus: &str,
    ) -> Result<SRPVerifier, SRPError> {
        let modulus_b64 = modulus_verifier.verify_and_extract_modulus(
            modulus,
            include_str!("../../resources/server_public_key.asc"),
        )?;

        let decoded_modulus = BASE_64.decode(modulus_b64.trim())?;
        let modulus_bytes: &[u8; SRP_LEN_BYTES] = decoded_modulus
            .as_slice()
            .try_into()
            .map_err(|_err| SRPError::InvalidModulus("length does not match"))?;

        // Either use the provided salt or generate a fresh one.
        let decoded_salt = if let Some(salt) = salt_opt {
            BASE_64.decode(salt)?
        } else {
            core::generate_random_salt()
        };
        let salt_bytes: &[u8; SALT_LEN_BYTES] = decoded_salt
            .as_slice()
            .try_into()
            .map_err(|_err| SRPError::InvalidSalt("wrong size"))?;

        core::generate_srp_verifier(PROTON_SRP_VERSION, password, salt_bytes, modulus_bytes)
    }

    /// Generates an SRP verifier to register with the server using rPGP as the server modulus verifier.
    ///
    /// The SRP verifier is required for example if a new account is created or
    /// on a password change request.
    ///
    /// # Parameters
    ///
    /// * `password`         - The user password.
    /// * `salt_opt`         - Some SRP salt for hashing the password, or None if a fresh salt should be generated.
    /// * `modulus`          - A pgp message including the SRP modulus signed by the server.
    ///
    /// # Errors
    ///
    /// Returns an error if modulus extraction or verification fails, or something
    /// goes wrong in the computation of the verifier.
    #[cfg(feature = "pgpinternal")]
    pub fn generate_verifier_with_pgp(
        password: &str,
        salt_opt: Option<&str>,
        modulus: &str,
    ) -> Result<SRPVerifier, SRPError> {
        Self::generate_verifier(&crate::RPGPVerifier::default(), password, salt_opt, modulus)
    }

    pub(crate) fn new_with_modulus_verifier<Verifier: ModulusSignatureVerifier>(
        verifier: &Verifier,
        password: &str,
        version: u8,
        salt: &str,
        modulus: &str,
        server_ephemeral: &str,
    ) -> Result<Self, SRPError> {
        // Extract and verify modulus with the provided verifier.
        let modulus_b64 = verifier.verify_and_extract_modulus(
            modulus,
            include_str!("../../resources/server_public_key.asc"),
        )?;

        // decoder.decode_slice does not work due to padding estimates
        let decoded_modulus = BASE_64.decode(modulus_b64.trim())?;
        let modulus_bytes: &[u8; SRP_LEN_BYTES] = decoded_modulus
            .as_slice()
            .try_into()
            .map_err(|_err| SRPError::InvalidModulus("length does not match"))?;

        let decoded_salt = BASE_64.decode(salt)?;
        let salt_bytes: &[u8; SALT_LEN_BYTES] = decoded_salt
            .as_slice()
            .try_into()
            .map_err(|_err| SRPError::InvalidSalt("wrong size"))?;

        let decoded_server_ephemeral = BASE_64.decode(server_ephemeral)?;
        let server_ephemeral_bytes: &[u8; SRP_LEN_BYTES] = decoded_server_ephemeral
            .as_slice()
            .try_into()
            .map_err(|_err| SRPError::InvalidServerEphemeral)?;

        SRPAuthData::new(
            version,
            modulus_bytes,
            salt_bytes,
            server_ephemeral_bytes,
            password,
        )
        .map(SRPAuth)
    }
}
