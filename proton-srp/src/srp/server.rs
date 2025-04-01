use std::ops::Deref;

use base64::{prelude::BASE64_STANDARD as BASE_64, Engine as _};
use zeroize::Zeroizing;

use crate::{ModulusSignatureVerifier, SRPError};

use crate::core::{ServerInteraction as CoreServerInteraction, SRP_LEN_BYTES};

use super::{SRPProof, SRPProofB64, SRPVerifier, SRPVerifierB64};

/// An SRP server challenge returned by the SRP server
/// containing the SRP server proof.
#[derive(Debug, Clone)]
pub struct ServerEphemeral(pub [u8; SRP_LEN_BYTES]);

impl ServerEphemeral {
    /// Encodes the server challenge as a base64 string.
    pub fn encode_b64(&self) -> String {
        BASE_64.encode(self.0)
    }
}

impl Deref for ServerEphemeral {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

/// An SRP server proof returned by the SRP server upon successful authentication.
#[derive(Debug, Clone)]
pub struct ServerProof(pub [u8; SRP_LEN_BYTES]);

impl ServerProof {
    /// Encodes the server proof as a base64 string.
    pub fn encode_b64(&self) -> String {
        BASE_64.encode(self.0)
    }
}

impl Deref for ServerProof {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

/// The client proof received via a message from the client.
#[derive(Debug, Clone)]
pub struct ServerClientProof {
    client_ephemeral: Vec<u8>,
    client_proof: Vec<u8>,
}

impl ServerClientProof {
    /// Creates a new client proof.
    ///
    /// # Parameters
    ///
    /// * `client_ephemeral` - The base64 client ephemeral.
    /// * `client_proof`     - The base64 client proof.
    ///
    /// # Errors
    ///
    /// Returns an error if decoding fails.
    pub fn new(client_ephemeral: &str, client_proof: &str) -> Result<Self, SRPError> {
        Ok(Self {
            client_ephemeral: BASE_64.decode(client_ephemeral)?,
            client_proof: BASE_64.decode(client_proof)?,
        })
    }

    /// Creates a new client proof.
    ///
    /// # Parameters
    ///
    /// * `client_ephemeral` - The raw client ephemeral.
    /// * `client_proof`     - The raw client proof.
    ///
    /// # Errors
    ///
    /// Returns an error if decoding fails.
    pub fn new_with_bytes(
        client_ephemeral: Vec<u8>,
        client_proof: Vec<u8>,
    ) -> Result<Self, SRPError> {
        Ok(Self {
            client_ephemeral,
            client_proof,
        })
    }
}

impl From<SRPProof> for ServerClientProof {
    fn from(value: SRPProof) -> Self {
        Self {
            client_ephemeral: value.client_ephemeral.into(),
            client_proof: value.client_proof.into(),
        }
    }
}

impl From<&SRPProof> for ServerClientProof {
    fn from(value: &SRPProof) -> Self {
        Self {
            client_ephemeral: value.client_ephemeral.into(),
            client_proof: value.client_proof.into(),
        }
    }
}

impl TryFrom<SRPProofB64> for ServerClientProof {
    type Error = SRPError;

    fn try_from(value: SRPProofB64) -> Result<Self, Self::Error> {
        Self::new(&value.client_ephemeral, &value.client_proof)
    }
}

impl TryFrom<&SRPProofB64> for ServerClientProof {
    type Error = SRPError;

    fn try_from(value: &SRPProofB64) -> Result<Self, Self::Error> {
        Self::new(&value.client_ephemeral, &value.client_proof)
    }
}

/// An unverified raw SRP modulus without an attached PGP signature.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RawSRPModulus(Vec<u8>);

impl RawSRPModulus {
    /// Creates a new raw SRP modulus.
    ///
    /// # Parameters
    ///
    /// * `raw_modulus` - The base64 encoded modulus.
    ///
    /// # Errors
    ///
    /// Returns an error if decoding fails.
    pub fn new(raw_modulus: &str) -> Result<Self, SRPError> {
        Ok(Self(BASE_64.decode(raw_modulus.trim())?))
    }

    /// Creates a new raw SRP modulus.
    ///
    /// # Parameters
    ///
    /// * `raw_modulus` - The raw SRP modulus.
    ///
    pub fn new_with_bytes(raw_modulus: Vec<u8>) -> Self {
        Self(raw_modulus)
    }

    /// Creates a new raw SRP modulus from a `OpenPGP` cleartext modulus message.
    ///
    /// Use this with care as the embedded signature is not verified.
    ///
    /// # Parameters
    ///
    /// * `modulus` - The `OpenPGP` cleartext modulus message.
    ///
    /// # Errors
    ///
    /// Returns an error if modulus extraction fails.
    pub fn new_with_pgp_modulus(modulus: &str) -> Result<Self, SRPError> {
        let mut raw_modulus = String::new();
        let mut in_body = false;

        for line in modulus.lines() {
            if line.starts_with("-----BEGIN PGP SIGNED MESSAGE-----") {
                in_body = true;
            } else if line.starts_with("-----BEGIN PGP SIGNATURE-----") {
                break;
            } else if in_body {
                let trimmed = line.trim();
                if !trimmed.is_empty()
                    && trimmed
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || "+/=".contains(c))
                {
                    raw_modulus.push_str(trimmed);
                }
            }
        }
        if raw_modulus.is_empty() {
            return Err(SRPError::InvalidModulus("no modulus found"));
        }
        Self::new(&raw_modulus)
    }

    /// Encodes the raw modulus as a base64 string.
    pub fn encode_b64(&self) -> String {
        BASE_64.encode(&self.0)
    }
}

impl Deref for RawSRPModulus {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

/// A client verifier stored on the server for client authentication.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ServerClientVerifier(Vec<u8>);

impl ServerClientVerifier {
    /// Creates a new client verifier.
    ///
    /// # Parameters
    ///
    /// * `client_verifier` - The base64 client verifier.
    ///
    /// # Errors
    ///
    /// Returns an error if decoding fails.
    pub fn new(client_verifier: &str) -> Result<Self, SRPError> {
        Ok(Self(BASE_64.decode(client_verifier.trim())?))
    }

    /// Creates a new client verifier.
    ///
    /// # Parameters
    ///
    /// * `client_verifier` - The raw client verifier.
    pub fn new_with_bytes(client_verifier: Vec<u8>) -> Self {
        Self(client_verifier)
    }
}

impl Deref for ServerClientVerifier {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl From<SRPVerifier> for ServerClientVerifier {
    fn from(value: SRPVerifier) -> Self {
        Self(value.verifier.into())
    }
}

impl From<&SRPVerifier> for ServerClientVerifier {
    fn from(value: &SRPVerifier) -> Self {
        Self(value.verifier.into())
    }
}

impl TryFrom<SRPVerifierB64> for ServerClientVerifier {
    type Error = SRPError;

    fn try_from(value: SRPVerifierB64) -> Result<Self, Self::Error> {
        Self::new(&value.verifier)
    }
}

impl TryFrom<&SRPVerifierB64> for ServerClientVerifier {
    type Error = SRPError;

    fn try_from(value: &SRPVerifierB64) -> Result<Self, Self::Error> {
        Self::new(&value.verifier)
    }
}

/// A state that allows to restore a [`ServerInteraction`].
#[derive(Debug)]
pub struct ServerInteractionState {
    /// The server ephemeral of the SRP interaction.
    pub server_ephemeral: Option<ServerEphemeral>,

    /// The server secret of the SRP interaction.
    pub server_ephemeral_secret: Zeroizing<Vec<u8>>,
}

#[derive(Debug)]
/// SRP interaction with a client from a servers point of view.
pub struct ServerInteraction {
    core_interaction: CoreServerInteraction,
}

impl ServerInteraction {
    /// Starts a new server interaction with a client.
    ///
    /// # Parameters
    ///
    /// * `raw_modulus`      - The base64 encoded modulus to use.
    /// * `verifier`         - The SRP verifier of the client to start the interaction with.
    ///
    /// # Errors
    ///
    /// Returns an error if input decoding fails or if the input is invalid
    pub fn new(
        raw_modulus: &RawSRPModulus,
        verifier: &ServerClientVerifier,
    ) -> Result<Self, SRPError> {
        let modulus_bytes: &[u8; SRP_LEN_BYTES] = raw_modulus
            .0
            .as_slice()
            .try_into()
            .map_err(|_err| SRPError::InvalidModulus("wrong byte size"))?;

        let verifier_bytes: &[u8; SRP_LEN_BYTES] = verifier
            .0
            .as_slice()
            .try_into()
            .map_err(|_err| SRPError::InvalidVerifier)?;

        Ok(Self {
            core_interaction: CoreServerInteraction::new(modulus_bytes, verifier_bytes)?,
        })
    }

    /// Starts a new server interaction with a client.
    ///
    /// # Parameters
    ///
    /// * `modulus_verifier` - The extractor that should be used to extract and verify the modulus.
    /// * `signed_modulus`   - The signed modulus to use encoded as a cleartext `OpenPGP` message.
    /// * `verifier`         - The SRP verifier of the client to start the interaction with.
    ///
    /// # Errors
    ///
    /// Returns an error if input decoding fails or if the input is invalid
    pub fn new_with_modulus_extractor(
        modulus_verifier: &impl ModulusSignatureVerifier,
        signed_modulus: &str,
        verifier: &ServerClientVerifier,
    ) -> Result<Self, SRPError> {
        let modulus_b64 = modulus_verifier.verify_and_extract_modulus(
            signed_modulus,
            include_str!("../../resources/server_public_key.asc"),
        )?;
        let raw_modulus = RawSRPModulus::new(&modulus_b64)?;
        Self::new(&raw_modulus, verifier)
    }

    /// Restores a server interaction from an existing state.
    ///
    /// # Parameters
    ///
    /// * `raw_modulus`      - The base64 encoded modulus to use.
    /// * `verifier`         - The SRP verifier of the client to start the interaction with.
    /// * `state`            - The SRP server interaction state to restore from.
    ///
    /// # Errors
    ///
    /// Returns an error if input decoding fails or if the input is invalid
    pub fn restore(
        raw_modulus: &RawSRPModulus,
        verifier: &ServerClientVerifier,
        state: &ServerInteractionState,
    ) -> Result<Self, SRPError> {
        let modulus_bytes: &[u8; SRP_LEN_BYTES] = raw_modulus
            .0
            .as_slice()
            .try_into()
            .map_err(|_err| SRPError::InvalidModulus("wrong byte size"))?;

        let verifier_bytes: &[u8; SRP_LEN_BYTES] = verifier
            .0
            .as_slice()
            .try_into()
            .map_err(|_err| SRPError::InvalidVerifier)?;

        let server_ephemeral_secret: &[u8; SRP_LEN_BYTES] = state
            .server_ephemeral_secret
            .as_slice()
            .try_into()
            .map_err(|_err| SRPError::InvalidServerState)?;

        let server_ephemeral: Option<&[u8; SRP_LEN_BYTES]> = state
            .server_ephemeral
            .as_ref()
            .map(|server_ephemeral| server_ephemeral.0.as_slice().try_into())
            .transpose()
            .map_err(|_| SRPError::InvalidServerState)?;

        Ok(Self {
            core_interaction: CoreServerInteraction::restore(
                modulus_bytes,
                verifier_bytes,
                server_ephemeral_secret,
                server_ephemeral,
            )?,
        })
    }

    /// Generates a client challenge message containing the SRP server ephemeral.
    pub fn generate_challenge(&mut self) -> ServerEphemeral {
        ServerEphemeral(self.core_interaction.generate_challenge())
    }

    /// Authenticates a client by verifying the client proof with the client ephemeral.
    ///
    /// # Parameters
    ///
    /// * `client_proof`     - The client proof received to verify from the client.
    ///
    /// # Errors
    ///
    /// Returns an error if inputs are invalid or client verification fails.
    /// If client verification fails sue to an invalid client proof
    /// the function will fail with [`SRPError::InvalidClientProof`].
    pub fn verify_proof(
        &mut self,
        client_proof: &ServerClientProof,
    ) -> Result<ServerProof, SRPError> {
        let client_ephemeral_bytes: &[u8; SRP_LEN_BYTES] = client_proof
            .client_ephemeral
            .as_slice()
            .try_into()
            .map_err(|_err| SRPError::InvalidClientEphemeral)?;

        let client_proof_bytes: &[u8; SRP_LEN_BYTES] = client_proof
            .client_proof
            .as_slice()
            .try_into()
            .map_err(|_err| SRPError::InvalidClientProof)?;
        self.core_interaction
            .verify_proof(client_ephemeral_bytes, client_proof_bytes)
            .map(ServerProof)
    }

    /// Returns the current state from the server interaction.
    ///
    /// The state [`ServerInteractionState`] allows to restore a server interaction
    /// at a later stage with [`Self::restore`].
    pub fn state(&self) -> ServerInteractionState {
        let server_ephemeral = self
            .core_interaction
            .server_ephemeral()
            .map(ServerEphemeral);
        let server_ephemeral_secret =
            Zeroizing::new(self.core_interaction.server_ephemeral_secret().to_vec());
        ServerInteractionState {
            server_ephemeral,
            server_ephemeral_secret,
        }
    }
}
