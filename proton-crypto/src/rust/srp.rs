use std::str::Utf8Error;
use std::sync::Arc;

use proton_srp::{
    MailboxHashError, ModulusSignatureVerifier, ModulusVerifyError, SRPAuth, SRPError, SRPProof,
    SRPProofB64, SRPVerifierB64,
};

use crate::crypto::{DataEncoding, VerifiedData, Verifier, VerifierSync};
use crate::PGPProviderSync;
use crate::SRPProvider;
use crate::{
    srp::{ClientVerifier, HashedPassword},
    ClientProof,
};

pub(crate) struct SRPModulusVerifer<T: PGPProviderSync>(T);

impl<T: PGPProviderSync> SRPModulusVerifer<T> {
    pub fn new(pgp_provider: T) -> SRPModulusVerifer<T> {
        SRPModulusVerifer(pgp_provider)
    }
}

impl<T: PGPProviderSync> ModulusSignatureVerifier for SRPModulusVerifer<T> {
    fn verify_and_extract_modulus(
        &self,
        modulus: &str,
        public_key: &str,
    ) -> Result<String, ModulusVerifyError> {
        let server_key = self
            .0
            .public_key_import(public_key, DataEncoding::Armor)
            .map_err(|err| ModulusVerifyError::KeyImport(err.0.to_string()))?;
        let verify_result = self
            .0
            .new_verifier()
            .with_verification_key(&server_key)
            .verify_cleartext(modulus.as_bytes())
            .map_err(|err| ModulusVerifyError::CleartextParse(err.0.to_string()))?;
        verify_result
            .verification_result()
            .map_err(|err| ModulusVerifyError::SignatureVerification(err.to_string()))?;
        let modulus = String::from_utf8(verify_result.into_vec())
            .map_err(|err| ModulusVerifyError::CleartextParse(err.to_string()))?;
        Ok(modulus)
    }
}

impl From<SRPProof> for ClientProof {
    fn from(value: SRPProof) -> Self {
        let b64_proof: SRPProofB64 = value.into();
        ClientProof {
            proof: b64_proof.client_proof,
            ephemeral: b64_proof.client_ephemeral,
            expected_server_proof: b64_proof.expected_server_proof,
        }
    }
}

impl From<SRPVerifierB64> for ClientVerifier {
    fn from(value: SRPVerifierB64) -> Self {
        Self {
            version: value.version,
            salt: value.salt,
            verifier: value.verifier,
        }
    }
}

impl From<SRPError> for crate::CryptoError {
    fn from(value: SRPError) -> Self {
        Self(Arc::new(value))
    }
}

impl From<MailboxHashError> for crate::CryptoError {
    fn from(value: MailboxHashError) -> Self {
        Self(Arc::new(value))
    }
}

impl From<Utf8Error> for crate::CryptoError {
    fn from(value: Utf8Error) -> Self {
        Self(Arc::new(value))
    }
}

#[allow(clippy::module_name_repetitions)]
pub struct RustSRP<T: PGPProviderSync>(SRPModulusVerifer<T>);

impl<T: PGPProviderSync + Send> RustSRP<T> {
    pub fn new(pgp_provider: T) -> RustSRP<T> {
        Self(SRPModulusVerifer::new(pgp_provider))
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct HashedPasswordBcrypt(proton_srp::MailboxHashedPassword);

impl HashedPassword for HashedPasswordBcrypt {
    fn prefix(&self) -> &[u8] {
        self.0.prefix()
    }

    fn password_hash(&self) -> &[u8] {
        self.0.hashed_password()
    }
}

impl AsRef<[u8]> for HashedPasswordBcrypt {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl<T: PGPProviderSync + Send> SRPProvider for RustSRP<T> {
    type HashedPassword = HashedPasswordBcrypt;

    fn generate_client_proof(
        &self,
        _username: &str,
        password: &str,
        version: u8,
        salt: &str,
        modulus: &str,
        server_ephemeral: &str,
    ) -> crate::Result<ClientProof> {
        let auth = SRPAuth::new(&self.0, password, version, salt, modulus, server_ephemeral)?;
        auth.generate_proofs()
            .map(ClientProof::from)
            .map_err(Into::into)
    }

    fn mailbox_password(
        &self,
        password: impl AsRef<[u8]>,
        salt: impl AsRef<[u8]>,
    ) -> crate::Result<Self::HashedPassword> {
        let password_str = std::str::from_utf8(password.as_ref())?;
        proton_srp::mailbox_password_hash(password_str, salt.as_ref())
            .map(HashedPasswordBcrypt)
            .map_err(Into::into)
    }

    fn generate_client_verifier(
        &self,
        password: &str,
        modulus: &str,
    ) -> crate::Result<ClientVerifier> {
        SRPAuth::generate_verifier(&self.0, password, None, modulus)
            .map(SRPVerifierB64::from)
            .map(ClientVerifier::from)
            .map_err(Into::into)
    }
}
