use crate::errors::SKLError;

use proton_crypto::crypto::{
    AsPublicKeyRef, DataEncoding, OpenPGPFingerprint, PGPProviderAsync, PGPProviderSync,
    PrivateKey, PublicKey, SHA256Fingerprint, Signer, SignerSync, UnixTimestamp, Verifier,
    VerifierAsync, VerifierSync,
};
use serde::{Deserialize, Serialize};

use super::{
    bool_from_integer, bool_to_integer, DecryptedAddressKey, KeyFlag, PrimaryUnlockedAddressKey,
    UnlockedAddressKeys,
};

pub const KT_SKL_VERIFICATION_CONTEXT_VALUE: &str = "key-transparency.key-list";

crate::string_id! {
    /// A Signed Key List (SKL) signature.
    SKLSignature
}

impl AsRef<[u8]> for SKLSignature {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

crate::string_id! {
    /// Signed key list data.
    SKLDataJson
}

crate::string_id! {
    /// A Signed Key List (SKL) signature.
    ObsolescenceToken
}

/// The data of an address key encoded in the Signed Key List (SKL).
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone, Hash)]
#[cfg_attr(feature = "facet", derive(facet::Facet))]
#[serde(rename_all = "PascalCase")]
#[allow(clippy::module_name_repetitions)]
pub struct SKLKeyData {
    #[serde(
        deserialize_with = "bool_from_integer",
        serialize_with = "bool_to_integer"
    )]
    pub primary: bool,
    pub flags: KeyFlag,
    pub fingerprint: OpenPGPFingerprint,
    #[serde(rename = "SHA256Fingerprints")]
    pub sha265_fingerprints: Vec<SHA256Fingerprint>,
}

impl SKLKeyData {
    /// Creates signed key list key info data from a decrypted address key.
    pub fn create_from<Priv: PrivateKey, Pub: PublicKey>(
        address_key: &DecryptedAddressKey<Priv, Pub>,
    ) -> Self {
        let fingerprint = address_key.private_key.key_fingerprint();
        let sha265_fingerprints = address_key.private_key.sha256_key_fingerprints();
        Self {
            flags: address_key.flags,
            primary: address_key.primary,
            fingerprint,
            sha265_fingerprints,
        }
    }
}

/// Represents a parsed list of [`SKLKeyData`].
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
pub struct SKLData(pub Vec<SKLKeyData>);

impl From<Vec<SKLKeyData>> for SKLData {
    fn from(value: Vec<SKLKeyData>) -> Self {
        Self(value)
    }
}

impl AsRef<[SKLKeyData]> for SKLData {
    fn as_ref(&self) -> &[SKLKeyData] {
        &self.0
    }
}

impl SKLData {
    /// Encode to json and sign.
    ///
    /// Encodes the signed key list (SKL) data to json format, which the is the format
    /// the signed key list persists data.
    /// Signs the json encoded data with the provided signing key and creates an armored
    /// `OpenPGP` signature.
    pub fn encode_and_sign<Provider: PGPProviderSync>(
        &self,
        pgp_provider: &Provider,
        primary_key: &PrimaryUnlockedAddressKey<Provider::PrivateKey, Provider::PublicKey>,
    ) -> Result<(SKLDataJson, SKLSignature), SKLError> {
        let encoded_data = serde_json::to_string(&self.0)?;
        let signing_context =
            pgp_provider.new_signing_context(KT_SKL_VERIFICATION_CONTEXT_VALUE.to_owned(), false);
        let signature = pgp_provider
            .new_signer()
            .with_signing_keys(primary_key.for_signing_skl())
            .with_signing_context(&signing_context)
            .with_utf8()
            .sign_detached(encoded_data.as_bytes(), DataEncoding::Armor)
            .map(String::from_utf8)
            .map_err(SKLError::SignatureCreation)??;
        Ok((SKLDataJson(encoded_data), SKLSignature(signature)))
    }
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone, Hash)]
#[cfg_attr(feature = "facet", derive(facet::Facet))]
#[serde(rename_all = "PascalCase")]
/// Represents a signed key list fetched from the API.
pub struct SignedKeyList {
    #[serde(rename = "MinEpochID")]
    /// Starting Epoch ID for the SKL. Can be None, if the epoch is not yet released.
    pub min_epoch_id: Option<u64>,
    #[serde(rename = "MaxEpochID")]
    /// Ending Epoch ID for the SKL. Can be None, if the epoch is not yet released
    pub max_epoch_id: Option<u64>,
    #[serde(rename = "ExpectedMinEpochID")]
    /// If epoch is not yet released this will be a future epoch ID.
    pub expected_min_epoch_id: Option<u64>,
    /// JSON-encoded content of the [`SKLData`]. If None, this SKL contains an `ObsolescenceToken`
    pub data: Option<SKLDataJson>,
    /// Hex token to prove the obsolescence of the signed key list in the merkle tree or None.
    ///
    /// The first 16 characters are a committed big-endian hex-encoded unix timestamp, remaining is random
    pub obsolescence_token: Option<ObsolescenceToken>,
    /// Armored `OpenPGP` signature for the data. If None, proof contains an obsolescenceToken
    pub signature: Option<SKLSignature>,
    /// SKL revision version.
    ///
    /// First revision is 1, then monotonically increasing.
    pub revision: u64,
}

impl SignedKeyList {
    /// Returns if the SKL is released in an epoch.
    #[must_use]
    pub fn is_released_in_epoch(&self) -> bool {
        self.max_epoch_id.is_some() && self.max_epoch_id.is_some()
    }
    /// Returns if the SKL represents an obsolete address.
    #[must_use]
    pub fn is_obsolete(&self) -> bool {
        self.obsolescence_token.is_some()
    }
    /// Returns if the SKL represents an address with active address keys.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.signature.is_some() && self.data.is_some() && !self.is_obsolete()
    }

    /// Returns if the SKL represents an address with active address keys.
    pub fn signed_key_list_data(&self) -> Result<SKLData, SKLError> {
        let data = self.data.as_ref().ok_or(SKLError::NoSKLData)?;
        let skl_data: Vec<SKLKeyData> = serde_json::from_str(data.0.as_str())
            .map_err(|err| SKLError::ParseError(err.to_string()))?;
        Ok(SKLData(skl_data))
    }

    /// Verifies the included SKL signature.
    pub fn verify_signature<Prov: PGPProviderSync>(
        &self,
        provider: &Prov,
        verification_keys: &[impl AsPublicKeyRef<Prov::PublicKey>],
        verification_time: Option<UnixTimestamp>,
    ) -> Result<UnixTimestamp, SKLError> {
        let (Some(data), Some(signature)) = (&self.data, &self.signature) else {
            return Err(SKLError::NoSKLData);
        };
        let verification_context = provider.new_verification_context(
            KT_SKL_VERIFICATION_CONTEXT_VALUE.to_owned(),
            false,
            UnixTimestamp::default(),
        );
        let mut verifier = provider
            .new_verifier()
            .with_verification_key_refs(verification_keys)
            .with_verification_context(&verification_context)
            .with_utf8_out();
        if let Some(timestamp) = verification_time {
            verifier = verifier.at_verification_time(timestamp);
        }
        verifier
            .verify_detached(data.0.as_bytes(), signature, DataEncoding::Armor)
            .map(|info| info.signature_creation_time)
            .map_err(SKLError::SignatureVerification)
    }

    /// Verifies the included SKL signature.
    pub async fn verify_signature_async<Prov: PGPProviderAsync>(
        &self,
        provider: &Prov,
        verification_keys: &[impl AsPublicKeyRef<Prov::PublicKey>],
        verification_time: Option<UnixTimestamp>,
    ) -> Result<UnixTimestamp, SKLError> {
        let (Some(data), Some(signature)) = (&self.data, &self.signature) else {
            return Err(SKLError::NoSKLData);
        };
        let verification_context = provider.new_verification_context(
            KT_SKL_VERIFICATION_CONTEXT_VALUE.to_owned(),
            false,
            UnixTimestamp::default(),
        );
        let mut verifier = provider
            .new_verifier_async()
            .with_verification_key_refs(verification_keys)
            .with_verification_context(&verification_context)
            .with_utf8_out();
        if let Some(timestamp) = verification_time {
            verifier = verifier.at_verification_time(timestamp);
        }
        verifier
            .verify_detached_async(data.0.as_bytes(), signature, DataEncoding::Armor)
            .await
            .map(|info| info.signature_creation_time)
            .map_err(SKLError::SignatureVerification)
    }
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone, Hash)]
#[cfg_attr(feature = "facet", derive(facet::Facet))]
#[serde(rename_all = "PascalCase")]
#[allow(clippy::module_name_repetitions)]
/// Represents a locally generated signed key list not yet synced with the backend.
pub struct LocalSignedKeyList {
    /// JSON-encoded content of the [`SKLData`]. If None, this SKL contains an `ObsolescenceToken`
    pub data: SKLDataJson,
    /// Armored `OpenPGP` signature for the data. If None, proof contains an obsolescenceToken
    pub signature: SKLSignature,
}

impl LocalSignedKeyList {
    /// Generates a local signed keys list representing the address keys provided.
    pub fn generate<Provider: PGPProviderSync>(
        pgp_provider: &Provider,
        address_keys: &UnlockedAddressKeys<Provider>,
    ) -> Result<Self, SKLError> {
        let mut skl_data = SKLData(Vec::with_capacity(address_keys.len()));
        skl_data
            .0
            .extend(address_keys.iter().map(SKLKeyData::create_from));
        let primary_key = address_keys
            .primary_for_mail()
            .map_err(|_| SKLError::NoPrimaryKey)?;
        let (data, signature) = skl_data.encode_and_sign(pgp_provider, &primary_key)?;
        Ok(Self { data, signature })
    }
}
