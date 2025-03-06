use super::{bool_from_integer, bool_to_integer};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, BoolFromInt};
use std::fmt::{Display, Formatter};

use serde_repr::{Deserialize_repr, Serialize_repr};

use super::SignedKeyList;
use crate::{FLAG_EMAIL_NO_ENCRYPT, FLAG_EMAIL_NO_SIGN, FLAG_NOT_COMPROMISED, FLAG_NOT_OBSOLETE};

#[derive(Serialize_repr, Deserialize_repr, PartialEq, Eq, Debug, Hash, Clone, Copy)]
#[repr(u32)]
pub enum APIPublicKeySource {
    Proton = 0,
    WKD = 1,
    KOO = 2,
}

crate::string_id! {
    /// Represent a user's API key ID.
    KeyId
}

/// Represent a flag of a key containing a bit map.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Hash, Clone, Copy)]
pub struct KeyFlag(u32);

impl Display for KeyFlag {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl<T: Into<u32>> From<T> for KeyFlag {
    fn from(value: T) -> Self {
        Self(value.into())
    }
}

impl Default for KeyFlag {
    fn default() -> Self {
        let mut flag = KeyFlag(0);
        flag.set_not_compromised();
        flag.set_not_obsolete();
        flag
    }
}

impl KeyFlag {
    /// Returns the key flag bitmap as u32.
    #[must_use]
    pub fn to_u32(&self) -> u32 {
        self.0
    }
    /// Returns true if the flag indicates no email signing.
    #[must_use]
    pub fn is_email_no_sign(&self) -> bool {
        (self.0 & FLAG_EMAIL_NO_SIGN) > 0
    }
    /// Returns true if the flag indicates no email encryption.
    ///
    /// If true the associated key can't be used to encrypt email.
    /// There are multiple scenarios where this can happen
    /// - the key is associated to a product without Mail, like Drive or VPN
    /// - the key is associated to an external address
    /// - the key is associated to an internal address e2e encryption disabled (e.g. because of forwarding)
    #[must_use]
    pub fn is_email_no_encryption(&self) -> bool {
        (self.0 & FLAG_EMAIL_NO_ENCRYPT) > 0
    }
    /// Returns true if the flag indicates that the associated key is obsolete.
    #[must_use]
    pub fn is_obsolete(&self) -> bool {
        (self.0 & FLAG_NOT_OBSOLETE) == 0
    }
    /// Returns true if the flag indicates that the associated key is compromised.
    #[must_use]
    pub fn is_compromised(&self) -> bool {
        (self.0 & FLAG_NOT_COMPROMISED) == 0
    }
    /// Indicates whether the key supports mail.
    #[must_use]
    pub fn supports_mail(&self) -> bool {
        !self.is_email_no_encryption()
    }
    /// Sets the key flag to be compromised.
    pub fn set_compromised(&mut self) {
        self.0 &= !FLAG_NOT_COMPROMISED;
    }
    /// Sets the key flag to not be compromised.
    pub fn set_not_compromised(&mut self) {
        self.0 |= FLAG_NOT_COMPROMISED;
    }
    /// Sets the key flag to be obsolete.
    pub fn set_obsolete(&mut self) {
        self.0 &= !FLAG_NOT_OBSOLETE;
    }
    /// Sets the key flag to not be obsolete.
    pub fn set_not_obsolete(&mut self) {
        self.0 |= FLAG_NOT_OBSOLETE;
    }
    /// Sets the key flag to no email encryption.
    pub fn set_email_no_encryption(&mut self) {
        self.0 |= FLAG_EMAIL_NO_ENCRYPT;
    }
    /// Sets the key flag to email encryption.
    pub fn set_email_encryption(&mut self) {
        self.0 &= !FLAG_EMAIL_NO_ENCRYPT;
    }
    /// Sets the key flag to no email encryption.
    pub fn set_email_no_sign(&mut self) {
        self.0 |= FLAG_EMAIL_NO_SIGN;
    }
    /// Sets the key flag to email sign.
    pub fn set_email_sign(&mut self) {
        self.0 &= !FLAG_EMAIL_NO_SIGN;
    }
}

crate::string_id! {
    /// An armored `OpenPGP` private key.
    ArmoredPrivateKey
}

crate::string_id! {
    /// A key token that contains a locked key secret.
    EncryptedKeyToken
}

crate::string_id! {
    /// A signature over the key token.
    KeyTokenSignature
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Hash, Clone)]
#[serde(rename_all = "PascalCase")]
/// Represents a locked jey retrieved from the API.
pub struct LockedKey {
    #[serde(rename = "ID")]
    /// Proton ID of the key.
    pub id: KeyId,
    /// Proton version of the key.
    pub version: u32,
    /// `OpenPGP` private key armored.
    pub private_key: ArmoredPrivateKey,
    /// Token to decrypt a key via another key (e.g., user key).
    pub token: Option<EncryptedKeyToken>,
    /// `OpenPGP` Signature to verify the token.
    pub signature: Option<KeyTokenSignature>, // Only available for address keys
    /// (Deprecated) Migrated accounts do not have the activation field set.
    pub activation: Option<String>,
    /// Is the key the primary key to use.
    #[serde(
        deserialize_with = "bool_from_integer",
        serialize_with = "bool_to_integer"
    )]
    pub primary: bool,
    /// The key is active and should be decryptable.
    #[serde(
        deserialize_with = "bool_from_integer",
        serialize_with = "bool_to_integer"
    )]
    pub active: bool,
    /// Key flags encoded in a bitmap.
    pub flags: Option<KeyFlag>, // Only available for address keys
    /// Secret for key recovery of a local file.
    pub recovery_secret: Option<String>, // Only available for user keys
    /// Signature for the recovery secret.
    pub recovery_secret_signature: Option<String>, // Only available for user keys
    #[serde(rename = "AddressForwardingID")]
    /// Represents a valid associated Address Forwarding instance, if not None.
    pub address_forwarding_id: Option<String>, // Only available for address keys
}

/// Represents a public key retrieved from the API.
///
/// For example the 'core/v4/keys/all' route can be used to retrieve public keys of
/// another proton user.
#[serde_as]
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Hash, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct APIPublicKey {
    /// Origin of the public key.
    pub source: APIPublicKeySource,
    /// Key flags encoded in a bitmap.
    pub flags: KeyFlag,
    /// `OpenPGP` armored public key.
    pub public_key: String,
    /// Is the key marked as primary.
    #[serde_as(as = "BoolFromInt")]
    pub primary: bool,
}
#[derive(Debug, Default, Serialize, Deserialize, Eq, PartialEq, Hash, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct APIPublicAddressKeyGroup {
    pub keys: Vec<APIPublicKey>,
    pub signed_key_list: Option<SignedKeyList>,
}

#[derive(Debug, Default, Serialize, Deserialize, Eq, PartialEq, Hash, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct APIUnverifiedPublicAddressKeyGroup {
    pub keys: Vec<APIPublicKey>,
}

impl AsRef<[APIPublicKey]> for APIPublicAddressKeyGroup {
    fn as_ref(&self) -> &[APIPublicKey] {
        &self.keys
    }
}

/// Represents the public keys returned from the `keys/all` route.
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Hash, Clone)]
#[serde(rename_all = "PascalCase")]
#[allow(clippy::module_name_repetitions)]
pub struct APIPublicAddressKeys {
    /// Information about the internal address itself, if it exists. Since the SKL is mandatory, this will never be nullable.
    #[serde(rename = "Address")]
    pub address_keys: APIPublicAddressKeyGroup,
    /// Information about the catch all address itself, if it exists. This can be null if the address keys are valid
    #[serde(rename = "CatchAll")]
    pub catch_all_keys: Option<APIPublicAddressKeyGroup>,
    /// Any other key that cannot be verified, such as Proton legacy keys or WKD.
    #[serde(rename = "Unverified")]
    pub unverified_keys: Option<APIUnverifiedPublicAddressKeyGroup>,
    /// List of warnings to show to the user related to phishing and message routing.
    pub warnings: Vec<String>,
    /// True when domain has valid proton MX.
    #[serde(rename = "ProtonMX")]
    pub proton_mx: bool,
    /// Tells whether this is an official Proton address.
    #[serde(
        deserialize_with = "bool_from_integer",
        serialize_with = "bool_to_integer"
    )]
    pub is_proton: bool,
}
