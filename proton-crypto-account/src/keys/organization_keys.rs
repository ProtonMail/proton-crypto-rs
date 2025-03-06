use proton_crypto::crypto::{AsPublicKeyRef, PrivateKey, PublicKey};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

#[derive(Serialize_repr, Deserialize_repr, PartialEq, Eq, Debug, Hash, Clone, Copy)]
#[repr(u32)]
pub enum AccessToOrgKey {
    /// The member does not and should not have access to the org key (e.g. not an admin).
    NoKey = 0,
    /// The member has full access to the most recent copy of the org key.
    Active = 1,
    /// The member does not have access to the most recent copy of the org key (including legacy keys).
    Missing = 2,
    /// The member has been invited to but needs to activate the most recent copy of the org key.
    Pending = 3,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct LockedOrganizationKey {
    /// `OpenPGP` organization private key.
    pub private_key: Option<String>,
    /// `OpenPGP` encrypted message to access the passwordless organization key.
    pub token: Option<String>,
    /// `OpenPGP` signature on the token.
    pub signature: Option<String>,
    /// Address email of the admin that signed the token (if not the user key of the member themself).
    pub signature_address: Option<String>,
    #[serde(rename = "EncryptionAddressID")]
    /// The address ID of the address that was invited to the organization key.
    pub encryption_address_id: String,
    /// Indicates the access to the organization key.
    pub access_to_org_key: Option<AccessToOrgKey>,
    /// Whether the organization has passwordless keys or not.
    pub passwordless: bool,
}

/// Represents a decrypted user key of a user.
///
/// Contains secret key material that must be protected.
#[derive(Debug)]
pub struct DecryptedOrganizationKey<Priv: PrivateKey, Pub: PublicKey> {
    /// PGP provider private key.
    pub private_key: Priv,
    /// PGP provider public key.
    pub public_key: Pub,
}

impl<Priv: PrivateKey, Pub: PublicKey> AsRef<Priv> for DecryptedOrganizationKey<Priv, Pub> {
    fn as_ref(&self) -> &Priv {
        &self.private_key
    }
}

impl<Priv: PrivateKey, Pub: PublicKey> AsPublicKeyRef<Pub> for DecryptedOrganizationKey<Priv, Pub> {
    fn as_public_key(&self) -> &Pub {
        &self.public_key
    }
}
