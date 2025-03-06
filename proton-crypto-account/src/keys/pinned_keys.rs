use std::str::FromStr;

use proton_crypto::crypto::{PublicKey, UnixTimestamp};

/// Error returned if parsing the [`PGPScheme`] from a string fails.
#[derive(Debug, PartialEq, Eq)]
pub struct ParsePGPSchemeError;

/// PGP scheme options to encrypt and email.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PGPScheme {
    PGPInline,
    #[default]
    PGPMime,
}

impl PGPScheme {
    /// Returns the string representation of a PGP scheme.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PGPInline => "pgp-inline",
            Self::PGPMime => "pgp-mime",
        }
    }

    /// Returns true if the input string represents a valid PGP scheme
    #[must_use]
    pub fn valid(other: &str) -> bool {
        matches!(other, "pgp-inline" | "pgp-mime")
    }
}

impl FromStr for PGPScheme {
    type Err = ParsePGPSchemeError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input {
            "pgp-inline" => Ok(Self::PGPInline),
            "pgp-mime" => Ok(Self::PGPMime),
            _ => Err(ParsePGPSchemeError),
        }
    }
}

/// Preferred mime type to receive an email with.
#[derive(Debug, Default, Clone, Copy, Eq, Hash, PartialEq)]
pub enum EmailMimeType {
    #[default]
    Html,
    Text,
}

impl EmailMimeType {
    /// Returns the string representation of the mime type.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Html => "text/html",
            Self::Text => "text/plain",
        }
    }
}

impl FromStr for EmailMimeType {
    type Err = ParsePGPSchemeError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input {
            "text/html" => Ok(Self::Html),
            "text/plain" => Ok(Self::Text),
            _ => Err(ParsePGPSchemeError),
        }
    }
}

/// Pinned keys represent public address keys extracted from a contact's v-card.
#[derive(Default, Debug, Clone)]
pub struct PinnedPublicKeys<Pub: PublicKey> {
    /// The imported and extracted public keys form the v-card.
    pub pinned_keys: Vec<Pub>,
    /// Extracted from `x-pm-encrypt` on the v-card email property group.
    pub encrypt_to_pinned: Option<bool>,
    /// Extracted from `x-pm-encrypt-untrusted` on the v-card email property group.
    pub encrypt_to_untrusted: Option<bool>,
    /// Extracted from `x-pm-sign` on the v-card email property group.
    pub sign: Option<bool>,
    /// Extracted from `x-pm-scheme` on the v-card email property group.
    pub scheme: Option<PGPScheme>,
    /// Extracted from `x-pm-mimetype` on the v-card email property group.
    pub mime_type: Option<EmailMimeType>,
    /// Indicates if the pinned keys got extracted from a contact
    /// v-card with a verified signature.
    pub contact_signature_verified: bool,
    /// If a v-card signature got verified, contains the signature's timestamp.
    pub signature_timestamp: Option<UnixTimestamp>,
}

impl<Pub: PublicKey> PinnedPublicKeys<Pub> {
    /// Creates pinned keys with the imported keys using default config values.
    #[must_use]
    pub fn new(pinned_keys: Vec<Pub>) -> PinnedPublicKeys<Pub> {
        Self {
            pinned_keys,
            encrypt_to_pinned: None,
            encrypt_to_untrusted: None,
            sign: None,
            scheme: None,
            mime_type: None,
            contact_signature_verified: false,
            signature_timestamp: None,
        }
    }
}
