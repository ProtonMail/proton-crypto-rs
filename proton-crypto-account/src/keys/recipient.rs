use std::{
    collections::HashSet,
    fmt::{self, Display},
};

use proton_crypto::{
    crypto::{AsPublicKeyRef, OpenPGPFingerprint, PrivateKey, PublicKey, UnixTimestamp},
    keytransparency::{KTVerificationResult, KT_UNVERIFIED, KT_VERIFIED},
};

use crate::{errors::EncryptionPreferencesError, keys::DecryptedAddressKey};

use super::{
    EmailMimeType, InboxPublicKeys, PGPScheme, PinnedPublicKeys, PublicAddressKey,
    PublicAddressKeys,
};

/// Represents the public key information and preferences for a recipient.
///
/// The type is a reflection of the vCard content plus the public key info retrieved from the API.
#[derive(Debug, Clone)]
#[allow(clippy::module_name_repetitions)]
pub struct RecipientPublicKeyModel<Pub: PublicKey> {
    /// Indicates whether the data should be encrypted.
    ///
    /// This is an optional boolean value. If `Some(true)`, the data should be encrypted. If `Some(false)`,
    /// the data should not be encrypted. If `None`, no specific encryption preference is set for the recipient.
    pub encrypt: Option<bool>,

    /// Indicates whether the data should be signed.
    ///
    /// This is an optional boolean value. If `Some(true)`, the data should be signed. If `Some(false)`,
    /// the data should not be signed. If `None`, no specific signing preference is set for the recipient.
    pub sign: Option<bool>,

    /// API public keys sorted by validity and user preference.
    pub api_keys: Vec<Pub>,

    /// V-card keys sorted by validity and user preference.
    pub pinned_keys: Vec<Pub>,

    /// The type of recipient e.g, internal, external.
    pub contact_type: ContactType,

    /// An optional PGP scheme indicating the preferred scheme for encryption.
    pub pgp_scheme: Option<PGPScheme>,

    /// An optional MIME type indicating the email body format type.
    pub mime_type: Option<EmailMimeType>,

    /// Indicates if the recipient is an internal address with disabled e2e encryption.
    pub is_internal_with_disabled_e2ee: bool,

    /// Result of the key transparency verification process.
    pub key_transparency_verification: KTVerificationResult,

    /// Contains all key fingerprints that are trusted, i.e., contained in the v-card.
    trusted_fingerprints: HashSet<OpenPGPFingerprint>,

    /// Contains all key fingerprints that are marked as obsolete.
    obsolete_fingerprints: HashSet<OpenPGPFingerprint>,

    /// Contains all key fingerprints that are capable to encrypt.
    encryption_capable_fingerprints: HashSet<OpenPGPFingerprint>,

    /// Contains all key fingerprints that are marked as compromised.
    compromised_fingerprints: HashSet<OpenPGPFingerprint>,
}

/// Different types of recipients.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum ContactType {
    Internal,
    ExternalWithApiKeys,
    ExternalWithNoApiKeys,
}

impl Display for ContactType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ContactType::Internal => f.write_str("internal recipient"),
            ContactType::ExternalWithApiKeys => f.write_str("external recipient with api keys"),
            ContactType::ExternalWithNoApiKeys => {
                f.write_str("external recipient with no api keys")
            }
        }
    }
}

impl<Pub: PublicKey> RecipientPublicKeyModel<Pub> {
    /// Creates a [`RecipientPublicKeyModel`] instance by sorting and prioritizing `OpenPGP`
    /// encryption keys and preferences.
    ///
    /// This function processes the provided public keys (`api_keys`) and optionally considers
    /// any pinned public keys (`pinned_keys`). It uses the current encryption time (`encryption_time`)
    /// to determine the validity of keys (e.g., checking for obsolescence, compromise, encryption capability) and then
    /// sorts them according to their priority. The sorted keys, along with relevant settings
    /// for encryption, signing, MIME type, and `OpenPGP` scheme, are packaged into a `RecipientPublicKeyModel`.
    ///
    /// The function does not select a single key for use but rather provides a structured
    /// way to handle these keys based on their priority, allowing for further decision-making downstream in the encryption preferences.
    ///
    /// # Parameters
    ///
    /// - `api_keys`: The `InboxPublicKeys<Pub>` containing the recipient's public keys.
    /// - `pinned_keys`: An optional `PinnedPublicKeys<Pub>` representing additional encryption key preferences from a v-card.
    /// - `encryption_time`: The `UnixTimestamp` representing the current time for validating the `OpenPGP` keys.
    /// - `prefer_v6`: Whether v6 keys should be preferred over v4 keys in the selection order.
    #[must_use]
    pub fn from_public_keys_at_time(
        api_keys: PublicAddressKeys<Pub>,
        pinned_keys: Option<PinnedPublicKeys<Pub>>,
        encryption_time: UnixTimestamp,
        prefer_v6: bool,
    ) -> Self {
        let api_keys_for_inbox = api_keys.into_inbox_keys(true);
        let contact_type = Self::determine_contact_type(&api_keys_for_inbox);

        let mut trusted_fingerprints = HashSet::new();
        let mut obsolete_fingerprints = HashSet::new();
        let mut encryption_capable_fingerprints = HashSet::new();
        let mut compromised_fingerprints = HashSet::new();

        Self::process_api_keys(
            &api_keys_for_inbox.public_keys,
            &mut obsolete_fingerprints,
            &mut compromised_fingerprints,
            &mut encryption_capable_fingerprints,
            encryption_time,
        );

        if let Some(trusted_keys) = &pinned_keys {
            Self::process_pinned_keys(
                trusted_keys,
                &mut trusted_fingerprints,
                &mut encryption_capable_fingerprints,
                encryption_time,
            );
        }

        let encrypt = Self::determine_encryption(pinned_keys.as_ref(), contact_type);
        let sign = pinned_keys.as_ref().and_then(|keys| keys.sign);
        let pgp_scheme = pinned_keys.as_ref().and_then(|keys| keys.scheme);
        let mime_type = pinned_keys.as_ref().and_then(|keys| keys.mime_type);

        let ordered_api_keys = Self::sort_api_keys_by_priority(
            api_keys_for_inbox.public_keys,
            &trusted_fingerprints,
            &obsolete_fingerprints,
            &compromised_fingerprints,
            prefer_v6,
        );

        let ordered_pinned_keys = pinned_keys
            .map(|value| {
                Self::sort_pinned_keys_by_priority(
                    value.pinned_keys,
                    &obsolete_fingerprints,
                    &compromised_fingerprints,
                    &encryption_capable_fingerprints,
                    prefer_v6,
                )
            })
            .unwrap_or_default();

        RecipientPublicKeyModel {
            encrypt,
            sign,
            api_keys: ordered_api_keys,
            pinned_keys: ordered_pinned_keys,
            pgp_scheme,
            mime_type,
            contact_type,
            key_transparency_verification: api_keys_for_inbox.key_transparency_verification,
            trusted_fingerprints,
            obsolete_fingerprints,
            encryption_capable_fingerprints,
            is_internal_with_disabled_e2ee: api_keys_for_inbox.is_internal_with_disabled_e2ee,
            compromised_fingerprints,
        }
    }

    /// Indicates wether the provided key is compromised according to the model.
    pub fn is_selected_key_compromised(&self, public_key: &Pub) -> bool {
        self.compromised_fingerprints
            .contains(&public_key.key_fingerprint())
    }

    /// Indicates wether the provided key is obsolete according to the model.
    pub fn is_selected_key_obsolete(&self, public_key: &Pub) -> bool {
        self.obsolete_fingerprints
            .contains(&public_key.key_fingerprint())
    }

    /// Indicates wether the provided key can encrypt according to the model.
    pub fn can_selected_key_encrypt(&self, public_key: &Pub) -> bool {
        self.encryption_capable_fingerprints
            .contains(&public_key.key_fingerprint())
    }

    /// Indicates wether the provided key is trusted according to the model.
    pub fn is_selected_key_trusted(&self, public_key: &Pub) -> bool {
        self.trusted_fingerprints
            .contains(&public_key.key_fingerprint())
    }

    /// Indicates wether the provided key is valid for sending.
    pub fn is_selected_key_valid_for_sending(&self, public_key: &Pub) -> bool {
        !self.is_selected_key_compromised(public_key)
            && !self.is_selected_key_obsolete(public_key)
            && self.can_selected_key_encrypt(public_key)
    }

    fn determine_contact_type(api_keys: &InboxPublicKeys<Pub>) -> ContactType {
        match api_keys.recipient_type {
            super::RecipientType::Internal => ContactType::Internal,
            super::RecipientType::External => {
                if api_keys.public_keys.is_empty() {
                    ContactType::ExternalWithNoApiKeys
                } else {
                    ContactType::ExternalWithApiKeys
                }
            }
        }
    }

    fn process_api_keys(
        public_keys: &[PublicAddressKey<Pub>],
        obsolete_fingerprints: &mut HashSet<OpenPGPFingerprint>,
        compromised_fingerprints: &mut HashSet<OpenPGPFingerprint>,
        encryption_capable_fingerprints: &mut HashSet<OpenPGPFingerprint>,
        encryption_time: UnixTimestamp,
    ) {
        for api_key in public_keys {
            let fingerprint = api_key.public_keys.key_fingerprint();
            if api_key.flags.is_compromised() {
                compromised_fingerprints.insert(fingerprint.clone());
            }
            if api_key.flags.is_obsolete() {
                obsolete_fingerprints.insert(fingerprint.clone());
            }
            if api_key.public_keys.can_encrypt(encryption_time)
                && !api_key.public_keys.is_expired(encryption_time)
                && !api_key.public_keys.is_revoked(encryption_time)
            {
                encryption_capable_fingerprints.insert(fingerprint);
            }
        }
    }

    fn process_pinned_keys(
        pinned_keys: &PinnedPublicKeys<Pub>,
        trusted_fingerprints: &mut HashSet<OpenPGPFingerprint>,
        encryption_capable_fingerprints: &mut HashSet<OpenPGPFingerprint>,
        encryption_time: UnixTimestamp,
    ) {
        for trusted_key in &pinned_keys.pinned_keys {
            let fingerprint = trusted_key.key_fingerprint();
            trusted_fingerprints.insert(fingerprint.clone());
            if trusted_key.can_encrypt(encryption_time)
                && !trusted_key.is_expired(encryption_time)
                && !trusted_key.is_revoked(encryption_time)
            {
                encryption_capable_fingerprints.insert(fingerprint);
            }
        }
    }

    fn determine_encryption(
        pinned_keys: Option<&PinnedPublicKeys<Pub>>,
        contact_type: ContactType,
    ) -> Option<bool> {
        if contact_type == ContactType::ExternalWithApiKeys && pinned_keys.is_none() {
            // Enable encryption for external users with API keys.
            return Some(true);
        }
        pinned_keys.map(|keys| {
            (!keys.pinned_keys.is_empty() && keys.encrypt_to_pinned.unwrap_or(true))
                || (contact_type == ContactType::ExternalWithApiKeys
                    && keys.encrypt_to_untrusted.unwrap_or(true))
        })
    }

    fn sort_api_keys_by_priority(
        public_keys: Vec<PublicAddressKey<Pub>>,
        trusted_fingerprints: &HashSet<OpenPGPFingerprint>,
        obsolete_fingerprints: &HashSet<OpenPGPFingerprint>,
        compromised_fingerprints: &HashSet<OpenPGPFingerprint>,
        prefer_v6: bool,
    ) -> Vec<Pub> {
        let mut keys_with_order = public_keys
            .into_iter()
            .map(|public_key| {
                let fingerprint = public_key.public_keys.key_fingerprint();
                let bitmask = u8::from(if prefer_v6 {public_key.public_keys.version() != 6} else {public_key.public_keys.version() != 4}) // isNotPreferredVersion
                    | (u8::from(!public_key.primary) << 1) // isNotPrimary
                    | (u8::from(obsolete_fingerprints.contains(&fingerprint)) << 2) // isObsolete
                    | (u8::from(compromised_fingerprints.contains(&fingerprint)) << 3) // isCompromised
                    | (u8::from(!trusted_fingerprints.contains(&fingerprint)) << 4); // isNotTrusted

                (bitmask, public_key.public_keys)
            })
            .collect::<Vec<_>>();

        keys_with_order.sort_by(|a, b| a.0.cmp(&b.0));
        keys_with_order.into_iter().map(|(_, key)| key).collect()
    }

    fn sort_pinned_keys_by_priority(
        pinned_keys: Vec<Pub>,
        obsolete_fingerprints: &HashSet<OpenPGPFingerprint>,
        compromised_fingerprints: &HashSet<OpenPGPFingerprint>,
        encryption_capable_fingerprints: &HashSet<OpenPGPFingerprint>,
        prefer_v6: bool,
    ) -> Vec<Pub> {
        let mut keys_with_order = pinned_keys
            .into_iter()
            .map(|public_key| {
                let fingerprint = public_key.key_fingerprint();
                let bitmask = u8::from(if prefer_v6 {public_key.version() != 6} else {public_key.version() != 4}) // isNotPreferredVersion
                    | (u8::from(obsolete_fingerprints.contains(&fingerprint)) << 1) // isObsolete
                    | (u8::from(compromised_fingerprints.contains(&fingerprint)) << 2) // isCompromised
                    | (u8::from(!encryption_capable_fingerprints.contains(&fingerprint)) << 3); // cannotSend

                (bitmask, public_key)
            })
            .collect::<Vec<_>>();

        keys_with_order.sort_by(|a, b| a.0.cmp(&b.0));
        keys_with_order.into_iter().map(|(_, key)| key).collect()
    }
}

/// A helper type that contains the default PGP preferences
/// extracted from the user's mailsettings.
#[derive(Debug, Default, PartialEq, Eq, Copy, Clone, Hash)]
pub struct CryptoMailSettings {
    /// The default PGP scheme to use.
    pub pgp_scheme: PGPScheme,

    /// If mails should be signed by default.
    pub sign: bool,
}

/// Represents the encryption preferences for sending an email, including options for encryption, signing,
/// PGP scheme, MIME type, and selected public key.
///
/// This struct encapsulates the settings and choices made when preparing an email for sending,
/// specifically focusing on whether the email should be encrypted or signed, and which PGP scheme and
/// MIME type to use. It also includes the selected public key for encryption and additional metadata
/// about the selection process.
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools, clippy::module_name_repetitions)]
pub struct EncryptionPreferences<Pub: PublicKey> {
    /// Indicates whether the email should be encrypted (`true`) or sent unencrypted (`false`).
    ///
    /// If `true`, the email content will be encrypted using the selected public key. If `false`,
    /// the email will be sent in plaintext.
    pub encrypt: bool,

    /// Indicates whether the email should be signed (`true`) or sent unsigned (`false`).
    ///
    /// If `true`, the email will be signed with the sender's private key, allowing the recipient
    /// to verify the authenticity and integrity of the message.
    pub sign: bool,

    /// The type of contact, which influences the default encryption and signing behavior.
    ///
    /// This field differentiates between internal and external contacts, which may have different
    /// default settings for encryption and signing. For instance, internal contacts might always
    /// require encryption, while external contacts might have more flexible settings.
    pub contact_type: ContactType,

    /// The `OpenPGP` scheme to use when encrypting the email to an external recipient.
    pub pgp_scheme: PGPScheme,

    /// An optional preference for the MIME type of the body.
    pub mime_type: Option<EmailMimeType>,

    /// Optionally stores the selected public key for encryption.
    ///
    /// This field contains the public key that will be used to encrypt the email content if
    /// encryption is enabled. It is `None` if encryption is not required or if no suitable
    /// public key was found.
    pub selected_key: Option<Pub>,

    /// Indicates whether the selected key is pinned.
    ///
    /// A pinned key is one that has been manually selected/trusted and, thus, the security of the key does
    /// not rely on trusting the server serving the right key.
    pub is_selected_key_pinned: bool,

    /// Indicates that the receiving address wants encryption disabled although
    /// being an proton internal address.
    pub encryption_disabled_mail: bool,

    /// Result of the key transparency verification process for API keys.
    pub key_transparency_verification: KTVerificationResult,
}

impl<Pub: PublicKey> EncryptionPreferences<Pub> {
    /// Creates an instance of [`EncryptionPreferences`] by determining the appropriate encryption and signing
    /// settings based on the recipient's public key model and the user's cryptographic mail settings.
    ///
    /// This function analyzes the recipient's public key information, the type of recipient, and the user's
    /// default mail settings to decide whether the email should be encrypted and/or signed. It also selects
    /// the most appropriate PGP scheme and MIME type for the email and identifies the public key to use for
    /// encryption, if applicable.
    /// See [confluence](https://confluence.protontech.ch/display/MAILFE/Send+preferences+for+outgoing+email) for more details on the logic.
    ///
    /// # Errors
    ///
    /// An [`EncryptionPreferencesError`] if the key selection fails.
    /// An [`EncryptionPreferencesError::ApiKeyNotPinned`] is thrown if there are pinned keys, but none of the fingerprints of the pinned keys matches
    /// the fingerprint of one of the keys served by the API.
    /// In this case the client should force the user (via a modal) to trust one of the keys served by the API before sending any email.
    pub fn from_key_model_and_settings(
        recipient_key_model: RecipientPublicKeyModel<Pub>,
        crypto_mail_settings: &CryptoMailSettings,
    ) -> Result<Self, EncryptionPreferencesError> {
        // Determine the PGP preferences and fallback to the mail settings if not set.
        let mut encrypt = recipient_key_model.encrypt.unwrap_or_default();
        let mut sign = recipient_key_model
            .sign
            .unwrap_or(crypto_mail_settings.sign);
        sign = encrypt || sign;
        let scheme = recipient_key_model
            .pgp_scheme
            .unwrap_or(crypto_mail_settings.pgp_scheme);
        let mime_type = recipient_key_model.mime_type;

        // Select the `OpenPGP` public key based on the recipient type.
        let (selected_key, is_selected_key_pinned) = match recipient_key_model.contact_type {
            ContactType::Internal => {
                encrypt = true;
                sign = true;
                Self::select_key_for_recipient_with_api_keys(&recipient_key_model)?
            }
            ContactType::ExternalWithApiKeys => {
                Self::select_key_for_recipient_with_api_keys(&recipient_key_model)?
            }
            ContactType::ExternalWithNoApiKeys => {
                Self::select_key_for_recipient_without_api_keys(&recipient_key_model, encrypt)?
            }
        };

        Ok(EncryptionPreferences {
            encrypt,
            sign,
            contact_type: recipient_key_model.contact_type,
            pgp_scheme: scheme,
            mime_type,
            selected_key: selected_key.cloned(),
            is_selected_key_pinned,
            encryption_disabled_mail: recipient_key_model.is_internal_with_disabled_e2ee,
            key_transparency_verification: recipient_key_model.key_transparency_verification,
        })
    }

    /// Creates an instance of `EncryptionPreferences` for sending an email to the user's own address
    /// by selecting the appropriate encryption and signing settings based on the provided address keys
    /// and mail settings.
    ///
    /// This function determines the encryption and signing preferences by selecting a valid primary key
    /// from the user's own address keys. The selected key must be capable of encryption, not compromised,
    /// and not obsolete. The function uses the user's mail settings to configure the PGP scheme and MIME type
    /// for the email.
    ///
    /// # Errors
    ///
    /// This function may return an [`EncryptionPreferencesError::NoPrimaryKey`] if no valid primary key
    /// is found in the user's address keys that meets the required conditions for encryption.
    pub fn from_unlocked_address_keys_and_settings<Priv: PrivateKey>(
        is_address_external: bool,
        address_keys: &[DecryptedAddressKey<Priv, Pub>],
        mail_settings: CryptoMailSettings,
        encryption_time: UnixTimestamp,
    ) -> Result<Self, EncryptionPreferencesError> {
        // Select a valid primary key in the address.
        let selected_key_v4_opt = address_keys.iter().find(|address_key| {
            address_key.primary
                && !address_key.flags.is_compromised()
                && !address_key.flags.is_obsolete()
                && address_key.public_key.can_encrypt(encryption_time)
                && !address_key.is_v6
        });

        // If there is a valid v6 primary key, prefer it for encryption.
        let selected_key_v6_opt = address_keys.iter().find(|address_key| {
            address_key.primary
                && !address_key.flags.is_compromised()
                && !address_key.flags.is_obsolete()
                && address_key.public_key.can_encrypt(encryption_time)
                && address_key.is_v6
        });

        let (selected_key, selected_key_flags) = match (selected_key_v4_opt, selected_key_v6_opt) {
            (None, None) => return Err(EncryptionPreferencesError::NoPrimaryKey),
            (None | Some(_), Some(selected_key_v6)) => {
                (selected_key_v6.public_key.clone(), selected_key_v6.flags)
            }
            (Some(selected_key_v4), None) => {
                (selected_key_v4.public_key.clone(), selected_key_v4.flags)
            }
        };

        let encryption_disabled_mail =
            is_address_external && selected_key_flags.is_email_no_encryption();

        Ok(EncryptionPreferences {
            encrypt: true,
            sign: true,
            contact_type: ContactType::Internal,
            pgp_scheme: mail_settings.pgp_scheme,
            mime_type: None,
            selected_key: Some(selected_key),
            is_selected_key_pinned: false,
            encryption_disabled_mail,
            key_transparency_verification: Ok(()),
        })
    }

    /// Helper function to select the encryption key for an internal or external recipient with API keys.
    fn select_key_for_recipient_with_api_keys(
        recipient_key_model: &RecipientPublicKeyModel<Pub>,
    ) -> Result<(Option<&Pub>, bool), EncryptionPreferencesError> {
        let is_external = recipient_key_model.contact_type != ContactType::Internal;
        // Take the first API key. They are ordered according to their validity and preference.
        // Pinned keys (trusted) have higher priority.
        // For an external user at most one API key (from WKD or KOO) will be returned by the server.
        // So, we again just take the first one.
        let Some(selected_key) = recipient_key_model.api_keys.first() else {
            return if is_external {
                Err(EncryptionPreferencesError::ExternalUserNoValidApiKey)
            } else {
                Err(EncryptionPreferencesError::InternalUserNoApiKeys)
            };
        };

        // Check if the key can be used to encrypt and send an email.
        if !recipient_key_model.is_selected_key_valid_for_sending(selected_key) {
            return Err(EncryptionPreferencesError::SelectedKeyCannotSend(
                recipient_key_model.contact_type,
                selected_key.key_fingerprint(),
                recipient_key_model.is_selected_key_obsolete(selected_key),
                recipient_key_model.is_selected_key_compromised(selected_key),
                recipient_key_model.can_selected_key_encrypt(selected_key),
            ));
        }

        // Check for pinned keys.
        if !recipient_key_model.pinned_keys.is_empty() {
            // The client should encrypt the email with the first pinned key whose fingerprint matches the fingerprint
            // of one of the keys served by the API.
            // The keys in the vCard should be ordered according to their PREF
            // property if that has not been specified they are taken in the order in which they are written in the vCard.
            let primary_fingerprint = selected_key.key_fingerprint();
            if !recipient_key_model.is_selected_key_trusted(selected_key) {
                return Err(EncryptionPreferencesError::PinnedKeyNotProvidedByAPI(
                    primary_fingerprint,
                ));
            }
            let pinned_key = recipient_key_model
                .pinned_keys
                .iter()
                .find(|key| key.key_fingerprint() == primary_fingerprint)
                .unwrap_or(selected_key); // There must always be a match if the primary is trusted.
            return Ok((Some(pinned_key), true));
        }
        Ok((Some(selected_key), false))
    }

    /// Helper function to select the encryption key for an external
    /// recipient with no API keys.
    fn select_key_for_recipient_without_api_keys(
        recipient_key_model: &RecipientPublicKeyModel<Pub>,
        encrypt: bool,
    ) -> Result<(Option<&Pub>, bool), EncryptionPreferencesError> {
        // Pinned keys are sorted according to their validity.
        // The first valid one (as stored in the vCard) should be used.
        let Some(pinned_key) = recipient_key_model.pinned_keys.first() else {
            return Ok((None, false));
        };
        if !encrypt {
            return Ok((None, false));
        }
        if !recipient_key_model.is_selected_key_valid_for_sending(pinned_key) {
            return Err(EncryptionPreferencesError::ExternalUserNoValidPinnedKey(
                pinned_key.key_fingerprint(),
                recipient_key_model.is_selected_key_obsolete(pinned_key),
                recipient_key_model.is_selected_key_compromised(pinned_key),
                recipient_key_model.can_selected_key_encrypt(pinned_key),
            ));
        }
        Ok((Some(pinned_key), true))
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum KeyOwnership {
    /// The public keys are extracted from self owned keys.
    SelfOwn,
    /// The public keys are from other users.
    Other,
}

/// A type that stores public keys to verify signatures and relevant
/// key information to display.
#[derive(Debug)]
pub struct VerificationPreferences<Pub: PublicKey> {
    /// Where did the keys originated from.
    pub ownership: KeyOwnership,
    /// Pinned public keys.
    pub pinned_keys: Vec<Pub>,
    /// API public keys.
    pub api_keys: Vec<Pub>,
    /// Fingerprints of keys marked as compromised.
    pub compromised_fingerprints: HashSet<OpenPGPFingerprint>,
    /// Key transparency verification result.
    pub key_transparency_verification: KTVerificationResult,
}

impl<Pub: PublicKey> Display for VerificationPreferences<Pub> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let pinned_key_ids = self
            .pinned_keys
            .iter()
            .map(|key| key.key_id().to_hex())
            .collect::<Vec<_>>();
        let api_key_ids = self
            .api_keys
            .iter()
            .map(|key| key.key_id().to_hex())
            .collect::<Vec<_>>();
        write!(f, "InboxVerificationPreferences {{ ")?;
        write!(f, "ownership: {:?}, ", self.ownership)?;
        write!(f, "pinned_keys: {pinned_key_ids:?}, ")?;
        write!(f, "api_keys: {api_key_ids:?}, ")?;
        write!(f, "}}")?;
        Ok(())
    }
}

impl<Pub: PublicKey> Default for VerificationPreferences<Pub> {
    fn default() -> Self {
        Self {
            ownership: KeyOwnership::Other,
            pinned_keys: Vec::default(),
            api_keys: Vec::default(),
            compromised_fingerprints: HashSet::default(),
            key_transparency_verification: KT_UNVERIFIED,
        }
    }
}

impl<Pub: PublicKey> VerificationPreferences<Pub> {
    /// Selects the valid signature verification keys from the unlocked user keys of the logged-in user.
    pub fn from_unlocked_address_keys<Priv: PrivateKey>(
        address_keys: &[DecryptedAddressKey<Priv, Pub>],
    ) -> VerificationPreferences<Pub> {
        let mut compromised_fingerprints = HashSet::new();
        let active_address_keys = address_keys
            .iter()
            .filter(|key| {
                if key.flags.is_compromised() {
                    compromised_fingerprints.insert(key.as_public_key().key_fingerprint());
                    return false;
                }
                true
            })
            .map(|address_key| address_key.as_public_key().clone())
            .collect::<Vec<_>>();
        VerificationPreferences {
            ownership: KeyOwnership::SelfOwn,
            pinned_keys: Vec::default(),
            api_keys: active_address_keys,
            compromised_fingerprints,
            key_transparency_verification: KT_VERIFIED,
        }
    }

    /// Selects the valid signature verification keys based on the retrieved keys from another user.
    ///
    /// Selects the public keys for signature verification based on the public keys fetched from the API
    /// and the public keys found in the associated contact.
    #[must_use]
    pub fn from_public_keys(
        api_keys: PublicAddressKeys<Pub>,
        vcard_keys: Option<PinnedPublicKeys<Pub>>,
    ) -> VerificationPreferences<Pub> {
        let inbox_keys = api_keys.into_inbox_keys(true);
        // Filter the inbox keys to be non-compromised and collect fingerprints for the compromised ones.
        let mut compromised_fingerprints = HashSet::new();
        let inbox_keys_active = inbox_keys
            .public_keys
            .into_iter()
            .filter(|public_key| {
                if public_key.flags.is_compromised() {
                    compromised_fingerprints.insert(public_key.as_public_key().key_fingerprint());
                    return false;
                }
                true
            })
            .map(|public_key| public_key.public_keys)
            .collect::<Vec<_>>();
        // Filter the pinned keys to not be flagged as compromised via the API.
        let pinned_keys_active = if let Some(keys) = vcard_keys {
            keys.pinned_keys
                .into_iter()
                .filter(|public_key| {
                    !compromised_fingerprints
                        .contains(&public_key.as_public_key().key_fingerprint())
                })
                .collect::<Vec<_>>()
        } else {
            Vec::default()
        };
        VerificationPreferences {
            ownership: KeyOwnership::Other,
            pinned_keys: pinned_keys_active,
            api_keys: inbox_keys_active,
            compromised_fingerprints,
            key_transparency_verification: inbox_keys.key_transparency_verification,
        }
    }

    /// Returns the a reference to the signature verification keys.
    ///
    /// The keys be the input input to the respective signature verification function.
    /// Pinned keys extracted from contacts are preferred over keys from the API.
    #[must_use]
    pub fn signature_verification_keys(&self) -> &[Pub] {
        if self.uses_pinned_keys() {
            return &self.pinned_keys;
        }
        &self.api_keys
    }

    /// Indicates whether contact pinned keys are used by these preferences.
    #[must_use]
    pub fn uses_pinned_keys(&self) -> bool {
        !self.pinned_keys.is_empty()
    }

    /// Checks whether this `OpenPGP` key fingerprint belongs to a key marked as compromised.
    ///
    /// This can be helpful to check whether as signature was created by a key marked as compromised.
    #[must_use]
    pub fn is_compromised(&self, fingerprint: &OpenPGPFingerprint) -> bool {
        self.compromised_fingerprints.contains(fingerprint)
    }

    /// Are the keys extract from self owned keys.
    #[must_use]
    pub fn self_owned_keys(&self) -> bool {
        matches!(self.ownership, KeyOwnership::SelfOwn)
    }
}
