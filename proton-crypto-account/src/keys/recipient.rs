use std::{collections::HashSet, fmt::Display};

use proton_crypto::{
    crypto::{OpenPGPFingerprint, PublicKey, UnixTimestamp},
    keytransparency::KTVerificationResult,
};

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
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
    #[must_use]
    pub fn from_public_keys_at_time(
        api_keys: PublicAddressKeys<Pub>,
        pinned_keys: Option<PinnedPublicKeys<Pub>>,
        encryption_time: UnixTimestamp,
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
        );

        let ordered_pinned_keys = pinned_keys
            .map(|value| {
                Self::sort_pinned_keys_by_priority(
                    value.pinned_keys,
                    &obsolete_fingerprints,
                    &compromised_fingerprints,
                    &encryption_capable_fingerprints,
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
    ) -> Vec<Pub> {
        let mut keys_with_order = public_keys
            .into_iter()
            .map(|public_key| {
                let fingerprint = public_key.public_keys.key_fingerprint();
                let bitmask = (u8::from(public_key.public_keys.version() != 6) << 4) // isNotPreferredVersion
                    | (u8::from(!public_key.primary) << 3) // isNotPrimary
                    | (u8::from(obsolete_fingerprints.contains(&fingerprint)) << 2) // isObsolete
                    | (u8::from(compromised_fingerprints.contains(&fingerprint)) << 1) // isCompromised
                    | u8::from(!trusted_fingerprints.contains(&fingerprint)); // isNotTrusted

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
    ) -> Vec<Pub> {
        let mut keys_with_order = pinned_keys
            .into_iter()
            .map(|public_key| {
                let fingerprint = public_key.key_fingerprint();
                let bitmask = (u8::from(public_key.version() != 6) << 3) // isNotPreferredVersion
                    | (u8::from(obsolete_fingerprints.contains(&fingerprint)) << 2) // isObsolete
                    | (u8::from(compromised_fingerprints.contains(&fingerprint)) << 1) // isCompromised
                    | u8::from(!encryption_capable_fingerprints.contains(&fingerprint)); // cannotSend

                (bitmask, public_key)
            })
            .collect::<Vec<_>>();

        keys_with_order.sort_by(|a, b| a.0.cmp(&b.0));
        keys_with_order.into_iter().map(|(_, key)| key).collect()
    }
}
