use proton_crypto::{
    crypto::PublicKey,
    keytransparency::{KTVerificationResult, KT_UNVERIFIED},
};

use super::{APIPublicKeySource, PublicAddressKey, PublicAddressKeys};

/// Recipient type is either `External` or `Internal`.
#[derive(Debug, Eq, PartialEq, Hash, Clone, Copy)]
pub enum RecipientType {
    Internal,
    External,
}

/// `AddressType` type is either `Normal` or `CatchAll`.
#[derive(Debug, Eq, PartialEq, Hash, Clone, Copy)]
pub enum AddressType {
    Normal,
    CatchAll,
}

/// The inbox public keys for an e-mail address.
///
/// Represents the filtered address keys form the `keys_all` route.
#[derive(Debug, Clone)]
#[allow(clippy::module_name_repetitions)]
pub struct InboxPublicKeys<Pub: PublicKey> {
    /// The public address keys.
    pub public_keys: Vec<PublicAddressKey<Pub>>,
    /// Indicates if the public keys are internal or external.
    pub recipient_type: RecipientType,
    /// Indicates if this key belongs to a catch-all address.
    pub address_type: AddressType,
    /// Internal addresses with e2ee disabled are marked as having EXTERNAL recipient type.
    /// This flag allows distinguishing them from actual external users, for which E2EE should
    /// never be disabled, even for mail (since e.g. they might have WKD set up, or uploaded keys associated with them).
    pub is_internal_with_disabled_e2ee: bool,
    /// List of warnings to show to the user related to phishing and message routing.
    pub warnings: Vec<String>,
    /// The key transparency verification result.
    ///
    /// Contains an unverified error if no verification was performed.
    pub key_transparency_verification: KTVerificationResult,
}

impl<Pub: PublicKey> PublicAddressKeys<Pub> {
    /// Transforms publ keys fetched and imported from the `keys/all` route into
    /// public keys used by inbox for mail encryption and signature verification.
    ///
    /// The `include_internal_keys_with_e2ee_disabled` indicates if internal keys
    /// with end-to-end encryption disabled should be considered in the output.
    #[must_use]
    pub fn into_inbox_keys(
        self,
        include_internal_keys_with_e2ee_disabled: bool,
    ) -> InboxPublicKeys<Pub> {
        let valid_proton_mx = self.proton_mx;

        if !self.address.keys.is_empty() {
            let internal_address_keys = self.address.keys;
            if let Some(mut inbox_key) = handle_address_keys(
                internal_address_keys,
                self.address.kt_verification,
                include_internal_keys_with_e2ee_disabled,
                valid_proton_mx,
            ) {
                inbox_key.warnings = self.warnings;
                return inbox_key;
            }
            // else, the recipient is believed external, and no address keys are returned
        }

        // Then we check if there are unverified internal address keys
        let mut mail_capable_external_keys_option: Option<Vec<PublicAddressKey<Pub>>> = None;
        if let Some(unverified_keys_group) = self.unverified {
            let mut mail_capable_internal_keys = Vec::new();
            let mut mail_capable_external_keys = Vec::new();
            for key in unverified_keys_group.keys {
                if key.flags.supports_mail() {
                    match key.source {
                        APIPublicKeySource::Proton => mail_capable_internal_keys.push(key),
                        _ => mail_capable_external_keys.push(key),
                    }
                }
            }
            mail_capable_external_keys_option = Some(mail_capable_external_keys);
            if !mail_capable_internal_keys.is_empty() {
                return InboxPublicKeys {
                    public_keys: mail_capable_internal_keys, // we checked `addressKeysForMailEncryption` to determine if the recipient is internal, but we return all keys as that's requested by the caller
                    recipient_type: RecipientType::Internal, // as e2ee-disabled flags are ignored, then from the perspective of the caller, this is an internal recipient
                    address_type: AddressType::Normal, // unused, could also be set to undefined
                    warnings: self.warnings,
                    is_internal_with_disabled_e2ee: false,
                    key_transparency_verification: KT_UNVERIFIED, // TODO: might want to return failure if one verification address/catch-all failed
                };
            }
        }

        // Then we check if there are internal catchall keys
        if let Some(catch_all_keys_group) = self.catch_all {
            let mail_capable_catch_all_keys: Vec<_> = catch_all_keys_group
                .keys
                .into_iter()
                .filter(|key| key.flags.supports_mail())
                .collect();
            if !mail_capable_catch_all_keys.is_empty() {
                return InboxPublicKeys {
                    public_keys: mail_capable_catch_all_keys,
                    recipient_type: RecipientType::Internal,
                    address_type: AddressType::CatchAll,
                    warnings: self.warnings,
                    is_internal_with_disabled_e2ee: false,
                    key_transparency_verification: catch_all_keys_group.kt_verification,
                };
            }
        }

        // Finally we check if there are external unverified keys
        if let Some(mail_capable_external_keys) = mail_capable_external_keys_option {
            if let Some(key) = mail_capable_external_keys.into_iter().next() {
                return InboxPublicKeys {
                    public_keys: vec![key],
                    recipient_type: RecipientType::External,
                    address_type: AddressType::Normal,
                    warnings: self.warnings,
                    is_internal_with_disabled_e2ee: false,
                    key_transparency_verification: KT_UNVERIFIED, // TODO: might want to return failure if one verification address/catch-all failed
                };
            }
        }

        InboxPublicKeys {
            public_keys: Vec::new(),
            recipient_type: RecipientType::External,
            address_type: AddressType::Normal,
            warnings: self.warnings,
            is_internal_with_disabled_e2ee: false,
            key_transparency_verification: KT_UNVERIFIED, // TODO: might want to return failure if one verification address/catch-all failed
        }
    }
}

fn handle_address_keys<T: PublicKey>(
    internal_address_keys: Vec<PublicAddressKey<T>>,
    kt_result: KTVerificationResult,
    include_internal_keys_with_e2ee_disabled: bool,
    valid_proton_mx: bool,
) -> Option<InboxPublicKeys<T>> {
    let has_mail_enc_keys = internal_address_keys
        .iter()
        .any(|key| key.flags.supports_mail());

    if !include_internal_keys_with_e2ee_disabled && has_mail_enc_keys {
        // E2EE is disabled with external forwarding, as well as in some setups with custom addresses.
        // unclear when/if it can happen that some keys have e2ee-disabled and some are not, but for now we cover the case.
        let mail_enc_keys: Vec<_> = internal_address_keys
            .into_iter()
            .filter(|key| key.flags.supports_mail())
            .collect();
        return Some(InboxPublicKeys {
            public_keys: mail_enc_keys,
            recipient_type: RecipientType::Internal,
            address_type: AddressType::Normal,
            warnings: Vec::new(),
            is_internal_with_disabled_e2ee: false,
            key_transparency_verification: kt_result,
        });
    }

    if !include_internal_keys_with_e2ee_disabled && !has_mail_enc_keys && valid_proton_mx {
        // All keys are disabled for E2EE in mail, hence the recipient may be treated as external
        return Some(InboxPublicKeys {
            public_keys: Vec::new(),
            recipient_type: RecipientType::External,
            address_type: AddressType::Normal,
            warnings: Vec::new(),
            is_internal_with_disabled_e2ee: true,
            key_transparency_verification: kt_result,
        });
    }

    if include_internal_keys_with_e2ee_disabled && (has_mail_enc_keys || valid_proton_mx) {
        return Some(InboxPublicKeys {
            public_keys: internal_address_keys, // we checked `addressKeysForMailEncryption` to determine if the recipient is internal, but we return all keys as that's requested by the caller
            recipient_type: RecipientType::Internal, // as e2ee-disabled flags are ignored, then from the perspective of the caller, this is an internal recipient
            address_type: AddressType::Normal,       // unused, could also be set to undefined
            warnings: Vec::new(),
            is_internal_with_disabled_e2ee: !has_mail_enc_keys,
            key_transparency_verification: kt_result,
        });
    }

    None
}
