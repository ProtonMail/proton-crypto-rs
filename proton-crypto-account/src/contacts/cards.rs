use derive_more::derive::TryFrom;
use proton_crypto::{
    crypto::{
        AsPublicKeyRef, DataEncoding, Decryptor, DecryptorSync, DetachedSignatureVariant,
        Encryptor, EncryptorSync, PGPProviderSync, Signer, SignerSync, SigningMode, VerifiedData,
        Verifier, VerifierSync, WritingMode,
    },
    utils::remove_trailing_spaces,
};
use std::str;

#[cfg(feature = "sql")]
use rusqlite::{
    types::{FromSql, FromSqlError, FromSqlResult, ToSql, ToSqlOutput, ValueRef},
    Error,
};

use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

use crate::{errors::CardCryptoError, keys::UnlockedUserKey};

crate::string_id! {
    /// An armored signature calculated on a plaintext vcard of a contact
    CardSignature
}

crate::string_id! {
    /// An armored ciphertext calculated on a plaintext vcard of a contact
    EncryptedCard
}

#[derive(Debug, Eq, PartialEq, Clone, Copy, Deserialize_repr, Serialize_repr, TryFrom)]
#[try_from(repr)]
#[repr(u8)]
pub enum ContactCardType {
    /// The card is in cleartext.
    ClearText = 0,
    /// The card is encrypted but not signed.
    Encrypted = 1,
    /// The card is signed.
    Signed = 2,
    /// The card is encrypted and signed.
    EncryptedAndSigned = 3,
}

#[cfg(feature = "sql")]
impl ToSql for ContactCardType {
    fn to_sql(&self) -> Result<ToSqlOutput, Error> {
        Ok(ToSqlOutput::from(*self as u8))
    }
}

#[cfg(feature = "sql")]
impl FromSql for ContactCardType {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        let val = u8::column_result(value)?;
        Self::try_from(val).map_err(|_| FromSqlError::OutOfRange(i64::from(val)))
    }
}

/// `DecryptableVerifiableCard` provides the ability to access the data from within contact cards, decrypting encrypted data
/// and verifying and signatures present
pub trait DecryptableVerifiableCard {
    /// Returns the card's crypto type.
    fn card_type(&self) -> ContactCardType;

    /// Returns the raw card data, which is either encrypted or in plain text.
    fn card_data(&self) -> &[u8];

    /// Returns the raw detached signature of the card if any.
    fn card_signature(&self) -> Option<&[u8]>;

    /// Returns the plain text data from the card.  If the card has been encrypted, it is decrypted.  If the card
    /// is signed, the signature is verified.
    ///
    /// # Parameters
    /// * `provider` - The pgp provider instance from [`proton_crypto`].
    /// * `decryption_keys` - The set of keys which will be used to decrypt the contact card
    /// * `verification_keys` - The set of keys which will be used to verify the signature on the contact card
    ///
    /// # Errors
    /// When decryption or signature verification fail
    fn decrypt_and_verify_sync<T: PGPProviderSync>(
        &self,
        provider: &T,
        decryption_keys: &[impl AsRef<T::PrivateKey>],
        verification_keys: &[impl AsPublicKeyRef<T::PublicKey>],
    ) -> Result<Vec<u8>, CardCryptoError> {
        match self.card_type() {
            ContactCardType::ClearText => Ok(self.card_data().to_owned()),
            ContactCardType::Encrypted => Ok(provider
                .new_decryptor()
                .with_decryption_key_refs(decryption_keys)
                .decrypt(self.card_data(), DataEncoding::Armor)
                .map_err(CardCryptoError::DecryptionError)?
                .into_vec()),
            ContactCardType::Signed => {
                // Strip trailing spaces to verify legacy contacts.
                let cleaned_data = remove_trailing_spaces(str::from_utf8(self.card_data())?);
                provider
                    .new_verifier()
                    .with_verification_key_refs(verification_keys)
                    .verify_detached(
                        cleaned_data,
                        self.card_signature().ok_or(CardCryptoError::NoSignature)?,
                        DataEncoding::Armor,
                    )
                    .map_err(CardCryptoError::SignatureVerificationError)?;
                Ok(self.card_data().to_owned())
            }
            ContactCardType::EncryptedAndSigned => {
                let decrypted_card_result = provider
                    .new_decryptor()
                    .with_decryption_key_refs(decryption_keys)
                    .with_verification_key_refs(verification_keys)
                    .with_detached_signature_ref(
                        self.card_signature().ok_or(CardCryptoError::NoSignature)?,
                        DetachedSignatureVariant::Plaintext,
                        true,
                    )
                    .decrypt(self.card_data(), DataEncoding::Armor)
                    .map_err(CardCryptoError::DecryptionError)?;
                decrypted_card_result.verification_result()?;
                Ok(decrypted_card_result.into_vec())
            }
        }
    }
}

/// `EncryptableAndSignableCard` provides the ability to sign or encrypt and sign contact vcards
pub trait EncryptableAndSignableCard {
    /// Returns a slice of the plaintext card data comprising a contact v-card.
    fn plaintext_card_data(&self) -> &[u8];

    /// Encrypt and and sign the plaintext card data.  This will produce two output values: the encrypted card
    /// and the detached signature calculated over the plaintext card data.
    ///
    /// # Parameters
    /// * `provider` - The PGP provider instance from [`proton_crypto`].
    /// * `user_key` - The PGP keys that the contact vcard is to be encrypted to and signed by
    ///
    /// # Errors
    /// Returns a `CardCryptoError` if the encryption, or signing fails.  Or alternatively if there are issues
    /// writing the plaintext vcard data to the stream encryptor or performing the string encoding of the ciphertext
    /// or detached signature.
    fn encrypt_and_sign_sync<T: PGPProviderSync>(
        &self,
        provider: &T,
        user_key: &UnlockedUserKey<T>,
    ) -> Result<(EncryptedCard, CardSignature), CardCryptoError> {
        let mut result_data: Vec<u8> = Vec::new();
        let detached_data = provider
            .new_encryptor()
            .with_encryption_key(user_key.as_public_key())
            .with_signing_key(user_key.as_ref())
            .with_utf8()
            .encrypt_to_writer(
                self.plaintext_card_data(),
                DataEncoding::Armor,
                SigningMode::Detached(DetachedSignatureVariant::Plaintext),
                WritingMode::All,
                &mut result_data,
            )
            .map_err(CardCryptoError::EncryptionError)?;

        let detached_signature = detached_data
            .try_into_detached_signature()
            .map_err(CardCryptoError::EncryptionError)?;

        Ok((
            EncryptedCard(String::from_utf8(result_data).map_err(CardCryptoError::EncodingError)?),
            CardSignature(
                String::from_utf8(detached_signature).map_err(CardCryptoError::EncodingError)?,
            ),
        ))
    }

    /// Create a detached signature for plaintext, contact vcard data.
    ///
    /// # Parameters
    /// * `provider` - The PGP provider instance from [`proton_crypto`].
    /// * `user_key` - The PGP keys that the contact vcard is to be signed by.
    ///
    /// # Errors
    /// Returns a `CardCryptoError` if signing the card fails or encoding the armored signature into a string fails
    fn sign_sync<T: PGPProviderSync>(
        &self,
        provider: &T,
        user_key: &UnlockedUserKey<T>,
    ) -> Result<CardSignature, CardCryptoError> {
        // Strip trailing spaces for detached signing.
        let cleaned_data = remove_trailing_spaces(str::from_utf8(self.plaintext_card_data())?);
        let signature = provider
            .new_signer()
            .with_signing_key(user_key.as_ref())
            .sign_detached(&cleaned_data, DataEncoding::Armor)
            .map_err(CardCryptoError::SigningError)?;

        Ok(CardSignature(
            String::from_utf8(signature).map_err(CardCryptoError::EncodingError)?,
        ))
    }
}
