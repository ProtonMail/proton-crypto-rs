use pgp::{
    composed::{Esk, Message, PlainSessionKey, TheRing},
    packet::PublicKeyEncryptedSessionKey,
};

use crate::{
    DecryptionError, Decryptor, GenericKeyIdentifier, PrivateKey, PrivateKeySelectionExt, Profile,
    PublicKeyExt, UnixTime,
};

pub trait MessageDecryptionExt<'a> {
    /// Decrypts the message using the given decryptor.
    fn decrypt_with_decryptor(self, decryptor: &Decryptor) -> Result<Message<'a>, DecryptionError>;
}

impl<'a> MessageDecryptionExt<'a> for Message<'a> {
    /// Decrypts the message using the given decryptor.
    ///
    /// This is a helper function for the decryptor.
    fn decrypt_with_decryptor(self, decryptor: &Decryptor) -> Result<Message<'a>, DecryptionError> {
        let Message::Encrypted {
            esk,
            edata: _,
            is_nested: _,
        } = &self
        else {
            return Err(DecryptionError::UnexpectedPlaintext);
        };

        // Try to extract session keys to decrypt the message;
        let mut session_keys = Vec::new();
        let mut errors = Vec::new();
        for esk_packet in esk {
            match esk_packet {
                Esk::PublicKeyEncryptedSessionKey(pkesk) => {
                    match handle_pkesk_decryption(
                        pkesk,
                        decryptor.decryption_keys.iter().copied(),
                        decryptor.profile,
                    ) {
                        Ok(session_key) => session_keys.push(session_key),
                        Err(e) => errors.push(e),
                    }
                }
                Esk::SymKeyEncryptedSessionKey(_skesk) => (),
            }
        }

        if session_keys.is_empty() {
            return Err(DecryptionError::SessionKeyDecryption(errors.into()));
        }

        // Use the session keys to decrypt the message with
        // `the ring`
        let the_ring = TheRing {
            secret_keys: Vec::new(),
            key_passwords: Vec::new(),
            message_password: Vec::new(),
            session_keys,
            allow_legacy: false,
        };

        let (message, _) = self.decrypt_the_ring(the_ring, false)?;

        Ok(message)
    }
}

pub(crate) trait PkeskExt {
    /// Returns the generic identifier of the PKESK.
    fn generic_identifier(&self) -> Option<GenericKeyIdentifier>;
}

impl PkeskExt for PublicKeyEncryptedSessionKey {
    fn generic_identifier(&self) -> Option<GenericKeyIdentifier> {
        match (self.id(), self.fingerprint()) {
            (Ok(id), Ok(Some(fp))) => Some(GenericKeyIdentifier::Both(*id, fp.clone())),
            (Ok(id), Err(_) | Ok(None)) => Some(GenericKeyIdentifier::KeyId(*id)),
            (Err(_), Ok(Some(fp))) => Some(GenericKeyIdentifier::Fingerprint(fp.clone())),
            (Err(_), Err(_) | Ok(None)) => None,
        }
    }
}

// Helper function to handle PKESK session key decryption.
fn handle_pkesk_decryption<'a>(
    pkesk: &PublicKeyEncryptedSessionKey,
    decryption_keys: impl Iterator<Item = &'a PrivateKey>,
    profile: &Profile,
) -> Result<PlainSessionKey, DecryptionError> {
    let Some(generic_identifier) = pkesk.generic_identifier() else {
        return Err(DecryptionError::PkeskNoIssuer);
    };
    let mut extracted_sks = None;
    let mut errors = Vec::new();

    // Try to decrypt the PKESK with decryption keys that match the PKESK.
    for decryption_key in decryption_keys.filter(|dk| check_pkesk_match(&generic_identifier, dk)) {
        // Only allow verified decryption keys.
        let decryption_keys_result = decryption_key.secret.decryption_keys(
            UnixTime::zero(), // disable time checks for decryption keys.
            Some(generic_identifier.clone()),
            profile,
        );

        let decryption_keys = match decryption_keys_result {
            Ok(keys) => keys,
            Err(e) => {
                errors.push(DecryptionError::KeySelection(
                    Box::new(generic_identifier.clone()),
                    e,
                ));
                continue;
            }
        };

        // Try to decrypt with the valid component decryption keys.
        if let Some(sk) = decryption_keys.into_iter().find_map(|dk| {
            match dk.private_key.decrypt_session_key(pkesk) {
                Ok(sk) => Some(sk),
                Err(err) => {
                    errors.push(DecryptionError::SinglePkeskDecryption(err));
                    None
                }
            }
        }) {
            extracted_sks = Some(sk);
            break;
        }
    }

    if extracted_sks.is_none() && errors.is_empty() {
        return Err(DecryptionError::PkeskNoMatchingKey(Box::new(
            generic_identifier,
        )));
    }

    extracted_sks.ok_or(DecryptionError::PkeskDecryption(
        Box::new(generic_identifier),
        errors.into(),
    ))
}

/// helper function to check if a decryption key matches a PKESK.
fn check_pkesk_match(pkesk_identifier: &GenericKeyIdentifier, decryption_key: &PrivateKey) -> bool {
    decryption_key
        .secret
        .secret_subkeys
        .iter()
        .map(|k| k.generic_identifier())
        .any(|identifier| &identifier == pkesk_identifier)
        || &decryption_key.as_signed_public_key().generic_identifier() == pkesk_identifier
}
