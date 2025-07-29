use proton_rpgp::armor;

use crate::crypto::ArmorerSync;

#[derive(Default, Clone, Copy)]
pub struct RustArmorer {}

impl ArmorerSync for RustArmorer {
    fn armor_public_key(&self, public_key: impl AsRef<[u8]>) -> crate::Result<Vec<u8>> {
        armor::armor_public_key(public_key).map_err(Into::into)
    }

    fn armor_private_key(&self, private: impl AsRef<[u8]>) -> crate::Result<Vec<u8>> {
        armor::armor_private_key(private).map_err(Into::into)
    }

    fn armor_signature(&self, signature: impl AsRef<[u8]>) -> crate::Result<Vec<u8>> {
        armor::armor_signature(signature).map_err(Into::into)
    }

    fn armor_message(&self, message: impl AsRef<[u8]>) -> crate::Result<Vec<u8>> {
        armor::armor_message(message).map_err(Into::into)
    }

    fn unarmor(&self, armored: impl AsRef<[u8]>) -> crate::Result<Vec<u8>> {
        armor::unarmor(armored).map_err(Into::into)
    }
}
