use gopenpgp_sys::armor::ArmorType;

use crate::crypto::ArmorerSync;

pub struct GoArmorer {}

impl ArmorerSync for GoArmorer {
    fn armor_public_key(&self, public_key: impl AsRef<[u8]>) -> crate::Result<Vec<u8>> {
        gopenpgp_sys::armor::armor(public_key.as_ref(), ArmorType::PublicKey).map_err(Into::into)
    }

    fn armor_private_key(&self, private_key: impl AsRef<[u8]>) -> crate::Result<Vec<u8>> {
        gopenpgp_sys::armor::armor(private_key.as_ref(), ArmorType::PrivateKey).map_err(Into::into)
    }

    fn armor_signature(&self, signature: impl AsRef<[u8]>) -> crate::Result<Vec<u8>> {
        gopenpgp_sys::armor::armor(signature.as_ref(), ArmorType::Signature).map_err(Into::into)
    }

    fn armor_message(&self, message: impl AsRef<[u8]>) -> crate::Result<Vec<u8>> {
        gopenpgp_sys::armor::armor(message.as_ref(), ArmorType::Message).map_err(Into::into)
    }

    fn unarmor(&self, armored: impl AsRef<[u8]>) -> crate::Result<Vec<u8>> {
        gopenpgp_sys::armor::unarmor(armored.as_ref()).map_err(Into::into)
    }
}
