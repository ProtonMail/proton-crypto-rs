use std::ffi::c_uchar;

use crate::{ext_buffer::ExtBuffer, sys, PGPError};

#[derive(PartialEq, Eq, Copy, Hash, Clone, Debug)]
pub enum ArmorType {
    Message,
    Signature,
    PublicKey,
    PrivateKey,
}

impl ArmorType {
    pub(crate) fn get_go_id(&self) -> c_uchar {
        match self {
            ArmorType::Message => sys::PGP_ARMOR_HEADER::ARMOR_MESSAGE as c_uchar,
            ArmorType::Signature => sys::PGP_ARMOR_HEADER::ARMOR_SIGNATURE as c_uchar,
            ArmorType::PublicKey => sys::PGP_ARMOR_HEADER::ARMOR_PUB_KEY as c_uchar,
            ArmorType::PrivateKey => sys::PGP_ARMOR_HEADER::ARMOR_PRIV_KEY as c_uchar,
        }
    }
}

pub fn armor(data: &[u8], armor_type: ArmorType) -> Result<Vec<u8>, PGPError> {
    unsafe {
        let mut buffer = ExtBuffer::with_capacity(data.len());
        let ext_buffer = ExtBuffer::make_ext_buffer_writer(&mut buffer);
        let err = sys::pgp_armor_message(
            data.as_ptr(),
            data.len(),
            armor_type.get_go_id(),
            ext_buffer,
        );
        PGPError::unwrap(err)?;
        Ok(buffer.take())
    }
}

pub fn unarmor(data: &[u8]) -> Result<Vec<u8>, PGPError> {
    unsafe {
        let mut buffer = ExtBuffer::with_capacity(data.len());
        let ext_buffer = ExtBuffer::make_ext_buffer_writer(&mut buffer);
        let err = sys::pgp_unarmor_message(data.as_ptr(), data.len(), ext_buffer);
        PGPError::unwrap(err)?;
        Ok(buffer.take())
    }
}

pub fn is_armored(data: &[u8]) -> bool {
    let Ok(data_str) = std::str::from_utf8(data) else {
        return false;
    };
    let begin_marker = "-----BEGIN PGP";
    let end_marker = "-----END PGP";
    let (Some(begin_index), Some(end_index)) =
        (data_str.find(begin_marker), data_str.find(end_marker))
    else {
        return false;
    };
    end_index > begin_index
}
