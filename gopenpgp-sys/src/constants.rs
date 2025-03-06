use std::ffi::c_uchar;

use crate::sys;

#[derive(PartialEq, Eq, Hash, Clone, Copy, Debug)]
pub enum DataEncoding {
    Armor,
    Bytes,
    Auto,
}

#[derive(PartialEq, Eq, Hash, Clone, Copy, Debug)]
pub enum SessionKeyAlgorithm {
    Default,
    TripleDes,
    Cast5,
    Aes128,
    Aes192,
    Aes256,
}

#[derive(PartialEq, Eq, Hash, Clone, Copy, Debug)]
pub enum KeyGenerationOptions {
    Default,
    ECCurve25519,
    RSA4096,
}

impl DataEncoding {
    pub(crate) fn go_id(&self) -> c_uchar {
        match self {
            DataEncoding::Armor => sys::PGP_DATA_ENCODING::ARMOR as c_uchar,
            DataEncoding::Bytes => sys::PGP_DATA_ENCODING::BYTES as c_uchar,
            DataEncoding::Auto => sys::PGP_DATA_ENCODING::AUTO as c_uchar,
        }
    }
}

impl SessionKeyAlgorithm {
    pub(crate) fn from_go_cipher_id(id: c_uchar) -> Self {
        match id {
            x if x == sys::PGP_SYMMETRIC_CIPHERS::TRIPLE_DES as c_uchar => Self::TripleDes,
            x if x == sys::PGP_SYMMETRIC_CIPHERS::CAST5 as c_uchar => Self::Cast5,
            x if x == sys::PGP_SYMMETRIC_CIPHERS::AES_128 as c_uchar => Self::Aes128,
            x if x == sys::PGP_SYMMETRIC_CIPHERS::AES_192 as c_uchar => Self::Aes192,
            x if x == sys::PGP_SYMMETRIC_CIPHERS::AES_256 as c_uchar => Self::Aes256,
            _ => Self::Default,
        }
    }

    pub(crate) fn go_key_algorithm(&self) -> sys::PGP_SYMMETRIC_CIPHERS {
        match self {
            SessionKeyAlgorithm::Aes128 => sys::PGP_SYMMETRIC_CIPHERS::AES_128,
            SessionKeyAlgorithm::Default | SessionKeyAlgorithm::Aes256 => {
                sys::PGP_SYMMETRIC_CIPHERS::AES_256
            }
            SessionKeyAlgorithm::TripleDes => sys::PGP_SYMMETRIC_CIPHERS::TRIPLE_DES,
            SessionKeyAlgorithm::Cast5 => sys::PGP_SYMMETRIC_CIPHERS::CAST5,
            SessionKeyAlgorithm::Aes192 => sys::PGP_SYMMETRIC_CIPHERS::AES_192,
        }
    }
}

impl KeyGenerationOptions {
    pub(crate) fn go_id(&self) -> c_uchar {
        match self {
            KeyGenerationOptions::Default | KeyGenerationOptions::ECCurve25519 => {
                sys::PGP_KEY_GENERATION::KEY_GEN_ECC as c_uchar
            }
            KeyGenerationOptions::RSA4096 => sys::PGP_KEY_GENERATION::KEY_GEN_RSA as c_uchar, // Not supported yet
        }
    }
}
