use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{
    aead::{AesGcmKey, AES_GCM_256_KEY_SIZE},
    SubtleError, SubtleResult,
};

const MIN_SECRET_LEN: usize = 16;

/// Derives an AES-GCM-256 key from a secret using HKDF-SHA256.
///
/// The `info` parameter is used bind the derived key to context.
/// It is recommended that the number of salt bytes equlas the ouput length.
///
/// # Security
///
/// The input secret must be a high-entropy secret and not a password.
/// For password-based key deriviation, a password-key derivation function should be used instead.
///
/// # Examples
///
/// ```
/// use proton_crypto_subtle::hkdf;
///
/// let secret = [0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x7a, 0x8b, 0x9c, 0xad, 0xbe, 0xcf, 0xd0, 0xe1, 0xf2, 0x03, 0x14, 0x25, 0x36, 0x47, 0x58, 0x69, 0x7a, 0x8b, 0x9c, 0xad, 0xbe, 0xcf, 0xd0, 0xe1, 0xf2, 0x03];
/// let salt = [0_u8; 32];
///
/// let info = b"my-info";
///
/// let key = hkdf::derive_aes_gcm_key(&secret, &salt, info).unwrap();
///
pub fn derive_aes_gcm_key(
    high_entropy_secret: &[u8],
    salt: &[u8],
    info: &[u8],
) -> SubtleResult<AesGcmKey> {
    if high_entropy_secret.len() < MIN_SECRET_LEN {
        return Err(SubtleError::InvalidSecretLen);
    }

    let mut out = Zeroizing::new([0_u8; AES_GCM_256_KEY_SIZE]);
    let hkdf = Hkdf::<Sha256>::new(Some(salt), high_entropy_secret);
    hkdf.expand(info, out.as_mut_slice())
        .map_err(|_| SubtleError::InvalidKeyLength)?;
    AesGcmKey::from_bytes(out)
}
