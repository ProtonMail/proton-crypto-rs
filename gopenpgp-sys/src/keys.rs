#[cfg(test)]
#[path = "tests/keys.rs"]
mod tests;

use std::ffi::c_uchar;
use std::ptr::{null, null_mut};
use std::sync::Arc;

use crate::ext_buffer::ExtBuffer;
use crate::go::PGPError;
use crate::sys::uchar_t;
use crate::{
    sys, DataEncoding, KeyGenerationOptions, OwnedCStr, PGPBytes, SecretBytes, SecretGoBytes,
    SecretString, SessionKeyAlgorithm,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::os::raw::c_void;

pub trait PublicKeyReference {
    fn public_ref(&self) -> &GoKey;

    fn version(&self) -> i32 {
        self.public_ref().version()
    }

    fn key_id(&self) -> u64 {
        self.public_ref().key_id()
    }

    fn key_fingerprint(&self) -> impl AsRef<[u8]> {
        self.public_ref().key_fingerprint()
    }

    fn sha256_key_fingerprints(&self) -> Vec<impl AsRef<[u8]>> {
        self.public_ref().sha256_key_fingerprints()
    }

    fn can_encrypt(&self, unix_time: u64) -> bool {
        self.public_ref().can_encrypt(unix_time)
    }

    fn can_verify(&self, unix_time: u64) -> bool {
        self.public_ref().can_verify(unix_time)
    }

    fn is_expired(&self, unix_time: u64) -> bool {
        self.public_ref().is_expired(unix_time)
    }

    fn is_revoked(&self, unix_time: u64) -> bool {
        self.public_ref().is_revoked(unix_time)
    }
}

pub trait PrivateKeyReference: PublicKeyReference {
    fn private_ref(&self) -> &GoKey;
}

#[derive(Debug)]
pub struct GoKey(usize);

impl Drop for GoKey {
    fn drop(&mut self) {
        unsafe {
            // Also zeros the keys
            sys::pgp_key_destroy(self.0);
        }
    }
}

impl GoKey {
    pub(crate) fn c_handle(&self) -> usize {
        self.0
    }

    fn to_public_key(&self) -> Result<Self, PGPError> {
        unsafe {
            let mut handle: usize = 0;
            let err = sys::pgp_private_key_get_public_key(self.0, &mut handle);
            PGPError::unwrap(err)?;
            Ok(GoKey(handle))
        }
    }

    fn lock_key(&self, password: &[u8]) -> Result<GoKey, PGPError> {
        unsafe {
            let mut handle: usize = 0;
            let err = sys::pgp_key_lock(self.0, password.as_ptr(), password.len(), &mut handle);
            PGPError::unwrap(err)?;
            Ok(GoKey(handle))
        }
    }

    pub fn serialize(&self, force_public: bool, armored: bool) -> Result<Vec<u8>, PGPError> {
        unsafe {
            let mut buffer: ExtBuffer = ExtBuffer::with_capacity(1024);
            let ext_buffer = ExtBuffer::make_ext_buffer_writer(&mut buffer);
            let err = sys::pgp_key_export(self.0, force_public, armored, ext_buffer);
            PGPError::unwrap(err)?;
            Ok(buffer.take())
        }
    }

    fn version(&self) -> i32 {
        unsafe { sys::pgp_key_get_version(self.0) as i32 }
    }

    fn key_id(&self) -> u64 {
        unsafe { sys::pgp_key_get_key_id(self.0) }
    }

    fn key_fingerprint(&self) -> impl AsRef<[u8]> {
        unsafe {
            let mut size: usize = 0;
            let mut data: *mut uchar_t = null_mut();
            sys::pgp_key_get_fingerprint_bytes(self.0, &mut data, &mut size);
            PGPBytes::new(data, size)
        }
    }

    fn sha256_key_fingerprints(&self) -> Vec<impl AsRef<[u8]>> {
        unsafe {
            let out = sys::pgp_key_get_sha256_fingerprints(self.0);
            let mut fingerprints = Vec::with_capacity(out.num);
            if out.num == 0 || out.strings.is_null() {
                return fingerprints;
            }
            let fingerprints_array = std::slice::from_raw_parts(out.strings, out.num);
            for ptr in fingerprints_array {
                fingerprints.push(OwnedCStr::new(*ptr));
            }
            sys::pgp_free(out.strings as *mut c_void);
            fingerprints
        }
    }

    fn can_encrypt(&self, unix_time: u64) -> bool {
        unsafe { sys::pgp_key_can_encrypt(self.0, unix_time) }
    }

    fn can_verify(&self, unix_time: u64) -> bool {
        unsafe { sys::pgp_key_can_encrypt(self.0, unix_time) }
    }

    fn is_expired(&self, unix_time: u64) -> bool {
        unsafe { sys::pgp_key_is_expired(self.0, unix_time) }
    }

    fn is_revoked(&self, unix_time: u64) -> bool {
        unsafe { sys::pgp_key_is_revoked(self.0, unix_time) }
    }
}

// For cheap clones we use a reference counter to the go handle.
// The invariant is that the GoKey is immutable.
#[derive(Debug, Clone)]
pub struct PublicKey(Arc<GoKey>);

impl PublicKeyReference for PublicKey {
    fn public_ref(&self) -> &GoKey {
        &self.0
    }
}

impl PublicKey {
    pub fn import(public_key: &[u8], encoding: DataEncoding) -> Result<Self, PGPError> {
        unsafe {
            let mut key_handle = 0usize;
            let err = sys::pgp_public_key_import(
                public_key.as_ptr(),
                public_key.len(),
                encoding.go_id(),
                &mut key_handle,
            );
            PGPError::unwrap(err)?;

            Ok(Self(Arc::new(GoKey(key_handle))))
        }
    }

    pub fn export(&self, armored: bool) -> Result<Vec<u8>, PGPError> {
        self.0.serialize(true, armored)
    }
}

// For cheap clones we use a reference counter to the go handle.
// The invariant is that the GoKey is immutable in the go world.
#[derive(Debug, Clone)]
pub struct PrivateKey(Arc<GoKey>);

impl PrivateKeyReference for PrivateKey {
    fn private_ref(&self) -> &GoKey {
        &self.0
    }
}

impl PublicKeyReference for PrivateKey {
    fn public_ref(&self) -> &GoKey {
        &self.0
    }
}

impl PrivateKey {
    pub fn import(
        private_key: &[u8],
        passphrase: &[u8],
        encoding: DataEncoding,
    ) -> Result<Self, PGPError> {
        unsafe {
            let mut key_handle = 0usize;
            let err = sys::pgp_private_key_import(
                private_key.as_ptr(),
                private_key.len(),
                passphrase.as_ptr(),
                passphrase.len(),
                encoding.go_id(),
                &mut key_handle,
            );
            PGPError::unwrap(err)?;

            Ok(Self(Arc::new(GoKey(key_handle))))
        }
    }

    pub fn import_unlocked(private_key: &[u8], encoding: DataEncoding) -> Result<Self, PGPError> {
        unsafe {
            let mut key_handle = 0usize;
            let err = sys::pgp_private_key_import(
                private_key.as_ptr(),
                private_key.len(),
                null(),
                0,
                encoding.go_id(),
                &mut key_handle,
            );
            PGPError::unwrap(err)?;

            Ok(Self(Arc::new(GoKey(key_handle))))
        }
    }

    pub fn import_from_api_message<'a>(
        keys: &'a [impl PrivateKeyReference + 'a],
        private_key: &'a [u8],
        message: &'a str,
        signature: &'a str,
    ) -> Result<PrivateKey, PGPError> {
        unsafe {
            let mut key_handle = 0usize;
            let handles: Vec<usize> = keys
                .iter()
                .map(|key| key.private_ref().c_handle())
                .collect();
            let err = sys::pgp_key_unlock_with_token(
                handles.as_ptr().cast(),
                handles.len(),
                private_key.as_ptr(),
                private_key.len(),
                message.as_ptr().cast(),
                message.len(),
                signature.as_ptr().cast(),
                signature.len(),
                &mut key_handle,
            );

            PGPError::unwrap(err)?;

            Ok(Self(Arc::new(GoKey(key_handle))))
        }
    }

    pub fn export(&self, passphrase: &[u8], armored: bool) -> Result<Vec<u8>, PGPError> {
        let locked_key = self.0.lock_key(passphrase)?;
        locked_key.serialize(false, armored)
    }

    pub fn export_unlocked(&self, armored: bool) -> Result<impl AsRef<[u8]>, PGPError> {
        let data = self.0.serialize(false, armored)?;
        Ok(SecretBytes::new(data))
    }

    pub fn to_public_key_implicit(&self) -> PublicKey {
        PublicKey(self.0.clone())
    }

    pub fn to_public_key(&self) -> Result<PublicKey, PGPError> {
        let go_key = self.0.to_public_key()?;
        Ok(PublicKey(Arc::new(go_key)))
    }
}

#[derive(Debug)]
pub struct SessionKey(pub(crate) usize);

impl Drop for SessionKey {
    fn drop(&mut self) {
        unsafe {
            // Zeros the session key as well
            sys::pgp_session_key_destroy(self.0);
        }
    }
}

impl Clone for SessionKey {
    fn clone(&self) -> Self {
        unsafe {
            let cloned_session_key = sys::pgp_clone_session_key(self.0);
            Self(cloned_session_key)
        }
    }
}

impl SessionKey {
    pub(crate) fn c_handle(&self) -> usize {
        self.0
    }
}

impl SessionKey {
    pub fn generate(algorithm: SessionKeyAlgorithm) -> Result<Self, PGPError> {
        unsafe {
            let mut session_key_handle = 0usize;
            let err = sys::pgp_generate_session_key(
                algorithm.go_key_algorithm(),
                &mut session_key_handle,
            );
            PGPError::unwrap(err)?;

            Ok(Self(session_key_handle))
        }
    }

    pub fn from_token(token: &[u8], algorithm: SessionKeyAlgorithm) -> Self {
        unsafe {
            Self(sys::pgp_new_session_key_from_token(
                token.as_ptr(),
                token.len(),
                algorithm.go_key_algorithm(),
            ))
        }
    }

    pub fn algorithm(&self) -> Result<SessionKeyAlgorithm, PGPError> {
        unsafe {
            let mut out: c_uchar = 0;
            let err = sys::pgp_session_key_get_algorithm(self.0, &mut out);
            PGPError::unwrap(err)?;
            Ok(SessionKeyAlgorithm::from_go_cipher_id(out))
        }
    }

    pub fn export_token(&self) -> impl AsRef<[u8]> {
        unsafe {
            let mut size: usize = 0;
            let mut data: *mut uchar_t = null_mut();
            sys::pgp_session_key_export_token(self.0, &mut data, &mut size);
            SecretGoBytes::new(data, size)
        }
    }

    pub fn export_token_base64(&self) -> impl AsRef<str> {
        SecretString::new(STANDARD.encode(self.export_token()))
    }
}

impl Default for sys::PGP_KeyGeneration {
    fn default() -> Self {
        Self {
            algorithm: KeyGenerationOptions::Default.go_id(),
            email: null_mut(),
            email_len: 0,
            name: null_mut(),
            name_len: 0,
            has_generation_time: false,
            has_user_id: false,
            generation_time: 0,
        }
    }
}

pub struct KeyGenerator {
    algorithm: KeyGenerationOptions,
    user_id: Option<(String, String)>,
    generation_time: Option<u64>,
}

impl KeyGenerator {
    fn create_c_key_generator(&self) -> sys::PGP_KeyGeneration {
        let mut c_handle = sys::PGP_KeyGeneration::default();
        if let Some((name, email)) = &self.user_id {
            c_handle.has_user_id = true;
            c_handle.email = email.as_ptr().cast();
            c_handle.email_len = email.len();
            c_handle.name = name.as_ptr().cast();
            c_handle.name_len = name.len();
        }
        if let Some(generation_time) = self.generation_time {
            c_handle.has_generation_time = true;
            c_handle.generation_time = generation_time;
        }
        c_handle.algorithm = self.algorithm.go_id();
        c_handle
    }
}

impl Default for KeyGenerator {
    fn default() -> Self {
        Self {
            algorithm: KeyGenerationOptions::Default,
            user_id: None,
            generation_time: None,
        }
    }
}

impl KeyGenerator {
    pub fn new() -> Self {
        KeyGenerator::default()
    }

    pub fn with_user_id(mut self, name: &str, email: &str) -> Self {
        self.user_id = Some((name.to_owned(), email.to_owned()));
        self
    }

    pub fn with_generation_time(mut self, unix_time: u64) -> Self {
        self.generation_time = Some(unix_time);
        self
    }

    pub fn with_algorithm(mut self, option: KeyGenerationOptions) -> Self {
        self.algorithm = option;
        self
    }

    pub fn generate(self) -> Result<PrivateKey, PGPError> {
        let c_key_generator = self.create_c_key_generator();
        unsafe {
            let mut out_handle: usize = 0;
            let err = sys::pgp_generate_key(&c_key_generator, &mut out_handle);
            PGPError::unwrap(err)?;
            Ok(PrivateKey(Arc::new(GoKey(out_handle))))
        }
    }
}

pub(crate) fn get_key_handles(keys: &[&GoKey]) -> Vec<usize> {
    keys.iter().map(|key| key.c_handle()).collect()
}
