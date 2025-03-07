#[cfg(test)]
#[path = "tests/decryption.rs"]
mod tests;

use std::{
    io::{self, Error, ErrorKind},
    ptr::null_mut,
};

use crate::{
    ext_buffer::ExtBuffer,
    get_key_handles,
    streaming::ReaderForGo,
    sys::{self},
    DataEncoding, GoKey, PGPError, PrivateKeyReference, PublicKeyReference, SessionKey,
    VerificationContext, VerificationResult, Verifier,
};

#[derive(Debug)]
pub struct VerifiedData {
    pub(crate) data: Vec<u8>,
    pub(crate) verification_result: Option<VerificationResult>,
}

impl AsRef<[u8]> for VerifiedData {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl VerifiedData {
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    pub fn verification_result(&self) -> Option<&VerificationResult> {
        self.verification_result.as_ref()
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.data
    }
}

#[derive(Debug)]
struct VerifiedDataReaderHandle(usize);

impl Drop for VerifiedDataReaderHandle {
    fn drop(&mut self) {
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            sys::pgp_go_reader_destroy(self.0);
        }
    }
}

pub struct VerifiedDataReader<'a, T> {
    handle: VerifiedDataReaderHandle,
    _ciphertext_reader: ReaderForGo<T>,
    _decryption_keys: Vec<&'a GoKey>,
    _verification_keys: Vec<&'a GoKey>,
    _password: Option<&'a str>,
    _session_key: Option<&'a SessionKey>,
    _verification_context: Option<&'a VerificationContext>,
}

impl<'a, T> VerifiedDataReader<'a, T> {
    pub(crate) fn new_from_verifier(
        handle: usize,
        reader: ReaderForGo<T>,
        verifier: Verifier<'a>,
    ) -> Self {
        Self {
            handle: VerifiedDataReaderHandle(handle),
            _ciphertext_reader: reader,
            _decryption_keys: Vec::new(),
            _verification_keys: verifier.verification_keys,
            _password: None,
            _session_key: None,
            _verification_context: verifier.verification_context,
        }
    }

    fn new_from_decryptor(handle: usize, reader: ReaderForGo<T>, decryptor: Decryptor<'a>) -> Self {
        Self {
            handle: VerifiedDataReaderHandle(handle),
            _ciphertext_reader: reader,
            _decryption_keys: decryptor.decryption_keys,
            _verification_keys: decryptor.verification_keys,
            _password: decryptor.password,
            _session_key: decryptor.session_key,
            _verification_context: decryptor.verification_context,
        }
    }

    pub fn verification_result(&self) -> Result<VerificationResult, PGPError> {
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            let mut result_handle: usize = 0;
            let err =
                sys::pgp_verification_reader_get_verify_result(self.handle.0, &mut result_handle);
            PGPError::unwrap(err)?;
            Ok(VerificationResult::new(result_handle))
        }
    }
}

impl<T: io::Read> io::Read for VerifiedDataReader<'_, T> {
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        unsafe {
            let mut data_read: usize = 0;
            let err = sys::pgp_verification_reader_read(
                self.handle.0,
                buf.as_mut_ptr(),
                buf.len(),
                &mut data_read,
            );
            PGPError::unwrap(err).map_err(|err| Error::new(ErrorKind::Other, err.to_string()))?;
            if data_read > buf.len() {
                return Err(Error::new(ErrorKind::Other, "read more than buffer length"));
            }
            Ok(data_read)
        }
    }
}

impl Default for sys::PGP_DecryptionHandle {
    fn default() -> Self {
        Self {
            decryption_keys_len: 0,
            verification_keys_len: 0,
            has_session_key: false,
            has_verification_context: false,
            has_verification_time: false,
            utf8: false,
            decryption_keys: null_mut(),
            verification_keys: null_mut(),
            session_key: 0,
            verification_context: 0,
            password_len: 0,
            password: null_mut(),
            verification_time: 0,
            detached_sig: null_mut(),
            detached_sig_len: 0,
            detached_sig_is_encrypted: false,
            detached_sig_armored: false,
        }
    }
}

#[derive(Default)]
pub struct Decryptor<'a> {
    decryption_keys: Vec<&'a GoKey>,
    verification_keys: Vec<&'a GoKey>,
    password: Option<&'a str>,
    session_key: Option<&'a SessionKey>,
    session_key_owned: Option<SessionKey>,
    verification_context: Option<&'a VerificationContext>,
    verification_time: Option<u64>,
    detached_signature: Option<&'a [u8]>,
    detached_signature_full: Option<Vec<u8>>,
    detached_signature_encrypted: bool,
    detached_signature_armored: bool,
    utf8: bool,
}

impl Decryptor<'_> {
    fn create_c_decryptor(
        &self,
        decryption_key_handles: &[usize],
        verification_keys: &[usize],
    ) -> sys::PGP_DecryptionHandle {
        let mut c_handle = sys::PGP_DecryptionHandle::default();
        if !decryption_key_handles.is_empty() {
            c_handle.decryption_keys_len = decryption_key_handles.len();
            c_handle.decryption_keys = decryption_key_handles.as_ptr().cast();
        }
        if !verification_keys.is_empty() {
            c_handle.verification_keys_len = verification_keys.len();
            c_handle.verification_keys = verification_keys.as_ptr().cast();
        }
        if let Some(session_key) = self.session_key {
            c_handle.has_session_key = true;
            c_handle.session_key = session_key.c_handle();
        }
        if let Some(session_key_owned) = &self.session_key_owned {
            c_handle.has_session_key = true;
            c_handle.session_key = session_key_owned.c_handle();
        }
        if let Some(passphrase) = self.password {
            c_handle.password = passphrase.as_bytes().as_ptr();
            c_handle.password_len = passphrase.len();
        }
        if let Some(verification_context) = self.verification_context {
            c_handle.has_verification_context = true;
            c_handle.verification_context = verification_context.c_handle();
        }
        if let Some(verification_time) = self.verification_time {
            c_handle.has_verification_time = true;
            c_handle.verification_time = verification_time;
        }
        if self.utf8 {
            c_handle.utf8 = true;
        }
        if let Some(detached_signature) = &self.detached_signature_full {
            c_handle.detached_sig = detached_signature.as_ptr();
            c_handle.detached_sig_len = detached_signature.len();
            c_handle.detached_sig_is_encrypted = self.detached_signature_encrypted;
            c_handle.detached_sig_armored = self.detached_signature_armored
        } else if let Some(detached_signature) = self.detached_signature {
            c_handle.detached_sig = detached_signature.as_ptr();
            c_handle.detached_sig_len = detached_signature.len();
            c_handle.detached_sig_is_encrypted = self.detached_signature_encrypted;
            c_handle.detached_sig_armored = self.detached_signature_armored
        }
        c_handle
    }
}

impl<'a> Decryptor<'a> {
    pub fn new() -> Self {
        Decryptor::default()
    }

    pub fn with_passphrase(mut self, passphrase: &'a str) -> Self {
        self.password = Some(passphrase);
        self
    }

    pub fn with_decryption_key(mut self, decryption_key: &'a impl PrivateKeyReference) -> Self {
        self.decryption_keys.push(decryption_key.private_ref());
        self
    }

    pub fn with_decryption_keys(mut self, decryption_keys: &'a [impl PrivateKeyReference]) -> Self {
        self.decryption_keys
            .extend(decryption_keys.iter().map(|key| key.private_ref()));
        self
    }

    pub fn with_verification_key(mut self, verification_key: &'a impl PublicKeyReference) -> Self {
        self.verification_keys.push(verification_key.public_ref());
        self
    }

    pub fn with_verification_keys(
        mut self,
        verification_keys: &'a [impl PublicKeyReference],
    ) -> Self {
        self.verification_keys
            .extend(verification_keys.iter().map(|key| key.public_ref()));
        self
    }

    pub fn with_session_key(mut self, session_key: &'a SessionKey) -> Self {
        self.session_key = Some(session_key);
        self
    }

    pub fn with_session_key_move(mut self, session_key: SessionKey) -> Self {
        self.session_key_owned = Some(session_key);
        self
    }

    pub fn with_verification_context(
        mut self,
        verification_context: &'a VerificationContext,
    ) -> Self {
        self.verification_context = Some(verification_context);
        self
    }

    pub fn at_verification_time(mut self, unix_timestamp: u64) -> Self {
        self.verification_time = Some(unix_timestamp);
        self
    }

    pub fn with_utf8_out(mut self) -> Self {
        self.utf8 = true;
        self
    }

    pub fn with_detached_signature_ref(
        mut self,
        detached_signature: &'a [u8],
        encrypted: bool,
        armored: bool,
    ) -> Self {
        self.detached_signature = Some(detached_signature);
        self.detached_signature_encrypted = encrypted;
        self.detached_signature_armored = armored;
        self
    }

    pub fn with_detached_signature(
        mut self,
        detached_signature: Vec<u8>,
        encrypted: bool,
        armored: bool,
    ) -> Self {
        self.detached_signature_full = Some(detached_signature);
        self.detached_signature_encrypted = encrypted;
        self.detached_signature_armored = armored;
        self
    }

    pub fn decrypt(
        self,
        data: &[u8],
        data_encoding: DataEncoding,
    ) -> Result<VerifiedData, PGPError> {
        let decryption_key_handles = get_key_handles(&self.decryption_keys);
        let verification_key_handles = get_key_handles(&self.verification_keys);
        let c_decryptor =
            self.create_c_decryptor(&decryption_key_handles, &verification_key_handles);
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            let mut buffer: ExtBuffer = ExtBuffer::with_capacity(data.len());
            let ext_buffer_vtable = ExtBuffer::make_ext_buffer_writer(&mut buffer);
            let mut result = sys::PGP_PlaintextResult {
                has_verification_result: false,
                verification_result: 0,
                plaintext_buffer: ext_buffer_vtable,
            };
            let err = sys::pgp_decrypt(
                &c_decryptor,
                data.as_ptr(),
                data.len(),
                data_encoding.go_id(),
                &mut result,
            );
            PGPError::unwrap(err)?;
            Ok(VerifiedData {
                data: buffer.take(),
                verification_result: Some(VerificationResult::new(result.verification_result)),
            })
        }
    }

    pub fn decrypt_stream<T: io::Read>(
        self,
        data: T,
        data_encoding: DataEncoding,
    ) -> Result<VerifiedDataReader<'a, T>, PGPError> {
        let decryption_key_handles = get_key_handles(&self.decryption_keys);
        let verification_key_handles = get_key_handles(&self.verification_keys);
        let c_decryptor =
            self.create_c_decryptor(&decryption_key_handles, &verification_key_handles);
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            let mut reader = ReaderForGo::new(data);
            let c_handle = reader.make_external_reader();
            let mut handle: usize = 0;
            let err =
                sys::pgp_decrypt_stream(&c_decryptor, c_handle, data_encoding.go_id(), &mut handle);
            PGPError::unwrap(err)?;

            Ok(VerifiedDataReader::new_from_decryptor(handle, reader, self))
        }
    }

    pub fn decrypt_session_key(self, key_packets: &[u8]) -> Result<SessionKey, PGPError> {
        let decryption_key_handles = get_key_handles(&self.decryption_keys);
        let verification_key_handles = get_key_handles(&self.verification_keys);
        let c_decryptor =
            self.create_c_decryptor(&decryption_key_handles, &verification_key_handles);
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            let mut result: usize = 0;
            let err = sys::pgp_decrypt_session_key(
                &c_decryptor,
                key_packets.as_ptr(),
                key_packets.len(),
                &mut result,
            );
            PGPError::unwrap(err)?;
            Ok(SessionKey(result))
        }
    }
}
