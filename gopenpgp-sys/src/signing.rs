#[cfg(test)]
#[path = "tests/signing.rs"]
mod tests;

use std::{io, ptr::null_mut};

use crate::{
    ext_buffer::ExtBuffer,
    get_key_handles,
    streaming::WriterForGo,
    sys::{self},
    DataEncoding, GoKey, PGPEncryptorWriteCloser, PGPError, PrivateKeyReference,
};

#[derive(Debug)]
pub struct SigningContext(usize);

impl Clone for SigningContext {
    fn clone(&self) -> Self {
        unsafe {
            let cloned_signing_context = sys::pgp_clone_signing_context(self.0);
            Self(cloned_signing_context)
        }
    }
}

impl SigningContext {
    pub fn new(value: &str, is_critical: bool) -> Self {
        unsafe {
            let handle =
                sys::pgp_signing_context_new(value.as_ptr().cast(), value.len(), is_critical);
            SigningContext(handle)
        }
    }

    pub(crate) fn get_c_handle(&self) -> usize {
        self.0
    }
}

impl Drop for SigningContext {
    fn drop(&mut self) {
        unsafe {
            sys::pgp_signing_context_new_destroy(self.0);
        }
    }
}

impl Default for sys::PGP_SignHandle {
    fn default() -> Self {
        Self {
            signing_keys_len: 0,
            has_signing_context: false,
            has_sign_time: false,
            utf8: false,
            signing_keys: null_mut(),
            signing_context: 0,
            sign_time: 0,
        }
    }
}

#[derive(Default)]
pub struct Signer<'a> {
    pub(crate) signing_keys: Vec<&'a GoKey>,
    pub(crate) signing_context: Option<&'a SigningContext>,
    signing_time: Option<u64>,
    utf8: bool,
}

impl Signer<'_> {
    fn create_c_signer(&self, signing_key_handles: &[usize]) -> sys::PGP_SignHandle {
        let mut c_handle = sys::PGP_SignHandle::default();
        if !signing_key_handles.is_empty() {
            c_handle.signing_keys_len = signing_key_handles.len();
            c_handle.signing_keys = signing_key_handles.as_ptr().cast();
        }
        if let Some(signing_context) = self.signing_context {
            c_handle.has_signing_context = true;
            c_handle.signing_context = signing_context.get_c_handle();
        }
        if let Some(signing_time) = self.signing_time {
            c_handle.has_sign_time = true;
            c_handle.sign_time = signing_time;
        }
        if self.utf8 {
            c_handle.utf8 = true;
        }
        c_handle
    }
}

impl<'a> Signer<'a> {
    pub fn new() -> Self {
        Signer::default()
    }

    pub fn with_signing_key(mut self, signing_key: &'a impl PrivateKeyReference) -> Self {
        self.signing_keys.push(signing_key.private_ref());
        self
    }

    pub fn with_signing_keys(mut self, signing_keys: &'a [impl PrivateKeyReference]) -> Self {
        self.signing_keys
            .extend(signing_keys.iter().map(|key| key.private_ref()));
        self
    }

    pub fn with_signing_context(mut self, signing_context: &'a SigningContext) -> Self {
        self.signing_context = Some(signing_context);
        self
    }

    pub fn at_signing_time(mut self, unix_timestamp: u64) -> Self {
        self.signing_time = Some(unix_timestamp);
        self
    }

    pub fn as_utf8(mut self) -> Self {
        self.utf8 = true;
        self
    }

    pub fn sign(
        self,
        data: &[u8],
        detached: bool,
        out_encoding: DataEncoding,
    ) -> Result<Vec<u8>, PGPError> {
        let signing_key_handles = get_key_handles(&self.signing_keys);
        let c_signer = self.create_c_signer(&signing_key_handles);
        unsafe {
            let mut buffer: ExtBuffer = ExtBuffer::with_capacity(data.len());
            let ext_buffer_vtable = ExtBuffer::make_ext_buffer_writer(&mut buffer);
            let err = sys::pgp_sign(
                &c_signer,
                data.as_ptr(),
                data.len(),
                out_encoding.go_id(),
                detached,
                ext_buffer_vtable,
            );
            PGPError::unwrap(err)?;
            Ok(buffer.take())
        }
    }

    pub fn sign_cleartext(self, data: &[u8]) -> Result<Vec<u8>, PGPError> {
        let signing_key_handles = get_key_handles(&self.signing_keys);
        let c_signer = self.create_c_signer(&signing_key_handles);
        unsafe {
            let mut buffer: ExtBuffer = ExtBuffer::with_capacity(data.len());
            let ext_buffer_vtable = ExtBuffer::make_ext_buffer_writer(&mut buffer);
            let err =
                sys::pgp_sign_cleartext(&c_signer, data.as_ptr(), data.len(), ext_buffer_vtable);
            PGPError::unwrap(err)?;
            Ok(buffer.take())
        }
    }

    pub fn sing_stream<T: io::Write>(
        self,
        sign_writer: T,
        detached: bool,
        data_encoding: DataEncoding,
    ) -> Result<PGPEncryptorWriteCloser<'a, T>, PGPError> {
        let signing_key_handles = get_key_handles(&self.signing_keys);
        let c_signer = self.create_c_signer(&signing_key_handles);
        unsafe {
            let mut writer = WriterForGo::new(sign_writer);
            let c_handle = writer.make_external_writer();
            let mut handle: usize = 0;
            let err = sys::pgp_sign_stream(
                &c_signer,
                c_handle,
                data_encoding.go_id(),
                detached,
                &mut handle,
            );
            PGPError::unwrap(err)?;
            Ok(PGPEncryptorWriteCloser::new_from_signer(
                handle, writer, self,
            ))
        }
    }
}
