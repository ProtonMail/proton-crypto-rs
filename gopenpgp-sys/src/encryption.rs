#[cfg(test)]
#[path = "tests/encryption.rs"]
mod tests;

use std::{
    io::{self, Error},
    ptr::null_mut,
};

use crate::{
    armor::{self, ArmorType},
    ext_buffer::{ExtBuffer, ExtVecWriter},
    get_key_handles,
    streaming::WriterForGo,
    sys::{self},
    DataEncoding, GoKey, PGPError, PGPSlice, PrivateKeyReference, PublicKeyReference, SessionKey,
    Signer, SigningContext,
};

const ESTIMATE_SESSION_KEY_SIZE: usize = 32;
// This is are ruff estimate for ECDH at proton. Varies depending on the algorithm.
const ESTIMATE_SESSION_KEY_PACKET_SIZE: usize = 96;
// Varies depending on the algorithm/encoding.
const ESTIMATE_DETACHED_SIG_SIZE: usize = 247;

#[derive(Debug)]
struct PGPMessageHandle(usize);

impl Drop for PGPMessageHandle {
    fn drop(&mut self) {
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            sys::pgp_message_destroy(self.0);
        }
    }
}

pub struct PGPMessage {
    handle: PGPMessageHandle,
    data: Vec<u8>,
}

impl PGPMessage {
    pub fn new(message: Vec<u8>) -> Self {
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            let handle = sys::pgp_message_new(message.as_ptr(), message.len(), false);
            PGPMessage {
                handle: PGPMessageHandle(handle),
                data: message,
            }
        }
    }

    pub fn new_from_slice(message: &[u8]) -> Self {
        Self::new(message.to_vec())
    }

    pub fn new_from_armored(message: &[u8]) -> Result<Self, PGPError> {
        let binary_message = armor::unarmor(message)?;
        Ok(Self::new(binary_message))
    }

    pub fn armored(&self) -> Result<Vec<u8>, PGPError> {
        armor::armor(&self.data, ArmorType::Message)
    }

    pub fn key_packet(&self) -> &[u8] {
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            let split = sys::pgp_message_key_packet_split(self.handle.0);
            &self.data[..split]
        }
    }

    pub fn data_packet(&self) -> &[u8] {
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            let split = sys::pgp_message_key_packet_split(self.handle.0);
            &self.data[split..]
        }
    }

    pub fn encryption_key_ids(&self) -> Option<impl AsRef<[u64]>> {
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            let mut data_ptr: *mut u64 = null_mut();
            let mut size: usize = 0;
            sys::pgp_message_get_enc_key_ids(self.handle.0, &mut data_ptr, &mut size);
            if size > 0 {
                return Some(PGPSlice::new(data_ptr, size));
            }
            None
        }
    }

    pub fn encryption_key_ids_hex(&self) -> Option<Vec<String>> {
        let key_ids = self.encryption_key_ids();
        match key_ids {
            None => None,
            Some(list) => {
                let mut out = Vec::with_capacity(list.as_ref().len());
                for value in list.as_ref() {
                    out.push(format!("{value:016X}"))
                }
                Some(out)
            }
        }
    }

    pub fn signature_key_ids(&self) -> Option<impl AsRef<[u64]>> {
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            let mut data_ptr: *mut u64 = null_mut();
            let mut size: usize = 0;
            sys::pgp_message_get_sig_key_ids(self.handle.0, &mut data_ptr, &mut size);
            if size > 0 {
                return Some(PGPSlice::new(data_ptr, size));
            }
            None
        }
    }

    pub fn signature_key_ids_hex(&self) -> Option<Vec<String>> {
        let key_ids = self.signature_key_ids();
        match key_ids {
            None => None,
            Some(list) => {
                let mut out = Vec::with_capacity(list.as_ref().len());
                for value in list.as_ref() {
                    out.push(format!("{value:016X}"))
                }
                Some(out)
            }
        }
    }
}

impl AsRef<[u8]> for PGPMessage {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

#[derive(Debug)]
struct PGPEncryptorWriteCloserHandle(usize);

impl Drop for PGPEncryptorWriteCloserHandle {
    fn drop(&mut self) {
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            sys::pgp_message_write_closer_destroy(self.0);
        }
    }
}

pub struct PGPEncryptorWriteCloser<'a, T> {
    handle: PGPEncryptorWriteCloserHandle,
    internal_writer: WriterForGo<T>,
    _encryption_keys: Vec<&'a GoKey>,
    _signing_keys: Vec<&'a GoKey>,
    _password: Option<&'a str>,
    _session_key: Option<&'a SessionKey>,
    _signing_context: Option<&'a SigningContext>,
}

impl<T: io::Write> io::Write for PGPEncryptorWriteCloser<'_, T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            let mut data_written: usize = 0;
            let err = sys::pgp_message_write_closer_write(
                self.handle.0,
                buf.as_ptr(),
                buf.len(),
                &mut data_written,
            );
            PGPError::unwrap(err).map_err(|err| Error::other(err.to_string()))?;
            Ok(data_written)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a, T: io::Write> PGPEncryptorWriteCloser<'a, T> {
    pub(crate) fn new_from_signer(
        handle: usize,
        writer: WriterForGo<T>,
        signer: Signer<'a>,
    ) -> Self {
        Self {
            handle: PGPEncryptorWriteCloserHandle(handle),
            internal_writer: writer,
            _encryption_keys: Vec::new(),
            _signing_keys: signer.signing_keys,
            _password: None,
            _session_key: None,
            _signing_context: signer.signing_context,
        }
    }

    pub(crate) fn new_from_encryptor(
        handle: usize,
        writer: WriterForGo<T>,
        encryptor: Encryptor<'a>,
    ) -> Self {
        Self {
            handle: PGPEncryptorWriteCloserHandle(handle),
            internal_writer: writer,
            _encryption_keys: encryptor.encryption_keys,
            _signing_keys: encryptor.signing_keys,
            _password: encryptor.password,
            _session_key: encryptor.session_key,
            _signing_context: encryptor.signing_context,
        }
    }

    pub fn close(&mut self) -> io::Result<()> {
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            let err = sys::pgp_message_write_closer_close(self.handle.0);
            PGPError::unwrap(err).map_err(|err| Error::other(err.to_string()))?;
        }
        self.internal_writer.flush()
    }
}

pub struct PGPEncryptorWithDetachedSigWriteCloser<'a, T> {
    write_closer: PGPEncryptorWriteCloser<'a, T>,
    detached_sig_buffer: ExtVecWriter,
    closed: bool,
}

impl<T: io::Write> io::Write for PGPEncryptorWithDetachedSigWriteCloser<'_, T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_closer.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.write_closer.flush()
    }
}

impl<'a, T: io::Write> PGPEncryptorWithDetachedSigWriteCloser<'a, T> {
    pub(crate) fn new(
        handle: usize,
        writer: WriterForGo<T>,
        buffer: ExtVecWriter,
        encryptor: Encryptor<'a>,
    ) -> Self {
        Self {
            write_closer: PGPEncryptorWriteCloser::new_from_encryptor(handle, writer, encryptor),
            detached_sig_buffer: buffer,
            closed: false,
        }
    }

    pub fn take_detached_signature(self) -> Vec<u8> {
        self.detached_sig_buffer.take()
    }

    pub fn close(&mut self) -> io::Result<()> {
        self.closed = true;
        self.write_closer.close()
    }
}

impl Default for sys::PGP_EncryptionHandle {
    fn default() -> Self {
        Self {
            encryption_keys_len: 0,
            signing_keys_len: 0,
            has_session_key: false,
            has_signing_context: false,
            has_encryption_time: false,
            utf8: false,
            compress: false,
            detached_sig: false,
            detached_sig_encrypted: false,
            encryption_keys: null_mut(),
            signing_keys: null_mut(),
            session_key: 0,
            signing_context: 0,
            password_len: 0,
            password: null_mut(),
            encryption_time: 0,
        }
    }
}

#[derive(Default)]
pub struct Encryptor<'a> {
    encryption_keys: Vec<&'a GoKey>,
    signing_keys: Vec<&'a GoKey>,
    password: Option<&'a str>,
    session_key: Option<&'a SessionKey>,
    session_key_owned: Option<SessionKey>,
    signing_context: Option<&'a SigningContext>,
    signing_time: Option<u64>,
    utf8: bool,
    compress: bool,
}

impl Encryptor<'_> {
    fn create_c_encryptor(
        &self,
        encryption_key_handles: &[usize],
        signing_key_handles: &[usize],
    ) -> sys::PGP_EncryptionHandle {
        let mut c_handle = sys::PGP_EncryptionHandle::default();
        if !encryption_key_handles.is_empty() {
            c_handle.encryption_keys_len = encryption_key_handles.len();
            c_handle.encryption_keys = encryption_key_handles.as_ptr().cast();
        }
        if !signing_key_handles.is_empty() {
            c_handle.signing_keys_len = signing_key_handles.len();
            c_handle.signing_keys = signing_key_handles.as_ptr().cast();
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
        if let Some(signing_context) = self.signing_context {
            c_handle.has_signing_context = true;
            c_handle.signing_context = signing_context.get_c_handle();
        }
        if let Some(signing_time) = self.signing_time {
            c_handle.has_encryption_time = true;
            c_handle.encryption_time = signing_time;
        }
        if self.utf8 {
            c_handle.utf8 = true;
        }
        if self.compress {
            c_handle.compress = true;
        }
        c_handle
    }
}

impl<'a> Encryptor<'a> {
    pub fn new() -> Self {
        Encryptor::default()
    }

    pub fn with_passphrase(mut self, passphrase: &'a str) -> Self {
        self.password = Some(passphrase);
        self
    }

    pub fn with_encryption_key(mut self, encryption_key: &'a impl PublicKeyReference) -> Self {
        self.encryption_keys.push(encryption_key.public_ref());
        self
    }

    pub fn with_encryption_keys(mut self, encryption_keys: &'a [impl PublicKeyReference]) -> Self {
        self.encryption_keys
            .extend(encryption_keys.iter().map(|key| key.public_ref()));
        self
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

    pub fn with_session_key(mut self, session_key: &'a SessionKey) -> Self {
        self.session_key = Some(session_key);
        self
    }

    pub fn with_session_key_move(mut self, session_key: SessionKey) -> Self {
        self.session_key_owned = Some(session_key);
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

    pub fn with_compression(mut self) -> Self {
        self.compress = true;
        self
    }

    pub fn encrypt(self, data: &[u8]) -> Result<PGPMessage, PGPError> {
        let pgp_message_data = self.encrypt_raw(data, DataEncoding::Bytes)?;
        Ok(PGPMessage::new(pgp_message_data))
    }

    pub fn encrypt_raw(
        self,
        data: &[u8],
        data_encoding: DataEncoding,
    ) -> Result<Vec<u8>, PGPError> {
        let encryption_key_handles = get_key_handles(&self.encryption_keys);
        let signing_key_handles = get_key_handles(&self.signing_keys);
        let c_encryptor = self.create_c_encryptor(&encryption_key_handles, &signing_key_handles);
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            let mut buffer: ExtBuffer = ExtBuffer::with_capacity(data.len());
            let ext_buffer_vtable = ExtBuffer::make_ext_buffer_writer(&mut buffer);
            let err = sys::pgp_encrypt(
                &c_encryptor,
                data.as_ptr(),
                data.len(),
                data_encoding.go_id(),
                null_mut(),
                ext_buffer_vtable,
            );
            PGPError::unwrap(err)?;
            Ok(buffer.take())
        }
    }

    pub fn encrypt_raw_with_detached_signature(
        self,
        data: &[u8],
        encrypt_detached_signature: bool,
        encoding: DataEncoding,
    ) -> Result<(Vec<u8>, Vec<u8>), PGPError> {
        let encryption_key_handles = get_key_handles(&self.encryption_keys);
        let signing_key_handles = get_key_handles(&self.signing_keys);
        let mut c_encryptor =
            self.create_c_encryptor(&encryption_key_handles, &signing_key_handles);
        c_encryptor.detached_sig = true;
        c_encryptor.detached_sig_encrypted = encrypt_detached_signature;
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            let mut encrypted_data_buffer: ExtBuffer = ExtBuffer::with_capacity(data.len());
            let encrypted_data_buffer_writer =
                ExtBuffer::make_ext_buffer_writer(&mut encrypted_data_buffer);
            let mut signature_data_buffer: ExtBuffer =
                ExtBuffer::with_capacity(ESTIMATE_DETACHED_SIG_SIZE);
            let mut signature_data_buffer_writer =
                ExtBuffer::make_ext_buffer_writer(&mut signature_data_buffer);
            let err = sys::pgp_encrypt(
                &c_encryptor,
                data.as_ptr(),
                data.len(),
                encoding.go_id(),
                &mut signature_data_buffer_writer,
                encrypted_data_buffer_writer,
            );
            PGPError::unwrap(err)?;
            Ok((encrypted_data_buffer.take(), signature_data_buffer.take()))
        }
    }

    pub fn encrypt_stream_split<T: io::Write>(
        self,
        ciphertext_writer: T,
    ) -> Result<(Vec<u8>, PGPEncryptorWriteCloser<'a, T>), PGPError> {
        let encryption_key_handles = get_key_handles(&self.encryption_keys);
        let signing_key_handles = get_key_handles(&self.signing_keys);
        let c_encryptor = self.create_c_encryptor(&encryption_key_handles, &signing_key_handles);
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            let mut key_packet_buffer: ExtBuffer = ExtBuffer::with_capacity(
                self.encryption_keys.len() * ESTIMATE_SESSION_KEY_PACKET_SIZE,
            );
            let ext_key_packet_writer = ExtBuffer::make_ext_buffer_writer(&mut key_packet_buffer);

            let mut writer = WriterForGo::new(ciphertext_writer);
            let c_handle = writer.make_external_writer();
            let mut handle: usize = 0;
            let err = sys::pgp_encrypt_stream_split(
                &c_encryptor,
                c_handle,
                null_mut(),
                ext_key_packet_writer,
                &mut handle,
            );
            PGPError::unwrap(err)?;
            Ok((
                key_packet_buffer.take(),
                PGPEncryptorWriteCloser::new_from_encryptor(handle, writer, self),
            ))
        }
    }

    pub fn encrypt_stream_split_with_detached_signature<T: io::Write>(
        self,
        ciphertext_writer: T,
        encrypt_detached_signature: bool,
    ) -> Result<(Vec<u8>, PGPEncryptorWithDetachedSigWriteCloser<'a, T>), PGPError> {
        let encryption_key_handles = get_key_handles(&self.encryption_keys);
        let signing_key_handles = get_key_handles(&self.signing_keys);
        let mut c_encryptor =
            self.create_c_encryptor(&encryption_key_handles, &signing_key_handles);
        c_encryptor.detached_sig = true;
        c_encryptor.detached_sig_encrypted = encrypt_detached_signature;
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            let mut key_packet_buffer: ExtBuffer = ExtBuffer::with_capacity(
                self.encryption_keys.len() * ESTIMATE_SESSION_KEY_PACKET_SIZE,
            );
            let ext_key_packet_writer = ExtBuffer::make_ext_buffer_writer(&mut key_packet_buffer);

            let mut writer = WriterForGo::new(ciphertext_writer);
            let c_handle = writer.make_external_writer();
            let mut buffer_sig = ExtVecWriter::with_capacity(ESTIMATE_DETACHED_SIG_SIZE);
            let mut c_handle_sig = buffer_sig.make_external_writer();
            let mut handle: usize = 0;
            let err = sys::pgp_encrypt_stream_split(
                &c_encryptor,
                c_handle,
                &mut c_handle_sig,
                ext_key_packet_writer,
                &mut handle,
            );
            PGPError::unwrap(err)?;
            Ok((
                key_packet_buffer.take(),
                PGPEncryptorWithDetachedSigWriteCloser::new(handle, writer, buffer_sig, self),
            ))
        }
    }

    pub fn encrypt_stream<T: io::Write>(
        self,
        ciphertext_writer: T,
        data_encoding: DataEncoding,
    ) -> Result<PGPEncryptorWriteCloser<'a, T>, PGPError> {
        let encryption_key_handles = get_key_handles(&self.encryption_keys);
        let signing_key_handles = get_key_handles(&self.signing_keys);
        let c_encryptor = self.create_c_encryptor(&encryption_key_handles, &signing_key_handles);
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            let mut writer = WriterForGo::new(ciphertext_writer);
            let c_handle = writer.make_external_writer();
            let mut handle: usize = 0;
            let err = sys::pgp_encrypt_stream(
                &c_encryptor,
                c_handle,
                null_mut(),
                data_encoding.go_id(),
                &mut handle,
            );
            PGPError::unwrap(err)?;
            Ok(PGPEncryptorWriteCloser::new_from_encryptor(
                handle, writer, self,
            ))
        }
    }

    pub fn encrypt_stream_with_detached_signature<T: io::Write>(
        self,
        ciphertext_writer: T,
        encrypt_detached_signature: bool,
        data_encoding: DataEncoding,
    ) -> Result<PGPEncryptorWithDetachedSigWriteCloser<'a, T>, PGPError> {
        let encryption_key_handles = get_key_handles(&self.encryption_keys);
        let signing_key_handles = get_key_handles(&self.signing_keys);
        let mut c_encryptor =
            self.create_c_encryptor(&encryption_key_handles, &signing_key_handles);
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            c_encryptor.detached_sig = true;
            c_encryptor.detached_sig_encrypted = encrypt_detached_signature;
            let mut writer = WriterForGo::new(ciphertext_writer);
            let c_handle = writer.make_external_writer();
            let mut buffer_sig = ExtVecWriter::with_capacity(ESTIMATE_DETACHED_SIG_SIZE);
            let mut c_handle_sig = buffer_sig.make_external_writer();
            let mut handle: usize = 0;
            let err = sys::pgp_encrypt_stream(
                &c_encryptor,
                c_handle,
                &mut c_handle_sig,
                data_encoding.go_id(),
                &mut handle,
            );
            PGPError::unwrap(err)?;
            Ok(PGPEncryptorWithDetachedSigWriteCloser::new(
                handle, writer, buffer_sig, self,
            ))
        }
    }

    pub fn encrypt_session_key(self, session_key: &SessionKey) -> Result<Vec<u8>, PGPError> {
        let encryption_key_handles = get_key_handles(&self.encryption_keys);
        let signing_key_handles = get_key_handles(&self.signing_keys);
        let c_encryptor = self.create_c_encryptor(&encryption_key_handles, &signing_key_handles);
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            let mut buffer: ExtBuffer = ExtBuffer::with_capacity(ESTIMATE_SESSION_KEY_SIZE);
            let ext_buffer = ExtBuffer::make_ext_buffer_writer(&mut buffer);
            let err =
                sys::pgp_encrypt_session_key(&c_encryptor, session_key.c_handle(), ext_buffer);
            PGPError::unwrap(err)?;
            Ok(buffer.take())
        }
    }
}
