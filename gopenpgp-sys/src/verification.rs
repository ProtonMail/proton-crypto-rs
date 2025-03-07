#[cfg(test)]
#[path = "tests/verification.rs"]
mod tests;

use crate::ext_buffer::ExtBuffer;
use crate::go::PGPError;
use crate::streaming::ReaderForGo;
use crate::{
    get_key_handles, sys, DataEncoding, GoKey, OwnedCStr, PublicKeyReference, VerifiedData,
    VerifiedDataReader,
};
use std::ffi::c_char;
use std::io;
use std::ptr::null_mut;

#[derive(Debug)]
pub enum VerificationStatus {
    Ok,
    NotSigned(PGPError),
    NoVerifier(PGPError),
    Failed(PGPError),
    BadContext(PGPError),
    Error(PGPError),
}

#[derive(Debug)]
pub struct VerificationContext(usize);

impl Clone for VerificationContext {
    fn clone(&self) -> Self {
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            let cloned_verification_context = sys::pgp_clone_verification_context(self.0);
            Self(cloned_verification_context)
        }
    }
}

impl VerificationContext {
    pub fn new(value: &str, is_required: bool, required_after_unix: u64) -> Self {
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            Self(sys::pgp_verification_context_new(
                value.as_ptr().cast(),
                value.len(),
                is_required,
                required_after_unix,
            ))
        }
    }

    pub fn get_value(&self) -> String {
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            let mut out: *mut c_char = null_mut();
            sys::pgp_verification_context_get_value(self.0, &mut out);
            OwnedCStr::new(out).to_string()
        }
    }

    pub fn is_required(&self) -> bool {
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { sys::pgp_verification_context_is_required(self.0) }
    }

    pub fn is_required_after(&self) -> u64 {
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { sys::pgp_verification_context_is_required_after(self.0) }
    }
}

impl VerificationContext {
    pub(crate) fn c_handle(&self) -> usize {
        self.0
    }
}

impl Drop for VerificationContext {
    fn drop(&mut self) {
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            sys::pgp_verification_context_destroy(self.0);
        }
    }
}

pub struct SignatureInfo(sys::PGP_SignatureInfo);

impl SignatureInfo {
    pub fn creation_time(&self) -> u64 {
        self.0.creation_time
    }

    pub fn signature_type(&self) -> u8 {
        self.0.signature_type
    }

    pub fn key_id(&self) -> u64 {
        self.0.key_id
    }

    pub fn key_id_hex(&self) -> String {
        format!("{:x}", self.key_id())
    }

    pub fn selected_signature(&self) -> Option<&[u8]> {
        if self.0.key_fingerprint.is_null() {
            return None;
        }
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            Some(std::slice::from_raw_parts(
                self.0.selected_signature,
                self.0.selected_signature_len,
            ))
        }
    }

    pub fn key_fingerprint(&self) -> Option<&[u8]> {
        if self.0.key_fingerprint.is_null() {
            return None;
        }
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            Some(std::slice::from_raw_parts(
                self.0.key_fingerprint,
                self.0.key_fingerprint_len,
            ))
        }
    }

    pub fn key_fingerprint_hex(&self) -> Option<String> {
        self.key_fingerprint().map(hex::encode)
    }
}

impl Default for SignatureInfo {
    fn default() -> Self {
        Self(sys::PGP_SignatureInfo {
            signature_type: 0,
            creation_time: 0,
            key_id: 0,
            key_fingerprint: null_mut(),
            key_fingerprint_len: 0,
            selected_signature: null_mut(),
            selected_signature_len: 0,
        })
    }
}

impl Drop for SignatureInfo {
    fn drop(&mut self) {
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            if !self.0.key_fingerprint.is_null() {
                sys::pgp_free(self.0.key_fingerprint.cast());
            }
            if !self.0.selected_signature.is_null() {
                sys::pgp_free(self.0.selected_signature.cast());
            }
        }
    }
}

pub struct Signatures(sys::PGP_Signatures);

impl Default for Signatures {
    fn default() -> Self {
        Self(sys::PGP_Signatures {
            number_of_signatures: 0,
            all_signatures: null_mut(),
            all_signatures_len: 0,
        })
    }
}

impl Drop for Signatures {
    fn drop(&mut self) {
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            if !self.0.all_signatures.is_null() {
                sys::pgp_free(self.0.all_signatures.cast());
            }
        }
    }
}

impl AsRef<[u8]> for Signatures {
    fn as_ref(&self) -> &[u8] {
        if self.number_of_signatures() == 0 || self.0.all_signatures.is_null() {
            return &[];
        }
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { std::slice::from_raw_parts(self.0.all_signatures, self.0.all_signatures_len) }
    }
}

impl Signatures {
    pub fn to_vec(&self) -> Vec<u8> {
        self.as_ref().to_vec()
    }

    pub fn number_of_signatures(&self) -> usize {
        self.0.number_of_signatures
    }
}

#[derive(Debug)]
pub struct VerificationResult(usize);

impl VerificationResult {
    pub(crate) fn new(c_result: usize) -> Self {
        Self(c_result)
    }
}

impl VerificationResult {
    pub fn status(&self) -> VerificationStatus {
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            let mut status_code: std::os::raw::c_int = 0;
            let err = sys::pgp_verification_result_error(self.0, &mut status_code);
            let pgp_err = PGPError::new(err);
            match status_code {
                0 => VerificationStatus::Ok,
                1 => VerificationStatus::NotSigned(pgp_err),
                2 => VerificationStatus::NoVerifier(pgp_err),
                4 => VerificationStatus::BadContext(pgp_err),
                _ => VerificationStatus::Failed(pgp_err),
            }
        }
    }

    pub fn signature_info(&self) -> Result<SignatureInfo, PGPError> {
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            let mut signature_info = SignatureInfo::default();
            let err = sys::pgp_verification_result_signature_info(self.0, &mut signature_info.0);
            PGPError::unwrap(err)?;
            Ok(signature_info)
        }
    }

    pub fn signatures(&self) -> Result<Signatures, PGPError> {
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            let mut signatures = Signatures::default();
            let err = sys::pgp_verification_result_all_signatures(self.0, &mut signatures.0);
            PGPError::unwrap(err)?;
            Ok(signatures)
        }
    }
}

impl Drop for VerificationResult {
    fn drop(&mut self) {
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { sys::pgp_verification_result_destroy(self.0) }
    }
}

impl Default for sys::PGP_VerificationHandle {
    fn default() -> Self {
        Self {
            verification_keys_len: 0,
            has_verification_context: false,
            has_verification_time: false,
            utf8: false,
            verification_keys: null_mut(),
            verification_context: 0,
            verification_time: 0,
        }
    }
}

#[derive(Default)]
pub struct Verifier<'a> {
    pub(crate) verification_keys: Vec<&'a GoKey>,
    pub(crate) verification_context: Option<&'a VerificationContext>,
    verification_time: Option<u64>,
    utf8: bool,
}

impl Verifier<'_> {
    fn create_c_verifier(&self, verification_keys: &[usize]) -> sys::PGP_VerificationHandle {
        let mut c_handle = sys::PGP_VerificationHandle::default();
        if !verification_keys.is_empty() {
            c_handle.verification_keys_len = verification_keys.len();
            c_handle.verification_keys = verification_keys.as_ptr().cast();
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
        c_handle
    }
}

impl<'a> Verifier<'a> {
    pub fn new() -> Self {
        Verifier::default()
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

    pub fn verify_detached(
        self,
        data: &[u8],
        signature: &[u8],
        data_encoding: DataEncoding,
    ) -> Result<VerificationResult, PGPError> {
        let verification_key_handles = get_key_handles(&self.verification_keys);
        let c_verifier = self.create_c_verifier(&verification_key_handles);
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            let mut verification_result: usize = 0;
            let err = sys::pgp_verify_detached(
                &c_verifier,
                data.as_ptr(),
                data.len(),
                signature.as_ptr(),
                signature.len(),
                data_encoding.go_id(),
                &mut verification_result,
            );
            PGPError::unwrap(err)?;
            Ok(VerificationResult::new(verification_result))
        }
    }

    pub fn verify_inline(
        self,
        data: &[u8],
        data_encoding: DataEncoding,
    ) -> Result<VerifiedData, PGPError> {
        let verification_key_handles = get_key_handles(&self.verification_keys);
        let c_verifier = self.create_c_verifier(&verification_key_handles);
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            let mut buffer = ExtBuffer::with_capacity(data.len());
            let ext_buffer_vtable = ExtBuffer::make_ext_buffer_writer(&mut buffer);
            let mut result = sys::PGP_PlaintextResult {
                has_verification_result: false,
                verification_result: 0,
                plaintext_buffer: ext_buffer_vtable,
            };
            let err = sys::pgp_verify_inline(
                &c_verifier,
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

    pub fn verify_cleartext(self, data: &[u8]) -> Result<VerifiedData, PGPError> {
        let verification_key_handles = get_key_handles(&self.verification_keys);
        let c_verifier = self.create_c_verifier(&verification_key_handles);
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            let mut buffer = ExtBuffer::with_capacity(data.len());
            let ext_buffer_vtable = ExtBuffer::make_ext_buffer_writer(&mut buffer);
            let mut result = sys::PGP_PlaintextResult {
                has_verification_result: false,
                verification_result: 0,
                plaintext_buffer: ext_buffer_vtable,
            };
            let err =
                sys::pgp_verify_cleartext(&c_verifier, data.as_ptr(), data.len(), &mut result);
            PGPError::unwrap(err)?;
            Ok(VerifiedData {
                data: buffer.take(),
                verification_result: Some(VerificationResult::new(result.verification_result)),
            })
        }
    }

    pub fn verify_detached_stream<T: io::Read>(
        self,
        data: T,
        signature: &[u8],
        data_encoding: DataEncoding,
    ) -> Result<VerificationResult, PGPError> {
        let verification_key_handles = get_key_handles(&self.verification_keys);
        let c_verifier = self.create_c_verifier(&verification_key_handles);
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            let mut reader_go = ReaderForGo::new(data);
            let mut verification_result: usize = 0;
            let reader_go_c = reader_go.make_external_reader();
            let err = sys::pgp_verify_detached_stream(
                &c_verifier,
                reader_go_c,
                signature.as_ptr(),
                signature.len(),
                data_encoding.go_id(),
                &mut verification_result,
            );
            PGPError::unwrap(err)?;
            Ok(VerificationResult::new(verification_result))
        }
    }

    pub fn verify_inline_stream<T: io::Read>(
        self,
        data: T,
        data_encoding: DataEncoding,
    ) -> Result<VerifiedDataReader<'a, T>, PGPError> {
        let verification_key_handles = get_key_handles(&self.verification_keys);
        let c_verifier = self.create_c_verifier(&verification_key_handles);
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            let mut reader = ReaderForGo::new(data);
            let c_handle = ReaderForGo::make_external_reader(&mut reader);
            let mut handle: usize = 0;
            let err = sys::pgp_verify_inline_stream(
                &c_verifier,
                c_handle,
                data_encoding.go_id(),
                &mut handle,
            );
            PGPError::unwrap(err)?;
            Ok(VerifiedDataReader::new_from_verifier(handle, reader, self))
        }
    }
}

#[test]
fn test_verification_context_new() {
    VerificationContext::new("test", true, 0);
}
