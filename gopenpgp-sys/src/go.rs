#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(deref_nullptr)]
#![allow(clippy::all)]
#![allow(dead_code)]
#![allow(improper_ctypes)]

use std::error::Error;
use std::ffi::{CStr, CString};
use std::fmt::{Debug, Display, Formatter};
use std::os::raw::{c_char, c_uchar, c_void};
use std::ptr::null_mut;
use zeroize::Zeroize;

pub(crate) mod sys {
    include!(concat!(env!("OUT_DIR"), "/gopenpgp-sys.rs"));
}

#[doc(hidden)]
pub struct PGPBytes {
    ptr: *mut c_uchar,
    len: usize,
}

impl PGPBytes {
    pub unsafe fn new(ptr: *mut c_uchar, len: usize) -> Self {
        let mut buffer_len = len;
        if ptr.is_null() {
            buffer_len = 0;
        }
        Self {
            ptr: ptr,
            len: buffer_len,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        if self.ptr.is_null() {
            return &[];
        }
        unsafe { std::slice::from_raw_parts(self.ptr as *mut u8, self.len) }
    }

    pub fn len(&self) -> usize {
        self.len
    }
}

impl AsRef<[u8]> for PGPBytes {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl Drop for PGPBytes {
    fn drop(&mut self) {
        unsafe {
            if !self.ptr.is_null() {
                sys::pgp_free(self.ptr as *mut c_void);
            }
        }
    }
}

#[doc(hidden)]
pub struct SecretGoBytes {
    ptr: *mut c_uchar,
    len: usize,
}

impl SecretGoBytes {
    pub unsafe fn new(ptr: *mut c_uchar, len: usize) -> Self {
        let mut buffer_len = len;
        if ptr.is_null() {
            buffer_len = 0;
        }
        Self {
            ptr: ptr,
            len: buffer_len,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        if self.ptr.is_null() {
            return &[];
        }
        unsafe { std::slice::from_raw_parts(self.ptr as *mut u8, self.len) }
    }

    pub fn len(&self) -> usize {
        self.len
    }
}

impl AsRef<[u8]> for SecretGoBytes {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl Drop for SecretGoBytes {
    fn drop(&mut self) {
        unsafe {
            if !self.ptr.is_null() {
                let data = std::slice::from_raw_parts_mut(self.ptr as *mut u8, self.len);
                data.zeroize();
                sys::pgp_free(self.ptr as *mut c_void);
            }
        }
    }
}

pub struct SecretBytes<T: AsRef<[u8]> + AsMut<[u8]>>(T);

impl<T: AsRef<[u8]> + AsMut<[u8]>> SecretBytes<T> {
    pub fn new(data: T) -> Self {
        SecretBytes(data)
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> AsRef<[u8]> for SecretBytes<T> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Drop for SecretBytes<T> {
    fn drop(&mut self) {
        self.0.as_mut().zeroize()
    }
}

pub struct SecretString<T: AsRef<str> + AsMut<str>>(T);

impl<T: AsRef<str> + AsMut<str>> SecretString<T> {
    pub fn new(data: T) -> Self {
        SecretString(data)
    }
}

impl<T: AsRef<str> + AsMut<str>> AsRef<str> for SecretString<T> {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

impl<T: AsRef<str> + AsMut<str>> Drop for SecretString<T> {
    fn drop(&mut self) {
        self.0.as_mut().zeroize()
    }
}

#[doc(hidden)]
pub struct PGPSlice<T: Sized> {
    ptr: *mut T,
    len: usize,
}

impl<T: Sized> PGPSlice<T> {
    pub unsafe fn new(ptr: *mut T, len: usize) -> Self {
        let mut buffer_len = len;
        if ptr.is_null() {
            buffer_len = 0;
        }
        Self {
            ptr,
            len: buffer_len,
        }
    }

    pub fn as_slice(&self) -> &[T] {
        if self.ptr.is_null() {
            return &[];
        }
        unsafe { std::slice::from_raw_parts(self.ptr as *mut T, self.len) }
    }

    pub fn len(&self) -> usize {
        self.len
    }
}

impl<T: Sized> AsRef<[T]> for PGPSlice<T> {
    fn as_ref(&self) -> &[T] {
        self.as_slice()
    }
}

impl<T: Sized> Drop for PGPSlice<T> {
    fn drop(&mut self) {
        unsafe {
            if !self.ptr.is_null() {
                sys::pgp_free(self.ptr as *mut c_void);
            }
        }
    }
}

#[doc(hidden)]
pub struct OwnedCStr {
    cstr: *mut c_char,
}

impl OwnedCStr {
    pub unsafe fn new(str: *mut c_char) -> Self {
        Self { cstr: str }
    }
}

impl OwnedCStr {
    pub fn to_string(&self) -> String {
        unsafe {
            if self.cstr.is_null() {
                return String::default();
            }
            CStr::from_ptr(self.cstr)
                .to_str()
                .unwrap_or_default()
                .to_owned()
        }
    }

    pub fn to_cstring(&self) -> CString {
        if self.cstr.is_null() {
            return CString::default();
        }
        unsafe { CString::from_raw(self.cstr) }
    }
}

impl AsRef<[u8]> for OwnedCStr {
    fn as_ref(&self) -> &[u8] {
        if self.cstr.is_null() {
            return &[];
        }
        unsafe { CStr::from_ptr(self.cstr).to_bytes() }
    }
}

impl Drop for OwnedCStr {
    fn drop(&mut self) {
        unsafe {
            if !self.cstr.is_null() {
                sys::pgp_free(self.cstr as *mut c_void);
            }
        }
    }
}

impl Debug for OwnedCStr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if self.cstr.is_null() {
            Debug::fmt("", f)
        } else {
            Debug::fmt(unsafe { CStr::from_ptr(self.cstr) }, f)
        }
    }
}

pub struct PGPError(sys::PGP_Error);

/// The type is immutable read-only, so it can be safely sent across threads.
unsafe impl Send for sys::PGP_Error {}

/// The type is immutable read-only, so it can be safely accessed in parallel.
unsafe impl Sync for sys::PGP_Error {}

impl PGPError {
    pub(crate) fn new(e: sys::PGP_Error) -> Self {
        Self(e)
    }

    pub(crate) fn unwrap(e: sys::PGP_Error) -> Result<(), Self> {
        let err = Self::new(e);
        if err.is_error() {
            return Err(err);
        }

        Ok(())
    }

    fn nil() -> Self {
        Self(sys::PGP_Error {
            err: null_mut(),
            err_len: 0,
        })
    }
    #[inline(always)]
    pub fn is_error(&self) -> bool {
        return !self.0.err.is_null();
    }

    unsafe fn as_cstr(&self) -> &CStr {
        if !self.is_error() {
            return CStr::from_bytes_with_nul_unchecked(&[0u8]);
        }
        CStr::from_bytes_with_nul_unchecked(std::slice::from_raw_parts(
            self.0.err.cast(),
            (self.0.err_len + 1) as usize,
        ))
    }
}

impl Default for PGPError {
    fn default() -> Self {
        Self::nil()
    }
}

impl Drop for PGPError {
    fn drop(&mut self) {
        unsafe {
            if !self.0.err.is_null() {
                sys::pgp_cfree(self.0.err.cast());
            }
        }
    }
}

impl Debug for PGPError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if !self.is_error() {
            write!(f, "{{nil}}")
        } else {
            unsafe { write!(f, "{{{}}}", self.as_cstr().to_string_lossy()) }
        }
    }
}

impl Display for PGPError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if !self.is_error() {
            write!(f, "no error")
        } else {
            unsafe { write!(f, "PGP Error: {}", self.as_cstr().to_string_lossy()) }
        }
    }
}

impl Error for PGPError {}
