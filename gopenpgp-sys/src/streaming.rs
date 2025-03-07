use std::{io, ptr::null_mut};

use crate::sys;

pub struct ReaderForGo<T: ?Sized>(Box<T>);

impl<T: io::Read> ReaderForGo<T> {
    pub fn new(reader: impl Into<Box<T>>) -> Self {
        Self(reader.into())
    }

    pub unsafe fn make_external_reader(&mut self) -> sys::PGP_ExtReader {
        sys::PGP_ExtReader {
            ptr: (self.0.as_mut() as *mut T).cast(),
            read: Some(ext_reader_read::<T>),
        }
    }
}

extern "C" fn ext_reader_read<T: io::Read>(
    ptr: *mut std::os::raw::c_void,
    data: *mut std::os::raw::c_void,
    size: usize,
    err_code: *mut i32,
) -> i64 {
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe {
        let reader: *mut T = ptr.cast();
        let data_bytes: &mut [u8] = std::slice::from_raw_parts_mut(data.cast(), size);
        let num_read = (*reader).read(data_bytes).unwrap_or_else(|_| {
            *err_code = sys::PGP_READER_CODES::READER_ERROR as i32;
            0
        });
        if size < num_read {
            *err_code = sys::PGP_READER_CODES::READER_ERROR as i32;
            return 0;
        }
        if num_read == 0 {
            *err_code = sys::PGP_READER_CODES::READER_EOF as i32;
        }
        num_read as i64
    }
}

pub struct WriterForGo<T: ?Sized>(Box<T>);

impl<T: io::Write> WriterForGo<T> {
    pub fn new(writer: impl Into<Box<T>>) -> Self {
        Self(writer.into())
    }

    pub fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }

    pub unsafe fn make_external_writer(&mut self) -> sys::PGP_ExtWriter {
        sys::PGP_ExtWriter {
            ptr: (self.0.as_mut() as *mut T).cast(),
            write: Some(ext_writer_write::<T>),
        }
    }
}

extern "C" fn ext_writer_write<T: io::Write>(
    ptr: *mut std::os::raw::c_void,
    data: *const std::os::raw::c_void,
    size: usize,
) -> i64 {
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe {
        let writer: *mut T = ptr.cast();
        let data_bytes: &[u8] = std::slice::from_raw_parts(data.cast(), size);
        let write_result = (*writer).write(data_bytes);
        match write_result {
            Ok(num_written) => num_written as i64,
            Err(_) => sys::PGP_WRITER_CODES::WRITER_ERROR as i64,
        }
    }
}

impl Default for sys::PGP_ExtWriter {
    fn default() -> Self {
        Self {
            ptr: null_mut(),
            write: None,
        }
    }
}
