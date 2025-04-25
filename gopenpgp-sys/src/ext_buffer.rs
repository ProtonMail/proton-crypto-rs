use crate::go::sys;
pub struct ExtBuffer(Vec<u8>);

impl ExtBuffer {
    pub fn with_capacity(capacity: usize) -> Self {
        Self(Vec::with_capacity(capacity))
    }

    pub fn take(self) -> Vec<u8> {
        self.0
    }

    pub unsafe fn make_ext_buffer_writer(buffer: &mut Self) -> sys::PGP_ExtWriter {
        sys::PGP_ExtWriter {
            ptr: (buffer as *mut Self).cast(),
            write: Some(ext_buffer_write),
        }
    }
}

extern "C" fn ext_buffer_write(
    ptr: *mut std::os::raw::c_void,
    data: *const std::os::raw::c_void,
    size: usize,
) -> i64 {
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let this: &mut ExtBuffer = unsafe { &mut *ptr.cast() };

    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let data: &[u8] = unsafe { std::slice::from_raw_parts(data.cast(), size) };

    this.0.extend_from_slice(data);

    size as i64
}

#[allow(clippy::box_collection)]
pub struct ExtVecWriter(Box<ExtBuffer>);

impl ExtVecWriter {
    pub fn with_capacity(capacity: usize) -> Self {
        Self(Box::new(ExtBuffer::with_capacity(capacity)))
    }

    pub fn take(self) -> Vec<u8> {
        self.0.take()
    }

    pub unsafe fn make_external_writer(&mut self) -> sys::PGP_ExtWriter {
        ExtBuffer::make_ext_buffer_writer(self.0.as_mut())
    }
}
