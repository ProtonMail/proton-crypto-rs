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
    unsafe {
        // Extend from slice does a 1 by 1 copy of the data, we should use memcpy instead.
        let buffer: *mut ExtBuffer = ptr.cast();
        let data_bytes: &[u8] = std::slice::from_raw_parts(data.cast(), size);
        let vec = &mut (*buffer).0;
        let current_len = vec.len();
        let new_size = current_len + size;

        // Reserve enough space for the new size;
        vec.reserve(new_size);
        // Copy data.
        let buffer_start = vec.as_mut_ptr().add(current_len);
        std::ptr::copy_nonoverlapping(data_bytes.as_ptr(), buffer_start, size);

        // Manually set the new size of the buffer.
        vec.set_len(new_size);

        size as i64
    }
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
