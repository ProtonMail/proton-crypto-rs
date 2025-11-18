use std::{cell::RefCell, io::Read, rc::Rc};

use nom::Input;
use pgp::{line_writer::LineBreak, normalize_lines::NormalizedReader};
use sha2::digest::DynDigest;

use crate::TextSanitizationError;

const BUF_SIZE: usize = 1024;

/// Checks that the input is utf-8 encoded and
/// replaces canonical newlines (`\r\n`) with native newlines (`\n`).
pub(crate) fn check_and_sanitize_text(cleartext: &[u8]) -> Result<Vec<u8>, TextSanitizationError> {
    let mut buffer = String::with_capacity(cleartext.len());
    NormalizedReader::new(cleartext, LineBreak::Lf).read_to_string(&mut buffer)?;
    Ok(buffer.into_bytes())
}

/// Copied code from [`pgp::normalize_lines::NormalizedReader`]
/// in rPGP as constructors and fields are private.
pub struct NormalizingHasher {
    hasher: Box<dyn DynDigest + Send>,
    text_mode: bool,
    last_was_cr: bool,
}

impl NormalizingHasher {
    pub(crate) fn new(hasher: Box<dyn DynDigest + Send>, text_mode: bool) -> Self {
        Self {
            hasher,
            text_mode,
            last_was_cr: false,
        }
    }

    pub(crate) fn done(mut self) -> Box<dyn DynDigest + Send> {
        if self.text_mode && self.last_was_cr {
            self.hasher.update(b"\n");
        }

        self.hasher
    }

    pub(crate) fn hash_buf(&mut self, buffer: &[u8]) {
        if buffer.is_empty() {
            return;
        }

        if self.text_mode {
            let mut buf = buffer;

            if self.last_was_cr {
                // detect and handle a LF that follows a CR
                // (it should not be normalized)
                if buf[0] == b'\n' {
                    self.hasher.update(b"\n");
                    buf = &buf[1..];
                }

                self.last_was_cr = false;
            }

            while !buf.is_empty() {
                match buf.position(|c| c == b'\r' || c == b'\n') {
                    None => {
                        // no line endings in sight, just hash the data
                        self.hasher.update(buf);
                        buf = &[];
                    }

                    Some(pos) => {
                        // consume all bytes before line-break-related position

                        self.hasher.update(&buf[..pos]);
                        buf = &buf[pos..];

                        // handle this line-break related context
                        let only_one = buf.len() == 1;
                        match (buf[0], only_one) {
                            (b'\n', _) => {
                                self.hasher.update(b"\r\n");
                                buf = &buf[1..];
                            }
                            (b'\r', false) => {
                                // we are guaranteed to have at least two bytes
                                if buf[1] == b'\n' {
                                    // there was a '\n' in the stream, we consume it as well
                                    self.hasher.update(b"\r\n");
                                    buf = &buf[2..];
                                } else {
                                    // this was a lone '\r', we don't normalize it
                                    self.hasher.update(b"\r");
                                    buf = &buf[1..];
                                }
                            }
                            (b'\r', true) => {
                                // this one '\r' was the last thing in the buffer
                                self.hasher.update(b"\r");
                                buf = &[];

                                // remember that the last character was a CR.
                                // if the next character is a LF, we want to *not* normalize it
                                self.last_was_cr = true;
                            }
                            _ => unreachable!("buf.position gave us either a '\n or a '\r'"),
                        }
                    }
                }
            }
        } else {
            self.hasher.update(buffer);
        }
    }
}

pub type ReaderReference<R> = Rc<RefCell<R>>;

pub struct ReferencedReader<R>
where
    R: Read,
{
    inner: Rc<RefCell<R>>,
}

impl<R: Read> ReferencedReader<R> {
    pub(crate) fn new(source: R) -> Self {
        Self {
            inner: Rc::new(RefCell::new(source)),
        }
    }

    pub(crate) fn reference(&self) -> ReaderReference<R> {
        Rc::clone(&self.inner)
    }
}

impl<R: Read> Read for ReferencedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.borrow_mut().read(buf)
    }
}
