use std::{io::Read, sync::LazyLock};

use nom::Input;
use pgp::{
    bytes::{Buf, BufMut, BytesMut},
    line_writer::LineBreak,
    normalize_lines::NormalizedReader,
};
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

static RE: LazyLock<regex::bytes::Regex> =
    LazyLock::new(|| regex::bytes::Regex::new(r"(\r\n?|\n)").expect("valid regex"));

/// This struct wraps a reader and normalize line endings.
/// Copied code from `NormalizedReader` in rPGP to add [`CustomNormalizedReader::into_inner`].
pub struct CustomNormalizedReader<R>
where
    R: Read,
{
    line_break: LineBreak,
    source: R,
    in_buffer: [u8; BUF_SIZE / 2],
    replaced: BytesMut,
    edge_case: Option<[u8; 2]>,
    is_done: bool,
}

impl<R: Read> CustomNormalizedReader<R> {
    pub fn new(source: R, line_break: LineBreak) -> Self {
        Self {
            source,
            line_break,
            in_buffer: [0_u8; BUF_SIZE / 2],
            replaced: BytesMut::with_capacity(BUF_SIZE),
            edge_case: None,
            is_done: false,
        }
    }

    pub fn into_inner(self) -> R {
        self.source
    }

    pub fn new_lf(source: R) -> Self {
        Self::new(source, LineBreak::Lf)
    }

    /// Fills the buffer, and then normalizes it
    fn fill_buffer(&mut self) -> std::io::Result<()> {
        // edge case, if the last byte of the previous buffer was `\r` and the first of the new is `\n`
        // we need to make sure to correctly handle it.
        let last_char = self.in_buffer[self.in_buffer.len() - 1];
        let read = fill_buffer(&mut self.source, &mut self.in_buffer, None)?;
        if read < self.in_buffer.len() {
            self.is_done = true;
        }
        self.cleanup_buffer(read, last_char);
        Ok(())
    }

    /// Normalizes the line endings in the current buffer
    fn cleanup_buffer(&mut self, read: usize, last_char: u8) {
        const CR: u8 = b'\r';
        const LF: u8 = b'\n';

        self.replaced.clear();
        let mut start = 0;
        let mut end = read;

        if read >= self.in_buffer.len() && self.in_buffer[self.in_buffer.len() - 1] == CR {
            // The next boundary could be an edge case, so we are not including it.
            end = read - 1;
        }

        // Handle edge case where the last byte of the previous buffer was `\r`.
        let edge_case = [last_char, self.in_buffer[0]];
        match (edge_case, read > 0) {
            ([CR, LF], true) => {
                // Edge case, we need to normalize it seperately.
                let res = RE.replace_all(&edge_case, self.line_break.as_ref());
                self.replaced.extend_from_slice(&res);
                start = 1;
            }
            ([CR, _], _) => {
                // The last `\r` was not included and normalization is not needed.
                self.replaced.put_u8(CR);
            }
            _ => {}
        }

        // Normalize the buffer.
        let res = RE.replace_all(&self.in_buffer[start..end], self.line_break.as_ref());
        self.replaced.extend_from_slice(&res);
    }
}

impl<R: Read> Read for CustomNormalizedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if !self.replaced.has_remaining() {
            if self.is_done {
                return Ok(0);
            }
            self.fill_buffer()?;
        }

        let to_write = self.replaced.remaining().min(buf.len());
        self.replaced.copy_to_slice(&mut buf[..to_write]);
        Ok(to_write)
    }
}

pub(crate) fn fill_buffer<R: Read>(
    mut source: R,
    buffer: &mut [u8],
    chunk_size: Option<usize>,
) -> std::io::Result<usize> {
    let mut offset = 0;
    let chunk_size = chunk_size.unwrap_or(buffer.len());
    loop {
        let read = source.read(&mut buffer[offset..chunk_size])?;
        offset += read;

        if read == 0 || offset == chunk_size {
            break;
        }
    }
    Ok(offset)
}

/// Copied code from `NormalizingHasher` in rPGP as constructors and fields are private.
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
