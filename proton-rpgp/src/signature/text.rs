use std::io::{self, Read};

use pgp::{line_writer::LineBreak, normalize_lines::NormalizedReader};

/// Sanitizes the cleartext by replacing all line breaks `\r\n` with `\n`.
pub(crate) fn sanitize_cleartext(cleartext: &[u8]) -> io::Result<Vec<u8>> {
    let mut buffer = Vec::with_capacity(cleartext.len());
    NormalizedReader::new(cleartext, LineBreak::Lf).read_to_end(&mut buffer)?;
    Ok(buffer)
}
