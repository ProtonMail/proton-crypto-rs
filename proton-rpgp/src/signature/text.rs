use std::io::Read;

use pgp::{line_writer::LineBreak, normalize_lines::NormalizedReader};

use crate::TextSanitizationError;

/// Checks that the input is utf-8 encoded and
/// replaces canonical newlines (`\r\n`) with native newlines (`\n`).
pub(crate) fn check_and_sanitize_text(cleartext: &[u8]) -> Result<Vec<u8>, TextSanitizationError> {
    std::str::from_utf8(cleartext)?;
    let mut buffer = Vec::with_capacity(cleartext.len());
    NormalizedReader::new(cleartext, LineBreak::Lf).read_to_end(&mut buffer)?;
    Ok(buffer)
}
