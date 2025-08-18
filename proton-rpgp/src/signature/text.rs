use std::io::Read;

use pgp::{line_writer::LineBreak, normalize_lines::NormalizedReader};

use crate::TextSanitizationError;

/// Checks that the input is utf-8 encoded and
/// replaces canonical newlines (`\r\n`) with native newlines (`\n`).
pub(crate) fn check_and_sanitize_text(cleartext: &[u8]) -> Result<Vec<u8>, TextSanitizationError> {
    let mut buffer = String::with_capacity(cleartext.len());
    NormalizedReader::new(cleartext, LineBreak::Lf).read_to_string(&mut buffer)?;
    Ok(buffer.into_bytes())
}
