use std::io::Read;

use pgp::armor::{BlockType, Dearmor};

use crate::ArmorError;

/// Unarmor the input into the output buffer.
///
/// If the `expected_type` is set, it checks if the armor header matches.
pub(crate) fn decode_to_buffer(
    input: &[u8],
    expected_type: Option<BlockType>,
    output: &mut Vec<u8>,
) -> Result<(), ArmorError> {
    let mut dearmor = Dearmor::new(input);
    dearmor
        .read_header()
        .map_err(|_| ArmorError::DecodeHeader)?;
    if let Some(expected_type) = expected_type {
        let typ = dearmor.typ.ok_or(ArmorError::DecodeHeader)?;
        if typ != expected_type {
            return Err(ArmorError::DecodeWrongHeader(
                typ.to_string(),
                expected_type,
            ));
        }
    }
    dearmor.read_to_end(output).map_err(ArmorError::Decode)?;
    Ok(())
}
