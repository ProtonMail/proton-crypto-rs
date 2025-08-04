use std::io::{self, Read};

use pgp::{
    armor::{self, BlockType, Dearmor},
    composed::Message,
    ser::Serialize,
};

use crate::{ArmorError, DataEncoding, MessageProcessingError};

const INCLUDE_CHECKSUM: bool = true;

/// Armors a public key.
///
/// Prodcues a message of the form:
/// ```skip
/// -----BEGIN PGP PUBLIC KEY BLOCK-----
///
/// ...
/// -----END PGP PUBLIC KEY BLOCK-----
/// ```
pub fn armor_public_key(public_key: impl AsRef<[u8]>) -> Result<Vec<u8>, ArmorError> {
    let mut armored = Vec::with_capacity(public_key.as_ref().len());
    encode_to_buffer(
        &BinaryArmorSource {
            data: public_key.as_ref(),
        },
        BlockType::PublicKey,
        INCLUDE_CHECKSUM,
        &mut armored,
    )?;
    Ok(armored)
}

/// Armors a private key.
///
/// Prodcues a message of the form:
/// ```skip
/// -----BEGIN PGP PRIVATE KEY BLOCK-----
///
/// ...
/// -----END PGP PRIVATE KEY BLOCK-----
/// ```
pub fn armor_private_key(private_key: impl AsRef<[u8]>) -> Result<Vec<u8>, ArmorError> {
    let mut armored = Vec::with_capacity(private_key.as_ref().len());
    encode_to_buffer(
        &BinaryArmorSource {
            data: private_key.as_ref(),
        },
        BlockType::PrivateKey,
        INCLUDE_CHECKSUM,
        &mut armored,
    )?;
    Ok(armored)
}

/// Armors a signature.
///
/// Prodcues a message of the form:
/// ```skip
/// -----BEGIN PGP SIGNATURE-----
///
/// ...
/// -----END PGP SIGNATURE-----
/// ```
pub fn armor_signature(signature: impl AsRef<[u8]>) -> Result<Vec<u8>, ArmorError> {
    let mut armored = Vec::with_capacity(signature.as_ref().len());
    encode_to_buffer(
        &BinaryArmorSource {
            data: signature.as_ref(),
        },
        BlockType::Signature,
        INCLUDE_CHECKSUM,
        &mut armored,
    )?;
    Ok(armored)
}

/// Armors a message.
///
/// Prodcues a message of the form:
/// ```skip
/// -----BEGIN PGP MESSAGE-----
///
/// ...
/// -----END PGP MESSAGE-----
/// ```
pub fn armor_message(message: impl AsRef<[u8]>) -> Result<Vec<u8>, ArmorError> {
    let mut armored = Vec::with_capacity(message.as_ref().len());
    encode_to_buffer(
        &BinaryArmorSource {
            data: message.as_ref(),
        },
        BlockType::Message,
        INCLUDE_CHECKSUM,
        &mut armored,
    )?;
    Ok(armored)
}

/// Unarmors the input.
///
/// The input must have the form:
/// ```skip
/// -----BEGIN PGP <TYPE>-----
///
/// ...
/// -----END PGP <TYPE>-----
/// ```
pub fn unarmor(armored: impl AsRef<[u8]>) -> Result<Vec<u8>, ArmorError> {
    let mut output = Vec::with_capacity(armored.as_ref().len());
    decode_to_buffer(armored.as_ref(), None, &mut output)?;
    Ok(output)
}

pub(crate) fn encode_to_buffer(
    input: &BinaryArmorSource<'_>,
    block_type: BlockType,
    include_checksum: bool,
    mut output: impl io::Write,
) -> Result<(), ArmorError> {
    armor::write(&input, block_type, &mut output, None, include_checksum)
        .map_err(ArmorError::Encode)
}

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

/// Internal function to decode a [`pgp::composed::Message`] from the input buffer.
pub(crate) fn decode_to_message(
    input: &[u8],
    data_encoding: DataEncoding,
) -> Result<Message<'_>, MessageProcessingError> {
    match data_encoding {
        DataEncoding::Armored => Message::from_armor(input)
            .map_err(MessageProcessingError::MessageParsing)
            .map(|value| value.0),
        DataEncoding::Unarmored => {
            Message::from_bytes(input).map_err(MessageProcessingError::MessageParsing)
        }
    }
}

pub(crate) struct BinaryArmorSource<'a> {
    data: &'a [u8],
}

impl Serialize for BinaryArmorSource<'_> {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> pgp::errors::Result<()> {
        writer.write_all(self.data)?;
        Ok(())
    }

    fn write_len(&self) -> usize {
        self.data.len()
    }
}
