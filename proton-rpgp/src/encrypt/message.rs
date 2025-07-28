use std::io::{self};

use crate::armor;

use pgp::{
    armor::{self as pgp_armor, BlockType},
    packet::{Packet, PacketParser, PacketTrait},
    ser::Serialize,
    types::{Fingerprint, KeyId},
};

use crate::{ArmorError, PgpMessageError, SessionKey};

/// Encrypted message type which allows to query information about the encrypted message.
pub struct EncryptedMessage {
    /// The encrypted data.
    pub encrypted_data: Vec<u8>,

    /// The revealed session key if any.
    revealed_session_key: Option<SessionKey>,
}

impl EncryptedMessage {
    pub(crate) fn new(encrypted_data: Vec<u8>, revealed_session_key: Option<SessionKey>) -> Self {
        Self {
            encrypted_data,
            revealed_session_key,
        }
    }

    /// Creates an `EncryptedMessage` from an armored `OpenPGP` message.
    pub fn from_armor(armor: &[u8]) -> Result<Self, PgpMessageError> {
        let mut encrypted_data = Vec::with_capacity(armor.len());
        armor::decode_to_buffer(armor, Some(BlockType::Message), &mut encrypted_data)?;
        // We quickly check the the message is splitable into key packets and data packets.
        split_pgp_message(&encrypted_data)?;
        Ok(Self::new(encrypted_data, None))
    }

    /// Creates an `EncryptedMessage` from a binary `OpenPGP` message.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PgpMessageError> {
        // We quickly check the the message is splitable into key packets and data packets.
        split_pgp_message(bytes)?;
        Ok(Self::new(bytes.to_vec(), None))
    }

    /// Returns the revealed session key if enabled
    pub fn revealed_session_key(&self) -> Option<&SessionKey> {
        self.revealed_session_key.as_ref()
    }

    /// Provides a slice of the key packets.
    pub fn as_key_packets(&self) -> Result<&[u8], PgpMessageError> {
        split_pgp_message(&self.encrypted_data).map(|(key_packets, _)| key_packets)
    }

    /// Provides a slice of the data packet.
    pub fn as_data_packet(&self) -> Result<&[u8], PgpMessageError> {
        split_pgp_message(&self.encrypted_data).map(|(_, data_packet)| data_packet)
    }

    /// Returns the `OpenPGP KeyIds` of the keys the data was encrypted to.
    ///
    /// This method only considers `PKESKv3` packets, because `PKESKv6` only contain key fingerprints.
    pub fn encryption_key_ids(&self) -> Vec<KeyId> {
        encyption_key_ids(&self.encrypted_data)
    }

    /// Returns the `OpenPGP fingerprints` of the keys the data was encrypted to.
    ///
    /// This method only considers `PKESKv6` packets, because `PKESKv3` only contain key-ids.
    pub fn encryption_fingerprints(&self) -> Vec<Fingerprint> {
        encyption_fingerprints(&self.encrypted_data)
    }

    /// Provides a slice of the key packets.
    ///
    /// Returns the entire data if any error occurs.
    pub fn as_key_packets_unchecked(&self) -> &[u8] {
        self.as_key_packets().unwrap_or(&self.encrypted_data)
    }

    /// Provides a slice of the data packet.
    ///
    /// Returns the entire data if any error occurs.
    pub fn as_data_packet_unchecked(&self) -> &[u8] {
        self.as_data_packet().unwrap_or(&self.encrypted_data)
    }

    /// Returns the armored message.
    pub fn armor(&self) -> Result<Vec<u8>, PgpMessageError> {
        let mut output = Vec::with_capacity(self.encrypted_data.len());
        pgp_armor::write(self, BlockType::Message, &mut output, None, true)
            .map_err(ArmorError::Encode)?;
        Ok(output)
    }
}

impl Serialize for EncryptedMessage {
    fn to_writer<W: io::Write>(&self, w: &mut W) -> pgp::errors::Result<()> {
        w.write_all(&self.encrypted_data)?;
        Ok(())
    }

    fn write_len(&self) -> usize {
        self.encrypted_data.len()
    }
}

impl AsRef<[u8]> for EncryptedMessage {
    fn as_ref(&self) -> &[u8] {
        &self.encrypted_data
    }
}

impl From<Vec<u8>> for EncryptedMessage {
    fn from(encrypted_data: Vec<u8>) -> Self {
        Self::new(encrypted_data, None)
    }
}

/// This function splits a message into key packets and data packet.
///
/// Assumes the message has the form:
/// `| key packets | data packet |`
/// All packets after data packet are ignored.
fn split_pgp_message(encrypted_message: &[u8]) -> Result<(&[u8], &[u8]), PgpMessageError> {
    let packet_parser = PacketParser::new(encrypted_message);
    let mut split_point: usize = 0;
    for packet in packet_parser {
        match packet {
            Ok(Packet::PublicKeyEncryptedSessionKey(pkesk)) => {
                split_point += pkesk.write_len_with_header();
            }
            Ok(Packet::SymKeyEncryptedSessionKey(skesk)) => {
                split_point += skesk.write_len_with_header();
            }
            Ok(Packet::SymEncryptedProtectedData(_)) => {
                break;
            }
            Err(e) => {
                return Err(PgpMessageError::ParseSplit(e));
            }
            _ => {
                return Err(PgpMessageError::NonExpectedPacketSplit);
            }
        }
    }
    Ok((
        &encrypted_message[..split_point],
        &encrypted_message[split_point..],
    ))
}

fn encyption_key_ids(encrypted_message: &[u8]) -> Vec<KeyId> {
    PacketParser::new(encrypted_message)
        .filter_map(|packet| match packet {
            Ok(Packet::PublicKeyEncryptedSessionKey(pkesk)) => pkesk.id().ok().copied(),
            _ => None,
        })
        .collect()
}

fn encyption_fingerprints(encrypted_message: &[u8]) -> Vec<Fingerprint> {
    PacketParser::new(encrypted_message)
        .filter_map(|packet| match packet {
            Ok(Packet::PublicKeyEncryptedSessionKey(pkesk)) => {
                pkesk.fingerprint().ok().flatten().cloned()
            }
            _ => None,
        })
        .collect()
}
