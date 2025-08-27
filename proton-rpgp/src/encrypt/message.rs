use std::{
    cell::RefCell,
    io::{self, BufRead, Read},
    rc::Rc,
};

use crate::{armor, ExternalDetachedSignature};

use pgp::{
    armor::{self as pgp_armor, BlockType},
    packet::{Packet, PacketParser},
    ser::Serialize,
    types::{Fingerprint, KeyId},
};

use crate::{ArmorError, EncryptedMessageError, SessionKey};

/// Encrypted message type which allows to query information about the encrypted message.
pub struct EncryptedMessage {
    /// The encrypted data.
    pub encrypted_data: Vec<u8>,

    /// An optional detached signature.
    pub(crate) detached_signature: Option<ExternalDetachedSignature<'static>>,

    /// The revealed session key if any.
    pub(crate) revealed_session_key: Option<SessionKey>,
}

impl EncryptedMessage {
    pub(crate) fn new(encrypted_data: Vec<u8>, revealed_session_key: Option<SessionKey>) -> Self {
        Self {
            encrypted_data,
            detached_signature: None,
            revealed_session_key,
        }
    }

    /// Creates an `EncryptedMessage` from an armored `OpenPGP` message.
    pub fn from_armor(armor: &[u8]) -> crate::Result<Self> {
        let mut encrypted_data = Vec::with_capacity(armor.len());
        armor::decode_to_buffer(armor, Some(BlockType::Message), &mut encrypted_data)?;
        // We quickly check the the message is splitable into key packets and data packets.
        split_pgp_message(&encrypted_data)?;
        Ok(Self::new(encrypted_data, None))
    }

    /// Creates an `EncryptedMessage` from a binary `OpenPGP` message.
    pub fn from_bytes(bytes: &[u8]) -> crate::Result<Self> {
        // We quickly check the the message is splitable into key packets and data packets.
        split_pgp_message(bytes)?;
        Ok(Self::new(bytes.to_vec(), None))
    }

    /// Returns the revealed session key if enabled
    pub fn revealed_session_key(&self) -> Option<&SessionKey> {
        self.revealed_session_key.as_ref()
    }

    /// Provides a slice of the key packets.
    pub fn as_key_packets(&self) -> crate::Result<&[u8]> {
        split_pgp_message(&self.encrypted_data)
            .map(|(key_packets, _)| key_packets)
            .map_err(Into::into)
    }

    /// Provides a slice of the data packet.
    pub fn as_data_packet(&self) -> crate::Result<&[u8]> {
        split_pgp_message(&self.encrypted_data)
            .map(|(_, data_packet)| data_packet)
            .map_err(Into::into)
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
    pub fn armor(&self) -> crate::Result<Vec<u8>> {
        let mut output = Vec::with_capacity(self.encrypted_data.len());
        pgp_armor::write(self, BlockType::Message, &mut output, None, true)
            .map_err(ArmorError::Encode)?;
        Ok(output)
    }

    /// Returns the detached signature if any.
    pub fn detached_signature(&self) -> Option<&ExternalDetachedSignature<'static>> {
        self.detached_signature.as_ref()
    }

    /// Splits the detached signature from the message.
    ///
    /// Returns the message without the detached signature and the detached signature.
    pub fn split_detached_signature(
        mut self,
    ) -> (Self, Option<ExternalDetachedSignature<'static>>) {
        let detached_signature = self.detached_signature.take();
        (self, detached_signature)
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
fn split_pgp_message(encrypted_message: &[u8]) -> Result<(&[u8], &[u8]), EncryptedMessageError> {
    let bytes_read = Rc::new(RefCell::new(0));
    let reader = ExternalCountingReader::new(encrypted_message, bytes_read.clone());
    let mut split_point = 0;
    for packet in PacketParser::new(reader) {
        match packet {
            Ok(Packet::PublicKeyEncryptedSessionKey(_) | Packet::SymKeyEncryptedSessionKey(_)) => {
                // Safe to read the counter as the reader is not used concurrently.
                split_point = *bytes_read.borrow();
            }
            Ok(Packet::SymEncryptedProtectedData(_)) => {
                break;
            }
            Err(e) => return Err(EncryptedMessageError::ParseSplit(e)),
            _ => return Err(EncryptedMessageError::NonExpectedPacketSplit),
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

type ExternalCounter = Rc<RefCell<usize>>;

/// Internal reader that counts the number of bytes read in an external counter.
///
/// `ExternalCountingReader` is !Send and !Sync, i.e., do not used it in concurrent environments.
/// It mutates the external counter when reading from the inner reader.
struct ExternalCountingReader<R> {
    /// The inner reader.
    inner: R,

    /// The external counter.
    bytes_read: ExternalCounter,
}

impl<R: BufRead> ExternalCountingReader<R> {
    fn new(inner: R, size: ExternalCounter) -> Self {
        Self {
            inner,
            bytes_read: size,
        }
    }

    fn bytes_read(&self) -> usize {
        *self.bytes_read.borrow()
    }
}

impl<R: BufRead> Read for ExternalCountingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        *self.bytes_read.borrow_mut() += n;
        Ok(n)
    }
}

impl<R: BufRead> BufRead for ExternalCountingReader<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.inner.fill_buf()
    }

    fn consume(&mut self, amt: usize) {
        *self.bytes_read.borrow_mut() += amt;
        self.inner.consume(amt);
    }
}
