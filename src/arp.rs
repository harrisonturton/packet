use crate::{ethernet::EtherType, Error, Result};
use byteorder::{ByteOrder, NetworkEndian};

/// An ARP packet.
///
/// # Standards conformance
///
/// Follows [RFC 826](https://www.rfc-editor.org/rfc/rfc826.html).
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct Packet<B: AsRef<[u8]>> {
    buf: B,
}

impl<B: AsRef<[u8]>> Packet<B> {
    /// Create a new ARP packet.
    ///
    /// # Errors
    ///
    /// Fails when the buffer is shorter than 28 bytes, the minimum size for ARP
    /// packets carrying 48-bit Ethernet MAC addresses.
    #[inline]
    #[must_use]
    pub fn new(buf: B) -> Result<Self> {
        if buf.as_ref().len() >= MIN_PACKET_LEN {
            Ok(Self { buf })
        } else {
            println!("BUFFERLEN: {}", buf.as_ref().len());
            Err(Error::CannotParse("buffer too small"))
        }
    }

    /// Extract the hardware type
    #[inline]
    pub fn hardware_type(&self) -> HardwareType {
        let data = self.buf.as_ref();
        NetworkEndian::read_u16(&data[offsets::HARDWARE_TYPE]).into()
    }

    /// Extract the protocol type
    #[inline]
    pub fn protocol_type(&self) -> EtherType {
        let data = self.buf.as_ref();
        NetworkEndian::read_u16(&data[offsets::PROTOCOL_TYPE]).into()
    }

    /// Extract the hardware address length
    #[inline]
    pub fn hardware_addr_len(&self) -> u8 {
        let data = self.buf.as_ref();
        data[offsets::HARDWARE_ADDR_LEN]
    }

    /// Extract the protocol address length
    #[inline]
    pub fn protocol_addr_len(&self) -> u8 {
        let data = self.buf.as_ref();
        data[offsets::PROTOCOL_ADDR_LEN]
    }

    /// Extract the operation
    #[inline]
    pub fn operation(&self) -> Operation {
        let data = self.buf.as_ref();
        NetworkEndian::read_u16(&data[offsets::OPERATION]).into()
    }

    /// Extract the senders hardware address
    #[inline]
    pub fn sender_hardware_addr(&self) -> &[u8] {
        let data = self.buf.as_ref();
        let hardware_len = usize::from(self.hardware_addr_len());

        let start = offsets::ADDRS;
        let end = start + hardware_len;
        &data[start..end]
    }

    /// Extract the senders protocol address
    #[inline]
    pub fn sender_protocol_addr(&self) -> &[u8] {
        let data = self.buf.as_ref();
        let hardware_len = usize::from(self.hardware_addr_len());
        let protocol_len = usize::from(self.protocol_addr_len());

        let start = offsets::ADDRS + hardware_len;
        let end = start + protocol_len;
        &data[start..end]
    }

    /// Extract the targets hardware address
    #[inline]
    pub fn target_hardware_addr(&self) -> &[u8] {
        let data = self.buf.as_ref();
        let hardware_len = usize::from(self.hardware_addr_len());
        let protocol_len = usize::from(self.protocol_addr_len());

        let start = offsets::ADDRS + hardware_len + protocol_len;
        let end = start + hardware_len;
        &data[start..end]
    }

    /// Extract the targets protocol address
    #[inline]
    pub fn target_protocol_addr(&self) -> &[u8] {
        let data = self.buf.as_ref();
        let hardware_len = usize::from(self.hardware_addr_len());
        let protocol_len = usize::from(self.protocol_addr_len());

        let start = offsets::ADDRS + hardware_len + protocol_len + hardware_len;
        let end = start + protocol_len;
        &data[start..end]
    }
}

mod offsets {
    use std::ops::Range;
    pub(crate) const HARDWARE_TYPE: Range<usize> = 0..2;
    pub(crate) const PROTOCOL_TYPE: Range<usize> = 2..4;
    pub(crate) const HARDWARE_ADDR_LEN: usize = 4;
    pub(crate) const PROTOCOL_ADDR_LEN: usize = 5;
    pub(crate) const OPERATION: Range<usize> = 6..8;
    pub(crate) const ADDRS: usize = 8;
}

/// Interpretation of the "hardware type" field in the ARP packet.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum HardwareType {
    Ethernet,
    Unknown(u16),
}

impl From<u16> for HardwareType {
    fn from(value: u16) -> Self {
        match value {
            1 => HardwareType::Ethernet,
            _ => HardwareType::Unknown(value),
        }
    }
}

impl From<HardwareType> for u16 {
    fn from(value: HardwareType) -> Self {
        match value {
            HardwareType::Ethernet => 1,
            HardwareType::Unknown(value) => value,
        }
    }
}

/// Interpretation of the "operation" field in the ARP packet.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum Operation {
    Request,
    Reply,
    Invalid(u16)
}

impl From<u16> for Operation {
    fn from(value: u16) -> Self {
        match value {
            1 => Operation::Request,
            2 => Operation::Reply,
            _ => Operation::Invalid(value),
        }
    }
}

impl From<Operation> for u16 {
    fn from(value: Operation) -> Self {
        match value {
            Operation::Request => 1,
            Operation::Reply => 2,
            Operation::Invalid(op) => op,
        }
    }
}

// ARP packet for a 48-bit MAC address
pub const MIN_PACKET_LEN: usize = 28;

#[cfg(test)]
mod tests {
    use std::result::Result;
    use std::error::Error;
    use crate::ethernet::{EtherType, Frame};
    use super::{Packet, HardwareType, Operation};

    const REPLY_PACKET: &'static [u8] = include_bytes!("../resources/enet-arp-reply.bin");

    #[test]
    fn packet_returns_err_when_buffer_too_short() {
        let packet = Packet::new(&[0, 0, 0]);
        assert!(packet.is_err());
    }

    #[test]
    fn packet_has_expected_hardware_type() -> Result<(), Box<dyn Error>> {
        let frame = Frame::new(REPLY_PACKET)?;
        let packet = Packet::new(frame.payload())?;
        assert_eq!(packet.hardware_type(), HardwareType::Ethernet);
        Ok(())
    }

    #[test]
    fn packet_has_expected_protocol_type() -> Result<(), Box<dyn Error>> {
        let frame = Frame::new(REPLY_PACKET)?;
        let packet = Packet::new(frame.payload())?;
        assert_eq!(packet.protocol_type(), EtherType::Ipv4);
        Ok(())
    }

    #[test]
    fn packet_has_expected_hardware_addr_len() -> Result<(), Box<dyn Error>> {
        let frame = Frame::new(REPLY_PACKET)?;
        let packet = Packet::new(frame.payload())?;
        assert_eq!(packet.hardware_addr_len(), 6);
        Ok(())
    }

    #[test]
    fn packet_has_expected_protocol_addr_len() -> Result<(), Box<dyn Error>> {
        let frame = Frame::new(REPLY_PACKET)?;
        let packet = Packet::new(frame.payload())?;
        assert_eq!(packet.protocol_addr_len(), 4);
        Ok(())
    }

    #[test]
    fn packet_has_expected_operation() -> Result<(), Box<dyn Error>> {
        let frame = Frame::new(REPLY_PACKET)?;
        let packet = Packet::new(frame.payload())?;
        assert_eq!(packet.operation(), Operation::Reply);
        Ok(())
    }

    #[test]
    fn packet_has_expected_sender_hardware_addr() -> Result<(), Box<dyn Error>> {
        let frame = Frame::new(REPLY_PACKET)?;
        let packet = Packet::new(frame.payload())?;
        assert_eq!(packet.sender_hardware_addr(), &[0xBC, 0xD0, 0x74, 0x0D, 0x9C, 0x12]);
        Ok(())
    }

    #[test]
    fn operation_from_u16_gives_expected_value_when_request() {
        let op = Operation::from(1u16);
        assert_eq!(op, Operation::Request);
    }

    #[test]
    fn operation_from_u16_gives_expected_value_when_reply() {
        let op = Operation::from(2u16);
        assert_eq!(op, Operation::Reply);
    }

    #[test]
    fn operation_from_u16_gives_expected_value_when_invalid() {
        let op = Operation::from(0u16);
        assert_eq!(op, Operation::Invalid(0));
    }
}