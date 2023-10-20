//! Read and write ARP packets.
use crate::{enet::EtherType, Error, Result};
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
        if buf.as_ref().len() >= HEADER_LEN {
            Ok(Self { buf })
        } else {
            Err(Error::CannotParse("buffer too small"))
        }
    }

    /// Create a new ARP packet from a byte array *without* checking that the
    /// array is valid. It is the responsibility of the caller to make sure the
    /// buffer is large enough for the packet.
    ///
    /// # Safety
    ///
    /// The buffer must be at least [`HEADER_LEN`](crate::arp::HEADER_LEN) bytes
    /// long.
    #[inline]
    #[must_use]
    pub unsafe fn new_unchecked(buf: B) -> Self {
        Self { buf }
    }

    /// Create a new [`PacketBuilder`] that modifies a buffer of bytes in-place.
    ///
    /// # Errors
    ///
    /// See [`PacketBuilder::new`].
    pub fn builder<T>(buf: T) -> Result<PacketBuilder<T>>
    where
        T: AsRef<[u8]> + AsMut<[u8]>,
    {
        PacketBuilder::new(buf)
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
        let addr = offsets::sender_hardware_addr(data);
        &data[addr]
    }

    /// Extract the senders protocol address
    #[inline]
    pub fn sender_protocol_addr(&self) -> &[u8] {
        let data = self.buf.as_ref();
        let addr = offsets::sender_protocol_addr(data);
        &data[addr]
    }

    /// Extract the targets hardware address
    #[inline]
    pub fn target_hardware_addr(&self) -> &[u8] {
        let data = self.buf.as_ref();
        let addr = offsets::target_hardware_addr(data);
        &data[addr]
    }

    /// Extract the targets protocol address
    #[inline]
    pub fn target_protocol_addr(&self) -> &[u8] {
        let data = self.buf.as_ref();
        let addr = offsets::target_protocol_addr(data);
        &data[addr]
    }
}

/// Builder for constructing [`Packet`] instances.
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct PacketBuilder<B: AsRef<[u8]> + AsMut<[u8]>> {
    buf: B,
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> PacketBuilder<B> {
    /// Create a new [`PacketBuilder`] instance from an underlying byte buffer.
    /// This will modify the buffer in-place, so can be used for making
    /// incremental modifications to an existing packet in memory.
    ///
    /// # Errors
    ///
    /// Fails when the byte slice is smaller 20 bytes long, but does no other
    /// validation.
    #[inline]
    #[must_use]
    pub fn new(buf: B) -> Result<Self> {
        if buf.as_ref().len() >= HEADER_LEN {
            Ok(PacketBuilder { buf })
        } else {
            Err(Error::CannotParse("buffer too small"))
        }
    }

    /// Set the hardware type.
    #[inline]
    #[must_use]
    pub fn hardware_type(mut self, htype: HardwareType) -> Self {
        let data = self.buf.as_mut();
        NetworkEndian::write_u16(&mut data[offsets::HARDWARE_TYPE], htype.into());
        self
    }

    /// Set the protocol type.
    #[inline]
    #[must_use]
    pub fn protocol_type(mut self, protocol: EtherType) -> Self {
        let data = self.buf.as_mut();
        NetworkEndian::write_u16(&mut data[offsets::PROTOCOL_TYPE], protocol.into());
        self
    }

    /// Set the hardware address length.
    #[inline]
    #[must_use]
    pub fn hardware_addr_len(mut self, len: u8) -> Self {
        let data = self.buf.as_mut();
        data[offsets::HARDWARE_ADDR_LEN] = len;
        self
    }

    /// Set the protocol address length.
    #[inline]
    #[must_use]
    pub fn protocol_addr_len(mut self, len: u8) -> Self {
        let data = self.buf.as_mut();
        data[offsets::PROTOCOL_ADDR_LEN] = len;
        self
    }

    /// Set the operation.
    #[inline]
    #[must_use]
    pub fn operation(mut self, operation: Operation) -> Self {
        let data = self.buf.as_mut();
        NetworkEndian::write_u16(&mut data[offsets::OPERATION], operation.into());
        self
    }

    /// Set the sender hardware address. [`PacketBuilder::hardware_addr_len`]
    /// must be called first to set the address length.
    ///
    /// # Errors
    ///
    /// Fails when the caller attempts to set a hardware address that is larger
    /// than the existing hardware address length.
    #[inline]
    #[must_use]
    pub fn sender_hardware_addr(mut self, addr: &[u8]) -> Result<Self> {
        let data = self.buf.as_mut();
        let sender_addr = offsets::sender_hardware_addr(data);

        if addr.len() > sender_addr.len() {
            return Err(Error::NotEnoughSpace("hardware address is too long"));
        }

        data[sender_addr].copy_from_slice(addr);
        Ok(self)
    }

    /// Set the sender protocol address. [`PacketBuilder::protocol_addr_len`]
    /// must be called first to set the address length.
    ///
    /// # Errors
    ///
    /// Fails when the caller attempts to set a protocol address that is larger
    /// than the existing protocol address length.
    #[inline]
    #[must_use]
    pub fn sender_protocol_addr(mut self, addr: &[u8]) -> Result<Self> {
        let data = self.buf.as_mut();
        let sender_addr = offsets::sender_protocol_addr(data);

        if addr.len() > sender_addr.len() {
            return Err(Error::NotEnoughSpace("protocol address is too long"));
        }

        data[sender_addr].copy_from_slice(addr);
        Ok(self)
    }

    /// Set the target hardware address. [`PacketBuilder::hardware_addr_len`]
    /// must be called first to set the address length.
    ///
    /// # Errors
    ///
    /// Fails when the caller attempts to set a hardware address that is larger
    /// than the existing hardware address length.
    #[inline]
    #[must_use]
    pub fn target_hardware_addr(mut self, addr: &[u8]) -> Result<Self> {
        let data = self.buf.as_mut();
        let target_addr = offsets::target_hardware_addr(data);

        if addr.len() > target_addr.len() {
            return Err(Error::NotEnoughSpace("protocol address is too long"));
        }

        data[target_addr].copy_from_slice(addr);
        Ok(self)
    }

    /// Set the target protocol address. [`PacketBuilder::protocol_addr_len`]
    /// must be called first to set the address length.
    ///
    /// # Errors
    ///
    /// Fails when the caller attempts to set a protocol address that is larger
    /// than the existing protocol address length.
    #[inline]
    #[must_use]
    pub fn target_protocol_addr(mut self, addr: &[u8]) -> Result<Self> {
        let data = self.buf.as_mut();
        let target_addr = offsets::target_protocol_addr(data);

        if addr.len() > target_addr.len() {
            return Err(Error::NotEnoughSpace("protocol address is too long"));
        }

        data[target_addr].copy_from_slice(addr);
        Ok(self)
    }

    /// Create the ARP packet.
    #[inline]
    pub fn build(self) -> Packet<B> {
        unsafe { Packet::new_unchecked(self.buf) }
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

    #[inline]
    pub(crate) fn sender_hardware_addr(data: &[u8]) -> Range<usize> {
        let hardware_len = usize::from(data[HARDWARE_ADDR_LEN]);

        let start = ADDRS;
        let end = start + hardware_len;
        start..end
    }

    #[inline]
    pub(crate) fn sender_protocol_addr(data: &[u8]) -> Range<usize> {
        let hardware_len = usize::from(data[HARDWARE_ADDR_LEN]);
        let protocol_len = usize::from(data[PROTOCOL_ADDR_LEN]);

        let start = ADDRS + hardware_len;
        let end = start + protocol_len;
        start..end
    }

    #[inline]
    pub(crate) fn target_hardware_addr(data: &[u8]) -> Range<usize> {
        let hardware_len = usize::from(data[HARDWARE_ADDR_LEN]);
        let protocol_len = usize::from(data[PROTOCOL_ADDR_LEN]);

        let start = ADDRS + hardware_len + protocol_len;
        let end = start + hardware_len;
        start..end
    }

    #[inline]
    pub(crate) fn target_protocol_addr(data: &[u8]) -> Range<usize> {
        let hardware_len = usize::from(data[HARDWARE_ADDR_LEN]);
        let protocol_len = usize::from(data[PROTOCOL_ADDR_LEN]);

        let start = ADDRS + hardware_len + protocol_len + hardware_len;
        let end = start + protocol_len;
        start..end
    }
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
    Invalid(u16),
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
pub const HEADER_LEN: usize = 28;

#[cfg(test)]
mod tests {
    use super::{HardwareType, Operation, Packet};
    use crate::enet::{EtherType, Frame};
    use std::error::Error;
    use std::result::Result;

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
        assert_eq!(
            packet.sender_hardware_addr(),
            &[0xBC, 0xD0, 0x74, 0x0D, 0x9C, 0x12]
        );
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
