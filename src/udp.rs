//! UDP datagram parsing.
//!
//! ## Standards conformance
//!
//! Follows [RFC 768](https://www.ietf.org/rfc/rfc768.txt).
use crate::{offset_read, Error, Result};

/// A UDP datagram.
///
/// See the module documentation for more information.
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct Datagram<'a> {
    bytes: &'a [u8],
}

impl<'a> Datagram<'a> {
    /// Create a new [`Datagram`] instance.
    ///
    /// # Errors
    ///
    /// Fails when the byte slice is shorter than 8 bytes long.
    #[inline]
    #[must_use]
    pub fn new(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() >= MIN_DATAGRAM_LEN {
            Ok(Self { bytes })
        } else {
            Err(Error::CannotParse("datagram too small"))
        }
    }

    /// Get the source port.
    #[inline]
    #[must_use]
    pub fn source(&self) -> u16 {
        u16::from_be_bytes(unsafe { offset_read(self.bytes, 0) })
    }

    /// Get the destination port.
    #[inline]
    #[must_use]
    pub fn dest(&self) -> u16 {
        u16::from_be_bytes(unsafe { offset_read(self.bytes, 2) })
    }

    /// Get the length of the payload.
    #[inline]
    #[must_use]
    pub fn len(&self) -> u16 {
        u16::from_be_bytes(unsafe { offset_read(self.bytes, 4) })
    }

    /// Get the checksum.
    #[inline]
    #[must_use]
    pub fn checksum(&self) -> [u8; 2] {
        unsafe { offset_read(self.bytes, 6) }
    }

    /// Get the payload.
    #[inline]
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.bytes[8..]
    }
}

// Size of the UDP header in bytes
const MIN_DATAGRAM_LEN: usize = 8;

#[cfg(test)]
mod tests {
    use super::Datagram;
    use crate::{ethernet::Frame, ipv4::Packet};
    use std::error::Error;

    // IPv4 packet wrapped in an Ethernet frame, captured using Wireshark.
    pub const ETH_IPV4_UDP: &'static [u8] = include_bytes!("../resources/ethernet-ipv4.bin");

    #[test]
    fn datagram_returns_err_when_byte_slice_too_short() {
        let datagram = Datagram::new(&[0, 0, 0, 0]);
        assert!(datagram.is_err());
    }

    #[test]
    fn datagram_source_returns_expected_addr() -> Result<(), Box<dyn Error>> {
        let frame = Frame::new(ETH_IPV4_UDP)?;
        let packet = Packet::new(frame.payload())?;
        let datagram = Datagram::new(packet.payload())?;
        assert_eq!(datagram.source(), 52152);
        Ok(())
    }

    #[test]
    fn datagram_dest_returns_expected_addr() -> Result<(), Box<dyn Error>> {
        let frame = Frame::new(ETH_IPV4_UDP)?;
        let packet = Packet::new(frame.payload())?;
        let datagram = Datagram::new(packet.payload())?;
        assert_eq!(datagram.dest(), 443);
        Ok(())
    }

    #[test]
    fn datagram_len_returns_expected_len() -> Result<(), Box<dyn Error>> {
        let frame = Frame::new(ETH_IPV4_UDP)?;
        let packet = Packet::new(frame.payload())?;
        let datagram = Datagram::new(packet.payload())?;
        assert_eq!(datagram.len(), 52);
        Ok(())
    }

    #[test]
    fn datagram_checksum_returns_expected_checksum() -> Result<(), Box<dyn Error>> {
        let frame = Frame::new(ETH_IPV4_UDP)?;
        let packet = Packet::new(frame.payload())?;
        let datagram = Datagram::new(packet.payload())?;
        assert_eq!(datagram.checksum(), [0xDA, 0xA7]);
        Ok(())
    }

    #[test]
    fn datagram_payload_len_matches_datagram_len() -> Result<(), Box<dyn Error>> {
        let frame = Frame::new(ETH_IPV4_UDP)?;
        let packet = Packet::new(frame.payload())?;
        let datagram = Datagram::new(packet.payload())?;
        assert_eq!(datagram.payload().len(), 44);
        Ok(())
    }
}
