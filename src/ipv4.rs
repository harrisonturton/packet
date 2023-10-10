//! IPv4 packet parsing.
//!
//! ## Standards conformance
//!
//! This implementation follows the [RFC
//! 791](https://datatracker.ietf.org/doc/html/rfc791) format as refined by [RFC
//! 2474](https://datatracker.ietf.org/doc/html/rfc2474) and [RFC
//! 3168](https://datatracker.ietf.org/doc/html/rfc3168).
//!
//! Specifically, it re-interpret the original type-of-service field as the
//! modern DSCP and ECN replacements.
//!
//! 1. [Internet protocol (RFC 791)](https://datatracker.ietf.org/doc/html/rfc791)
//! 2. [Definition of the Differentiated Services Field (DS Field) in the IPv4 and IPv6 Headers (RFC 2474)](https://datatracker.ietf.org/doc/html/rfc2474)
//! 3. [The Addition of Explicit Network Congestion Notification (ECN) to IP (RFC 3168)](https://datatracker.ietf.org/doc/html/rfc3168)
use crate::{bitset, offset_read, Error, Result};
use std::{mem::size_of, net::Ipv4Addr};

/// An IPv4 packet.
///
/// This struct wraps a byte slice directly. Nothing is parsed until the field
/// accessor methods are called, like [`Packet::dest`]). Some header values are
/// passed as copies when they're small, but the payload is always referred to
/// by reference.
///
/// See the module documentation for more information.
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct Packet<'a> {
    bytes: &'a [u8],
}

impl<'a> Packet<'a> {
    /// Create a new IP packet.
    ///
    /// # Errors
    ///
    /// Fails when the byte slice is smaller than 16 bytes long, but does not
    /// other validation.
    ///
    /// The field accessor methods on [`Packet`] index directly into the byte
    /// array (an unsafe operation) so this length precondition needs to be
    /// enforced to ensure safety at runtime.
    #[inline]
    #[must_use]
    pub fn new(bytes: &'a [u8]) -> Result<Packet> {
        if bytes.len() >= Self::MIN_HEADER_LEN as usize {
            Ok(Packet { bytes })
        } else {
            Err(Error::CannotParse("packet too small"))
        }
    }

    /// Extract the version.
    #[inline]
    #[must_use]
    pub fn version(&self) -> u8 {
        unsafe { offset_read::<u8>(self.bytes, 0) >> 4 }
    }

    /// Length of the header in bytes. This is different from the raw field
    /// contained in the IP packet, which reports the length in increments of
    /// [`u32`].
    #[inline]
    #[must_use]
    pub fn header_len(&self) -> u8 {
        // u32 has 4 bytes which is below u8::MAX, so it won't be truncated
        #[allow(clippy::cast_possible_truncation)]
        unsafe {
            (offset_read::<u8>(self.bytes, 0) & 0xF) * size_of::<u32>() as u8
        }
    }

    /// Extract the differentiate service code point (DSCP).
    #[inline]
    #[must_use]
    pub fn dscp(&self) -> Dscp {
        Dscp::from(unsafe { offset_read::<u8>(self.bytes, 1) & !0b11 })
    }

    /// Extract the explicit congestion notification field (ECN).
    #[inline]
    #[must_use]
    pub fn ecn(&self) -> Ecn {
        Ecn::from(unsafe { offset_read::<u8>(self.bytes, 1) & 0b11 })
    }

    /// Extract the total length.
    #[inline]
    #[must_use]
    pub fn len(&self) -> u16 {
        u16::from_be_bytes(unsafe { offset_read(self.bytes, 2) })
    }

    /// Extract the identification bits.
    #[inline]
    #[must_use]
    pub fn id(&self) -> u16 {
        u16::from_be_bytes(unsafe { offset_read(self.bytes, 4) })
    }

    /// Extract the flags.
    #[inline]
    #[must_use]
    pub fn flags(&self) -> Flags {
        Flags::new(unsafe { offset_read::<u8>(self.bytes, 6) >> 5 })
    }

    /// Extract the fragment offset.
    #[inline]
    #[must_use]
    pub fn fragment_offset(&self) -> u16 {
        unsafe { u16::from_be(offset_read::<u16>(self.bytes, 6)) & !0xE000 }
    }

    /// Extract the time-to-live (TTL).
    #[inline]
    #[must_use]
    pub fn ttl(&self) -> u8 {
        unsafe { offset_read(self.bytes, 8) }
    }

    /// Extract the protocol.
    #[inline]
    #[must_use]
    pub fn protocol(&self) -> u8 {
        unsafe { offset_read(self.bytes, 9) }
    }

    /// Extract the header checksum.
    #[inline]
    #[must_use]
    pub fn checksum(&self) -> [u8; 2] {
        unsafe { offset_read(self.bytes, 10) }
    }

    /// Extract the source address.
    #[inline]
    #[must_use]
    pub fn source(&self) -> Ipv4Addr {
        Ipv4Addr::from(unsafe { offset_read::<[u8; 4]>(self.bytes, 12) })
    }

    /// Extract the destination address.
    #[inline]
    #[must_use]
    pub fn dest(&self) -> Ipv4Addr {
        Ipv4Addr::from(unsafe { offset_read::<[u8; 4]>(self.bytes, 16) })
    }

    /// Whether the packet has an options field or not
    #[inline]
    #[must_use]
    pub fn has_options(&self) -> bool {
        self.header_len() - Self::MIN_HEADER_LEN > 0
    }

    /// Extract the options. You'll have to parse them yourself.
    #[inline]
    #[must_use]
    pub fn options(&self) -> Option<&[u8]> {
        if !self.has_options() {
            return None;
        }

        let start = Self::MIN_HEADER_LEN;
        let end = start + (self.header_len() - start);
        Some(&self.bytes[start as usize..end as usize])
    }

    /// Extract the payload.
    #[inline]
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.bytes[self.header_len() as usize..]
    }

    /// Minimum length of the header.
    pub const MIN_HEADER_LEN: u8 = 20;
}

/// Strongly-typed wrapper for "differentiated service code point" (DSCP) field
/// in the IP packet.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub struct Dscp {
    traffic_class: u8,
    drop_prob: u8,
}

impl Dscp {
    /// Create a new [`Dscp`] instance.
    #[inline]
    #[must_use]
    pub fn new(traffic_class: u8, drop_prob: u8) -> Self {
        Self {
            traffic_class,
            drop_prob,
        }
    }

    /// Extract the assured forwarding class selector.
    #[inline]
    #[must_use]
    pub fn traffic_class(&self) -> u8 {
        self.traffic_class
    }

    /// Extract the drop preference.
    #[inline]
    #[must_use]
    pub fn drop_probability(&self) -> u8 {
        self.drop_prob
    }
}

impl From<u8> for Dscp {
    fn from(value: u8) -> Self {
        let value = value >> 2; // Strip ECN and align
        let class = u8::from_be_bytes([value >> 3]);
        let drop_prob = u8::from_be_bytes([value & 0b111]);
        Self::new(class, drop_prob)
    }
}

/// Wrapper for the explicit congestion notification (ECN) header.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub struct Ecn {
    congested: bool,
    ecn_capable: bool,
}

impl Ecn {
    /// Create a new [`Ecn`] instance.
    #[inline]
    #[must_use]
    pub fn new(congested: bool, ecn_capable: bool) -> Self {
        Self {
            congested,
            ecn_capable,
        }
    }

    /// Whether the packet experienced significant congestion.
    #[inline]
    #[must_use]
    pub fn congested(&self) -> bool {
        self.congested
    }

    /// Whether the transport supports ECN.
    #[inline]
    #[must_use]
    pub fn ecn_capable(&self) -> bool {
        self.ecn_capable
    }
}

impl From<u8> for Ecn {
    fn from(value: u8) -> Self {
        let congested = bitset(value, 0);
        let ecn_capable = bitset(value, 1);
        Ecn::new(congested, ecn_capable)
    }
}

/// Strongly typed wrapper for the "flags" field on the IP packet.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub struct Flags {
    data: u8,
}

impl Flags {
    /// Create a new [`Flags`] instance.
    #[inline]
    #[must_use]
    pub fn new(data: u8) -> Self {
        Self { data }
    }

    /// True when the control flags indicates the packet should not be
    /// fragmented.
    #[inline]
    #[must_use]
    pub fn do_not_fragment(&self) -> bool {
        bitset(self.data, 0)
    }

    /// True when the control flags indicates the packet contains the last
    /// fragment, false when there are more fragments expected.
    #[inline]
    #[must_use]
    pub fn last_fragment(&self) -> bool {
        !bitset(self.data, 1)
    }
}

#[cfg(test)]
mod tests {
    use super::{Dscp, Ecn, Flags, Packet};
    use crate::ethernet::Frame;
    use std::{error::Error, net::Ipv4Addr};

    // IPv4 packet wrapped in an Ethernet frame, captured using Wireshark.
    pub const FRAME_WITH_PACKET: &'static [u8] = include_bytes!("../resources/ethernet-ipv4.bin");

    // IPv4 with junk options created using scapy
    pub const PACKET_WITH_OPTS: &'static [u8] = include_bytes!("../resources/ipv4-with-opts.bin");

    #[test]
    fn packet_returns_err_when_byte_slice_too_short() -> Result<(), Box<dyn Error>> {
        let frame = vec![0, 0, 0, 0];
        let packet = Packet::new(&frame);
        assert!(packet.is_err());
        Ok(())
    }

    #[test]
    fn packet_has_expected_version() -> Result<(), Box<dyn Error>> {
        let frame = Frame::new(FRAME_WITH_PACKET)?;
        let packet = Packet::new(frame.payload())?;
        assert_eq!(packet.version(), 4);
        Ok(())
    }

    #[test]
    fn packet_has_expected_header_len() -> Result<(), Box<dyn Error>> {
        let frame = Frame::new(FRAME_WITH_PACKET)?;
        let packet = Packet::new(frame.payload())?;
        assert_eq!(packet.header_len(), 20);
        Ok(())
    }

    #[test]
    fn packet_has_expected_dscp() -> Result<(), Box<dyn Error>> {
        let frame = Frame::new(FRAME_WITH_PACKET)?;
        let packet = Packet::new(frame.payload())?;
        assert_eq!(packet.dscp(), Dscp::from(0));
        Ok(())
    }

    #[test]
    fn packet_has_expected_id() -> Result<(), Box<dyn Error>> {
        let frame = Frame::new(FRAME_WITH_PACKET)?;
        let packet = Packet::new(frame.payload())?;
        assert_eq!(packet.id(), 0);
        Ok(())
    }

    #[test]
    fn packet_has_expected_source() -> Result<(), Box<dyn Error>> {
        let frame = Frame::new(FRAME_WITH_PACKET)?;
        let packet = Packet::new(frame.payload())?;
        assert_eq!(packet.source(), Ipv4Addr::new(10, 0, 53, 7));
        Ok(())
    }

    #[test]
    fn packet_has_expected_dest() -> Result<(), Box<dyn Error>> {
        let frame = Frame::new(FRAME_WITH_PACKET)?;
        let packet = Packet::new(frame.payload())?;
        assert_eq!(packet.dest(), Ipv4Addr::new(104, 17, 239, 159));
        Ok(())
    }

    #[test]
    fn packet_has_expected_len() -> Result<(), Box<dyn Error>> {
        let frame = Frame::new(FRAME_WITH_PACKET)?;
        let packet = Packet::new(frame.payload())?;
        assert_eq!(packet.len(), 72);
        Ok(())
    }

    #[test]
    fn packet_has_expected_flags() -> Result<(), Box<dyn Error>> {
        let frame = Frame::new(FRAME_WITH_PACKET)?;
        let packet = Packet::new(frame.payload())?;
        assert_eq!(packet.flags(), Flags::new(0b010));
        Ok(())
    }

    #[test]
    fn packet_has_expected_fragment_offset() -> Result<(), Box<dyn Error>> {
        let frame = Frame::new(FRAME_WITH_PACKET)?;
        let packet = Packet::new(frame.payload())?;
        assert_eq!(packet.fragment_offset(), 0);
        Ok(())
    }

    #[test]
    fn packet_has_expected_checksum() -> Result<(), Box<dyn Error>> {
        let frame = Frame::new(FRAME_WITH_PACKET)?;
        let packet = Packet::new(frame.payload())?;
        assert_eq!(packet.checksum(), [0xA3, 0xED]);
        Ok(())
    }

    #[test]
    fn packet_has_expected_options_when_no_options() -> Result<(), Box<dyn Error>> {
        let frame = Frame::new(FRAME_WITH_PACKET)?;
        let packet = Packet::new(frame.payload())?;
        assert_eq!(packet.options(), None);
        Ok(())
    }

    #[test]
    fn packet_has_expected_has_options_when_no_options() -> Result<(), Box<dyn Error>> {
        let frame = Frame::new(FRAME_WITH_PACKET)?;
        let packet = Packet::new(frame.payload())?;
        assert_eq!(packet.has_options(), false);
        Ok(())
    }

    #[test]
    fn packet_has_expected_options_when_options_exist() -> Result<(), Box<dyn Error>> {
        let packet = Packet::new(PACKET_WITH_OPTS)?;
        assert_eq!(packet.options(), Some([1, 10, 0, 0].as_slice()));
        Ok(())
    }

    #[test]
    fn packet_has_expected_has_options_when_options_exist() -> Result<(), Box<dyn Error>> {
        let packet = Packet::new(PACKET_WITH_OPTS)?;
        assert_eq!(packet.has_options(), true);
        Ok(())
    }

    #[test]
    fn packet_has_expected_ttl() -> Result<(), Box<dyn Error>> {
        let frame = Frame::new(FRAME_WITH_PACKET)?;
        let packet = Packet::new(frame.payload())?;
        assert_eq!(packet.ttl(), 64);
        Ok(())
    }

    #[test]
    fn packet_has_expected_protocol() -> Result<(), Box<dyn Error>> {
        let frame = Frame::new(FRAME_WITH_PACKET)?;
        let packet = Packet::new(frame.payload())?;
        assert_eq!(packet.protocol(), 17);
        Ok(())
    }

    #[test]
    fn packet_has_expected_ecn() -> Result<(), Box<dyn Error>> {
        let frame = Frame::new(FRAME_WITH_PACKET)?;
        let packet = Packet::new(frame.payload())?;
        assert_eq!(packet.ecn(), Ecn::from(0));
        Ok(())
    }

    #[test]
    fn dscp_has_expected_traffic_class() {
        let dscp = Dscp::from(0b0010_0000);
        assert_eq!(dscp.traffic_class(), 1);
    }

    #[test]
    fn dscp_has_expected_drop_probability() {
        let dscp = Dscp::from(0b0000_0100);
        assert_eq!(dscp.drop_probability(), 1);
    }

    #[test]
    fn ecn_has_expected_congestion_flag() {
        let ecn = Ecn::from(0b10);
        assert_eq!(ecn.congested(), false);
    }

    #[test]
    fn ecn_has_expected_ecn_capable_flag() {
        let ecn = Ecn::from(0b10);
        assert_eq!(ecn.ecn_capable(), true);
    }

    #[test]
    fn flags_has_expected_do_not_fragment() {
        let flags = Flags::new(0b10);
        assert_eq!(flags.do_not_fragment(), false);
    }

    #[test]
    fn flags_has_expected_last_fragment_flag() {
        let flags = Flags::new(0b00);
        assert_eq!(flags.last_fragment(), true);
    }
}
