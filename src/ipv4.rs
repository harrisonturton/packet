use crate::{bitset, offset_read, Error, Result};

/// An IP packet as defined by RFC 791 and refined by RFC 2474 and RFC 3168. The
/// payload is in network byte order.
///
/// This struct wraps a byte array directly. Nothing is parsed until the field
/// accessor methods (e.g. [`dest`]) are called. Some header values are passed
/// as copies when they're small, but the payload is always referred to by
/// reference.
///
/// # Relevant RFCs
/// 1. [Internet protocol (RFC 791)](https://datatracker.ietf.org/doc/html/rfc791)
/// 2. [Definition of the Differentiated Services Field (DS Field) in the IPv4 and IPv6 Headers (RFC 2474)](https://datatracker.ietf.org/doc/html/rfc2474)
/// 3. [(RFC 3168)]()
#[derive(Debug, PartialEq, Eq, Clone)]
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
        if bytes.len() < MIN_HEADER_LEN {
            return Err(Error::InvalidArgument("packet too small"));
        }
        Ok(Packet { bytes })
    }

    /// Extract the version.
    #[inline]
    #[must_use]
    pub fn version(&self) -> u8 {
        unsafe { offset_read::<u8>(self.bytes, 0) >> 4 }
    }

    /// Extract the header length.
    #[inline]
    #[must_use]
    pub fn header_len(&self) -> u8 {
        unsafe { offset_read::<u8>(self.bytes, 0) & 0xF }
    }

    /// Extract the differentiate service code point (DSCP).
    #[inline]
    #[must_use]
    pub fn dscp(&self) -> Dscp {
        Dscp::new(unsafe { offset_read::<u8>(self.bytes, 1) & !0b11 })
    }

    /// Extract the explicit congestion notification field (ECN).
    #[inline]
    #[must_use]
    pub fn tos<T>(&self) -> Ecn {
        Ecn::new(unsafe { offset_read::<u8>(self.bytes, 1) & 0b11 })
    }

    /// Extract the explicit congestion notification field (ECN).
    #[inline]
    #[must_use]
    pub fn ecn(&self) -> Ecn {
        Ecn::new(unsafe { offset_read::<u8>(self.bytes, 1) & 0b11 })
    }

    /// Extract the total length.
    #[inline]
    #[must_use]
    pub fn total_length(&self) -> u16 {
        u16::from_be_bytes(unsafe { offset_read(self.bytes, 2) })
    }

    /// Extract the identification.
    #[inline]
    #[must_use]
    pub fn ident(&self) -> u16 {
        u16::from_be_bytes(unsafe { offset_read(self.bytes, 4) })
    }

    /// Extract the flags.
    #[inline]
    #[must_use]
    pub fn flags(&self) -> u8 {
        unsafe { offset_read::<u8>(self.bytes, 6) >> 5 }
    }

    /// Extract the fragment offset.
    #[inline]
    #[must_use]
    pub fn fragment_offset(&self) -> u16 {
        unsafe { u16::from_be(offset_read::<u16>(self.bytes, 6) & !0x7) }
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
    pub fn header_checksum(&self) -> [u8; 2] {
        unsafe { offset_read(self.bytes, 10) }
    }

    /// Extract the source address.
    #[inline]
    #[must_use]
    pub fn source(&self) -> [u8; 4] {
        unsafe { offset_read(self.bytes, 12) }
    }

    /// Extract the destination address.
    #[inline]
    #[must_use]
    pub fn dest(&self) -> [u8; 4] {
        unsafe { offset_read(self.bytes, 16) }
    }
}

/// Strongly-typed wrapper for "differentiated service code point" (DSCP) field
/// in the IP packet.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Dscp {
    data: u8,
}

impl Dscp {
    /// Create a new [`Dscp`] instance.
    #[inline]
    #[must_use]
    pub fn new(data: u8) -> Self {
        Self { data }
    }

    /// Extract the assured forwarding class selector.
    #[inline]
    #[must_use]
    pub fn forwarding_class(&self) -> u8 {
        u8::from_be_bytes([self.data >> 3])
    }

    /// Extract the drop preference.
    #[inline]
    #[must_use]
    pub fn drop_preference(&self) -> u8 {
        u8::from_be_bytes([(self.data & !0b111001) >> 1])
    }
}

/// Strongly typed wrapper for the explicit congestion notification (ECN) field
/// in the IP header.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Ecn {
    data: u8,
}

impl Ecn {
    /// Create a new [`Ecn`] instance.
    #[inline]
    #[must_use]
    pub fn new(data: u8) -> Self {
        Self { data }
    }

    /// Whether the packet experienced significant congestion.
    #[inline]
    #[must_use]
    pub fn congested(&self) -> bool {
        bitset(self.data, 0)
    }

    /// Whether the transport supports ECN.
    #[inline]
    #[must_use]
    pub fn ecn_capable(&self) -> bool {
        bitset(self.data, 1)
    }
}

// Strongly typed wrapped for the "flags" field on the IP packet.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct ControlFlags {
    data: u8,
}

impl ControlFlags {
    /// Create a new [`ControlFlags`] instance.
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

// Minimum length of an IP packet header.
const MIN_HEADER_LEN: usize = 20;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_has_expected_version() {
        let dscp = Dscp::new(0b001010);
        assert_eq!(dscp.forwarding_class(), 1);
    }

    #[test]
    fn dscp_has_expected_forwarding_class() {
        let dscp = Dscp::new(0b001010);
        assert_eq!(dscp.forwarding_class(), 1);
    }

    #[test]
    fn dscp_has_expected_drop_preference() {
        let dscp = Dscp::new(0b001010);
        assert_eq!(dscp.drop_preference(), 1);
    }

    #[test]
    fn ecn_has_expected_congestion_flag() {
        let ecn = Ecn::new(0b10);
        assert_eq!(ecn.congested(), false);
    }

    #[test]
    fn ecn_has_expected_ecn_capable_flag() {
        let ecn = Ecn::new(0b10);
        assert_eq!(ecn.ecn_capable(), true);
    }

    #[test]
    fn ecn_has_expected_drop_preference() {
        let dscp = Dscp::new(0b001010);
        assert_eq!(dscp.drop_preference(), 1);
    }

    #[test]
    fn control_flags_has_expected_do_not_fragment() {
        let flags = ControlFlags::new(0b10);
        assert_eq!(flags.do_not_fragment(), false);
    }

    #[test]
    fn control_flags_has_expected_last_fragment_flag() {
        let flags = ControlFlags::new(0b00);
        assert_eq!(flags.last_fragment(), true);
    }
}
