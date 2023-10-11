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
use crate::{bitset, ptr_write, setbits, Error, Result};
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
    /// Create a new IPv4 packet.
    ///
    /// # Errors
    ///
    /// Fails when the byte slice is smaller 20 bytes long, but does no other
    /// validation.
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
            Err(Error::CannotParse("buffer too small"))
        }
    }

    /// Create a new IPv4 packet from a byte array *without* checking that the
    /// array is valid. It is the responsibility of the caller to make sure the
    /// buffer is large enough for the packet.
    #[inline]
    pub unsafe fn new_unchecked(bytes: &'a [u8]) -> Packet {
        Packet { bytes }
    }

    /// Create a new [`PacketBuilder`] that modifies a buffer of bytes in-place.
    ///
    /// # Errors
    ///
    /// See [`PacketBuilder::new`].
    pub fn builder(buf: &'a mut [u8]) -> Result<PacketBuilder<'a>> {
        PacketBuilder::new(buf)
    }

    /// Extract the version.
    #[inline]
    #[must_use]
    pub fn version(&self) -> u8 {
        unsafe { offsets::version(self.bytes).read() >> 4 }
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
            (offsets::header_len(self.bytes).read() & 0b1111) * size_of::<u32>() as u8
        }
    }

    /// Extract the differentiate service code point (DSCP).
    #[inline]
    #[must_use]
    pub fn dscp(&self) -> Dscp {
        Dscp::from(unsafe { offsets::dscp(self.bytes).read() & !0b11 })
    }

    /// Extract the explicit congestion notification field (ECN).
    #[inline]
    #[must_use]
    pub fn ecn(&self) -> Ecn {
        Ecn::from(unsafe { offsets::ecn(self.bytes).read() & 0b11 })
    }

    /// Extract the total length.
    #[inline]
    #[must_use]
    pub fn len(&self) -> u16 {
        u16::from_be(unsafe { offsets::len(self.bytes).read().to_le() })
    }

    /// Extract the identification bits.
    #[inline]
    #[must_use]
    pub fn id(&self) -> u16 {
        u16::from_be(unsafe { offsets::id(self.bytes).read().to_le() })
    }

    /// Extract the flags.
    #[inline]
    #[must_use]
    pub fn flags(&self) -> Flags {
        Flags::from(unsafe { offsets::flags(self.bytes).read() >> 5 })
    }

    /// Extract the fragment offset.
    #[inline]
    #[must_use]
    pub fn fragment_offset(&self) -> u16 {
        unsafe { u16::from_be(offsets::fragment_offset(self.bytes).read()) & !0xE000 }
    }

    /// Extract the time-to-live (TTL).
    #[inline]
    #[must_use]
    pub fn ttl(&self) -> u8 {
        unsafe { offsets::ttl(self.bytes).read() }
    }

    /// Extract the protocol.
    #[inline]
    #[must_use]
    pub fn protocol(&self) -> u8 {
        unsafe { offsets::protocol(self.bytes).read() }
    }

    /// Extract the header checksum.
    #[inline]
    #[must_use]
    pub fn checksum(&self) -> [u8; 2] {
        unsafe { offsets::checksum(self.bytes).read() }
    }

    /// Extract the source address.
    #[inline]
    #[must_use]
    pub fn source(&self) -> Ipv4Addr {
        Ipv4Addr::from(unsafe { offsets::source(self.bytes).read() })
    }

    /// Extract the destination address.
    #[inline]
    #[must_use]
    pub fn dest(&self) -> Ipv4Addr {
        Ipv4Addr::from(unsafe { offsets::dest(self.bytes).read() })
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
        let start = self.header_len() as usize;
        let end = self.len() as usize;
        &self.bytes[start..end]
    }

    /// Minimum length of the header.
    pub const MIN_HEADER_LEN: u8 = 20;
}

/// Builder for constructing [`Packet`] instances.
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct PacketBuilder<'a> {
    bytes: &'a mut [u8],
}

impl<'a> PacketBuilder<'a> {
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
    pub fn new(bytes: &'a mut [u8]) -> Result<Self> {
        if bytes.len() >= Packet::MIN_HEADER_LEN as usize {
            Ok(PacketBuilder { bytes })
        } else {
            Err(Error::CannotParse("buffer too small"))
        }
    }

    /// Set the version.
    #[inline]
    #[must_use]
    pub fn version(self, version: u8) -> Self {
        unsafe {
            let offset = offsets::version_mut(self.bytes);
            let mask = 0b1111_0000;
            let version = version.to_be() << 4;
            let new = setbits(self.bytes[0], version, mask);
            ptr_write(offset, &[new]);
        }
        self
    }

    /// Set the header length in bytes. This is in the native byte order,
    /// representing increments of 32 bits.
    #[inline]
    #[must_use]
    pub fn header_len(self, len: u8) -> Self {
        unsafe {
            let offset = offsets::header_len_mut(self.bytes);
            let mask = 0b0000_1111;
            let new = setbits(self.bytes[0], len, mask);
            ptr_write(offset, &[new]);
        }
        self
    }

    /// Set the [`Dscp`].
    #[inline]
    #[must_use]
    pub fn dscp(self, dscp: Dscp) -> Self {
        unsafe {
            let offset = offsets::dscp_mut(self.bytes);
            let dscp: u8 = dscp.into();
            let curr = offset.read();
            let new = dscp | (curr & 0b11);
            ptr_write(offset, &[new]);
        }
        self
    }

    /// Set the [`Ecn`].
    #[inline]
    #[must_use]
    pub fn ecn(self, ecn: Ecn) -> Self {
        unsafe {
            let offset = offsets::ecn_mut(self.bytes);
            let ecn: u8 = ecn.into();
            let curr = offset.read();
            let new = (curr & !0b11) | ecn;
            ptr_write(offset, &[new]);
        }
        self
    }

    /// Set the total length.
    #[inline]
    #[must_use]
    pub fn len(self, len: u16) -> Self {
        unsafe {
            let offset = offsets::len_mut(self.bytes);
            ptr_write(offset, len.to_be_bytes());
        }
        self
    }

    /// Set the identification bits.
    #[inline]
    #[must_use]
    pub fn id(self, id: u16) -> Self {
        unsafe {
            let id = id.to_be_bytes();
            let offset = offsets::id_mut(self.bytes);
            ptr_write(offset, &id);
        }
        self
    }

    /// Set the flags.
    #[inline]
    #[must_use]
    pub fn flags(self, flags: Flags) -> Self {
        unsafe {
            let offset = offsets::flags_mut(self.bytes);
            let flags: u8 = flags.into();
            let curr = offset.read();
            let new = (flags << 5) | (curr & !0b111 << 5);
            ptr_write(offset, [new]);
        }
        self
    }

    /// Set the fragment offset.
    #[inline]
    #[must_use]
    pub fn fragment_offset(self, fragment_offset: u16) -> Self {
        unsafe {
            let offset = offsets::fragment_offset_mut(self.bytes);
            ptr_write(offset, fragment_offset.to_be_bytes());
        }
        self
    }

    /// Set the ttl.
    #[inline]
    #[must_use]
    pub fn ttl(self, ttl: u8) -> Self {
        unsafe {
            let offset = offsets::ttl_mut(self.bytes);
            ptr_write(offset, [ttl]);
        }
        self
    }

    /// Set the protocol.
    #[inline]
    #[must_use]
    pub fn protocol(self, protocol: u8) -> Self {
        unsafe {
            let offset = offsets::protocol_mut(self.bytes);
            ptr_write(offset, protocol.to_be_bytes());
        }
        self
    }

    /// Set the checksum.
    #[inline]
    #[must_use]
    pub fn checksum(self, checksum: [u8; 2]) -> Self {
        unsafe {
            let offset = offsets::checksum_mut(self.bytes);
            ptr_write(offset, checksum);
        }
        self
    }

    /// Set the source.
    #[inline]
    #[must_use]
    pub fn source(self, source: Ipv4Addr) -> Self {
        unsafe {
            let offset = offsets::source_mut(self.bytes);
            ptr_write(offset, source.octets());
        }
        self
    }

    /// Set the destination.
    #[inline]
    #[must_use]
    pub fn dest(self, dest: Ipv4Addr) -> Self {
        unsafe {
            let offset = offsets::dest_mut(self.bytes);
            ptr_write(offset, dest.octets());
        }
        self
    }

    /// Set the payload.
    #[inline]
    #[must_use]
    pub fn payload<P>(self, payload: P, options_len: isize) -> Self
    where
        P: AsRef<[u8]>,
    {
        unsafe {
            let offset = offsets::payload_mut(self.bytes, options_len);
            ptr_write(offset, payload.as_ref());
        }
        self
    }

    /// Create the [`Packet`].
    ///
    /// # Safety
    ///
    /// This operation calls [`Packet::new_unchecked`] under the hood. This is
    /// safe due to the bounds checking in the [`PacketBuilder::new`]
    /// constructor.
    #[inline]
    #[must_use]
    pub fn build(self) -> Packet<'a> {
        unsafe { Packet::new_unchecked(self.bytes) }
    }
}

mod offsets {
    use crate::{offset_mut_ptr, offset_ptr};

    use super::Packet;

    /// Get a constant pointer to the byte storing the version.
    #[inline]
    #[must_use]
    pub(crate) unsafe fn version(bytes: &[u8]) -> *const u8 {
        offset_ptr(bytes, 0)
    }

    /// Get a mutable pointer to the byte storing the version.
    #[inline]
    #[must_use]
    pub(crate) unsafe fn version_mut(bytes: &mut [u8]) -> *mut u8 {
        offset_mut_ptr(bytes, 0)
    }

    /// Get a constant pointer to the byte storing the header length.
    #[inline]
    #[must_use]
    pub(crate) unsafe fn header_len(bytes: &[u8]) -> *const u8 {
        offset_ptr(bytes, 0)
    }

    /// Get a mutable pointer to the byte storing the header length.
    #[inline]
    #[must_use]
    pub(crate) unsafe fn header_len_mut(bytes: &mut [u8]) -> *mut u8 {
        offset_mut_ptr(bytes, 0)
    }

    /// Get a constant pointer to the byte storing the [`Dscp`].
    #[inline]
    #[must_use]
    pub(crate) unsafe fn dscp(bytes: &[u8]) -> *const u8 {
        offset_ptr(bytes, 1)
    }

    /// Get a mutable pointer to the byte storing the [`Dscp`].
    #[inline]
    #[must_use]
    pub(crate) unsafe fn dscp_mut(bytes: &mut [u8]) -> *mut u8 {
        offset_mut_ptr(bytes, 1)
    }

    /// Get a constant pointer to the byte storing the [`Ecn`].
    #[inline]
    #[must_use]
    pub(crate) unsafe fn ecn(bytes: &[u8]) -> *const u8 {
        offset_ptr(bytes, 1)
    }

    /// Get a mutable pointer to the byte storing the [`Ecn`].
    #[inline]
    #[must_use]
    pub(crate) unsafe fn ecn_mut(bytes: &mut [u8]) -> *mut u8 {
        offset_mut_ptr(bytes, 1)
    }

    /// Get a constant pointer to the bytes storing the total length.
    #[inline]
    #[must_use]
    pub(crate) unsafe fn len(bytes: &[u8]) -> *const u16 {
        offset_ptr(bytes, 2)
    }

    /// Get a mutable pointer to the bytes storing the total length.
    #[inline]
    #[must_use]
    pub(crate) unsafe fn len_mut(bytes: &mut [u8]) -> *mut u16 {
        offset_mut_ptr(bytes, 2)
    }

    /// Get a constant pointer to the byte storing the identification bits.
    #[inline]
    #[must_use]
    pub(crate) unsafe fn id(bytes: &[u8]) -> *const u16 {
        offset_ptr(bytes, 4)
    }

    /// Get a mutable pointer to the byte storing the identification bits.
    #[inline]
    #[must_use]
    pub(crate) unsafe fn id_mut(bytes: &mut [u8]) -> *mut u16 {
        offset_mut_ptr(bytes, 4)
    }

    /// Get a constant pointer to the byte storing the flags.
    #[inline]
    #[must_use]
    pub(crate) unsafe fn flags(bytes: &[u8]) -> *const u8 {
        offset_ptr(bytes, 6)
    }

    /// Get a mutable pointer to the byte storing the flags.
    #[inline]
    #[must_use]
    pub(crate) unsafe fn flags_mut(bytes: &mut [u8]) -> *mut u8 {
        offset_mut_ptr(bytes, 6)
    }

    /// Get a constant pointer to the byte storing the fragment offset.
    #[inline]
    #[must_use]
    pub(crate) unsafe fn fragment_offset(bytes: &[u8]) -> *const u16 {
        offset_ptr(bytes, 6)
    }

    /// Get a mutable pointer to the byte storing the fragment offset.
    #[inline]
    #[must_use]
    pub(crate) unsafe fn fragment_offset_mut(bytes: &mut [u8]) -> *mut u16 {
        offset_mut_ptr(bytes, 6)
    }

    /// Get a constant pointer to the byte storing the ttl.
    #[inline]
    #[must_use]
    pub(crate) unsafe fn ttl(bytes: &[u8]) -> *const u8 {
        offset_ptr(bytes, 8)
    }

    /// Get a mutable pointer to the byte storing the ttl.
    #[inline]
    #[must_use]
    pub(crate) unsafe fn ttl_mut(bytes: &mut [u8]) -> *mut u8 {
        offset_mut_ptr(bytes, 8)
    }

    /// Get a constant pointer to the byte storing the protocol.
    #[inline]
    #[must_use]
    pub(crate) unsafe fn protocol(bytes: &[u8]) -> *const u8 {
        offset_ptr(bytes, 9)
    }

    /// Get a mutable pointer to the byte storing the protocol.
    #[inline]
    #[must_use]
    pub(crate) unsafe fn protocol_mut(bytes: &mut [u8]) -> *mut u8 {
        offset_mut_ptr(bytes, 9)
    }

    /// Get a constant pointer to the byte storing the checksum.
    #[inline]
    #[must_use]
    pub(crate) unsafe fn checksum(bytes: &[u8]) -> *const [u8; 2] {
        offset_ptr(bytes, 10)
    }

    /// Get a mutable pointer to the byte storing the checksum.
    #[inline]
    #[must_use]
    pub(crate) unsafe fn checksum_mut(bytes: &mut [u8]) -> *mut u8 {
        offset_mut_ptr(bytes, 10)
    }

    /// Get a constant pointer to the byte storing the source.
    #[inline]
    #[must_use]
    pub(crate) unsafe fn source(bytes: &[u8]) -> *const [u8; 4] {
        offset_ptr(bytes, 12)
    }

    /// Get a mutable pointer to the byte storing the source.
    #[inline]
    #[must_use]
    pub(crate) unsafe fn source_mut(bytes: &mut [u8]) -> *mut [u8; 4] {
        offset_mut_ptr(bytes, 12)
    }

    /// Get a constant pointer to the byte storing the dest.
    #[inline]
    #[must_use]
    pub(crate) unsafe fn dest(bytes: &[u8]) -> *const [u8; 4] {
        offset_ptr(bytes, 16)
    }

    /// Get a mutable pointer to the byte storing the dest.
    #[inline]
    #[must_use]
    pub(crate) unsafe fn dest_mut(bytes: &mut [u8]) -> *mut [u8; 4] {
        offset_mut_ptr(bytes, 16)
    }

    /// Get a pointer to the byte where the payload begins.
    #[inline]
    #[must_use]
    pub(crate) unsafe fn payload(bytes: &[u8], options_len: isize) -> *const u8 {
        offset_ptr(bytes, Packet::MIN_HEADER_LEN as isize + options_len)
    }

    /// Get a mutable pointer to the byte where the payload begins.
    #[inline]
    #[must_use]
    pub(crate) unsafe fn payload_mut(bytes: &mut [u8], options_len: isize) -> *mut u8 {
        offset_mut_ptr(bytes, Packet::MIN_HEADER_LEN as isize + options_len)
    }
}

/// Strongly-typed wrapper for "differentiated service code point" (DSCP) field
/// in the IP packet.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub struct Dscp {
    class: u8,
    drop: u8,
}

impl Dscp {
    /// Create a new [`Dscp`] instance. Note that the class and drop probably
    /// cannot be larger than 7, since they are represented using 3 bits each.
    #[inline]
    #[must_use]
    pub fn new(class: u8, drop: u8) -> Result<Self> {
        if class <= 7 && drop <= 7 {
            Ok(Self { class, drop })
        } else {
            Err(Error::CannotParse(
                "traffic class and drop probability cannot be greater than 7",
            ))
        }
    }

    /// Extract the assured forwarding class selector.
    #[inline]
    #[must_use]
    pub fn traffic_class(&self) -> u8 {
        self.class
    }

    /// Extract the drop probability.
    #[inline]
    #[must_use]
    pub fn drop_probability(&self) -> u8 {
        self.drop
    }
}

impl From<u8> for Dscp {
    fn from(value: u8) -> Self {
        let value = value >> 2; // Strip ECN
        let class = u8::from_be(value >> 3);
        let drop = u8::from_be(value & 0b111);
        Dscp { class, drop }
    }
}

impl From<Dscp> for u8 {
    fn from(dscp: Dscp) -> Self {
        let class = dscp.traffic_class().to_be();
        let drop = dscp.drop_probability().to_be();
        (class << 5) | (drop << 2)
    }
}

/// Wrapper for the explicit congestion notification (ECN) header.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub struct Ecn {
    congested: bool,
    capable: bool,
}

impl Ecn {
    /// Create a new [`Ecn`] instance.
    #[inline]
    #[must_use]
    pub fn new(congested: bool, capable: bool) -> Self {
        Self { congested, capable }
    }

    /// Whether the packet experienced significant congestion.
    #[inline]
    #[must_use]
    pub fn congested(&self) -> bool {
        self.congested
    }

    /// Whether the transport supports ECN, i.e. is "ECN capable".
    #[inline]
    #[must_use]
    pub fn capable(&self) -> bool {
        self.capable
    }
}

impl From<u8> for Ecn {
    fn from(value: u8) -> Self {
        let congested = bitset(value, 1);
        let capable = bitset(value, 0);
        Ecn::new(congested, capable)
    }
}

impl From<Ecn> for u8 {
    fn from(ecn: Ecn) -> Self {
        let congested = ecn.congested() as u8;
        let capable = ecn.capable() as u8;
        (congested << 1) | capable
    }
}

/// Strongly typed wrapper for the "flags" field on the IP packet.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub struct Flags {
    do_not_fragment: bool,
    more_fragments: bool,
}

impl Flags {
    /// Create a new [`Flags`] instance.
    #[inline]
    #[must_use]
    pub fn new(do_not_fragment: bool, more_fragments: bool) -> Self {
        Self {
            do_not_fragment,
            more_fragments,
        }
    }

    /// True when the control flags indicates the packet should not be
    /// fragmented.
    #[inline]
    #[must_use]
    pub fn do_not_fragment(&self) -> bool {
        self.do_not_fragment
    }

    /// True when the control flags indicates the packet contains the last
    /// fragment, false when there are more fragments expected.
    #[inline]
    #[must_use]
    pub fn more_fragments(&self) -> bool {
        self.more_fragments
    }
}

impl From<u8> for Flags {
    /// Parses the flags field from a three-bit value in the byte. It assumes
    /// that the value has been right-aligned (i.e. the fragment offset field
    /// has been stripped from the byte).
    fn from(value: u8) -> Self {
        let do_not_fragment = bitset(value, 1);
        let more_fragments = bitset(value, 0);
        Flags::new(do_not_fragment, more_fragments)
    }
}

impl From<Flags> for u8 {
    /// Returns the three-bit flags field, but is not properly aligned to the
    /// byte boundary. If this needs to be combined with the fragment offset,
    /// this value will needed to be shifted.
    fn from(flags: Flags) -> Self {
        let do_not_fragment = flags.do_not_fragment as u8;
        let more_fragments = flags.more_fragments as u8;
        (do_not_fragment << 1) | more_fragments
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
        assert_eq!(packet.flags(), Flags::from(0b010));
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
    fn packet_builder_has_expected_version() -> Result<(), Box<dyn Error>> {
        let buf = &mut [0; Packet::MIN_HEADER_LEN as usize];
        let packet = Packet::builder(buf)?.version(12).build();
        assert_eq!(packet.version(), 12);
        Ok(())
    }

    #[test]
    fn packet_builder_has_expected_header_len() -> Result<(), Box<dyn Error>> {
        let buf = &mut [0; Packet::MIN_HEADER_LEN as usize];
        let packet = Packet::builder(buf)?.header_len(12).build();
        assert_eq!(packet.header_len(), 48);
        Ok(())
    }

    #[test]
    fn packet_builder_has_expected_dscp() -> Result<(), Box<dyn Error>> {
        let buf = &mut [0; Packet::MIN_HEADER_LEN as usize];
        let dscp = Dscp::new(5, 7)?;
        let packet = Packet::builder(buf)?.dscp(dscp).build();
        assert_eq!(packet.dscp(), dscp);
        Ok(())
    }

    #[test]
    fn packet_builder_has_expected_ecn() -> Result<(), Box<dyn Error>> {
        let buf = &mut [0; Packet::MIN_HEADER_LEN as usize];
        let ecn = Ecn::new(true, false);
        let packet = Packet::builder(buf)?.ecn(ecn).build();
        assert_eq!(packet.ecn(), ecn);
        Ok(())
    }

    #[test]
    fn packet_builder_has_expected_total_len() -> Result<(), Box<dyn Error>> {
        let buf = &mut [0; Packet::MIN_HEADER_LEN as usize];
        let packet = Packet::builder(buf)?.len(20).build();
        assert_eq!(packet.len(), 20);
        Ok(())
    }

    #[test]
    fn packet_builder_has_expected_id() -> Result<(), Box<dyn Error>> {
        let buf = &mut [0; Packet::MIN_HEADER_LEN as usize];
        let packet = Packet::builder(buf)?.id(17).build();
        assert_eq!(packet.id(), 17);
        Ok(())
    }

    #[test]
    fn packet_builder_has_expected_flags() -> Result<(), Box<dyn Error>> {
        let buf = &mut [0; Packet::MIN_HEADER_LEN as usize];
        let flags = Flags::new(true, false);
        let packet = Packet::builder(buf)?.flags(flags).build();
        assert_eq!(packet.flags(), flags);
        Ok(())
    }

    #[test]
    fn packet_builder_has_expected_fragment_offset() -> Result<(), Box<dyn Error>> {
        let buf = &mut [0; Packet::MIN_HEADER_LEN as usize];
        let packet = Packet::builder(buf)?.fragment_offset(12).build();
        assert_eq!(packet.fragment_offset(), 12);
        Ok(())
    }

    #[test]
    fn packet_builder_has_expected_ttl() -> Result<(), Box<dyn Error>> {
        let buf = &mut [0; Packet::MIN_HEADER_LEN as usize];
        let packet = Packet::builder(buf)?.ttl(12).build();
        assert_eq!(packet.ttl(), 12);
        Ok(())
    }

    #[test]
    fn packet_builder_has_expected_protocol() -> Result<(), Box<dyn Error>> {
        let buf = &mut [0; Packet::MIN_HEADER_LEN as usize];
        let packet = Packet::builder(buf)?.protocol(12).build();
        assert_eq!(packet.protocol(), 12);
        Ok(())
    }

    #[test]
    fn packet_builder_has_expected_checksum() -> Result<(), Box<dyn Error>> {
        let buf = &mut [0; Packet::MIN_HEADER_LEN as usize];
        let packet = Packet::builder(buf)?.checksum([0xA, 0xF]).build();
        assert_eq!(packet.checksum(), [0xA, 0xF]);
        Ok(())
    }

    #[test]
    fn packet_builder_has_expected_source() -> Result<(), Box<dyn Error>> {
        let buf = &mut [0; Packet::MIN_HEADER_LEN as usize];
        let addr = Ipv4Addr::new(127, 0, 0, 1);
        let packet = Packet::builder(buf)?.source(addr).build();
        assert_eq!(packet.source(), addr);
        Ok(())
    }

    #[test]
    fn packet_builder_has_expected_dest() -> Result<(), Box<dyn Error>> {
        let buf = &mut [0; Packet::MIN_HEADER_LEN as usize];
        let addr = Ipv4Addr::new(127, 0, 0, 1);
        let packet = Packet::builder(buf)?.dest(addr).build();
        assert_eq!(packet.dest(), addr);
        Ok(())
    }

    #[test]
    fn packet_builder_has_expected_payload() -> Result<(), Box<dyn Error>> {
        let buf = &mut [0; Packet::MIN_HEADER_LEN as usize + 4];
        let payload = [1, 2, 3, 4];
        let packet = Packet::builder(buf)?
            .header_len(5)
            .len(24)
            .payload(payload, 0)
            .build();
        assert_eq!(packet.payload(), payload);
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
    fn dscp_from_u8_gives_expected_value() -> Result<(), Box<dyn Error>> {
        let dscp = Dscp::from(0b11111101);
        assert_eq!(dscp, Dscp::new(7, 7)?);
        Ok(())
    }

    #[test]
    fn dscp_into_u8_gives_expected_value() {
        let octet = 0b11111100;
        let dscp: u8 = Dscp::from(octet).into();
        assert_eq!(dscp, octet);
    }

    #[test]
    fn ecn_has_expected_congestion_flag() {
        let ecn = Ecn::from(0b10);
        assert_eq!(ecn.congested(), true);
    }

    #[test]
    fn ecn_has_expected_ecn_capable_flag() {
        let ecn = Ecn::from(0b01);
        assert_eq!(ecn.capable(), true);
    }

    #[test]
    fn ecn_from_u8_gives_expected_value() {
        let ecn = Ecn::from(0b11111110);
        assert_eq!(ecn, Ecn::new(true, false));
    }

    #[test]
    fn ecn_into_u8_gives_expected_value() {
        let ecn: u8 = Ecn::new(true, false).into();
        assert_eq!(ecn, 0b10);
    }

    #[test]
    fn flags_from_u8_has_expected_do_not_fragment() {
        let flags = Flags::from(0b010);
        assert_eq!(flags.do_not_fragment(), true);
    }

    #[test]
    fn flags_from_u8_has_expected_more_fragments() {
        let flags = Flags::from(0b001);
        assert_eq!(flags.more_fragments(), true);
    }
}
