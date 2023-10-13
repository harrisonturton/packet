//! Read and write IPv4 packets.
//!
//! ## Standards conformance
//!
//! This implementation uses the modern DSCP and ECN interpretation of the
//! type-of-service field. Specifically, it follows the [RFC
//! 791](https://datatracker.ietf.org/doc/html/rfc791) format as refined by [RFC
//! 2474](https://datatracker.ietf.org/doc/html/rfc2474) and [RFC
//! 3168](https://datatracker.ietf.org/doc/html/rfc3168).
//!
//! 1. [Internet protocol (RFC 791)](https://datatracker.ietf.org/doc/html/rfc791)
//! 2. [Definition of the Differentiated Services Field (DS Field) in the IPv4 and IPv6 Headers (RFC 2474)](https://datatracker.ietf.org/doc/html/rfc2474)
//! 3. [The Addition of Explicit Network Congestion Notification (ECN) to IP (RFC 3168)](https://datatracker.ietf.org/doc/html/rfc3168)
use byteorder::{ByteOrder, NetworkEndian};

use crate::{bitset, setbits, Error, Result};
use std::{io::Read, mem::size_of, net::Ipv4Addr};

/// An IPv4 packet.
///
/// This struct wraps a byte slice directly. Nothing is parsed until the field
/// accessor methods are called, like [`Packet::dest`]. Some header values are
/// passed as copies when they're small, but the payload is always referred to
/// by reference.
///
/// See the module documentation for more information.
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct Packet<B: AsRef<[u8]>> {
    buf: B,
}

impl<B: AsRef<[u8]>> Packet<B> {
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
    pub fn new(buf: B) -> Result<Self> {
        if buf.as_ref().len() >= MIN_HEADER_LEN as usize {
            Ok(Self { buf })
        } else {
            Err(Error::CannotParse("buffer too small"))
        }
    }

    /// Create a new IPv4 packet from a byte array *without* checking that the
    /// array is valid. It is the responsibility of the caller to make sure the
    /// buffer is large enough for the packet.
    ///
    /// # Safety
    ///
    /// The buffer must be large enough to contain the IPv4 packet header and
    /// the payload. This means it must be at least 20 bytes long, and longer if
    /// any packet options or payload is desired.
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

    /// Extract the version.
    #[inline]
    #[must_use]
    pub fn version(&self) -> u8 {
        let data = self.buf.as_ref();
        data[offsets::VERSION] >> 4
    }

    /// Length of the header in bytes. This is different from the raw field
    /// contained in the IP packet, which reports the length in increments of
    /// [`u32`].
    #[inline]
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn header_len(&self) -> u8 {
        let data = self.buf.as_ref();
        (data[offsets::HEADER_LEN] & 0b1111) * size_of::<u32>() as u8
    }

    /// Extract the differentiated service code point (DSCP).
    #[inline]
    #[must_use]
    pub fn dscp(&self) -> Dscp {
        let data = self.buf.as_ref();
        Dscp::from(data[offsets::DSCP] & !0b11)
    }

    /// Extract the explicit congestion notification field (ECN).
    #[inline]
    #[must_use]
    pub fn ecn(&self) -> Ecn {
        let data = self.buf.as_ref();
        Ecn::from(data[offsets::ECN] & 0b11)
    }

    /// Extract the total length.
    #[inline]
    #[must_use]
    pub fn len(&self) -> u16 {
        let data = self.buf.as_ref();
        NetworkEndian::read_u16(&data[offsets::LEN])
    }

    /// Extract the identification bits.
    #[inline]
    #[must_use]
    pub fn id(&self) -> u16 {
        let data = self.buf.as_ref();
        NetworkEndian::read_u16(&data[offsets::IDENT])
    }

    /// Extract the flags.
    #[inline]
    #[must_use]
    pub fn flags(&self) -> Flags {
        let data = self.buf.as_ref();
        Flags::from(data[offsets::FLAGS] >> 5)
    }

    /// Extract the fragment offset.
    #[inline]
    #[must_use]
    pub fn fragment_offset(&self) -> u16 {
        let data = self.buf.as_ref();
        NetworkEndian::read_u16(&data[offsets::FRAGMENT_OFFSET]) & !0xE000
    }

    /// Extract the time-to-live (TTL).
    #[inline]
    #[must_use]
    pub fn ttl(&self) -> u8 {
        let data = self.buf.as_ref();
        data[offsets::TTL]
    }

    /// Extract the protocol.
    #[inline]
    #[must_use]
    pub fn protocol(&self) -> u8 {
        let data = self.buf.as_ref();
        data[offsets::PROTOCOL]
    }

    /// Extract the header checksum.
    #[inline]
    #[must_use]
    pub fn checksum(&self) -> u16 {
        let data = self.buf.as_ref();
        NetworkEndian::read_u16(&data[offsets::CHECKSUM])
    }

    /// Extract the source address.
    ///
    /// # Panics
    ///
    /// Panics if there are not enough bytes to fulfil the read.
    #[inline]
    #[must_use]
    pub fn source(&self) -> Ipv4Addr {
        let data = self.buf.as_ref();
        let octets: [u8; 4] = data[offsets::SOURCE].try_into().unwrap();
        Ipv4Addr::from(octets)
    }

    /// Extract the destination address.
    ///
    /// # Panics
    ///
    /// Panics if there are not enough bytes to fulfil the read.
    #[inline]
    #[must_use]
    pub fn dest(&self) -> Ipv4Addr {
        let data = self.buf.as_ref();
        let octets: [u8; 4] = data[offsets::DEST].try_into().unwrap();
        Ipv4Addr::from(octets)
    }

    /// Whether the packet has an options field or not
    #[inline]
    #[must_use]
    pub fn has_options(&self) -> bool {
        self.header_len() - MIN_HEADER_LEN > 0
    }

    /// Extract the options. You'll have to parse them yourself.
    #[inline]
    #[must_use]
    pub fn options(&self) -> Option<&[u8]> {
        if !self.has_options() {
            return None;
        }

        let start = MIN_HEADER_LEN;
        let end = start + (self.header_len() - start);
        let data = self.buf.as_ref();
        Some(&data[start as usize..end as usize])
    }

    /// Extract the payload.
    #[inline]
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        let start = self.header_len() as usize;
        let end = self.len() as usize;
        let data = self.buf.as_ref();
        &data[start..end]
    }
}

/// Minimum length of the header.
pub const MIN_HEADER_LEN: u8 = 20;

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
        if buf.as_ref().len() >= MIN_HEADER_LEN as usize {
            Ok(PacketBuilder { buf })
        } else {
            Err(Error::CannotParse("buffer too small"))
        }
    }

    /// Set the version.
    #[inline]
    #[must_use]
    pub fn version(mut self, version: u8) -> Self {
        let data = self.buf.as_mut();
        let version = version.to_be() << 4;
        let new = setbits(data[offsets::VERSION], version, 0b1111_0000);
        data[offsets::VERSION] = new;
        self
    }

    /// Set the header length in bytes. This is in the native byte order,
    /// representing increments of 32 bits.
    #[inline]
    #[must_use]
    pub fn header_len(mut self, len: u8) -> Self {
        let data = self.buf.as_mut();
        let mask = 0b0000_1111;
        let new = setbits(data[offsets::VERSION], len, mask);
        data[offsets::VERSION] = new;
        self
    }

    /// Set the [`Dscp`].
    #[inline]
    #[must_use]
    pub fn dscp(mut self, dscp: Dscp) -> Self {
        let data = self.buf.as_mut();
        let dscp: u8 = dscp.into();
        let curr = data[offsets::DSCP];
        data[offsets::DSCP] = dscp | (curr & 0b11);
        self
    }

    /// Set the [`Ecn`].
    #[inline]
    #[must_use]
    pub fn ecn(mut self, ecn: Ecn) -> Self {
        let data = self.buf.as_mut();
        let ecn: u8 = ecn.into();
        let curr = data[offsets::ECN];
        data[offsets::ECN] = (curr & !0b11) | ecn;
        self
    }

    /// Set the total length.
    #[inline]
    #[must_use]
    pub fn len(mut self, len: u16) -> Self {
        let data = self.buf.as_mut();
        NetworkEndian::write_u16(&mut data[offsets::LEN], len);
        self
    }

    /// Set the identification bits.
    #[inline]
    #[must_use]
    pub fn id(mut self, id: u16) -> Self {
        let data = self.buf.as_mut();
        NetworkEndian::write_u16(&mut data[offsets::IDENT], id);
        self
    }

    /// Set the flags.
    #[inline]
    #[must_use]
    pub fn flags(mut self, flags: Flags) -> Self {
        let data = self.buf.as_mut();
        let flags: u8 = flags.into();
        let curr = data[offsets::FLAGS];
        data[offsets::FLAGS] = (flags << 5) | (curr & !0b111 << 5);
        self
    }

    /// Set the fragment offset.
    #[inline]
    #[must_use]
    pub fn fragment_offset(mut self, fragment_offset: u16) -> Self {
        let data = self.buf.as_mut();
        NetworkEndian::write_u16(&mut data[offsets::FRAGMENT_OFFSET], fragment_offset);
        self
    }

    /// Set the ttl.
    #[inline]
    #[must_use]
    pub fn ttl(mut self, ttl: u8) -> Self {
        let data = self.buf.as_mut();
        data[offsets::TTL] = ttl;
        self
    }

    /// Set the protocol.
    #[inline]
    #[must_use]
    pub fn protocol(mut self, protocol: u8) -> Self {
        let data = self.buf.as_mut();
        data[offsets::PROTOCOL] = protocol;
        self
    }

    /// Set the checksum.
    #[inline]
    #[must_use]
    pub fn checksum(mut self, checksum: u16) -> Self {
        let data = self.buf.as_mut();
        NetworkEndian::write_u16(&mut data[offsets::CHECKSUM], checksum);
        self
    }

    /// Set the source.
    #[inline]
    #[must_use]
    pub fn source(mut self, source: Ipv4Addr) -> Self {
        let data = self.buf.as_mut();
        let octets = source.octets();
        data[offsets::SOURCE].copy_from_slice(&octets);
        self
    }

    /// Set the destination.
    #[inline]
    #[must_use]
    pub fn dest(mut self, dest: Ipv4Addr) -> Self {
        let data = self.buf.as_mut();
        let octets = dest.octets();
        data[offsets::DEST].copy_from_slice(&octets);
        self
    }

    /// Set the payload.
    ///
    /// # Errors
    ///
    /// Returns an error when [`Read`](std::io::Read) returns any error other
    /// than [`ErrorKind::Interrupted`](std::io::ErrorKind::Interrupted).
    #[inline]
    #[must_use]
    pub fn payload<R: Read>(mut self, payload: R, options_len: usize) -> Result<Self> {
        let data = self.buf.as_mut();
        let start = usize::from(MIN_HEADER_LEN) + options_len;
        crate::write_all_bytes(payload, &mut data[start..])?;
        Ok(self)
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
    pub fn build(self) -> Packet<B> {
        unsafe { Packet::new_unchecked(self.buf) }
    }
}

mod offsets {
    use std::ops::Range;
    pub(crate) const VERSION: usize = 0;
    pub(crate) const HEADER_LEN: usize = 0;
    pub(crate) const DSCP: usize = 1;
    pub(crate) const ECN: usize = 1;
    pub(crate) const LEN: Range<usize> = 2..4;
    pub(crate) const IDENT: Range<usize> = 4..6;
    pub(crate) const FLAGS: usize = 6;
    pub(crate) const FRAGMENT_OFFSET: Range<usize> = 6..8;
    pub(crate) const TTL: usize = 8;
    pub(crate) const PROTOCOL: usize = 9;
    pub(crate) const CHECKSUM: Range<usize> = 10..12;
    pub(crate) const SOURCE: Range<usize> = 12..16;
    pub(crate) const DEST: Range<usize> = 16..20;
}

/// Wrapper for "differentiated service code point" (DSCP) field in the IP
/// packet.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub struct Dscp {
    class: u8,
    drop: u8,
}

impl Dscp {
    /// Create a new [`Dscp`] instance. Note that the class and drop probably
    /// cannot be larger than 7, since they are represented using 3 bits each.
    ///
    /// # Errors
    ///
    /// Fails when class or drop are larger than 7.
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
        let congested = u8::from(ecn.congested());
        let capable = u8::from(ecn.capable());
        (congested << 1) | capable
    }
}

/// Wrapper for the "flags" field on the IP packet.
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
        let do_not_fragment = u8::from(flags.do_not_fragment);
        let more_fragments = u8::from(flags.more_fragments);
        (do_not_fragment << 1) | more_fragments
    }
}

#[cfg(test)]
mod tests {
    use super::{Dscp, Ecn, Flags, Packet};
    use crate::{ethernet::Frame, ipv4::MIN_HEADER_LEN};
    use std::{error::Error, io::Cursor, net::Ipv4Addr};

    // IPv4 packet wrapped in an Ethernet frame, captured using Wireshark.
    const FRAME_WITH_PACKET: &'static [u8] = include_bytes!("../resources/enet-ipv4.bin");

    // IPv4 with junk options created using scapy
    const PACKET_WITH_OPTS: &'static [u8] = include_bytes!("../resources/ipv4-with-opts.bin");

    #[test]
    fn packet_returns_err_when_byte_slice_too_short() {
        let frame = vec![0, 0, 0, 0];
        let packet = Packet::new(&frame);
        assert!(packet.is_err());
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
        assert_eq!(packet.checksum(), 0xA3ED);
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
        let buf = &mut [0; MIN_HEADER_LEN as usize];
        let packet = Packet::<&[u8]>::builder(buf)?.version(12).build();
        assert_eq!(packet.version(), 12);
        Ok(())
    }

    #[test]
    fn packet_builder_has_expected_header_len() -> Result<(), Box<dyn Error>> {
        let buf = &mut [0; MIN_HEADER_LEN as usize];
        let packet = Packet::<&[u8]>::builder(buf)?.header_len(12).build();
        assert_eq!(packet.header_len(), 48);
        Ok(())
    }

    #[test]
    fn packet_builder_has_expected_dscp() -> Result<(), Box<dyn Error>> {
        let buf = &mut [0; MIN_HEADER_LEN as usize];
        let dscp = Dscp::new(5, 7)?;
        let packet = Packet::<&[u8]>::builder(buf)?.dscp(dscp).build();
        assert_eq!(packet.dscp(), dscp);
        Ok(())
    }

    #[test]
    fn packet_builder_has_expected_ecn() -> Result<(), Box<dyn Error>> {
        let buf = &mut [0; MIN_HEADER_LEN as usize];
        let ecn = Ecn::new(true, false);
        let packet = Packet::<&[u8]>::builder(buf)?.ecn(ecn).build();
        assert_eq!(packet.ecn(), ecn);
        Ok(())
    }

    #[test]
    fn packet_builder_has_expected_total_len() -> Result<(), Box<dyn Error>> {
        let buf = &mut [0; MIN_HEADER_LEN as usize];
        let packet = Packet::<&[u8]>::builder(buf)?.len(20).build();
        assert_eq!(packet.len(), 20);
        Ok(())
    }

    #[test]
    fn packet_builder_has_expected_id() -> Result<(), Box<dyn Error>> {
        let buf = &mut [0; MIN_HEADER_LEN as usize];
        let packet = Packet::<&[u8]>::builder(buf)?.id(20).build();
        assert_eq!(packet.id(), 20);
        Ok(())
    }

    #[test]
    fn packet_builder_has_expected_flags() -> Result<(), Box<dyn Error>> {
        let buf = &mut [0; MIN_HEADER_LEN as usize];
        let flags = Flags::new(true, false);
        let packet = Packet::<&[u8]>::builder(buf)?.flags(flags).build();
        assert_eq!(packet.flags(), flags);
        Ok(())
    }

    #[test]
    fn packet_builder_has_expected_fragment_offset() -> Result<(), Box<dyn Error>> {
        let buf = &mut [0; MIN_HEADER_LEN as usize];
        let packet = Packet::<&[u8]>::builder(buf)?.fragment_offset(12).build();
        assert_eq!(packet.fragment_offset(), 12);
        Ok(())
    }

    #[test]
    fn packet_builder_has_expected_ttl() -> Result<(), Box<dyn Error>> {
        let buf = &mut [0; MIN_HEADER_LEN as usize];
        let packet = Packet::<&[u8]>::builder(buf)?.ttl(12).build();
        assert_eq!(packet.ttl(), 12);
        Ok(())
    }

    #[test]
    fn packet_builder_has_expected_protocol() -> Result<(), Box<dyn Error>> {
        let buf = &mut [0; MIN_HEADER_LEN as usize];
        let packet = Packet::<&[u8]>::builder(buf)?.protocol(12).build();
        assert_eq!(packet.protocol(), 12);
        Ok(())
    }

    #[test]
    fn packet_builder_has_expected_checksum() -> Result<(), Box<dyn Error>> {
        let buf = &mut [0; MIN_HEADER_LEN as usize];
        let packet = Packet::<&[u8]>::builder(buf)?.checksum(0xB0BA).build();
        assert_eq!(packet.checksum(), 0xB0BA);
        Ok(())
    }

    #[test]
    fn packet_builder_has_expected_source() -> Result<(), Box<dyn Error>> {
        let buf = &mut [0; MIN_HEADER_LEN as usize];
        let addr = Ipv4Addr::new(127, 0, 0, 1);
        let packet = Packet::<&[u8]>::builder(buf)?.source(addr).build();
        assert_eq!(packet.source(), addr);
        Ok(())
    }

    #[test]
    fn packet_builder_has_expected_dest() -> Result<(), Box<dyn Error>> {
        let buf = &mut [0; MIN_HEADER_LEN as usize];
        let addr = Ipv4Addr::new(127, 0, 0, 1);
        let packet = Packet::<&[u8]>::builder(buf)?.dest(addr).build();
        assert_eq!(packet.dest(), addr);
        Ok(())
    }

    #[test]
    fn packet_builder_has_expected_payload() -> Result<(), Box<dyn Error>> {
        let buf = &mut [0; MIN_HEADER_LEN as usize + 4];
        let payload = [1, 2, 3, 4];
        let reader = Cursor::new(payload);

        let packet = Packet::<&[u8]>::builder(buf)?
            .header_len(5)
            .len(24)
            .payload(reader, 0)?
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
