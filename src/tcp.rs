//! Read and write TCP segments.
//!
//! This module is still in development.
//!
//! # Standards conformance
//!
//! Follows [RFC
//! 9293](https://www.rfc-editor.org/rfc/rfc9293.html#name-functional-specification).
use crate::{bitset, setbits, Error, Result};
use byteorder::{ByteOrder, NetworkEndian};

/// A TCP segment.
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct Segment<B: AsRef<[u8]>> {
    buf: B,
}

impl<B: AsRef<[u8]>> Segment<B> {
    /// Create a new TCP segment.
    ///
    /// # Errors
    ///
    /// Fails when the buffer is smaller than the minimum TCP header size.
    #[inline]
    #[must_use]
    pub fn new(buf: B) -> Result<Self> {
        if buf.as_ref().len() >= MIN_HEADER_LEN as usize {
            Ok(Self { buf })
        } else {
            Err(Error::CannotParse("buffer too small"))
        }
    }

    /// Extract the source port.
    #[inline]
    #[must_use]
    pub fn source(&self) -> u16 {
        let data = self.buf.as_ref();
        NetworkEndian::read_u16(&data[offsets::SOURCE])
    }

    /// Extract the destination port.
    #[inline]
    #[must_use]
    pub fn dest(&self) -> u16 {
        let data = self.buf.as_ref();
        NetworkEndian::read_u16(&data[offsets::DEST])
    }

    /// Extract the sequence number.
    #[inline]
    #[must_use]
    pub fn sequence(&self) -> u32 {
        let data = self.buf.as_ref();
        NetworkEndian::read_u32(&data[offsets::SEQUENCE])
    }

    /// Extract the acknowledgment number.
    #[inline]
    #[must_use]
    pub fn acked(&self) -> u32 {
        let data = self.buf.as_ref();
        NetworkEndian::read_u32(&data[offsets::ACKED])
    }

    /// Extract the data offset.
    #[inline]
    #[must_use]
    pub fn data_offset(&self) -> u8 {
        let data = self.buf.as_ref();
        data[offsets::DATA_OFFSET] >> 4
    }

    /// Extract the control bit flags.
    #[inline]
    #[must_use]
    pub fn flags(&self) -> Flags {
        let data = self.buf.as_ref();
        Flags::from(data[offsets::FLAGS])
    }

    /// Extract the window size.
    #[inline]
    #[must_use]
    pub fn window(&self) -> u16 {
        let data = self.buf.as_ref();
        NetworkEndian::read_u16(&data[offsets::WINDOW])
    }

    /// Extract the segment checksum.
    #[inline]
    #[must_use]
    pub fn checksum(&self) -> u16 {
        let data = self.buf.as_ref();
        NetworkEndian::read_u16(&data[offsets::CHECKSUM])
    }

    /// Extract the urgent pointer.
    #[inline]
    #[must_use]
    pub fn urgent(&self) -> u16 {
        let data = self.buf.as_ref();
        NetworkEndian::read_u16(&data[offsets::URGENT])
    }
}

/// Builds [`Segment`] instances.
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct SegmentBuilder<B: AsRef<[u8]> + AsMut<[u8]>> {
    buf: B,
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> SegmentBuilder<B> {
    /// Create a new TCP segment builder.
    ///
    /// # Errors
    ///
    /// Fails when the buffer is smaller than the minimum TCP header size.
    #[inline]
    #[must_use]
    pub fn new(buf: B) -> Result<Self> {
        if buf.as_ref().len() >= MIN_HEADER_LEN as usize {
            Ok(Self { buf })
        } else {
            Err(Error::CannotParse("buffer too small"))
        }
    }

    /// Set the source port.
    #[inline]
    #[must_use]
    pub fn source(mut self, port: u16) {
        let data = self.buf.as_mut();
        NetworkEndian::write_u16(&mut data[offsets::SOURCE], port);
    }

    /// Set the destination port.
    #[inline]
    #[must_use]
    pub fn dest(mut self, port: u16) {
        let data = self.buf.as_mut();
        NetworkEndian::write_u16(&mut data[offsets::DEST], port);
    }

    /// Set the sequence number.
    #[inline]
    #[must_use]
    pub fn sequence(mut self, seq: u32) {
        let data = self.buf.as_mut();
        NetworkEndian::write_u32(&mut data[offsets::SEQUENCE], seq);
    }

    /// Set the acknowledgment number.
    #[inline]
    #[must_use]
    pub fn acked(mut self, acked: u32) {
        let data = self.buf.as_mut();
        NetworkEndian::write_u32(&mut data[offsets::ACKED], acked);
    }

    /// Set the data offset.
    #[inline]
    #[must_use]
    pub fn data_offset(mut self, offset: u8) {
        let data = self.buf.as_mut();
        let current = data[offsets::DATA_OFFSET];
        data[offsets::DATA_OFFSET] = setbits(current, offset << 4, 0b1111 << 4);
    }

    /// Set the control flags.
    #[inline]
    #[must_use]
    pub fn flags(mut self, flags: Flags) {
        let data = self.buf.as_mut();
        let flags: u8 = flags.into();
        let current = data[offsets::FLAGS];
        data[offsets::FLAGS] = setbits(current, flags, 0b1111);
    }

    /// Set the window.
    #[inline]
    #[must_use]
    pub fn window(mut self, window: u16) {
        let data = self.buf.as_mut();
        NetworkEndian::write_u16(&mut data[offsets::WINDOW], window);
    }

    /// Set the checksum.
    #[inline]
    #[must_use]
    pub fn checksum(mut self, checksum: u16) {
        let data = self.buf.as_mut();
        NetworkEndian::write_u16(&mut data[offsets::CHECKSUM], checksum);
    }

    /// Set the urgent pointer.
    #[inline]
    #[must_use]
    pub fn urgent(mut self, urgent: u16) {
        let data = self.buf.as_mut();
        NetworkEndian::write_u16(&mut data[offsets::URGENT], urgent);
    }
}

mod offsets {
    use std::ops::Range;
    pub(crate) const SOURCE: Range<usize> = 0..2;
    pub(crate) const DEST: Range<usize> = 2..4;
    pub(crate) const SEQUENCE: Range<usize> = 4..8;
    pub(crate) const ACKED: Range<usize> = 8..12;
    pub(crate) const DATA_OFFSET: usize = 12;
    pub(crate) const FLAGS: usize = 13;
    pub(crate) const WINDOW: Range<usize> = 14..16;
    pub(crate) const CHECKSUM: Range<usize> = 16..18;
    pub(crate) const URGENT: Range<usize> = 18..20;
}

/// TCP control bit flags.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub struct Flags {
    cwr: bool,
    ece: bool,
    urg: bool,
    ack: bool,
    psh: bool,
    rst: bool,
    syn: bool,
    fin: bool,
}

impl Flags {
    /// Whether the congestion window is set.
    #[inline]
    #[must_use]
    pub fn congestion_window_reduced(&self) -> bool {
        self.cwr
    }

    // Whether the ECN echo flag is set.
    #[inline]
    #[must_use]
    pub fn ecn_echo(&self) -> bool {
        self.ece
    }

    // Whether the urgent significant flag is set.
    #[inline]
    #[must_use]
    pub fn urgent_significant(&self) -> bool {
        self.urg
    }

    // Whether the ack significant flag is set.
    #[inline]
    #[must_use]
    pub fn ack_significant(&self) -> bool {
        self.ack
    }

    // Whether the push flag is set.
    #[inline]
    #[must_use]
    pub fn push(&self) -> bool {
        self.psh
    }

    // Whether the reset connection flag is set.
    #[inline]
    #[must_use]
    pub fn reset_conn(&self) -> bool {
        self.rst
    }

    // Whether the synchronize sequence numbers flag is set.
    #[inline]
    #[must_use]
    pub fn synchronize(&self) -> bool {
        self.syn
    }

    // Whether the finish flag is set.
    #[inline]
    #[must_use]
    pub fn finished(&self) -> bool {
        self.fin
    }
}

impl From<u8> for Flags {
    fn from(value: u8) -> Self {
        Self {
            cwr: bitset(value, 7),
            ece: bitset(value, 6),
            urg: bitset(value, 5),
            ack: bitset(value, 4),
            psh: bitset(value, 3),
            rst: bitset(value, 2),
            syn: bitset(value, 1),
            fin: bitset(value, 0),
        }
    }
}

impl From<Flags> for u8 {
    fn from(value: Flags) -> Self {
        (value.cwr as u8) << 7
            | (value.ece as u8) << 6
            | (value.urg as u8) << 5
            | (value.ack as u8) << 4
            | (value.psh as u8) << 3
            | (value.rst as u8) << 2
            | (value.syn as u8) << 1
            | value.fin as u8
    }
}

pub(crate) const MIN_HEADER_LEN: usize = 20;

#[cfg(test)]
mod tests {
    use super::{Flags, Segment};
    use crate::enet::Frame;
    use crate::ipv4;
    use std::error::Error;
    use std::result::Result;

    const ENET_IPV4_TCP: &'static [u8] = include_bytes!("../resources/enet-ipv4-tcp.bin");

    #[test]
    fn new_returns_err_when_buffer_too_short() {
        let segment = Segment::new(&[0, 0, 0]);
        assert!(segment.is_err());
    }

    #[test]
    fn segment_has_expected_source_port() -> Result<(), Box<dyn Error>> {
        let frame = Frame::new(ENET_IPV4_TCP)?;
        let packet = ipv4::Packet::new(frame.payload())?;
        let segment = Segment::new(packet.payload())?;
        assert_eq!(segment.source(), 443);
        Ok(())
    }

    #[test]
    fn segment_has_expected_dest_port() -> Result<(), Box<dyn Error>> {
        let frame = Frame::new(ENET_IPV4_TCP)?;
        let packet = ipv4::Packet::new(frame.payload())?;
        let segment = Segment::new(packet.payload())?;
        assert_eq!(segment.dest(), 52138);
        Ok(())
    }

    #[test]
    fn segment_has_expected_sequence_number() -> Result<(), Box<dyn Error>> {
        let frame = Frame::new(ENET_IPV4_TCP)?;
        let packet = ipv4::Packet::new(frame.payload())?;
        let segment = Segment::new(packet.payload())?;
        assert_eq!(segment.sequence(), 2433487296);
        Ok(())
    }

    #[test]
    fn segment_has_expected_acknowledged() -> Result<(), Box<dyn Error>> {
        let frame = Frame::new(ENET_IPV4_TCP)?;
        let packet = ipv4::Packet::new(frame.payload())?;
        let segment = Segment::new(packet.payload())?;
        assert_eq!(segment.acked(), 4135257849);
        Ok(())
    }

    #[test]
    fn segment_has_expected_data_offset() -> Result<(), Box<dyn Error>> {
        let frame = Frame::new(ENET_IPV4_TCP)?;
        let packet = ipv4::Packet::new(frame.payload())?;
        let segment = Segment::new(packet.payload())?;
        assert_eq!(segment.data_offset(), 8);
        Ok(())
    }

    #[test]
    fn segment_has_expected_flags() -> Result<(), Box<dyn Error>> {
        let frame = Frame::new(ENET_IPV4_TCP)?;
        let packet = ipv4::Packet::new(frame.payload())?;
        let segment = Segment::new(packet.payload())?;

        assert_eq!(
            segment.flags(),
            Flags {
                cwr: false,
                ece: false,
                urg: false,
                ack: true,
                psh: false,
                rst: false,
                syn: false,
                fin: false,
            }
        );

        Ok(())
    }

    #[test]
    fn segment_has_expected_window() -> Result<(), Box<dyn Error>> {
        let frame = Frame::new(ENET_IPV4_TCP)?;
        let packet = ipv4::Packet::new(frame.payload())?;
        let segment = Segment::new(packet.payload())?;
        assert_eq!(segment.window(), 501);
        Ok(())
    }

    #[test]
    fn segment_has_expected_checksum() -> Result<(), Box<dyn Error>> {
        let frame = Frame::new(ENET_IPV4_TCP)?;
        let packet = ipv4::Packet::new(frame.payload())?;
        let segment = Segment::new(packet.payload())?;
        assert_eq!(segment.checksum(), 0x82fd);
        Ok(())
    }

    #[test]
    fn segment_has_expected_urgent() -> Result<(), Box<dyn Error>> {
        let frame = Frame::new(ENET_IPV4_TCP)?;
        let packet = ipv4::Packet::new(frame.payload())?;
        let segment = Segment::new(packet.payload())?;
        assert_eq!(segment.urgent(), 0);
        Ok(())
    }
}
