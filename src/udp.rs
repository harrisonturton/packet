//! Read and write UDP datagrams.
//!
//! ## Standards conformance
//!
//! Follows [RFC 768](https://www.ietf.org/rfc/rfc768.txt).
use crate::{checksum::Checksum, ipv4::Protocol, Error, Result};
use byteorder::{ByteOrder, NetworkEndian};
use std::{io::Read, net::Ipv4Addr};

/// A UDP datagram.
///
/// See the module documentation for more information.
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct Datagram<B: AsRef<[u8]>> {
    buf: B,
}

impl<B: AsRef<[u8]>> Datagram<B> {
    /// Create a new [`Datagram`] instance.
    ///
    /// # Errors
    ///
    /// Fails when the byte slice is shorter than 8 bytes long.
    #[inline]
    #[must_use]
    pub fn new(buf: B) -> Result<Self> {
        if buf.as_ref().len() >= HEADER_LEN {
            Ok(Self { buf })
        } else {
            Err(Error::CannotParse("datagram too small"))
        }
    }

    /// Create a new Datagram from a byte array *without* checking that the
    /// array is valid. It is the responsibility of the caller to make sure the
    /// buffer is large enough for the packet.
    ///
    /// # Safety
    ///
    /// The buffer must be large enough to contain the UDP datagram header and
    /// the payload. This means it must be at least 8 larger than the payload.
    #[inline]
    #[must_use]
    pub unsafe fn new_unchecked(buf: B) -> Datagram<B> {
        Datagram { buf }
    }

    /// Create a new [`DatagramBuilder`] that modifies a buffer of bytes in-place.
    ///
    /// # Errors
    ///
    /// See [`DatagramBuilder::new`].
    pub fn builder<T>(buf: T) -> Result<DatagramBuilder<T>>
    where
        T: AsRef<[u8]> + AsMut<[u8]>,
    {
        DatagramBuilder::new(buf)
    }

    /// Get the source port.
    #[inline]
    #[must_use]
    pub fn source(&self) -> u16 {
        let data = self.buf.as_ref();
        NetworkEndian::read_u16(&data[offsets::SOURCE])
    }

    /// Get the destination port.
    #[inline]
    #[must_use]
    pub fn dest(&self) -> u16 {
        let data = self.buf.as_ref();
        NetworkEndian::read_u16(&data[offsets::DEST])
    }

    /// Get the length of the payload.
    #[inline]
    #[must_use]
    pub fn len(&self) -> u16 {
        let data = self.buf.as_ref();
        NetworkEndian::read_u16(&data[offsets::LEN])
    }

    /// Get the checksum.
    #[inline]
    #[must_use]
    pub fn checksum(&self) -> u16 {
        let data = self.buf.as_ref();
        NetworkEndian::read_u16(&data[offsets::CHECKSUM])
    }

    /// Get the payload.
    #[inline]
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.buf.as_ref()[offsets::PAYLOAD]
    }
}

/// Builder for constructing [`Datagram`] instances in-place.
pub struct DatagramBuilder<B: AsMut<[u8]>> {
    bytes: B,
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> DatagramBuilder<B> {
    /// Create a new [`DatagramBuilder`] instance from an underlying byte
    /// buffer.  This will modify the buffer in-place, so can be used for making
    /// incremental modifications to an existing datagram in memory.
    ///
    /// # Errors
    ///
    /// Fails when the byte slice is smaller 8 bytes long, or when the byte
    /// slice is longer than [`u16::MAX`], but does no other validation. It
    /// fails when the buffer is too large because the UDP datagram length field
    /// is a `u16`.
    #[inline]
    #[must_use]
    pub fn new(bytes: B) -> Result<Self> {
        if bytes.as_ref().len() >= u16::MAX.into() {
            return Err(Error::CannotParse("UDP buffer too large"));
        }

        if bytes.as_ref().len() < HEADER_LEN {
            return Err(Error::CannotParse("buffer too small"));
        }

        Ok(DatagramBuilder { bytes })
    }

    /// Set the source.
    #[inline]
    #[must_use]
    pub fn source(mut self, source: u16) -> Self {
        let data = self.bytes.as_mut();
        NetworkEndian::write_u16(&mut data[offsets::SOURCE], source);
        self
    }

    /// Set the destination.
    #[inline]
    #[must_use]
    pub fn dest(mut self, dest: u16) -> Self {
        let data = self.bytes.as_mut();
        NetworkEndian::write_u16(&mut data[offsets::DEST], dest);
        self
    }

    /// Set the length field.
    #[inline]
    #[must_use]
    pub fn len(mut self, len: u16) -> Self {
        let data = self.bytes.as_mut();
        NetworkEndian::write_u16(&mut data[offsets::LEN], len);
        self
    }

    /// Set the checksum field.
    #[inline]
    #[must_use]
    pub fn checksum(mut self, checksum: u16) -> Self {
        let data = self.bytes.as_mut();
        NetworkEndian::write_u16(&mut data[offsets::CHECKSUM], checksum);
        self
    }

    /// Calculate and set the checksum field.
    ///
    /// The source and destination IPv4 addresses are included in the checksum
    /// as part of the "pseudo-header" which spans both the IPv4 header and the
    /// UDP header.
    ///
    /// See the following RFCs, each superseding the last:
    ///
    /// 1. [User Datagram Protocol (RFC 768)](https://www.ietf.org/rfc/rfc768.txt)
    /// 2. [Computing the Internet Checksum (RFC 1071)](https://datatracker.ietf.org/doc/html/rfc1071).
    /// 3. [Incremental Updating of the Internet Checksum (RFC 1141)](https://datatracker.ietf.org/doc/html/rfc1141)
    /// 4. [Computation of the Internet Checksum via Incremental Update (RFC 1624)](https://datatracker.ietf.org/doc/html/rfc1624)
    ///
    /// And also see [Fast checksum computation](https://blogs.igalia.com/dpino/2018/06/14/fast-checksum-computation/).
    ///
    /// # Panics
    ///
    /// Panics when the datagram buffer is longer than [`u16::MAX`]. Datagram
    /// packets cannot be longer than this.
    #[inline]
    #[must_use]
    pub fn gen_checksum(mut self, source: Ipv4Addr, dest: Ipv4Addr) -> Self {
        let buf = self.bytes.as_mut();

        // The checksum calculation omits the checksum field
        NetworkEndian::write_u16(&mut buf[offsets::CHECKSUM], 0);

        // Truncate this on purpose. The UDP header only has space for a `u16`
        // length field; longer buffers are an error. This precondition is
        // enforced through the [`Datagram::new`].
        #[allow(clippy::cast_possible_truncation)]
        let len = buf.len() as u16;

        let checksum = Checksum::new()
            .add(buf)
            .add(&source.octets())
            .add(&dest.octets())
            .add(&[Protocol::Udp.code()])
            .add(&len.to_be_bytes())
            .finish();

        NetworkEndian::write_u16(&mut buf[offsets::CHECKSUM], checksum);
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
    pub fn payload<R: Read>(mut self, payload: R) -> Result<Self> {
        let data = self.bytes.as_mut();
        crate::write_all_bytes(payload, &mut data[offsets::PAYLOAD])?;
        Ok(self)
    }

    /// Get the built [`Datagram`] instance.
    #[inline]
    pub fn build(self) -> Datagram<B> {
        // Safe because of the preconditions asserted in [`DatagramBuilder::new`]
        unsafe { Datagram::new_unchecked(self.bytes) }
    }
}

// Minimum length of a UDP datagram.
pub const HEADER_LEN: usize = 8;

mod offsets {
    use std::ops::{Range, RangeFrom};
    pub(crate) const SOURCE: Range<usize> = 0..2;
    pub(crate) const DEST: Range<usize> = 2..4;
    pub(crate) const LEN: Range<usize> = 4..6;
    pub(crate) const CHECKSUM: Range<usize> = 6..8;
    pub(crate) const PAYLOAD: RangeFrom<usize> = 8..;
}

#[cfg(test)]
mod tests {
    use super::Datagram;
    use crate::{enet::Frame, ipv4::Packet, udp::HEADER_LEN};
    use std::{error::Error, io::Cursor};

    // IPv4 packet wrapped in an Ethernet frame, captured using Wireshark.
    pub const ETH_IPV4_UDP: &'static [u8] = include_bytes!("../resources/enet-ipv4.bin");

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
        assert_eq!(datagram.checksum(), 0xDAA7);
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

    #[test]
    fn datagram_builder_has_expected_source() -> Result<(), Box<dyn Error>> {
        let buf = &mut [0; HEADER_LEN];
        let datagram = Datagram::<&mut [u8]>::builder(buf)?.source(42).build();
        assert_eq!(datagram.source(), 42);
        Ok(())
    }

    #[test]
    fn datagram_builder_has_expected_dest() -> Result<(), Box<dyn Error>> {
        let buf = &mut [0; HEADER_LEN];
        let datagram = Datagram::<&mut [u8]>::builder(buf)?.dest(42).build();
        assert_eq!(datagram.dest(), 42);
        Ok(())
    }

    #[test]
    fn datagram_builder_has_expected_len() -> Result<(), Box<dyn Error>> {
        let buf = &mut [0; HEADER_LEN];
        let datagram = Datagram::<&mut [u8]>::builder(buf)?.len(12).build();
        assert_eq!(datagram.len(), 12);
        Ok(())
    }

    #[test]
    fn datagram_builder_has_expected_checksum() -> Result<(), Box<dyn Error>> {
        let buf = &mut [0; HEADER_LEN];
        let datagram = Datagram::<&mut [u8]>::builder(buf)?
            .checksum(0xAABB)
            .build();
        assert_eq!(datagram.checksum(), 0xAABB);
        Ok(())
    }

    #[test]
    fn datagram_builder_has_expected_payload() -> Result<(), Box<dyn Error>> {
        let buf = &mut [0; 8 + 4];
        let payload = [1, 2, 3, 4];
        let reader = Cursor::new(payload);

        let datagram = Datagram::<&mut [u8]>::builder(buf)?
            .payload(reader)?
            .build();

        assert_eq!(datagram.payload(), payload);
        Ok(())
    }
}
