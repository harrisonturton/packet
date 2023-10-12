//! Read and write UDP datagrams.
//!
//! ## Standards conformance
//!
//! Follows [RFC 768](https://www.ietf.org/rfc/rfc768.txt).
use std::io::Read;

use crate::{ptr_write, Error, Result};

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
        if bytes.len() >= Self::MIN_DATAGRAM_LEN {
            Ok(Self { bytes })
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
    pub unsafe fn new_unchecked(bytes: &'a [u8]) -> Datagram {
        Datagram { bytes }
    }

    /// Create a new [`DatagramBuilder`] that modifies a buffer of bytes in-place.
    ///
    /// # Errors
    ///
    /// See [`DatagramBuilder::new`].
    pub fn builder(buf: &'a mut [u8]) -> Result<DatagramBuilder<'a>> {
        DatagramBuilder::new(buf)
    }

    /// Get the source port.
    #[inline]
    #[must_use]
    pub fn source(&self) -> u16 {
        u16::from_be_bytes(unsafe { offsets::source(self.bytes).read() })
    }

    /// Get the destination port.
    #[inline]
    #[must_use]
    pub fn dest(&self) -> u16 {
        u16::from_be_bytes(unsafe { offsets::dest(self.bytes).read() })
    }

    /// Get the length of the payload.
    #[inline]
    #[must_use]
    pub fn len(&self) -> u16 {
        u16::from_be_bytes(unsafe { offsets::len(self.bytes).read() })
    }

    /// Get the checksum.
    #[inline]
    #[must_use]
    pub fn checksum(&self) -> [u8; 2] {
        unsafe { offsets::checksum(self.bytes).read() }
    }

    /// Get the payload.
    #[inline]
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.bytes[8..]
    }

    // Size of the UDP header in bytes
    const MIN_DATAGRAM_LEN: usize = 8;
}

/// Builder for constructing [`Datagram`] instances in-place.
pub struct DatagramBuilder<'a> {
    bytes: &'a mut [u8],
}

impl<'a> DatagramBuilder<'a> {
    /// Create a new [`DatagramBuilder`] instance from an underlying byte
    /// buffer.  This will modify the buffer in-place, so can be used for making
    /// incremental modifications to an existing datagram in memory.
    ///
    /// # Errors
    ///
    /// Fails when the byte slice is smaller 8 bytes long, but does no other
    /// validation.
    #[inline]
    #[must_use]
    pub fn new(bytes: &'a mut [u8]) -> Result<Self> {
        if bytes.len() >= Datagram::MIN_DATAGRAM_LEN {
            Ok(DatagramBuilder { bytes })
        } else {
            Err(Error::CannotParse("buffer too small"))
        }
    }

    /// Set the source.
    #[inline]
    #[must_use]
    pub fn source(self, source: u16) -> Self {
        unsafe {
            let offset = offsets::source_mut(self.bytes);
            ptr_write(offset, source.to_be_bytes());
        }
        self
    }

    /// Set the destination.
    #[inline]
    #[must_use]
    pub fn dest(self, dest: u16) -> Self {
        unsafe {
            let offset = offsets::dest_mut(self.bytes);
            ptr_write(offset, dest.to_be_bytes());
        }
        self
    }

    /// Set the length field.
    #[inline]
    #[must_use]
    pub fn len(self, len: u16) -> Self {
        unsafe {
            let offset = offsets::len_mut(self.bytes);
            ptr_write(offset, len.to_be_bytes());
        }
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
    pub fn payload<R: Read>(self, payload: R) -> Result<Self> {
        let buf = &mut self.bytes[Datagram::MIN_DATAGRAM_LEN..];
        crate::read_all_bytes(payload, buf)?;
        Ok(self)
    }

    /// Set the checksum field.
    #[inline]
    #[must_use]
    pub fn checksum(self, checksum: [u8; 2]) -> Self {
        unsafe {
            let offset = offsets::checksum_mut(self.bytes);
            ptr_write(offset, checksum);
        }
        self
    }

    /// Get the built [`Datagram`] instance.
    #[inline]
    #[must_use]
    pub fn build(self) -> Datagram<'a> {
        // Safe because of the preconditions asserted in [`DatagramBuilder::new`]
        unsafe { Datagram::new_unchecked(self.bytes) }
    }
}

mod offsets {
    use crate::{offset_mut_ptr, offset_ptr};

    /// Get a constant pointer to the byte storing the source.
    #[inline]
    #[must_use]
    pub(crate) unsafe fn source(bytes: &[u8]) -> *const [u8; 2] {
        offset_ptr(bytes, 0)
    }

    /// Get a mutable pointer to the byte storing the source.
    #[inline]
    #[must_use]
    pub(crate) unsafe fn source_mut(bytes: &mut [u8]) -> *mut [u8; 2] {
        offset_mut_ptr(bytes, 0)
    }

    /// Get a constant pointer to the byte storing the destination.
    #[inline]
    #[must_use]
    pub(crate) unsafe fn dest(bytes: &[u8]) -> *const [u8; 2] {
        offset_ptr(bytes, 2)
    }

    /// Get a mutable pointer to the byte storing the dest.
    #[inline]
    #[must_use]
    pub(crate) unsafe fn dest_mut(bytes: &mut [u8]) -> *mut [u8; 2] {
        offset_mut_ptr(bytes, 2)
    }

    /// Get a constant pointer to the byte storing the length of the payload.
    #[inline]
    #[must_use]
    pub(crate) unsafe fn len(bytes: &[u8]) -> *const [u8; 2] {
        offset_ptr(bytes, 4)
    }

    /// Get a mutable pointer to the byte storing the len.
    #[inline]
    #[must_use]
    pub(crate) unsafe fn len_mut(bytes: &mut [u8]) -> *mut [u8; 2] {
        offset_mut_ptr(bytes, 4)
    }

    /// Get a constant pointer to the byte storing the checksum.
    #[inline]
    #[must_use]
    pub(crate) unsafe fn checksum(bytes: &[u8]) -> *const [u8; 2] {
        offset_ptr(bytes, 6)
    }

    /// Get a mutable pointer to the byte storing the checksum.
    #[inline]
    #[must_use]
    pub(crate) unsafe fn checksum_mut(bytes: &mut [u8]) -> *mut [u8; 2] {
        offset_mut_ptr(bytes, 6)
    }
}

#[cfg(test)]
mod tests {
    use super::Datagram;
    use crate::{ethernet::Frame, ipv4::Packet};
    use std::{error::Error, io::Cursor};

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

    #[test]
    fn datagram_builder_has_expected_source() -> Result<(), Box<dyn Error>> {
        let buf = &mut [0; Datagram::MIN_DATAGRAM_LEN];
        let datagram = Datagram::builder(buf)?.source(42).build();
        assert_eq!(datagram.source(), 42);
        Ok(())
    }

    #[test]
    fn datagram_builder_has_expected_dest() -> Result<(), Box<dyn Error>> {
        let buf = &mut [0; Datagram::MIN_DATAGRAM_LEN];
        let datagram = Datagram::builder(buf)?.dest(42).build();
        assert_eq!(datagram.dest(), 42);
        Ok(())
    }

    #[test]
    fn datagram_builder_has_expected_len() -> Result<(), Box<dyn Error>> {
        let buf = &mut [0; Datagram::MIN_DATAGRAM_LEN];
        let datagram = Datagram::builder(buf)?.len(12).build();
        assert_eq!(datagram.len(), 12);
        Ok(())
    }

    #[test]
    fn datagram_builder_has_expected_checksum() -> Result<(), Box<dyn Error>> {
        let buf = &mut [0; Datagram::MIN_DATAGRAM_LEN];
        let datagram = Datagram::builder(buf)?.checksum([0xA, 0xB]).build();
        assert_eq!(datagram.checksum(), [0xA, 0xB]);
        Ok(())
    }

    #[test]
    fn datagram_builder_has_expected_payload() -> Result<(), Box<dyn Error>> {
        let buf = &mut [0; 8 + 4];
        let payload = [1, 2, 3, 4];
        let reader = Cursor::new(payload);

        let datagram = Datagram::builder(buf)?.payload(reader)?.build();

        assert_eq!(datagram.payload(), payload);
        Ok(())
    }
}
