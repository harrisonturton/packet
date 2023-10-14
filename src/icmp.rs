//! Read and write ICMP packets.
//!
//! This module is still in development.
use crate::{Error, Result};
use byteorder::{ByteOrder, NetworkEndian};

/// An ICMP packet.
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct Packet<B: AsRef<[u8]>> {
    buf: B,
}

impl<B: AsRef<[u8]>> Packet<B> {
    /// Create a new ICMP packet.
    ///
    /// # Errors
    ///
    /// Fails when the buffer is smaller than the minimum ICMP header size.
    #[inline]
    #[must_use]
    pub fn new(buf: B) -> Result<Self> {
        if buf.as_ref().len() >= MIN_HEADER_LEN as usize {
            Ok(Self { buf })
        } else {
            Err(Error::CannotParse("buffer too small"))
        }
    }

    /// Extract the "type" header field.
    #[inline]
    #[must_use]
    pub fn typ(&self) -> u8 {
        let data = self.buf.as_ref();
        data[offsets::TYPE]
    }

    /// Extract the "code" header field.
    #[inline]
    #[must_use]
    pub fn code(&self) -> u8 {
        let data = self.buf.as_ref();
        data[offsets::CODE]
    }

    /// Extract the header checksum.
    #[inline]
    #[must_use]
    pub fn checksum(&self) -> u16 {
        let data = self.buf.as_ref();
        NetworkEndian::read_u16(&data[offsets::CHECKSUM])
    }

    /// Get a reference to the payload bytes
    #[inline]
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        let data = self.buf.as_ref();
        &data[offsets::PAYLOAD]
    }
}

mod offsets {
    use std::ops::{Range, RangeFrom};
    pub(crate) const TYPE: usize = 0;
    pub(crate) const CODE: usize = 1;
    pub(crate) const CHECKSUM: Range<usize> = 2..4;
    pub(crate) const PAYLOAD: RangeFrom<usize> = 4..;
}

pub(crate) const MIN_HEADER_LEN: usize = 4;
