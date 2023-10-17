//! Read and write Ethernet MAC frames.
//!
//! ## Standards conformance
//!
//! This implementation follows the [2022 IEEE Standard for
//! Ethernet](https://standards.ieee.org/ieee/802.3/10422/).
//!
//! It does not offer methods for extracting the preamble and start frame
//! delimiter (SFD) because those are layer 1 components. They're typically
//! stripped by the NIC anyway, so they're not usually available. It also does
//! not support extracting the frame check sequence (FCS) because it is often
//! innacurate or stripped due to checksum offloading on the NIC.
use byteorder::{ByteOrder, NetworkEndian};

use crate::{Error, Result};
use std::fmt::Debug;

/// An Ethernet frame.
///
/// This struct wraps a byte array directly. Nothing is parsed until the field
/// accessor methods (e.g. [`Frame::dest`]) are called. Some header values are
/// passed as copies when they're small, but client data (the payload) is always
/// referred to by reference.
///
/// See the module documentation for more information.
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct Frame<B: AsRef<[u8]>> {
    buf: B,
}

impl<B: AsRef<[u8]>> Frame<B> {
    /// Create a new Ethernet frame.
    ///
    /// # Errors
    ///
    /// Fails when the byte slice is smaller than the minimum size, but does no
    /// other validation.
    ///
    /// The field accessor methods on [`Frame`] index directly into the byte
    /// array (an unsafe operation) so this length precondition needs to be
    /// enforced to ensure safety at runtime.
    #[inline]
    #[must_use]
    pub fn new(buf: B) -> Result<Self> {
        if buf.as_ref().len() >= HEADER_LEN {
            Ok(Self { buf })
        } else {
            Err(Error::CannotParse("buffer too small"))
        }
    }

    /// Create a new Ethernet frame without checking the validity of the buffer
    /// length.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the buffer is longer than [`HEADER_LEN`]
    /// bytes long.
    #[inline]
    #[must_use]
    pub unsafe fn new_unchecked(buf: B) -> Self {
        Self { buf }
    }

    /// Construct a new [`Frame`] using a [`FrameBuilder`].
    ///
    /// # Errors
    ///
    /// See [`Frame::new`]
    #[inline]
    #[must_use]
    pub fn builder<T>(buf: T) -> Result<FrameBuilder<T>>
    where
        T: AsRef<[u8]> + AsMut<[u8]>,
    {
        FrameBuilder::<T>::new(buf)
    }

    /// Extract the destination MAC address.
    ///
    /// # Panics
    ///
    /// Panics when there are not enough bytes to read the destination address.
    /// This will never happen if the checked constructor [`Frame::new`] is
    /// used.
    #[inline]
    #[must_use]
    pub fn dest(&self) -> MacAddr {
        let data = self.buf.as_ref();
        let octets: [u8; 6] = data[offsets::DEST].try_into().unwrap();
        MacAddr::from(octets)
    }

    /// Extract the source MAC address.
    ///
    /// # Panics
    ///
    /// Panics when there are not enough bytes to read the destination address.
    /// This will never happen if the checked constructor [`Frame::new`] is
    /// used.
    #[inline]
    #[must_use]
    pub fn source(&self) -> MacAddr {
        let data = self.buf.as_ref();
        let octets: [u8; 6] = data[offsets::SOURCE].try_into().unwrap();
        MacAddr::from(octets)
    }

    /// Extract the length/type field.
    ///
    /// The value represents the length of the client data if it's value is less
    /// than or equal to 1500, and represents an `EtherType` if it is greater or
    /// equal to 1536. See section `3.2.6` of the standard for more info.
    #[inline]
    #[must_use]
    pub fn length_type(&self) -> LengthType {
        let data = self.buf.as_ref();
        let field = NetworkEndian::read_u16(&data[offsets::LENGTH_TYPE]);
        LengthType::new(field)
    }

    /// Extract the client data field.
    #[inline]
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        let data = self.buf.as_ref();
        &data[offsets::PAYLOAD]
    }

    /// Total length of the frame.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.buf.as_ref().len()
    }
}

/// Builder for constructing [`Frame`] instances.
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct FrameBuilder<B: AsRef<[u8]> + AsMut<[u8]>> {
    buf: B,
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> FrameBuilder<B> {
    /// Create a new [`FrameBuilder`] instance from an underlying byte slice.
    /// 
    /// # Errors
    /// 
    /// Fails when the buffer is shorter than [`HEADER_LEN`] bytes long.
    #[inline]
    #[must_use]
    pub fn new(buf: B) -> Result<Self> {
        if buf.as_ref().len() >= HEADER_LEN {
            Ok(Self { buf })
        } else {
            Err(Error::CannotParse("buffer too small"))
        }
    }

    /// Set the destination MAC address.
    #[inline]
    #[must_use]
    pub fn dest(mut self, dest: MacAddr) -> Self {
        let data = &mut self.buf.as_mut();
        data[offsets::DEST].copy_from_slice(&dest.octets);
        self
    }

    /// Set the source MAC address.
    #[inline]
    #[must_use]
    pub fn source(mut self, source: MacAddr) -> Self {
        let data = &mut self.buf.as_mut();
        data[offsets::SOURCE].copy_from_slice(&source.octets);
        self
    }

    /// Set the "length/type" field as an [`EtherType`].
    #[inline]
    #[must_use]
    pub fn ethertype(mut self, ethertype: EtherType) -> Self {
        let data = &mut self.buf.as_mut();
        let ethertype: u16 = ethertype.into();
        NetworkEndian::write_u16(&mut data[offsets::LENGTH_TYPE], ethertype);
        self
    }

    /// Copy the payload into the buffer.
    ///
    /// # Errors
    ///
    /// Fails when there is not enough space in the buffer for the payload, or
    /// when when [`Read`](std::io::Read) returns any error other than
    /// [`ErrorKind::Interrupted`](std::io::ErrorKind::Interrupted).
    #[inline]
    #[must_use]
    pub fn payload(mut self, payload: &[u8]) -> Result<Self> {
        let data = self.buf.as_mut();
        let payload_buf = &mut data[offsets::PAYLOAD];

        if payload_buf.len() < payload.len() {
            return Err(Error::NotEnoughSpace(
                "buffer not large enough to write payload",
            ));
        }

        crate::write_all_bytes(payload, payload_buf)?;
        Ok(self)
    }

    /// Create the [`Frame`].
    ///
    /// # Errors
    ///
    /// Fails when [`Frame::new`] fails.
    #[inline]
    #[must_use]
    pub fn build(self) -> Frame<B> {
        unsafe { Frame::new_unchecked(self.buf) }
    }
}

mod offsets {
    use std::ops::{Range, RangeFrom};
    pub(crate) const DEST: Range<usize> = 0..6;
    pub(crate) const SOURCE: Range<usize> = 6..12;
    pub(crate) const LENGTH_TYPE: Range<usize> = 12..14;
    pub(crate) const PAYLOAD: RangeFrom<usize> = 14..;
}

/// The Ethernet header has a "length/type" field which represents either the
/// length of the client data or an [`EtherType`] depending on the value (See
/// clause 3.2.6).
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum LengthType {
    Length(u16),
    Type(EtherType),
    Invalid(u16),
}

impl LengthType {
    /// Create a new [`LengthType`] instance.
    #[inline]
    #[must_use]
    pub fn new(value: u16) -> Self {
        match value {
            len if len <= MAX_LENTYPE_LEN => LengthType::Length(len),
            typ if typ >= MIN_LENTYPE_ETHERTYPE => LengthType::Type(value.into()),
            _ => LengthType::Invalid(value),
        }
    }
}

/// See the [IANA list of EtherType
/// values](https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml#ieee-802-numbers-1).
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum EtherType {
    Arp,
    Ipv4,
    Ipv6,
    Unknown(u16),
}

impl From<EtherType> for u16 {
    fn from(value: EtherType) -> Self {
        match value {
            EtherType::Arp => ETHERTYPE_ARP,
            EtherType::Ipv4 => ETHERTYPE_IPV4,
            EtherType::Ipv6 => ETHERTYPE_IPV6,
            EtherType::Unknown(typ) => typ,
        }
    }
}

impl From<u16> for EtherType {
    fn from(value: u16) -> Self {
        match value {
            ETHERTYPE_ARP => EtherType::Arp,
            ETHERTYPE_IPV4 => EtherType::Ipv4,
            ETHERTYPE_IPV6 => EtherType::Ipv6,
            _ => EtherType::Unknown(value),
        }
    }
}

/// A MAC address.
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct MacAddr {
    octets: [u8; 6],
}

impl MacAddr {
    /// Create a new [`MacAddr`] instance.
    #[inline]
    #[must_use]
    pub fn new(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8) -> Self {
        Self {
            octets: [a, b, c, d, e, f],
        }
    }
}

impl From<[u8; 6]> for MacAddr {
    fn from(octets: [u8; 6]) -> Self {
        MacAddr { octets }
    }
}

impl Debug for MacAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_string())
    }
}

impl ToString for MacAddr {
    fn to_string(&self) -> String {
        let [a, b, c, d, e, f] = self.octets;
        format!("{a:02x?}:{b:02x?}:{c:02x?}:{d:02x?}:{e:02x?}:{f:02x?}")
    }
}

/// Size of the Ethernet header.
pub const HEADER_LEN: usize = 14;

// When the length/type field is below this value it is considered a length.
const MAX_LENTYPE_LEN: u16 = 0x5DC;

// When the length/type field is above this value it is considered an [`EtherType`].
const MIN_LENTYPE_ETHERTYPE: u16 = 0x600;

// EtherType code for IPv4.
const ETHERTYPE_IPV4: u16 = 0x800;

// EtherType code for ARP.
const ETHERTYPE_ARP: u16 = 0x806;

// EtherType code for IPv6.
const ETHERTYPE_IPV6: u16 = 0x86DD;

#[cfg(test)]
mod tests {
    use crate::enet::ETHERTYPE_ARP;

    use super::{EtherType, Frame, LengthType, MacAddr, ETHERTYPE_IPV4, ETHERTYPE_IPV6};
    use std::error::Error;

    // IP packet wrapped in an Ethernet frame, captured using Wireshark.
    pub const FRAME: &'static [u8] = include_bytes!("../resources/enet-frame.bin");

    #[test]
    fn frame_returns_err_when_byte_slice_too_short() {
        let frame = Frame::new(&[0, 0, 0, 0]);
        assert!(frame.is_err());
    }

    #[test]
    fn frame_has_expected_dest_address() -> Result<(), Box<dyn Error>> {
        let frame = Frame::new(FRAME)?;
        let addr = MacAddr::new(0x74, 0xA6, 0xCD, 0xB1, 0xF9, 0x8B);
        assert_eq!(frame.dest(), addr);
        Ok(())
    }

    #[test]
    fn frame_has_expected_source_address() -> Result<(), Box<dyn Error>> {
        let frame = Frame::new(FRAME)?;
        let addr = MacAddr::new(0xC2, 0x17, 0x54, 0x77, 0x7A, 0x64);
        assert_eq!(frame.source(), addr);
        Ok(())
    }

    #[test]
    fn frame_has_expected_length_type() -> Result<(), Box<dyn Error>> {
        let frame = Frame::new(FRAME)?;
        assert_eq!(frame.length_type(), LengthType::Type(EtherType::Ipv4));
        Ok(())
    }

    #[test]
    fn frame_has_expected_payload() -> Result<(), Box<dyn Error>> {
        let frame = Frame::new(FRAME)?;
        assert_eq!(frame.payload(), &FRAME[14..]);
        Ok(())
    }

    #[test]
    fn frame_has_expected_len() -> Result<(), Box<dyn Error>> {
        let frame = Frame::new(FRAME)?;
        assert_eq!(frame.len(), 126);
        Ok(())
    }

    #[test]
    fn frame_builder_returns_expected_frame() -> Result<(), Box<dyn Error>> {
        let mut buf = [0; 1024];
        let frame = Frame::<&[u8]>::builder(&mut buf)?
            .source(MacAddr::new(0, 0, 0, 0, 0, 0))
            .dest(MacAddr::new(10, 10, 10, 10, 10, 10))
            .ethertype(EtherType::Ipv4)
            .payload(&[1, 2, 3])?
            .build();

        assert_eq!(frame.source(), MacAddr::new(0, 0, 0, 0, 0, 0));
        assert_eq!(frame.dest(), MacAddr::new(10, 10, 10, 10, 10, 10));
        assert_eq!(frame.length_type(), LengthType::Type(EtherType::Ipv4));
        assert_eq!(&frame.payload()[0..5], &[1, 2, 3, 0, 0]);

        Ok(())
    }

    #[test]
    fn length_type_has_expected_value_when_length() {
        let actual = LengthType::new(100);
        let expected = LengthType::Length(100);
        assert_eq!(actual, expected);
    }

    #[test]
    fn length_type_has_expected_value_when_ipv4() {
        let actual = LengthType::new(ETHERTYPE_IPV4);
        let expected = LengthType::Type(EtherType::Ipv4);
        assert_eq!(actual, expected);
    }

    #[test]
    fn length_type_has_expected_value_when_arp() {
        let actual = LengthType::new(ETHERTYPE_ARP);
        let expected = LengthType::Type(EtherType::Arp);
        assert_eq!(actual, expected);
    }

    #[test]
    fn length_type_has_expected_value_when_ipv6() {
        let actual = LengthType::new(ETHERTYPE_IPV6);
        let expected = LengthType::Type(EtherType::Ipv6);
        assert_eq!(actual, expected);
    }

    #[test]
    fn length_type_has_expected_value_when_unknown_type() {
        let actual = LengthType::new(1550);
        let expected = LengthType::Type(EtherType::Unknown(1550));
        assert_eq!(actual, expected);
    }

    #[test]
    fn length_type_has_expected_value_when_invalid() {
        let actual = LengthType::new(1530);
        let expected = LengthType::Invalid(1530);
        assert_eq!(actual, expected);
    }

    #[test]
    fn macaddr_to_string_gives_expected_value() {
        let addr = MacAddr::new(0, 10, 20, 5, 40, 50);
        assert_eq!(addr.to_string(), "00:0a:14:05:28:32".to_string());
    }

    #[test]
    fn macaddr_fmt_gives_expected_value() {
        let addr = MacAddr::new(0, 10, 20, 5, 40, 50);
        assert_eq!(format!("{addr:?}"), "00:0a:14:05:28:32".to_string());
    }
}
