//! Ethernet MAC frame parsing.
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
//! innacurate (or stripped) due to checksum offloading on the NIC.
use crate::{offset_read, Error};
use std::fmt::Debug;

/// An Ethernet frame.
///
/// This struct wraps a byte array directly. Nothing is parsed until the field
/// accessor methods (e.g. [`dest`]) are called. Some header values are passed
/// as copies when they're small, but client data (the payload) is always
/// referred to by reference.
///
/// See the module documentation for more information.
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct Frame<'a> {
    bytes: &'a [u8],
}

impl<'a> Frame<'a> {
    /// Create a new Ethernet frame.
    ///
    /// # Errors
    ///
    /// Fails when the byte slice is smaller than the minimum
    /// [`MIN_ETHERNET_FRAME`] size, but does not other validation.
    ///
    /// The field accessor methods on [`Frame`] index directly into the byte
    /// array (an unsafe operation) so this length precondition needs to be
    /// enforced to ensure safety at runtime.
    #[inline]
    #[must_use]
    pub fn new(bytes: &'a [u8]) -> Result<Frame, Error> {
        if bytes.len() >= MIN_FRAME_LEN {
            Ok(Frame { bytes })
        } else {
            return Err(Error::CannotParse("frame too small"));
        }
    }

    /// Extract the destination MAC address.
    #[inline]
    #[must_use]
    pub fn dest(&self) -> MacAddr {
        MacAddr::from(unsafe { offset_read::<[u8; 6]>(self.bytes, 0) })
    }

    /// Extract the source MAC address.
    #[inline]
    #[must_use]
    pub fn source(&self) -> MacAddr {
        MacAddr::from(unsafe { offset_read::<[u8; 6]>(self.bytes, 6) })
    }

    /// Extract the length/type field.
    ///
    /// The value represents the length of the client data if it's value is less
    /// than or equal to 1500, and represents an `EtherType` if it is greater or
    /// equal to 1536. See section `3.2.6` of the standard for more info.
    #[inline]
    #[must_use]
    pub fn length_type(&self) -> LengthType {
        LengthType::new(u16::from_be_bytes(unsafe { offset_read(self.bytes, 12) }))
    }

    /// Extract the client data field.
    #[inline]
    #[must_use]
    pub fn payload(&self) -> &'a [u8] {
        &self.bytes[PAYLOAD_START..]
    }

    /// Total length of the frame.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }
}

/// The Ethernet header has a "length/type" field which represents either the
/// length of the client data or an [`EtherType`] depending on the value (See
/// clause 3.2.6).
#[derive(Debug, PartialEq, Eq, Clone)]
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
            ETHERTYPE_IPV4 => LengthType::Type(EtherType::Ipv4),
            ETHERTYPE_IPV6 => LengthType::Type(EtherType::Ipv6),
            len if len <= MAX_LENTYPE_LEN => LengthType::Length(len),
            typ if typ >= MIN_LENTYPE_TYP => LengthType::Type(EtherType::Unknown(typ)),
            _ => LengthType::Invalid(value),
        }
    }
}

/// See the [IANA list of EtherType
/// values](https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml#ieee-802-numbers-1).
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub enum EtherType {
    Ipv4,
    Ipv6,
    Unknown(u16),
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

// Minimum length of an Ethernet frame.
const MIN_FRAME_LEN: usize = 64;

// When the length/type field is below this value it is considered a length.
const MAX_LENTYPE_LEN: u16 = 0x5DC;

// When the length/type field is above this value it is considered an [`EtherType`].
const MIN_LENTYPE_TYP: u16 = 0x600;

// EtherType code for IPv4.
const ETHERTYPE_IPV4: u16 = 0x800;

// EtherType code for IPv6.
const ETHERTYPE_IPV6: u16 = 0x86DD;

// Index where the header ends and client data begins
const PAYLOAD_START: usize = 14;

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    // IP packet wrapped in an Ethernet frame, captured using Wireshark.
    pub const FRAME: &'static [u8] = include_bytes!("../resources/ethernet-frame.bin");

    #[test]
    fn frame_returns_err_when_byte_slice_too_short() {
        let frame = Frame::new(&[0, 0, 0, 0]);
        assert!(frame.is_err());
    }

    #[test]
    fn frame_has_expected_dest_address() -> Result<(), Box<dyn Error>> {
        let frame = Frame::new(FRAME)?;
        assert_eq!(
            frame.dest(),
            MacAddr::new(0x74, 0xA6, 0xCD, 0xB1, 0xF9, 0x8B)
        );
        Ok(())
    }

    #[test]
    fn frame_has_expected_source_address() -> Result<(), Box<dyn Error>> {
        let frame = Frame::new(FRAME)?;
        assert_eq!(
            frame.source(),
            MacAddr::new(0xC2, 0x17, 0x54, 0x77, 0x7A, 0x64)
        );
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
