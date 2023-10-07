use crate::{offset_read, Error};

/// An MAC packet as defined by the IEEE Standard for Ethernet (IEEE Std
/// 802.3-2022). All values are returned in network byte order.
///
/// This struct wraps a byte array directly. Nothing is parsed until the field
/// accessor methods (e.g. [`mac_dest`]) are called. The header values are passed
/// around as copies since they're so small, but the client data (the payload) is
/// returned as a slice into the frame byte array.
///
/// This implementation doesn't offer methods for extracting the preamble and
/// start frame delimiter (SFD) because those are layer 1 components. They're
/// typically stripped by the NIC anyway, so they're not usually available.
///
/// It also does not support extracting the frame check sequence (FCS) because
/// it is often innacurate (or stripped) due to checksum offloading on the NIC.
#[derive(Debug, PartialEq, Eq, Clone)]
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
    pub fn new(bytes: &'a [u8]) -> Result<Frame, Error> {
        if bytes.len() < MIN_FRAME_LEN {
            return Err(Error::InvalidArgument("frame too short"));
        }
        Ok(Frame { bytes })
    }

    /// Extract the destination MAC address.
    #[inline]
    #[must_use]
    pub fn mac_dest(&self) -> [u8; 6] {
        unsafe { offset_read(self.bytes, 0) }
    }

    /// Extract the source MAC address.
    #[inline]
    #[must_use]
    pub fn mac_src(&self) -> [u8; 6] {
        unsafe { offset_read(self.bytes, 6) }
    }

    /// Extract the length/type field.
    ///
    /// The value represents the length of the client data if it's value is less
    /// than or equal to 1500, and represents an `EtherType` if it is greater or
    /// equal to 1536. See section `3.2.6` of the standard for more info.
    #[inline]
    #[must_use]
    pub fn length_type(&self) -> LengthType {
        match u16::from_be_bytes(unsafe { offset_read(self.bytes, 12) }) {
            ETHERTYPE_IPV4 => LengthType::Type(EtherType::Ipv4),
            ETHERTYPE_IPV6 => LengthType::Type(EtherType::Ipv6),
            len if len <= MAX_LENTYPE_LEN => LengthType::Length(len),
            typ if typ >= MIN_LENTYPE_TYP => LengthType::Type(EtherType::Unknown(typ)),
            val => LengthType::Unknown(val),
        }
    }

    /// Extract the client data field.
    #[inline]
    #[must_use]
    pub fn client_data(&self) -> &'a [u8] {
        &self.bytes[14..]
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
/// clause `3.2.6`).
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum LengthType {
    Length(u16),
    Type(EtherType),
    Unknown(u16),
}

// See the [IANA list of EtherType
// values](https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml#ieee-802-numbers-1).
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum EtherType {
    Ipv4,
    Ipv6,
    Unknown(u16),
}

// Minimum length of an Ethernet frame.
const MIN_FRAME_LEN: usize = 64;
// When the length/type field is below this value it is considered a length.
const MAX_LENTYPE_LEN: u16 = 0x5DC;
// When the length/type field is above this value it is considered an EtherType.
const MIN_LENTYPE_TYP: u16 = 0x600;
// EtherType code for IPv4.
const ETHERTYPE_IPV4: u16 = 0x800;
// EtherType code for IPv6.
const ETHERTYPE_IPV6: u16 = 0x86DD;

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    // Ethernet frame captured using Wireshark.
    pub const FRAME: &'static [u8] = include_bytes!("../resources/packet.bin");

    #[test]
    fn has_expected_mac_dest_address() -> Result<(), Box<dyn Error>> {
        let frame = Frame::new(FRAME)?;
        assert_eq!(frame.mac_dest(), [0x74, 0xA6, 0xCD, 0xB1, 0xF9, 0x8B]);
        Ok(())
    }

    #[test]
    fn has_expected_mac_src_address() -> Result<(), Box<dyn Error>> {
        let frame = Frame::new(FRAME)?;
        assert_eq!(frame.mac_src(), [0xC2, 0x17, 0x54, 0x77, 0x7A, 0x64]);
        Ok(())
    }

    #[test]
    fn has_expected_length_type() -> Result<(), Box<dyn Error>> {
        let frame = Frame::new(FRAME)?;
        assert_eq!(frame.length_type(), LengthType::Type(EtherType::Ipv4));
        Ok(())
    }

    #[test]
    fn has_expected_client_data() -> Result<(), Box<dyn Error>> {
        let frame = Frame::new(FRAME)?;
        assert_eq!(frame.client_data(), &FRAME[14..]);
        Ok(())
    }

    #[test]
    fn has_expected_len() -> Result<(), Box<dyn Error>> {
        let frame = Frame::new(FRAME)?;
        assert_eq!(frame.len(), 126);
        Ok(())
    }
}
