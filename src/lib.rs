//! Fast, safe network packet parsing.
//!
//! ## Performance
//!
//! This crate never allocates heap memory. It exclusively uses references to
//! pre-allocated byte slices. This means it can read and write to the *exact*
//! same buffers used by network devices, making it suitable as part of a
//! zero-copy networking stack. Packet fields are only parsed and written when
//! they're used, meaning that callers only pay for the protocol features they
//! actually use.
//!
//! The only "gotcha" is that the payload setter fields, like
//! [`PacketBuilder::payload`](crate::ipv4::PacketBuilder::payload), accept a
//! [`Read`](std::io::Read) parameter that is used to write bytes directly into
//! the underlying packet buffer. It is the responsibility of the caller to make
//! sure this [`Read`](std::io::Read) is efficient.
//!
//! Fields are returned by value (i.e. copied) when they are small, like an IPv4
//! address. Passing them by reference requires a pointer anyway, which is
//! already 8 bytes long on a 64-bit system.
//!
//! This gives us the following benefits:
//!
//! * Removes redundant runtime checks, because only one check is needed in the constructor
//! * Allows the API to return constant-sized arrays
//! * Allows the API to return more values directly, rather than wrapping them in a [`Result`]
#![warn(clippy::pedantic)]
#![allow(clippy::double_must_use)]
#![allow(clippy::many_single_char_names)]
#![allow(clippy::len_without_is_empty)]

pub mod arp;
pub mod enet;
pub mod icmp;
pub mod ipv4;
pub mod tcp;
pub mod udp;

mod checksum;

/// Utility wrapper for packet parsing results.
pub type Result<T> = std::result::Result<T, Error>;

/// Everything that can go wrong when parsing the packets.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("invalid argument: {0}")]
    CannotParse(&'static str),
    #[error("not enough space: {0}")]
    NotEnoughSpace(&'static str),
    #[error("io error: {0}")]
    IoError(std::io::Error),
}

// Read all the bytes from `src` and write them into `dst`.
//
// # Errors
//
// Returns an error when [`Read`](std::io::Read) returns any error other
// than [`ErrorKind::Interrupted`](std::io::ErrorKind::Interrupted).
pub(crate) fn write_all_bytes<R: std::io::Read>(mut src: R, dst: &mut [u8]) -> Result<()> {
    let mut read = 0;
    while read < dst.len() {
        match src.read(dst) {
            Ok(0) => break,
            Ok(n) => read += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(Error::IoError(e)),
        }
    }
    Ok(())
}

// Check if the nth bit is set
#[inline]
#[must_use]
pub(crate) fn bitset(byte: u8, n: usize) -> bool {
    byte & (1 << n) != 0
}

// Set bits of dst from src according to mask.
#[must_use]
#[inline]
pub(crate) fn setbits(a: u8, b: u8, mask: u8) -> u8 {
    (a & !mask) | (b & mask)
}

#[cfg(test)]
mod tests {
    use super::{bitset, setbits};

    #[test]
    fn bitset_returns_expected_value() {
        assert_eq!(bitset(0b0000_00100, 2), true);
    }

    #[test]
    fn setbits_returns_expected_value() {
        assert_eq!(setbits(0b0000_0000, 0b1111_1111, 0b1111_0000), 0b1111_0000);
    }
}
