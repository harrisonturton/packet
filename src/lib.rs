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
//! ## Safety
//!
//! Consuming the slice on-demand creates a problem with Rust's existing type
//! system. There are many cases where values need to be pulled out of this byte
//! slice that are known to exist, but this cannot be verified at compile time.
//! For example, it's clear that if the byte slice is longer than the minimum
//! header size of an IPv4 packet (20 bytes) it is memory safe to parse the
//! bytes at offset `2..4` into a `u16` field.
//!
//! But we cannot do this in safe-only Rust, because the type system does not
//! allow us to extract constant-sized arrays from a slice at runtime. This is
//! due to const generics being a compile-time-only feature, blocking the
//! ability to use methods like [`u16::from_be_bytes`], forcing us to perform
//! multiple runtime boundary checks to satisfy the type system.
//!
//! Instead, this crate uses `unsafe` to directly index the bytes and return
//! primitive types. This interface is safe because the slice length is checked
//! when each type is constructed, which guarantees that the memory accesses are
//! valid.
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

pub mod ethernet;
pub mod ipv4;
pub mod udp;

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

// Read all the bytes from `src` into `dst`.
//
// # Errors
//
// Returns an error when [`Read`](std::io::Read) returns any error other
// than [`ErrorKind::Interrupted`](std::io::ErrorKind::Interrupted).
pub(crate) fn read_all_bytes<R: std::io::Read>(mut src: R, dst: &mut [u8]) -> Result<()> {
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

// Get a constant pointer to a T at an arbitrary byte offset in a byte array
#[inline]
#[must_use]
pub(crate) unsafe fn offset_ptr<T>(source: &[u8], offset: isize) -> *const T {
    source.as_ptr().offset(offset).cast()
}

// Get a mutable pointer to a T at an arbitrary byte offset in a byte array
#[inline]
#[must_use]
pub(crate) unsafe fn offset_mut_ptr<T>(source: &mut [u8], offset: isize) -> *mut T {
    source.as_mut_ptr().offset(offset).cast()
}

// Read a value of type T at an arbitrary byte offset from a byte array.
#[inline]
#[must_use]
pub(crate) unsafe fn offset_read<T>(source: &[u8], offset: isize) -> T {
    (source.as_ptr().offset(offset) as *mut T).read()
}

// Write a value of type T at an arbitrary byte offset from a byte array. This
// copies the bytes from `value` into `dest`.
#[inline]
pub(crate) unsafe fn offset_write(dest: &mut [u8], offset: usize, value: &[u8]) {
    dest[offset..offset + value.len()].copy_from_slice(value);
}

// Write a byte slice to a raw byte array.
#[inline]
pub(crate) unsafe fn ptr_write<T, K: AsRef<[u8]>>(dst: *mut T, src: K) {
    std::ptr::copy_nonoverlapping(src.as_ref().as_ptr(), dst.cast(), src.as_ref().len());
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
    use super::{bitset, offset_read, offset_write, setbits};

    #[test]
    fn offset_read_returns_expected_value() {
        let bytes = &[0, 0xFF, 0xF, 0, 0];
        assert_eq!(unsafe { offset_read::<u16>(bytes, 1) }, 0xFFF);
    }

    #[test]
    fn offset_write_performs_expected_mutation() -> Result<(), Box<dyn std::error::Error>> {
        let bytes = &mut [0, 0, 0, 0, 0];
        unsafe { offset_write(bytes, 1, &[0xA, 0xB]) };
        assert_eq!(&[0, 0xA, 0xB, 0, 0], bytes);
        Ok(())
    }

    #[test]
    fn bitset_returns_expected_value() {
        assert_eq!(bitset(0b0000_00100, 2), true);
    }

    #[test]
    fn setbits_returns_expected_value() {
        assert_eq!(setbits(0b0000_0000, 0b1111_1111, 0b1111_0000), 0b1111_0000);
    }
}
