#![warn(clippy::pedantic)]
#![allow(clippy::double_must_use)]

pub mod ethernet;
pub mod ipv4;

/// Everything that can go wrong when parsing the packets.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("invalid argument: {0}")]
    InvalidArgument(&'static str),
}

pub type Result<T> = std::result::Result<T, Error>;

// Read a value of type T at an arbitrary byte offset from a raw byte array.
#[inline]
#[must_use]
pub(crate) unsafe fn offset_read<T>(bytes: &[u8], offset: isize) -> T {
    (bytes.as_ptr().offset(offset) as *mut T).read()
}

// Read a slice of N elements at an arbitrary byte offset from a raw byte array.
#[inline]
#[must_use]
#[allow(dead_code)]
pub(crate) unsafe fn offset_slice(bytes: &[u8], offset: isize, len: usize) -> &[u8] {
    std::slice::from_raw_parts(bytes.as_ptr().offset(offset), len)
}

// Check if the nth bit is set
#[inline]
#[must_use]
pub(crate) fn bitset(byte: u8, n: usize) -> bool {
    byte & (1 << n) != 0
}
