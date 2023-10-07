#![warn(clippy::pedantic)]

pub mod ethernet;

/// Everything that can go wrong when parsing the packets.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("invalid argument: {0}")]
    InvalidArgument(&'static str),
}

// Read a value of type T at an arbitrary byte offset from a raw byte array.
#[inline]
#[must_use]
pub(crate) unsafe fn offset_read<'a, T>(bytes: &'a [u8], offset: isize) -> T {
    (bytes.as_ptr().offset(offset) as *mut T).read()
}

// Read a slice of N elements at an arbitrary byte offset from a raw byte array.
#[inline]
#[must_use]
#[allow(dead_code)]
pub(crate) unsafe fn offset_slice<'a>(bytes: &'a [u8], offset: isize, len: usize) -> &'a [u8] {
    std::slice::from_raw_parts(bytes.as_ptr().offset(offset), len)
}
