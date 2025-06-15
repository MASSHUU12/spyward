use std::fmt::Debug;

/// Common interface for any packet header.
pub trait Header: Sized + Debug {
    /// How many bytes you must have in `buf` to call `parse`
    const MIN_HEADER_SIZE: usize;

    /// Parse a header out of the first MIN_HEADER_SIZE bytes of `buf`
    fn parse(buf: &[u8]) -> Self;

    /// The real length of this header in bytes
    fn header_length(&self) -> usize;
}
