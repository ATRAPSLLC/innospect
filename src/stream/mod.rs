//! The compressed streams inside an installer: setup-0's CRC-framed
//! blocks, setup-1's chunks and slices, the BCJ filter, and the checksums
//! that guard extracted files.
//!
//! Internal: the public view is [`crate::decompress`] and
//! [`crate::extract`].

pub mod bcj;
pub mod block;
pub mod checksum;
pub mod chunk;
pub mod file;
pub mod slice;
