//! Decompression layer.
//!
//! Handles the blocks setup-0 is stored in: an outer header (see
//! [`block`]) followed by a sequence of 4 KiB CRC32-prefixed sub-chunks.
//! The un-prefixed sub-chunks concatenate into an LZMA1 / zlib / stored
//! stream.
//!
//! The setup-1 chunk stream uses a different framing and lives in
//! the internal `stream::chunk` module; [`crate::extract`] is its public face.
//!
//! Upstream: `TCompressedBlockReader` (issrc
//! `Projects/Src/Compression.Base.pas`).

pub mod block;

pub use block::{BlockCompression, decompress_block};
