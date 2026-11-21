//! `setup-0` block decompression.
//!
//! Upstream: `TCompressedBlockReader` (issrc `Projects/Src/Compression.Base.pas`);
//! reader reference: innoextract `stream/block.cpp`.
//!
//! ## Outer header (4.0.9+)
//!
//! ```text
//! [ expected_crc32 (4) | stored_size (4; 8 from 6.7.0) | compressed_flag (1) ]
//! ```
//!
//! `TCompressedBlockHeader`: 9 bytes, 13 from 6.7.0, whose `StoredSize` is
//! an `Int64`. `expected_crc32` covers `stored_size` + `compressed_flag`
//! only - it is the integrity check on the *outer* header itself, not the
//! payload. `compressed_flag == 0` ⇒ Stored. Otherwise: Zlib for
//! `< 4.1.6`, LZMA1 for `≥ 4.1.6`. A block of 4 GiB or more is refused
//! ([`Error::Overflow`]).
//!
//! ## Outer header (< 4.0.9)
//!
//! ```text
//! [ expected_crc32 (4) | compressed_size (4) | uncompressed_size (4) ]
//! ```
//!
//! `compressed_size == 0xFFFF_FFFF` ⇒ Stored, with the raw size in
//! `uncompressed_size`; otherwise Zlib. Older installers store the
//! 4 KiB CRC overhead *outside* the size figure, so we add it back:
//! `stored_size += ceil(stored_size / 4096) * 4`.
//!
//! ## Inner framing
//!
//! After the outer header the next `stored_size` bytes are a sequence
//! of **4 KiB sub-chunks**, each prefixed by a 4-byte CRC32 over the
//! sub-chunk's compressed bytes. The last sub-chunk may be shorter.
//! Stripping the CRC prefixes yields the zlib / LZMA1 stream.
//!
//! ## LZMA1 wrapping
//!
//! Inno's LZMA1 stream uses a non-standard 5-byte header rather than
//! the LZMA-Alone 13-byte form: byte 0 is the lc/lp/pb properties
//! triple encoded as `pb*45 + lp*9 + lc`, bytes 1..4 are the
//! little-endian dictionary size. There is no 8-byte uncompressed
//! size - instead the bitstream ends with an end-of-payload marker.
//! We hand the properties to `lzma_rust2::LzmaReader::new_with_props`
//! with an unknown uncompressed size, so the decoder stops at that
//! marker.

use crate::{error::Error, version::Version};

/// Compression method declared in the block's outer header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum BlockCompression {
    /// `compressed_flag == 0` - sub-chunks are uncompressed.
    Stored,
    /// `< 4.1.6` and `compressed_flag != 0` - a zlib stream after
    /// CRC stripping.
    Zlib,
    /// `≥ 4.1.6` and `compressed_flag != 0` - LZMA1 stream with
    /// Inno's 5-byte properties header.
    Lzma1,
}

stable_name_enum!(BlockCompression, {
    Self::Stored => "stored",
    Self::Zlib => "zlib",
    Self::Lzma1 => "lzma1",
});

/// Result of [`decompress_block`].
#[derive(Debug)]
pub struct DecompressedBlock {
    /// Decompressed bytes. Owned so that downstream record views can
    /// borrow from a stable buffer for the lifetime of the
    /// `InnoInstaller`.
    pub bytes: Box<[u8]>,
    /// Compression method that produced `bytes`.
    pub compression: BlockCompression,
    /// Total bytes consumed from the input - outer header (12 bytes
    /// before 4.0.9, 9 from 4.0.9, 13 from 6.7.0) plus `stored_size`.
    pub consumed: usize,
}

/// Decompresses one block from `setup0[start..]`.
///
/// `start` is the byte offset of the block within the (already-located)
/// setup-0 region - i.e. where the outer header begins. The function
/// reads the outer header, validates its CRC, walks the inner 4 KiB
/// CRC-framed sub-chunks, and feeds the concatenated compressed bytes
/// to the appropriate decompressor.
///
/// # Errors
///
/// - [`Error::Truncated`] / [`Error::Overflow`] on out-of-bounds
///   reads.
/// - [`Error::BadChecksum`] if the outer-header CRC or any inner
///   sub-chunk CRC fails.
/// - [`Error::Decompress`] on LZMA / Zlib decoder failures.
pub fn decompress_block(
    setup0: &[u8],
    start: usize,
    version: &Version,
) -> Result<DecompressedBlock, Error> {
    crate::stream::block::decompress(setup0, start, version, None)
}
