//! `setup-0` block decompression.
//!
//! Format reference: `RESEARCH.md` §4 and
//! `research-notes/05-streams-and-compression.md` §"Block (setup-0)";
//! canonical implementation `research/src/stream/block.cpp`.
//!
//! ## Outer header (≥ 4.0.9)
//!
//! ```text
//! [ expected_crc32 (4) | stored_size (4) | compressed_flag (1) ]
//! ```
//!
//! `expected_crc32` covers `stored_size` + `compressed_flag` only —
//! it is the integrity check on the *outer* header itself, not the
//! payload. `compressed_flag == 0` ⇒ Stored. Otherwise: Zlib for
//! `< 4.1.6`, LZMA1 for `≥ 4.1.6`.
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
//! Stripping the CRC prefixes yields the raw deflate / LZMA1 stream.
//!
//! ## LZMA1 wrapping
//!
//! Inno's LZMA1 stream uses a non-standard 5-byte header rather than
//! the LZMA-Alone 13-byte form: byte 0 is the lc/lp/pb properties
//! triple encoded as `pb*45 + lp*9 + lc`, bytes 1..4 are the
//! little-endian dictionary size. There is no 8-byte uncompressed
//! size — instead the bitstream ends with an end-of-payload marker.
//! We feed this directly to `lzma_rs` via
//! [`lzma_rs::decompress::UnpackedSize::UseProvided`]`(None)`.

use std::io::{Cursor, Read as _};

use flate2::read::ZlibDecoder;
use lzma_rust2::LzmaReader;

use crate::{
    error::Error,
    util::{checksum::crc32, read::Reader},
    version::Version,
};

/// Inner sub-chunk size in bytes. Fixed by the format (every chunk
/// except the last is exactly this size).
const CHUNK_SIZE: usize = 4096;
/// Length of the 4-byte CRC32 prefix on each sub-chunk.
const CHUNK_CRC_LEN: usize = 4;

/// Compression method declared in the block's outer header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum BlockCompression {
    /// `compressed_flag == 0` — sub-chunks are uncompressed.
    Stored,
    /// `< 4.1.6` and `compressed_flag != 0` — Deflate stream after
    /// CRC stripping.
    Zlib,
    /// `≥ 4.1.6` and `compressed_flag != 0` — LZMA1 stream with
    /// Inno's 5-byte properties header.
    Lzma1,
}

/// Result of [`decompress_block`].
#[derive(Debug)]
pub struct DecompressedBlock {
    /// Decompressed bytes. Owned so that downstream record views can
    /// borrow from a stable buffer for the lifetime of the
    /// `InnoInstaller`.
    pub bytes: Box<[u8]>,
    /// Compression method that produced `bytes`.
    pub compression: BlockCompression,
    /// Total bytes consumed from the input — outer header (9 bytes
    /// for ≥ 4.0.9, 12 for < 4.0.9) plus `stored_size`.
    pub consumed: usize,
}

/// Decompresses one block from `setup0[start..]`.
///
/// `start` is the byte offset of the block within the (already-located)
/// setup-0 region — i.e. where the outer header begins. The function
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
    decompress_block_inner(setup0, start, version, None)
}

/// Same as [`decompress_block`] but applies XChaCha20 decryption
/// to the unframed (post-CRC-strip) compressed bytes before
/// decompression. Used for `euFull` (6.5+) installers where the
/// inner 4 KiB sub-chunks are XChaCha20-encrypted under a special
/// crypt context (`sccCompressedBlocks1` for setup-0 records,
/// `sccCompressedBlocks2` for the data-entries block).
///
/// Per Pascal `TCompressedBlockWriter.FlushOutputBuffer`
/// (`research/issrc/Projects/Src/Compression.Base.pas`):
///
/// ```text
/// for each 4 KiB sub-chunk:
///   1. Encrypt the chunk in place under XChaCha20 (state shared
///      across all sub-chunks within the block).
///   2. CRC32 the ENCRYPTED bytes.
///   3. Write [CRC32 LE u32][encrypted bytes].
/// ```
///
/// The reader inverts: validate CRC over encrypted bytes (= our
/// existing `unframe_chunks`), then decrypt the concatenated body.
pub(crate) fn decompress_block_with_decryption(
    setup0: &[u8],
    start: usize,
    version: &Version,
    key: &[u8; 32],
    nonce: &[u8; 24],
) -> Result<DecompressedBlock, Error> {
    decompress_block_inner(setup0, start, version, Some((key, nonce)))
}

fn decompress_block_inner(
    setup0: &[u8],
    start: usize,
    version: &Version,
    decryption: Option<(&[u8; 32], &[u8; 24])>,
) -> Result<DecompressedBlock, Error> {
    let mut reader = Reader::at(setup0, start)?;

    let (compression, stored_size, header_consumed) = parse_outer_header(&mut reader, version)?;

    let stored_usize = usize::try_from(stored_size).map_err(|_| Error::Overflow {
        what: "stored_size",
    })?;

    let compressed_start = reader.pos();
    let compressed_end = compressed_start
        .checked_add(stored_usize)
        .ok_or(Error::Overflow {
            what: "compressed end",
        })?;
    let framed = setup0
        .get(compressed_start..compressed_end)
        .ok_or(Error::Truncated {
            what: "block compressed body",
        })?;

    let mut raw = unframe_chunks(framed)?;

    // euFull decryption applies AFTER CRC validation (CRCs cover
    // the encrypted bytes) and BEFORE decompression. XChaCha20
    // state is continuous across the 4 KiB sub-chunks within a
    // single block, so we can apply the keystream once over the
    // concatenated unframed bytes.
    if let Some((key, nonce)) = decryption {
        crate::crypto::xchacha20::apply_keystream(key, nonce, &mut raw);
    }

    let bytes = match compression {
        BlockCompression::Stored => raw.into_boxed_slice(),
        BlockCompression::Zlib => decompress_zlib(&raw)?.into_boxed_slice(),
        BlockCompression::Lzma1 => decompress_inno_lzma1(&raw)?.into_boxed_slice(),
    };

    let consumed = header_consumed
        .checked_add(stored_usize)
        .ok_or(Error::Overflow { what: "block end" })?;

    Ok(DecompressedBlock {
        bytes,
        compression,
        consumed,
    })
}

fn parse_outer_header(
    reader: &mut Reader<'_>,
    version: &Version,
) -> Result<(BlockCompression, u32, usize), Error> {
    let expected_crc = reader.u32_le("block expected_crc")?;

    if version.at_least(6, 7, 0) {
        // Inno Setup 6.7.0+ widened `TCompressedBlockHeader.StoredSize`
        // from `Integer` (Int32) to `Int64` — see issrc commit
        // `8f02a4c0` (2025-11-26, "Update totals to Int64"). The
        // outer header is now 4 (CRC) + 8 (size) + 1 (flag) = 13
        // bytes; the CRC covers the trailing 9 bytes only.
        let header9 = reader.array::<9>("block header (>=6.7.0)")?;
        let actual_crc = crc32(&header9);
        if actual_crc != expected_crc {
            return Err(Error::BadChecksum {
                what: "block header (>=6.7.0)",
                expected: expected_crc,
                actual: actual_crc,
            });
        }
        let [s0, s1, s2, s3, s4, s5, s6, s7, flag] = header9;
        let stored_size_u64 = u64::from_le_bytes([s0, s1, s2, s3, s4, s5, s6, s7]);
        // Downstream still expects u32. Reject sizes ≥ 4 GiB rather
        // than truncate silently — these would be pathological setup-0
        // blocks (or adversarial input).
        let stored_size = u32::try_from(stored_size_u64).map_err(|_| Error::Overflow {
            what: "block stored_size > u32::MAX",
        })?;
        let compression = if flag == 0 {
            BlockCompression::Stored
        } else {
            BlockCompression::Lzma1
        };
        // Header consumed: 4 (expected_crc) + 9 (size+flag) = 13 bytes.
        Ok((compression, stored_size, 13))
    } else if version.at_least(4, 0, 9) {
        let header5 = reader.array::<5>("block header (>=4.0.9)")?;
        let actual_crc = crc32(&header5);
        if actual_crc != expected_crc {
            return Err(Error::BadChecksum {
                what: "block header (>=4.0.9)",
                expected: expected_crc,
                actual: actual_crc,
            });
        }
        let [s0, s1, s2, s3, flag] = header5;
        let stored_size = u32::from_le_bytes([s0, s1, s2, s3]);
        let compression = if flag == 0 {
            BlockCompression::Stored
        } else if version.at_least(4, 1, 6) {
            BlockCompression::Lzma1
        } else {
            BlockCompression::Zlib
        };
        // Header consumed: 4 (expected_crc) + 5 (size+flag) = 9 bytes.
        Ok((compression, stored_size, 9))
    } else {
        let header8 = reader.array::<8>("block header (<4.0.9)")?;
        let actual_crc = crc32(&header8);
        if actual_crc != expected_crc {
            return Err(Error::BadChecksum {
                what: "block header (<4.0.9)",
                expected: expected_crc,
                actual: actual_crc,
            });
        }
        let [c0, c1, c2, c3, u0, u1, u2, u3] = header8;
        let compressed_size = u32::from_le_bytes([c0, c1, c2, c3]);
        let uncompressed_size = u32::from_le_bytes([u0, u1, u2, u3]);
        let (mut stored_size, compression) = if compressed_size == u32::MAX {
            (uncompressed_size, BlockCompression::Stored)
        } else {
            (compressed_size, BlockCompression::Zlib)
        };
        // Older path stores the 4 KiB CRC overhead *outside* the size
        // figure — add it back so callers can locate the next block.
        // Compute `chunks = ceil(stored_size / CHUNK_SIZE)` =
        // `(stored_size + CHUNK_SIZE - 1) / CHUNK_SIZE` using
        // checked arithmetic.
        const CHUNK_SIZE_U32: u32 = CHUNK_SIZE as u32;
        const CHUNK_SIZE_MINUS_1: u32 = CHUNK_SIZE_U32.wrapping_sub(1);
        const CHUNK_CRC_LEN_U32: u32 = CHUNK_CRC_LEN as u32;
        let bumped = stored_size
            .checked_add(CHUNK_SIZE_MINUS_1)
            .ok_or(Error::Overflow {
                what: "old block ceil",
            })?;
        let chunks = bumped.checked_div(CHUNK_SIZE_U32).ok_or(Error::Overflow {
            what: "old block ceil-div",
        })?;
        let crc_overhead = chunks
            .checked_mul(CHUNK_CRC_LEN_U32)
            .ok_or(Error::Overflow {
                what: "old block CRC overhead",
            })?;
        stored_size = stored_size
            .checked_add(crc_overhead)
            .ok_or(Error::Overflow {
                what: "old stored_size",
            })?;
        // Header consumed: 4 (expected_crc) + 8 (sizes) = 12 bytes.
        Ok((compression, stored_size, 12))
    }
}

/// Strips the per-sub-chunk 4-byte CRC32 prefixes and concatenates
/// the remainder.
fn unframe_chunks(framed: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(framed.len());
    let mut cursor = 0usize;

    while cursor < framed.len() {
        let crc_end = cursor.checked_add(CHUNK_CRC_LEN).ok_or(Error::Overflow {
            what: "chunk CRC end",
        })?;
        let crc_bytes = framed
            .get(cursor..crc_end)
            .ok_or(Error::Truncated { what: "chunk CRC" })?;
        let mut crc_arr = [0u8; 4];
        crc_arr.copy_from_slice(crc_bytes);
        let expected = u32::from_le_bytes(crc_arr);

        let chunk_start = crc_end;
        let remaining = framed.len().saturating_sub(chunk_start);
        let chunk_len = remaining.min(CHUNK_SIZE);
        let chunk_end = chunk_start
            .checked_add(chunk_len)
            .ok_or(Error::Overflow { what: "chunk end" })?;
        let chunk = framed
            .get(chunk_start..chunk_end)
            .ok_or(Error::Truncated { what: "chunk body" })?;

        let actual = crc32(chunk);
        if actual != expected {
            return Err(Error::BadChecksum {
                what: "block sub-chunk",
                expected,
                actual,
            });
        }

        out.extend_from_slice(chunk);
        cursor = chunk_end;
    }

    Ok(out)
}

fn decompress_zlib(raw: &[u8]) -> Result<Vec<u8>, Error> {
    let mut decoder = ZlibDecoder::new(raw);
    let mut out = Vec::new();
    decoder
        .read_to_end(&mut out)
        .map_err(|source| Error::Decompress {
            stream: "block (zlib)",
            source,
        })?;
    Ok(out)
}

fn decompress_inno_lzma1(raw: &[u8]) -> Result<Vec<u8>, Error> {
    // Inno's 5-byte LZMA1 properties header: byte 0 is
    // `pb*45 + lp*9 + lc`, bytes 1..4 are LE dict_size. lzma-rust2's
    // LzmaReader consumes a standard 13-byte LZMA-Alone header, so pad
    // the 5-byte Inno header with the 8-byte unknown-size sentinel
    // (u64::MAX) and rely on the end-of-payload marker — the same
    // stream shape the nsis crate decodes.
    let mut header = Vec::with_capacity(raw.len().saturating_add(8));
    header.extend_from_slice(raw.get(..5).ok_or_else(|| Error::Decompress {
        stream: "block (lzma1)",
        source: std::io::Error::other("LZMA1 header too short"),
    })?);
    header.extend_from_slice(&u64::MAX.to_le_bytes());
    header.extend_from_slice(raw.get(5..).unwrap_or(&[]));

    let mut out = Vec::new();
    let mut reader =
        LzmaReader::new_mem_limit(Cursor::new(header), u32::MAX, None).map_err(|e| {
            Error::Decompress {
                stream: "block (lzma1)",
                source: std::io::Error::other(e.to_string()),
            }
        })?;
    std::io::copy(&mut reader, &mut out).map_err(|e| Error::Decompress {
        stream: "block (lzma1)",
        source: e,
    })?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unframe_strips_crc_prefixes() {
        // Two sub-chunks: a full 4096-byte one followed by a short
        // final one. Inno guarantees every non-final sub-chunk is
        // exactly CHUNK_SIZE.
        let chunk_a: Vec<u8> = (0..CHUNK_SIZE).map(|i| (i & 0xFF) as u8).collect();
        let chunk_b = b"final-tail".to_vec();
        let crc_a = super::crc32(&chunk_a);
        let crc_b = super::crc32(&chunk_b);
        let mut framed = Vec::new();
        framed.extend_from_slice(&crc_a.to_le_bytes());
        framed.extend_from_slice(&chunk_a);
        framed.extend_from_slice(&crc_b.to_le_bytes());
        framed.extend_from_slice(&chunk_b);

        let raw = unframe_chunks(&framed).unwrap();
        assert_eq!(raw.len(), chunk_a.len() + chunk_b.len());
        assert_eq!(&raw[..CHUNK_SIZE], chunk_a.as_slice());
        assert_eq!(&raw[CHUNK_SIZE..], chunk_b.as_slice());
    }

    #[test]
    fn unframe_rejects_bad_crc() {
        let mut framed = vec![0u8; 4];
        framed.extend_from_slice(b"abcd");
        let err = unframe_chunks(&framed).unwrap_err();
        assert!(matches!(err, Error::BadChecksum { .. }));
    }
}
