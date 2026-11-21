//! Chunk reader: takes a `(first_slice, start_offset)` pair and
//! returns the **decompressed** bytes for that chunk.
//!
//! Chunks are deduplicated by `(first_slice, start_offset)` -
//! multiple `FileLocation` entries can point at the same compressed
//! chunk (solid LZMA mode is the common case). The
//! [`crate::installer::InnoInstaller`] holds one
//! `OnceLock<Arc<[u8]>>` per unique chunk; the first call to
//! [`chunk_bytes`] for a given chunk index does the decompression
//! work, all subsequent calls return the cached `&[u8]` directly.
//!
//! Wire layout (innoextract `stream/chunk.cpp`):
//!
//! ```text
//! [ "zlb\x1a"          (4 bytes) ]   chunk magic
//! [ encryption header  (0|8 bytes)]  Plaintext: 0; ARC4_*: 8-byte salt
//! [ compressed bytes   ('size' bytes) ]
//! ```
//!
//! When the `ChunkEncrypted` flag is set on the data entry and no
//! [`EncryptionContext`] is supplied, [`decompress_chunk`] surfaces
//! [`Error::Encrypted`].

use std::{io, sync::Arc};

use bzip2::read::BzDecoder;
use flate2::read::ZlibDecoder;

use crate::{
    error::Error,
    header::{CompressMethod, HeaderTail},
    records::dataentry::{DataEntry, DataFlag},
    stream::block::{decompress_inno_lzma1, read_at_most},
    stream::slice::SliceReader,
};

/// Encryption parameters threaded through chunk decompression.
/// Two variants distinguish the modern (6.4+ XChaCha20) and the
/// legacy (pre-6.4 ARC4) paths - they have different key
/// derivation, different on-disk chunk layouts (legacy has an
/// 8-byte per-chunk salt prefix), and obviously different ciphers.
pub enum EncryptionContext<'a> {
    /// 6.4+ XChaCha20. `key` is PBKDF2-derived once per installer;
    /// per-chunk nonce comes from `base_nonce` XOR'd with the
    /// chunk's `(start_offset, first_slice)`.
    Modern {
        key: &'a [u8; 32],
        base_nonce: &'a [u8; 24],
    },
    /// Pre-6.4 ARC4. The per-chunk RC4 key is derived from
    /// `salt8 || password_bytes` with SHA-1 (5.3.9..6.4) or
    /// MD5 (pre-5.3.9). The 8-byte salt sits inside the chunk
    /// body, just after the `zlb\x1a` magic. `password_bytes` is
    /// UTF-16LE for Unicode builds and Windows-1252 for ANSI
    /// builds - innoextract picks the codepage in `info::get_key`
    /// (innoextract `setup/info.cpp`).
    Legacy {
        password: &'a str,
        /// `true` for 5.3.9..6.4 (SHA-1 keying), `false` for
        /// pre-5.3.9 (MD5).
        use_sha1: bool,
        /// `true` for Unicode builds (5.6+ default and any
        /// `(u)`-marker pre-5.6 build), `false` for ANSI.
        unicode: bool,
    },
}

const CHUNK_MAGIC: [u8; 4] = *b"zlb\x1a";

/// The method `data`'s chunk is compressed with, as Setup chooses it
/// (`TFileExtractor`; innoextract `setup/data.cpp`): stored without
/// [`DataFlag::ChunkCompressed`] (a `nocompression` file, 4.2.5+), bzip2
/// with the pre-4.0.1 [`DataFlag::BZipped`], else the header's
/// `CompressMethod`.
///
/// # Errors
///
/// [`Error::UnsupportedCompression`] when the chunk needs the header's
/// method and its byte is one this crate does not know.
pub fn chunk_method(data: &DataEntry, header: &HeaderTail) -> Result<CompressMethod, Error> {
    if !data.flags.contains(&DataFlag::ChunkCompressed) {
        return Ok(CompressMethod::Stored);
    }
    if data.flags.contains(&DataFlag::BZipped) {
        return Ok(CompressMethod::Bzip2);
    }
    header.compress_method.ok_or(Error::UnsupportedCompression {
        method: header.compress_method_raw,
    })
}

/// Decompresses the bytes of a chunk identified by the data entry's
/// `(first_slice, start_offset, chunk_compressed_size)` triple, with the
/// method [`chunk_method`] picks from the entry's flags and `header`.
///
/// When `encryption` is `Some` AND the data entry's
/// [`DataFlag::ChunkEncrypted`] is set, the chunk body is
/// XChaCha20-decrypted before decompression using a nonce derived
/// from `(base_nonce, data.start_offset, data.first_slice)` per the
/// Pascal `InitCryptContext` algorithm.
///
/// Decompresses no further than `needed` bytes: how far the furthest file
/// in the chunk reaches (its `chunk_sub_offset` plus `original_size`),
/// which is all Setup reads.
///
/// Caller is expected to wrap this in `OnceLock::get_or_init`.
pub fn decompress_chunk(
    slice: &SliceReader<'_>,
    data: &DataEntry,
    header: &HeaderTail,
    encryption: Option<&EncryptionContext<'_>>,
    needed: u64,
) -> Result<Arc<[u8]>, Error> {
    let compression = chunk_method(data, header)?;

    // For encrypted chunks, an EncryptionContext is required.
    // Without one, surface `Error::Encrypted` so the caller can
    // react (typically by re-parsing with a candidate password).
    let chunk_is_encrypted = data.flags.contains(&DataFlag::ChunkEncrypted);
    if chunk_is_encrypted && encryption.is_none() {
        return Err(Error::Encrypted);
    }

    // Read magic + payload from setup-1.
    // `chunk_compressed_size` is the size of the encrypted +
    // compressed body - it does NOT include the 4-byte magic.
    // The legacy ARC4 path additionally has an 8-byte per-chunk
    // salt sitting between the magic and the body, which is
    // OUTSIDE `chunk_compressed_size` (matches innoextract
    // `chunk.cpp:159-202`: the salt is read before `restrict(base,
    // chunk.size)` is pushed).
    let salt_overhead: u64 =
        if chunk_is_encrypted && matches!(encryption, Some(EncryptionContext::Legacy { .. })) {
            8
        } else {
            0
        };
    let magic_len: u64 = 4;
    let total = magic_len
        .checked_add(salt_overhead)
        .and_then(|n| n.checked_add(data.chunk_compressed_size))
        .ok_or(Error::Overflow {
            what: "chunk total bytes",
        })?;
    let region = slice.read_at(data.first_slice, data.last_slice, data.start_offset, total)?;
    let region: &[u8] = &region;

    let (magic, after_magic) = match region {
        [m0, m1, m2, m3, rest @ ..] => ([*m0, *m1, *m2, *m3], rest),
        _ => {
            return Err(Error::Truncated {
                what: "chunk header",
            });
        }
    };
    if magic != CHUNK_MAGIC {
        return Err(Error::BadChunkMagic { got: magic });
    }

    // Decrypt in place when applicable (we copy the body to an
    // owned buffer so we can mutate it). For plaintext chunks the
    // borrow stays - we only allocate when encryption forces us to.
    let owned_body: Vec<u8>;
    let compressed: &[u8] = if chunk_is_encrypted {
        let ctx = encryption.ok_or(Error::Encrypted)?;
        match ctx {
            EncryptionContext::Modern {
                key, base_nonce, ..
            } => {
                let nonce = crate::crypto::xchacha20::chunk_nonce(
                    base_nonce,
                    data.start_offset,
                    i32::try_from(data.first_slice).unwrap_or(0),
                );
                let mut buf = after_magic.to_vec();
                crate::crypto::xchacha20::apply_keystream(key, &nonce, &mut buf);
                owned_body = buf;
                &owned_body
            }
            EncryptionContext::Legacy {
                password,
                use_sha1,
                unicode,
            } => {
                // Split the 8-byte per-chunk salt off the body.
                let (salt_arr, body) = match after_magic {
                    [s0, s1, s2, s3, s4, s5, s6, s7, rest @ ..] => {
                        ([*s0, *s1, *s2, *s3, *s4, *s5, *s6, *s7], rest)
                    }
                    _ => {
                        return Err(Error::Truncated {
                            what: "ARC4 chunk salt",
                        });
                    }
                };
                let key = crate::crypto::kdflegacy::arc4_chunk_key(
                    password, &salt_arr, *use_sha1, *unicode,
                );
                let mut buf = body.to_vec();
                let mut cipher = crate::crypto::arc4::Rc4::new(&key);
                // ISCrypt.dll drops the first 1000 keystream bytes;
                // see `crypto::arc4::Rc4::discard`.
                cipher.discard(1000);
                cipher.apply(&mut buf);
                owned_body = buf;
                &owned_body
            }
        }
    } else {
        after_magic
    };

    // Decompress only as far as the chunk's files reach (`needed`): that is
    // all Setup reads, and a stream that claims more cannot make the
    // parser allocate it.
    let out = match compression {
        CompressMethod::Stored => compressed
            .get(..usize::try_from(needed).unwrap_or(usize::MAX))
            .unwrap_or(compressed)
            .to_vec(),
        // A zlib stream, header and Adler-32 trailer included, as
        // innoextract's `boost::iostreams::zlib_decompressor` reads it.
        CompressMethod::Zlib => read_at_most(ZlibDecoder::new(compressed), needed, "chunk Zlib")?,
        CompressMethod::Bzip2 => read_at_most(BzDecoder::new(compressed), needed, "chunk BZip2")?,
        // Inno's LZMA1 wrap: 5-byte properties + raw LZMA1, the same
        // framing as the setup-0 outer block.
        CompressMethod::Lzma1 => decompress_inno_lzma1(compressed, "chunk LZMA1", needed)?,
        CompressMethod::Lzma2 => {
            // Inno's LZMA2 wrap: 1-byte dictionary-size property +
            // raw LZMA2 stream. lzma-rust2 treats the dictionary size
            // as a hard window limit, so it must come from the
            // property byte rather than a fixed default.
            let [prop, stream @ ..] = compressed else {
                return Err(Error::Truncated {
                    what: "LZMA2 prop byte",
                });
            };
            let dict_size = lzma2_dict_size(*prop)?;
            read_at_most(
                lzma_rust2::Lzma2Reader::new(stream, dict_size, None),
                needed,
                "chunk LZMA2",
            )?
        }
    };

    Ok(Arc::<[u8]>::from(out))
}

/// Decodes the LZMA2 dictionary-size property byte: values 0..=39
/// encode `(2 | (p & 1)) << (p / 2 + 11)`, and 40 means 4 GiB - 1.
fn lzma2_dict_size(prop: u8) -> Result<u32, Error> {
    match prop {
        0..=39 => {
            let mantissa = 2 | u32::from(prop & 1);
            let shift = u32::from(prop / 2).saturating_add(11);
            Ok(mantissa << shift)
        }
        40 => Ok(u32::MAX),
        _ => Err(Error::Decompress {
            stream: "chunk LZMA2",
            source: io::Error::other(format!("invalid LZMA2 dictionary property {prop}")),
        }),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::{
        crypto::{arc4::Rc4, kdflegacy::arc4_chunk_key},
        records::dataentry::{DataChecksum, DataEntry, DataFlag},
    };

    /// Synthetic legacy ARC4 round-trip. Builds a fake encrypted
    /// chunk by hand:
    ///
    /// 1. Take a known plaintext payload.
    /// 2. Compress it via Inno's LZMA1 wrap (5-byte properties +
    ///    LZMA1 stream - same as the setup-0 outer block).
    /// 3. Pick a per-chunk salt; derive RC4 key via the
    ///    `chunk_salt || password_utf16le` rule.
    /// 4. RC4-encrypt the compressed body.
    /// 5. Wire `[zlb\x1a magic][salt][encrypted body]` into a
    ///    fake input buffer + craft a `DataEntry` pointing at it.
    /// 6. Call [`decompress_chunk`] with the `Legacy` context.
    /// 7. Expect the original plaintext back.
    ///
    /// This validates the chunk reader's Legacy branch end-to-end
    /// without requiring a real pre-6.4 installer sample.
    #[test]
    fn lzma2_dict_size_decodes_property_byte() {
        assert_eq!(lzma2_dict_size(0).unwrap(), 4 << 10);
        assert_eq!(lzma2_dict_size(1).unwrap(), 6 << 10);
        assert_eq!(lzma2_dict_size(24).unwrap(), 16 << 20);
        // `Compression=lzma2/ultra64` uses a 64 MiB dictionary.
        assert_eq!(lzma2_dict_size(28).unwrap(), 64 << 20);
        assert_eq!(lzma2_dict_size(39).unwrap(), 3 << 30);
        assert_eq!(lzma2_dict_size(40).unwrap(), u32::MAX);
        assert!(lzma2_dict_size(41).is_err());
    }

    #[test]
    fn legacy_arc4_round_trip_synthetic() {
        // 1. Plaintext payload.
        let plaintext = b"Inno test payload v1\n".to_vec();

        // 2. Compress with LZMA1-Inno wrap. lzma-rs's `lzma_compress`
        //    emits the LZMA-Alone 13-byte header (5 props + 8-byte
        //    uncompressed-size); strip the size bytes to get Inno's
        //    5-byte form.
        let mut compressed_lzma_alone: Vec<u8> = Vec::new();
        let mut input = std::io::Cursor::new(plaintext.clone());
        lzma_rs::lzma_compress(&mut input, &mut compressed_lzma_alone).unwrap();
        let mut inno_lzma1 = Vec::with_capacity(compressed_lzma_alone.len() - 8);
        inno_lzma1.extend_from_slice(&compressed_lzma_alone[..5]);
        inno_lzma1.extend_from_slice(&compressed_lzma_alone[13..]);

        // 3. Per-chunk salt + password.
        let salt = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let password = "test123";
        let key = arc4_chunk_key(
            password, &salt, true, /* SHA-1 */
            true, /* Unicode */
        );

        // 4. RC4-encrypt the compressed body in place. Match the
        //    real-installer drop-1000 keystream skip so the round
        //    trip exercises the same bytes the decrypt path will.
        let mut encrypted = inno_lzma1.clone();
        let mut enc = Rc4::new(&key);
        enc.discard(1000);
        enc.apply(&mut encrypted);

        // 5. Build the on-disk chunk: magic + salt + encrypted body
        //    inside a fake setup-1 region.
        let mut input_buf = vec![0u8; 0x100];
        let setup1_offset = input_buf.len() as u64;
        let chunk_start_in_setup1 = 0x42_u64;
        input_buf.resize(input_buf.len() + chunk_start_in_setup1 as usize, 0u8);
        input_buf.extend_from_slice(b"zlb\x1a");
        input_buf.extend_from_slice(&salt);
        input_buf.extend_from_slice(&encrypted);

        let slice = SliceReader::embedded(&input_buf, setup1_offset).unwrap();

        // 6. DataEntry pointing at the synthesized chunk.
        let mut flags = HashSet::new();
        flags.insert(DataFlag::ChunkEncrypted);
        flags.insert(DataFlag::ChunkCompressed);
        let data = DataEntry {
            first_slice: 0,
            last_slice: 0,
            start_offset: chunk_start_in_setup1,
            chunk_sub_offset: 0,
            original_size: plaintext.len() as u64,
            chunk_compressed_size: encrypted.len() as u64,
            checksum: DataChecksum::Sha256([0u8; 32]),
            timestamp_seconds: 0,
            timestamp_nanos: 0,
            file_version: 0,
            flags,
            flags_raw: vec![0],
            sign_mode: crate::records::dataentry::SignMode::NoSetting,
            sign_mode_raw: 0,
        };

        let ctx = EncryptionContext::Legacy {
            password,
            use_sha1: true,
            unicode: true,
        };

        // 7. Decompress and check.
        let header = HeaderTail {
            compress_method: Some(CompressMethod::Lzma1),
            ..HeaderTail::default()
        };
        let bytes = decompress_chunk(&slice, &data, &header, Some(&ctx), u64::MAX).unwrap();
        assert_eq!(bytes.as_ref(), plaintext.as_slice());
    }

    fn entry(flags: &[DataFlag], start_offset: u64, size: u64) -> DataEntry {
        DataEntry {
            first_slice: 0,
            last_slice: 0,
            start_offset,
            chunk_sub_offset: 0,
            original_size: size,
            chunk_compressed_size: size,
            checksum: DataChecksum::Sha256([0u8; 32]),
            timestamp_seconds: 0,
            timestamp_nanos: 0,
            file_version: 0,
            flags: flags.iter().copied().collect(),
            flags_raw: vec![0],
            sign_mode: crate::records::dataentry::SignMode::NoSetting,
            sign_mode_raw: 0,
        }
    }

    fn tail(method: Option<CompressMethod>, raw: u8) -> HeaderTail {
        HeaderTail {
            compress_method: method,
            compress_method_raw: raw,
            ..HeaderTail::default()
        }
    }

    /// Setup picks the method per chunk: stored without `ChunkCompressed`,
    /// bzip2 with `BZipped`, else the header's.
    #[test]
    fn chunk_method_follows_the_entry_flags() {
        let lzma = tail(Some(CompressMethod::Lzma2), 4);
        let method =
            |flags: &[DataFlag], header: &HeaderTail| chunk_method(&entry(flags, 0, 0), header);
        assert_eq!(method(&[], &lzma).unwrap(), CompressMethod::Stored);
        assert_eq!(
            method(&[DataFlag::ChunkCompressed], &lzma).unwrap(),
            CompressMethod::Lzma2
        );
        let zlib = tail(Some(CompressMethod::Zlib), 0);
        assert_eq!(
            method(&[DataFlag::ChunkCompressed, DataFlag::BZipped], &zlib).unwrap(),
            CompressMethod::Bzip2
        );
        let unknown = tail(None, 9);
        assert!(matches!(
            method(&[DataFlag::ChunkCompressed], &unknown),
            Err(Error::UnsupportedCompression { method: 9 })
        ));
        // A stored chunk needs no method, so an unknown one does not matter.
        assert_eq!(method(&[], &unknown).unwrap(), CompressMethod::Stored);
    }

    /// A `nocompression` file's chunk is its bytes as they are, even when
    /// the installer compresses everything else.
    #[test]
    fn a_chunk_decompresses_only_as_far_as_its_files_reach() {
        // 64 MiB of zeros, a few kilobytes of zlib: a bomb, unless the
        // decompression stops where the chunk's files end.
        use std::io::Write as _;
        let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
        let zeros = vec![0u8; 1 << 20];
        for _ in 0..64 {
            encoder.write_all(&zeros).unwrap();
        }
        let body = encoder.finish().unwrap();
        let mut input = vec![0u8; 0x40];
        input.extend_from_slice(b"zlb\x1a");
        input.extend_from_slice(&body);
        let slice = SliceReader::embedded(&input, 0x40).unwrap();
        let data = entry(&[DataFlag::ChunkCompressed], 0, body.len() as u64);
        let bytes = decompress_chunk(
            &slice,
            &data,
            &tail(Some(CompressMethod::Zlib), 1),
            None,
            1000,
        )
        .unwrap();
        assert_eq!(bytes.len(), 1000);
    }

    #[test]
    fn uncompressed_chunk_is_read_as_stored() {
        let body = b"stored as is";
        let mut input = vec![0u8; 0x40];
        input.extend_from_slice(b"zlb\x1a");
        input.extend_from_slice(body);
        let slice = SliceReader::embedded(&input, 0x40).unwrap();
        let data = entry(&[], 0, body.len() as u64);
        let bytes = decompress_chunk(
            &slice,
            &data,
            &tail(Some(CompressMethod::Lzma1), 3),
            None,
            u64::MAX,
        )
        .unwrap();
        assert_eq!(bytes.as_ref(), body);
    }
}
