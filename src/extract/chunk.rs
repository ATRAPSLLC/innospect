//! Chunk reader: takes a `(first_slice, start_offset)` pair and
//! returns the **decompressed** bytes for that chunk.
//!
//! Chunks are deduplicated by `(first_slice, start_offset)` —
//! multiple `FileLocation` entries can point at the same compressed
//! chunk (solid LZMA mode is the common case). The
//! [`crate::installer::InnoInstaller`] holds one
//! `OnceLock<Arc<[u8]>>` per unique chunk; the first call to
//! [`chunk_bytes`] for a given chunk index does the decompression
//! work, all subsequent calls return the cached `&[u8]` directly.
//!
//! Wire layout (`research/src/stream/chunk.cpp:159-185`):
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

use std::{
    io::{self, Read as _},
    sync::Arc,
};

use bzip2::read::BzDecoder;
use flate2::read::ZlibDecoder;

use crate::{
    error::Error,
    extract::slice::SliceReader,
    header::CompressMethod,
    installer::EncryptionMode,
    records::dataentry::{DataEntry, DataFlag},
};

/// Encryption parameters threaded through chunk decompression.
/// Two variants distinguish the modern (6.4+ XChaCha20) and the
/// legacy (pre-6.4 ARC4) paths — they have different key
/// derivation, different on-disk chunk layouts (legacy has an
/// 8-byte per-chunk salt prefix), and obviously different ciphers.
pub(crate) enum EncryptionContext<'a> {
    /// 6.4+ XChaCha20. `key` is PBKDF2-derived once per installer;
    /// per-chunk nonce comes from `base_nonce` XOR'd with the
    /// chunk's `(start_offset, first_slice)`.
    Modern {
        key: &'a [u8; 32],
        base_nonce: &'a [u8; 24],
        // Carried for parity with the upstream wire layout; the
        // chunk-decrypt path keys + nonces alone, mode is consumed
        // by the setup-0 decompression branch in the installer.
        #[allow(dead_code)]
        mode: EncryptionMode,
    },
    /// Pre-6.4 ARC4. The per-chunk RC4 key is derived from
    /// `salt8 || password_bytes` with SHA-1 (5.3.9..6.4) or
    /// MD5 (pre-5.3.9). The 8-byte salt sits inside the chunk
    /// body, just after the `zlb\x1a` magic. `password_bytes` is
    /// UTF-16LE for Unicode builds and Windows-1252 for ANSI
    /// builds — innoextract picks the codepage in `info::get_key`
    /// (`research/src/setup/info.cpp:322-352`).
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

/// Decompresses the bytes of a chunk identified by the data entry's
/// `(first_slice, start_offset, chunk_compressed_size)` triple plus
/// the installer's per-chunk compression method.
///
/// When `encryption` is `Some` AND the data entry's
/// [`DataFlag::ChunkEncrypted`] is set, the chunk body is
/// XChaCha20-decrypted before decompression using a nonce derived
/// from `(base_nonce, data.start_offset, data.first_slice)` per the
/// Pascal `InitCryptContext` algorithm.
///
/// Caller is expected to wrap this in `OnceLock::get_or_init`.
pub(crate) fn decompress_chunk(
    slice: &SliceReader<'_>,
    data: &DataEntry,
    compression: CompressMethod,
    encryption: Option<&EncryptionContext<'_>>,
) -> Result<Arc<[u8]>, Error> {
    if data.first_slice != data.last_slice {
        return Err(Error::MultiSliceChunk {
            first: data.first_slice,
            last: data.last_slice,
        });
    }

    // For encrypted chunks, an EncryptionContext is required.
    // Without one, surface `Error::Encrypted` so the caller can
    // react (typically by re-parsing with a candidate password).
    let chunk_is_encrypted = data.flags.contains(&DataFlag::ChunkEncrypted);
    if chunk_is_encrypted && encryption.is_none() {
        return Err(Error::Encrypted);
    }

    // Read magic + payload from setup-1.
    // `chunk_compressed_size` is the size of the encrypted +
    // compressed body — it does NOT include the 4-byte magic.
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
    let region = slice.read_at(data.first_slice, data.start_offset, total)?;

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
    // borrow stays — we only allocate when encryption forces us to.
    let owned_body: Vec<u8>;
    let compressed: &[u8] = if chunk_is_encrypted {
        let ctx = encryption.ok_or(Error::Encrypted)?;
        match ctx {
            EncryptionContext::Modern {
                key, base_nonce, ..
            } => {
                let nonce = crate::crypto::xchacha20::chunk_nonce(
                    base_nonce,
                    u64::from(data.start_offset),
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

    // Allocate `original_size`-sized output up front. We don't have
    // an explicit decompressed size on the wire; the caller knows
    // the sum-of-files-in-this-chunk (from data entries that share
    // it) but doesn't pre-aggregate that — let the decompressor
    // grow as needed.
    let mut out = Vec::<u8>::new();

    match compression {
        CompressMethod::Stored => {
            out.extend_from_slice(compressed);
        }
        CompressMethod::Zlib => {
            // Inno's Zlib chunks use the raw deflate stream (no
            // zlib wrapper). innoextract uses
            // `boost::iostreams::zlib_decompressor` — we use
            // flate2's `ZlibDecoder` first and fall back to
            // `DeflateDecoder` if a sample later proves the wrapper
            // is absent.
            let mut dec = ZlibDecoder::new(compressed);
            dec.read_to_end(&mut out).map_err(|e| Error::Decompress {
                stream: "chunk Zlib",
                source: e,
            })?;
        }
        CompressMethod::Bzip2 => {
            let mut dec = BzDecoder::new(compressed);
            dec.read_to_end(&mut out).map_err(|e| Error::Decompress {
                stream: "chunk BZip2",
                source: e,
            })?;
        }
        CompressMethod::Lzma1 => {
            // Inno's LZMA1 wrap: 5-byte properties + raw LZMA1.
            // We already have a working call site for setup-0
            // outer block in `decompress::block` — replicate the
            // approach here.
            decompress_lzma1(compressed, &mut out)?;
        }
        CompressMethod::Lzma2 => {
            // Inno's LZMA2 wrap: 1-byte property prefix + raw
            // LZMA2 stream. lzma-rs ignores the property byte
            // (memory unbounded), so just skip it.
            let [_inno_prop, stream @ ..] = compressed else {
                return Err(Error::Truncated {
                    what: "LZMA2 prop byte",
                });
            };
            let mut input = io::BufReader::new(stream);
            let mut reader = lzma_rust2::Lzma2Reader::new(&mut input, 32 * 1024 * 1024, None);
            io::copy(&mut reader, &mut out).map_err(|e| Error::Decompress {
                stream: "chunk LZMA2",
                source: io::Error::other(e.to_string()),
            })?;
        }
    }

    Ok(Arc::<[u8]>::from(out))
}

fn decompress_lzma1(compressed: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
    // Inno's LZMA1 chunk format: [5-byte properties | raw stream].
    // No 8-byte uncompressed-size field — same as the setup-0 outer
    // block path. Pad with the 8-byte unknown-size sentinel (u64::MAX)
    // so lzma-rust2's LzmaReader can consume the 13-byte LZMA-Alone
    // header and rely on the end-of-payload marker.
    let mut header = Vec::with_capacity(compressed.len().saturating_add(8));
    header.extend_from_slice(compressed.get(..5).ok_or_else(|| Error::Decompress {
        stream: "chunk LZMA1",
        source: io::Error::other("LZMA1 header too short"),
    })?);
    header.extend_from_slice(&u64::MAX.to_le_bytes());
    header.extend_from_slice(compressed.get(5..).unwrap_or(&[]));

    let mut reader = lzma_rust2::LzmaReader::new_mem_limit(io::Cursor::new(header), u32::MAX, None)
        .map_err(|e| Error::Decompress {
            stream: "chunk LZMA1",
            source: io::Error::other(e.to_string()),
        })?;
    io::copy(&mut reader, out).map_err(|e| Error::Decompress {
        stream: "chunk LZMA1",
        source: e,
    })?;
    Ok(())
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
    ///    LZMA1 stream — same as the setup-0 outer block).
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
        let chunk_start_in_setup1 = 0x42_u32;
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
        let bytes = decompress_chunk(&slice, &data, CompressMethod::Lzma1, Some(&ctx)).unwrap();
        assert_eq!(bytes.as_ref(), plaintext.as_slice());
    }
}
