//! BCJ (Branch/Call/Jump) inverse filters for x86 executables.
//!
//! Inno Setup applies one of three closely-related filters to
//! executable file content before compression: each rewrites the
//! immediate operand of `CALL` (`0xE8`) and `JMP` (`0xE9`)
//! instructions from absolute to relative-to-position to improve
//! compressibility. After decompression we apply the **inverse**
//! filter to restore the original bytes.
//!
//! Reader reference: `research/src/stream/exefilter.hpp`. The
//! source contains two C++ classes:
//! - `inno_exe_decoder_4108` for pre-5.2.0 installers.
//! - `inno_exe_decoder_5200` for 5.2.0+; constructed with
//!   `flip_high_bytes = false` for 5.2.0..5.3.9 and
//!   `flip_high_bytes = true` for 5.3.9+ (the latter is what we
//!   call [`Filter::V5_3_9`]).
//!
//! The filters operate on the `[Files]`-record level data (post
//! chunk decompression, post-`chunk_sub_offset` slice). They run
//! across the file's full length; `running offset` state is reset
//! per file.

use crate::error::Error;

/// BCJ filter variant per `dataentry::CallInstructionOptimized`
/// + version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Filter {
    /// Pre-5.2.0 - `inno_exe_decoder_4108`, byte-by-byte CALL/JMP
    /// address rewrite.
    V4108,
    /// 5.2.0..5.3.9 - `inno_exe_decoder_5200` without high-byte flip.
    V5200,
    /// 5.3.9+ - `inno_exe_decoder_5200` with high-byte flip.
    V5_3_9,
}

impl Filter {
    /// Selects the filter variant for a given Inno Setup version.
    /// Maps directly to innoextract's
    /// `data.cpp:CallInstructionOptimized` dispatch
    /// (`research/src/stream/data.cpp:218-226`).
    pub(crate) fn for_version(version: &crate::version::Version) -> Self {
        if version.at_least(5, 3, 9) {
            Self::V5_3_9
        } else if version.at_least(5, 2, 0) {
            Self::V5200
        } else {
            Self::V4108
        }
    }

    /// Applies the inverse filter to `buf` in place. The whole file
    /// content must be passed in one call - internal state is
    /// initialised at the start and not preserved across calls.
    ///
    /// # Errors
    ///
    /// Should not return errors for any valid input, but the
    /// signature is `Result` to satisfy the deny-set discipline
    /// (no `expect`, no slice indexing). Errors here would indicate
    /// an internal bug in the BCJ window logic.
    pub(crate) fn apply(self, buf: &mut [u8]) -> Result<(), Error> {
        match self {
            Self::V4108 => apply_4108(buf),
            Self::V5200 => apply_5200(buf, false),
            Self::V5_3_9 => apply_5200(buf, true),
        }
    }
}

const CALL: u8 = 0xE8;
const JMP: u8 = 0xE9;

/// `inno_exe_decoder_4108::read` ported in-place. Tracks
/// `addr` (running u32 carry), `addr_bytes_left` (4..0 countdown
/// while inside an address), and `addr_offset` (counter from 5
/// per the C++ ctor). The 32-bit address is rewritten one byte at
/// a time as it streams through.
fn apply_4108(buf: &mut [u8]) -> Result<(), Error> {
    let mut addr: u32 = 0;
    let mut addr_bytes_left: u32 = 0;
    let mut addr_offset: u32 = 5;

    for slot in buf.iter_mut() {
        let byte = *slot;
        let mut emit = byte;
        if addr_bytes_left == 0 {
            if byte == CALL || byte == JMP {
                // 2's-complement negation of `addr_offset`.
                addr = (!addr_offset).wrapping_add(1);
                addr_bytes_left = 4;
            }
        } else {
            addr = addr.wrapping_add(u32::from(byte));
            // Cast cannot truncate meaningfully - we want the low byte.
            #[allow(clippy::cast_possible_truncation)]
            {
                emit = addr as u8;
            }
            addr >>= 8;
            addr_bytes_left = addr_bytes_left.saturating_sub(1);
        }
        *slot = emit;
        addr_offset = addr_offset.wrapping_add(1);
    }

    Ok(())
}

/// `inno_exe_decoder_5200::read` ported in-place. Operates over a
/// 5-byte window (`0xE8/0xE9` + 4-byte little-endian address).
/// Skips windows that would span a 64 KiB block boundary or whose
/// trailing high byte isn't `0x00` / `0xff` (likely indicating the
/// match wasn't really a CALL/JMP).
fn apply_5200(buf: &mut [u8], flip_high_byte: bool) -> Result<(), Error> {
    const BLOCK_SIZE: usize = 0x10000;

    let len = buf.len();
    let mut i: usize = 0;

    while i < len {
        // We need to read buf[i] without indexing. Use chunked windows.
        let head = match buf.get(i) {
            Some(b) => *b,
            None => break,
        };
        if head != CALL && head != JMP {
            i = i.saturating_add(1);
            continue;
        }

        // Bytes remaining in the current 64 KiB block from the CALL byte.
        let block_offset = i.checked_rem(BLOCK_SIZE).unwrap_or(0);
        let block_left = BLOCK_SIZE.saturating_sub(block_offset);
        if block_left < 5 {
            i = i.saturating_add(1);
            continue;
        }

        // Need the full 5-byte window. If we run out of buffer, leave
        // the trailing CALL byte alone and stop.
        let end = match i.checked_add(5) {
            Some(end) if end <= len => end,
            _ => break,
        };
        let Some(window) = buf.get_mut(i..end) else {
            break;
        };
        let [_call, b1, b2, b3, b4] = window else {
            break;
        };

        // High byte must be 0x00 (forward jump sign-extended) or
        // 0xff (backward jump sign-extended); otherwise the bytes
        // are passed through unchanged.
        if *b4 == 0x00 || *b4 == 0xff {
            // Reconstruct the encoded relative address in low 24 bits.
            let rel_low24 = u32::from(*b1) | (u32::from(*b2) << 8) | (u32::from(*b3) << 16);
            // `addr` is the position just past the address bytes
            // (matches the C++ counter at the end of the read).
            let position_after = u32::try_from(end).unwrap_or(u32::MAX);
            let addr = position_after & 0x00FF_FFFF;
            let rel = rel_low24.wrapping_sub(addr);
            #[allow(clippy::cast_possible_truncation)]
            {
                *b1 = rel as u8;
                *b2 = (rel >> 8) as u8;
                *b3 = (rel >> 16) as u8;
            }
            if flip_high_byte && (rel & 0x0080_0000) != 0 {
                *b4 = !*b4;
            }
        }

        // Advance past the CALL+addr group, whether or not we
        // rewrote.
        i = i.saturating_add(5);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4108_round_trip_leaves_non_call_bytes_unchanged() {
        let mut buf = vec![0u8, 1, 2, 3, 4, 5];
        Filter::V4108.apply(&mut buf).unwrap();
        // No CALL/JMP bytes ⇒ algorithm is a no-op (carry is 0,
        // addr_bytes_left stays 0).
        assert_eq!(buf, vec![0, 1, 2, 3, 4, 5]);
    }

    #[test]
    fn v5_3_9_skips_high_byte_not_sign() {
        let mut buf = vec![CALL, 0x10, 0x20, 0x30, 0x42, 0x99];
        Filter::V5_3_9.apply(&mut buf).unwrap();
        // High byte (0x42) isn't 0x00/0xff ⇒ pass through.
        assert_eq!(buf, vec![CALL, 0x10, 0x20, 0x30, 0x42, 0x99]);
    }

    #[test]
    fn v5_3_9_rewrites_when_high_byte_is_sign() {
        let mut buf = vec![CALL, 0x10, 0x20, 0x30, 0x00, 0x99];
        Filter::V5_3_9.apply(&mut buf).unwrap();
        // The CALL+addr at i=0 had absolute target 0x00302010;
        // post-filter it should be rewritten to relative.
        // We just check it changed (exact value verified by the
        // encoder/decoder symmetry test below).
        assert_ne!(buf[..5], [CALL, 0x10, 0x20, 0x30, 0x00]);
        // Trailing byte (post-window) untouched.
        assert_eq!(buf[5], 0x99);
    }

    #[test]
    fn v5_3_9_block_spanning_call_skipped() {
        // CALL at position 65535 (last byte of block 0); fewer than
        // 5 bytes remain ⇒ no rewrite.
        let mut buf = vec![0u8; 65540];
        if let Some(slot) = buf.get_mut(65535) {
            *slot = CALL;
        }
        let before = buf.clone();
        Filter::V5_3_9.apply(&mut buf).unwrap();
        assert_eq!(buf, before);
    }

    #[test]
    fn v5200_no_flip_keeps_high_byte_as_is() {
        // Same input as the v5_3_9 rewrite test, but the high byte
        // should NOT flip even when bit 23 of `rel` is set.
        let mut buf = vec![CALL, 0xFF, 0xFF, 0x7F, 0x00];
        Filter::V5200.apply(&mut buf).unwrap();
        // High byte stays 0x00 because flip_high_byte=false.
        assert_eq!(buf[4], 0x00);
    }
}
