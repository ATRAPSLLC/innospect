//! `TSetupFileLocationEntry` (innoextract `dataentry`) - the
//! contents of the **second** decompressed block (a.k.a. block 2).
//! Each entry is the bookkeeping for one chunk of `setup-1` payload:
//! offsets, size, checksum, timestamp, version info, encryption /
//! compression flags.
//!
//! Pascal layout (`is-6_4_1:Projects/Src/Shared.Struct.pas`):
//!
//! ```text
//! TSetupFileLocationEntry = packed record
//!     FirstSlice, LastSlice: Integer;
//!     StartOffset: Cardinal;
//!     ChunkSubOffset: Int64;       // since 4.0.1
//!     OriginalSize, ChunkCompressedSize: Int64;  // u32 pre-4.0
//!     Checksum: TFileChecksum;     // SHA256 (6.4+) / SHA1 (5.3.9+) / MD5 (4.2+) / CRC32 / Adler32
//!     TimeStamp: TFileTime;        // FAT for 16-bit, FILETIME for 32-bit
//!     FileVersionMS, FileVersionLS: Cardinal;
//!     Flags: TSetupFileLocationFlags;  // variable-width set
//!     SignMode: TSetupFileLocationSignMode;  // since 6.3.0
//! end;
//! ```
//!
//! Reader reference: `research/src/setup/data.cpp`.

use std::collections::HashSet;

use crate::{error::Error, util::read::Reader, version::Version};

/// Checksum carried by a [`DataEntry`]. The variant indicates which
/// hash family is in use; the byte slice has the canonical length
/// for that family.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DataChecksum {
    /// `Adler32` - pre-4.0.1 only.
    Adler32(u32),
    /// `CRC32` - 4.0.1..4.2.0.
    Crc32(u32),
    /// `MD5` - 4.2.0..5.3.9.
    Md5([u8; 16]),
    /// `SHA1` - 5.3.9..6.4.0.
    Sha1([u8; 20]),
    /// `SHA256` - 6.4.0+.
    Sha256([u8; 32]),
}

stable_name_enum!(DataChecksum, {
    Self::Adler32(_) => "adler32",
    Self::Crc32(_) => "crc32",
    Self::Md5(_) => "md5",
    Self::Sha1(_) => "sha1",
    Self::Sha256(_) => "sha256",
});

/// `TSetupFileLocationFlags` flag bits.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum DataFlag {
    VersionInfoValid,
    VersionInfoNotValid,
    /// Pre-4.0.1 only.
    BZipped,
    TimeStampInUTC,
    IsUninstallerExe,
    CallInstructionOptimized,
    Touch,
    ChunkEncrypted,
    ChunkCompressed,
    SolidBreak,
    Sign,
    SignOnce,
}

stable_flag_enum!(DataFlag, {
    VersionInfoValid => "version_info_valid",
    VersionInfoNotValid => "version_info_not_valid",
    BZipped => "bzipped",
    TimeStampInUTC => "time_stamp_in_utc",
    IsUninstallerExe => "is_uninstaller_exe",
    CallInstructionOptimized => "call_instruction_optimized",
    Touch => "touch",
    ChunkEncrypted => "chunk_encrypted",
    ChunkCompressed => "chunk_compressed",
    SolidBreak => "solid_break",
    Sign => "sign",
    SignOnce => "sign_once",
});

/// `TSetupFileLocationSignMode` - 6.3.0+ replacement for the
/// per-entry `Sign` / `SignOnce` flags.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignMode {
    /// `smNoSetting`.
    NoSetting,
    /// `smYes`.
    Yes,
    /// `smOnce`.
    Once,
    /// `smCheck`.
    Check,
}

stable_name_enum!(SignMode, {
    Self::NoSetting => "no_setting",
    Self::Yes => "yes",
    Self::Once => "once",
    Self::Check => "check",
});

/// Parsed `TSetupFileLocationEntry`.
#[derive(Clone, Debug)]
pub struct DataEntry {
    /// `FirstSlice` - index of the first slice (`setup-1.bin`,
    /// `setup-2.bin`, …) this chunk belongs to.
    pub first_slice: u32,
    /// `LastSlice` - index of the last slice this chunk belongs to.
    pub last_slice: u32,
    /// `StartOffset` - byte offset within `FirstSlice`.
    pub start_offset: u32,
    /// `ChunkSubOffset` - byte offset within the (possibly
    /// compressed/encrypted) chunk where this file's bytes begin.
    /// `0` for pre-4.0.1 versions.
    pub chunk_sub_offset: u64,
    /// `OriginalSize` - uncompressed size of this file.
    pub original_size: u64,
    /// `ChunkCompressedSize` - compressed-on-disk size of the chunk
    /// (note: a chunk may contain *multiple* file payloads).
    pub chunk_compressed_size: u64,
    /// File-content checksum.
    pub checksum: DataChecksum,
    /// Unix-seconds timestamp.
    pub timestamp_seconds: i64,
    /// Sub-second nanoseconds.
    pub timestamp_nanos: u32,
    /// `FileVersionMS:FileVersionLS` packed as `(ms << 32) | ls`.
    pub file_version: u64,
    /// Decoded flags.
    pub flags: HashSet<DataFlag>,
    /// Raw `Flags` bytes.
    pub flags_raw: Vec<u8>,
    /// `SignMode` - 6.3.0+. Synthesized from `Sign` / `SignOnce`
    /// flags on older versions.
    pub sign_mode: SignMode,
    /// Raw sign-mode byte (only meaningful 6.3.0+).
    pub sign_mode_raw: u8,
}

impl DataEntry {
    /// Reads one `TSetupFileLocationEntry`.
    ///
    /// Layout evolution (`research-notes/12-format-evolution-audit.md`):
    /// - 6.5.0+: Flags simplified to 5 bits; `SignMode` removed.
    /// - 6.6.0+: `StartOffset` widened from `Cardinal` (4) to
    ///   `Int64` (8).
    ///
    /// # Errors
    ///
    /// Truncation / overflow per [`Error`]. Pre-4.0.0 installers
    /// with non-positive slice numbers return [`Error::Truncated`]
    /// (we don't accept a malformed slice index silently the way
    /// innoextract logs+continues).
    pub(crate) fn read(reader: &mut Reader<'_>, version: &Version) -> Result<Self, Error> {
        let mut first_slice = reader.u32_le("Data.FirstSlice")?;
        let mut last_slice = reader.u32_le("Data.LastSlice")?;
        if !version.at_least(4, 0, 0) {
            // Pre-4.0 installers store 1-based slice numbers.
            first_slice = first_slice.saturating_sub(1);
            last_slice = last_slice.saturating_sub(1);
        }

        let start_offset = if version.at_least(6, 5, 2) {
            // Promoted to Int64 at 6.5.2 (issrc commit `b5881a9b` -
            // "Increase max Setup size without disk spanning from
            // almost 2 GB to almost 4 GB"; widens StartOffset and
            // ChunkSuboffset to Int64). Wire is signed but
            // semantically non-negative.
            let v = reader.i64_le("Data.StartOffset")?;
            // Stored value preserved via sub-offset; downstream
            // narrows on demand. Held as u32 for the public accessor
            // type; widening to u64 would be a breaking change.
            u32::try_from(v.unsigned_abs()).unwrap_or(u32::MAX)
        } else {
            reader.u32_le("Data.StartOffset")?
        };

        let chunk_sub_offset = if version.at_least(4, 0, 1) {
            reader.u64_le("Data.ChunkSubOffset")?
        } else {
            0
        };

        let (original_size, chunk_compressed_size) = if version.at_least(4, 0, 0) {
            (
                reader.u64_le("Data.OriginalSize")?,
                reader.u64_le("Data.ChunkCompressedSize")?,
            )
        } else {
            (
                u64::from(reader.u32_le("Data.OriginalSize")?),
                u64::from(reader.u32_le("Data.ChunkCompressedSize")?),
            )
        };

        let checksum = read_checksum(reader, version)?;

        // Timestamp: pre-32-bit installers are unreachable for us, so
        // only handle Win32 FILETIME.
        let (timestamp_seconds, timestamp_nanos) = read_filetime(reader)?;

        let file_version_ms = reader.u32_le("Data.FileVersionMS")?;
        let file_version_ls = reader.u32_le("Data.FileVersionLS")?;
        let file_version = (u64::from(file_version_ms) << 32) | u64::from(file_version_ls);

        let table = data_flag_table(version);
        let raw = reader.set_bytes(table.len(), true, "Data.Flags")?;
        let mut flags = super::decode_packed_flags(&raw, &table);
        // Pre-4.2.5 always set ChunkCompressed.
        if !version.at_least(4, 2, 5) {
            flags.insert(DataFlag::ChunkCompressed);
        }

        // SignMode was a 6.3.0..6.4.3 byte; removed at 6.4.3 along
        // with the legacy file-location flags (issrc commit `00d335b7`).
        let (sign_mode, sign_mode_raw) = if version.at_least(6, 4, 3) {
            (SignMode::NoSetting, 0)
        } else if version.at_least(6, 3, 0) {
            let raw = reader.u8("Data.SignMode")?;
            (SignMode::from_raw(raw).unwrap_or(SignMode::NoSetting), raw)
        } else if flags.contains(&DataFlag::SignOnce) {
            (SignMode::Once, 0)
        } else if flags.contains(&DataFlag::Sign) {
            (SignMode::Yes, 0)
        } else {
            (SignMode::NoSetting, 0)
        };

        Ok(Self {
            first_slice,
            last_slice,
            start_offset,
            chunk_sub_offset,
            original_size,
            chunk_compressed_size,
            checksum,
            timestamp_seconds,
            timestamp_nanos,
            file_version,
            flags,
            flags_raw: raw,
            sign_mode,
            sign_mode_raw,
        })
    }
}

/// Win32 `FILETIME` epoch offset (1601-01-01 → 1970-01-01 in 100-ns
/// ticks). From innoextract `data.cpp`.
const FILETIME_OFFSET: i64 = 0x019D_B1DE_D53E_8000;

fn read_filetime(reader: &mut Reader<'_>) -> Result<(i64, u32), Error> {
    let raw = reader.i64_le("Data.Timestamp")?;
    let shifted = raw.checked_sub(FILETIME_OFFSET).unwrap_or(0);
    let secs = shifted.checked_div(10_000_000).unwrap_or(0);
    let rem = shifted.checked_rem(10_000_000).unwrap_or(0);
    let nanos_signed = rem.checked_mul(100).unwrap_or(0);
    let nanos = u32::try_from(nanos_signed.unsigned_abs()).unwrap_or(0);
    Ok((secs, nanos))
}

fn read_checksum(reader: &mut Reader<'_>, version: &Version) -> Result<DataChecksum, Error> {
    if version.at_least(6, 4, 0) {
        Ok(DataChecksum::Sha256(reader.array::<32>("Data.SHA256")?))
    } else if version.at_least(5, 3, 9) {
        Ok(DataChecksum::Sha1(reader.array::<20>("Data.SHA1")?))
    } else if version.at_least(4, 2, 0) {
        Ok(DataChecksum::Md5(reader.array::<16>("Data.MD5")?))
    } else if version.at_least(4, 0, 1) {
        Ok(DataChecksum::Crc32(reader.u32_le("Data.CRC32")?))
    } else {
        Ok(DataChecksum::Adler32(reader.u32_le("Data.Adler32")?))
    }
}

fn data_flag_table(version: &Version) -> Vec<DataFlag> {
    // 6.4.3 (commit `00d335b7` "Cleanup: TSetupFileLocationEntry
    // contained a few things which Setup doesn't need…") dropped
    // VersionInfoNotValid / IsUninstallerExe / Touch / SolidBreak and
    // removed the trailing `Sign: TSetupFileLocationSign` field. The
    // resulting 5-flag, no-Sign layout is what 6.5.0+ inherited.
    if version.at_least(6, 4, 3) {
        return vec![
            DataFlag::VersionInfoValid,
            DataFlag::TimeStampInUTC,
            DataFlag::CallInstructionOptimized,
            DataFlag::ChunkEncrypted,
            DataFlag::ChunkCompressed,
        ];
    }

    let mut t = vec![DataFlag::VersionInfoValid, DataFlag::VersionInfoNotValid];
    if version.at_least(2, 0, 17) && !version.at_least(4, 0, 1) {
        t.push(DataFlag::BZipped);
    }
    if version.at_least(4, 0, 10) {
        t.push(DataFlag::TimeStampInUTC);
    }
    if version.at_least(4, 1, 0) {
        t.push(DataFlag::IsUninstallerExe);
    }
    if version.at_least(4, 1, 8) {
        t.push(DataFlag::CallInstructionOptimized);
    }
    if version.at_least(4, 2, 0) {
        t.push(DataFlag::Touch);
    }
    if version.at_least(4, 2, 2) {
        t.push(DataFlag::ChunkEncrypted);
    }
    if version.at_least(4, 2, 5) {
        t.push(DataFlag::ChunkCompressed);
    }
    if version.at_least(5, 1, 13) {
        t.push(DataFlag::SolidBreak);
    }
    if version.at_least(5, 5, 7) && !version.at_least(6, 3, 0) {
        t.push(DataFlag::Sign);
        t.push(DataFlag::SignOnce);
    }
    t
}

impl SignMode {
    /// Resolves the persisted on-disk discriminant byte back to a [`SignMode`],
    /// or [`None`] for an unknown value. Inverse of the byte read during
    /// parsing; used to re-derive the label from a stored `sign_mode_raw`.
    #[must_use]
    pub fn from_raw(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::NoSetting),
            1 => Some(Self::Yes),
            2 => Some(Self::Once),
            3 => Some(Self::Check),
            _ => None,
        }
    }
}
