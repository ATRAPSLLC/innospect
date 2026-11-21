//! `TSetupFileLocationEntry` (innoextract's "data entry"): where one
//! file's bytes are and how to check them. These are the only records of
//! setup-0's second block. A [`crate::records::file::FileEntry`] names one by
//! index; several file entries share one when their contents are identical.
//!
//! The bytes sit in a *chunk* of setup-1: a run of one or more files,
//! compressed (and possibly encrypted) together, starting `start_offset`
//! bytes into slice `first_slice`. A file is `original_size` bytes at
//! `chunk_sub_offset` within the decompressed chunk. With solid compression
//! every file of the installer is one chunk; otherwise each file has its
//! own.
//!
//! On disk this is the packed record verbatim, no strings: `FirstSlice`,
//! `LastSlice`, `StartOffset` (64-bit from 6.5.2), from 4.0.1
//! `ChunkSuboffset`, `OriginalSize`, `ChunkCompressedSize` (64-bit from
//! 4.0.0), the checksum, the time stamp, `FileVersionMS` / `LS`, the
//! `Flags` set, and from 6.3.0 to 6.4.2 a `Sign` byte. Reader reference:
//! innoextract `setup/data.cpp`; every layout is checked against
//! upstream's own declarations by the `crate::upstream` tests.

use std::collections::HashSet;

use crate::{
    error::Error,
    util::read::{FromReader, Reader},
    version::Version,
};

/// The checksum of a file's decompressed, unfiltered bytes, which
/// [`crate::extract::FileReader`] verifies when it reaches the end. The
/// algorithm is fixed by the version.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DataChecksum {
    /// Pascal `Adler`: Adler-32 (before 4.0.1).
    Adler32(u32),
    /// Pascal `CRC`: CRC-32 (4.0.1 to 4.2.0).
    Crc32(u32),
    /// Pascal `MD5Sum`: MD5 (4.2.0 to 5.3.9).
    Md5([u8; 16]),
    /// Pascal `SHA1Sum`: SHA-1 (5.3.9 to 6.4.0).
    Sha1([u8; 20]),
    /// Pascal `SHA256Sum`: SHA-256 (6.4.0+).
    Sha256([u8; 32]),
}

stable_name_enum!(DataChecksum, {
    Self::Adler32(_) => "adler32",
    Self::Crc32(_) => "crc32",
    Self::Md5(_) => "md5",
    Self::Sha1(_) => "sha1",
    Self::Sha256(_) => "sha256",
});

/// `TSetupFileLocationEntry.Flags`. 6.4.3 rewrote the set as five
/// `flo*` members (`floVersionInfoValid`, `floTimeStampInUTC`,
/// `floCallInstructionOptimized`, `floChunkEncrypted`,
/// `floChunkCompressed`), which decode to the same variants.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[non_exhaustive]
pub enum DataFlag {
    /// `foVersionInfoValid`: [`DataEntry::file_version`] holds the file's
    /// version resource.
    VersionInfoValid,
    /// `foVersionInfoNotValid`: the file has no version resource (before
    /// 6.4.3; from then on the absence of [`Self::VersionInfoValid`] says
    /// so).
    VersionInfoNotValid,
    /// `foBzipped`: the chunk is bzip2- rather than zlib-compressed (2.0.17
    /// to 4.0.1, when the method became per-installer).
    BZipped,
    /// `foTimeStampInUTC`: [`DataEntry::timestamp_seconds`] is UTC; without
    /// it the stored time is the build machine's local time (4.0.10+).
    TimeStampInUTC,
    /// `foIsUninstExe`: these bytes are the uninstaller (4.1.0 to 6.4.2).
    IsUninstallerExe,
    /// `foCallInstructionOptimized`: the bytes went through Inno's x86
    /// branch filter before compression; extraction reverses it (4.1.8+).
    CallInstructionOptimized,
    /// `foTouch` (`touch` flag; `foApplyTouchDateTime` from 5.5.7): Setup
    /// sets the installed file's time from the `TouchDate` / `TouchTime`
    /// directives (4.2.0 to 6.4.2).
    Touch,
    /// `foChunkEncrypted`: the chunk is encrypted (`Encryption=yes` and no
    /// `noencryption` flag); extraction needs the password (4.2.2+).
    ChunkEncrypted,
    /// `foChunkCompressed`: the chunk is compressed (no `nocompression`
    /// flag). Before 4.2.5 every chunk was, and this crate adds the flag.
    ChunkCompressed,
    /// `foSolidBreak` (`solidbreak` flag): the compiler began a new solid
    /// chunk with this file (5.1.13 to 6.4.2).
    SolidBreak,
    /// `foSign` (`sign` flag): the compiler signed the source file before
    /// storing it (SetupID 5.5.7 to 6.1.0; then [`DataEntry::sign_mode`]).
    Sign,
    /// `foSignOnce` (`signonce` flag): signed unless already signed (5.5.7
    /// to 6.1.0).
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

/// `TSetupFileLocationSign`: what the compiler did about signing a source
/// file. The compiler acts on it; Setup does not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignMode {
    /// `fsNoSetting`: no signing flag.
    NoSetting,
    /// `fsYes` (`sign` flag): signed before storing.
    Yes,
    /// `fsOnce` (`signonce` flag): signed unless already signed.
    Once,
    /// `fsCheck` (`signcheck` flag, 6.3.0+): checked for a signature, not
    /// signed.
    Check,
}

stable_name_enum!(SignMode, {
    Self::NoSetting => "no_setting",
    Self::Yes => "yes",
    Self::Once => "once",
    Self::Check => "check",
});

/// One file's location and checks (`TSetupFileLocationEntry`).
#[derive(Clone, Debug)]
pub struct DataEntry {
    /// `FirstSlice` (`FirstDisk` before 4.0.0): the slice the chunk starts
    /// in, 0-based (the stored value is 1-based before 4.0.0). Slice 0 is
    /// the installer's own setup-1 data unless `DiskSpanning` split it into
    /// `setup-1.bin`, `setup-2.bin`, ...
    pub first_slice: u32,
    /// `LastSlice`: the slice the chunk ends in, 0-based; greater than
    /// `first_slice` when the chunk spans slices.
    pub last_slice: u32,
    /// `StartOffset`: where the chunk starts within `first_slice` (64-bit
    /// from 6.5.2).
    pub start_offset: u64,
    /// `ChunkSuboffset`: where this file's bytes start within the
    /// decompressed chunk (4.0.1+; 0 before, one file per chunk).
    pub chunk_sub_offset: u64,
    /// `OriginalSize`: the file's size in bytes.
    pub original_size: u64,
    /// `ChunkCompressedSize` (`CompressedSize` before 4.0.0): the stored
    /// size of the whole chunk, which may hold other files too.
    pub chunk_compressed_size: u64,
    /// The checksum of the file's bytes.
    pub checksum: DataChecksum,
    /// `TimeStamp` (`Date`, `SourceTimeStamp`): the source file's last-write
    /// time, as seconds since the Unix epoch. UTC with
    /// [`DataFlag::TimeStampInUTC`], else the build machine's local time.
    /// A 16-bit installer (1.2.x) stores a DOS date and time, to the even
    /// second.
    pub timestamp_seconds: i64,
    /// The sub-second part of the time stamp, in nanoseconds (100 ns
    /// resolution, as `FILETIME` stores it; 0 in a 16-bit installer).
    pub timestamp_nanos: u32,
    /// `FileVersionMS` and `FileVersionLS` as `(ms << 32) | ls`: the four
    /// 16-bit parts of the file's version, most significant first. Valid
    /// with [`DataFlag::VersionInfoValid`].
    pub file_version: u64,
    /// `Flags`, decoded.
    pub flags: HashSet<DataFlag>,
    /// `Flags` as stored: the set's bytes, whose size grows with the number
    /// of flags the version defines.
    pub flags_raw: Vec<u8>,
    /// `Sign` (6.3.0 to 6.4.2), or derived from [`DataFlag::Sign`] /
    /// [`DataFlag::SignOnce`] before; [`SignMode::NoSetting`] from 6.4.3,
    /// which no longer records it.
    pub sign_mode: SignMode,
    /// `Sign` as stored; 0 when the version has no such byte.
    pub sign_mode_raw: u8,
}

impl FromReader for DataEntry {
    const SIZED_BEFORE_1_3: bool = false;

    /// Reads one `TSetupFileLocationEntry`, in the layout the module
    /// documentation describes.
    ///
    /// # Errors
    ///
    /// [`Error::Truncated`] when the record runs past the input. A
    /// pre-4.0.0 slice number of 0, which the 1-based numbering forbids,
    /// reads as slice 0.
    fn read(reader: &mut Reader<'_>, version: &Version) -> Result<Self, Error> {
        let mut first_slice = reader.native_u32(version, "Data.FirstSlice")?;
        let mut last_slice = reader.native_u32(version, "Data.LastSlice")?;
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
            u64::try_from(v).map_err(|_| Error::Overflow {
                what: "Data.StartOffset (negative)",
            })?
        } else {
            u64::from(reader.u32_le("Data.StartOffset")?)
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

        // A Win32 `FILETIME`; in a 16-bit installer (1.2.x) a DOS date and
        // time in one `Longint`.
        let (timestamp_seconds, timestamp_nanos) = if version.is_16bit() {
            read_dos_time(reader)?
        } else {
            read_filetime(reader)?
        };

        let file_version_ms = reader.u32_le("Data.FileVersionMS")?;
        let file_version_ls = reader.u32_le("Data.FileVersionLS")?;
        let file_version = (u64::from(file_version_ms) << 32) | u64::from(file_version_ls);

        let table = data_flag_table(version);
        let raw = reader.set_bytes(table.len(), version, "Data.Flags")?;
        let mut flags = crate::util::flags::decode_packed_flags(&raw, &table);
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

/// Reads a DOS date and time (the time in the low word, as 16-bit Setup
/// stores the `Longint` it gets from `GetFTime`) as seconds since the Unix
/// epoch, in the build machine's local time. Two-second resolution.
fn read_dos_time(reader: &mut Reader<'_>) -> Result<(i64, u32), Error> {
    let time = i64::from(reader.u16_le("Data.Time")?);
    let date = i64::from(reader.u16_le("Data.Date")?);
    let second = (time & 0x1F).saturating_mul(2);
    let minute = (time >> 5) & 0x3F;
    let hour = time >> 11;
    let day = date & 0x1F;
    let month = (date >> 5) & 0x0F;
    let year = (date >> 9).saturating_add(1980);
    let days = days_from_civil(year, month, day);
    let seconds = days
        .saturating_mul(86_400)
        .saturating_add(hour.saturating_mul(3_600))
        .saturating_add(minute.saturating_mul(60))
        .saturating_add(second);
    Ok((seconds, 0))
}

/// Days from 1970-01-01 to the given proleptic Gregorian date (Howard
/// Hinnant's `days_from_civil`), for years from 1980 on. An out-of-range
/// month or day, which a DOS date can hold, counts on from the month
/// before rather than failing.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 {
        year.saturating_sub(1)
    } else {
        year
    };
    let era = year.checked_div(400).unwrap_or(0);
    let year_of_era = year.saturating_sub(era.saturating_mul(400));
    let shifted_month = if month > 2 {
        month.saturating_sub(3)
    } else {
        month.saturating_add(9)
    };
    let day_of_year = shifted_month
        .saturating_mul(153)
        .saturating_add(2)
        .checked_div(5)
        .unwrap_or(0)
        .saturating_add(day)
        .saturating_sub(1);
    let day_of_era = year_of_era
        .saturating_mul(365)
        .saturating_add(year_of_era.checked_div(4).unwrap_or(0))
        .saturating_sub(year_of_era.checked_div(100).unwrap_or(0))
        .saturating_add(day_of_year);
    era.saturating_mul(146_097)
        .saturating_add(day_of_era)
        .saturating_sub(719_468)
}

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

#[cfg(test)]
mod tests {
    use super::*;

    fn dos(year: u16, month: u16, day: u16, hour: u16, minute: u16, second: u16) -> [u8; 4] {
        let time = (hour << 11) | (minute << 5) | (second / 2);
        let date = ((year - 1980) << 9) | (month << 5) | day;
        let mut out = [0u8; 4];
        out[..2].copy_from_slice(&time.to_le_bytes());
        out[2..].copy_from_slice(&date.to_le_bytes());
        out
    }

    #[test]
    fn dos_time_reads_as_unix_seconds() {
        // Each against `date -u -d ... +%s`.
        for (bytes, unix) in [
            (dos(1980, 1, 1, 0, 0, 0), 315_532_800),
            (dos(1999, 12, 31, 23, 59, 58), 946_684_798),
            (dos(2000, 2, 29, 12, 34, 56), 951_827_696),
            (dos(1996, 3, 1, 8, 15, 30), 825_668_130),
        ] {
            let got = read_dos_time(&mut Reader::new(&bytes)).unwrap();
            assert_eq!(got, (unix, 0), "{bytes:02x?}");
        }
    }
}
