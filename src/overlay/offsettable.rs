//! Decode the `SetupLdrOffsetTable` resource into a typed
//! [`OffsetTable`].
//!
//! The format has gone through three generations across the
//! `1.2.10 → 7.0.0.3` range. The full evolution table lives in
//! `research-notes/10-version-evolution.md` §B.1; this module
//! summarizes:
//!
//! - **Pre-5.1.5**: variable-length record located via the `0x30`
//!   file-offset pointer; checksum optional (≥ 4.0.10), Adler32 vs
//!   CRC32 swapped at 4.0.3, `message_offset` removed at 4.0.0,
//!   `exe_compressed_size` removed at 4.1.6. We model these as a
//!   single "v0" layout that handles all sub-cases via version
//!   gates.
//! - **5.1.5 → 6.5.1**: 32-bit fields in a fixed-shape record stored
//!   as PE resource `11111`, prefixed by a 4-byte `revision = 1`.
//!   We model this as "v1".
//! - **6.5.2 → 7.0.0.3**: 64-byte fixed record, `version = 2`,
//!   `Int64` offsets, no `message_offset`, no `exe_compressed_size`,
//!   trailing CRC32 covers the entire preceding record. We model
//!   this as "v2".

use crate::{
    error::Error,
    util::{checksum::crc32, read::Reader},
};

/// Recognized SetupLdr 12-byte magic family. Each family pins the
/// minimum Inno Setup version that ships it; format-version logic
/// (`OffsetTable::version_id`) gates the field layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SetupLdrFamily {
    /// `rDlPtS02\x87eVx` - Inno Setup ≥ 1.2.10.
    V1_2_10,
    /// `rDlPtS04\x87eVx` - Inno Setup ≥ 4.0.0.
    V4_0_0,
    /// `rDlPtS05\x87eVx` - Inno Setup ≥ 4.0.3.
    V4_0_3,
    /// `rDlPtS06\x87eVx` - Inno Setup ≥ 4.0.10.
    V4_0_10,
    /// `rDlPtS07\x87eVx` - Inno Setup ≥ 4.1.6.
    V4_1_6,
    /// `rDlPtS\xCD\xE6\xD7{\x0B*` - Inno Setup ≥ 5.1.5; this magic is
    /// also reused by 6.x and 7.x. The record-format generation is
    /// then determined by the `Version` field (v1 vs v2).
    V5_1_5,
    /// `nS5W7dT\x83\xAA\x1B\x0Fj` - alternative 5.1.5+ magic seen on
    /// some modified variants.
    V5_1_5Alt,
}

stable_name_enum!(SetupLdrFamily, {
    Self::V1_2_10 => "v1_2_10",
    Self::V4_0_0 => "v4_0_0",
    Self::V4_0_3 => "v4_0_3",
    Self::V4_0_10 => "v4_0_10",
    Self::V4_1_6 => "v4_1_6",
    Self::V5_1_5 => "v5_1_5",
    Self::V5_1_5Alt => "v5_1_5_alt",
});

impl SetupLdrFamily {
    /// Returns the canonical 12-byte signature for this family.
    pub fn signature(self) -> &'static [u8; 12] {
        match self {
            Self::V1_2_10 => &[
                b'r', b'D', b'l', b'P', b't', b'S', b'0', b'2', 0x87, b'e', b'V', b'x',
            ],
            Self::V4_0_0 => &[
                b'r', b'D', b'l', b'P', b't', b'S', b'0', b'4', 0x87, b'e', b'V', b'x',
            ],
            Self::V4_0_3 => &[
                b'r', b'D', b'l', b'P', b't', b'S', b'0', b'5', 0x87, b'e', b'V', b'x',
            ],
            Self::V4_0_10 => &[
                b'r', b'D', b'l', b'P', b't', b'S', b'0', b'6', 0x87, b'e', b'V', b'x',
            ],
            Self::V4_1_6 => &[
                b'r', b'D', b'l', b'P', b't', b'S', b'0', b'7', 0x87, b'e', b'V', b'x',
            ],
            Self::V5_1_5 => &[
                b'r', b'D', b'l', b'P', b't', b'S', 0xCD, 0xE6, 0xD7, b'{', 0x0B, b'*',
            ],
            Self::V5_1_5Alt => &[
                b'n', b'S', b'5', b'W', b'7', b'd', b'T', 0x83, 0xAA, 0x1B, 0x0F, b'j',
            ],
        }
    }

    /// Recognize a 12-byte magic prefix.
    pub fn from_bytes(magic: &[u8; 12]) -> Option<Self> {
        [
            Self::V1_2_10,
            Self::V4_0_0,
            Self::V4_0_3,
            Self::V4_0_10,
            Self::V4_1_6,
            Self::V5_1_5,
            Self::V5_1_5Alt,
        ]
        .into_iter()
        .find(|f| magic == f.signature())
    }

    /// `(major, minor, patch)` minimum version associated with this
    /// magic family.
    pub fn min_version(self) -> (u8, u8, u8) {
        match self {
            Self::V1_2_10 => (1, 2, 10),
            Self::V4_0_0 => (4, 0, 0),
            Self::V4_0_3 => (4, 0, 3),
            Self::V4_0_10 => (4, 0, 10),
            Self::V4_1_6 => (4, 1, 6),
            Self::V5_1_5 | Self::V5_1_5Alt => (5, 1, 5),
        }
    }
}

/// Which generation of the offset-table record we parsed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum OffsetTableGeneration {
    /// Pre-5.1.5 variable-shape record.
    V0,
    /// 5.1.5 → 6.5.1 fixed 32-bit record (`Version = 1`).
    V1,
    /// 6.5.2+ fixed 64-byte record (`Version = 2`).
    V2,
}

/// How / where the offset table was found inside the PE.
#[derive(Clone, Copy, Debug)]
pub struct OffsetTableSource {
    /// Byte offset of the offset-table record inside the input.
    pub start: usize,
    /// Byte length of the parsed record (bytes consumed).
    pub len: usize,
    /// SetupLdr 12-byte magic family.
    pub family: SetupLdrFamily,
    /// Which record generation was parsed.
    pub generation: OffsetTableGeneration,
}

/// Decoded `SetupLdrOffsetTable`.
///
/// Field meanings, per `Shared.Struct.pas:423-435`:
/// - `offset_setup0` ⇒ where the 64-byte SetupID marker begins
///   (canonical `Offset0`).
/// - `offset_setup1` ⇒ where the file payload chunks begin (canonical
///   `Offset1`); `0` means the payload lives in external `setup-N.bin`
///   files.
/// - `offset_exe` ⇒ where the compressed `setup.e32`/`setup.e64`
///   stub-handoff payload begins (canonical `OffsetEXE`).
#[derive(Clone, Debug)]
pub struct OffsetTable {
    /// Provenance of the bytes we decoded.
    pub source: OffsetTableSource,
    /// `OffsetTable.Version` field (`1` or `2` for v1/v2; `0` for the
    /// pre-5.1.5 path that has no explicit version field).
    pub version_id: u32,
    /// `OffsetEXE`.
    pub offset_exe: u64,
    /// `Offset0` (start of `setup-0.bin` data).
    pub offset_setup0: u64,
    /// `Offset1` (start of `setup-1.bin` data, or `0` for external).
    pub offset_setup1: u64,
    /// `UncompressedSizeEXE`.
    pub uncompressed_size_exe: u32,
    /// `CRCEXE`.
    pub crc_exe: u32,
    /// `TotalSize` (v2 only; `0` otherwise).
    pub total_size: u64,
    /// `message_offset` (pre-4.0.0 only; `0` otherwise).
    pub message_offset: u32,
    /// `exe_compressed_size` (pre-4.1.6 only; `0` otherwise).
    pub exe_compressed_size: u32,
}

impl OffsetTable {
    /// Decodes the offset-table bytes that the [`pe`](super::pe)
    /// locator returned.
    ///
    /// # Errors
    ///
    /// - [`Error::UnknownSetupLdrMagic`] if the 12-byte magic is not in
    ///   our recognized table.
    /// - [`Error::Truncated`] if the record runs past the buffer.
    /// - [`Error::BadChecksum`] for v1/v2 if the trailing CRC does not
    ///   match.
    pub fn parse(input: &[u8], start: usize, len: usize) -> Result<Self, Error> {
        let end = start.checked_add(len).ok_or(Error::Overflow {
            what: "offset table end",
        })?;
        let region = input.get(start..end).ok_or(Error::Truncated {
            what: "offset table region",
        })?;

        let mut reader = Reader::new(region);
        let magic_bytes = reader.array::<12>("offset table magic")?;
        let family = SetupLdrFamily::from_bytes(&magic_bytes)
            .ok_or(Error::UnknownSetupLdrMagic { magic: magic_bytes })?;

        match family {
            SetupLdrFamily::V5_1_5 | SetupLdrFamily::V5_1_5Alt => {
                Self::parse_modern(region, start, &mut reader, family)
            }
            _ => Self::parse_legacy(region, start, &mut reader, family),
        }
    }

    fn parse_modern(
        region: &[u8],
        start: usize,
        reader: &mut Reader<'_>,
        family: SetupLdrFamily,
    ) -> Result<Self, Error> {
        // The `Version` field follows the 12-byte magic. `1` ⇒ legacy
        // 32-bit record; `2` ⇒ canonical 64-byte record.
        let version_id = reader.u32_le("offset table Version")?;

        match version_id {
            2 => Self::parse_v2(region, start, reader, family),
            1 => Self::parse_v1(region, start, reader, family),
            _ => {
                // Some pre-bumped 5.1.5 builds emit the v1 layout
                // without an explicit version dword. We fall back to
                // legacy parsing - the magic is enough to identify the
                // file. Rewind 4 bytes so the legacy parser sees the
                // u32 we just consumed.
                let pos_after = reader.pos();
                let _ = pos_after; // bookkeeping only
                Self::parse_legacy(region, start, &mut Reader::at(region, 12)?, family)
            }
        }
    }

    fn parse_v2(
        region: &[u8],
        start: usize,
        reader: &mut Reader<'_>,
        family: SetupLdrFamily,
    ) -> Result<Self, Error> {
        // Field order from Shared.Struct.pas:423-435:
        //   ID(12) Version(4) TotalSize(8) OffsetEXE(8)
        //   UncompressedSizeEXE(4) CRCEXE(4) Offset0(8) Offset1(8)
        //   ReservedPadding(4) TableCRC(4)
        // We've already consumed ID(12) + Version(4) = 16 bytes.
        let total_size = reader.u64_le("TotalSize")?;
        let offset_exe = reader.u64_le("OffsetEXE")?;
        let uncompressed_size_exe = reader.u32_le("UncompressedSizeEXE")?;
        let crc_exe = reader.u32_le("CRCEXE")?;
        let offset_setup0 = reader.u64_le("Offset0")?;
        let offset_setup1 = reader.u64_le("Offset1")?;
        let _reserved = reader.u32_le("ReservedPadding")?;
        let table_crc = reader.u32_le("TableCRC")?;
        let bytes_read = reader.pos();

        // CRC32 is computed over every preceding byte of the record
        // up to (but not including) TableCRC itself.
        let crc_input_end = bytes_read.checked_sub(4).ok_or(Error::Overflow {
            what: "v2 CRC range",
        })?;
        let crc_input = region.get(..crc_input_end).ok_or(Error::Truncated {
            what: "v2 CRC range",
        })?;
        let actual = crc32(crc_input);
        if actual != table_crc {
            return Err(Error::BadChecksum {
                what: "SetupLdrOffsetTable v2",
                expected: table_crc,
                actual,
            });
        }

        Ok(Self {
            source: OffsetTableSource {
                start,
                len: bytes_read,
                family,
                generation: OffsetTableGeneration::V2,
            },
            version_id: 2,
            offset_exe,
            offset_setup0,
            offset_setup1,
            uncompressed_size_exe,
            crc_exe,
            total_size,
            message_offset: 0,
            exe_compressed_size: 0,
        })
    }

    fn parse_v1(
        region: &[u8],
        start: usize,
        reader: &mut Reader<'_>,
        family: SetupLdrFamily,
    ) -> Result<Self, Error> {
        // Pre-6.5.2 layout (innoextract `loader/offsets.cpp:145-200`):
        // After magic+version we have all 32-bit fields:
        //   [discarded u32] OffsetEXE(4) UncompressedSizeEXE(4)
        //   CRCEXE(4) Offset0(4) Offset1(4) TableCRC(4)
        // The "discarded" first u32 is the `TotalSize` upper word
        // before it was widened to Int64. We capture it but don't
        // expose it.
        let _total_size_lo = reader.u32_le("v1 placeholder/total")?;
        let offset_exe = u64::from(reader.u32_le("v1 OffsetEXE")?);
        let uncompressed_size_exe = reader.u32_le("v1 UncompressedSizeEXE")?;
        let crc_exe = reader.u32_le("v1 CRCEXE")?;
        let offset_setup0 = u64::from(reader.u32_le("v1 Offset0")?);
        let offset_setup1 = u64::from(reader.u32_le("v1 Offset1")?);
        let table_crc = reader.u32_le("v1 TableCRC")?;
        let bytes_read = reader.pos();

        let crc_input_end = bytes_read.checked_sub(4).ok_or(Error::Overflow {
            what: "v1 CRC range",
        })?;
        let crc_input = region.get(..crc_input_end).ok_or(Error::Truncated {
            what: "v1 CRC range",
        })?;
        let actual = crc32(crc_input);
        if actual != table_crc {
            return Err(Error::BadChecksum {
                what: "SetupLdrOffsetTable v1",
                expected: table_crc,
                actual,
            });
        }

        Ok(Self {
            source: OffsetTableSource {
                start,
                len: bytes_read,
                family,
                generation: OffsetTableGeneration::V1,
            },
            version_id: 1,
            offset_exe,
            offset_setup0,
            offset_setup1,
            uncompressed_size_exe,
            crc_exe,
            total_size: 0,
            message_offset: 0,
            exe_compressed_size: 0,
        })
    }

    fn parse_legacy(
        region: &[u8],
        start: usize,
        reader: &mut Reader<'_>,
        family: SetupLdrFamily,
    ) -> Result<Self, Error> {
        // Reproduce innoextract's pre-5.1.5 loader (offsets.cpp:140-200).
        // Cursor is positioned right after the 12-byte magic.
        let (min_a, min_b, min_c) = family.min_version();

        // Skip a u32 (innoextract reads-and-discards here; the field is
        // the historical `TotalSize` lower word).
        let _ = reader.u32_le("legacy placeholder")?;

        let offset_exe = u64::from(reader.u32_le("legacy OffsetEXE")?);

        let exe_compressed_size = if (min_a, min_b, min_c) >= (4, 1, 6) {
            0
        } else {
            reader.u32_le("legacy ExeCompressedSize")?
        };

        let uncompressed_size_exe = reader.u32_le("legacy UncompressedSizeEXE")?;
        let crc_exe = reader.u32_le("legacy CRCEXE/Adler32")?;

        let message_offset = if (min_a, min_b, min_c) >= (4, 0, 0) {
            0
        } else {
            reader.u32_le("legacy MessageOffset")?
        };

        let offset_setup0 = u64::from(reader.u32_le("legacy Offset0")?);
        let offset_setup1 = u64::from(reader.u32_le("legacy Offset1")?);

        // The trailing CRC32 only exists in 4.0.10+ (see CHANGELOG;
        // innoextract gates this on `version >= INNO_VERSION(4, 0, 10)`).
        if (min_a, min_b, min_c) >= (4, 0, 10) {
            let bytes_read_before_crc = reader.pos();
            let table_crc = reader.u32_le("legacy TableCRC")?;
            let crc_input = region
                .get(..bytes_read_before_crc)
                .ok_or(Error::Truncated {
                    what: "legacy CRC range",
                })?;
            let actual = crc32(crc_input);
            if actual != table_crc {
                return Err(Error::BadChecksum {
                    what: "SetupLdrOffsetTable legacy",
                    expected: table_crc,
                    actual,
                });
            }
        }

        Ok(Self {
            source: OffsetTableSource {
                start,
                len: reader.pos(),
                family,
                generation: OffsetTableGeneration::V0,
            },
            version_id: 0,
            offset_exe,
            offset_setup0,
            offset_setup1,
            uncompressed_size_exe,
            crc_exe,
            total_size: 0,
            message_offset,
            exe_compressed_size,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn family_signatures_round_trip() {
        for f in [
            SetupLdrFamily::V1_2_10,
            SetupLdrFamily::V4_0_0,
            SetupLdrFamily::V4_0_3,
            SetupLdrFamily::V4_0_10,
            SetupLdrFamily::V4_1_6,
            SetupLdrFamily::V5_1_5,
            SetupLdrFamily::V5_1_5Alt,
        ] {
            assert_eq!(SetupLdrFamily::from_bytes(f.signature()), Some(f));
        }
    }

    #[test]
    fn unknown_magic_rejected() {
        let m = [0u8; 12];
        assert_eq!(SetupLdrFamily::from_bytes(&m), None);
    }
}
