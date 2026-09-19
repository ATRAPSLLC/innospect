//! Locate the `SetupLdrOffsetTable` bytes inside the PE container.
//!
//! # Strategy 1 - legacy (pre-5.1.5)
//!
//! Read three dwords at file offset `0x30`: `'Inno'` magic
//! (`0x6f6e6e49`), then a pointer to the offset-table record, then
//! the bitwise-complement of that pointer for self-validation. If
//! the magic matches and pointer + ~pointer round-trip, we follow
//! the pointer. This must be tried **before** the signature scan
//! because the same `rDlPtS<NN>` magic appears as a literal string
//! constant inside the loader's code section in pre-5.1.5 builds -
//! a naïve scan would lock onto that false match instead of the
//! real offset-table copy that the `0x30` pointer leads to.
//!
//! # Strategy 2 - modern (5.1.5+)
//!
//! Scan the input for the 12-byte SetupLdr magic. The 5.1.5+ format
//! moved the offset table into a PE resource (id 11111) and the
//! magic no longer appears as a string constant in the loader, so
//! the first match is the real one. Scanning sidesteps walking the
//! PE resource tree and tolerates BlackBox/GOG installers that may
//! place the resource oddly.

use crate::{error::Error, overlay::offsettable::SetupLdrFamily, util::read::u32_le_at};

/// Resource id used by Inno Setup 5.1.5+ to embed the offset table
/// inside the PE `.rsrc` section. From `SetupLdrOffsetTableResID = 11111`
/// in `Shared.Struct.pas:463`. Retained as documentation; the
/// signature scan does not depend on it.
#[allow(dead_code)]
pub(crate) const OFFSET_TABLE_RESOURCE_ID: u32 = 11111;

/// File offset where pre-5.1.5 installers stored the SetupLdr pointer.
const LEGACY_LOCATOR_FILE_OFFSET: usize = 0x30;
/// `'Inno'` little-endian; sits at `LEGACY_LOCATOR_FILE_OFFSET + 4`.
const LEGACY_LOCATOR_MAGIC: u32 = 0x6f6e_6e49;

/// Source of the offset-table bytes inside the PE.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum LocatorMode {
    /// 5.1.5+ : found by scanning for the 12-byte SetupLdr magic
    /// inside the PE.
    SignatureScan,
    /// pre-5.1.5 : found via the file-offset-`0x30` pointer + `'Inno'`
    /// magic scheme.
    LegacyFileOffset,
}

stable_name_enum!(LocatorMode, {
    Self::SignatureScan => "signature_scan",
    Self::LegacyFileOffset => "legacy_file_offset",
});

/// Span of bytes inside the input slice that contains the offset
/// table.
#[derive(Clone, Copy, Debug)]
pub struct OffsetTableLocation {
    /// Byte offset into the original input.
    pub start: usize,
    /// Byte length of the located region (whatever remains of the
    /// input after `start`; the actual record is shorter).
    pub len: usize,
    /// Which locator strategy succeeded.
    pub mode: LocatorMode,
}

/// Walks the PE container and locates the `SetupLdrOffsetTable` bytes.
///
/// Tries the modern signature-scan path first; falls back to the
/// legacy `0x30` file-offset path. Returns [`Error::NotInnoSetup`]
/// only if both strategies fail.
///
/// # Errors
///
/// - [`Error::NotPe`] if the bytes do not begin with `MZ` or are
///   shorter than the minimum PE header.
/// - [`Error::NotInnoSetup`] if neither locator strategy finds the
///   table.
pub(crate) fn locate(input: &[u8]) -> Result<OffsetTableLocation, Error> {
    // Cheap "is this even a PE?" probe. Real PEs start with `MZ`
    // (`0x5A4D`) at offset 0; we don't need a full PE parse to do
    // the magic scan. Section-aware lookups would need `goblin`,
    // but every Inno Setup payload locator only requires raw
    // file-offset arithmetic.
    if input.len() < 64
        || input.first().copied() != Some(b'M')
        || input.get(1).copied() != Some(b'Z')
    {
        return Err(Error::NotPe);
    }

    if let Some(loc) = try_legacy_file_offset(input)? {
        return Ok(loc);
    }
    if let Some(loc) = try_signature_scan(input) {
        return Ok(loc);
    }
    Err(Error::NotInnoSetup)
}

fn try_signature_scan(input: &[u8]) -> Option<OffsetTableLocation> {
    const FAMILIES: &[SetupLdrFamily] = &[
        SetupLdrFamily::V1_2_10,
        SetupLdrFamily::V4_0_0,
        SetupLdrFamily::V4_0_3,
        SetupLdrFamily::V4_0_10,
        SetupLdrFamily::V4_1_6,
        SetupLdrFamily::V5_1_5,
        SetupLdrFamily::V5_1_5Alt,
    ];

    let mut best: Option<usize> = None;
    for family in FAMILIES {
        let signature = family.signature();
        if let Some(offset) = find_subslice(input, signature) {
            best = Some(match best {
                Some(prev) => prev.min(offset),
                None => offset,
            });
        }
    }

    let start = best?;
    let len = input.len().saturating_sub(start);
    Some(OffsetTableLocation {
        start,
        len,
        mode: LocatorMode::SignatureScan,
    })
}

/// Naïve memmem - fine for our inputs (typical Inno installers are
/// 1–50 MB, signature is 12 bytes, only one match expected). Avoids a
/// dependency on the `memchr` crate.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    let last_start = haystack.len().checked_sub(needle.len())?;
    let mut i = 0usize;
    while i <= last_start {
        let window = haystack.get(i..i.checked_add(needle.len())?)?;
        if window == needle {
            return Some(i);
        }
        i = i.checked_add(1)?;
    }
    None
}

fn try_legacy_file_offset(input: &[u8]) -> Result<Option<OffsetTableLocation>, Error> {
    // Layout at file offset 0x30 (matches innoextract `loader/offsets.cpp`
    // `load_from_exe_file`):
    //   +0x00  magic = 'Inno' (0x6f6e6e49)
    //   +0x04  offset_table_offset
    //   +0x08  ~offset_table_offset (self-check)
    let probe_end = LEGACY_LOCATOR_FILE_OFFSET
        .checked_add(12)
        .ok_or(Error::Overflow {
            what: "legacy locator probe end",
        })?;
    if input.len() < probe_end {
        return Ok(None);
    }
    let magic = u32_le_at(input, LEGACY_LOCATOR_FILE_OFFSET, "legacy locator magic")?;
    if magic != LEGACY_LOCATOR_MAGIC {
        return Ok(None);
    }
    let pointer_offset = LEGACY_LOCATOR_FILE_OFFSET
        .checked_add(4)
        .ok_or(Error::Overflow {
            what: "legacy locator pointer offset",
        })?;
    let pointer = u32_le_at(input, pointer_offset, "legacy locator pointer")?;
    let not_pointer_offset = LEGACY_LOCATOR_FILE_OFFSET
        .checked_add(8)
        .ok_or(Error::Overflow {
            what: "legacy locator not-pointer offset",
        })?;
    let not_pointer = u32_le_at(input, not_pointer_offset, "legacy locator pointer check")?;
    if pointer != !not_pointer {
        return Ok(None);
    }
    let start = pointer as usize;
    if start >= input.len() {
        return Err(Error::Truncated {
            what: "legacy offset table pointer",
        });
    }
    let len = input.len().saturating_sub(start);
    Ok(Some(OffsetTableLocation {
        start,
        len,
        mode: LocatorMode::LegacyFileOffset,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_pe() {
        let err = locate(&[0u8; 128]).unwrap_err();
        assert!(matches!(err, Error::NotPe));
    }

    #[test]
    fn finds_signature_in_synthetic_buffer() {
        let mut buf = vec![0u8; 4096];
        buf[0] = b'M';
        buf[1] = b'Z';
        // Place the V5_1_5 signature at offset 1024.
        let sig = SetupLdrFamily::V5_1_5.signature();
        buf[1024..1024 + sig.len()].copy_from_slice(sig);
        let loc = locate(&buf).unwrap();
        assert_eq!(loc.mode, LocatorMode::SignatureScan);
        assert_eq!(loc.start, 1024);
    }

    #[test]
    fn unknown_resource_id_constant_is_documented() {
        // Smoke test that the constant is exposed for downstream
        // documentation use. The signature scan does not depend on it.
        assert_eq!(OFFSET_TABLE_RESOURCE_ID, 11111);
    }
}
