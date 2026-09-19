//! String-decoding helpers for the Inno Setup wire format.
//!
//! Per `Shared.SetupEntFunc.pas:97-118`, every length-prefixed field
//! is laid out as `[u32 length-in-bytes] [length bytes of payload]`:
//!
//! - `String` fields use UTF-16LE on Unicode builds (the modern path,
//!   from Inno Setup 5.6 onward and almost universally what we see in
//!   the wild). The `Len` value is the **byte** count, so the number
//!   of UTF-16 code units is `Len / 2`. ANSI builds use the legacy
//!   ANSI codepage and `Len` is the byte/char count directly.
//! - `AnsiString` fields are always raw bytes; the codepage is
//!   determined elsewhere (per-installer or per-language).
//!
//! Modern Inno Setup is Unicode by default. The `(u)` / `(U)` suffix
//! on the version marker is best treated as a hint, not a directive -
//! see [`is_unicode_for_version`] for our decision logic.

use crate::{error::Error, util::read::Reader, version::Version};

/// Reads a length-prefixed UTF-16LE string and returns a Rust
/// `String`.
///
/// # Errors
///
/// - [`Error::Truncated`] / [`Error::Overflow`] on out-of-bounds.
/// - [`Error::InvalidUtf16`] if the byte count is odd or the units
///   form an unpaired surrogate.
pub(crate) fn read_utf16_string(
    reader: &mut Reader<'_>,
    what: &'static str,
) -> Result<String, Error> {
    let len_bytes = reader.u32_le(what)? as usize;
    if len_bytes == 0 {
        return Ok(String::new());
    }
    if len_bytes.checked_rem(2).ok_or(Error::Overflow { what })? != 0 {
        return Err(Error::InvalidUtf16 { what });
    }
    let bytes = reader.take(len_bytes, what)?;
    let pairs = len_bytes.checked_div(2).ok_or(Error::Overflow { what })?;
    let mut units = Vec::with_capacity(pairs);
    for pair in bytes.as_chunks::<2>().0 {
        units.push(u16::from_le_bytes(*pair));
    }
    String::from_utf16(&units).map_err(|_| Error::InvalidUtf16 { what })
}

/// Reads a length-prefixed ANSI string (raw bytes - caller decodes
/// via the appropriate codepage if a `&str` is needed).
///
/// # Errors
///
/// - [`Error::Truncated`] / [`Error::Overflow`] on out-of-bounds.
pub(crate) fn read_ansi_bytes(
    reader: &mut Reader<'_>,
    what: &'static str,
) -> Result<Vec<u8>, Error> {
    let len = reader.u32_le(what)? as usize;
    let bytes = reader.take(len, what)?;
    Ok(bytes.to_vec())
}

/// Reads a length-prefixed string, choosing UTF-16LE vs ANSI based on
/// `version`. The returned `String` is best-effort:
///
/// - Unicode path: real UTF-16LE decode (errors on bad surrogates).
/// - ANSI path: bytes are interpreted as Windows-1252 (a superset of
///   ASCII; never fails). Per-language codepage selection lives in
///   [`crate::records::language::LanguageEntry`]; this function is a
///   default for header-level strings that don't carry their own
///   codepage hint.
///
/// # Errors
///
/// Same as [`read_utf16_string`] for the Unicode path; the ANSI path
/// only fails on truncation.
pub(crate) fn read_setup_string(
    reader: &mut Reader<'_>,
    version: &Version,
    what: &'static str,
) -> Result<String, Error> {
    if is_unicode_for_version(version) {
        read_utf16_string(reader, what)
    } else {
        let raw = read_ansi_bytes(reader, what)?;
        Ok(decode_windows_1252(&raw))
    }
}

/// Decides whether a given `Version` uses UTF-16LE strings on the
/// wire.
///
/// The marker's `(u)` suffix is the most explicit signal but it is
/// inconsistent in practice: HeidiSQL 6.4.0.1 ships an ANSI marker
/// yet stores all strings as UTF-16LE. Inno Setup has been
/// Unicode-by-default since 5.6 - we treat that as the rule and
/// the marker `(u)` as an informational hint.
pub(crate) fn is_unicode_for_version(version: &Version) -> bool {
    if version.is_unicode() {
        return true;
    }
    // Inno Setup 5.6 (release 2017) made the Unicode build the
    // default; legacy ANSI builds shipped only for 5.5 and earlier.
    // For 5.6+ we treat the wire as Unicode regardless of the marker
    // suffix.
    version.at_least(5, 6, 0)
}

/// Decodes a Windows-1252 byte slice losslessly into a Rust `String`.
/// Used as the fallback for legacy (pre-5.6) ANSI installers and as
/// the default codepage for the `AnsiString` blobs (license text,
/// info-before / info-after) when the language table hasn't been
/// parsed yet.
///
/// Windows-1252 is a superset of ASCII; every byte maps to a
/// well-defined Unicode code point. The mapping below is straight
/// from the Unicode Consortium's `WIN1252.TXT`.
pub(crate) fn decode_windows_1252(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for &b in bytes {
        out.push(byte_to_char_1252(b));
    }
    out
}

fn byte_to_char_1252(b: u8) -> char {
    match b {
        0x80 => '\u{20AC}',
        0x82 => '\u{201A}',
        0x83 => '\u{0192}',
        0x84 => '\u{201E}',
        0x85 => '\u{2026}',
        0x86 => '\u{2020}',
        0x87 => '\u{2021}',
        0x88 => '\u{02C6}',
        0x89 => '\u{2030}',
        0x8A => '\u{0160}',
        0x8B => '\u{2039}',
        0x8C => '\u{0152}',
        0x8E => '\u{017D}',
        0x91 => '\u{2018}',
        0x92 => '\u{2019}',
        0x93 => '\u{201C}',
        0x94 => '\u{201D}',
        0x95 => '\u{2022}',
        0x96 => '\u{2013}',
        0x97 => '\u{2014}',
        0x98 => '\u{02DC}',
        0x99 => '\u{2122}',
        0x9A => '\u{0161}',
        0x9B => '\u{203A}',
        0x9C => '\u{0153}',
        0x9E => '\u{017E}',
        0x9F => '\u{0178}',
        // 0x81, 0x8D, 0x8F, 0x90, 0x9D are unmapped in Windows-1252;
        // we surface them as U+FFFD so they don't silently merge with
        // valid code points.
        0x81 | 0x8D | 0x8F | 0x90 | 0x9D => '\u{FFFD}',
        _ => char::from(b),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_1252_ascii_passes_through() {
        assert_eq!(decode_windows_1252(b"Hello, World!"), "Hello, World!");
    }

    #[test]
    fn windows_1252_extended_chars() {
        // 0x80 = €, 0xA9 = ©.
        assert_eq!(decode_windows_1252(&[0x80, 0xA9]), "€©");
    }

    #[test]
    fn read_utf16_string_decodes_inno_app_name() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&16u32.to_le_bytes()); // 16 bytes = 8 chars
        for c in "HeidiSQL".chars() {
            let u = c as u16;
            bytes.extend_from_slice(&u.to_le_bytes());
        }
        let mut reader = Reader::new(&bytes);
        let s = read_utf16_string(&mut reader, "AppName").unwrap();
        assert_eq!(s, "HeidiSQL");
    }

    #[test]
    fn read_utf16_empty_string() {
        let bytes = 0u32.to_le_bytes();
        let mut reader = Reader::new(&bytes);
        let s = read_utf16_string(&mut reader, "AppName").unwrap();
        assert_eq!(s, "");
    }

    #[test]
    fn read_utf16_rejects_odd_byte_count() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&3u32.to_le_bytes());
        bytes.extend_from_slice(&[b'H', 0, 0]);
        let mut reader = Reader::new(&bytes);
        let err = read_utf16_string(&mut reader, "AppName").unwrap_err();
        assert!(matches!(err, Error::InvalidUtf16 { .. }));
    }
}
