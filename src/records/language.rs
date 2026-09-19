//! `TSetupLanguageEntry` - `[Languages]` section entry.
//!
//! Pascal layout (`is-6_4_1:Projects/Src/Shared.Struct.pas`):
//!
//! ```text
//! TSetupLanguageEntry = packed record
//!     Name: AnsiString;        // since 4.0.0
//!     LanguageName: AnsiString;
//!     DialogFontName, TitleFontName, WelcomeFontName,
//!         CopyrightFontName: AnsiString;
//!     Data: AnsiString;        // since 4.0.0
//!     LicenseText, InfoBeforeText, InfoAfterText: AnsiString;  // since 4.0.1
//!     LanguageId: Cardinal;
//!     LanguageCodepage: Cardinal;  // 4.2.2+ (non-Unicode); pre-5.3 unicode skip-u32
//!     DialogFontSize: Integer;
//!     DialogFontStandardHeight: Integer;  // pre-4.1.0 only
//!     TitleFontSize, WelcomeFontSize, CopyrightFontSize: Integer;
//!     RightToLeft: Boolean;    // since 5.2.3
//! end;
//! ```
//!
//! Reader reference: `research/src/setup/language.cpp`. Note that
//! "binary_string" in innoextract is a length-prefixed raw blob -
//! always read as the wire bytes regardless of unicode build. We use
//! `read_ansi_bytes` here.
//!
//! Codepage selection (matches innoextract):
//! - Unicode build (5.6+ and most 5.3+ Unicode) ⇒ `UTF-16LE`.
//! - Pre-4.2.2 ANSI ⇒ derived from a Windows language-id table.
//! - 4.2.2+ ANSI ⇒ wire field `language_codepage` (defaulting to 1252).

use crate::{
    error::Error,
    util::{
        encoding::{is_unicode_for_version, read_ansi_bytes},
        read::Reader,
    },
    version::Version,
};

/// Codepage of an Inno Setup language entry.
///
/// Matches innoextract's reduced codepage enum: Unicode installers
/// always declare `Utf16Le`; legacy installers can carry one of a
/// handful of Windows codepages. Unknown values are surfaced as
/// [`Self::Other`] with the raw codepage number for caller-side
/// handling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LanguageCodepage {
    /// `cp_utf16le` - modern unicode builds.
    Utf16Le,
    /// Numeric Windows codepage (e.g. 1252, 1251, 932). The variant
    /// covers every legacy ANSI installer; common values are
    /// 1250..1258 plus the East-Asian double-byte pages.
    Windows(u32),
    /// Codepage explicitly absent (older versions / unknown numeric).
    Other(u32),
}

impl LanguageCodepage {
    /// Returns the numeric codepage value carried by this variant.
    #[must_use]
    pub fn raw(self) -> u32 {
        match self {
            Self::Utf16Le => 1200,
            Self::Windows(codepage) | Self::Other(codepage) => codepage,
        }
    }

    /// Reconstructs a [`LanguageCodepage`] from a stored numeric codepage.
    ///
    /// The canonical UTF-16LE page (`1200`) maps to [`Self::Utf16Le`]; every
    /// other positive codepage is treated as a legacy Windows ANSI page. Used
    /// to re-derive the family [`label`](Self::label) from a persisted
    /// `codepage_raw` without storing the derived text.
    #[must_use]
    pub fn from_raw(codepage: u32) -> Self {
        match codepage {
            1200 => Self::Utf16Le,
            other => Self::Windows(other),
        }
    }

    /// Returns a stable label for this codepage family.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Utf16Le => "utf16le",
            Self::Windows(_) => "windows",
            Self::Other(_) => "other",
        }
    }

    /// Decodes `bytes` from this codepage into an owned [`String`].
    ///
    /// `Utf16Le` decodes little-endian UTF-16 (modern Unicode builds).
    /// `Windows` / `Other` numeric codepages are decoded through the
    /// matching Windows code page (cp1250..cp1258, cp932, …) via
    /// `encoding_rs`; an unknown or unmappable codepage falls back to a
    /// strict-then-lossy UTF-8 interpretation. Returns `None` only when the
    /// input is not valid UTF-16 (odd byte length / unpaired surrogate);
    /// the ANSI path always yields a value.
    ///
    /// # Examples
    ///
    /// ```
    /// use innospect::LanguageCodepage;
    /// // "ñ" in cp1252 is the single byte 0xF1.
    /// assert_eq!(LanguageCodepage::Windows(1252).decode(&[0xF1]).as_deref(), Some("ñ"));
    /// ```
    #[must_use]
    pub fn decode(self, bytes: &[u8]) -> Option<String> {
        match self {
            Self::Utf16Le => decode_utf16le(bytes),
            Self::Windows(codepage) | Self::Other(codepage) => Some(decode_ansi(bytes, codepage)),
        }
    }
}

/// Decodes `bytes` using the Windows ANSI code page `codepage`, falling back
/// to strict-then-lossy UTF-8 when the code page is unknown to `encoding_rs`.
fn decode_ansi(bytes: &[u8], codepage: u32) -> String {
    if let Ok(cp) = u16::try_from(codepage)
        && let Some(encoding) = codepage::to_encoding(cp)
    {
        let (decoded, _had_errors) = encoding.decode_without_bom_handling(bytes);
        return decoded.into_owned();
    }
    String::from_utf8(bytes.to_vec())
        .unwrap_or_else(|_| String::from_utf8_lossy(bytes).into_owned())
}

impl core::fmt::Display for LanguageCodepage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.label())
    }
}

/// Parsed `TSetupLanguageEntry`.
///
/// Strings are returned as raw bytes (`Vec<u8>`) - codepage decoding
/// to `String` happens above this layer once a target encoding is
/// chosen. The associated codepage is exposed via
/// [`Self::codepage`]. For 6.x Unicode installers the bytes are
/// UTF-16LE.
#[derive(Clone, Debug)]
pub struct LanguageEntry {
    /// `Name:` directive - language identifier (e.g. `"english"`).
    /// 4.0.0+; absent on older versions.
    pub name: Vec<u8>,
    /// Human-readable language name (e.g. `"English"`).
    pub language_name: Vec<u8>,
    /// Default dialog font name.
    pub dialog_font: Vec<u8>,
    /// Default title font name.
    pub title_font: Vec<u8>,
    /// Welcome page font name.
    pub welcome_font: Vec<u8>,
    /// Copyright text font name.
    pub copyright_font: Vec<u8>,
    /// Opaque per-language `Data` blob. 4.0.0+.
    pub data: Vec<u8>,
    /// `LicenseText:` directive value. 4.0.1+.
    pub license_text: Vec<u8>,
    /// `InfoBeforeText:` directive value. 4.0.1+.
    pub info_before: Vec<u8>,
    /// `InfoAfterText:` directive value. 4.0.1+.
    pub info_after: Vec<u8>,
    /// Windows `LANGID` (e.g. `0x0409` for U.S. English).
    pub language_id: u32,
    /// Resolved codepage for the language's strings.
    pub codepage: LanguageCodepage,
    /// `DialogFontSize` (in points).
    pub dialog_font_size: u32,
    /// `DialogFontStandardHeight`. Pre-4.1.0 only; 0 otherwise.
    pub dialog_font_standard_height: u32,
    /// `TitleFontSize`.
    pub title_font_size: u32,
    /// `WelcomeFontSize`.
    pub welcome_font_size: u32,
    /// `CopyrightFontSize`.
    pub copyright_font_size: u32,
    /// `RightToLeft:` flag. 5.2.3+.
    pub right_to_left: bool,
}

impl LanguageEntry {
    /// Reads one `TSetupLanguageEntry`.
    ///
    /// 6.6.0 reworked the entry: dropped the `Title*` and
    /// `Copyright*` fonts, narrowed `LanguageID` from `Cardinal` to
    /// `Word`, removed the per-language `Codepage`, and added
    /// `DialogFontBaseScaleHeight/Width`. The reader dispatches per
    /// version. See `research-notes/12-format-evolution-audit.md`.
    ///
    /// # Errors
    ///
    /// String / truncation errors per [`Error`].
    pub(crate) fn read(reader: &mut Reader<'_>, version: &Version) -> Result<Self, Error> {
        if version.at_least(6, 6, 0) {
            return read_v6_6(reader, version);
        }
        read_legacy(reader, version)
    }

    /// Convenience: returns [`Self::name`] decoded as UTF-8 / UTF-16LE
    /// based on the language's codepage. Returns `None` if the bytes
    /// don't form valid Unicode.
    #[must_use]
    pub fn name_string(&self) -> Option<String> {
        self.codepage.decode(&self.name)
    }

    /// Convenience: returns [`Self::language_name`] decoded.
    #[must_use]
    pub fn language_name_string(&self) -> Option<String> {
        self.codepage.decode(&self.language_name)
    }
}

/// 6.6.0+ reader: 4 strings, `LanguageID: Word`, no codepage,
/// `DialogFontBaseScaleHeight/Width`. See
/// `research-notes/12-format-evolution-audit.md`.
fn read_v6_6(reader: &mut Reader<'_>, _version: &Version) -> Result<LanguageEntry, Error> {
    let name = read_ansi_bytes(reader, "Language.Name")?;
    let language_name = read_ansi_bytes(reader, "Language.LanguageName")?;
    let dialog_font = read_ansi_bytes(reader, "Language.DialogFont")?;
    let welcome_font = read_ansi_bytes(reader, "Language.WelcomeFont")?;

    let data = read_ansi_bytes(reader, "Language.Data")?;
    let license_text = read_ansi_bytes(reader, "Language.LicenseText")?;
    let info_before = read_ansi_bytes(reader, "Language.InfoBefore")?;
    let info_after = read_ansi_bytes(reader, "Language.InfoAfter")?;

    // LanguageID narrowed to Word (2 bytes) at 6.6.0.
    let language_id_word = reader.u16_le("Language.LanguageId")?;
    let language_id = u32::from(language_id_word);
    // Codepage removed at 6.6.0; we synthesize UTF-16LE for unicode
    // builds (which are all 5.6+ - and 6.6.0 is well past that).
    let codepage = LanguageCodepage::Utf16Le;

    let dialog_font_size = reader.u32_le("Language.DialogFontSize")?;
    // New at 6.6.0: BaseScaleHeight + BaseScaleWidth (replaces the
    // pre-4.1.0 DialogFontStandardHeight; semantically a font scale
    // reference). Currently surfaced as `dialog_font_standard_height`
    // for the height field; width is read past pending an accessor.
    let dialog_font_standard_height = reader.u32_le("Language.DialogFontBaseScaleHeight")?;
    let _dialog_font_base_scale_width = reader.u32_le("Language.DialogFontBaseScaleWidth")?;
    let welcome_font_size = reader.u32_le("Language.WelcomeFontSize")?;

    let right_to_left = reader.u8("Language.RightToLeft")? != 0;

    Ok(LanguageEntry {
        name,
        language_name,
        dialog_font,
        title_font: Vec::new(),
        welcome_font,
        copyright_font: Vec::new(),
        data,
        license_text,
        info_before,
        info_after,
        language_id,
        codepage,
        dialog_font_size,
        dialog_font_standard_height,
        title_font_size: 0,
        welcome_font_size,
        copyright_font_size: 0,
        right_to_left,
    })
}

/// Pre-6.6.0 reader (covers 4.0..6.5.x). 6 fonts, Cardinal LangID,
/// optional Codepage, four font-size integers + RTL boolean.
fn read_legacy(reader: &mut Reader<'_>, version: &Version) -> Result<LanguageEntry, Error> {
    let name = if version.at_least(4, 0, 0) {
        read_ansi_bytes(reader, "Language.Name")?
    } else {
        Vec::new()
    };

    let language_name = read_ansi_bytes(reader, "Language.LanguageName")?;

    // BlackBox 5.5.7.1 inserts an extra binary_string here - read
    // it past as a no-op for that exact format-version.
    if version.at_least_4(5, 5, 7, 1) && !version.at_least_4(5, 5, 7, 2) {
        let _skip = read_ansi_bytes(reader, "Language.BlackBoxSkip")?;
    }

    let dialog_font = read_ansi_bytes(reader, "Language.DialogFont")?;
    let title_font = read_ansi_bytes(reader, "Language.TitleFont")?;
    let welcome_font = read_ansi_bytes(reader, "Language.WelcomeFont")?;
    let copyright_font = read_ansi_bytes(reader, "Language.CopyrightFont")?;

    let data = if version.at_least(4, 0, 0) {
        read_ansi_bytes(reader, "Language.Data")?
    } else {
        Vec::new()
    };

    let (license_text, info_before, info_after) = if version.at_least(4, 0, 1) {
        (
            read_ansi_bytes(reader, "Language.LicenseText")?,
            read_ansi_bytes(reader, "Language.InfoBefore")?,
            read_ansi_bytes(reader, "Language.InfoAfter")?,
        )
    } else {
        (Vec::new(), Vec::new(), Vec::new())
    };

    let language_id = reader.u32_le("Language.LanguageId")?;

    let codepage = if version.at_least(4, 2, 2) {
        if is_unicode_for_version(version) {
            if !version.at_least(5, 3, 0) {
                // Pre-5.3 unicode build: header has a redundant
                // codepage field that is ignored.
                let _skip = reader.u32_le("Language.CodepageSkip")?;
            }
            LanguageCodepage::Utf16Le
        } else {
            let cp = reader.u32_le("Language.Codepage")?;
            if cp == 0 {
                LanguageCodepage::Windows(1252)
            } else {
                LanguageCodepage::Windows(cp)
            }
        }
    } else if is_unicode_for_version(version) {
        LanguageCodepage::Utf16Le
    } else {
        LanguageCodepage::Windows(1252)
    };

    let dialog_font_size = reader.u32_le("Language.DialogFontSize")?;

    let dialog_font_standard_height = if !version.at_least(4, 1, 0) {
        reader.u32_le("Language.DialogFontStandardHeight")?
    } else {
        0
    };

    let title_font_size = reader.u32_le("Language.TitleFontSize")?;
    let welcome_font_size = reader.u32_le("Language.WelcomeFontSize")?;
    let copyright_font_size = reader.u32_le("Language.CopyrightFontSize")?;

    // BlackBox 5.5.7.1 trailing u32 - read past for that exact
    // format-version only.
    if version.at_least_4(5, 5, 7, 1) && !version.at_least_4(5, 5, 7, 2) {
        let _ = reader.u32_le("Language.BlackBoxTail")?;
    }

    let right_to_left = if version.at_least(5, 2, 3) {
        reader.u8("Language.RightToLeft")? != 0
    } else {
        false
    };

    Ok(LanguageEntry {
        name,
        language_name,
        dialog_font,
        title_font,
        welcome_font,
        copyright_font,
        data,
        license_text,
        info_before,
        info_after,
        language_id,
        codepage,
        dialog_font_size,
        dialog_font_standard_height,
        title_font_size,
        welcome_font_size,
        copyright_font_size,
        right_to_left,
    })
}

fn decode_utf16le(bytes: &[u8]) -> Option<String> {
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let mut units = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.as_chunks::<2>().0 {
        units.push(u16::from_le_bytes(*pair));
    }
    String::from_utf16(&units).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::version::{Version, VersionFlags};

    fn v6_4_unicode() -> Version {
        Version {
            a: 6,
            b: 4,
            c: 0,
            d: 0,
            flags: VersionFlags::UNICODE,
            raw_marker: [0u8; 64],
        }
    }

    fn put_blob(buf: &mut Vec<u8>, b: &[u8]) {
        let len = u32::try_from(b.len()).unwrap();
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(b);
    }

    fn put_utf16(buf: &mut Vec<u8>, s: &str) {
        let bytes: Vec<u8> = s.encode_utf16().flat_map(u16::to_le_bytes).collect();
        put_blob(buf, &bytes);
    }

    #[test]
    fn parses_minimal_english_language() {
        let v = v6_4_unicode();
        let mut bytes = Vec::new();
        put_utf16(&mut bytes, "english"); // name
        put_utf16(&mut bytes, "English"); // language_name
        put_utf16(&mut bytes, "Tahoma"); // dialog_font
        put_utf16(&mut bytes, "Verdana"); // title_font
        put_utf16(&mut bytes, "Verdana"); // welcome_font
        put_utf16(&mut bytes, "Arial"); // copyright_font
        put_blob(&mut bytes, &[0xDE, 0xAD]); // data
        put_utf16(&mut bytes, ""); // license_text
        put_utf16(&mut bytes, ""); // info_before
        put_utf16(&mut bytes, ""); // info_after
        bytes.extend_from_slice(&0x0409u32.to_le_bytes()); // language_id (en-US)
        // 6.4 unicode → no codepage / skip field
        bytes.extend_from_slice(&8u32.to_le_bytes()); // dialog_font_size
        // 4.1+: no DialogFontStandardHeight
        bytes.extend_from_slice(&12u32.to_le_bytes()); // title_font_size
        bytes.extend_from_slice(&12u32.to_le_bytes()); // welcome_font_size
        bytes.extend_from_slice(&9u32.to_le_bytes()); // copyright_font_size
        bytes.push(0); // right_to_left

        let mut r = Reader::new(&bytes);
        let l = LanguageEntry::read(&mut r, &v).unwrap();
        assert_eq!(l.language_id, 0x0409);
        assert_eq!(l.codepage, LanguageCodepage::Utf16Le);
        assert_eq!(l.dialog_font_size, 8);
        assert!(!l.right_to_left);
        assert_eq!(l.name_string().as_deref(), Some("english"));
        assert_eq!(l.language_name_string().as_deref(), Some("English"));
        assert_eq!(l.data, vec![0xDE, 0xAD]);
        assert_eq!(r.pos(), bytes.len());
    }
}
