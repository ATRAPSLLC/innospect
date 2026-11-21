//! `TSetupLanguageEntry`: one `[Languages]` entry, a language the wizard
//! can run in, with its messages, fonts and per-language license and info
//! texts (4.0.0+; earlier releases have a single language and no entries).
//!
//! On disk (`SECompressedBlockWrite`): before 6.6.0 `Name` (4.0.0+),
//! `LanguageName`, four font names, `Data` (4.0.0+), `LicenseText`,
//! `InfoBeforeText`, `InfoAfterText` (4.0.1+), `LanguageID` (32-bit), from
//! 4.2.2 `LanguageCodePage`, `DialogFontSize`, before 4.1.0
//! `DialogFontStandardHeight`, the title, welcome and copyright font
//! sizes, and from 5.2.3 `RightToLeft`. 6.6.0 dropped the title and
//! copyright fonts and the code page, narrowed `LanguageID` to 16 bits and
//! added `DialogFontBaseScaleHeight` / `Width`. In Unicode builds the names
//! are UTF-16LE (`String`) and the rest raw bytes (`AnsiString`); every
//! field is kept as stored, see [`LanguageEntry::codepage`]. Reader
//! reference: innoextract `setup/language.cpp`; every layout is checked
//! against upstream's own declarations by the `crate::upstream` tests.

use crate::{
    error::Error,
    util::{
        encoding::{is_unicode_for_version, read_ansi_bytes},
        read::{FromReader, Reader},
    },
    version::Version,
};

/// The encoding of a language entry's name fields and, in ANSI builds, of
/// its messages: UTF-16LE in Unicode builds, else the language's Windows
/// code page (`LanguageCodePage` from 4.2.2, derived from the language ID
/// before, as innoextract does).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LanguageCodepage {
    /// A Unicode build: UTF-16LE (code page 1200).
    Utf16Le,
    /// An ANSI build's Windows code page, e.g. 1252, 1251 or 932.
    Windows(u32),
    /// A code page held as given. The reader never produces it, mapping
    /// every ANSI code page to [`Self::Windows`]; it is for values a caller
    /// builds itself.
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

/// One `[Languages]` entry (`TSetupLanguageEntry`). Fields are the bytes
/// as stored: decode the names with [`Self::codepage`] (or
/// [`Self::name_string`]); the texts are the files the script named, as
/// they were. A field the version does not have is empty or 0.
#[derive(Clone, Debug)]
pub struct LanguageEntry {
    /// `Name:`: the language's internal name, e.g. `english`, which
    /// `Languages:` parameters name (4.0.0+).
    pub name: Vec<u8>,
    /// `LanguageName` (from the messages file's `[LangOptions]`): the name
    /// the language list shows, e.g. `English`. UTF-16LE from 4.2.2 in
    /// every build, ANSI ones included ([`Self::language_name_utf16`]);
    /// decode it with [`Self::language_name_string`].
    pub language_name: Vec<u8>,
    /// Whether [`Self::language_name`] is UTF-16LE whatever
    /// [`Self::codepage`] says: from 4.2.2, when upstream made it Unicode
    /// (`Struct.pas`: "LanguageName is Unicode").
    pub language_name_utf16: bool,
    /// `DialogFontName`: the wizard's dialog font.
    pub dialog_font: Vec<u8>,
    /// `TitleFontName`: the background window's title font (before 6.6.0).
    pub title_font: Vec<u8>,
    /// `WelcomeFontName`: the Welcome page heading font.
    pub welcome_font: Vec<u8>,
    /// `CopyrightFontName`: the background window's copyright font (before
    /// 6.6.0).
    pub copyright_font: Vec<u8>,
    /// `Data`: the language's compiled messages file, a `TMessagesHeader`
    /// followed by every setup message, in [`Self::codepage`] for ANSI
    /// builds (4.0.0+).
    pub data: Vec<u8>,
    /// `LicenseFile:` for this language: the file's bytes as stored, RTF or
    /// plain text (4.0.1+).
    pub license_text: Vec<u8>,
    /// `InfoBeforeFile:` for this language, as stored (4.0.1+).
    pub info_before: Vec<u8>,
    /// `InfoAfterFile:` for this language, as stored (4.0.1+).
    pub info_after: Vec<u8>,
    /// `LanguageID`: the Windows `LANGID`, e.g. `0x0409` for U.S. English
    /// (16-bit from 6.6.0).
    pub language_id: u32,
    /// How the name fields, and in ANSI builds the messages, are encoded.
    /// Before 4.2.2, which stores none, the code page Windows uses for
    /// [`Self::language_id`].
    pub codepage: LanguageCodepage,
    /// `DialogFontSize`, in points.
    pub dialog_font_size: u32,
    /// `DialogFontStandardHeight` (before 4.1.0; 0 after).
    pub dialog_font_standard_height: u32,
    /// `DialogFontBaseScaleHeight`: the font height the wizard's layout is
    /// scaled from (6.6.0+; 0 before).
    pub dialog_font_base_scale_height: u32,
    /// `DialogFontBaseScaleWidth`: the matching average character width
    /// (6.6.0+; 0 before).
    pub dialog_font_base_scale_width: u32,
    /// `TitleFontSize`, in points (before 6.6.0).
    pub title_font_size: u32,
    /// `WelcomeFontSize`, in points.
    pub welcome_font_size: u32,
    /// `CopyrightFontSize`, in points (before 6.6.0).
    pub copyright_font_size: u32,
    /// `RightToLeft`: the language reads right to left (5.2.3+).
    pub right_to_left: bool,
}

impl LanguageEntry {
    /// [`Self::name`] decoded with [`Self::codepage`]; `None` when the
    /// bytes are not valid in it.
    #[must_use]
    pub fn name_string(&self) -> Option<String> {
        self.codepage.decode(&self.name)
    }

    /// [`Self::language_name`] decoded: as UTF-16LE when
    /// [`Self::language_name_utf16`], else with [`Self::codepage`].
    #[must_use]
    pub fn language_name_string(&self) -> Option<String> {
        if self.language_name_utf16 {
            LanguageCodepage::Utf16Le.decode(&self.language_name)
        } else {
            self.codepage.decode(&self.language_name)
        }
    }
}

impl FromReader for LanguageEntry {
    /// Reads one `TSetupLanguageEntry`.
    ///
    /// 6.6.0 reworked the entry: dropped the `Title*` and
    /// `Copyright*` fonts, narrowed `LanguageID` from `Cardinal` to
    /// `Word`, removed the per-language `Codepage`, and added
    /// `DialogFontBaseScaleHeight/Width`. The reader dispatches per
    /// version.
    ///
    /// # Errors
    ///
    /// String / truncation errors per [`Error`].
    fn read(reader: &mut Reader<'_>, version: &Version) -> Result<Self, Error> {
        if version.at_least(6, 6, 0) {
            return read_v6_6(reader, version);
        }
        read_legacy(reader, version)
    }
}

/// 6.6.0+ reader: 4 strings, `LanguageID: Word`, no codepage,
/// `DialogFontBaseScaleHeight/Width`.
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
    let dialog_font_base_scale_height = reader.u32_le("Language.DialogFontBaseScaleHeight")?;
    let dialog_font_base_scale_width = reader.u32_le("Language.DialogFontBaseScaleWidth")?;
    let welcome_font_size = reader.u32_le("Language.WelcomeFontSize")?;

    let right_to_left = reader.u8("Language.RightToLeft")? != 0;

    Ok(LanguageEntry {
        name,
        language_name,
        language_name_utf16: true,
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
        dialog_font_standard_height: 0,
        dialog_font_base_scale_height,
        dialog_font_base_scale_width,
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
        // Before 4.2.2 the record names no code page: the messages file
        // was written in its language's, which Windows names by `LANGID`.
        LanguageCodepage::Windows(default_codepage(language_id))
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
        language_name_utf16: version.at_least(4, 2, 2),
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
        dialog_font_base_scale_height: 0,
        dialog_font_base_scale_width: 0,
        title_font_size,
        welcome_font_size,
        copyright_font_size,
        right_to_left,
    })
}

/// The ANSI code page Windows uses for a `LANGID` (its
/// `LOCALE_IDEFAULTANSICODEPAGE`), for the languages Inno Setup's message
/// files were written in; 1252 for the rest. After innoextract's
/// `default_codepage_for_language`, with Japanese, which it lacks.
fn default_codepage(language_id: u32) -> u32 {
    match language_id & 0xFFFF {
        // Chinese: Traditional (Taiwan, Hong Kong, Macao), Simplified.
        0x0404 | 0x0C04 | 0x1404 => 950,
        0x0804 | 0x1004 => 936,
        // Serbian, Azeri and Uzbek in Latin script; Cyrillic below.
        0x081A => 1250,
        0x042C | 0x0443 => 1254,
        0x0C1A | 0x082C | 0x0843 => 1251,
        id => match id & 0x03FF {
            0x01 | 0x20 | 0x29 => 1256, // Arabic, Urdu, Farsi
            0x02 | 0x19 | 0x22 | 0x23 | 0x2F | 0x3F | 0x40 | 0x44 | 0x50 => 1251,
            0x05 | 0x0E | 0x15 | 0x18 | 0x1A | 0x1B | 0x1C | 0x24 => 1250,
            0x08 => 1253,        // Greek
            0x0D => 1255,        // Hebrew
            0x11 => 932,         // Japanese
            0x12 => 949,         // Korean
            0x1E => 874,         // Thai
            0x1F => 1254,        // Turkish
            0x25..=0x27 => 1257, // Baltic
            0x2A => 1258,        // Vietnamese
            _ => 1252,
        },
    }
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

    #[test]
    fn codepage_before_4_2_2_follows_the_language() {
        for (id, cp) in [
            (0x0409, 1252),
            (0x0407, 1252),
            (0x0419, 1251),
            (0x0405, 1250),
            (0x0411, 932),
            (0x0804, 936),
            (0x0404, 950),
            (0x0412, 949),
            (0x0408, 1253),
            (0x081A, 1250),
            (0x0C1A, 1251),
        ] {
            assert_eq!(default_codepage(id), cp, "{id:#06x}");
        }
    }

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
