//! `TSetupIniEntry` - `[INI]` directive entry.
//!
//! Pascal layout (`is-6_4_1:Projects/Src/Shared.Struct.pas`):
//!
//! ```text
//! TSetupIniEntry = packed record
//!     IniFile, Section, Key, Value: AnsiString;
//!     [ItemConditions]
//!     [WindowsVersionRange]
//!     Options: TSetupIniOptions;     // 5 bits → 1 byte
//! end;
//! ```
//!
//! Reader reference: `research/src/setup/ini.cpp`. innoextract
//! defaults `inifile` to `{windows}/WIN.INI` when empty - we surface
//! the field as-stored and let the caller apply that fallback.

use std::collections::HashSet;

use crate::{
    error::Error,
    records::item::ItemBase,
    util::{encoding::read_setup_string, read::Reader},
    version::Version,
};

/// `TSetupIniOptions` flag bits.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum IniFlag {
    CreateKeyIfDoesntExist,
    UninsDeleteEntry,
    UninsDeleteEntireSection,
    UninsDeleteSectionIfEmpty,
    HasValue,
}

stable_flag_enum!(IniFlag, {
    CreateKeyIfDoesntExist => "create_key_if_doesnt_exist",
    UninsDeleteEntry => "unins_delete_entry",
    UninsDeleteEntireSection => "unins_delete_entire_section",
    UninsDeleteSectionIfEmpty => "unins_delete_section_if_empty",
    HasValue => "has_value",
});

/// Parsed `TSetupIniEntry`.
#[derive(Clone, Debug)]
pub struct IniEntry {
    /// `Filename:` directive - path of the `.ini` file.
    pub inifile: String,
    /// `Section:` directive.
    pub section: String,
    /// `Key:` directive.
    pub key: String,
    /// `String:` directive - value to write (when [`IniFlag::HasValue`]
    /// is set).
    pub value: String,
    /// Shared conditions + Windows version range.
    pub item: ItemBase,
    /// Decoded options.
    pub flags: HashSet<IniFlag>,
    /// Raw `Options` byte.
    pub options_raw: u8,
}

impl IniEntry {
    /// Reads one `TSetupIniEntry`.
    ///
    /// # Errors
    ///
    /// String / truncation / overflow per [`Error`].
    pub(crate) fn read(reader: &mut Reader<'_>, version: &Version) -> Result<Self, Error> {
        let inifile = read_setup_string(reader, version, "Ini.Filename")?;
        let section = read_setup_string(reader, version, "Ini.Section")?;
        let key = read_setup_string(reader, version, "Ini.Key")?;
        let value = read_setup_string(reader, version, "Ini.Value")?;
        let item = ItemBase::read(reader, version)?;
        let raw = reader.set_bytes(5, true, "Ini.Options")?;
        let options_raw = raw.first().copied().unwrap_or(0);
        let flags = decode_ini_flags(options_raw);
        Ok(Self {
            inifile,
            section,
            key,
            value,
            item,
            flags,
            options_raw,
        })
    }
}

fn decode_ini_flags(raw: u8) -> HashSet<IniFlag> {
    let table = [
        IniFlag::CreateKeyIfDoesntExist,
        IniFlag::UninsDeleteEntry,
        IniFlag::UninsDeleteEntireSection,
        IniFlag::UninsDeleteSectionIfEmpty,
        IniFlag::HasValue,
    ];
    super::decode_packed_flags(&[raw], &table)
}
