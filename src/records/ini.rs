//! `TSetupIniEntry`: one `[INI]` entry, a key Setup writes to an `.ini`
//! file, and what the uninstaller removes.
//!
//! On disk (`SECompressedBlockWrite`): `Filename`, `Section`, `Entry`,
//! `Value`, the condition strings, the Windows version range and the
//! `Options` set. Reader reference: innoextract `setup/ini.cpp`; every
//! layout is checked against upstream's own declarations by the
//! `crate::upstream` tests.

use std::collections::HashSet;

use crate::{
    error::Error,
    records::item::ItemBase,
    util::{
        encoding::read_setup_string,
        read::{FromReader, Reader},
    },
    version::Version,
};

/// `TSetupIniEntry.Options`: the entry's `Flags:`, and whether it has a
/// value.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[non_exhaustive]
pub enum IniFlag {
    /// `ioCreateKeyIfDoesntExist` (`createkeyifdoesntexist`): write the key
    /// only if it does not already exist.
    CreateKeyIfDoesntExist,
    /// `ioUninsDeleteEntry` (`uninsdeleteentry`): delete the key at
    /// uninstall.
    UninsDeleteEntry,
    /// `ioUninsDeleteEntireSection` (`uninsdeletesection`): delete the whole
    /// section at uninstall.
    UninsDeleteEntireSection,
    /// `ioUninsDeleteSectionIfEmpty` (`uninsdeletesectionifempty`): delete
    /// the section at uninstall if no keys are left in it.
    UninsDeleteSectionIfEmpty,
    /// `ioHasValue`: the entry gave `String:`, so Setup writes the key; an
    /// entry without one only takes part at uninstall.
    HasValue,
}

stable_flag_enum!(IniFlag, {
    CreateKeyIfDoesntExist => "create_key_if_doesnt_exist",
    UninsDeleteEntry => "unins_delete_entry",
    UninsDeleteEntireSection => "unins_delete_entire_section",
    UninsDeleteSectionIfEmpty => "unins_delete_section_if_empty",
    HasValue => "has_value",
});

/// One `[INI]` entry (`TSetupIniEntry`). Strings may contain constants
/// such as `{app}`, unexpanded.
#[derive(Clone, Debug)]
pub struct IniEntry {
    /// `Filename:`: the `.ini` file. Without a path it is in the Windows
    /// directory; empty means `win.ini` there.
    pub inifile: String,
    /// `Section:`: the section to write in.
    pub section: String,
    /// `Key:` (Pascal `Entry`): the key to set; empty means none.
    pub key: String,
    /// `String:` (Pascal `Value`): the value to set, with
    /// [`IniFlag::HasValue`].
    pub value: String,
    /// `Components:` .. `AfterInstall:` and `MinVersion:` /
    /// `OnlyBelowVersion:`.
    pub item: ItemBase,
    /// `Options`, decoded.
    pub flags: HashSet<IniFlag>,
    /// `Options` as stored.
    pub options_raw: u8,
}

impl FromReader for IniEntry {
    /// Reads one `TSetupIniEntry`.
    ///
    /// # Errors
    ///
    /// String / truncation / overflow per [`Error`].
    fn read(reader: &mut Reader<'_>, version: &Version) -> Result<Self, Error> {
        let inifile = read_setup_string(reader, version, "Ini.Filename")?;
        let section = read_setup_string(reader, version, "Ini.Section")?;
        let key = read_setup_string(reader, version, "Ini.Key")?;
        let value = read_setup_string(reader, version, "Ini.Value")?;
        let item = ItemBase::read(reader, version)?;
        let raw = reader.set_bytes(5, version, "Ini.Options")?;
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
    crate::util::flags::decode_packed_flags(&[raw], &table)
}
