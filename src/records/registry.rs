//! `TSetupRegistryEntry`: one `[Registry]` entry, a key or value Setup
//! creates, changes or deletes, and what the uninstaller does with it.
//!
//! On disk (`SECompressedBlockWrite`): `Subkey`, `ValueName`, `ValueData`,
//! the condition strings, from 4.0.11 to 4.1.0 an inline `Permissions`
//! string, the Windows version range, `RootKey`, from 4.1.0
//! `PermissionsEntry`, `Typ`, from SetupID 7.0.0.3 `Bitness`, and the
//! `Options` set. The conditions and the version range are split by that
//! permissions string, so they are read apart rather than as an
//! [`crate::records::item::ItemBase`]. Reader reference: innoextract
//! `setup/registry.cpp`; every layout is checked against upstream's own
//! declarations by the `crate::upstream` tests.

use std::{borrow::Cow, collections::HashSet};

use crate::{
    error::Error,
    records::{
        item::ItemConditions,
        windows::{Bitness, WindowsVersionRange},
    },
    util::{
        encoding::{
            decode_windows_1252, is_unicode_for_version, read_ansi_bytes, read_setup_string,
        },
        read::{FromReader, Reader},
    },
    version::Version,
};

/// The root key an entry is under (`Root:`), from `RootKey`. The
/// predefined handles are `0x80000000` plus the index this enum lists them
/// in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RegistryHive {
    /// `HKEY_CLASSES_ROOT`.
    ClassesRoot,
    /// `HKEY_CURRENT_USER`.
    CurrentUser,
    /// `HKEY_LOCAL_MACHINE`.
    LocalMachine,
    /// `HKEY_USERS`.
    Users,
    /// `HKEY_PERFORMANCE_DATA`.
    PerformanceData,
    /// `HKEY_CURRENT_CONFIG`.
    CurrentConfig,
    /// `HKEY_DYN_DATA` (Win9x legacy).
    DynData,
    /// A value that is no predefined handle, holding it with the high bit
    /// cleared.
    Unknown(u32),
    /// `HKA` (`HKEY_AUTO`, stored as 1; 6.0.0+): `HKEY_LOCAL_MACHINE` when
    /// Setup runs in administrative install mode, `HKEY_CURRENT_USER`
    /// otherwise.
    Auto,
}

stable_name_enum!(RegistryHive, {
    Self::ClassesRoot => "classes_root",
    Self::CurrentUser => "current_user",
    Self::LocalMachine => "local_machine",
    Self::Users => "users",
    Self::PerformanceData => "performance_data",
    Self::CurrentConfig => "current_config",
    Self::DynData => "dyn_data",
    Self::Unknown(_) => "unknown",
    Self::Auto => "auto",
});

/// `ValueType:` (`Typ`): the type of the value an entry writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RegistryValueType {
    /// `rtNone` (`none`): create the key only, no value.
    None,
    /// `rtString` (`string`): `REG_SZ`.
    String,
    /// `rtExpandString` (`expandsz`): `REG_EXPAND_SZ`.
    ExpandString,
    /// `rtDWord` (`dword`): `REG_DWORD`.
    DWord,
    /// `rtBinary` (`binary`): `REG_BINARY`.
    Binary,
    /// `rtMultiString` (`multisz`): `REG_MULTI_SZ`.
    MultiString,
    /// `rtQWord` (`qword`): `REG_QWORD` (5.2.5+).
    QWord,
}

stable_name_enum!(RegistryValueType, {
    Self::None => "none",
    Self::String => "string",
    Self::ExpandString => "expand_string",
    Self::DWord => "dword",
    Self::Binary => "binary",
    Self::MultiString => "multi_string",
    Self::QWord => "qword",
});

/// `ValueData:` decoded per [`RegistryEntry::value_type`] and the version.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RegistryData {
    /// `none`: no value, only the key.
    None,
    /// `string` / `expandsz`: the text, constants unexpanded.
    String(String),
    /// `multisz`: the text, lines separated by the `{break}` constant,
    /// which Setup turns into NULs; other constants unexpanded.
    MultiString(String),
    /// `dword` / `qword` known when compiling. Before 4.1.4 a `dword` is
    /// stored as its four little-endian bytes; from 4.1.4 both are stored
    /// as text, `$` and hexadecimal digits.
    Number(u64),
    /// `dword` / `qword` given as a constant, such as `{reg:...}`, which
    /// Setup resolves at install time (4.1.4+).
    NumberExpression(String),
    /// `binary`, or a value whose type this crate does not know: the bytes.
    Binary(Vec<u8>),
}

/// `TSetupRegistryEntry.Options`: the entry's `Flags:`.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[non_exhaustive]
pub enum RegistryFlag {
    /// `roCreateValueIfDoesntExist` (`createvalueifdoesntexist`): write the
    /// value only if none of that name exists.
    CreateValueIfDoesntExist,
    /// `roUninsDeleteValue` (`uninsdeletevalue`): delete the value at
    /// uninstall.
    UninsDeleteValue,
    /// `roUninsClearValue` (`uninsclearvalue`): set the value to an empty
    /// `REG_SZ` at uninstall.
    UninsClearValue,
    /// `roUninsDeleteEntireKey` (`uninsdeletekey`): delete the key with all
    /// its values and subkeys at uninstall.
    UninsDeleteEntireKey,
    /// `roUninsDeleteEntireKeyIfEmpty` (`uninsdeletekeyifempty`): delete
    /// the key at uninstall if nothing is left in it.
    UninsDeleteEntireKeyIfEmpty,
    /// `roPreserveStringType` (`preservestringtype`): keep an existing
    /// value's `REG_SZ` / `REG_EXPAND_SZ` type.
    PreserveStringType,
    /// `roDeleteKey` (`deletekey`): delete the key first, then write.
    DeleteKey,
    /// `roDeleteValue` (`deletevalue`): delete the value first, then write.
    DeleteValue,
    /// `roNoError` (`noerror`): no error message if writing fails.
    NoError,
    /// `roDontCreateKey` (`dontcreatekey`): do nothing if the key does not
    /// already exist.
    DontCreateKey,
    /// `ro32Bit` (`HKLM32` etc.): the 32-bit registry view (5.1.0 to
    /// SetupID 7.0.0.2; then [`RegistryEntry::bitness`]).
    Bits32,
    /// `ro64Bit` (`HKLM64` etc.): the 64-bit view (5.1.0 to 7.0.0.2; then
    /// [`RegistryEntry::bitness`]).
    Bits64,
}

stable_flag_enum!(RegistryFlag, {
    CreateValueIfDoesntExist => "create_value_if_doesnt_exist",
    UninsDeleteValue => "unins_delete_value",
    UninsClearValue => "unins_clear_value",
    UninsDeleteEntireKey => "unins_delete_entire_key",
    UninsDeleteEntireKeyIfEmpty => "unins_delete_entire_key_if_empty",
    PreserveStringType => "preserve_string_type",
    DeleteKey => "delete_key",
    DeleteValue => "delete_value",
    NoError => "no_error",
    DontCreateKey => "dont_create_key",
    Bits32 => "bits32",
    Bits64 => "bits64",
});

/// One `[Registry]` entry (`TSetupRegistryEntry`). Strings may contain
/// constants such as `{app}`, unexpanded.
#[derive(Clone, Debug)]
pub struct RegistryEntry {
    /// `Subkey:`: the key's path under [`Self::hive`].
    pub subkey: String,
    /// `ValueName:`: the value to write; empty is the key's default value.
    /// Always empty in a 16-bit installer (1.2.x), which has no value names
    /// and writes the default value.
    pub value_name: String,
    /// `ValueData:` as stored: a string field, so UTF-16LE in Unicode
    /// builds. A `binary` value is one byte per character (per UTF-16 unit
    /// in Unicode builds), and a `dword` from 4.1.4 on is text. Decoded in
    /// [`Self::data`].
    pub value: Vec<u8>,
    /// `ValueData:` decoded.
    pub data: RegistryData,
    /// `Components:` .. `AfterInstall:`.
    pub conditions: ItemConditions,
    /// `Permissions:` as an inline array of `TGrantPermissionEntry` (4.0.11
    /// to 4.1.0; later releases index [`crate::InnoInstaller::permissions`]
    /// through [`Self::permission_index`]).
    pub legacy_permissions: Vec<u8>,
    /// `MinVersion:` / `OnlyBelowVersion:`.
    pub winver: WindowsVersionRange,
    /// `Root:`, decoded.
    pub hive: RegistryHive,
    /// `RootKey` with the predefined-handle bit (`0x80000000`) cleared:
    /// 0 is `HKCR`, 1 `HKCU`, 2 `HKLM`, and so on. `HKA` is 1 as stored,
    /// so it also reads 1 here; tell them apart by [`Self::hive`] or
    /// [`Self::root_key_raw`].
    pub hive_raw: u32,
    /// `RootKey` as stored. A 16-bit installer (1.2.x) stores none: it only
    /// writes under `HKEY_CLASSES_ROOT` (1.2.16 `INSTALL.PAS`), so this is
    /// that key's value, `0x80000000`.
    pub root_key_raw: u32,
    /// `PermissionsEntry`: index into [`crate::InnoInstaller::permissions`]
    /// of the ACL `Permissions:` grants; -1 for none (4.1.0+; -1 before).
    pub permission_index: i16,
    /// `ValueType:`, decoded; `None` for a value this crate does not know.
    pub value_type: Option<RegistryValueType>,
    /// `Typ` as stored.
    pub value_type_raw: u8,
    /// `Bitness`: the registry view (SetupID 7.0.0.3+, replacing
    /// [`RegistryFlag::Bits32`] / [`RegistryFlag::Bits64`]). `None` before,
    /// or for a value this crate does not know.
    pub bitness: Option<Bitness>,
    /// `Bitness` as stored; 0 when the version has no such byte.
    pub bitness_raw: u8,
    /// `Options`, decoded.
    pub flags: HashSet<RegistryFlag>,
    /// `Options` as stored: the set's bytes, whose size grows with the
    /// number of flags the version defines.
    pub options_raw: Vec<u8>,
}

impl RegistryEntry {
    /// `ValueData:` as stored; see [`Self::value`].
    #[must_use]
    pub fn value_bytes(&self) -> &[u8] {
        &self.value
    }

    /// [`Self::data`] as text: a string as written, a known number in
    /// decimal, a number expression as written, binary data in lower-case
    /// hex, and nothing for `none`.
    #[must_use]
    pub fn value_text(&self) -> Cow<'_, str> {
        match &self.data {
            RegistryData::None => Cow::Borrowed(""),
            RegistryData::String(s)
            | RegistryData::MultiString(s)
            | RegistryData::NumberExpression(s) => Cow::Borrowed(s.as_str()),
            RegistryData::Number(n) => Cow::Owned(n.to_string()),
            RegistryData::Binary(b) => Cow::Owned(format_hex(b)),
        }
    }
}

/// Decodes `ValueData` per its type and the version's encoding.
fn decode_data(
    value: &[u8],
    value_type: Option<RegistryValueType>,
    version: &Version,
) -> RegistryData {
    let unicode = is_unicode_for_version(version);
    let text = |b: &[u8]| {
        if unicode {
            decode_utf16le_lossy(b)
        } else {
            decode_windows_1252(b)
        }
    };
    match value_type {
        Some(RegistryValueType::None) => RegistryData::None,
        Some(RegistryValueType::String | RegistryValueType::ExpandString) => {
            RegistryData::String(text(value))
        }
        Some(RegistryValueType::MultiString) => RegistryData::MultiString(text(value)),
        Some(RegistryValueType::DWord) if !version.at_least(4, 1, 4) => match value {
            [a, b, c, d] => RegistryData::Number(u64::from(u32::from_le_bytes([*a, *b, *c, *d]))),
            _ => RegistryData::Binary(value.to_vec()),
        },
        Some(RegistryValueType::DWord | RegistryValueType::QWord) => {
            let t = text(value);
            let trimmed = t.trim();
            let number = match trimmed.strip_prefix('$') {
                Some(hex) => u64::from_str_radix(hex, 16).ok(),
                None => trimmed.parse::<u64>().ok(),
            };
            number.map_or(
                RegistryData::NumberExpression(t.clone()),
                RegistryData::Number,
            )
        }
        Some(RegistryValueType::Binary) if unicode => {
            // One byte per UTF-16 unit; a unit above 0xFF is not something
            // the compiler writes, so the data is kept as stored.
            let units = value.as_chunks::<2>().0;
            if value.len().is_multiple_of(2) && units.iter().all(|[_, hi]| *hi == 0) {
                RegistryData::Binary(units.iter().map(|[lo, _]| *lo).collect())
            } else {
                RegistryData::Binary(value.to_vec())
            }
        }
        Some(RegistryValueType::Binary) | None => RegistryData::Binary(value.to_vec()),
    }
}

impl FromReader for RegistryEntry {
    /// Reads one `TSetupRegistryEntry`.
    ///
    /// # Errors
    ///
    /// String / truncation / overflow per [`Error`].
    fn read(reader: &mut Reader<'_>, version: &Version) -> Result<Self, Error> {
        let subkey = read_setup_string(reader, version, "Registry.Subkey")?;
        let value_name = if version.is_16bit() {
            String::new()
        } else {
            read_setup_string(reader, version, "Registry.ValueName")?
        };
        let value = read_ansi_bytes(reader, "Registry.ValueData")?;
        let conditions = ItemConditions::read(reader, version)?;

        let legacy_permissions = if version.at_least(4, 0, 11) && !version.at_least(4, 1, 0) {
            read_ansi_bytes(reader, "Registry.LegacyPermissions")?
        } else {
            Vec::new()
        };

        let winver = WindowsVersionRange::read(reader, version)?;

        const HKEY_CLASSES_ROOT: u32 = 0x8000_0000;
        let root_key_raw = if version.is_16bit() {
            HKEY_CLASSES_ROOT
        } else {
            reader.u32_le("Registry.RootKey")?
        };
        // Predefined handles are `0x80000000 + n`; `HKA` (6.0.0+) is
        // `HKEY_AUTO`, the plain value 1 (`Shared.SetupTypes.pas`).
        let hive_raw = root_key_raw & !0x8000_0000;
        let hive = if root_key_raw == 1 && version.at_least(6, 0, 0) {
            RegistryHive::Auto
        } else {
            RegistryHive::from_raw(hive_raw)
        };

        let permission_index = if version.at_least(4, 1, 0) {
            reader
                .array::<2>("Registry.PermissionIndex")
                .map(i16::from_le_bytes)?
        } else {
            -1
        };

        let value_type_raw = reader.u8("Registry.Typ")?;
        let value_type = decode_value_type(value_type_raw, version);
        let data = decode_data(&value, value_type, version);

        // SetupBinVersion 7.0.0.3 (issrc commit `3553e3b7`) adds a
        // `Bitness` byte between `Typ` and `Options`. 7.0.0.0..7.0.0.2
        // and earlier still use the legacy `ro32Bit` / `ro64Bit` flag
        // bits.
        let (bitness, bitness_raw) = if version.at_least_4(7, 0, 0, 3) {
            let raw = reader.u8("Registry.Bitness")?;
            (Bitness::from_raw(raw), raw)
        } else {
            (None, 0)
        };

        let table = registry_flag_table(version);
        let raw = reader.set_bytes(table.len(), version, "Registry.Options")?;
        let flags = crate::util::flags::decode_packed_flags(&raw, &table);

        Ok(Self {
            subkey,
            value_name,
            value,
            data,
            conditions,
            legacy_permissions,
            winver,
            hive,
            hive_raw,
            root_key_raw,
            permission_index,
            value_type,
            value_type_raw,
            bitness,
            bitness_raw,
            flags,
            options_raw: raw,
        })
    }
}

impl RegistryHive {
    /// Resolves the persisted raw hive number back to a [`RegistryHive`].
    ///
    /// Total (never fails): unrecognised numbers surface as
    /// [`RegistryHive::Unknown`]. Public inverse of the internal hive decode,
    /// used to re-derive the label from a stored `hive_raw`.
    #[must_use]
    pub fn from_raw(raw: u32) -> Self {
        match raw {
            0 => Self::ClassesRoot,
            1 => Self::CurrentUser,
            2 => Self::LocalMachine,
            3 => Self::Users,
            4 => Self::PerformanceData,
            5 => Self::CurrentConfig,
            6 => Self::DynData,
            n => Self::Unknown(n),
        }
    }
}

impl RegistryValueType {
    /// Resolves the persisted on-disk discriminant byte back to a
    /// [`RegistryValueType`], or [`None`] for an unknown value.
    ///
    /// Maps the full byte range regardless of format version, unlike the
    /// version-gated decode applied at parse time: byte `6` (`QWord`) only
    /// appears in 5.2.5+ installers, but since the stored `value_type_raw` was
    /// already validated against its own version when parsed, re-deriving the
    /// label here needs no format version.
    #[must_use]
    pub fn from_raw(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::None),
            1 => Some(Self::String),
            2 => Some(Self::ExpandString),
            3 => Some(Self::DWord),
            4 => Some(Self::Binary),
            5 => Some(Self::MultiString),
            6 => Some(Self::QWord),
            _ => None,
        }
    }
}

fn decode_value_type(b: u8, version: &Version) -> Option<RegistryValueType> {
    // Byte→variant mapping lives in `RegistryValueType::from_raw`; this only
    // applies the version gate: `QWord` (byte 6) was added in 5.2.5.
    match RegistryValueType::from_raw(b)? {
        RegistryValueType::QWord if !version.at_least(5, 2, 5) => None,
        kind => Some(kind),
    }
}

fn decode_utf16le_lossy(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .collect();
    String::from_utf16_lossy(&units)
}

fn format_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        if let Some(ch) = HEX.get(usize::from(byte >> 4)) {
            out.push(char::from(*ch));
        }
        if let Some(ch) = HEX.get(usize::from(byte & 0x0f)) {
            out.push(char::from(*ch));
        }
    }
    out
}

fn registry_flag_table(version: &Version) -> Vec<RegistryFlag> {
    let mut t = Vec::new();
    // A 16-bit installer has no value names to test or delete.
    if !version.is_16bit() {
        t.push(RegistryFlag::CreateValueIfDoesntExist);
        t.push(RegistryFlag::UninsDeleteValue);
    }
    t.extend([
        RegistryFlag::UninsClearValue,
        RegistryFlag::UninsDeleteEntireKey,
        RegistryFlag::UninsDeleteEntireKeyIfEmpty,
    ]);
    if version.at_least(1, 2, 6) {
        t.push(RegistryFlag::PreserveStringType);
    }
    if version.at_least(1, 3, 9) {
        t.push(RegistryFlag::DeleteKey);
        t.push(RegistryFlag::DeleteValue);
    }
    if version.at_least(1, 3, 12) {
        t.push(RegistryFlag::NoError);
    }
    if version.at_least(1, 3, 16) {
        t.push(RegistryFlag::DontCreateKey);
    }
    // SetupBinVersion 7.0.0.3 (issrc commit `3553e3b7`) moves the
    // bitness from these flag bits into a separate `Bitness` byte.
    // 7.0.0.0..7.0.0.2 still keep the named flags.
    if version.at_least(5, 1, 0) && !version.at_least_4(7, 0, 0, 3) {
        t.push(RegistryFlag::Bits32);
        t.push(RegistryFlag::Bits64);
    }
    t
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::upstream::version;

    fn utf16(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    #[test]
    fn dword_is_four_bytes_before_4_1_4_and_text_after() {
        let dword = Some(RegistryValueType::DWord);
        let old = version("4.1.3", false);
        assert_eq!(
            decode_data(&123u32.to_le_bytes(), dword, &old),
            RegistryData::Number(123)
        );
        let ansi = version("5.0.4", false);
        assert_eq!(decode_data(b"$7B", dword, &ansi), RegistryData::Number(123));
        let unicode = version("7.1.1", true);
        assert_eq!(
            decode_data(&utf16("$7B"), dword, &unicode),
            RegistryData::Number(123)
        );
        assert_eq!(
            decode_data(&utf16("{reg:HKLM\\X,Y}"), dword, &unicode),
            RegistryData::NumberExpression("{reg:HKLM\\X,Y}".into())
        );
        let qword = Some(RegistryValueType::QWord);
        assert_eq!(
            decode_data(&utf16("$FFFFFFFFFF"), qword, &unicode),
            RegistryData::Number(0xFF_FFFF_FFFF)
        );
    }

    #[test]
    fn strings_follow_the_build_and_binary_is_one_byte_per_char() {
        let unicode = version("7.1.1", true);
        let ansi = version("5.5.7", false);
        let string = Some(RegistryValueType::String);
        assert_eq!(
            decode_data(&utf16("{app}"), string, &unicode),
            RegistryData::String("{app}".into())
        );
        assert_eq!(
            decode_data(b"caf\xe9", string, &ansi),
            RegistryData::String("café".into())
        );
        let multi = Some(RegistryValueType::MultiString);
        assert_eq!(
            decode_data(&utf16("a{break}b"), multi, &unicode),
            RegistryData::MultiString("a{break}b".into())
        );
        let binary = Some(RegistryValueType::Binary);
        assert_eq!(
            decode_data(&[0x01, 0x00, 0xAB, 0x00], binary, &unicode),
            RegistryData::Binary(vec![0x01, 0xAB])
        );
        assert_eq!(
            decode_data(&[0x01, 0xAB], binary, &ansi),
            RegistryData::Binary(vec![0x01, 0xAB])
        );
        assert_eq!(
            decode_data(b"", Some(RegistryValueType::None), &unicode),
            RegistryData::None
        );
    }
}
