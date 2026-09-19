//! `TSetupRegistryEntry` - `[Registry]` directive entry.
//!
//! Pascal layout (`is-6_4_1:Projects/Src/Shared.Struct.pas`):
//!
//! ```text
//! TSetupRegistryEntry = packed record
//!     SubKey: AnsiString;
//!     ValueName: AnsiString;
//!     ValueData: AnsiString;             // binary, not encoded
//!     [ItemConditions]
//!     Permissions: AnsiString;           // 4.0.11..4.1.0 only
//!     [WindowsVersionRange]
//!     RootKey: HKEY;                     // u32 (with high-bit mask)
//!     PermissionsEntry: SmallInt;        // since 4.1.0
//!     Typ: TSetupRegistryValueType;      // u8 enum
//!     Options: TSetupRegistryOptions;
//! end;
//! ```
//!
//! Reader reference: `research/src/setup/registry.cpp`. Conditions
//! and version range are split (the legacy permissions blob from
//! 4.0.11..4.1.0 sits between), so we read [`ItemConditions`] and
//! [`WindowsVersionRange`] separately rather than via `ItemBase`.

use std::{borrow::Cow, collections::HashSet};

use crate::{
    error::Error,
    records::{
        item::ItemConditions,
        windows::{Bitness, WindowsVersionRange},
    },
    util::{
        encoding::{read_ansi_bytes, read_setup_string},
        read::Reader,
    },
    version::Version,
};

/// Windows registry hive (`RootKey` after high-bit mask).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
#[allow(missing_docs)]
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
    /// Unknown / not-set numeric hive value.
    Unknown(u32),
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
});

/// Registry value type (`TSetupRegistryValueType`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum RegistryValueType {
    None,
    String,
    ExpandString,
    DWord,
    Binary,
    MultiString,
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

/// `TSetupRegistryOptions` flag bits.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum RegistryFlag {
    CreateValueIfDoesntExist,
    UninsDeleteValue,
    UninsClearValue,
    UninsDeleteEntireKey,
    UninsDeleteEntireKeyIfEmpty,
    PreserveStringType,
    DeleteKey,
    DeleteValue,
    NoError,
    DontCreateKey,
    Bits32,
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

/// Parsed `TSetupRegistryEntry`.
#[derive(Clone, Debug)]
pub struct RegistryEntry {
    /// `Subkey:` directive.
    pub subkey: String,
    /// `ValueName:` directive (empty = the `(Default)` value).
    pub value_name: String,
    /// `ValueData:` raw bytes. Encoding depends on
    /// [`Self::value_type`]: `String`/`ExpandString`/`MultiString`
    /// values are UTF-16LE on Unicode builds; `DWord`/`QWord`/
    /// `Binary` are raw bytes; `None` is empty.
    pub value: Vec<u8>,
    /// `[ItemConditions]`.
    pub conditions: ItemConditions,
    /// Legacy 4.0.11..4.1.0 inline permissions blob (replaced by the
    /// `[Permissions]` table at 4.1.0).
    pub legacy_permissions: Vec<u8>,
    /// `[WindowsVersionRange]`.
    pub winver: WindowsVersionRange,
    /// Decoded hive.
    pub hive: RegistryHive,
    /// Raw `RootKey` u32 (after stripping the `0x80000000` "auto"
    /// flag bit).
    pub hive_raw: u32,
    /// Index into [`crate::InnoInstaller::permissions`]; `-1` =
    /// no entry. 4.1.0+.
    pub permission_index: i16,
    /// Decoded value type.
    pub value_type: Option<RegistryValueType>,
    /// Raw `Typ` byte.
    pub value_type_raw: u8,
    /// `Bitness` enum (6.7.0+; replaces `Bits32`/`Bits64` flag bits).
    pub bitness: Option<Bitness>,
    /// Raw bitness byte (or 0 when absent).
    pub bitness_raw: u8,
    /// Decoded options.
    pub flags: HashSet<RegistryFlag>,
    /// Raw `Options` bytes.
    pub options_raw: Vec<u8>,
}

impl RegistryEntry {
    /// Returns the raw registry value bytes.
    #[must_use]
    pub fn value_bytes(&self) -> &[u8] {
        &self.value
    }

    /// Renders the registry value using the decoded registry value type.
    #[must_use]
    pub fn value_text(&self) -> Cow<'_, str> {
        match self.value_type {
            Some(RegistryValueType::DWord) => Cow::Owned(format_le_u32(&self.value)),
            Some(RegistryValueType::QWord) => Cow::Owned(format_le_u64(&self.value)),
            Some(RegistryValueType::String | RegistryValueType::ExpandString) => {
                Cow::Owned(decode_utf16le_lossy(&self.value))
            }
            Some(RegistryValueType::MultiString) => {
                Cow::Owned(decode_utf16le_lossy(&self.value).replace('\0', "\\0"))
            }
            Some(RegistryValueType::Binary) | Some(RegistryValueType::None) | None => {
                Cow::Owned(format_hex(&self.value))
            }
        }
    }

    /// Reads one `TSetupRegistryEntry`.
    ///
    /// # Errors
    ///
    /// String / truncation / overflow per [`Error`].
    pub(crate) fn read(reader: &mut Reader<'_>, version: &Version) -> Result<Self, Error> {
        let subkey = read_setup_string(reader, version, "Registry.Subkey")?;
        let value_name = read_setup_string(reader, version, "Registry.ValueName")?;
        let value = read_ansi_bytes(reader, "Registry.ValueData")?;
        let conditions = ItemConditions::read(reader, version)?;

        let legacy_permissions = if version.at_least(4, 0, 11) && !version.at_least(4, 1, 0) {
            read_ansi_bytes(reader, "Registry.LegacyPermissions")?
        } else {
            Vec::new()
        };

        let winver = WindowsVersionRange::read(reader, version)?;

        let raw_root = reader.u32_le("Registry.RootKey")?;
        // Inno sets the high bit when the root key was determined at
        // compile time vs runtime; mask it off for the canonical hive.
        let hive_raw = raw_root & !0x8000_0000;
        let hive = RegistryHive::from_raw(hive_raw);

        let permission_index = if version.at_least(4, 1, 0) {
            reader
                .array::<2>("Registry.PermissionIndex")
                .map(i16::from_le_bytes)?
        } else {
            -1
        };

        let value_type_raw = reader.u8("Registry.Typ")?;
        let value_type = decode_value_type(value_type_raw, version);

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
        let raw = reader.set_bytes(table.len(), true, "Registry.Options")?;
        let flags = super::decode_packed_flags(&raw, &table);

        Ok(Self {
            subkey,
            value_name,
            value,
            conditions,
            legacy_permissions,
            winver,
            hive,
            hive_raw,
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

fn format_le_u32(bytes: &[u8]) -> String {
    let mut buf = [0_u8; 4];
    for (idx, byte) in bytes.iter().take(4).enumerate() {
        if let Some(slot) = buf.get_mut(idx) {
            *slot = *byte;
        }
    }
    u32::from_le_bytes(buf).to_string()
}

fn format_le_u64(bytes: &[u8]) -> String {
    let mut buf = [0_u8; 8];
    for (idx, byte) in bytes.iter().take(8).enumerate() {
        if let Some(slot) = buf.get_mut(idx) {
            *slot = *byte;
        }
    }
    u64::from_le_bytes(buf).to_string()
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
    let mut t = vec![
        RegistryFlag::CreateValueIfDoesntExist,
        RegistryFlag::UninsDeleteValue,
        RegistryFlag::UninsClearValue,
        RegistryFlag::UninsDeleteEntireKey,
        RegistryFlag::UninsDeleteEntireKeyIfEmpty,
    ];
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
