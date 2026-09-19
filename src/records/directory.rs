//! `TSetupDirEntry` - `[Dirs]` directive entry.
//!
//! Pascal layout (`is-6_4_1:Projects/Src/Shared.Struct.pas`):
//!
//! ```text
//! TSetupDirEntry = packed record
//!     DirName: AnsiString;
//!     [ItemConditions]
//!     Permissions: AnsiString;          // only 4.0.11..4.1.0 (legacy)
//!     Attribs: Cardinal;                 // since 2.0.11
//!     [WindowsVersionRange]
//!     PermissionsEntry: SmallInt;        // since 4.1.0
//!     Options: TSetupDirOptions;         // 3 or 5 bits
//! end;
//! ```
//!
//! Reader reference: `research/src/setup/directory.cpp`. Note:
//! `directory` interposes `permissions` + `attributes` between the
//! shared conditions section and the version range, so we read the
//! two halves of `ItemBase` separately.

use std::collections::HashSet;

use crate::{
    error::Error,
    records::{item::ItemConditions, windows::WindowsVersionRange},
    util::{
        encoding::{read_ansi_bytes, read_setup_string},
        read::Reader,
    },
    version::Version,
};

/// `TSetupDirOptions` flag bits.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum DirectoryFlag {
    NeverUninstall,
    DeleteAfterInstall,
    AlwaysUninstall,
    SetNtfsCompression,
    UnsetNtfsCompression,
}

stable_flag_enum!(DirectoryFlag, {
    NeverUninstall => "never_uninstall",
    DeleteAfterInstall => "delete_after_install",
    AlwaysUninstall => "always_uninstall",
    SetNtfsCompression => "set_ntfs_compression",
    UnsetNtfsCompression => "unset_ntfs_compression",
});

/// Parsed `TSetupDirEntry`.
#[derive(Clone, Debug)]
pub struct DirectoryEntry {
    /// `Name:` directive - directory path with Inno constants.
    pub name: String,
    /// `[ItemConditions]`.
    pub conditions: ItemConditions,
    /// `Permissions:` legacy 4.0.11..4.1.0 inline blob (the
    /// permissions were inlined here for that narrow version range
    /// before the `[Permissions]` table was introduced). Empty
    /// outside that range.
    pub legacy_permissions: Vec<u8>,
    /// `Attribs:` directive - Win32 file-attribute flags.
    pub attributes: u32,
    /// `[WindowsVersionRange]`.
    pub winver: WindowsVersionRange,
    /// Index into [`crate::InnoInstaller::permissions`]; `-1` =
    /// no entry. 4.1.0+.
    pub permission_index: i16,
    /// Decoded options.
    pub flags: HashSet<DirectoryFlag>,
    /// Raw `Options` byte.
    pub options_raw: u8,
}

impl DirectoryEntry {
    /// Reads one `TSetupDirEntry`.
    ///
    /// # Errors
    ///
    /// String / truncation / overflow per [`Error`].
    pub(crate) fn read(reader: &mut Reader<'_>, version: &Version) -> Result<Self, Error> {
        let name = read_setup_string(reader, version, "Dir.Name")?;
        let conditions = ItemConditions::read(reader, version)?;

        let legacy_permissions = if version.at_least(4, 0, 11) && !version.at_least(4, 1, 0) {
            read_ansi_bytes(reader, "Dir.LegacyPermissions")?
        } else {
            Vec::new()
        };

        let attributes = if version.at_least(2, 0, 11) {
            reader.u32_le("Dir.Attribs")?
        } else {
            0
        };

        let winver = WindowsVersionRange::read(reader, version)?;

        let permission_index = if version.at_least(4, 1, 0) {
            reader
                .array::<2>("Dir.PermissionIndex")
                .map(i16::from_le_bytes)?
        } else {
            -1
        };

        let bit_count = if version.at_least(5, 2, 0) { 5 } else { 3 };
        let raw = reader.set_bytes(bit_count, true, "Dir.Options")?;
        let options_raw = raw.first().copied().unwrap_or(0);
        let flags = decode_directory_flags(options_raw, version);

        Ok(Self {
            name,
            conditions,
            legacy_permissions,
            attributes,
            winver,
            permission_index,
            flags,
            options_raw,
        })
    }
}

fn decode_directory_flags(raw: u8, version: &Version) -> HashSet<DirectoryFlag> {
    let mut table: Vec<DirectoryFlag> = vec![
        DirectoryFlag::NeverUninstall,
        DirectoryFlag::DeleteAfterInstall,
        DirectoryFlag::AlwaysUninstall,
    ];
    if version.at_least(5, 2, 0) {
        table.push(DirectoryFlag::SetNtfsCompression);
        table.push(DirectoryFlag::UnsetNtfsCompression);
    }
    super::decode_packed_flags(&[raw], &table)
}
