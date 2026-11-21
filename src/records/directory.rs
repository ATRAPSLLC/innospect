//! `TSetupDirEntry`: one `[Dirs]` entry, a directory Setup creates beyond
//! those its files need, and what the uninstaller does with it.
//!
//! On disk (`SECompressedBlockWrite`): `DirName`, the condition strings,
//! from 4.0.11 to 4.1.0 an inline `Permissions` string, from 2.0.11
//! `Attribs`, the Windows version range, from 4.1.0 `PermissionsEntry`,
//! and the `Options` set. The conditions and the version range are split by
//! the fields between them, so they are read apart rather than as an
//! [`crate::records::item::ItemBase`]. Reader reference: innoextract
//! `setup/directory.cpp`; every layout is checked against upstream's own
//! declarations by the `crate::upstream` tests.

use std::collections::HashSet;

use crate::{
    error::Error,
    records::{item::ItemConditions, windows::WindowsVersionRange},
    util::{
        encoding::{read_ansi_bytes, read_setup_string},
        read::{FromReader, Reader},
    },
    version::Version,
};

/// `TSetupDirEntry.Options`: the entry's `Flags:`.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[non_exhaustive]
pub enum DirectoryFlag {
    /// `doUninsNeverUninstall` (`uninsneveruninstall`): the uninstaller
    /// leaves the directory.
    NeverUninstall,
    /// `doDeleteAfterInstall` (`deleteafterinstall`): create it, then delete
    /// it when Setup finishes if it is empty.
    DeleteAfterInstall,
    /// `doUninsAlwaysUninstall` (`uninsalwaysuninstall`): the uninstaller
    /// removes it if empty even when it existed before installing.
    AlwaysUninstall,
    /// `doSetNTFSCompression` (`setntfscompression`): turn NTFS compression
    /// on for the directory (5.2.0+).
    SetNtfsCompression,
    /// `doUnsetNTFSCompression` (`unsetntfscompression`): turn it off
    /// (5.2.0+).
    UnsetNtfsCompression,
}

stable_flag_enum!(DirectoryFlag, {
    NeverUninstall => "never_uninstall",
    DeleteAfterInstall => "delete_after_install",
    AlwaysUninstall => "always_uninstall",
    SetNtfsCompression => "set_ntfs_compression",
    UnsetNtfsCompression => "unset_ntfs_compression",
});

/// One `[Dirs]` entry (`TSetupDirEntry`).
#[derive(Clone, Debug)]
pub struct DirectoryEntry {
    /// `Name:` (Pascal `DirName`): the directory, constants such as `{app}`
    /// unexpanded.
    pub name: String,
    /// `Components:` .. `AfterInstall:`.
    pub conditions: ItemConditions,
    /// `Permissions:` as an inline array of `TGrantPermissionEntry` (4.0.11
    /// to 4.1.0; later releases index [`crate::InnoInstaller::permissions`]
    /// through [`Self::permission_index`]). Empty otherwise.
    pub legacy_permissions: Vec<u8>,
    /// `Attribs:`: Windows file attributes Setup sets on the directory
    /// (`FILE_ATTRIBUTE_READONLY` 0x1, `_HIDDEN` 0x2, `_SYSTEM` 0x4,
    /// `_NOT_CONTENT_INDEXED` 0x2000); 0 for none (2.0.11+).
    pub attributes: u32,
    /// `MinVersion:` / `OnlyBelowVersion:`.
    pub winver: WindowsVersionRange,
    /// `PermissionsEntry`: index into [`crate::InnoInstaller::permissions`]
    /// of the ACL `Permissions:` grants; -1 for none (4.1.0+; -1 before).
    pub permission_index: i16,
    /// `Options`, decoded.
    pub flags: HashSet<DirectoryFlag>,
    /// `Options` as stored.
    pub options_raw: u8,
}

impl FromReader for DirectoryEntry {
    /// Reads one `TSetupDirEntry`.
    ///
    /// # Errors
    ///
    /// String / truncation / overflow per [`Error`].
    fn read(reader: &mut Reader<'_>, version: &Version) -> Result<Self, Error> {
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
        let raw = reader.set_bytes(bit_count, version, "Dir.Options")?;
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
    crate::util::flags::decode_packed_flags(&[raw], &table)
}
